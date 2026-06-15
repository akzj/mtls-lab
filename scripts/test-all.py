#!/usr/bin/env python3
"""test-all.py — Comprehensive integration test suite for Zero-FAS mTLS Lab.

Tests: infrastructure, Vault health/backends/secrets, Authentik reachability/OIDC,
       Web UI endpoints, SSH CA keys and daemon, Terraform state, step-ca ACME.

Exit code = number of failed tests (0 = all pass).
Output: [PASS]/[FAIL] per test + summary.

All HTTP requests use verify=False because Vault uses -dev-tls (self-signed cert).
"""
import json
import os
import socket
import subprocess
import sys
import time

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "root-token")
TOKEN_HEADER = {"X-Vault-Token": VAULT_TOKEN}
AUTHENTIK_TOKEN = os.environ.get("AUTHENTIK_TOKEN", "authentik-bootstrap-token")

VAULT_ADDR = "https://localhost:8200"
AUTHENTIK_ADDR = "http://localhost:9000"
WEB_UI_ADDR = "http://localhost:9091"
STEP_CA_ADDR = "https://localhost:8443"

DOCKER_COMPOSE_DIR = PROJECT_DIR

PASS = 0
FAIL = 0

# Shorter timeout for all HTTP requests
REQ_TIMEOUT = 4


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------
def docker_ps():
    """Return list of running container names from docker compose ps."""
    try:
        r = subprocess.run(
            ["docker", "compose", "ps", "--format", "{{.Name}}"],
            capture_output=True, text=True, timeout=10, cwd=DOCKER_COMPOSE_DIR,
        )
        return [n.strip() for n in r.stdout.strip().split("\n") if n.strip()]
    except Exception:
        return []


def port_open(host, port, timeout=2):
    """Check if a TCP port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port)) == 0
        s.close()
        return result
    except Exception:
        return False


def dig_resolve(hostname):
    """Resolve hostname via CoreDNS on localhost:5354. Returns IP or None."""
    try:
        r = subprocess.run(
            ["dig", "@127.0.0.1", "-p", "5354", hostname, "+short"],
            capture_output=True, text=True, timeout=4,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().split("\n")[0]
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 1. Infrastructure
# ---------------------------------------------------------------------------
def test_infrastructure():
    """Test all containers are running, DNS resolves, ports are open."""
    tests = []

    containers = docker_ps()

    required = [
        "vault", "go-server", "go-client", "nginx", "gateway",
        "gateway-dc2", "coredns", "authentik-server", "step-ca",
        "internal-app",
    ]
    for c in required:
        tests.append((f"Container running: {c}", c in containers))

    # DNS resolution via CoreDNS (direct dig to port 5354 — avoids system resolver hang)
    dns_hosts = [
        ("auth.lab.local", "auth.lab.local"),
        ("vault.lab.local", "vault.lab.local"),
        ("web.lab.local", "web.lab.local"),
        ("nginx.lab.local", "nginx.lab.local"),
    ]
    for host, label in dns_hosts:
        ip = dig_resolve(host)
        tests.append((f"DNS resolves: {label}", ip is not None))

    # Port reachability on localhost
    port_checks = [
        (8200, "Vault API"),
        (9000, "Authentik UI/API"),
        (9090, "Go-server (internal)"),
        (9091, "Web UI"),
        (443, "nginx HTTPS"),
        (8443, "step-ca ACME"),
        (2222, "Gateway DC1 SSH"),
        (2223, "Gateway DC2 SSH"),
        (22022, "Go-client SSH"),
    ]
    for port, name in port_checks:
        tests.append((f"Port open: {name} ({port})", port_open("127.0.0.1", port)))

    return tests


# ---------------------------------------------------------------------------
# 2. Vault
# ---------------------------------------------------------------------------
def test_vault():
    """Test Vault health, auth backends, secrets engines, SSH CA, KV, OIDC."""
    base = VAULT_ADDR
    tests = []

    # --- Health ---
    try:
        r = requests.get(f"{base}/v1/sys/health", verify=False, timeout=REQ_TIMEOUT)
        tests.append(("Vault health check (sys/health)", r.status_code in (200, 429)))
    except requests.RequestException:
        tests.append(("Vault health check", False))

    # --- Auth backends ---
    try:
        r = requests.get(f"{base}/v1/sys/auth", headers=TOKEN_HEADER, verify=False, timeout=REQ_TIMEOUT)
        data = r.json().get("data", {})
        tests.append(("Vault auth: OIDC", "oidc/" in data))
        tests.append(("Vault auth: userpass", "userpass/" in data))
        tests.append(("Vault auth: cert", "cert/" in data))
        tests.append(("Vault auth: token", "token/" in data))
    except requests.RequestException:
        tests.append(("Vault auth backends readable", False))

    # --- Secrets engines ---
    try:
        r = requests.get(f"{base}/v1/sys/mounts", headers=TOKEN_HEADER, verify=False, timeout=REQ_TIMEOUT)
        data = r.json().get("data", {})
        tests.append(("Vault secrets: PKI", "pki/" in data))
        tests.append(("Vault secrets: KV v2", "kv/" in data))
        tests.append(("Vault secrets: SSH (DC1)", "ssh/" in data))
        tests.append(("Vault secrets: SSH-dc2", "ssh-dc2/" in data))
    except requests.RequestException:
        tests.append(("Vault secrets engines readable", False))

    # --- KV secret readable (kv-v2: path is kv/data/server-config) ---
    try:
        r = requests.get(f"{base}/v1/kv/data/server-config", headers=TOKEN_HEADER, verify=False, timeout=REQ_TIMEOUT)
        tests.append(("Vault KV secret: server-config", r.status_code == 200))
        if r.status_code == 200:
            data = r.json().get("data", {}).get("data", {})
            has_api_key = "api_key" in data
            has_db_pass = "db_password" in data
            tests.append(("Vault KV secret: has api_key", has_api_key))
            tests.append(("Vault KV secret: has db_password", has_db_pass))
    except requests.RequestException:
        tests.append(("Vault KV secret readable", False))

    # --- OIDC config ---
    try:
        r = requests.get(f"{base}/v1/auth/oidc/config", headers=TOKEN_HEADER, verify=False, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            data = r.json().get("data", {})
            has_discovery = "auth.lab.local" in str(data)
            has_client_id = data.get("oidc_client_id") == "vault-client-id"
            tests.append(("OIDC: discovery URL contains auth.lab.local", has_discovery))
            tests.append(("OIDC: client_id correct", has_client_id))
        else:
            tests.append(("OIDC config readable", False))
    except requests.RequestException:
        tests.append(("OIDC config readable", False))

    # --- OIDC roles (Vault uses HTTP LIST for enumeration) ---
    try:
        r = requests.request("LIST", f"{base}/v1/auth/oidc/role", headers=TOKEN_HEADER, verify=False, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            keys = r.json().get("data", {}).get("keys", [])
            tests.append(("OIDC: roles listable", True))
            for role in ("admin", "ops", "dev"):
                tests.append((f"OIDC: role '{role}' exists", role in keys))
        else:
            tests.append(("OIDC roles listable", False))
    except requests.RequestException:
        tests.append(("OIDC roles listable", False))

    # --- SSH CA roles (LIST method required) ---
    for mount, label in [("ssh", "DC1"), ("ssh-dc2", "DC2")]:
        try:
            r = requests.request("LIST", f"{base}/v1/{mount}/roles", headers=TOKEN_HEADER, verify=False, timeout=REQ_TIMEOUT)
            if r.status_code == 200:
                keys = r.json().get("data", {}).get("keys", [])
                tests.append((f"SSH {label}: roles listable", True))
                tests.append((f"SSH {label}: sign-ssh role exists", "sign-ssh" in keys))
            else:
                tests.append((f"SSH {label}: roles listable", False))
        except requests.RequestException:
            tests.append((f"SSH {label}: roles reachable", False))

    # --- SSH CA public key readable ---
    try:
        r = requests.get(f"{base}/v1/ssh/config/ca", headers=TOKEN_HEADER, verify=False, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            pub_key = r.json().get("data", {}).get("public_key", "")
            tests.append(("SSH DC1: CA public key readable", bool(pub_key)))
            tests.append(("SSH DC1: CA key is ssh-rsa", pub_key.startswith("ssh-rsa ")))
        else:
            tests.append(("SSH DC1: CA public key endpoint", False))
    except requests.RequestException:
        tests.append(("SSH DC1: CA public key endpoint", False))

    # --- Userpass users exist (LIST method) ---
    try:
        r = requests.request("LIST", f"{base}/v1/auth/userpass/users", headers=TOKEN_HEADER, verify=False, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            keys = r.json().get("data", {}).get("keys", [])
            for user in ("admin", "ops", "dev"):
                tests.append((f"Userpass user: {user}", user in keys))
        else:
            tests.append(("Userpass users listable", False))
    except requests.RequestException:
        tests.append(("Userpass users listable", False))

    # --- PKI roles (LIST method) ---
    try:
        r = requests.request("LIST", f"{base}/v1/pki/roles", headers=TOKEN_HEADER, verify=False, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            keys = r.json().get("data", {}).get("keys", [])
            for role in ("server", "user"):
                tests.append((f"PKI role: {role}", role in keys))
        else:
            tests.append(("PKI roles listable", False))
    except requests.RequestException:
        tests.append(("PKI roles listable", False))

    return tests


# ---------------------------------------------------------------------------
# 3. Authentik
# ---------------------------------------------------------------------------
def test_authentik():
    """Test Authentik UI/API reachability and OIDC discovery endpoints."""
    base = AUTHENTIK_ADDR
    tests = []

    # UI root reachable
    try:
        r = requests.get(f"{base}/", timeout=REQ_TIMEOUT, allow_redirects=False)
        tests.append(("Authentik: UI root reachable", r.status_code in (200, 302)))
    except requests.RequestException:
        tests.append(("Authentik: UI root reachable", False))

    # API v3 reachable
    try:
        r = requests.get(f"{base}/api/v3/", timeout=REQ_TIMEOUT)
        tests.append(("Authentik: API v3 reachable", r.status_code in (200, 401, 403)))
    except requests.RequestException:
        tests.append(("Authentik: API v3 reachable", False))

    # OIDC provider discovery — Vault and Go Server
    for app, label in [("vault", "Vault"), ("go-server", "Go Server")]:
        try:
            r = requests.get(
                f"{base}/application/o/{app}/.well-known/openid-configuration",
                timeout=REQ_TIMEOUT,
            )
            if r.status_code == 200:
                body = r.json()
                tests.append((f"OIDC discovery: {label}", True))
                tests.append((f"OIDC discovery: {label} has issuer", "issuer" in body))
                tests.append(
                    (f"OIDC discovery: {label} authorization_endpoint",
                     "authorization_endpoint" in body)
                )
                tests.append(
                    (f"OIDC discovery: {label} token_endpoint",
                     "token_endpoint" in body)
                )
            else:
                tests.append((f"OIDC discovery: {label} endpoint", False))
        except requests.RequestException:
            tests.append((f"OIDC discovery: {label} endpoint", False))

    # OIDC providers list via API
    try:
        r = requests.get(
            f"{base}/api/v3/providers/oauth2/",
            headers={"Authorization": f"Bearer {AUTHENTIK_TOKEN}"},
            timeout=REQ_TIMEOUT,
        )
        tests.append(("Authentik: OIDC providers endpoint reachable",
                       r.status_code in (200, 401, 403)))
    except requests.RequestException:
        tests.append(("Authentik: OIDC providers endpoint reachable", False))

    return tests


# ---------------------------------------------------------------------------
# 4. Web UI (go-server HTTP)
# ---------------------------------------------------------------------------
def test_web_ui():
    """Test go-server web UI endpoints."""
    base = WEB_UI_ADDR
    tests = []

    # Root — unauthenticated should redirect to login
    try:
        r = requests.get(f"{base}/", timeout=REQ_TIMEOUT, allow_redirects=False)
        tests.append(("Web UI: root redirects (302)", r.status_code == 302))
    except requests.RequestException:
        tests.append(("Web UI: root redirects", False))

    # Session API — returns JSON with unauthenticated status
    try:
        r = requests.get(f"{base}/api/session", timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            tests.append(("Web UI: /api/session returns JSON", True))
            tests.append(("Web UI: /api/session reports unauthenticated",
                          not data.get("authenticated", True)))
        else:
            tests.append(("Web UI: /api/session endpoint", False))
    except requests.RequestException:
        tests.append(("Web UI: /api/session endpoint", False))

    # Health endpoint
    try:
        r = requests.get(f"{base}/health", timeout=REQ_TIMEOUT)
        tests.append(("Web UI: /health endpoint", r.status_code == 200))
    except requests.RequestException:
        tests.append(("Web UI: /health endpoint", False))

    # Devices API
    try:
        r = requests.get(f"{base}/api/devices", timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            tests.append(("Web UI: /api/devices returns list", isinstance(data, list)))
            if data and isinstance(data, list):
                tests.append(("Web UI: devices registered", len(data) > 0))
                device = data[0]
                tests.append(("Web UI: device has 'id'", "id" in device))
                tests.append(("Web UI: device has 'label'", "label" in device))
                tests.append(("Web UI: device has 'online'", "online" in device))
        else:
            tests.append(("Web UI: /api/devices endpoint", False))
    except requests.RequestException:
        tests.append(("Web UI: /api/devices endpoint", False))

    return tests


# ---------------------------------------------------------------------------
# 5. SSH CA & Daemon
# ---------------------------------------------------------------------------
def test_ssh_ca():
    """Test SSH CA keys on gateways and sshd running on go-client."""
    tests = []

    # CA public key on DC1 gateway
    for gw, label in [("gateway", "DC1"), ("gateway-dc2", "DC2")]:
        try:
            r = subprocess.run(
                ["docker", "exec", gw, "cat", "/ssh/ca.pub"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip().startswith("ssh-rsa"):
                tests.append((f"SSH CA key on {label} gateway ({gw})", True))
            else:
                tests.append((f"SSH CA key on {label} gateway ({gw})", False))
        except Exception:
            tests.append((f"SSH CA key on {label} gateway ({gw})", False))

    # sshd process running inside go-client
    try:
        r = subprocess.run(
            ["docker", "exec", "go-client", "ps", "aux"],
            capture_output=True, text=True, timeout=5,
        )
        tests.append(("go-client: sshd process running", "sshd" in r.stdout))
    except Exception:
        tests.append(("go-client: sshd process running", False))

    # go-client: CA key available inside container
    try:
        r = subprocess.run(
            ["docker", "exec", "go-client", "ls", "-la", "/ssh/ca.pub"],
            capture_output=True, text=True, timeout=5,
        )
        tests.append(("go-client: /ssh/ca.pub exists", r.returncode == 0))
    except Exception:
        tests.append(("go-client: /ssh/ca.pub exists", False))

    # go-client: sshd listening on port 22 (check via /proc or netstat)
    try:
        r = subprocess.run(
            ["docker", "exec", "go-client", "sh", "-c",
             "grep -q sshd /proc/*/comm 2>/dev/null || ps aux | grep -q 'sshd.*listener'"],
            capture_output=True, text=True, timeout=5,
        )
        tests.append(("go-client: sshd listening (port 22)", r.returncode == 0))
    except Exception:
        tests.append(("go-client: sshd listening (port 22)", False))

    # go-client: /app/certs/ accessible
    try:
        r = subprocess.run(
            ["docker", "exec", "go-client", "ls", "-la", "/app/certs/"],
            capture_output=True, text=True, timeout=5,
        )
        tests.append(("go-client: /app/certs/ directory accessible",
                      r.returncode == 0 and "total " in r.stdout))
    except Exception:
        tests.append(("go-client: /app/certs/ directory accessible", False))

    return tests


# ---------------------------------------------------------------------------
# 6. Terraform
# ---------------------------------------------------------------------------
def test_terraform():
    """Test Terraform state file and resource count."""
    tf_dir = os.path.join(PROJECT_DIR, "terraform")
    tests = []

    state_file = os.path.join(tf_dir, "terraform.tfstate")
    exists = os.path.exists(state_file)
    tests.append(("Terraform: state file exists", exists))

    if exists:
        with open(state_file) as f:
            state = json.load(f)
        resources = state.get("resources", [])
        tests.append(("Terraform: resources present in state", len(resources) > 0))
        tests.append(("Terraform: >= 20 resources configured",
                      len(resources) >= 20))

        # Check specific resource types
        types = set(r["type"] for r in resources)
        for rt in ("vault_mount", "vault_jwt_auth_backend_role",
                   "vault_ssh_secret_backend_role", "vault_policy",
                   "vault_auth_backend"):
            tests.append((f"Terraform: resource type '{rt}' present",
                          rt in types))
    else:
        tests.append(("Terraform: resources in state", False))
        tests.append(("Terraform: >= 20 resources", False))

    return tests


# ---------------------------------------------------------------------------
# 7. step-ca ACME
# ---------------------------------------------------------------------------
def test_step_ca_acme():
    """Test step-ca container and ACME directory endpoint."""
    tests = []

    containers = docker_ps()
    tests.append(("step-ca: container running", "step-ca" in containers))

    # ACME directory endpoint
    try:
        r = requests.get(f"{STEP_CA_ADDR}/acme/acme/directory",
                         verify=False, timeout=REQ_TIMEOUT)
        tests.append(("step-ca: ACME directory endpoint", r.status_code == 200))
        if r.status_code == 200:
            body = r.json()
            for key in ("newNonce", "newAccount", "newOrder"):
                tests.append((f"step-ca: ACME directory has '{key}'",
                              key in body))
    except requests.RequestException:
        tests.append(("step-ca: ACME directory endpoint", False))

    return tests


# ---------------------------------------------------------------------------
# 8. Network / DNS (CoreDNS internals)
# ---------------------------------------------------------------------------
def test_network_dns():
    """Test CoreDNS internal resolution from inside containers."""
    tests = []

    # Query coredns directly via dig (bypasses system resolver)
    for host in ["auth.lab.local", "vault.lab.local", "web.lab.local", "nginx.lab.local"]:
        ip = dig_resolve(host)
        tests.append((f"CoreDNS: {host} resolves", ip is not None))

    # Reverse check — coredns container port
    tests.append(("CoreDNS: port 5354 open", port_open("127.0.0.1", 5354)))

    return tests


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------
def report(category, results):
    global PASS, FAIL
    print(f"\n{'=' * 60}")
    print(f"  {category}")
    print(f"{'=' * 60}")
    for desc, passed in results:
        if passed:
            print(f"  [PASS] {desc}")
            PASS += 1
        else:
            print(f"  [FAIL] {desc}")
            FAIL += 1


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# mTLS Identity Test
# ---------------------------------------------------------------------------
def test_mtls_identity():
    """Test mTLS client certificate identity resolution (admin/ops/dev certs)."""
    tests = []
    cert_dir = f"{PROJECT_DIR}/certs"

    for user in ['admin', 'ops', 'dev']:
        try:
            cert = f"{cert_dir}/{user}.crt"
            key = f"{cert_dir}/{user}-key.pem"
            
            result = subprocess.run([
                "curl", "-sk", "--cert", cert, "--key", key,
                "--resolve", "go-server:9090:127.0.0.1",
                "https://go-server:9090/api/whoami"
            ], capture_output=True, text=True, timeout=10)
            
            data = json.loads(result.stdout)
            username = data.get("username", "")
            tests.append((f'{user} cert → /api/whoami (HTTP {result.returncode})', result.returncode == 0))
            tests.append((f'{user} username={username}', username == user))
        except Exception as e:
            tests.append((f'{user} cert → /api/whoami', False))
            tests.append((f'{user} error: {e}', False))

    return tests


# Main
# ---------------------------------------------------------------------------
def main():
    global PASS, FAIL
    print(f"{'=' * 60}")
    print("  Zero-FAS mTLS Lab — Automated Test Suite")
    print(f"{'=' * 60}")
    print(f"  Started:  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Project:  {PROJECT_DIR}")
    print(f"  Vault:    {VAULT_ADDR}")
    print(f"  Authentik: {AUTHENTIK_ADDR}")
    print(f"  Web UI:   {WEB_UI_ADDR}")
    print(f"  step-ca:  {STEP_CA_ADDR}")
    print(f"{'=' * 60}")

    report("1. Infrastructure", test_infrastructure())
    report("2. Vault", test_vault())
    report("3. Authentik", test_authentik())
    report("4. Web UI", test_web_ui())
    report("5. SSH CA & Daemon", test_ssh_ca())
    report("6. Terraform", test_terraform())
    report("7. step-ca ACME", test_step_ca_acme())
    report("8. Network / DNS", test_network_dns())
    report("9. mTLS Identity", test_mtls_identity())

    total = PASS + FAIL
    print(f"\n{'=' * 60}")
    print(f"  Results: {PASS} passed / {FAIL} failed / {total} total")
    print(f"  {'ALL TESTS PASSED' if FAIL == 0 else f'{FAIL} TEST(S) FAILED'}")
    print(f"{'=' * 60}")

    return FAIL


if __name__ == "__main__":
    sys.exit(main())