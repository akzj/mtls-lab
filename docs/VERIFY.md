# Zero-FAS mTLS Lab — Verification Guide

## Prerequisites

- Docker stack deployed: `docker compose up -d` (from project root)

> **DNS Prerequisite**: All services use `*.lab.local` domain names via CoreDNS on port 5354.
> Ensure DNS is configured (`/etc/resolver/lab.local` → `127.0.0.1:5354`) or add entries to `/etc/hosts`.
> Commands below use domain names as primary; localhost fallbacks are noted where applicable.

- All services running or completed (see `docker compose ps`)

---

## 1. Service Status

```bash
cd /Users/one/workspace/vault

docker compose ps
```

Expected output (all 13+ services):

```
NAME                IMAGE                        STATUS
postgres            postgres:16-alpine            Up (healthy)
redis               redis:7-alpine                Up (healthy)
vault               hashicorp/vault:latest        Up (healthy)
vault-init          hashicorp/vault:latest        Exited (0)
authentik-server    authentik-server              Up
authentik-worker    authentik-worker              Up
step-ca             vault-step-ca                 Up
go-server           vault-go-server               Up
nginx               vault-nginx                   Up
go-client           vault-go-client               Up
gateway             vault-gateway                 Up
gateway-dc2         vault-gateway-dc2             Up
ssh-server          vault-ssh-server              Up
internal-app        vault-internal-app            Up
```

> `vault-init` is a placeholder (real init via `init-all.sh`). `go-client` is now a
> long-running ACME daemon (not one-shot). All other services should be `Up`.

---

## 2. Vault Initialization

### Check Vault health

```bash
# Vault uses dev-tls (HTTPS), so use -tls-skip-verify
docker compose exec vault vault status -tls-skip-verify
```

Expected output:
```
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    1
Threshold       1
Version         x.x.x
Build Date      ...
Storage Type    file
Cluster Name    ...
Cluster ID      ...
HA Enabled      false
```

### Check init-all.sh logs

The real Vault initialization is done by `scripts/init-all.sh` (not the vault-init container):

```bash
# Check the output from when you ran init-all.sh, or re-run to verify:
bash scripts/init-all.sh 2>&1 | tail -30
```

Expected output:
```
[4/6] Applying Terraform for Vault PKI + KV + OIDC + SSH...
  Waiting for OIDC discovery URL...
  Discovery URL ready ✅
  Resources imported ✅
  Terraform apply complete ✅
  OIDC config set ✅
  Role 'admin' created ✅
  Role 'ops' created ✅
  Role 'dev' created ✅
[5/6] Exporting SSH CA public keys...
  DC1 SSH CA key exported to gateway ✅
  DC2 SSH CA key exported to gateway-dc2 ✅
[6/6] Final verification...
  PKI engine
  kv engine
  ssh engine(s)
  oidc auth

=== Initialization Complete ===
Vault UI:     https://vault.lab.local:8200/ui (OIDC: admin/123123)
Authentik:    http://auth.lab.local:9000 (admin/123123)
Web UI:       http://web.lab.local:9091
SSH Gateway:  ssh gateway-user@vault.lab.local -p 2222
SSH Gateway DC2: ssh gateway-user@vault.lab.local -p 2223

Localhost fallback (no DNS):
  Vault UI:   https://localhost:8200/ui
  Authentik:  http://localhost:9000
  SSH:        ssh gateway-user@localhost -p 2222
```

### Verify KV secrets

```bash
docker compose exec vault vault kv get kv/server-config
```

Expected output:
```
=====  Metadata  =====
Key              Value
---              -----
created_time     ...
deletion_time    n/a
destroyed        false
version          1

======  Data  ======
Key              Value
---              -----
api_key          zero-fas-secret-12345
db_password      db-pass-98765
```

### Verify PKI intermediate

```bash
docker compose exec vault openssl x509 -in /certs/intermediate-vault-pki.crt -noout -subject -issuer
```

Expected output:
```
subject=CN = Vault PKI Intermediate CA
issuer=CN = Zero-FAS Root CA
```

### Verify Terraform State

```bash
# Check Terraform applied resources
docker compose exec vault vault secrets list -tls-skip-verify
```

Expected output includes:
```
Path          Type         Accessor              Description
----          ----         --------              -----------
kv/           kv-v2        ...                   KV v2 secrets engine
pki/          pki          ...                   PKI secrets engine
ssh/          ssh          ...                   SSH Certificate Authority (DC1)
ssh-dc2/      ssh          ...                   SSH Certificate Authority (DC2)
```

```bash
# Verify auth backends
docker compose exec vault vault auth list -tls-skip-verify
```

Expected output includes:
```
Path         Type      Accessor               Description
----         ----      --------               -----------
cert/        cert      ...                    TLS certificate authentication
oidc/        oidc      ...                    OIDC authentication via Authentik
token/       token     ...                    token based credentials
userpass/    userpass  ...                    Username/password authentication
```

### Verify OIDC Configuration

```bash
# Check OIDC backend config
docker compose exec vault vault read auth/oidc/config -tls-skip-verify
```

Expected output includes OIDC discovery URL pointing to Authentik and client credentials.

```bash
# Check OIDC roles
docker compose exec vault vault list auth/oidc/roles -tls-skip-verify
```

Expected output:
```
Keys
----
admin
dev
ops
```

---

## 3. nginx Verification

### Check nginx config

```bash
docker compose exec nginx nginx -t
```

Expected output:
```
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

### Check nginx is listening

```bash
docker compose exec nginx netstat -tlnp 2>/dev/null || docker compose exec nginx ss -tlnp
## 7. OIDC SSO Login Test

### Verify Authentik UI

```bash
# Open http://auth.lab.local:9000 in a browser
# Fallback (no DNS): http://localhost:9000
# Login with: admin / 123123
```

Expected: Authentik admin dashboard loads.

### Verify Vault OIDC Login

```bash
# Open https://vault.lab.local:8200/ui in a browser
# Fallback (no DNS): https://localhost:8200/ui
# Click "OIDC" login button
# Login with: admin / 123123
```

Expected: Vault UI loads with admin permissions (full access).

```bash
# Test OIDC login via CLI
docker compose exec vault vault login -tls-skip-verify \
  -method=oidc role=admin
```

Expected: Opens browser for OIDC authentication → returns Vault token.

### Verify User Groups and Policies

```bash
# Check mapped policies
docker compose exec vault vault read -tls-skip-verify auth/oidc/role/admin
```

Expected output:
```
Key                     Value
---                     -----
bound_audiences         [vault-client-id]
policies                [admin-policy]
token_ttl               3600
```

```bash
# Verify userpass users exist
docker compose exec vault vault list -tls-skip-verify auth/userpass/users
```

Expected:
```
Keys
----
admin
dev
ops
```

---

## 8. SSH CA Verification

### Verify SSH CA Configuration

```bash
# Check DC1 SSH CA
docker compose exec vault vault read -tls-skip-verify ssh/config/ca
```

Expected output includes a `public_key` field — the SSH CA public key for DC1.

```bash
# Check DC2 SSH CA
docker compose exec vault vault read -tls-skip-verify ssh-dc2/config/ca
```

Expected output includes a different `public_key` field (independent from DC1).

### Verify CA Key Export to Gateways

```bash
# Check DC1 gateway
docker compose exec gateway cat /ssh/ca.pub
```

Expected: SSH public key (starts with `ssh-rsa AAA...`).

```bash
# Check DC2 gateway
docker compose exec gateway-dc2 cat /ssh/ca.pub
```

Expected: Different SSH public key.

### Run SSH Demo

```bash
cd /Users/one/workspace/vault
bash scripts/ssh-demo.sh
```

Expected output:
```
=== Vault SSH Certificate Signing Demo ===
--- Step 1: Generating SSH key pair ---
--- Step 2: Signing public key with Vault SSH CA ---
  Serial: ...
  Signed certificate saved
--- Step 3: Verifying the certificate ---
  (certificate details)
--- Step 4: SSH login with signed certificate ---
  ✅ SSH LOGIN SUCCESSFUL with signed certificate!
  ✅ Certificate-based SSH login works!
--- Step 5: Certificate details ---
--- Step 6: Unsigned key would be rejected ---
=== Demo complete ===
```

### Manual SSH Test

```bash
# Generate a key pair
ssh-keygen -t rsa -b 2048 -f /tmp/test-ssh-key -N "" -q

# Sign with Vault SSH CA (DC1)
cat /tmp/test-ssh-key.pub | docker compose exec -T vault sh -c \
  "VAULT_ADDR=http://vault:8200 VAULT_TOKEN=root-token vault write -field=signed_key \
  ssh/sign/sign-ssh public_key=- valid_principals=gateway-user" > /tmp/test-ssh-key-cert.pub

# SSH to gateway via domain name (requires DNS)
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -i /tmp/test-ssh-key gateway-user@vault.lab.local -p 2222 \
  "echo 'SSH via signed cert works!'; hostname"

# Fallback (no DNS):
# ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
#   -i /tmp/test-ssh-key gateway-user@localhost -p 2222 \
#   "echo 'SSH via signed cert works!'; hostname"
```

Expected: Connection succeeds and shows gateway hostname.

---

## 9. step-ca ACME Verification

### Check step-ca logs

```bash
docker compose logs step-ca | grep -E "(listening|ACME|challenge)"
```

Expected: step-ca is listening on :8443 and has processed ACME requests from go-client.

### Verify go-client ACME cert

```bash
# Check ACME certificate details
docker compose exec go-client openssl x509 -in /app/data/acme-client.crt -noout -subject -issuer -dates
```

Expected:
```
subject=CN = go-client
issuer=CN = step-ca Intermediate CA
notBefore=...
notAfter=...
```

### Verify ACME Account

```bash
# Check ACME account key exists
docker compose exec go-client ls -la /app/data/
```

Expected:
```
total ...
-rw-------   1 root root  ... acme-account-key.pem
-rw-r--r--   1 root root  ... acme-client.crt
-rw-------   1 root root  ... acme-client-key.pem
``````

Expected output includes `0.0.0.0:443` in LISTEN state.

### Verify certificate files in container

```bash
docker compose exec nginx ls -la /certs/
docker compose exec nginx openssl x509 -in /certs/nginx.crt -noout -subject -issuer
```

Expected subject: `CN = nginx`, issuer: `CN = step-ca Intermediate CA`

---

## 4. Go Server Verification

### Check go-server logs

```bash
docker compose logs go-server
```

Expected output:
```
YYYY/MM/DD HH:MM:SS Go server starting on :9090 with mTLS
YYYY/MM/DD HH:MM:SS Vault config loaded: api_key=ze...45, db_password=db...65
```

The `Vault config loaded` line confirms the server read secrets from Vault successfully.
The masked values (`ze...45`, `db...65`) indicate the secrets were read and masked for logging.

### Verify server certificate

```bash
docker compose exec go-server openssl x509 -in /app/certs/server.crt -noout -subject -issuer
```

Expected output:
```
subject=CN = go-server
issuer=CN = Vault PKI Intermediate CA
```

---

## 5. Go Client (ACME Daemon) Verification

### Check go-client logs

```bash
docker compose logs go-client | grep -E "(ACME|Registration|Daemon|WS echo|Heartbeat|SSHD)"
```

Expected output includes:
```
[1/5] ACME certificate enrollment...
  Generating ACME account key (ECDSA P-256)...
  Registering ACME account...
  Account registered
  Generating certificate key (RSA 2048)...
  Creating ACME order...
  Accepting HTTP-01 challenge...
  Challenge validated!
  Certificate saved to /app/data/acme-client.crt
✅ ACME certificate obtained

[2/5] Device registration with go-server...
  Registered device_id=... ✅

[3/5] Configuring system OpenSSH daemon...
  SSHD config updated: TrustedUserCAKeys, PasswordAuthentication no
  OpenSSH daemon started
✅ OpenSSH daemon started on port 22

[4/5] Starting heartbeat loop (30s interval)...
✅ Daemon ready. Waiting for shutdown signal (Ctrl+C)

[5/5] Connecting to WebSocket echo through nginx...
WS echo connected through nginx:443
WS echo: [server-echo]: Heartbeat 0 from ACME client (...)
```

The daemon runs continuously:
- ACME cert auto-renews at 7-day threshold
- Heartbeat sent every 30s to go-server:9091
- WebSocket echo ping/pong every 60s through nginx:443
- SSH daemon accepts certificate-based connections on port 22

---

## 6. End-to-End Verification

### Full Chain Validation

```bash
# Root CA self-verification
openssl verify -CAfile certs/root-ca.crt certs/root-ca.crt

# step-ca intermediate
openssl verify -CAfile certs/root-ca.crt certs/intermediate-step-ca.crt

# Vault PKI intermediate
openssl verify -CAfile certs/root-ca.crt certs/intermediate-vault-pki.crt

# Leaf certs against trust chain
openssl verify -CAfile certs/trust-chain.crt certs/nginx.crt
openssl verify -CAfile certs/trust-chain.crt certs/server.crt
openssl verify -CAfile certs/trust-chain.crt certs/nginx-proxy.crt
openssl verify -CAfile certs/trust-chain.crt certs/client.crt
```

All should output `OK`.

### Verify Certificate Chain Depth

```bash
# Show full chain for client cert
openssl verify -CAfile certs/trust-chain.crt -show_chain certs/client.crt
```

Expected output shows a chain of depth 2 (leaf → intermediate → root):

```
client.crt: OK
Chain:
depth=0: CN = client
depth=1: CN = step-ca Intermediate CA
depth=2: CN = Zero-FAS Root CA
```

---

## 10. Manual mTLS Test (from host)

If you want to test the mTLS connection manually from your host machine:

```bash
# Test TLS handshake with client cert via nginx.lab.local (requires DNS)
openssl s_client -connect nginx.lab.local:443 \
  -cert certs/client.crt \
  -key certs/client-key.pem \
  -CAfile certs/ca-chain.crt \
  -verify_return_error \
  -tlsextdebug \
  -status

# Fallback (no DNS):
# echo "127.0.0.1 nginx" | sudo tee -a /etc/hosts
# openssl s_client -connect nginx:443 ...
```

Expected output includes:
```
```
SSL handshake has read ... bytes and written ... bytes
Verification: OK
```

To test WebSocket manually (using `websocat` or similar):

```bash
# Via domain name (requires DNS)
websocat wss://nginx.lab.local:443/ws \
  --cert certs/client.crt \
  --key certs/client-key.pem \
  --ca-file certs/ca-chain.crt \
  -v

# Fallback:
# websocat wss://nginx:443/ws --cert ... --key ... --ca-file ...
```

Type a message and press Enter — you should see the echoed response.

---

## 11. Security Verification

### Verify private key permissions

```bash
ls -la certs/*-key.pem
```

All private keys should be `-rw-------` (chmod 600).

### Verify key types and sizes

```bash
for f in certs/*-key.pem; do
  echo -n "$f: "
  openssl rsa -in "$f" -text -noout 2>/dev/null | head -1
done
```

All should be `Private-Key: (2048 bit)`.

### Verify YubiKey root CA key (host only)

```bash
yubico-piv-tool -a status | grep -A3 "Slot 9c"
```

Expected output shows slot 9C as:
```
Slot 9c: ... 
  Algorithm:      RSA2048
  (key is present, never extractable)
```

---

## 12. Cleanup Verification

```bash
# Check no containers remain
docker compose ps

# Should show nothing (or empty)
docker ps -a | grep vault
```

---

## Verification Checklist

| # | Check | Command | Expected |
|---|-------|---------|----------|
| 1 | Services running | `docker compose ps` | All 14 services Up |
| 2 | Vault healthy | `vault status -tls-skip-verify` | Initialized, Unsealed |
| 3 | KV secrets exist | `vault kv get kv/server-config` | api_key + db_password |
| 4 | init-all.sh complete | Run `bash scripts/init-all.sh` | All 6 steps ✅ |
| 5 | PKI imported | `openssl verify ...` | OK for all certs |
| 6 | nginx config OK | `nginx -t` | Syntax OK |
| 7 | nginx serving | `ss -tlnp` | Listening on :443 |
| 8 | Go server up | `logs go-server` | "Starting on :9090" |
| 9 | Vault config loaded | `logs go-server` | "config loaded" |
| 10 | Go client ACME | `logs go-client` | "ACME certificate obtained" |
| 11 | Go client daemon | `logs go-client` | "Daemon ready" |
| 12 | WebSocket echo | `logs go-client` | WS echo responses |
| 13 | OIDC auth enabled | `vault auth list` | oidc/ present |
| 14 | OIDC roles exist | `vault list auth/oidc/roles` | admin, ops, dev |
| 15 | Authentik UI | `http://auth.lab.local:9000` | Login page loads |
| 16 | Vault OIDC login | `https://vault.lab.local:8200/ui` | Login with admin/123123 |
| 17 | SSH CA configured | `vault read ssh/config/ca` | public_key present |
| 18 | SSH CA (DC2) | `vault read ssh-dc2/config/ca` | Different public_key |
| 19 | SSH demo | `bash scripts/ssh-demo.sh` | SSH login successful |
| 20 | SSH gateway | `ssh -p 2222` with signed cert | Connection succeeds |
| 21 | CA key exported | `gateway cat /ssh/ca.pub` | SSH public key |
| 22 | ACME cert | `openssl x509 -in ...` | CN=go-client, step-ca issuer |
| 23 | Terraform applied | `vault secrets list` | pki, kv, ssh, ssh-dc2 |
| 24 | mTLS cert chain | `openssl verify` | OK (depth 3) |
| 25 | Key permissions | `ls -la *-key.pem` | chmod 600 |
| 26 | YubiKey slot | `yubico-piv-tool` | RSA2048 present |

If all 26 checks pass, the Zero-FAS mTLS lab is fully operational.
