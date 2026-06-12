# Zero-FAS mTLS Lab — Verification Guide

## Prerequisites

- Docker stack deployed: `docker compose up -d` (from project root)
- All services running or completed (see `docker compose ps`)

---

## 1. Service Status

```bash
cd /Users/one/workspace/vault

docker compose ps
```

Expected output (all services running or exited with code 0):

```
NAME                IMAGE                        STATUS
vault               hashicorp/vault:latest        Up (healthy)
vault-init          hashicorp/vault:latest        Exited (0)
go-server           vault-go-server               Up
nginx               vault-nginx                   Up
go-client           vault-go-client               Exited (0)
```

> `vault-init` and `go-client` are one-shot services that exit after completion.
> Exit code 0 = success.

---

## 2. Vault Initialization

### Check Vault health

```bash
docker compose exec vault vault status
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

### Check vault-init logs

```bash
docker compose logs vault-init
```

Expected output includes:
```
=== Zero-FAS Vault Initialization ===
VAULT_ADDR=http://vault:8200
Vault is ready.
--- 1. Enabling PKI secrets engine ---
Success!
--- 2. Importing Vault PKI intermediate ---
Success!
--- 3. Creating server certificate role ---
Success!
--- 4. Enabling KV secrets engine ---
Success!
--- 5. Writing test secrets ---
Success! Data written to: kv/data/server-config
--- 6. Configuring AppRole authentication ---
Success!
=== Vault initialization complete ===
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

### Verify AppRole configuration

```bash
docker compose exec vault vault read auth/approle/role/server/role-id
```

Expected output:
```
Key      Value
---      -----
role_id  ... (a UUID)
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
```

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

## 5. Go Client Verification

### Check go-client logs

```bash
docker compose logs go-client
```

Expected output:
```
YYYY/MM/DD HH:MM:SS Connecting to wss://nginx:443/ws
YYYY/MM/DD HH:MM:SS Sending: Hello from Go client!
YYYY/MM/DD HH:MM:SS Received: [server-echo]: Hello from Go client!
YYYY/MM/DD HH:MM:SS Sending: mTLS is working!
YYYY/MM/DD HH:MM:SS Received: [server-echo]: mTLS is working!
YYYY/MM/DD HH:MM:SS Sending: Ping from Zero-FAS Lab
YYYY/MM/DD HH:MM:SS Received: [server-echo]: Ping from Zero-FAS Lab
YYYY/MM/DD HH:MM:SS ✅ All messages exchanged successfully!
--- CLIENT COMPLETED SUCCESSFULLY ---
```

The `✅ All messages exchanged successfully!` line confirms the full mTLS WebSocket
round-trip worked: client → nginx → server → nginx → client.

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

## 7. Manual mTLS Test (from host)

If you want to test the mTLS connection manually from your host machine:

```bash
# Add nginx to /etc/hosts if needed
echo "127.0.0.1 nginx" | sudo tee -a /etc/hosts

# Test TLS handshake with client cert
openssl s_client -connect nginx:443 \
  -cert certs/client.crt \
  -key certs/client-key.pem \
  -CAfile certs/ca-chain.crt \
  -verify_return_error \
  -tlsextdebug \
  -status
```

Expected output includes:
```
SSL handshake has read ... bytes and written ... bytes
Verification: OK
```

To test WebSocket manually (using `websocat` or similar):

```bash
websocat wss://nginx:443/ws \
  --cert certs/client.crt \
  --key certs/client-key.pem \
  --ca-file certs/ca-chain.crt \
  -v
```

Type a message and press Enter — you should see the echoed response.

---

## 8. Security Verification

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

## 9. Cleanup Verification

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
| 1 | Services running | `docker compose ps` | vault Up, others OK |
| 2 | Vault healthy | `vault status` | Initialized, Unsealed |
| 3 | KV secrets exist | `vault kv get kv/server-config` | api_key + db_password |
| 4 | vault-init complete | `logs vault-init` | "Vault init complete" |
| 5 | PKI imported | `openssl verify ...` | OK for all certs |
| 6 | nginx config OK | `nginx -t` | Syntax OK |
| 7 | nginx serving | `ss -tlnp` | Listening on :443 |
| 8 | Go server up | `logs go-server` | "Starting on :9090" |
| 9 | Vault config loaded | `logs go-server` | "config loaded" |
| 10 | Client connected | `logs go-client` | "All messages exchanged" |
| 11 | WebSocket echo | `logs go-client` | Received: [server-echo] |
| 12 | mTLS cert chain | `openssl verify` | OK (depth 3) |
| 13 | Key permissions | `ls -la *-key.pem` | chmod 600 |
| 14 | YubiKey slot | `yubico-piv-tool` | RSA2048 present |

If all 14 checks pass, the Zero-FAS mTLS lab is fully operational.
