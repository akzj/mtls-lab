# Zero-FAS mTLS Lab — Setup Guide

## Prerequisites

### Hardware
- **YubiKey 5C Nano** (or compatible PIV token) inserted into USB port
- macOS (ARM64 tested; Intel should also work)

### Software
| Tool | Version (tested) | Purpose |
|------|-----------------|---------|
| Docker Desktop | latest | Container runtime |
| `docker compose` | v2.x | Multi-container orchestration |
| `yubico-piv-tool` | 2.7.3 | YubiKey PIV key generation/import |
| `opensc` / `pkcs11-tool` | 0.27.1 | PKCS#11 signing operations |
| `openssl` | 3.6.2 | Certificate creation and verification |
| `python3` | 3.x | CSR signing script (`sign-intermediate.py`) |
| `cryptography` | (pip) | Python crypto library for DER construction |
| `terraform` | >= 1.0 | Vault configuration management (IaC) |

### Install Dependencies (macOS)

```bash
# Install YubiKey tools
brew install yubico-piv-tool ykman

# Install OpenSC for pkcs11-tool
brew install opensc

# Install Python cryptography library
pip3 install cryptography
```

---

## Step 1: Initialize Root CA

> ⚠️ **This creates an RSA 2048 Root CA: OpenSSL key generation → backup → YubiKey import.**
> The software key backup is retained at `root-ca/root-ca-key.pem` for disaster recovery.
> Only run once, or if you need to regenerate the root.

```bash
cd /Users/one/workspace/vault

# Ensure YubiKey is inserted
yubico-piv-tool -a status

# Run the root CA setup script
bash scripts/01-init-root-ca.sh
```

This script:
1. Generates an RSA 2048 key with OpenSSL (saves backup to `root-ca/root-ca-key.pem`)
2. Creates a self-signed root CA certificate with CA extensions
3. Extracts public key and converts to DER format
4. Verifies the certificate self-signature
5. Imports the private key into YubiKey PIV slot 9C
6. Writes the certificate to YubiKey slot 9C
7. Verifies the certificate on the YubiKey

### Verify Root CA

```bash
openssl x509 -in certs/root-ca.crt -text -noout
openssl verify -CAfile certs/root-ca.crt certs/root-ca.crt
```

---

## Step 2: Generate Intermediate CAs and Leaf Certificates

Two intermediate CAs must be generated and signed by the root CA on YubiKey.

### Generate and Sign step-ca Intermediate

```bash
# Generate intermediate key and CSR
openssl req -new \
  -config root-ca/intermediate-step-ca-openssl.cnf \
  -keyout certs/intermediate-step-ca-key.pem \
  -out certs/intermediate-step-ca.csr

# Sign with Root CA (requires YubiKey + PIN)
python3 scripts/sign-intermediate.py \
  --subject "/CN=step-ca Intermediate CA" \
  --serial 0x02 \
  --days 1825 \
  --ca-key-slot 9c \
  --ca-cert certs/root-ca.crt \
  --out-key certs/intermediate-step-ca-key.pem \
  --out-cert certs/intermediate-step-ca.crt \
  --out-csr certs/intermediate-step-ca.csr \
  --pathlen 0

chmod 600 certs/intermediate-step-ca-key.pem
```

### Generate and Sign Vault PKI Intermediate

```bash
openssl req -new \
  -config root-ca/intermediate-vault-pki-openssl.cnf \
  -keyout certs/intermediate-vault-pki-key.pem \
  -out certs/intermediate-vault-pki.csr

python3 scripts/sign-intermediate.py \
  --subject "/CN=Vault PKI Intermediate CA" \
  --serial 0x03 \
  --days 1825 \
  --ca-key-slot 9c \
  --ca-cert certs/root-ca.crt \
  --out-key certs/intermediate-vault-pki-key.pem \
  --out-cert certs/intermediate-vault-pki.crt \
  --out-csr certs/intermediate-vault-pki.csr \
  --pathlen 0

chmod 600 certs/intermediate-vault-pki-key.pem
```

### Generate and Sign Leaf Certificates

**nginx server certificate:**

```bash
openssl genrsa -out certs/nginx-key.pem 2048
chmod 600 certs/nginx-key.pem

# Create CSR config for nginx
cat > /tmp/nginx-ext.cnf << 'EOF'
[v3_ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @san
[san]
DNS.1 = nginx
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -new -key certs/nginx-key.pem \
  -subj "/CN=nginx" -out certs/nginx.csr

# Sign with step-ca intermediate
openssl x509 -req -in certs/nginx.csr \
  -CA certs/intermediate-step-ca.crt \
  -CAkey certs/intermediate-step-ca-key.pem \
  -CAcreateserial \
  -out certs/nginx.crt -days 365 \
  -extfile /tmp/nginx-ext.cnf -extensions v3_ext
```

**nginx-proxy certificate (mTLS client auth for upstream):**

```bash
openssl genrsa -out certs/nginx-proxy-key.pem 2048
chmod 600 certs/nginx-proxy-key.pem

openssl req -new -key certs/nginx-proxy-key.pem \
  -subj "/CN=nginx-proxy" -out certs/nginx-proxy.csr

openssl x509 -req -in certs/nginx-proxy.csr \
  -CA certs/intermediate-step-ca.crt \
  -CAkey certs/intermediate-step-ca-key.pem \
  -CAcreateserial \
  -out certs/nginx-proxy.crt -days 365 \
  -extfile <(echo "extendedKeyUsage = clientAuth")
```

**Client certificate:**

```bash
openssl genrsa -out certs/client-key.pem 2048
chmod 600 certs/client-key.pem

openssl req -new -key certs/client-key.pem \
  -subj "/CN=client" -out certs/client.csr

openssl x509 -req -in certs/client.csr \
  -CA certs/intermediate-step-ca.crt \
  -CAkey certs/intermediate-step-ca-key.pem \
  -CAcreateserial \
  -out certs/client.crt -days 365 \
  -extfile <(echo "extendedKeyUsage = clientAuth")
```

**Go server certificate:**

```bash
openssl genrsa -out certs/server-key.pem 2048
chmod 600 certs/server-key.pem

cat > /tmp/server-ext.cnf << 'EOF'
[v3_ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @san
[san]
DNS.1 = go-server
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -new -key certs/server-key.pem \
  -subj "/CN=go-server" -out certs/server.csr

# Sign with Vault PKI intermediate
openssl x509 -req -in certs/server.csr \
  -CA certs/intermediate-vault-pki.crt \
  -CAkey certs/intermediate-vault-pki-key.pem \
  -CAcreateserial \
  -out certs/server.crt -days 365 \
  -extfile /tmp/server-ext.cnf -extensions v3_ext
```

### Build Trust Chains

```bash
# ca-chain: step-ca intermediate + root
cat certs/intermediate-step-ca.crt certs/root-ca.crt > certs/ca-chain.crt

# trust-chain: vault PKI intermediate + root
cat certs/intermediate-vault-pki.crt certs/root-ca.crt > certs/trust-chain.crt
```

### Verify All Certificates

```bash
# Root CA self-verification
openssl verify -CAfile certs/root-ca.crt certs/root-ca.crt

# Intermediate CAs
openssl verify -CAfile certs/root-ca.crt certs/intermediate-step-ca.crt
openssl verify -CAfile certs/root-ca.crt certs/intermediate-vault-pki.crt

# Leaf certs against their chains
openssl verify -CAfile certs/trust-chain.crt certs/nginx.crt
openssl verify -CAfile certs/trust-chain.crt certs/server.crt
openssl verify -CAfile certs/trust-chain.crt certs/client.crt
```

---

## Step 3: Build Docker Images

```bash
cd /Users/one/workspace/vault

# Build all 13+ services
docker compose build

# Verify images exist
docker images | grep -E "(go-server|go-client|nginx|step-ca|gateway|ssh-server|internal-app)"
```

---

## Step 4: Deploy the Stack

```bash
# Start all services
docker compose up -d

# Watch initialization (services start in dependency order)
docker compose logs -f
```

Initialization order:
1. Vault starts (dev-tls mode, HTTPS, health check runs)
2. PostgreSQL + Redis start (Authentik dependencies)
3. vault-init runs (placeholder — real init is via init-all.sh)
4. Authentik server + worker start (OIDC identity provider)
5. step-ca starts (ACME certificate authority)
6. go-server starts (reads Vault secrets via VAULT_TOKEN)
7. nginx starts (reverse proxy)
8. go-client starts (ACME enrollment → device registration → SSH → heartbeat → WS echo)
9. Gateway + ssh-server start (SSH bastions)

---

## Step 5: One-Click Initialization

After all services are running, run the initialization script that configures Vault
(PKI, KV, policies, auth), Authentik (OIDC), and SSH CA (DC1 + DC2).

```bash
cd /Users/one/workspace/vault

# Run one-click init (Terraform + Authentik config + SSH CA export)
bash scripts/init-all.sh
```

This script performs:

| Step | Action | Details |
|------|--------|---------|
| [1] | Wait for Vault | Polls `https://localhost:8200/v1/sys/health` |
| [2] | Wait for Authentik | Polls `http://localhost:9000/api/v3/` |
| [3] | Initialize Authentik | Creates groups (admin/ops/dev), users, OIDC provider, Application |
| [4] | Apply Terraform | Runs `terraform apply` in `terraform/` directory for PKI, KV, auth, OIDC, SSH |
| [5] | Export SSH CA keys | Copies DC1 + DC2 CA public keys to gateway Docker volumes |
| [6] | Final verification | Checks PKI, KV, SSH, OIDC engines are configured |

Expected output:
```
=== mTLS Lab: Full Initialization ===
[1/6] Waiting for Vault... Vault ready ✅
[2/6] Waiting for Authentik... Authentik ready ✅
[3/6] Initializing Authentik... Done
[4/6] Applying Terraform for Vault PKI + KV + OIDC + SSH... Done
[5/6] Exporting SSH CA public keys... Done
[6/6] Final verification... PKI KV SSH OIDC
=== Initialization Complete ===
Vault UI:     https://localhost:8200/ui
Authentik:    http://localhost:9000
SSH Gateway:  ssh gateway-user@localhost -p 2222
```

---

## Step 6: Verify Deployment

See [VERIFY.md](VERIFY.md) for detailed verification steps.

Quick checks:

```bash
# All services running
docker compose ps

# Vault initialization completed
docker compose logs vault-init

# Go client successfully connected
docker compose logs go-client

# Go server is serving
docker compose logs go-server
```

---

## Step 7: Clean Up

```bash
# Stop and remove containers
docker compose down

# Remove containers + volumes (including SSH CA volumes, Authentik data)
docker compose down -v

# Remove images
docker compose down --rmi all

# Remove everything including build cache
docker compose down --rmi all -v

# Clean Terraform state (if re-initializing)
cd terraform && rm -rf .terraform .terraform.lock.hcl terraform.tfstate* 2>/dev/null; cd ..
```

---

## Troubleshooting

### Vault health check fails

```bash
# Check vault logs
docker compose logs vault

# Vault now uses dev-tls (HTTPS). Use skip-verify:
curl -sk https://localhost:8200/v1/sys/health

# Check vault status inside container
docker compose exec vault vault status -tls-skip-verify
```

### init-all.sh fails

```bash
# Check vault-init is placeholder only — real init happens on host
bash scripts/init-all.sh -x  # Run with debug output for diagnosis

# Common issues:
# - Vault not yet healthy (wait longer)
# - Authentik not fully initialized (PostgreSQL/Redis not ready)
# - Terraform import conflicts (already exists errors)
# - OIDC timing: Authentik OIDC provider not yet ready when Terraform runs

# Run Terraform manually:
cd terraform
export VAULT_ADDR=https://localhost:8200
export VAULT_SKIP_VERIFY=true
export VAULT_TOKEN=root-token
terraform init
terraform plan -var="vault_token=root-token" -var="certs_dir=$PWD/../certs"
terraform apply -auto-approve -var="vault_token=root-token" -var="certs_dir=$PWD/../certs"
```

### Authentik login fails

```bash
# Check Authentik logs
docker compose logs authentik-server

# Verify Authentik API
curl -s http://localhost:9000/api/v3/

# Re-run Authentik init
docker cp scripts/create_ak_config.py authentik-server:/create_ak_config.py
docker exec authentik-server python3 /create_ak_config.py
```

### SSH gateway connection fails

```bash
# Check gateway logs
docker compose logs gateway

# Verify SSH CA public key exported
docker compose exec gateway cat /ssh/ca.pub

# Re-export CA key manually:
docker compose exec vault vault read -field=public_key ssh/config/ca | \
  docker compose exec -T gateway sh -c "cat > /ssh/ca.pub"
```
