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
| `yubico-piv-tool` | 2.7.3 | YubiKey PIV key generation |
| `yubico-piv-tool` | — | PIN/PUK management |
| `opensc` / `pkcs11-tool` | 0.27.1 | PKCS#11 signing operations |
| `openssl` | 3.6.2 | Certificate creation and verification |
| `python3` | 3.x | CSR signing script |
| `cryptography` | (pip) | Python crypto library for DER construction |

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

## Step 1: Initialize Root CA on YubiKey

> ⚠️ **This will generate a new RSA 2048 key on YubiKey PIV slot 9C.**
> Only run once, or if you need to regenerate the root.

```bash
cd /Users/one/workspace/vault

# Ensure YubiKey is inserted
yubico-piv-tool -a status

# Run the root CA setup script
bash scripts/01-init-root-ca.sh
```

This script:
1. Generates an RSA 2048 key **on the YubiKey** (slot 9C) — key never leaves hardware
2. Creates the root CA self-signed certificate using `DER` construction (workaround for
   `yubico-piv-tool 2.7.3` `selfsign-certificate` bug)
3. Outputs: `certs/root-ca.crt`, `certs/root-ca.der`, `certs/root-ca.pub`

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

# Build all services
docker compose build

# Verify images exist
docker images | grep -E "(go-server|go-client|nginx)"
```

---

## Step 4: Deploy the Stack

```bash
# Start all services
docker compose up -d

# Watch initialization order:
# 1. vault starts (health check runs)
# 2. vault-init runs PKI + KV + AppRole setup
# 3. go-server starts (reads Vault secrets)
# 4. nginx starts (reverse proxy)
# 5. go-client connects, sends messages, exits

# Follow logs
docker compose logs -f
```

---

## Step 5: Verify Deployment

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

## Step 6: Clean Up

```bash
# Stop and remove containers
docker compose down

# Remove containers + volumes
docker compose down -v

# Remove images
docker compose down --rmi all

# Remove everything including build cache
docker compose down --rmi all -v
```

---

## Troubleshooting

### Vault health check fails

```bash
# Check vault logs
docker compose logs vault

# Verify vault is accessible
curl -s http://localhost:8200/v1/sys/health
```

### vault-init fails

```bash
# Check vault-init logs
docker compose logs vault-init

# Common issues:
# - VAULT_TOKEN not set correctly
# - Vault not yet healthy
# - Script path wrong (expects /scripts/02-init-vault.sh)
# - Certificate files not mounted

# Manually run vault-init
docker compose run --rm vault-init \
  /bin/sh -c "vault login root-token && /scripts/02-init-vault.sh"
```

### nginx fails to start

```bash
# Check nginx config syntax
docker compose run --rm nginx nginx -t

# Check nginx logs
docker compose logs nginx
```

### Go server can't connect to Vault

```bash
# Verify environment
docker compose exec go-server env | grep VAULT

# Test Vault connectivity
docker compose exec go-server wget -qO- http://vault:8200/v1/sys/health
```

### mTLS handshake fails

```bash
# Verify certificate files exist in container
docker compose exec nginx ls -la /certs/

# Check certificate chain order
docker compose exec nginx openssl verify -CAfile /certs/ca-chain.crt /certs/client.crt
```
