#!/bin/sh
# 02-init-vault.sh — Initialize Vault with PKI, KV, secrets, and cert auth
set -e

export VAULT_SKIP_VERIFY=true
CERTS_DIR="/certs"

echo "=== Zero-FAS Vault Initialization ==="
echo "VAULT_ADDR=${VAULT_ADDR}"

# --------------------------------------------------
# 1. Enable PKI secrets engine
# --------------------------------------------------
echo ""
echo "--- 1. Enabling PKI secrets engine ---"
vault secrets enable -path=pki pki 2>/dev/null || echo "  (already enabled, continuing)"

# --------------------------------------------------
# 2. Import Vault PKI intermediate certificate and key
# --------------------------------------------------
echo ""
echo "--- 2. Importing Vault PKI intermediate ---"
INTERMEDIATE_CERT="${CERTS_DIR}/intermediate-vault-pki.crt"
INTERMEDIATE_KEY="${CERTS_DIR}/intermediate-vault-pki-key.pem"

PEM_BUNDLE=$(cat "${INTERMEDIATE_CERT}")
echo "" > /tmp/bundle.pem
echo "${PEM_BUNDLE}" > /tmp/bundle.pem
cat "${INTERMEDIATE_KEY}" >> /tmp/bundle.pem

vault write -format=json pki/config/ca pem_bundle=@/tmp/bundle.pem
echo "  Intermediate CA imported."

vault write pki/config/urls \
  issuing_certificates="${VAULT_ADDR}/v1/pki/ca" \
  crl_distribution_points="${VAULT_ADDR}/v1/pki/crl"

# --------------------------------------------------
# 3. Create a role for issuing server certs
# --------------------------------------------------
echo ""
echo "--- 3. Creating server certificate role ---"
vault write pki/roles/server \
  allow_any_name=true max_ttl=8760h key_type=rsa key_bits=2048 \
  server_flag=true client_flag=false require_cn=false
echo "  Role 'server' created."

# --------------------------------------------------
# 4. Enable KV secrets engine
# --------------------------------------------------
echo ""
echo "--- 4. Enabling KV secrets engine ---"
vault secrets enable -path=kv kv-v2 2>/dev/null || echo "  (already enabled, continuing)"

# --------------------------------------------------
# 5. Write test secret
# --------------------------------------------------
echo ""
echo "--- 5. Writing test secrets ---"
vault kv put kv/server-config \
  api_key="zero-fas-secret-12345" db_password="db-pass-98765"
echo "  Secret kv/server-config written."

# --------------------------------------------------
# 6. Create server policy
# --------------------------------------------------
echo ""
echo "--- 6. Creating server policy ---"
vault policy write server-policy /vault/policies/server-policy.hcl
echo "  Policy 'server-policy' written."

# --------------------------------------------------
# 7. Configure TLS certificate authentication
# --------------------------------------------------
echo ""
echo "--- 7. Configuring TLS certificate authentication ---"
vault auth enable cert 2>/dev/null || echo "  (already enabled, continuing)"

vault write auth/cert/certs/go-server \
  display_name=go-server \
  policies=server-policy \
  certificate=@${CERTS_DIR}/trust-chain.crt \
  allowed_common_names=go-server
echo "  TLS cert auth configured for CN=go-server → server-policy"

echo ""
echo "=== Vault initialization complete ==="
