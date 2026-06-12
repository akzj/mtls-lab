#!/bin/sh
# 03-init-users.sh — Create Vault users with path isolation demo
set -e

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:?VAULT_TOKEN must be set}"
export VAULT_ADDR VAULT_TOKEN

echo "=== Zero-FAS Vault User Setup ==="

echo ""
echo "--- 1. Enabling userpass auth ---"
vault auth enable userpass 2>/dev/null || echo "  (already enabled, continuing)"

echo ""
echo "--- 2. Writing policies ---"
vault policy write admin /vault/policies/admin-policy.hcl
echo "  admin-policy written."
vault policy write ops /vault/policies/ops-policy.hcl
echo "  ops-policy written."
vault policy write dev /vault/policies/dev-policy.hcl
echo "  dev-policy written."

echo ""
echo "--- 3. Creating users ---"
vault write auth/userpass/users/admin password=admin123 token_policies=admin
echo "  admin created."
vault write auth/userpass/users/ops password=ops123 token_policies=ops
echo "  ops created."
vault write auth/userpass/users/dev password=dev123 token_policies=dev
echo "  dev created."

echo ""
echo "--- 4. Creating test secrets ---"
vault kv put kv/production/db_password value="prod-db-secret-98765"
echo "  kv/production/db_password written."
vault kv put kv/production/api_key value="prod-api-key-ABC123"
echo "  kv/production/api_key written."
vault kv put kv/staging/api_key value="staging-api-key-XYZ789"
echo "  kv/staging/api_key written."
vault kv put kv/staging/db_password value="staging-db-pass-456"
echo "  kv/staging/db_password written."
vault kv put kv/dev/api_key value="dev-api-key-001"
echo "  kv/dev/api_key written."
vault kv put kv/dev/notes value="dev-notes: this is a playground"
echo "  kv/dev/notes written."

echo ""
echo "=== Vault user setup complete ==="
echo "Users: admin/admin123 (full), ops/ops123 (prod r + staging/dev rw), dev/dev123 (dev r)"
