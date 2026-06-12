#!/bin/bash
# One-click initialization for mTLS Lab
# Run from the host after: docker compose up -d

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== mTLS Lab: Full Initialization ==="

echo "[1/5] Waiting for Vault..."
while ! curl -sk https://localhost:8200/v1/sys/health >/dev/null 2>&1; do sleep 2; done
echo "  Vault ready ✅"

echo "[2/5] Waiting for Authentik..."
while ! curl -s http://localhost:9000/api/v3/ >/dev/null 2>&1; do sleep 2; done
echo "  Authentik ready ✅"

echo "[3/5] Initializing Authentik..."
docker cp "$SCRIPT_DIR/create_ak_config.py" authentik-server:/create_ak_config.py
docker exec authentik-server /ak-root/venv/bin/python3 \
  /create_ak_config.py 2>&1 | grep -E "Group:|User:|OIDC|Signing|Application|Done" | sed 's/^/  /'
echo "  Authentik init complete ✅"

echo "[4/5] Applying Terraform for Vault PKI + KV + OIDC..."
cd "$PROJECT_DIR/terraform"
export VAULT_ADDR=https://localhost:8200
export VAULT_TOKEN=root-token
export VAULT_SKIP_VERIFY=true
terraform init -upgrade >/dev/null 2>&1

# Import existing resources to avoid "already exists" errors
echo "  Importing existing Vault resources..."
for res in \
  "vault_mount.pki pki" "vault_mount.kv kv" \
  "vault_policy.admin admin-policy" "vault_policy.ops ops-policy" \
  "vault_policy.dev dev-policy" "vault_policy.server server-policy" \
  "vault_auth_backend.cert cert" "vault_jwt_auth_backend.oidc oidc"
do
  tf="${res%% *}"; vp="${res##* }"
  terraform import -var="vault_token=root-token" \
    -var="certs_dir=$PROJECT_DIR/certs" \
    -var="policies_dir=$PROJECT_DIR/vault/policies" \
    "$tf" "$vp" 2>/dev/null || true
done
echo "  Resources imported ✅"

terraform apply -auto-approve \
  -var="vault_token=root-token" \
  -var="certs_dir=$PROJECT_DIR/certs" \
  -var="policies_dir=$PROJECT_DIR/vault/policies" 2>&1 || true
echo "  Terraform apply complete ✅"

# OIDC CLI fallback (if Terraform OIDC step failed due to timing)
VAULT_ADDR=https://localhost:8200 VAULT_SKIP_VERIFY=true vault write auth/oidc/config   oidc_discovery_url=http://auth.local:9000/application/o/vault/   oidc_client_id=vault-client-id   oidc_client_secret=vault-client-secret   default_role=dev 2>/dev/null && echo "  OIDC config set ✅" || true
for role in admin ops dev; do
  VAULT_ADDR=https://localhost:8200 VAULT_SKIP_VERIFY=true vault write auth/oidc/role/$role     allowed_redirect_uris="http://localhost:8200/oidc/callback,https://localhost:8200/oidc/callback,http://localhost:8200/ui/vault/auth/oidc/oidc/callback,https://localhost:8200/ui/vault/auth/oidc/oidc/callback,http://localhost:8200/v1/auth/oidc/oidc/callback,https://localhost:8200/v1/auth/oidc/oidc/callback"     bound_audiences=vault-client-id     user_claim=sub     oidc_scopes=openid     policies=${role}-policy 2>/dev/null && echo "  Role '${role}' created ✅" || true
done

echo "Creating userpass users for multi-user demo..."
for user_info in "admin admin123 admin-policy" "ops ops123 ops-policy" "dev dev123 dev-policy"; do
  read -r user pass policy <<< "$user_info"
  docker exec -e VAULT_SKIP_VERIFY=true vault vault write \
    auth/userpass/users/$user password=$pass token_policies=$policy 2>/dev/null && \
    echo "  User '$user' created (policy: $policy) ✅" || \
    echo "  User '$user' already exists (skipped)"
done

echo ""
echo "=== Initialization Complete ==="
echo "Vault UI:     https://localhost:8200/ui (OIDC: admin/123123)"
echo "Authentik:    http://localhost:9000 (admin/123123)"
echo "Web UI:       http://localhost:9091"
