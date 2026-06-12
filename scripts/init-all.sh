#!/bin/bash
# One-click initialization for mTLS Lab
# Run from the host after: docker compose up -d

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== mTLS Lab: Full Initialization ==="

echo "[1/6] Waiting for Vault..."
while ! curl -sk https://localhost:8200/v1/sys/health >/dev/null 2>&1; do sleep 2; done
echo "  Vault ready ✅"

echo "[2/6] Waiting for Authentik..."
while ! curl -s http://localhost:9000/api/v3/ >/dev/null 2>&1; do sleep 2; done
echo "  Authentik ready ✅"

echo "[3/6] Initializing Authentik..."
docker cp "$SCRIPT_DIR/create_ak_config.py" authentik-server:/create_ak_config.py
docker exec authentik-server env PYTHONPATH=/authentik:/ak-root/venv/lib/python3.12/site-packages \
  /ak-root/venv/bin/python3 /create_ak_config.py 2>&1 | grep -E "Group:|User:|OIDC|Signing|Application|Done" | sed 's/^/  /'
echo "  Authentik init complete ✅"

echo "[4/6] Applying Terraform for Vault PKI + KV + OIDC + SSH..."
cd "$PROJECT_DIR/terraform"
export VAULT_ADDR=https://localhost:8200
export VAULT_TOKEN=root-token
export VAULT_SKIP_VERIFY=true

# Wait for OIDC discovery URL (needed by Terraform vault_jwt_auth_backend)
echo "  Waiting for OIDC discovery URL..."
for i in $(seq 1 30); do
  curl -s --max-time 3 "http://authentik-server:9000/application/o/vault/.well-known/openid-configuration" 2>/dev/null | grep -q "issuer" && echo "  Discovery URL ready ✅" && break
  sleep 2
done

export VAULT_SKIP_VERIFY=true
terraform init -upgrade >/dev/null 2>&1

# Import existing resources to avoid "already exists" errors
echo "  Importing existing Vault resources..."
for res in \
  "vault_mount.pki pki" "vault_mount.kv kv" "vault_mount.ssh ssh" "vault_mount.ssh_dc2 ssh-dc2" \
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
VAULT_ADDR=https://localhost:8200 VAULT_SKIP_VERIFY=true vault write auth/oidc/config \
  oidc_discovery_url=http://authentik-server:9000/application/o/vault/ \
  oidc_client_id=vault-client-id \
  oidc_client_secret=vault-client-secret \
  default_role=dev 2>/dev/null && echo "  OIDC config set ✅" || true
for role in admin ops dev; do
  VAULT_ADDR=https://localhost:8200 VAULT_SKIP_VERIFY=true vault write auth/oidc/role/$role \
    allowed_redirect_uris="http://localhost:8200/oidc/callback,https://localhost:8200/oidc/callback,http://localhost:8200/ui/vault/auth/oidc/oidc/callback,https://localhost:8200/ui/vault/auth/oidc/oidc/callback,http://localhost:8200/v1/auth/oidc/oidc/callback,https://localhost:8200/v1/auth/oidc/oidc/callback" \
    bound_audiences=vault-client-id \
    user_claim=sub \
    oidc_scopes=openid \
    policies=${role}-policy 2>/dev/null && echo "  Role '${role}' created ✅" || true
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
echo "[5/6] Exporting SSH CA public keys..."
# Read CA public keys from Vault and write to shared Docker volumes
# The ssh-ca-pub volume is mounted on gateway:/ssh and ssh-server:/ssh
# The ssh-ca-dc2-pub volume is mounted on gateway-dc2:/ssh
DC1_CA_KEY=$(docker exec -e VAULT_SKIP_VERIFY=true vault vault read -field=public_key ssh/config/ca 2>/dev/null)
if [ -n "$DC1_CA_KEY" ]; then
  echo "$DC1_CA_KEY" | docker exec -i gateway sh -c "cat > /ssh/ca.pub" 2>/dev/null && \
    echo "  DC1 SSH CA key exported to gateway ✅" || \
    echo "  DC1 SSH CA key export to gateway failed"
fi

DC2_CA_KEY=$(docker exec -e VAULT_SKIP_VERIFY=true vault vault read -field=public_key ssh-dc2/config/ca 2>/dev/null)
if [ -n "$DC2_CA_KEY" ]; then
  echo "$DC2_CA_KEY" | docker exec -i gateway-dc2 sh -c "cat > /ssh/ca.pub" 2>/dev/null && \
    echo "  DC2 SSH CA key exported to gateway-dc2 ✅" || \
    echo "  DC2 SSH CA key export to gateway-dc2 failed"
fi
echo "  SSH CA export complete ✅"

echo ""
echo "[6/6] Final verification..."
echo "  PKI:" && docker exec -e VAULT_SKIP_VERIFY=true vault vault secrets list 2>/dev/null | grep -c "pki/" | xargs echo "    pki engine"
echo "  KV:" && docker exec -e VAULT_SKIP_VERIFY=true vault vault secrets list 2>/dev/null | grep -c "kv/" | xargs echo "    kv engine"
echo "  SSH:" && docker exec -e VAULT_SKIP_VERIFY=true vault vault secrets list 2>/dev/null | grep -c "ssh/" | xargs echo "    ssh engine(s)"
echo "  OIDC:" && docker exec -e VAULT_SKIP_VERIFY=true vault vault auth list 2>/dev/null | grep -c "oidc/" | xargs echo "    oidc auth"

echo ""
echo "=== Initialization Complete ==="
echo "Vault UI:     https://localhost:8200/ui (OIDC: admin/123123)"
echo "Authentik:    http://localhost:9000 (admin/123123)"
echo "Web UI:       http://localhost:9091"
echo "SSH Gateway:  ssh gateway-user@localhost -p 2222"
echo "SSH Gateway DC2: ssh gateway-user@localhost -p 2223"
