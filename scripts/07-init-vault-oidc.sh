#!/bin/sh
# 07-init-vault-oidc.sh — Configure Vault OIDC auth with Authentik
set -e

export VAULT_SKIP_VERIFY=true
AUTHENTIK_URL="http://authentik-server:9000"

echo "=== Zero-FAS Vault OIDC Configuration ==="
echo "VAULT_ADDR=${VAULT_ADDR}"
echo "AUTHENTIK_URL=${AUTHENTIK_URL}"

# Wait for Authentik (in case 06-init-authentik.sh is still finalizing)
echo "Waiting for Authentik API..."
for i in $(seq 1 30); do
  if wget -q -O- "${AUTHENTIK_URL}/api/v3/" >/dev/null 2>&1; then
    echo "Authentik is ready."
    break
  fi
  sleep 2
done

# Wait for the Vault OIDC application to exist
echo "Waiting for Vault OIDC application in Authentik..."
for i in $(seq 1 15); do
  APP_DATA=$(wget -q -O- --header="Authorization: Bearer ${AUTHENTIK_BOOTSTRAP_TOKEN}" \
    "${AUTHENTIK_URL}/api/v3/core/applications/?slug=vault" 2>/dev/null)
  APP_SLUG=$(echo "$APP_DATA" | grep -o '"slug":"[^"]*"' | cut -d'"' -f4)
  if [ "${APP_SLUG}" = "vault" ]; then
    echo "  Vault application found (slug: ${APP_SLUG})."
    break
  fi
  echo "  Waiting... (attempt ${i})"
  sleep 2
done

# The OIDC discovery URL for the Authentik application
OIDC_DISCOVERY_URL="${AUTHENTIK_URL}/application/o/vault/"

# --------------------------------------------------
# Enable OIDC auth in Vault
# --------------------------------------------------
echo ""
echo "--- Enabling Vault OIDC auth ---"
vault auth enable -path=oidc oidc 2>/dev/null || echo "  (already enabled, continuing)"

# --------------------------------------------------
# Configure OIDC with Authentik
# --------------------------------------------------
echo ""
echo "--- Configuring OIDC auth method ---"
vault write auth/oidc/config \
  oidc_discovery_url="${OIDC_DISCOVERY_URL}" \
  oidc_client_id="vault-client-id" \
  oidc_client_secret="vault-client-secret" \
  default_role="dev" \
  bound_issuer="${OIDC_DISCOVERY_URL}"
echo "  OIDC config written."

# --------------------------------------------------
# Create OIDC roles mapped to Vault policies
# --------------------------------------------------
echo ""
echo "--- Creating OIDC roles ---"

# Admin role → admin-policy (full access)
cat <<EOF | vault write auth/oidc/role/admin -
{
  "bound_audiences": ["vault-client-id"],
  "allowed_redirect_uris": [
    "http://localhost:8250/oidc/callback",
    "http://localhost:8200/oidc/callback",
    "https://localhost:8200/oidc/callback",
    "http://localhost:8200/v1/auth/oidc/oidc/callback",
    "https://localhost:8200/ui/vault/auth/oidc/oidc/callback"
  ],
  "user_claim": "sub",
  "policies": ["admin-policy"],
  "ttl": "1h"
}
EOF
echo "  Role 'admin' → admin-policy"

# Ops role → ops-policy
cat <<EOF | vault write auth/oidc/role/ops -
{
  "bound_audiences": ["vault-client-id"],
  "allowed_redirect_uris": [
    "http://localhost:8250/oidc/callback",
    "http://localhost:8200/oidc/callback",
    "https://localhost:8200/oidc/callback",
    "http://localhost:8200/v1/auth/oidc/oidc/callback",
    "https://localhost:8200/ui/vault/auth/oidc/oidc/callback"
  ],
  "user_claim": "sub",
  "policies": ["ops-policy"],
  "ttl": "1h"
}
EOF
echo "  Role 'ops' → ops-policy"

# Dev role → dev-policy
cat <<EOF | vault write auth/oidc/role/dev -
{
  "bound_audiences": ["vault-client-id"],
  "allowed_redirect_uris": [
    "http://localhost:8250/oidc/callback",
    "http://localhost:8200/oidc/callback",
    "https://localhost:8200/oidc/callback",
    "http://localhost:8200/v1/auth/oidc/oidc/callback",
    "https://localhost:8200/ui/vault/auth/oidc/oidc/callback"
  ],
  "user_claim": "sub",
  "policies": ["dev-policy"],
  "ttl": "1h"
}
EOF
echo "  Role 'dev' → dev-policy"

echo ""
echo "--- Verifying OIDC configuration ---"
echo ""
echo "OIDC Config:"
vault read auth/oidc/config
echo ""
echo "OIDC Roles:"
vault list auth/oidc/roles

echo ""
echo "=== Vault OIDC configuration complete ==="
echo "OIDC Discovery URL: ${OIDC_DISCOVERY_URL}"
echo "Authentik UI:       http://localhost:9000"
echo "Vault UI:           https://localhost:8200/ui/"
echo ""
echo "Users (Authentik):  admin/123123, ops/123123, dev/123123"
echo "Users (Vault userpass fallback): admin/admin123, ops/ops123, dev/dev123"
