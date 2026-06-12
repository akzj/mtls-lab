#!/bin/sh
# 07-init-vault-oidc.sh — Configure Vault OIDC auth with Authentik
set -e

export VAULT_SKIP_VERIFY=true
AUTHENTIK_URL="http://authentik-server:9000"

echo "=== Zero-FAS Vault OIDC Configuration ==="
echo "VAULT_ADDR=${VAULT_ADDR}"
echo "AUTHENTIK_URL=${AUTHENTIK_URL}"

echo "Waiting for Authentik API..."
for i in $(seq 1 30); do
  if wget -q -O- "${AUTHENTIK_URL}/api/v3/" >/dev/null 2>&1; then
    echo "Authentik is ready."
    break
  fi
  sleep 2
done

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
  default_role="dev"
echo "  OIDC config written."

# --------------------------------------------------
# Create OIDC roles mapped to Vault policies
# Redirect URIs must match between Vault roles and Authentik OIDC provider.
# Uses port 8200 (Vault's TLS port) — NOT port 8250 (CLI callback port).
# --------------------------------------------------
echo ""
echo "--- Creating OIDC roles ---"

ALLOWED_REDIRECT_URIS='[
  "http://localhost:8200/oidc/callback",
  "https://localhost:8200/oidc/callback",
  "http://localhost:8200/ui/vault/auth/oidc/oidc/callback",
  "https://localhost:8200/ui/vault/auth/oidc/oidc/callback",
  "http://localhost:8200/v1/auth/oidc/oidc/callback",
  "https://localhost:8200/v1/auth/oidc/oidc/callback"
]'

create_oidc_role() {
  local role=$1
  local policy=$2
  local ttl=${3:-1h}
  cat <<EOF | vault write "auth/oidc/role/${role}" -
{
  "bound_audiences": ["vault-client-id"],
  "allowed_redirect_uris": ${ALLOWED_REDIRECT_URIS},
  "user_claim": "sub",
  "oidc_scopes": ["openid"],
  "policies": ["${policy}"],
  "ttl": "${ttl}"
}
EOF
  echo "  Role '${role}' → ${policy}"
}

create_oidc_role admin admin-policy
create_oidc_role ops ops-policy
create_oidc_role dev dev-policy

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
