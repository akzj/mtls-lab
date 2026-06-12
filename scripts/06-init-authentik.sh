#!/bin/sh
# 06-init-authentik.sh — Initialize Authentik with groups, users, OIDC provider
set -e

AUTHENTIK_URL="http://authentik-server:9000"
BOOTSTRAP_TOKEN="${AUTHENTIK_BOOTSTRAP_TOKEN:-authentik-bootstrap-token}"

echo "=== Zero-FAS Authentik Initialization ==="
echo "AUTHENTIK_URL=${AUTHENTIK_URL}"

# Wait for Authentik to be ready
echo "Waiting for Authentik..."
for i in $(seq 1 60); do
  if wget -q -O- "${AUTHENTIK_URL}/api/v3/" >/dev/null 2>&1; then
    echo "Authentik is ready."
    break
  fi
  sleep 2
done

AUTH_HEADER="Authorization: Bearer ${BOOTSTRAP_TOKEN}"
CONTENT_TYPE="Content-Type: application/json"

# Helper: POST JSON from heredoc to a temp file, then POST it
api_post() {
  local endpoint="$1"
  local json_content="$2"
  local tmpf
  tmpf=$(mktemp -t authentik.XXXXXX)
  printf '%s' "$json_content" > "$tmpf"
  wget -q -O- --header="$AUTH_HEADER" --header="$CONTENT_TYPE" \
    --post-file="$tmpf" "${AUTHENTIK_URL}${endpoint}" 2>/dev/null
  rm -f "$tmpf"
}

# Helper: GET JSON
api_get() {
  local endpoint="$1"
  wget -q -O- --header="$AUTH_HEADER" \
    "${AUTHENTIK_URL}${endpoint}" 2>/dev/null
}

# Helper: extract a simple string value from JSON by key
json_val() {
  local key="$1"
  grep -o "\"${key}\":\"[^\"]*\"" | head -1 | cut -d'"' -f4
}

# --------------------------------------------------
# Create groups
# --------------------------------------------------
echo ""
echo "--- Creating groups ---"
for group in admin-group ops-group dev-group; do
  GROUP_EXISTS=$(api_get "/api/v3/core/groups/?name=${group}" | json_val "name")
  if [ -z "$GROUP_EXISTS" ]; then
    api_post "/api/v3/core/groups/" "{\"name\":\"${group}\"}" >/dev/null
    echo "  Group '${group}' created."
  else
    echo "  Group '${group}' already exists."
  fi
done

# --------------------------------------------------
# Create users and assign to groups
# --------------------------------------------------
echo ""
echo "--- Creating users ---"

# Get group PKs
ADMIN_GROUP_PK=$(api_get "/api/v3/core/groups/?name=admin-group" | json_val "pk")
OPS_GROUP_PK=$(api_get "/api/v3/core/groups/?name=ops-group" | json_val "pk")
DEV_GROUP_PK=$(api_get "/api/v3/core/groups/?name=dev-group" | json_val "pk")

echo "  Got group PKs: admin=${ADMIN_GROUP_PK}"

# Helper: create user with group membership and password
create_user() {
  local username="$1"
  local display_name="$2"
  local group_pk="$3"
  local password="$4"

  USER_EXISTS=$(api_get "/api/v3/core/users/?username=${username}" | json_val "username")
  if [ -n "$USER_EXISTS" ]; then
    echo "  User '${username}' already exists, skipping."
    return 0
  fi

  CREATE_RESP=$(api_post "/api/v3/core/users/" \
    "{\"username\":\"${username}\",\"name\":\"${display_name}\",\"groups\":[\"${group_pk}\"]}")
  USER_PK=$(echo "$CREATE_RESP" | json_val "pk")

  if [ -z "$USER_PK" ]; then
    USER_PK=$(api_get "/api/v3/core/users/?username=${username}" | json_val "pk")
  fi

  if [ -n "$USER_PK" ]; then
    # Set password
    api_post "/api/v3/core/users/${USER_PK}/set_password/" \
      "{\"password\":\"${password}\"}" >/dev/null 2>&1 || true
    echo "  User '${username}' created (password: ${password}). PK=${USER_PK}"
  else
    echo "  ERROR: Could not create user '${username}'."
  fi
}

create_user "admin" "Admin User" "$ADMIN_GROUP_PK" "123123"
create_user "ops" "Ops User" "$OPS_GROUP_PK" "123123"
create_user "dev" "Dev User" "$DEV_GROUP_PK" "123123"

# --------------------------------------------------
# Create OIDC Provider in Authentik
# --------------------------------------------------
echo ""
echo "--- Creating OIDC Provider for Vault ---"

# Find the default authorization flow
AUTH_FLOW_UUID=$(api_get "/api/v3/flows/instances/?slug=default-provider-authorization-implicit-consent" | \
  json_val "pk")

if [ -z "$AUTH_FLOW_UUID" ]; then
  echo "  WARNING: Could not find default auth flow, trying first available flow..."
  AUTH_FLOW_UUID=$(api_get "/api/v3/flows/instances/" | json_val "pk")
fi
echo "  Using authorization flow: ${AUTH_FLOW_UUID}"

# Get invalidation flow UUID
INVAL_FLOW_UUID=$(api_get "/api/v3/flows/instances/?slug=default-provider-invalidation-flow" | \
  json_val "pk")
echo "  Using invalidation flow: ${INVAL_FLOW_UUID}"

# Create OAuth2 Provider
# Note: Use heredoc for complex JSON with arrays of objects
cat > /tmp/provider-data.json << PROVIDER_EOF
{"name":"Vault OIDC","authorization_flow":"${AUTH_FLOW_UUID}","invalidation_flow":"${INVAL_FLOW_UUID}","client_type":"confidential","client_id":"vault-client-id","client_secret":"vault-client-secret","redirect_uris":[{"url":"http://localhost:8250/oidc/callback","matching_mode":"strict"}]}
PROVIDER_EOF
PROVIDER_RESP=$(wget -q -O- --header="$AUTH_HEADER" --header="$CONTENT_TYPE" \
  --post-file=/tmp/provider-data.json "${AUTHENTIK_URL}/api/v3/providers/oauth2/" 2>/dev/null)
PROVIDER_PK=$(echo "$PROVIDER_RESP" | json_val "pk")
echo "  OAuth2 provider created (PK: ${PROVIDER_PK})."

# --------------------------------------------------
# Create Application linking to the provider
# --------------------------------------------------
echo ""
echo "--- Creating Application ---"
# Delete existing app with same slug if it exists
EXISTING_APP_PK=$(api_get "/api/v3/core/applications/?slug=vault" | json_val "pk")
if [ -n "$EXISTING_APP_PK" ]; then
  echo "  Application 'vault' already exists, will need manual setup."
  echo "  Skipping creation — already linked by previous setup."
  APP_SLUG="vault"
else
  cat > /tmp/app-data.json << APP_EOF
{"name":"Vault","slug":"vault","provider":${PROVIDER_PK}}
APP_EOF
  APP_RESP=$(wget -q -O- --header="$AUTH_HEADER" --header="$CONTENT_TYPE" \
    --post-file=/tmp/app-data.json "${AUTHENTIK_URL}/api/v3/core/applications/" 2>/dev/null)
  APP_SLUG=$(echo "$APP_RESP" | json_val "slug")
  echo "  Application created (slug: ${APP_SLUG})."
fi

echo ""
echo "=== Authentik initialization complete ==="
echo "OIDC Discovery URL: http://authentik-server:9000/application/o/vault/"
echo "Authentik UI:       http://localhost:9000"
echo "Users (Authentik):  admin/123123, ops/123123, dev/123123"
