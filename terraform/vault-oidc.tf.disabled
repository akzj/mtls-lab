# Vault OIDC Authentication with Authentik
# Uses JWT auth backend with OIDC type.

# ---------------------------------------------------------------------------
# JWT/OIDC Auth Backend
# ---------------------------------------------------------------------------
resource "vault_jwt_auth_backend" "oidc" {
  type               = "oidc"
  path               = "oidc"
  description        = "OIDC authentication via Authentik"
  oidc_discovery_url = "http://authentik-server:9000/application/o/vault/"
  oidc_client_id     = "vault-client-id"
  oidc_client_secret = "vault-client-secret"
  default_role       = "dev"
  bound_issuer       = "http://authentik-server:9000/application/o/vault/"
}

# ---------------------------------------------------------------------------
# OIDC Roles (mapped to Vault policies)
# Redirect URIs: port 8200 only (Vault dev-tls), NOT 8250.
# Must match Authentik OIDC provider in 06-init-authentik.sh.
# ---------------------------------------------------------------------------

locals {
  allowed_redirect_uris = [
    "http://localhost:8200/oidc/callback",
    "https://localhost:8200/oidc/callback",
    "http://localhost:8200/ui/vault/auth/oidc/oidc/callback",
    "https://localhost:8200/ui/vault/auth/oidc/oidc/callback",
    "http://localhost:8200/v1/auth/oidc/oidc/callback",
    "https://localhost:8200/v1/auth/oidc/oidc/callback",
  ]
}

resource "vault_jwt_auth_backend_role" "admin" {
  backend          = vault_jwt_auth_backend.oidc.path
  role_name        = "admin"
  bound_audiences  = ["vault-client-id"]
  allowed_redirect_uris = local.allowed_redirect_uris
  user_claim       = "sub"
  oidc_scopes      = ["openid"]
  token_policies   = ["admin-policy"]
  token_ttl        = 3600
}

resource "vault_jwt_auth_backend_role" "ops" {
  backend          = vault_jwt_auth_backend.oidc.path
  role_name        = "ops"
  bound_audiences  = ["vault-client-id"]
  allowed_redirect_uris = local.allowed_redirect_uris
  user_claim       = "sub"
  oidc_scopes      = ["openid"]
  token_policies   = ["ops-policy"]
  token_ttl        = 3600
}

resource "vault_jwt_auth_backend_role" "dev" {
  backend          = vault_jwt_auth_backend.oidc.path
  role_name        = "dev"
  bound_audiences  = ["vault-client-id"]
  allowed_redirect_uris = local.allowed_redirect_uris
  user_claim       = "sub"
  oidc_scopes      = ["openid"]
  token_policies   = ["dev-policy"]
  token_ttl        = 3600
}
