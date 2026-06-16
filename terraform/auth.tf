# Server policy is already defined in policies.tf (vault_policy.server)
# Enable userpass auth backend for multi-user demo
resource "vault_auth_backend" "userpass" {
  type        = "userpass"
  path        = "userpass"
  description = "Username/password authentication for multi-user demo"
}

# Enable certificate auth backend
resource "vault_auth_backend" "cert" {
  type        = "cert"
  path        = "cert"
  description = "TLS certificate authentication"
}

# Configure cert auth role for go-server
resource "vault_cert_auth_backend_role" "go_server" {
  depends_on           = [vault_auth_backend.cert]
  backend              = vault_auth_backend.cert.path
  name                 = "go-server"
  certificate          = file("${var.certs_dir}/trust-chain.crt")
  allowed_common_names = ["go-server"]
  token_policies       = ["server-policy"]
  token_ttl            = 86400
}

# Personal certificate roles (step-ca signed, ca-chain.crt trust)
resource "vault_cert_auth_backend_role" "personal_admin" {
  depends_on            = [vault_auth_backend.cert]
  backend               = vault_auth_backend.cert.path
  name                  = "personal-admin"
  certificate           = file("${var.certs_dir}/ca-chain.crt")
  allowed_common_names  = ["admin@lab.local"]
  token_policies        = ["admin-policy"]
  token_ttl             = 86400
}

resource "vault_cert_auth_backend_role" "personal_ops" {
  depends_on            = [vault_auth_backend.cert]
  backend               = vault_auth_backend.cert.path
  name                  = "personal-ops"
  certificate           = file("${var.certs_dir}/ca-chain.crt")
  allowed_common_names  = ["ops@lab.local"]
  token_policies        = ["ops-policy"]
  token_ttl             = 86400
}

resource "vault_cert_auth_backend_role" "personal_dev" {
  depends_on            = [vault_auth_backend.cert]
  backend               = vault_auth_backend.cert.path
  name                  = "personal-dev"
  certificate           = file("${var.certs_dir}/ca-chain.crt")
  allowed_common_names  = ["dev@lab.local"]
  token_policies        = ["dev-policy"]
  token_ttl             = 86400
}
