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
  token_ttl            = 3600
}
