locals {
  # Combine intermediate certificate and private key into pem_bundle
  intermediate_pem_bundle = "${file("${var.certs_dir}/intermediate-vault-pki.crt")}${file("${var.certs_dir}/intermediate-vault-pki-key.pem")}"
}

# Enable PKI secrets engine
resource "vault_mount" "pki" {
  path        = "pki"
  type        = "pki"
  description = "PKI secrets engine"
}

# Import Vault PKI intermediate certificate and key
resource "vault_pki_secret_backend_config_ca" "intermediate" {
  depends_on = [vault_mount.pki]
  backend    = vault_mount.pki.path
  pem_bundle = local.intermediate_pem_bundle
}

# Configure issuing and CRL URLs
resource "vault_pki_secret_backend_config_urls" "urls" {
  depends_on              = [vault_mount.pki]
  backend                 = vault_mount.pki.path
  issuing_certificates    = ["${var.vault_addr}/v1/pki/ca"]
  crl_distribution_points = ["${var.vault_addr}/v1/pki/crl"]
}

# Role for issuing server certificates
resource "vault_pki_secret_backend_role" "server" {
  depends_on     = [vault_mount.pki]
  backend        = vault_mount.pki.path
  name           = "server"
  allow_any_name = true
  max_ttl        = 31536000 # 8760h
  key_type       = "rsa"
  key_bits       = 2048
  server_flag    = true
  client_flag    = false
  require_cn     = false
}
