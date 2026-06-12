# SSH Certificate Authority (DC2 — multi-DC isolation demo)
# Official Terraform resources (not vault_generic_endpoint)

# Enable SSH secrets engine at ssh-dc2/ path (independent from DC1)
resource "vault_mount" "ssh_dc2" {
  path        = "ssh-dc2"
  type        = "ssh"
  description = "SSH Certificate Authority (DC2 — isolated from DC1)"
}

# Configure DC2 SSH CA with independent key generation
resource "vault_ssh_secret_backend_ca" "ca_dc2" {
  depends_on           = [vault_mount.ssh_dc2]
  backend              = vault_mount.ssh_dc2.path
  generate_signing_key = true
}

# Create DC2 SSH signing role
resource "vault_ssh_secret_backend_role" "sign_dc2" {
  depends_on              = [vault_ssh_secret_backend_ca.ca_dc2]
  backend                 = vault_mount.ssh_dc2.path
  name                    = "sign-ssh"
  key_type                = "ca"
  ttl                     = "5m"
  allow_user_certificates = true
  allowed_users           = "*"
  default_user            = "ssh-user"
  default_extensions = {
    "login@openssh.com"       = "permit-pty"
    "permit-agent-forwarding" = ""
    "permit-port-forwarding"  = ""
  }
}
