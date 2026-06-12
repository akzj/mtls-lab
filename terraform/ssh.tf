# SSH Certificate Authority (DC1)
# Official Terraform resources (not vault_generic_endpoint)

# Enable SSH secrets engine (DC1)
resource "vault_mount" "ssh" {
  path        = "ssh"
  type        = "ssh"
  description = "SSH Certificate Authority (DC1)"
}

# Configure SSH CA with key generation
resource "vault_ssh_secret_backend_ca" "ca" {
  depends_on           = [vault_mount.ssh]
  backend              = vault_mount.ssh.path
  generate_signing_key = true
}

# Create SSH signing role
resource "vault_ssh_secret_backend_role" "sign" {
  depends_on              = [vault_ssh_secret_backend_ca.ca]
  backend                 = vault_mount.ssh.path
  name                    = "sign-ssh"
  key_type                = "ca"
  ttl                     = "5m"
  allow_user_certificates = true
  allowed_users           = "*"
  default_extensions = {
    "login@openssh.com"       = "permit-pty"
    "permit-agent-forwarding" = ""
    "permit-port-forwarding"  = ""
  }
}
