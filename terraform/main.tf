# Terraform configuration for mTLS Lab Vault
# This replaces scripts/07-init-vault-oidc.sh with declarative Terraform.

terraform {
  required_version = ">= 1.0"
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
  }
}

# Vault provider connects using VAULT_ADDR + VAULT_TOKEN env vars
# On the vault-init container:
#   VAULT_ADDR=https://vault:8200
#   VAULT_TOKEN=root-token
#   VAULT_SKIP_VERIFY=true
provider "vault" {
  # Environment variables handled by provider automatically
  # VAULT_ADDR, VAULT_TOKEN, VAULT_SKIP_VERIFY
}