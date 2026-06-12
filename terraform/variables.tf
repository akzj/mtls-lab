variable "vault_addr" {
  description = "Vault server address"
  type        = string
  default     = "https://vault:8200"
}

variable "vault_token" {
  description = "Vault root token"
  type        = string
  sensitive   = true
}

variable "certs_dir" {
  description = "Directory with certificate files"
  type        = string
  default     = "/certs"
}

variable "policies_dir" {
  description = "Directory with Vault policy files"
  type        = string
  default     = "/vault/policies"
}
