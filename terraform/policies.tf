# Vault Policies — map .hcl files to Terraform resources

resource "vault_policy" "admin" {
  name   = "admin-policy"
  policy = file("${path.module}/../vault/policies/admin-policy.hcl")
}

resource "vault_policy" "ops" {
  name   = "ops-policy"
  policy = file("${path.module}/../vault/policies/ops-policy.hcl")
}

resource "vault_policy" "dev" {
  name   = "dev-policy"
  policy = file("${path.module}/../vault/policies/dev-policy.hcl")
}

# Server policy (for mTLS cert auth — go-server)
resource "vault_policy" "server" {
  name   = "server-policy"
  policy = file("${path.module}/../vault/policies/server-policy.hcl")
}