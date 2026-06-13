# Enable KV v2 secrets engine
resource "vault_mount" "kv" {
  path        = "kv"
  type        = "kv-v2"
  description = "KV v2 secrets engine"
}

# Write test configuration secret (replaces vault kv put kv/server-config)
resource "vault_kv_secret_v2" "server_config" {
  depends_on = [vault_mount.kv]
  mount      = vault_mount.kv.path
  name       = "server-config"
  data_json = jsonencode({
    api_key     = "zero-fas-secret-12345"
    db_password = "db-pass-98765"
  })
}
