# Dev - read-only dev namespace
path "kv/data/dev/*" {
  capabilities = ["read", "list"]
}
path "kv/metadata/dev/*" {
  capabilities = ["read", "list"]
}
