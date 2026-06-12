# Ops - read production/staging secrets, issue certificates
path "kv/data/production/*" {
  capabilities = ["read", "list"]
}
path "kv/metadata/production/*" {
  capabilities = ["read", "list"]
}
path "kv/data/staging/*" {
  capabilities = ["read", "list", "create", "update"]
}
path "kv/metadata/staging/*" {
  capabilities = ["read", "list"]
}
path "kv/data/dev/*" {
  capabilities = ["read", "list", "create", "update"]
}
path "kv/metadata/dev/*" {
  capabilities = ["read", "list"]
}
path "pki/issue/*" {
  capabilities = ["create", "update"]
}
