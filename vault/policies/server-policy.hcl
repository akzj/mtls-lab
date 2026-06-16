path "kv/data/server-config" {
  capabilities = ["read"]
}

path "pki/issue/server" {
  capabilities = ["create", "update"]
}

path "ssh/sign/sign-ssh" {
  capabilities = ["create", "update"]
path "pki/issue/user" {
  capabilities = ["create", "update"]
}

path "auth/cert/certs/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

}

path "ssh-dc2/sign/sign-ssh" {
  capabilities = ["create", "update"]
}

path "ssh/config/ca" {
  capabilities = ["read"]
}

path "ssh-dc2/config/ca" {
  capabilities = ["read"]
}
