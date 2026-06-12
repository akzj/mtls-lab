# Terraform Vault Configuration Reference

> Managed Vault setup for the Zero-FAS mTLS Lab.
> All `.tf` files reside in `terraform/` and are applied by `init-all.sh` or `terraform-init` container.

## Quick Reference

```bash
cd terraform
terraform init                    # Initialize Vault provider
terraform plan                    # Preview changes
terraform apply -auto-approve     # Apply configuration
terraform destroy                 # Remove all managed resources
```

Variables required: `vault_token`, `vault_addr`, `certs_dir`, `policies_dir`

---

## File: `main.tf` — Provider Configuration

**Purpose:** Define Terraform version, Vault provider, and connection settings.

| Resource | Key Settings |
|----------|-------------|
| `terraform.required_providers.vault` | `hashicorp/vault` ~> 4.0 |
| `provider "vault"` | Uses env vars: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_SKIP_VERIFY` |

**Notes:**
- Provider uses `VAULT_ADDR=https://vault:8200`, `VAULT_TOKEN=root-token`, `VAULT_SKIP_VERIFY=true` from container environment
- No explicit provider config needed — environment variables handle authentication
- Vault runs in `-dev-tls` mode with self-signed cert, hence `VAULT_SKIP_VERIFY=true`

---

## File: `variables.tf` — Input Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `vault_addr` | string | `https://vault:8200` | Vault server address |
| `vault_token` | string (sensitive) | required | Root token for Vault operations |
| `certs_dir` | string | `/certs` | Certificate files directory |
| `policies_dir` | string | `/vault/policies` | Vault policy HCL files directory |

**Notes:**
- `vault_token` is marked `sensitive = true` — never printed in logs/state
- Default values work when Terraform runs inside the Docker network

---

## File: `pki.tf` — PKI Secrets Engine

**Purpose:** Configure Vault PKI with existing intermediate CA, URL endpoints, and server certificate role.

| Resource | Type | Description |
|----------|------|-------------|
| `vault_mount.pki` | PKI engine | Mounts PKI at `pki/` path |
| `vault_pki_secret_backend_config_ca.intermediate` | CA import | Imports `intermediate-vault-pki.crt` + key as PEM bundle |
| `vault_pki_secret_backend_config_urls.urls` | URL config | Sets issuing certificates and CRL distribution URLs |
| `vault_pki_secret_backend_role.server` | Certificate role | Creates `server` role for issuing server TLS certs |

**Dependencies:**
```
vault_mount.pki → vault_pki_secret_backend_config_ca.intermediate
                → vault_pki_secret_backend_config_urls.urls
                → vault_pki_secret_backend_role.server
```

**Notes:**
- Uses `local.intermediate_pem_bundle` to combine the intermediate cert and private key from files
- Certificate files come from `var.certs_dir` (default: `/certs`)
- Server role: RSA 2048, `allow_any_name=true`, 8760h max TTL, `server_flag=true`

---

## File: `kv.tf` — KV v2 Secrets Engine

**Purpose:** Enable KV v2 engine and create the test configuration secret.

| Resource | Type | Description |
|----------|------|-------------|
| `vault_mount.kv` | KV v2 engine | Mounts KV at `kv/` path |
| `vault_kv_secret_v2.server_config` | Secret | Creates `kv/server-config` with `api_key` and `db_password` |

**Notes:**
- Secret data defined as `jsonencode()` in `data_json`
- The Go server reads this secret at startup using mTLS cert auth

---

## File: `auth.tf` — Authentication Backends

**Purpose:** Enable userpass and certificate authentication backends.

| Resource | Type | Description |
|----------|------|-------------|
| `vault_auth_backend.userpass` | Userpass auth | Username/password auth (multi-user demo) |
| `vault_auth_backend.cert` | Certificate auth | TLS client certificate auth |
| `vault_cert_auth_backend_role.go_server` | Cert role | Maps CN=go-server → `server-policy` |

**Notes:**
- Userpass backend enabled here; user creation is done by `init-all.sh` (Terraform cannot manage passwords directly)
- Cert auth uses `trust-chain.crt` (Vault PKI intermediate + Root CA) to verify client certs
- The cert role requires `allowed_common_names = ["go-server"]` to match the server certificate CN
- Users: admin/admin123 → admin-policy, ops/ops123 → ops-policy, dev/dev123 → dev-policy

---

## File: `vault-oidc.tf` — OIDC Authentication

**Purpose:** Configure Vault OIDC authentication with Authentik identity provider.

| Resource | Type | Description |
|----------|------|-------------|
| `vault_jwt_auth_backend.oidc` | OIDC auth backend | JWT/OIDC backend pointing to Authentik |
| `vault_jwt_auth_backend_role.admin` | OIDC role (admin) | Maps authenticated admin users → `admin-policy` |
| `vault_jwt_auth_backend_role.ops` | OIDC role (ops) | Maps authenticated ops users → `ops-policy` |
| `vault_jwt_auth_backend_role.dev` | OIDC role (dev) | Maps authenticated dev users → `dev-policy` |

**OIDC Configuration:**
| Setting | Value |
|---------|-------|
| `oidc_discovery_url` | `http://authentik-server:9000/application/o/vault/` |
| `oidc_client_id` | `vault-client-id` |
| `oidc_client_secret` | `vault-client-secret` |
| `default_role` | `dev` |
| `bound_issuer` | `http://authentik-server:9000/application/o/vault/` |

**Notes:**
- Uses `vault_jwt_auth_backend` with `type = "oidc"` (official Vault OIDC resource)
- Allowed redirect URIs include both HTTP/HTTPS variants for port 8200
- Each role uses `oidc_scopes = ["openid"]` and `user_claim = "sub"`
- The OIDC provider is created in Authentik by `create_ak_config.py` (run from `init-all.sh`)

---

## File: `policies.tf` — Vault Policies

**Purpose:** Define Vault ACL policies from HCL files.

| Resource | Policy Name | Source File |
|----------|-------------|------------|
| `vault_policy.admin` | `admin-policy` | `vault/policies/admin-policy.hcl` |
| `vault_policy.ops` | `ops-policy` | `vault/policies/ops-policy.hcl` |
| `vault_policy.dev` | `dev-policy` | `vault/policies/dev-policy.hcl` |
| `vault_policy.server` | `server-policy` | `vault/policies/server-policy.hcl` |

**Policy Scope:**
| Policy | Permissions |
|--------|------------|
| `admin-policy` | Full access (`path "*" { capabilities = ["*"] }`) |
| `ops-policy` | Production(r), staging/dev(rw), pki/issue |
| `dev-policy` | Dev namespace read-only |
| `server-policy` | KV read, pki/issue, ssh/sign |

---

## File: `ssh.tf` — SSH CA (DC1)

**Purpose:** Enable SSH secrets engine and configure DC1 SSH Certificate Authority.

| Resource | Type | Description |
|----------|------|-------------|
| `vault_mount.ssh` | SSH engine | Mounts SSH at `ssh/` path (DC1) |
| `vault_ssh_secret_backend_ca.ca` | SSH CA config | Generates SSH CA signing key |
| `vault_ssh_secret_backend_role.sign` | SSH signing role | Creates `sign-ssh` role for DC1 |

**Role Configuration:**
| Setting | Value |
|---------|-------|
| `key_type` | `ca` |
| `ttl` | `5m` |
| `allow_user_certificates` | `true` |
| `allowed_users` | `*` |
| `default_extensions` | `permit-pty`, `permit-agent-forwarding`, `permit-port-forwarding` |

**Notes:**
- Uses official `vault_ssh_secret_backend_ca` and `vault_ssh_secret_backend_role` resources
- CA public key exported to Docker volume `ssh-ca-pub` (via `init-all.sh` step 6)
- Gateway container trusts this CA via `TrustedUserCAKeys /ssh/ca.pub`

---

## File: `ssh-dc2.tf` — SSH CA (DC2)

**Purpose:** Independent SSH CA for DC2, demonstrating multi-DC SSH isolation.

| Resource | Type | Description |
|----------|------|-------------|
| `vault_mount.ssh_dc2` | SSH engine | Mounts SSH at `ssh-dc2/` path |
| `vault_ssh_secret_backend_ca.ca_dc2` | SSH CA config | Generates separate DC2 SSH CA signing key |
| `vault_ssh_secret_backend_role.sign_dc2` | SSH signing role | Creates `sign-ssh` role for DC2 |

**Differences from DC1:**
- Engine path: `ssh-dc2/` (not `ssh/`)
- Role has `default_user = "ssh-user"` (DC1 role omits this)
- CA key is independently generated (different from DC1)
- CA public key exported to Docker volume `ssh-ca-dc2-pub`

**Isolation:** DC1-signed SSH certificates cannot authenticate to DC2 gateway, and vice versa.

---

## Apply Order

Terraform handles dependency ordering internally, but the logical order is:

1. `main.tf` — Provider initialization
2. `policies.tf` — Policy definitions (no dependencies)
3. `pki.tf` — PKI engine + intermediate CA + role
4. `kv.tf` — KV engine + secrets
5. `auth.tf` — Auth backends (cert + userpass)
6. `ssh.tf` — SSH CA DC1
7. `ssh-dc2.tf` — SSH CA DC2
8. `vault-oidc.tf` — OIDC auth (depends on Authentik being configured first)

**Post-Terraform steps (handled by `init-all.sh`):**
- Create userpass users (admin/ops/dev)
- Export SSH CA public keys to Docker volumes
- Initialize Authentik (OIDC provider)

## Integration with init-all.sh

The `init-all.sh` script orchestrates the full initialization:
1. Wait for Vault and Authentik
2. Initialize Authentik via `create_ak_config.py`
3. Import existing resources into Terraform state
4. `terraform apply -auto-approve`
5. Create userpass users (`docker exec vault vault write auth/userpass/users/...`)
6. Export SSH CA public keys to Docker volumes
