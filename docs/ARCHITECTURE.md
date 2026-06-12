# Zero-FAS mTLS Lab — Architecture

## Overview

Three-layer PKI hierarchy with a YubiKey hardware root of trust, two intermediate
certificate authorities, mTLS WebSocket communications, OIDC SSO via Authentik,
and SSH certificate-based access — all managed declaratively with Terraform.

### Core Capabilities

| Capability | Implementation |
|------------|---------------|
| PKI | Root CA (YubiKey) → step-ca / Vault PKI → Leaf certs |
| mTLS | nginx reverse proxy + Go server/client mutual TLS |
| ACME | step-ca ACME server for automated client cert enrollment |
| OIDC SSO | Authentik identity → Vault OIDC auth → RBAC policies |
| SSH CA | Vault SSH engine signs user certs for gateway access |
| IaC | Terraform manages PKI, KV, auth, OIDC, SSH in Vault |

---

## PKI Hierarchy

```
┌──────────────────────────────────────────────────────────────────┐
│               Root CA (YubiKey + Software Backup)                │
│               ─────────────────────────────────────               │
│               YubiKey 5C Nano · PIV slot 9C                     │
│               RSA 2048 · Imported (not on-card gen)             │
│               CN = Zero-FAS Root CA                             │
│               Self-signed · 10-year validity                    │
│               Key backup: root-ca/root-ca-key.pem ⚠️           │
│               Signs ONLY intermediate CSRs                      │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   │ (signed via pkcs11-tool on YubiKey)
                   │
         ┌─────────┴──────────────────────┐
         ▼                                ▼
┌────────────────────────┐    ┌────────────────────────────┐
│ step-ca Intermediate   │    │ Vault PKI Intermediate     │
│ CA (Hot / Software)    │    │ CA (Hot / Software)        │
│ ─────────────────────  │    │ ────────────────────────   │
│ ACME server :8443      │    │ Terraform-managed          │
│ Signs via ACME:        │    │                            │
│  • go-client (daemon)  │    │ Signs via Vault PKI:       │
│ Signs via OpenSSL:     │    │  • Go server cert         │
│  • nginx (serverAuth)  │    │  • SSH CA (DC1 + DC2)    │
│  • nginx-proxy(client) │    │  • Dynamic issuance       │
└───────────┬────────────┘    └───────────┬────────────────┘
            │                             │
            ▼                             ▼
   ┌──────────────────┐         ┌───────────────────────┐
   │   nginx.crt      │         │    server.crt         │
   │   nginx-proxy.crt│         │  (Go server leaf)     │
   │   ACME certs     │         │                        │
   │   (go-client)    │         │  SSH CA key (DC1)      │
   └──────────────────┘         │  SSH CA key (DC2)      │
                                └───────────────────────┘
```

### Certificate Path Validation

```
Leaf (nginx)       → step-ca Intermediate → Root CA
Leaf (nginx-proxy) → step-ca Intermediate → Root CA
ACME (go-client)   → step-ca Intermediate → Root CA
Leaf (server)      → Vault PKI Intermediate → Root CA
SSH CA (DC1)       → Vault SSH engine (self-signed CA)
SSH CA (DC2)       → Vault SSH engine (separate CA, isolated)
```

### Trust Chains

Two trust chain files bundle the intermediates with the root:

| File | Contents |
|------|----------|
| `certs/ca-chain.crt` | step-ca Intermediate + Root CA |
| `certs/trust-chain.crt` | Vault PKI Intermediate + Root CA |

---

## Communication Flow

```
┌──────────┐    WSS :443     ┌──────────┐   HTTP :9090    ┌───────────┐
│ Go Client│ ──────────────► │  nginx   │ ──────────────► │ Go Server │
│ (mTLS)   │                 │ (reverse │                 │ (mTLS)    │
│          │◄────────────────│  proxy)  │◄────────────────│           │
└──────────┘                 └──────────┘                 └───────────┘
     │                            │                            │
     │ Uses client.crt            │ Uses nginx.crt             │ Uses server.crt
     │ + client-key.pem           │ + nginx-key.pem            │ + server-key.pem
     │                            │                            │
     │ Verifies server            │ Requires client cert       │ Verifies proxy cert
     │ via ca-chain.crt           │ via ca-chain.crt           │ via ca-chain.crt
     │                            │                            │
     │                            │ Uses nginx-proxy.crt       │ Reads Vault secrets
     │                            │ + nginx-proxy-key.pem      │ at startup
     │                            │ for upstream mTLS          │
     │                            │                            │
     │                            │ Verifies server cert       │
     │                            │ via trust-chain.crt        │
```

### mTLS Handshake Steps

**Phase 1: Client → nginx (TLS termination)**

1. Client presents `client.crt` as its client certificate
2. nginx requires client certificate verification via `ssl_client_certificate`
3. nginx validates client cert against `ca-chain.crt` (step-ca intermediate + root)
4. nginx presents `nginx.crt` as its server certificate

---

## OIDC SSO Flow (Authentik → Vault)

```
┌─────────────────────────────────────────────────────────────────┐
│  OIDC SSO Authentication Flow                                    │
│                                                                   │
│  User opens Vault UI at https://localhost:8200/ui                 │
│         │                                                         │
│         ▼                                                         │
│  Vault presents OIDC login button                                 │
│         │                                                         │
│         ▼                                                         │
│  Redirect to Authentik :9000/application/o/vault/                 │
│         │                                                         │
│         ▼                                                         │
│  Authentik login page (username/password)                         │
│         │                                                         │
│  ┌──────┴──────┐                                                  │
│  │ admin/123123│  ops/123123  dev/123123                          │
│  └──────┬──────┘                                                  │
│         │                                                         │
│         ▼                                                         │
│  Authentik validates credentials → generates ID token             │
│         │                                                         │
│         ▼                                                         │
│  Vault OIDC auth backend validates token                          │
│         │                                                         │
│         ▼                                                         │
│  Vault maps token to role (admin/ops/dev) → applies policy       │
│         │                                                         │
│         ▼                                                         │
│  User logged into Vault with group-based permissions              │
└─────────────────────────────────────────────────────────────────┘
```

### OIDC Components

| Component | Role | URL |
|-----------|------|-----|
| Authentik Server | OIDC identity provider | http://localhost:9000 |
| Authentik Worker | Background tasks | (internal) |
| PostgreSQL | Authentik database | (internal) |
| Redis | Authentik cache/queue | (internal) |
| Vault OIDC Auth | JWT/OIDC auth backend | https://localhost:8200 |

### Vault OIDC Roles

| Role | Bound Groups | Vault Policy | Access Level |
|------|-------------|-------------|-------------|
| `admin` | admin-group | `admin-policy` | Full access (create/read/update/delete/sudo) |
| `ops` | ops-group | `ops-policy` | Read production/staging, PKI issue |
| `dev` | dev-group | `dev-policy` | Read-only dev namespace |

---

## ACME Certificate Enrollment (step-ca)

```
Go Client (ACME daemon)                     step-ca (:8443)
         │                                       │
         │───── Get directory ──────────────────►│
         │◄──── ACME directory ──────────────────│
         │                                       │
         │───── Register account (ECDSA P-256) ─►│
         │◄──── Account URI ─────────────────────│
         │                                       │
         │───── Create order (go-client) ────────►│
         │◄──── Order + authz URLs ──────────────│
         │                                       │
         │───── HTTP-01 challenge ───────────────►│
         │  (starts temp HTTP :80 server)        │  step-ca connects
         │  serves .well-known/acme-challenge/   │◄── to go-client:80
         │◄──── Challenge validated ─────────────│
         │                                       │
         │───── CSR + finalize ──────────────────►│
         │◄──── Certificate (RSA 2048) ──────────│
         │                                       │
         │  Auto-renewal (24h check, 7d threshold)│
         │───── Repeated ACME flow ──────────────►│
```

---

## SSH Certificate Authority

```
                            Vault
                     ┌──────────────────┐
                     │  SSH engine DC1  │
                     │  ssh/config/ca   │
                     │  ssh/roles/sign  │
                     └────────┬─────────┘
                              │ CA public key exported to /ssh/ca.pub
                              │ (shared Docker volume)
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  SSH Access Flow                                                  │
│                                                                   │
│  User generates SSH key pair                                      │
│         │                                                         │
│         ▼                                                         │
│  User submits public key to Vault SSH sign endpoint                │
│  docker exec vault vault write ssh/sign/sign-ssh ...              │
│         │                                                         │
│         ▼                                                         │
│  Vault returns signed certificate (5 min TTL)                     │
│         │                                                         │
│         ▼                                                         │
│  User SSHs to gateway:2222 with signed cert                       │
│         │                                                         │
│         ▼                                                         │
│  Gateway validates cert against /ssh/ca.pub                       │
│  PasswordAuthentication no → only certs accepted                  │
│         │                                                         │
│         ▼                                                         │
│  Gateway forwards to ssh-server (internal)                        │
│         │                                                         │
│         ▼                                                         │
│  SSH tunnel to internal-app:80 (accessible only via tunnel)       │
└──────────────────────────────────────────────────────────────────┘
```

### DC1 vs DC2 Isolation

| Datacenter | SSH Engine Path | Gateway | Port | CA Volume |
|-----------|----------------|---------|------|-----------|
| DC1 | `ssh/` | gateway | 2222 | `ssh-ca-pub:/ssh` |
| DC2 | `ssh-dc2/` | gateway-dc2 | 2223 | `ssh-ca-dc2-pub:/ssh` |

Each datacenter has its own CA signing key. DC1 and DC2 gateways trust only their respective CA.

---

## Terraform-Managed Vault Configuration

All Vault resources (PKI, KV, auth backends, OIDC, SSH CA, policies) are managed
declaratively via Terraform HCL in the `terraform/` directory.

### Terraform Files

| File | Resources Managed |
|------|------------------|
| `main.tf` | Provider config (hashicorp/vault ~> 4.0) |
| `pki.tf` | PKI mount, intermediate CA import, URLs, server role |
| `kv.tf` | KV v2 mount, `server-config` secret |
| `policies.tf` | admin-policy, ops-policy, dev-policy, server-policy |
| `auth.tf` | userpass auth, cert auth, go-server cert role |
| `vault-oidc.tf` | OIDC auth backend, admin/ops/dev roles with redirect URIs |
| `ssh.tf` | SSH engine (DC1), CA key generation, sign-ssh role |
| `ssh-dc2.tf` | SSH engine (DC2), independent CA key, sign-ssh role |
| `variables.tf` | vault_addr, vault_token, certs_dir, policies_dir |

### Execution

Terraform is run by `scripts/init-all.sh` which:
1. Waits for Vault + Authentik health
2. Initializes Authentik OIDC provider (users, groups, application)
3. Runs `terraform init` and imports existing resources
4. Applies Terraform configuration
5. Falls back to CLI commands if OIDC Terraform step fails due to timing

### Application Flow (init-all.sh)

```
[1] Wait for Vault (https://localhost:8200)
[2] Wait for Authentik (http://localhost:9000)
[3] Initialize Authentik (create groups, users, OIDC provider, application)
[4] Apply Terraform (PKI → KV → policies → auth → OIDC → SSH)
[5] Export SSH CA public keys to gateway volumes
[6] Final verification
```5. Client validates nginx cert against `ca-chain.crt`
6. Mutual TLS established; WebSocket upgrade proceeds

**Phase 2: nginx → Go Server (upstream mTLS)**

1. nginx initiates HTTPS connection to `go-server:9090`
2. nginx presents `nginx-proxy.crt` as its client certificate
3. Go server requires client certificate verification
4. Go server validates proxy cert against `ca-chain.crt`
5. Go server presents `server.crt` as its server certificate
6. nginx validates server cert against `trust-chain.crt` (Vault PKI + root)
7. Mutual TLS established; HTTP/1.1 proxied with WebSocket upgrade headers

### WebSocket Flow

```
Client                    nginx                  Go Server
  │                         │                       │
  │──── WSS Upgrade ──────►│                       │
  │   (mTLS layer 1)       │                       │
  │                         │── HTTP Upgrade ─────►│
  │                         │   (mTLS layer 2)     │
  │                         │◄─── 101 Switching ───│
  │◄──── 101 Switching ────│                       │
  │                         │                       │
  │──── "Hello" ──────────►│──── "Hello" ─────────►│
  │                         │                       │
  │◄── "[echo]: Hello" ────│◄── "[echo]: Hello" ───│
  │                         │                       │
  │── "mTLS is working!"──►│── "mTLS is working!"─►│
  │◄── "[echo]: mTLS..." ──│◄── "[echo]: mTLS..." ─│
  │                         │                       │
```

---

## Component Responsibilities

### 1. Root CA (YubiKey 5C Nano, Slot 9C)

- **Key source**: OpenSSL-generated RSA 2048 → imported to YubiKey (not on-card generated)
- **Software backup**: `root-ca/root-ca-key.pem` ⚠️ retained for disaster recovery
- **Cold key**: YubiKey only inserted for signing intermediate CSRs
- **Key material**: Imported key with `never extractable`, `always sensitive` policy on YubiKey
- **Security model**: If the YubiKey is lost, the software backup enables CA restoration
- **Operation**: Signing requires physical presence (YubiKey inserted) + PIN entry
- **Backup**: Root CA certificate (`certs/root-ca.crt`) is the trust anchor

### 2. step-ca Intermediate CA & ACME Server

- **Hot key**: Software key stored on disk (`intermediate-step-ca-key.pem`, chmod 400)
- **Purpose**: 
  - ACME server at `:8443` for automated client certificate enrollment
  - Signs static certs for nginx and nginx-proxy via OpenSSL
- **ACME clients**: go-client daemon enrolls via HTTP-01 challenge
- **ACME auto-renewal**: Client checks daily, renews at 7-day remaining threshold
- **ACME validation**: HTTP-01 challenge at `http://go-client:80/.well-known/acme-challenge/`
- **Trust anchor**: `ca-chain.crt` bundles step-ca + root for verification
- **Config**: `step-ca/config/ca.json`

### 3. Vault PKI Intermediate CA

- **Hot key**: Software key loaded into Vault at runtime
- **Purpose**: Signs Go server certificate; can dynamically issue server certs via Terraform
- **Management**: Declarative Terraform HCL (`terraform/pki.tf`)
- **Vault integration**: PKI secrets engine at `pki/` path
- **Role**: `pki/roles/server` — allows cert issuance for Go server
- **Trust anchor**: `trust-chain.crt` bundles vault PKI + root for verification

### 4. nginx Reverse Proxy

- **TLS termination**: Incoming mTLS on port 443
- **Client verification**: Requires valid client cert (ACME cert) signed by step-ca intermediate
- **Upstream mTLS**: Re-authenticates to Go server using nginx-proxy certificate
- **WebSocket support**: `proxy_http_version 1.1` + `Connection: upgrade`
- **Config**: `nginx/nginx.conf`

### 5. Go Server (mTLS + Web UI)

- **mTLS**: Requires valid client cert (nginx-proxy) via `ca-chain.crt`
- **WebSocket**: Echo server at `/ws` on port 9090
- **Web UI**: HTTP interface at port 9091 (for heartbeats, device management)
- **Device API**: `/api/register` (mTLS), `/api/heartbeat` (HTTP)
- **Vault client**: Reads secrets from `kv/data/server-config` at startup
- **Auth**: Now uses `VAULT_TOKEN` env var (supports cert auth via `auth/token/create`)
- **Certs**: `server.crt` + `server-key.pem` (signed by Vault PKI intermediate)

### 6. Go Client (ACME Daemon)

- **ACME enrollment**: Bootstraps certificate from step-ca ACME at startup
- **Auto-renewal**: Background goroutine checks daily, renews at 7-day threshold
- **Device registration**: Registers with go-server via direct mTLS (`/api/register`)
- **SSH daemon**: Starts system OpenSSH daemon with TrustedUserCAKeys config
- **Heartbeat**: Sends heartbeat to go-server:9091 every 30s
- **WebSocket echo**: Maintains persistent WS echo connection through nginx:443
- **Long-running**: Daemon stays up; exits only on interrupt signal

### 7. Vault Secrets Engine (Terraform-Managed)

- **KV v2**: `kv/data/server-config` — API key and database password
- **PKI**: `pki/` secrets engine with imported Vault PKI intermediate
- **Cert Auth**: `auth/cert` — go-server role with `trust-chain.crt` binding
- **Userpass**: `auth/userpass` — admin/ops/dev users with password auth
- **OIDC**: `auth/oidc` — JWT/OIDC backend pointing to Authentik
- **SSH CA (DC1)**: `ssh/` — CA key + sign-ssh role (5 min TTL)
- **SSH CA (DC2)**: `ssh-dc2/` — independent CA key + sign-ssh role
- **Policies**: admin-policy (full access), ops-policy (prod read/PKI issue), dev-policy (dev read)

### 8. step-ca ACME Certificate Authority

- **Image**: `smallstep/step-ca:latest`
- **Port**: 8443
- **Purpose**: ACME certificate issuance for go-client daemon
- **ACME endpoint**: `https://step-ca:8443/acme/acme/directory`
- **TLS**: Serves with intermediate.crt signed by root-ca.crt
- **Enrollment**: HTTP-01 challenge (step-ca connects to go-client:80)
- **ACME account**: ECDSA P-256 key; certificate key: RSA 2048

### 9. Gateway SSH Bastions

| Gateway | Port | CA Trust | Purpose |
|---------|------|----------|---------|
| gateway | 2222 | DC1 (`ssh-ca-pub`) | Primary SSH bastion |
| gateway-dc2 | 2223 | DC2 (`ssh-ca-dc2-pub`) | Multi-DC isolation demo |

- **Auth**: Certificate-only (`PasswordAuthentication no`)
- **CA trust**: `TrustedUserCAKeys /ssh/ca.pub`
- **Tunnel support**: `AllowTcpForwarding yes`, `GatewayPorts yes`
- **SSH target**: Forwards to internal ssh-server, then tunnel to internal-app

### 10. Authentik OIDC Identity Provider

- **Server port**: 9000
- **Database**: PostgreSQL 16 (internal)
- **Cache**: Redis 7 (internal)
- **Users**: admin/123123, ops/123123, dev/123123
- **Groups**: admin-group, ops-group, dev-group
- **OIDC client**: vault-client-id / vault-client-secret
- **Application**: "Vault" mapped to Vault OIDC provider

---

## Port Mapping

| Service | Internal Port | External Port | Protocol |
|---------|--------------|---------------|----------|
| nginx | 443 | 443 | HTTPS (mTLS) |
| Vault | 8200 | 8200 | HTTPS (dev-tls) |
| Go Server (mTLS) | 9090 | 9090 | HTTPS (mTLS) |
| Go Server (HTTP) | 9091 | 9091 | HTTP (heartbeat) |
| step-ca | 8443 | — | HTTPS (ACME) |
| Gateway DC1 | 22 | 2222 | SSH (cert auth) |
| Gateway DC2 | 22 | 2223 | SSH (cert auth) |
| Authentik | 9000 | 9000 | HTTP (OIDC UI)

---

## Certificate Details

### Leaf Certificates

| Cert | Signed By | Key Usage | Extended Key Usage | SAN |
|------|-----------|-----------|-------------------|-----|
| `nginx.crt` | step-ca | digitalSignature, keyEncipherment | serverAuth | nginx, localhost, 127.0.0.1 |
| `client.crt` | step-ca | digitalSignature | clientAuth | — |
| `nginx-proxy.crt` | step-ca | digitalSignature | clientAuth | — |
| `server.crt` | Vault PKI | digitalSignature, keyEncipherment | serverAuth | go-server, localhost, 127.0.0.1 |

### Chain Files

| File | Order |
|------|-------|
| `ca-chain.crt` | step-ca Intermediate (top) → Root CA (bottom) |
| `trust-chain.crt` | Vault PKI Intermediate (top) → Root CA (bottom) |

---

## Security Properties

1. **Defense in depth**: Two separate intermediate CAs — compromise of one does not
   compromise the other
2. **Hardware root of trust**: Root CA private key on YubiKey (software backup retained
   for disaster recovery — store offline in production)
3. **Dual mTLS**: Both ingress (client→nginx) and backend (nginx→server) use mutual TLS
4. **OIDC SSO**: Authentik identity → Vault OIDC → group-based RBAC (admin/ops/dev)
5. **SSH CA**: Vault SSH engine signs short-lived certs (5 min TTL) — unsigned keys rejected
6. **Multi-DC isolation**: DC1 and DC2 have independent SSH CA keys and gateways
7. **TLS 1.2 minimum**: No legacy protocol support
8. **Secrets isolation**: Application secrets in Vault KV, not in environment variables or files
9. **Read-only mounts**: All certificate volumes mounted `:ro` in production
10. **No root CA in runtime**: Root key never touches any server; offline in YubiKey
11. **No password auth**: SSH gateways use certificate-only auth (`PasswordAuthentication no`)
