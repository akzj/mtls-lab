# Zero-FAS mTLS Lab — Architecture

## Overview

Three-layer PKI hierarchy with a YubiKey hardware root of trust, two intermediate
certificate authorities, and four leaf certificates enabling mTLS WebSocket
communications between a Go client and Go server through an nginx reverse proxy.

---

## PKI Hierarchy

```
┌──────────────────────────────────────────────────────────────────┐
│                    Root CA (Cold / YubiKey)                      │
│                    ─────────────────────────                      │
│                    YubiKey 5C Nano · PIV slot 9C                │
│                    RSA 2048 · Never extractable                  │
│                    CN = Zero-FAS Root CA                         │
│                    Self-signed · 10-year validity                │
│                    Signs ONLY intermediate CSRs                   │
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
│ CN = step-ca Interned. │    │ CN = Vault PKI Interned.   │
│ Serial: 0x02           │    │ Serial: 0x03               │
│ pathlen:0              │    │ pathlen:0                  │
│ 5-year validity        │    │ 5-year validity            │
│                        │    │                            │
│ Signs:                 │    │ Signs:                     │
│  • nginx (serverAuth)  │    │  • Go server (serverAuth)  │
│  • nginx-proxy (client)│    │                            │
│  • client (clientAuth) │    │                            │
└───────────┬────────────┘    └───────────┬────────────────┘
            │                             │
            ▼                             ▼
   ┌──────────────────┐         ┌──────────────────────┐
   │   nginx.crt      │         │    server.crt        │
   │   nginx-proxy.crt│         │  (Go server leaf)    │
   │   client.crt     │         │                      │
   └──────────────────┘         └──────────────────────┘
```

### Certificate Path Validation

```
Leaf (client) → step-ca Intermediate → Root CA
Leaf (nginx)  → step-ca Intermediate → Root CA
Leaf (proxy)  → step-ca Intermediate → Root CA
Leaf (server) → Vault PKI Intermediate → Root CA
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
5. Client validates nginx cert against `ca-chain.crt`
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

- **Cold key**: Never connected to network; used only for signing intermediate CSRs
- **Key material**: Generated on-card; `never extractable`, `always sensitive`
- **Security model**: If the YubiKey is lost, all intermediate CAs and leaf certs
  must be re-issued
- **Operation**: Signing requires physical presence (YubiKey inserted) + PIN entry
- **Backup**: Root CA certificate (`certs/root-ca.crt`) is the trust anchor;
  private key has NO backup

### 2. step-ca Intermediate CA

- **Hot key**: Software key stored on disk (`intermediate-step-ca-key.pem`, chmod 600)
- **Purpose**: Signs certificates for the nginx ingress layer
- **Issued certs**: nginx (server), nginx-proxy (client auth), client (client auth)
- **Trust anchor**: `ca-chain.crt` bundles step-ca + root for verification

### 3. Vault PKI Intermediate CA

- **Hot key**: Software key loaded into Vault at runtime
- **Purpose**: Signs Go server certificate; can dynamically issue server certs
- **Vault integration**: PKI secrets engine at `pki/` path
- **Role**: `pki/roles/server` — allows cert issuance for Go server
- **Trust anchor**: `trust-chain.crt` bundles vault PKI + root for verification

### 4. nginx Reverse Proxy

- **TLS termination**: Incoming mTLS on port 443
- **Client verification**: Requires valid client cert signed by step-ca intermediate
- **Upstream mTLS**: Re-authenticates to Go server using nginx-proxy certificate
- **WebSocket support**: `proxy_http_version 1.1` + `Connection: upgrade`
- **Config**: `nginx/nginx.conf`

### 5. Go Server

- **mTLS**: Requires valid client cert (nginx-proxy) via `ca-chain.crt`
- **WebSocket**: Echo server at `/ws` on port 9090
- **Vault client**: Reads secrets from `kv/data/server-config` at startup
- **Auth**: Currently uses `VAULT_TOKEN` env var; can switch to AppRole
- **Certs**: `server.crt` + `server-key.pem` (signed by Vault PKI intermediate)

### 6. Go Client

- **mTLS**: Authenticates with `client.crt` + `client-key.pem`
- **Server verification**: Validates nginx cert against `ca-chain.crt`
- **WebSocket**: Connects to `wss://nginx:443/ws`, sends 3 test messages
- **Exit**: Exits after successful message exchange + 2s grace period

### 7. Vault Secrets Engine

- **KV v2**: `kv/data/server-config` — API key and database password
- **PKI**: `pki/` secrets engine with imported Vault PKI intermediate
- **AppRole**: `auth/approle/role/server` — role ID + secret ID for Go server auth
- **Policy**: `server-policy.hcl` — read `kv/data/server-config`, issue `pki/role/server`

---

## Port Mapping

| Service | Internal Port | External Port | Protocol |
|---------|--------------|---------------|----------|
| nginx | 443 | 443 | HTTPS (mTLS) |
| Vault | 8200 | 8200 | HTTP |
| Go Server | 9090 | (none) | HTTPS (mTLS) |

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
2. **Hardware root of trust**: Root CA private key cannot be extracted from YubiKey
3. **Dual mTLS**: Both ingress (client→nginx) and backend (nginx→server) use mutual TLS
4. **TLS 1.2 minimum**: No legacy protocol support
5. **Secrets isolation**: Application secrets in Vault, not in environment variables or files
6. **Read-only mounts**: All certificate volumes mounted `:ro` in production
7. **No root CA in runtime**: Root key never touches any server; offline in YubiKey
