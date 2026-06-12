# Zero-FAS mTLS Lab

> **Zero-Trust PKI Laboratory with YubiKey Hardware Root of Trust**
>
> Three-layer PKI hierarchy · mTLS WebSocket communications · Docker Compose deployment
> Root CA on YubiKey 5C Nano (RSA 2048, never extractable)

---

## Quick Start

```bash
# Prerequisites: Docker, YubiKey inserted, root CA initialized on slot 9C

# 1. Build all images
docker compose build

# 2. Deploy the stack
docker compose up -d

# 3. Watch initialization
docker compose logs -f
```

After deployment, verify the setup: [docs/VERIFY.md](docs/VERIFY.md)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    YubiKey 5C Nano                          │
│                   PIV slot 9C (RSA 2048)                    │
│               Root CA — COLD (non-extractable)               │
│               Signs: intermediate CAs only                   │
└────────────────────┬────────────────────────────────────────┘
                     │ signs via pkcs11-tool
          ┌──────────┴──────────┐
          ▼                     ▼
┌─────────────────┐  ┌──────────────────────┐
│ step-ca Interm. │  │ Vault PKI Interm.    │
│ CA (HOT key)    │  │ CA (HOT key)         │
│ pathlen:0       │  │ pathlen:0            │
│                 │  │                      │
│ Signs:          │  │ Signs:               │
│  • nginx        │  │  • Go server         │
│  • nginx-proxy  │  │                      │
│  • client       │  │                      │
└────────┬────────┘  └──────────┬───────────┘
         │                      │
         ▼                      ▼
   nginx (reverse proxy)    Go Server (mTLS)
         │                      │
         └──────────┬───────────┘
                    ▼
              Go Client (mTLS)
```

**Full architecture**: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## Trust Chain

```
Root CA (cold, YubiKey, slot 9C, RSA 2048)
  ├── step-ca Intermediate CA (hot, software key)
  │     ├── nginx.crt       (serverAuth, SAN: nginx, localhost, 127.0.0.1)
  │     ├── nginx-proxy.crt (clientAuth, mTLS upstream)
  │     └── client.crt      (clientAuth, mTLS client)
  └── Vault PKI Intermediate CA (hot, software key, in Vault)
        └── server.crt      (serverAuth, SAN: go-server, localhost, 127.0.0.1)
```

### Chain Files

| File | Contents | Used By |
|------|----------|---------|
| `certs/ca-chain.crt` | step-ca Intermediate + Root CA | nginx client verify, Go server client verify |
| `certs/trust-chain.crt` | Vault PKI Intermediate + Root CA | nginx upstream verify |

---

## Communication Flow

```
┌──────────┐    wss://nginx:443/ws    ┌──────────┐   http://go-server:9090/ws   ┌───────────┐
│ Go Client │ ──────────────────────► │  nginx   │ ──────────────────────────► │ Go Server │
│ (mTLS)    │◄────────────────────────│ (reverse │◄───────────────────────────│ (mTLS)    │
│           │                         │  proxy)  │                              │           │
└──────────┘                          └──────────┘                              └───────────┘
```

1. **Client → nginx**: Mutual TLS via `client.crt` + `ca-chain.crt` verification
2. **nginx → Server**: Mutual TLS via `nginx-proxy.crt` + `trust-chain.crt` verification
3. **Go Server**: Reads secrets from Vault at startup (`kv/data/server-config`)
4. **WebSocket**: Client sends 3 test messages, receives `[server-echo]` responses

---

## Directory Structure

```
vault/
├── docker-compose.yml          # Service orchestration
├── README.md                   # This file
├── docs/
│   ├── ARCHITECTURE.md         # PKI architecture & communication flow
│   ├── SETUP.md                # Deployment guide (root CA → build → deploy)
│   └── VERIFY.md               # Verification steps & checklist
├── certs/                      # All certificates and keys
│   ├── root-ca.crt             # Root CA certificate (PEM)
│   ├── root-ca.der             # Root CA certificate (DER)
│   ├── root-ca.pub             # Root CA public key (PEM)
│   ├── intermediate-step-ca.crt / .key / .csr
│   ├── intermediate-vault-pki.crt / .key / .csr
│   ├── nginx.crt / nginx-key.pem
│   ├── nginx-proxy.crt / nginx-proxy-key.pem
│   ├── server.crt / server-key.pem
│   ├── client.crt / client-key.pem
│   ├── ca-chain.crt            # step-ca + root
│   └── trust-chain.crt         # vault PKI + root
├── go-server/
│   ├── main.go                 # WebSocket echo server with mTLS + Vault client
│   ├── Dockerfile
│   ├── go.mod
│   └── go.sum
├── go-client/
│   ├── main.go                 # WebSocket client with mTLS
│   ├── Dockerfile
│   ├── go.mod
│   └── go.sum
├── nginx/
│   ├── nginx.conf              # Reverse proxy with mTLS + WebSocket
│   └── Dockerfile
├── vault/
│   ├── config/vault.hcl        # Vault server config
│   └── policies/server-policy.hcl
├── scripts/
│   ├── 01-init-root-ca.sh      # Root CA on YubiKey setup
│   ├── 02-init-vault.sh        # Vault PKI + KV + AppRole init
│   └── sign-intermediate.py    # CSR signing with YubiKey
└── root-ca/
    ├── root-ca-ext.cnf
    ├── root-ca-openssl.cnf
    ├── intermediate-step-ca-openssl.cnf
    └── intermediate-vault-pki-openssl.cnf
```

---

## Services

| Service | Image | Purpose | Exposed Port |
|---------|-------|---------|-------------|
| `vault` | hashicorp/vault:latest | Secrets engine (dev mode) | 8200 |
| `vault-init` | hashicorp/vault:latest | One-shot PKI + KV + AppRole setup | — |
| `go-server` | local (go-server/Dockerfile) | mTLS WebSocket echo server | 9090* |
| `nginx` | local (nginx/Dockerfile) | mTLS reverse proxy with WebSocket | 443 |
| `go-client` | local (go-client/Dockerfile) | One-shot mTLS WebSocket test | — |

\* go-server port 9090 is internal (exposed only within the compose network)

---

## Deployment

**Setup** (first time, requires YubiKey):
1. Initialize Root CA on YubiKey: `bash scripts/01-init-root-ca.sh`
2. Generate intermediates and leaf certs (see [docs/SETUP.md](docs/SETUP.md))
3. Build containers: `docker compose build`
4. Deploy: `docker compose up -d`

**Verify**: See [docs/VERIFY.md](docs/VERIFY.md) for a 14-step verification checklist.

---

## YubiKey Details

| Property | Value |
|----------|-------|
| Device | YubiKey 5C Nano |
| Firmware | PIV 5.4.3 |
| Slot | 9C (Digital Signature) |
| Algorithm | RSA 2048 |
| Key Policy | `never extractable`, `always sensitive`, `always authenticate` |
| PIN | `123123` |

---

## Technical Notes

- RSA 2048 maximum for on-card YubiKey generation (YubiKey 5C Nano limitation)
- PKCS#11 modules: Yubico (`libykcs11.dylib`) and OpenSC (`opensc-pkcs11.so`)
- Root CA construction uses manual DER assembly (workaround for `yubico-piv-tool 2.7.3` bug)
- Vault uses `-dev` mode (auto-initialized, no unseal step required)
- All private keys: `chmod 600`

---

## Security Properties

- **Hardware root of trust**: Root CA key never leaves YubiKey
- **Defense in depth**: Two separate intermediate CAs (compromise of one ≠ compromise of the other)
- **Dual mTLS**: Both ingress and backend paths use mutual TLS
- **TLS 1.2 minimum**: No legacy protocol support
- **Secrets isolation**: Application secrets in Vault, not in environment or config files
- **Read-only cert mounts**: All certificate volumes mounted `:ro`

---

## References

- [Architecture Document](docs/ARCHITECTURE.md) — Full PKI hierarchy, mTLS flow, component responsibilities
- [Setup Guide](docs/SETUP.md) — Step-by-step from YubiKey initialization to deployment
- [Verification Guide](docs/VERIFY.md) — 14-point verification checklist
