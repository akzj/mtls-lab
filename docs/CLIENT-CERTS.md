# Client Certificate Authentication

## Authentication Methods

| Method | User Type | How |
|--------|-----------|-----|
| WebUI (OIDC) | Human via browser | Login via Authentik → Vault OIDC |
| CLI (mTLS) | Script/user via terminal | Vault PKI issues client cert → mTLS API call |

## Generating a Client Certificate

### Via Vault CLI:

```bash
vault write pki/issue/user common_name=username@domain.com ttl=24h \
  -format=json > cert.json

# Save certificate and key
cat cert.json | jq -r '.data.certificate' > client.crt
cat cert.json | jq -r '.data.private_key' > client-key.pem
chmod 600 client-key.pem
```

### Via curl:

```bash
# Login to Vault first (requires DNS for vault.lab.local)
VAULT_TOKEN=$(curl -sk \
  -X POST https://vault.lab.local:8200/v1/auth/userpass/login/admin \
  -d '{"password":"admin123"}' | jq -r '.auth.client_token')

# Fallback (no DNS):
# VAULT_TOKEN=$(curl -sk \
#   -X POST https://localhost:8200/v1/auth/userpass/login/admin \
#   -d '{"password":"admin123"}' | jq -r '.auth.client_token')

# Issue certificate
curl -sk -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST https://vault.lab.local:8200/v1/pki/issue/user \
  -d '{"common_name":"admin@zero-fas.local","ttl":"24h"}' > cert.json

# Extract cert and key
jq -r '.data.certificate' cert.json > client.crt
jq -r '.data.private_key' cert.json > client-key.pem
chmod 600 client-key.pem
```

### Using the Demo Script:

```bash
./scripts/cli-demo.sh
```

This will:
1. Log into Vault (userpass: admin / admin123)
2. Request a client certificate from `pki/issue/user`
3. Save cert → `/tmp/cli-user.crt`, key → `/tmp/cli-user-key.pem`
4. Call `GET /api/whoami` with the client cert via mTLS

## Using the Certificate for API Calls

```bash
curl --cert client.crt --key client-key.pem \
  --cacert certs/trust-chain.crt \
  https://web.lab.local:9090/api/whoami

# Fallback (no DNS):
# curl --cert client.crt --key client-key.pem \
#   --cacert certs/trust-chain.crt \
#   https://localhost:9090/api/whoami
```

Response:
```json
{
  "username": "admin@zero-fas.local",
  "auth_method": "client_cert",
  "cn": "admin@zero-fas.local"
}
```

## API Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/whoami` | mTLS (client cert) | Returns authenticated user identity |
| `POST /api/register` | mTLS (client cert) | Register device, returns SSH CA config |

Both endpoints are on the mTLS server (`:9090`), which requires client certificate authentication.
The HTTP server (`:9091`) serves the Web UI and tunnel APIs without mTLS.

## Requirements

- Vault PKI intermediate must be trusted by go-server (included in `certs/trust-chain.crt`)
- User must have permission to issue certs from `pki/issue/user`
- Client certificate must have `ext_key_usage = ["ClientAuth"]`
- The `pki/issue/user` role is defined in `terraform/pki.tf`

## Architecture

```
CLI user                     go-server:9090 (mTLS)          Vault
    │                             │                          │
    ├─ POST /pki/issue/user ──────┼─────────────────────────►│
    │◄── client.crt + key ────────┼──────────────────────────┤
    │                             │                          │
    ├─ GET /api/whoami (mTLS) ────►│                          │
    │◄── {username, auth_method} ──┤                          │
    │                             │                          │
    │  Client cert CN extracted   │                          │
    │  from r.TLS.PeerCertificates │                          │
```
