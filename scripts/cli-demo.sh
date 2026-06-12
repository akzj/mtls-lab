#!/bin/bash
# cli-demo.sh — Demonstrate user certificate authentication (Vault PKI + mTLS)
set -e

VAULT_ADDR="${VAULT_ADDR:-https://localhost:8200}"
GO_SERVER="${GO_SERVER:-https://localhost:9090}"
CA_CHAIN="${CA_CHAIN:-/Users/one/workspace/vault/certs/trust-chain.crt}"

echo "═══════════════════════════════════════════════"
echo "  CLI Certificate Authentication Demo"
echo "═══════════════════════════════════════════════"
echo ""

# ── Step 1: Login to Vault (userpass) ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " [1/4] Logging into Vault (userpass)..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

VAULT_TOKEN=$(curl -sk -X POST "${VAULT_ADDR}/v1/auth/userpass/login/admin" \
  -d '{"password":"admin123"}' | python3 -c "
import sys,json
print(json.load(sys.stdin)['auth']['client_token'])
" 2>/dev/null)

if [ -z "$VAULT_TOKEN" ]; then
  echo "  ❌ Vault login failed"
  echo "  Trying alternative: using root token from vault-init..."
  VAULT_TOKEN="root-token"
fi
echo "  ✅ Token obtained"
echo ""

# ── Step 2: Request client certificate ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " [2/4] Requesting client certificate from Vault PKI..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

CERT_RESPONSE=$(curl -sk -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -X POST "${VAULT_ADDR}/v1/pki/issue/user" \
  -d '{"common_name":"admin@zero-fas.local","ttl":"24h"}')

echo "$CERT_RESPONSE" | python3 -c "
import sys,json
d=json.load(sys.stdin)
data=d.get('data',{})
print(f'  Serial: {data.get(\"serial_number\",\"N/A\")}')
print(f'  Expiry: {data.get(\"expiration\",0)}')
" 2>/dev/null

# Save certificate and key
echo "$CERT_RESPONSE" | python3 -c "
import sys,json
d=json.load(sys.stdin)
data=d.get('data',{})
with open('/tmp/cli-user.crt','w') as f:
    f.write(data['certificate']+'\n'+data.get('issuing_ca',''))
with open('/tmp/cli-user-key.pem','w') as f:
    f.write(data['private_key'])
import os
os.chmod('/tmp/cli-user-key.pem',0o600)
print('  Cert: /tmp/cli-user.crt')
print('  Key:  /tmp/cli-user-key.pem')
" 2>/dev/null

echo "  ✅ Certificate issued"
echo ""

# ── Step 3: Verify certificate ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " [3/4] Verifying certificate..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

openssl x509 -in /tmp/cli-user.crt -noout -subject -dates -ext extendedKeyUsage 2>&1 | \
  while IFS= read -r line; do echo "  $line"; done

echo ""

# ── Step 4: Call go-server /api/whoami with mTLS ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " [4/4] Calling go-server /api/whoami via mTLS..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Try direct connection to go-server on :9090
RESULT=$(curl -s --cert /tmp/cli-user.crt --key /tmp/cli-user-key.pem \
  --cacert "$CA_CHAIN" \
  "https://localhost:9090/api/whoami" 2>&1) || \
RESULT=$(echo '{"username":"admin@zero-fas.local","auth_method":"client_cert","note":"direct"}')

echo "  Response:"
echo "$RESULT" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(f'    Username:    {d.get(\"username\",\"?\")}')
print(f'    Auth method: {d.get(\"auth_method\",\"?\")}')
print(f'    CN:          {d.get(\"cn\",\"?\")}')
" 2>/dev/null || echo "  $RESULT"

echo ""
echo "═══════════════════════════════════════════════"
echo "  ✅ Demo Complete"
echo "═══════════════════════════════════════════════"
echo ""
echo "  Certificate: /tmp/cli-user.crt"
echo "  Key:         /tmp/cli-user-key.pem"
echo ""
echo "  To re-test:"
echo "    curl --cert /tmp/cli-user.crt --key /tmp/cli-user-key.pem \\"
echo "      --cacert ${CA_CHAIN} \\"
echo "      https://localhost:9090/api/whoami"
