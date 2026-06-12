#!/bin/sh
# ssh-demo.sh — Demonstrate Vault SSH Certificate Signing
#
# Usage: ./ssh-demo.sh
# Prerequisites: ssh-keygen, ssh, python3 on host; docker compose running
#
# This script demonstrates Vault SSH CA:
# 1. Generate a temporary SSH key pair
# 2. Sign the public key with Vault (5 min TTL) via docker compose exec
# 3. SSH to ssh-server using the signed cert — SUCCESS
# 4. Show cert details
# 5. Show that unsigned key would be rejected

set -e

COMPOSE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "=== Vault SSH Certificate Signing Demo ==="
echo ""

# Step 1: Generate SSH key pair
echo "--- Step 1: Generating SSH key pair ---"
ssh-keygen -t rsa -b 2048 -f "$TEMP_DIR/id_rsa" -N "" -q
echo "  Private key: $TEMP_DIR/id_rsa"
echo "  Public key:  $TEMP_DIR/id_rsa.pub"
echo ""

# Step 2: Sign with Vault SSH CA (inside vault container)
echo "--- Step 2: Signing public key with Vault SSH CA ---"
docker compose -f "$COMPOSE_DIR/docker-compose.yml" cp "$TEMP_DIR/id_rsa.pub" vault:/tmp/ssh-demo.pub >/dev/null 2>&1

docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T vault sh -c \
  "VAULT_ADDR=http://vault:8200 VAULT_TOKEN=root-token vault write -format=json \
  ssh/sign/sign-ssh public_key=@/tmp/ssh-demo.pub valid_principals=ssh-user \
  > /tmp/ssh-demo-result.json 2>&1"

docker compose -f "$COMPOSE_DIR/docker-compose.yml" cp vault:/tmp/ssh-demo-result.json \
  "$TEMP_DIR/ssh-demo-result.json" >/dev/null 2>&1

python3 -c "
import json
with open('$TEMP_DIR/ssh-demo-result.json') as f:
    d = json.load(f)
print('  Serial:', d['data']['serial_number'])
cert = d['data']['signed_key']
with open('$TEMP_DIR/id_rsa-cert.pub', 'w') as f:
    f.write(cert)
print('  Signed certificate saved to: id_rsa-cert.pub')
"
echo ""

# Step 3: Verify the certificate
echo "--- Step 3: Verifying the certificate ---"
ssh-keygen -L -f "$TEMP_DIR/id_rsa-cert.pub" 2>&1 | head -12
echo ""

# Step 4: SSH login attempt with signed cert
echo "--- Step 4: SSH login with signed certificate ---"
echo "  Attempting ssh ssh-user@localhost -p 2222 ..."
if ssh -o StrictHostKeyChecking=no \
       -o UserKnownHostsFile=/dev/null \
       -o LogLevel=ERROR \
       -i "$TEMP_DIR/id_rsa" \
       ssh-user@localhost -p 2222 \
       "echo '  ✅ SSH LOGIN SUCCESSFUL with signed certificate!'; hostname; id"; then
    echo "  ✅ Certificate-based SSH login works!"
else
    echo "  ❌ SSH login failed. Check configuration."
    exit 1
fi
echo ""

# Step 5: Show cert details
echo "--- Step 5: Certificate details ---"
echo "  Issued by: Vault SSH CA"
echo "  Valid for: 5 minutes"
echo "  To verify expiration: ssh-keygen -L -f ~/.ssh/id_rsa-cert.pub"
echo "  After expiry: ssh will reject the certificate"
echo ""

# Step 6: Show unsigned key would fail
echo "--- Step 6: Unsigned key would be rejected ---"
echo "  ssh-server config: PasswordAuthentication=no"
echo "  ssh-server config: TrustedUserCAKeys=/ssh/ca.pub"
echo "  => Only certificates signed by Vault SSH CA are accepted"
echo "  => Unsigned public keys are rejected"
echo ""

echo "=== Demo complete ==="