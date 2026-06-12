#!/bin/sh
# 05-init-ssh-dc2.sh — Configure DC2 SSH Certificate Authority (multi-DC isolation demo)
set -e

VAULT_ADDR="${VAULT_ADDR:-https://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:?VAULT_TOKEN must be set}"
export VAULT_ADDR VAULT_TOKEN

echo "=== Zero-FAS DC2 SSH CA Setup ==="

echo ""
echo "--- 1. Enabling SSH secrets engine at ssh-dc2/ ---"
vault secrets enable -path=ssh-dc2 ssh 2>/dev/null || echo "  (already enabled, continuing)"

echo ""
echo "--- 2. Configuring DC2 SSH CA ---"
if vault read ssh-dc2/config/ca >/dev/null 2>&1; then
  echo "  DC2 SSH CA already configured, skipping."
else
  vault write ssh-dc2/config/ca generate_signing_key=true
  echo "  DC2 SSH CA key generated (independent from DC1)."
fi

echo ""
echo "--- 3. Creating DC2 signing role ---"
cat > /tmp/dc2-role.json << 'JSONEOF'
{
  "key_type": "ca",
  "ttl": "5m",
  "allow_user_certificates": true,
  "allowed_users": "*",
  "default_extensions": {
    "login@openssh.com": "permit-pty",
    "permit-agent-forwarding": "",
    "permit-port-forwarding": ""
  }
}
JSONEOF
vault write ssh-dc2/roles/sign-ssh @/tmp/dc2-role.json
echo "  DC2 Role 'sign-ssh' created (TTL: 5 minutes)."
rm -f /tmp/dc2-role.json

echo ""
echo "--- 4. Exporting DC2 CA public key ---"
mkdir -p /ssh-dc2
vault read -field=public_key ssh-dc2/config/ca > /ssh-dc2/ca.pub
echo "  DC2 CA public key written to /ssh-dc2/ca.pub"

echo ""
echo "=== DC2 SSH CA setup complete ==="
echo "  DC2 users can sign with: vault write ssh-dc2/sign/sign-ssh public_key=@~/.ssh/id_rsa.pub"
