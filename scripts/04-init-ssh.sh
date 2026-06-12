#!/bin/sh
# 04-init-ssh.sh — Configure Vault SSH Certificate Authority
set -e
apk add --no-cache openssh-keygen openssh-client 2>/dev/null || true

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:?VAULT_TOKEN must be set}"
export VAULT_ADDR VAULT_TOKEN

echo "=== Zero-FAS Vault SSH CA Setup ==="

echo ""
echo "--- 1. Enabling SSH secrets engine ---"
vault secrets enable ssh 2>/dev/null || echo "  (already enabled, continuing)"

echo ""
echo "--- 2. Configuring SSH CA ---"
if vault read ssh/config/ca >/dev/null 2>&1; then
  echo "  SSH CA already configured, skipping."
else
  vault write ssh/config/ca generate_signing_key=true
  echo "  SSH CA key generated."
fi

echo ""
echo "--- 3. Creating signing role ---"
# Use stdin (-) with JSON for proper map handling of default_extensions
vault write ssh/roles/sign-ssh - <<EOF
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
EOF
echo "  Role 'sign-ssh' created (TTL: 5 minutes)."

echo ""
echo "--- 4. Exporting CA public key ---"
mkdir -p /ssh
vault read -field=public_key ssh/config/ca > /ssh/ca.pub
echo "  CA public key written to /ssh/ca.pub"

echo ""
echo "=== Vault SSH CA setup complete ==="
echo "  Users can sign their SSH keys with:"
echo "    vault write ssh/sign/sign-ssh public_key=@~/.ssh/id_rsa.pub"
echo ""
echo "  Then SSH with:"

echo ""
echo "--- 5. Generating gateway-internal SSH key pair ---"
mkdir -p /ssh-keys
# Generate a key pair for the gateway to use when connecting to ssh-server
if [ -f /ssh-keys/gateway-key ]; then
  echo "  Gateway key already exists, skipping generation."
else
  ssh-keygen -t rsa -b 2048 -f /ssh-keys/gateway-key -N "" -q
  echo "  Gateway key pair generated."
fi
echo "  Gateway key pair generated."

# Sign it for ssh-user (the target user on ssh-server)
vault write -format=json ssh/sign/sign-ssh \
  public_key=@/ssh-keys/gateway-key.pub \
  valid_principals=ssh-user > /tmp/gateway-cert.json 2>&1

VAULT_SKIP_VERIFY=true vault write -field=signed_key ssh/sign/sign-ssh   public_key=@/ssh-keys/gateway-key.pub   valid_principals=ssh-user > /ssh-keys/gateway-key-cert.pub
echo "  Gateway SSH certificate signed for ssh-user."
chmod 600 /ssh-keys/gateway-key /ssh-keys/gateway-key-cert.pub
rm -f /tmp/gateway-cert.json
echo "  Gateway keys stored in /ssh-keys/"
echo "    ssh -i ~/.ssh/id_rsa-cert.pub user@host"