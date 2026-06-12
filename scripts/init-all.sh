#!/bin/bash
# One-click initialization for mTLS Lab
# Run from the host after docker compose up -d

set -e

echo "=== mTLS Lab: Full Initialization ==="

# Step 1: Wait for services to be ready
echo "[1/4] Waiting for Vault..."
while ! curl -sk https://localhost:8200/v1/sys/health >/dev/null 2>&1; do sleep 2; done
echo "  Vault ready ✅"

echo "[2/4] Waiting for Authentik..."
while ! curl -s http://localhost:9000/api/v3/ >/dev/null 2>&1; do sleep 2; done
echo "  Authentik ready ✅"

# Step 2: Initialize Authentik (groups, users, OIDC provider)
echo "[3/4] Initializing Authentik..."
docker exec authentik-server /ak-root/venv/bin/python3 \
  /scripts/create_ak_config.py 2>&1 | grep -E "Group:|User:|OIDC|Signing|Application|Done" | sed 's/^/  /'
echo "  Authentik init complete ✅"

# Step 3: Configure Vault OIDC + policies via Terraform
echo "[4/4] Applying Terraform for Vault OIDC..."
cd "$(dirname "$0")/../terraform"
apk add --no-cache terraform >/dev/null 2>&1 || true
VAULT_ADDR=https://localhost:8200 VAULT_TOKEN=root-token VAULT_SKIP_VERIFY=true \
  terraform init >/dev/null 2>&1
VAULT_ADDR=https://localhost:8200 VAULT_TOKEN=root-token VAULT_SKIP_VERIFY=true \
  terraform apply -auto-approve 2>&1 | grep -E "Apply complete|Added|Changed"
echo "  Terraform apply complete ✅"

echo ""
echo "=== Initialization Complete ==="
echo "Vault UI:     https://localhost:8200/ui (OIDC: admin/123123)"
echo "Authentik:    http://localhost:9000 (admin/123123)"
echo "Web UI:       http://localhost:9091"
