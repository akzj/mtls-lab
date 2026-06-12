#!/bin/sh
# apply.sh — Apply Terraform Vault configuration
# Run this from within the terraform/ directory with Vault access

set -e

cd "$(dirname "$0")"

# Create tfvars if not exists
if [ ! -f terraform.tfvars ]; then
  echo 'vault_token = "root-token"' > terraform.tfvars
fi

terraform init
terraform plan
terraform apply -auto-approve

echo "=== Terraform apply complete ==="
