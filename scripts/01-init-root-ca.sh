#!/usr/bin/env bash
#
# 01-init-root-ca.sh
# ====================
# Create Root CA: OpenSSL key generation → backup → YubiKey import
#
# This creates an RSA 2048-bit Root CA key with OpenSSL, creates a
# self-signed certificate with proper CA extensions, then imports both
# the private key and certificate into YubiKey PIV slot 9C.
#
# The software key backup is retained in root-ca/ for disaster recovery.
# In production, this backup should be stored securely offline.
#
# Prerequisites:
#   - YubiKey 5C Nano inserted (PIV enabled)
#   - yubico-piv-tool installed
#   - PIN: 123123 (default)
#
# Outputs:
#   root-ca/root-ca-key.pem  — Root CA private key (backup) ⚠️
#   certs/root-ca.crt        — Root CA certificate (PEM)
#   certs/root-ca.der        — Root CA certificate (DER, for YubiKey import)
#   certs/root-ca.pub        — Root CA public key (PEM)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="${PROJECT_DIR}/certs"
ROOT_CA_DIR="${PROJECT_DIR}/root-ca"

# YubiKey configuration
SLOT="9c"                        # Digital Signature slot
PIN="123123"
MGMT_KEY="010203040506070801020304050607080102030405060708"
SUBJECT="/CN=Zero-FAS Root CA"
VALID_DAYS=3650                   # ~10 years
SERIAL="0x01"

# Derived paths
CERT_PEM="${CERTS_DIR}/root-ca.crt"
CERT_DER="${CERTS_DIR}/root-ca.der"
KEY_PEM="${ROOT_CA_DIR}/root-ca-key.pem"
PUBKEY="${CERTS_DIR}/root-ca.pub"
OPENSSL_CONF="${ROOT_CA_DIR}/root-ca-ext.cnf"

mkdir -p "$CERTS_DIR" "$ROOT_CA_DIR"

echo "================================================"
echo " Root CA Setup: OpenSSL + YubiKey Import"
echo "================================================"

# ── Step 0: Idempotency check ──────────────────────
echo ""
echo "[0/6] Checking if root CA already exists..."

if [ -f "$CERT_PEM" ] && [ -f "$KEY_PEM" ]; then
    echo "  ✅ Root CA files already exist:"
    echo "     Certificate: ${CERT_PEM}"
    echo "     Key:         ${KEY_PEM}"
    echo ""
    echo "  Checking self-signature..."
    if openssl verify -CAfile "$CERT_PEM" "$CERT_PEM" >/dev/null 2>&1; then
        echo "  ✅ Self-signature valid. Root CA already initialized. Exiting."
        echo ""
        echo "  To regenerate, remove these files and re-run:"
        echo "    rm -f ${CERT_PEM} ${CERT_DER} ${PUBKEY} ${KEY_PEM}"
        exit 0
    else
        echo "  ⚠️  Certificate exists but self-signature INVALID. Recreating..."
    fi
else
    echo "  No existing root CA found. Proceeding with creation."
fi

# ── Step 1: Generate RSA 2048 key pair with OpenSSL ─
echo ""
echo "[1/6] Generating RSA 2048 key pair..."

openssl genrsa -out "$KEY_PEM" 2048 2>&1
chmod 600 "$KEY_PEM"
echo "  ✅ Key generated and saved to: ${KEY_PEM}"

# ── Step 2: Create self-signed Root CA certificate ─
echo ""
echo "[2/6] Creating self-signed root CA certificate..."
echo "      Subject: ${SUBJECT}"
echo "      Validity: ${VALID_DAYS} days"
echo "      Config: ${OPENSSL_CONF}"

if [ ! -f "$OPENSSL_CONF" ]; then
    echo "  ❌ Extension config not found: ${OPENSSL_CONF}"
    echo "     Please ensure root-ca-ext.cnf exists with [root_ca_extensions] section."
    exit 1
fi

openssl req -x509 -new \
    -key "$KEY_PEM" \
    -out "$CERT_PEM" \
    -subj "$SUBJECT" \
    -days "$VALID_DAYS" \
    -set_serial "$SERIAL" \
    -config "$OPENSSL_CONF" \
    -extensions root_ca_extensions \
    2>&1 | while IFS= read -r line; do echo "      $line"; done

echo "  ✅ Certificate saved to: ${CERT_PEM}"

# ── Step 3: Extract public key and convert formats ─
echo ""
echo "[3/6] Extracting public key and converting formats..."

openssl rsa -in "$KEY_PEM" -pubout -out "$PUBKEY" 2>/dev/null
echo "  ✅ Public key: ${PUBKEY}"

openssl x509 -in "$CERT_PEM" -outform DER -out "$CERT_DER" 2>/dev/null
echo "  ✅ DER format: ${CERT_DER}"

# ── Step 4: Verify the certificate ─────────────────
echo ""
echo "[4/6] Verifying certificate..."

echo ""
echo "  ── Certificate Details ──"
openssl x509 -in "$CERT_PEM" -noout -subject -issuer -dates -serial 2>&1 | \
    while IFS= read -r line; do echo "     $line"; done

echo ""
echo "  ── Key Usage ──"
openssl x509 -in "$CERT_PEM" -noout -ext keyUsage,extendedKeyUsage,basicConstraints 2>&1 | \
    while IFS= read -r line; do echo "     $line"; done

echo ""
echo "  ── Self-Signature ──"
if openssl verify -CAfile "$CERT_PEM" "$CERT_PEM" >/dev/null 2>&1; then
    echo "  ✅ Self-signature verified"
else
    echo "  ❌ Self-signature verification FAILED"
    exit 1
fi

# ── Step 5: Import private key to YubiKey ──────────
echo ""
echo "[5/6] Importing private key to YubiKey PIV slot ${SLOT}..."
echo "      (Key already backed up at: ${KEY_PEM})"

# Convert PEM key to DER for YubiKey import
TMP_KEY_DER=$(mktemp /tmp/root-ca-key.XXXXXXXXXX.der)
openssl pkcs8 -topk8 -nocrypt -in "$KEY_PEM" -outform DER -out "$TMP_KEY_DER" 2>/dev/null

# Check if slot 9c already has a key
if yubico-piv-tool -s "$SLOT" -a status 2>&1 | grep -q "Algorithm"; then
    echo "  ⚠️  Slot ${SLOT} already contains a key. Overwriting..."
fi

yubico-piv-tool -s "$SLOT" \
    -i "$TMP_KEY_DER" \
    -a import-key \
    -k "$MGMT_KEY" \
    --algorithm RSA2048 \
    2>&1 | while IFS= read -r line; do echo "      $line"; done

rm -f "$TMP_KEY_DER"
echo "  ✅ Private key imported to YubiKey slot ${SLOT}"

# ── Step 6: Write certificate to YubiKey ───────────
echo ""
echo "[6/6] Writing certificate to YubiKey..."

yubico-piv-tool -s "$SLOT" \
    -a import-certificate \
    -i "$CERT_DER" \
    -P "$PIN" \
    2>&1 | while IFS= read -r line; do echo "      $line"; done

echo "  ✅ Certificate written to YubiKey slot ${SLOT}"

# ── Verification ───────────────────────────────────
echo ""
echo "  ── YubiKey Slot ${SLOT} Verification ──"
echo "  Reading back certificate from YubiKey..."
yubico-piv-tool -s "$SLOT" -a read-certificate -P "$PIN" 2>/dev/null | \
    openssl x509 -noout -subject -issuer -serial -dates 2>&1 | \
    while IFS= read -r line; do echo "     $line"; done

echo ""
echo "  Key source: imported (NOT on-card generated)"
echo "  Key backup: ${KEY_PEM} ⚠️"

# ── Done ───────────────────────────────────────────
echo ""
echo "================================================"
echo " ✅ Root CA Setup Complete!"
echo "================================================"
echo ""
echo " Summary:"
echo "   Root CA Certificate : ${CERT_PEM}"
echo "   Root CA Key (backup): ${KEY_PEM}"
echo "   Root CA Public Key  : ${PUBKEY}"
echo "   Root CA (DER)       : ${CERT_DER}"
echo "   Key Location        : YubiKey PIV slot ${SLOT} + ${KEY_PEM}"
echo "   Subject             : ${SUBJECT}"
echo "   Validity            : ${VALID_DAYS} days"
echo "   Algorithm           : RSA2048"
echo "   PIN                 : ${PIN}"
echo ""
echo " ⚠️  SECURITY NOTE: The root CA private key backup exists at:"
echo "     ${KEY_PEM}"
echo "     For production: store this backup securely OFFLINE."
echo "     The YubiKey copy is for lab signing convenience."
echo "     In a real CA, generate the key ON the token to avoid this risk."
echo ""
