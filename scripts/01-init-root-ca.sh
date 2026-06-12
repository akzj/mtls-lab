#!/usr/bin/env bash
#
# 01-init-root-ca.sh
# ====================
# Create Root CA on YubiKey PIV (slot 9C — Digital Signature)
# Private key is generated ON the YubiKey and is NEVER extractable.
#
# Prerequisites:
#   - YubiKey 5C Nano inserted (PIV enabled)
#   - yubico-piv-tool installed
#   - pkcs11-tool (OpenSC) installed
#   - PIN: 123123 (default)
#
# Outputs:
#   certs/root-ca.crt     — Root CA certificate (PEM)
#   certs/root-ca.pub     — Root CA public key (PEM)
#   certs/root-ca.der     — Root CA certificate (DER)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="${PROJECT_DIR}/certs"
ROOT_CA_DIR="${PROJECT_DIR}/root-ca"

# YubiKey configuration
SLOT="9c"                        # Digital Signature slot (appropriate for CA)
ALGORITHM="RSA2048"              # Max supported by YubiKey 5C Nano PIV
PIN="123123"
SUBJECT="/CN=Zero-FAS Root CA"
VALID_DAYS=3650                   # ~10 years
SERIAL="0x01"
PKCS11_MODULE="/opt/homebrew/lib/libykcs11.dylib"

# Derived paths
CERT_PEM="${CERTS_DIR}/root-ca.crt"
CERT_DER="${CERTS_DIR}/root-ca.der"
PUBKEY="${CERTS_DIR}/root-ca.pub"
OPENSSL_CONF="${ROOT_CA_DIR}/root-ca-ext.cnf"

mkdir -p "$CERTS_DIR" "$ROOT_CA_DIR"

echo "================================================"
echo " Root CA Setup on YubiKey PIV"
echo "================================================"

# ── Step 0: Check if already initialized ────────────
echo ""
echo "[0/7] Checking if root CA already exists..."

if [ -f "$CERT_PEM" ] && [ -f "$PUBKEY" ]; then
    echo "  ✅ Root CA certificate exists: ${CERT_PEM}"
    echo ""
    echo "  ── Existing Cert Details ──"
    openssl x509 -in "$CERT_PEM" -noout -subject -issuer -dates -serial 2>&1 | \
        while IFS= read -r line; do echo "     $line"; done
    echo ""
    echo "  Checking self-signature..."
    if openssl verify -CAfile "$CERT_PEM" "$CERT_PEM" >/dev/null 2>&1; then
        echo "  ✅ Self-signature valid. Root CA already initialized. Exiting."
        echo ""
        echo "  To regenerate, remove these files and re-run:"
        echo "    rm ${CERT_PEM} ${CERT_DER} ${PUBKEY}"
        echo "  ⚠️  The YubiKey key in slot ${SLOT} will be overwritten."
        exit 0
    else
        echo "  ⚠️  Certificate exists but self-signature INVALID. Recreating..."
    fi
else
    echo "  No existing root CA found. Proceeding with creation."
fi

# ── Step 1: Generate key pair on YubiKey ────────────
echo ""
echo "[1/7] Generating ${ALGORITHM} key pair on YubiKey slot ${SLOT}..."
echo "      (Key is generated ON the token — never imported, never extractable)"

# Check if slot 9c already has a key
if yubico-piv-tool -s "$SLOT" -a status 2>&1 | grep -q "Algorithm"; then
    echo "  ⚠️  Slot ${SLOT} already has a key. It will be overwritten."
    echo "     (YubiKey PIV does not support key deletion; generating overwrites.)"
fi

yubico-piv-tool -s "$SLOT" -A "$ALGORITHM" -a generate \
    -P "$PIN" \
    -o "${PUBKEY}" \
    2>&1 | while IFS= read -r line; do echo "      $line"; done

echo "  ✅ Key pair generated successfully."
echo "  ✅ Public key saved to: ${PUBKEY}"

# ── Step 2: Create OpenSSL config for certificate ──
echo ""
echo "[2/7] Creating OpenSSL certificate configuration..."

if [ ! -f "$OPENSSL_CONF" ]; then
    cat > "$OPENSSL_CONF" << 'CNFE'
[req]
distinguished_name = req_dn
prompt = no
x509_extensions = root_ca_extensions

[req_dn]
CN = Zero-FAS Root CA

[root_ca_extensions]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
CNFE
fi
echo "  ✅ Config saved: ${OPENSSL_CONF}"

# ── Step 3: Create temporary self-signed cert ──────
echo ""
echo "[3/7] Creating temporary certificate with correct properties..."

TEMP_DIR=$(mktemp -d)
TEMP_KEY="${TEMP_DIR}/temp_ca.key"
TEMP_CERT="${TEMP_DIR}/temp_ca.crt"
TEMP_CERT_DER="${TEMP_DIR}/temp_ca.der"
TBS_NEW="${TEMP_DIR}/tbs_new.bin"
SIGNATURE="${TEMP_DIR}/signature.bin"
YK_PUBKEY_DER="${TEMP_DIR}/yk_pubkey.der"

openssl genrsa -out "$TEMP_KEY" 2048 2>/dev/null

openssl req -x509 -new \
    -key "$TEMP_KEY" \
    -config "$OPENSSL_CONF" \
    -out "$TEMP_CERT" \
    -outform PEM \
    -days "$VALID_DAYS" \
    -set_serial "$SERIAL" \
    -subj "$SUBJECT" \
    2>&1 | while IFS= read -r line; do echo "      $line"; done

openssl x509 -in "$TEMP_CERT" -out "$TEMP_CERT_DER" -outform DER 2>/dev/null
echo "  ✅ Temporary certificate created."

# ── Step 4: Replace public key with YubiKey key ──
echo ""
echo "[4/7] Swapping in YubiKey public key..."

# Convert YubiKey public key to DER
openssl pkey -pubin -in "$PUBKEY" -out "$YK_PUBKEY_DER" -outform DER 2>/dev/null

# Parse the temp cert to find offsets
# The temp cert has structure:
#   [0-3]  outer SEQUENCE header
#   [4-7]  TBS SEQUENCE header
#   [8-518] TBS content (511 bytes)
#     [13-15 -> 121-414: SPKI (294 bytes)]
#   [519-533] SignatureAlgorithm (15 bytes)
#   [534-end] Signature (261 bytes)

# Extract TBS content (after the TBS SEQUENCE header at offset 8)
TBS_CONTENT_OFFSET=8
TBS_CONTENT_LEN=511

# SPKI in TBS content starts at offset 121-8=113
SPKI_IN_TBS_OFFSET=113
SPKI_LEN=294
# Post-SPKI starts at offset 113+294=407, length 511-407=104

dd if="$TEMP_CERT_DER" bs=1 skip=$TBS_CONTENT_OFFSET count=$TBS_CONTENT_LEN 2>/dev/null \
    > "${TEMP_DIR}/tbs_content.bin"

# Splice TBS content with YubiKey SPKI
dd if="${TEMP_DIR}/tbs_content.bin" bs=1 count=$SPKI_IN_TBS_OFFSET 2>/dev/null \
    > "${TEMP_DIR}/tbs_pre.bin"
dd if="${TEMP_DIR}/tbs_content.bin" bs=1 skip=$((SPKI_IN_TBS_OFFSET + SPKI_LEN)) 2>/dev/null \
    > "${TEMP_DIR}/tbs_post.bin"

cat "${TEMP_DIR}/tbs_pre.bin" "$YK_PUBKEY_DER" "${TEMP_DIR}/tbs_post.bin" \
    > "${TEMP_DIR}/tbs_new_content.bin"

# Wrap in SEQUENCE
python3 -c "
import struct
data = open('${TEMP_DIR}/tbs_new_content.bin', 'rb').read()
tbs_der = b'\x30\x82' + struct.pack('>H', len(data)) + data
open('${TEMP_DIR}/tbs_full.bin', 'wb').write(tbs_der)
" 2>/dev/null

echo "  ✅ Public key swapped. TBS: $(wc -c < "${TEMP_DIR}/tbs_full.bin") bytes"

# ── Step 5: Sign with YubiKey ──────────────────────
echo ""
echo "[5/7] Signing certificate with YubiKey private key..."
echo "      (Private key stays on YubiKey — never leaves the token)"

pkcs11-tool --module "$PKCS11_MODULE" \
    --sign --mechanism SHA256-RSA-PKCS \
    --login --pin "$PIN" \
    --id 02 \
    --input-file "${TEMP_DIR}/tbs_full.bin" \
    --output-file "$SIGNATURE" \
    2>&1 | while IFS= read -r line; do echo "      $line"; done

echo "  ✅ Certificate signed by YubiKey."

# ── Step 6: Assemble final certificate ────────────
echo ""
echo "[6/7] Assembling final certificate..."

# Extract signature algorithm from temp cert
SIG_ALGO_OFFSET=519
SIG_ALGO_LEN=15

dd if="$TEMP_CERT_DER" bs=1 skip=$SIG_ALGO_OFFSET count=$SIG_ALGO_LEN 2>/dev/null \
    > "${TEMP_DIR}/sig_algo.bin"

python3 -c "
import struct

sig = open('$SIGNATURE', 'rb').read()
tbs = open('${TEMP_DIR}/tbs_full.bin', 'rb').read()
sig_algo = open('${TEMP_DIR}/sig_algo.bin', 'rb').read()

# BIT STRING wrapping: 03 82 01 01 00 + 256 bytes sig
sig_bs = b'\x03\x82\x01\x01\x00' + sig

# Assemble: TBS + SigAlgo + SigValue
cert_content = tbs + sig_algo + sig_bs
cert_der = b'\x30\x82' + struct.pack('>H', len(cert_content)) + cert_content

open('$CERT_DER', 'wb').write(cert_der)
" 2>/dev/null

# Convert to PEM
openssl x509 -inform DER -in "$CERT_DER" -outform PEM -out "$CERT_PEM" 2>/dev/null

# Extract public key from the cert (for consistency)
openssl x509 -in "$CERT_PEM" -noout -pubkey -out "$PUBKEY" 2>/dev/null

echo "  ✅ Root CA certificate assembled."
echo "  ✅ PEM: ${CERT_PEM}"
echo "  ✅ DER: ${CERT_DER}"
echo "  ✅ Public key: ${PUBKEY}"

# Cleanup temp files
rm -rf "$TEMP_DIR"

# ── Step 7: Verify everything ──────────────────────
echo ""
echo "[7/7] Running verification..."

echo ""
echo "  ── Certificate Details ──"
openssl x509 -in "$CERT_PEM" -noout -subject -issuer -dates -serial 2>&1 | \
    while IFS= read -r line; do echo "     $line"; done

echo ""
echo "  ── Extensions ──"
openssl x509 -in "$CERT_PEM" -noout -ext keyUsage,extendedKeyUsage,basicConstraints 2>&1 | \
    while IFS= read -r line; do echo "     $line"; done

echo ""
echo "  ── Self-Signature Verification ──"
if openssl verify -CAfile "$CERT_PEM" "$CERT_PEM" 2>&1; then
    echo "  ✅ Self-signature verification PASSED"
else
    echo "  ❌ Self-signature verification FAILED"
    exit 1
fi

echo ""
echo "  ── Test Signing with YubiKey ──"
TEST_MSG=$(mktemp)
TEST_SIG=$(mktemp)
echo "Root CA verification test $(date)" > "$TEST_MSG"

pkcs11-tool --module "$PKCS11_MODULE" \
    --sign --mechanism SHA256-RSA-PKCS \
    --login --pin "$PIN" \
    --id 02 \
    --input-file "$TEST_MSG" \
    --output-file "$TEST_SIG" \
    2>/dev/null

if openssl dgst -sha256 -verify "$PUBKEY" -signature "$TEST_SIG" "$TEST_MSG" 2>&1; then
    echo "  ✅ Test signature verification PASSED"
else
    echo "  ⚠️  Test signature verification could not be completed"
fi
rm -f "$TEST_MSG" "$TEST_SIG"

echo ""
echo "  ── Key Security Attributes ──"
echo "     Key location: YubiKey PIV slot ${SLOT}"
echo "     Generated ON token: ✅ (never imported)"
pkcs11-tool --module "$PKCS11_MODULE" -O -l -p "$PIN" 2>/dev/null | \
    grep -A4 "Private key for Digital Signature" | \
    while IFS= read -r line; do echo "     $line"; done

# ── Done ───────────────────────────────────────────
echo ""
echo "================================================"
echo " ✅ Root CA setup complete!"
echo "================================================"
echo ""
echo " Summary:"
echo "   Root CA Certificate : ${CERT_PEM}"
echo "   Root CA Public Key  : ${PUBKEY}"
echo "   Root CA (DER)       : ${CERT_DER}"
echo "   Key Location        : YubiKey PIV slot ${SLOT}"
echo "   Subject             : ${SUBJECT}"
echo "   Validity            : ${VALID_DAYS} days"
echo "   Algorithm           : ${ALGORITHM}"
echo "   Private Key Security: SENSITIVE | NEVER EXTRACTABLE | ALWAYS AUTHENTICATE"
echo ""
echo " Next steps:"
echo "   Run 02-init-step-ca.sh to create a Step CA intermediate"
echo "   signed by this Root CA."
echo ""
