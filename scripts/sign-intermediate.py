#!/usr/bin/env python3
"""
sign-intermediate.py — Sign an intermediate CA CSR with the Root CA key on YubiKey

Usage:
    python3 sign-intermediate.py \
        --subject "/CN=step-ca Intermediate CA" \
        --serial 0x02 \
        --days 1825 \
        --out-key certs/intermediate-step-ca-key.pem \
        --out-cert certs/intermediate-step-ca.crt \
        --out-csr certs/intermediate-step-ca.csr

Outputs:
    - Private key (PEM) — the intermediate's software key (HOT)
    - CSR (PEM) — for reference
    - Signed certificate (PEM) — signed by Root CA key on YubiKey

Requires:
    - YubiKey inserted with Root CA key in PIV slot 9C (PKCS#11 ID 0x02)
    - Root CA certificate at certs/root-ca.crt
    - pkcs11-tool from OpenSC
"""

import argparse
import os
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID, ExtensionOID


def parse_args():
    parser = argparse.ArgumentParser(description="Sign intermediate CA CSR with Root CA on YubiKey")
    parser.add_argument("--subject", required=True, help="Subject DN (e.g., /CN=step-ca Intermediate CA)")
    parser.add_argument("--serial", required=True, help="Certificate serial (e.g., 0x02)")
    parser.add_argument("--days", type=int, default=1825, help="Validity in days")
    parser.add_argument("--out-key", required=True, help="Output path for intermediate private key (PEM)")
    parser.add_argument("--out-cert", required=True, help="Output path for signed certificate (PEM)")
    parser.add_argument("--out-csr", required=True, help="Output path for CSR (PEM)")
    parser.add_argument("--root-ca", default="certs/root-ca.crt", help="Root CA certificate (PEM)")
    parser.add_argument("--pkcs11-module", default="/opt/homebrew/lib/libykcs11.dylib",
                        help="PKCS#11 module path")
    parser.add_argument("--key-id", default="02", help="PKCS#11 key ID for signing")
    parser.add_argument("--pin", default="123123", help="YubiKey PIN")
    return parser.parse_args()


def subject_from_rfc4514(rfc4514_str: str):
    """Parse RFC 4514 subject string into x509.Name."""
    # Format: /CN=name/OU=org/O=corp
    parts = rfc4514_str.strip("/").split("/")
    attrs = []
    oid_map = {
        "CN": NameOID.COMMON_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "L": NameOID.LOCALITY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "C": NameOID.COUNTRY_NAME,
        "DC": NameOID.DOMAIN_COMPONENT,
        "UID": NameOID.USER_ID,
        "E": NameOID.EMAIL_ADDRESS,
    }
    for part in parts:
        if "=" not in part:
            continue
        key, val = part.split("=", 1)
        key = key.strip()
        if key in oid_map:
            attrs.append(x509.NameAttribute(oid_map[key], val))
    if not attrs:
        raise ValueError(f"Could not parse subject: {rfc4514_str}")
    return x509.Name(attrs)


def ensure_dir(path):
    """Create parent directories if needed."""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def load_root_ca(root_ca_path: str):
    """Load the Root CA certificate and extract needed info."""
    with open(root_ca_path, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())

    # Root CA subject (DER encoded)
    issuer_der = root_cert.subject.public_bytes()

    # Root CA SKI (used as AKI in intermediate)
    ski_ext = root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    aki_key_id = ski_ext.value.digest

    # Root CA public key (DER)
    root_pubkey_der = root_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return root_cert, issuer_der, aki_key_id, root_pubkey_der


def pkcs11_sign(tbs_der: bytes, pkcs11_module: str, key_id: str, pin: str) -> bytes:
    """Sign a TBS DER structure with the YubiKey key using pkcs11-tool."""
    with tempfile.NamedTemporaryFile(delete=False) as f_tbs:
        f_tbs.write(tbs_der)
        tbs_path = f_tbs.name

    with tempfile.NamedTemporaryFile(delete=False) as f_sig:
        sig_path = f_sig.name

    try:
        result = subprocess.run(
            [
                "pkcs11-tool",
                "--module", pkcs11_module,
                "--sign",
                "--mechanism", "SHA256-RSA-PKCS",
                "--login",
                "--pin", pin,
                "--id", key_id,
                "--input-file", tbs_path,
                "--output-file", sig_path,
            ],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            print(f"pkcs11-tool stderr: {result.stderr}", file=sys.stderr)
            raise RuntimeError(f"pkcs11-tool signing failed with code {result.returncode}")

        with open(sig_path, "rb") as f:
            signature = f.read()

        print(f"  Signature: {len(signature)} bytes", file=sys.stderr)
        return signature
    finally:
        os.unlink(tbs_path)
        os.unlink(sig_path)


def build_intermediate_cert(
    issuer_der: bytes,
    subject_name: x509.Name,
    public_key: RSAPrivateKey.public_key,
    serial_number: int,
    not_before: datetime,
    not_after: datetime,
    aki_key_id: bytes,
    ski_key_id: bytes,
) -> bytes:
    """
    Build a DER-encoded TBSCertificate for an intermediate CA.
    Returns the DER bytes of the TBSCertificate SEQUENCE.
    """
    # Build the certificate using cryptography library
    builder = x509.CertificateBuilder()

    # Version 3
    builder = builder.serial_number(serial_number)

    # Signature algorithm (will be set in final cert assembly)
    # We'll use SHA256 with RSA

    # Issuer = Root CA subject
    builder = builder.issuer_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Zero-FAS Root CA")])
    )

    # Validity
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    # Subject
    builder = builder.subject_name(subject_name)

    # Public key
    builder = builder.public_key(public_key)

    # Add extensions
    # Basic Constraints: CA:TRUE, pathlen:0
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True
    )

    # Key Usage: keyCertSign, cRLSign
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True
    )

    # Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier(digest=ski_key_id),
        critical=False
    )

    # Authority Key Identifier
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=aki_key_id,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        ),
        critical=False
    )

    # Build the certificate (this creates the full cert with a placeholder signature)
    # We need to sign it, but we'll use the YubiKey for the actual signature
    # So we create a "dummy" signed cert first just to get the TBS bytes

    # Use a temporary key to create the structure
    temp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Sign with temp key to get the TBS bytes
    temp_cert = builder.sign(
        private_key=temp_key,
        algorithm=hashes.SHA256(),
    )

    # Get the TBS bytes (raw DER of the TBSCertificate)
    # We can extract this from the DER-encoded certificate
    cert_der = temp_cert.public_bytes(serialization.Encoding.DER)

    # Parse out the TBS certificate (it's the first element of the outer SEQUENCE)
    # DER: SEQUENCE { SEQUENCE (TBS), SEQUENCE (SigAlgo), BIT STRING (Sig) }
    # The TBS starts after the outer SEQUENCE header
    # We need to read the outer SEQUENCE to find where TBS ends

    # Actually, it's easier to get it from the cryptography library
    # The certificate data is already structured
    tbs_der = _extract_tbs_from_cert(cert_der)

    return tbs_der


def _extract_tbs_from_cert(cert_der: bytes) -> bytes:
    """
    Extract the TBSCertificate SEQUENCE from a DER-encoded certificate.
    The cert is: SEQUENCE { TBSCertificate, SignatureAlgorithm, SignatureValue }
    We need to extract just the TBSCertificate SEQUENCE.
    """
    # Read the outer SEQUENCE
    offset = 0
    tag = cert_der[offset]
    if tag != 0x30:  # SEQUENCE
        raise ValueError(f"Expected SEQUENCE tag, got 0x{tag:02x}")

    # Skip tag
    offset += 1
    # Read length
    len_bytes = cert_der[offset]
    if len_bytes & 0x80:
        num_len_bytes = len_bytes & 0x7F
        offset += 1
        content_len = int.from_bytes(cert_der[offset:offset + num_len_bytes], 'big')
        offset += num_len_bytes
    else:
        content_len = len_bytes
        offset += 1

    # Now offset points to the first element: TBSCertificate SEQUENCE
    tbs_start = offset

    # Read the TBS SEQUENCE to get its length
    tbs_tag = cert_der[tbs_start]
    if tbs_tag != 0x30:
        raise ValueError(f"Expected TBS SEQUENCE, got 0x{tbs_tag:02x}")

    tbs_len_offset = tbs_start + 1
    tbs_len_byte = cert_der[tbs_len_offset]
    if tbs_len_byte & 0x80:
        num_len = tbs_len_byte & 0x7F
        tbs_len = int.from_bytes(cert_der[tbs_len_offset + 1:tbs_len_offset + 1 + num_len], 'big')
        tbs_header_len = 1 + 1 + num_len
    else:
        tbs_len = tbs_len_byte
        tbs_header_len = 1 + 1

    tbs_total_len = tbs_header_len + tbs_len

    return cert_der[tbs_start:tbs_start + tbs_total_len]


def assemble_certificate(tbs_der: bytes, signature: bytes) -> bytes:
    """
    Assemble the final DER certificate from TBS + signature.
    Returns full DER certificate bytes.
    """
    # Signature Algorithm: sha256WithRSAEncryption, NULL params
    # DER: 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00
    sig_algo_der = bytes([
        0x30, 0x0d,  # SEQUENCE (13 bytes)
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,  # OID sha256WithRSAEncryption
            0x05, 0x00,  # NULL
    ])

    # Signature BIT STRING: 03 82 01 01 00 <256 bytes>
    # 0 unused bits, 256 bytes of signature = 257 bytes content
    # Length: 257 = 0x101
    sig_bitstring = bytes([0x03, 0x82, 0x01, 0x01, 0x00]) + signature

    # Assemble: TBS || SigAlgo || SigValue
    cert_content = tbs_der + sig_algo_der + sig_bitstring

    # Outer SEQUENCE wrapping
    cert_der = bytes([0x30, 0x82]) + struct.pack('>H', len(cert_content)) + cert_content

    return cert_der


def compute_ski(public_key_bytes: bytes) -> bytes:
    """Compute Subject Key Identifier as SHA-1 hash of the DER-encoded SubjectPublicKeyInfo."""
    digest = hashes.Hash(hashes.SHA1())
    digest.update(public_key_bytes)
    return digest.finalize()


def main():
    args = parse_args()

    print("=" * 50)
    print("  Sign Intermediate CA with Root CA on YubiKey")
    print("=" * 50)
    print(f"  Subject:     {args.subject}")
    print(f"  Serial:      {args.serial}")
    print(f"  Validity:    {args.days} days")
    print(f"  Root CA:     {args.root_ca}")
    print()

    # Parse serial
    if args.serial.startswith("0x") or args.serial.startswith("0X"):
        serial_num = int(args.serial, 16)
    else:
        serial_num = int(args.serial)

    # Parse subject
    subject_name = subject_from_rfc4514(args.subject)
    print(f"  Parsed subject: {subject_name.rfc4514_string()}")

    # Load Root CA
    print(f"\n[1/6] Loading Root CA...")
    root_cert, issuer_der, aki_key_id, root_pubkey_der = load_root_ca(args.root_ca)
    print(f"  Issuer: {root_cert.subject.rfc4514_string()}")
    print(f"  AKI: {aki_key_id.hex()}")

    # Generate intermediate key pair
    print(f"\n[2/6] Generating intermediate key pair (RSA 2048)...")
    ensure_dir(args.out_key)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Save private key
    with open(args.out_key, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"  Private key saved: {args.out_key}")

    # Get the public key
    public_key = private_key.public_key()

    # Compute SKI for this intermediate
    pubkey_spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ski_key_id = compute_ski(pubkey_spki_der)
    print(f"  SKI: {ski_key_id.hex()}")

    # Create CSR
    print(f"\n[3/6] Creating CSR...")
    ensure_dir(args.out_csr)
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(subject_name)

    csr = csr_builder.sign(private_key, hashes.SHA256())
    with open(args.out_csr, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    print(f"  CSR saved: {args.out_csr}")

    # Set validity
    not_before = datetime.now(timezone.utc)
    not_after = not_before + timedelta(days=args.days)

    # Build TBS certificate
    print(f"\n[4/6] Building TBS certificate...")
    tbs_der = build_intermediate_cert(
        issuer_der=issuer_der,
        subject_name=subject_name,
        public_key=public_key,
        serial_number=serial_num,
        not_before=not_before,
        not_after=not_after,
        aki_key_id=aki_key_id,
        ski_key_id=ski_key_id,
    )
    print(f"  TBS: {len(tbs_der)} bytes")

    # Verify TBS parses
    print(f"\n[5/6] Signing with YubiKey...")

    # Sign with YubiKey
    signature = pkcs11_sign(tbs_der, args.pkcs11_module, args.key_id, args.pin)
    print(f"  Signed with YubiKey key ID {args.key_id}")

    # Assemble final certificate
    cert_der = assemble_certificate(tbs_der, signature)
    print(f"  Final certificate: {len(cert_der)} bytes")

    # Save certificate
    ensure_dir(args.out_cert)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".der") as f:
        f.write(cert_der)
        cert_der_path = f.name

    # Convert to PEM
    result = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-in", cert_der_path,
         "-outform", "PEM", "-out", args.out_cert],
        capture_output=True, text=True
    )
    os.unlink(cert_der_path)
    if result.returncode != 0:
        print(f"Error converting to PEM: {result.stderr}", file=sys.stderr)
        return 1

    print(f"  Certificate saved: {args.out_cert}")

    # Verify
    print(f"\n[6/6] Verifying intermediate certificate...")
    result = subprocess.run(
        ["openssl", "x509", "-in", args.out_cert, "-noout",
         "-subject", "-issuer", "-dates", "-serial"],
        capture_output=True, text=True
    )
    print(f"  {result.stdout.replace(chr(10), chr(10)+'  ')}")

    # Verify chain with Root CA
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", args.root_ca, args.out_cert],
        capture_output=True, text=True
    )
    print(f"  Chain verification: {result.stdout.strip()}")
    if result.returncode != 0:
        print(f"  ❌ Verification FAILED: {result.stderr}")
        return 1

    # Show extensions
    result = subprocess.run(
        ["openssl", "x509", "-in", args.out_cert, "-noout",
         "-ext", "basicConstraints,keyUsage,subjectKeyIdentifier,authorityKeyIdentifier"],
        capture_output=True, text=True
    )
    print(f"  Extensions: {result.stdout.replace(chr(10), chr(10)+'  ')}")

    print()
    print("  ✅ Done!")
    print(f"  Certificate: {args.out_cert}")
    print(f"  Private key: {args.out_key}")
    print(f"  CSR:         {args.out_csr}")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
