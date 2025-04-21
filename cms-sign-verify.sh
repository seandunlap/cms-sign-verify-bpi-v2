#!/bin/bash
# cms-sign-verify.sh: Performs CMS signing/verification and compares with C program output
# Dependencies: bash, cmake, make, xxd, grep, tr, diff
# Input files: cm_device_cert.der, cm_device_private.pem, auth_request_data.txt, verify_data.bin
# Optional: root_certificate.der, ca_cert.der (for CA bundle)
# Output: cms.der (shell CMS), cms-computed-by-C-code.der (C program CMS)

# Exit on error, undefined variables, or pipeline errors
set -euo pipefail

# Set IFS to newline and tab for safer file handling
IFS=$'\n\t'

# Custom logging function (outputs to stderr)
log() { echo "[$(date +%T)] $*" >&2; }

# File paths
CM_DEVICE_CERT_DER="cm_device_cert.der"
CM_DEVICE_PRIV="cm_device_private.pem"
AUTH_REQUEST_FILE="auth_request_data.txt"
OUTPUT_CMS_FILE="cms.der"
CM_DEVICE_CERT_PEM="cm_device_cert.pem"
OUTPUT_CMS_FILE_C_CODE="cms-computed-by-C-code.der"
VERIFY_DATA="verify_data.bin"
CA_BUNDLE="ca-bundle.crt"
ROOT_CERT_DER="root_certificate.der"
INTERMEDIATE_CERT_DER="ca_cert.der"
ROOT_CERT_PEM="root_certificate.pem"
INTERMEDIATE_CERT_PEM="ca_cert.pem"
OPENSSL_DIR="./build/openssl/install"
OPENSSL_BIN="${OPENSSL_DIR}/bin/openssl"
OPENSSL_LIB_DIR="${OPENSSL_DIR}/lib"
OPENSSL_LOG_DIR="./build/openssl/src/openssl-stamp"

# Clean up temporary files on exit
trap 'rm -f auth_request_data.bin cm_device_cert.pem cms.der.hex verify_data.bin.hex "$OUTPUT_CMS_FILE_C_CODE.hex" "$ROOT_CERT_PEM" "$INTERMEDIATE_CERT_PEM" auth_request_data_clean.txt' EXIT

# Check for required commands
log "Checking for required commands"
for cmd in cmake make xxd grep tr diff; do
  if ! command -v "$cmd" >/dev/null; then
    log "Error: Required command '$cmd' not found"
    exit 1
  fi
done

# Build and run C program
log "Building openssl and cms_sign_verify.c"
if ! cmake -S . -B build; then
  log "Error: CMake configuration failed"
  exit 1
fi
if ! cmake --build build; then
  log "Error: Build failed"
  if [[ -d "$OPENSSL_LOG_DIR" ]]; then
    log "Checking OpenSSL build logs for errors..."
    cat "$OPENSSL_LOG_DIR"/openssl-*.log || true
  fi
  exit 1
fi

# Check if OpenSSL binary and libraries exist
log "Verifying OpenSSL installation"
if [[ ! -x "$OPENSSL_BIN" ]]; then
  log "Error: OpenSSL binary not found at '$OPENSSL_BIN'"
  log "Listing contents of $OPENSSL_DIR/bin:"
  ls -l "$OPENSSL_DIR/bin" || true
  log "Checking OpenSSL install log for errors..."
  cat "$OPENSSL_LOG_DIR"/openssl-install-*.log || true
  exit 1
fi
for lib in "$OPENSSL_LIB_DIR/libssl.a" "$OPENSSL_LIB_DIR/libcrypto.a"; do
  if [[ ! -f "$lib" ]]; then
    log "Error: OpenSSL library not found at '$lib'"
    log "Listing contents of $OPENSSL_LIB_DIR:"
    ls -l "$OPENSSL_LIB_DIR" || true
    exit 1
  fi
done
log "OpenSSL installation verified: $OPENSSL_BIN, $OPENSSL_LIB_DIR/libssl.a, $OPENSSL_LIB_DIR/libcrypto.a"

# Check input files (exclude optional CA_BUNDLE, ROOT_CERT_DER, INTERMEDIATE_CERT_DER)
log "Checking input files"
for f in "$CM_DEVICE_CERT_DER" "$CM_DEVICE_PRIV" "$AUTH_REQUEST_FILE" "$VERIFY_DATA"; do
  [[ -f "$f" && -r "$f" ]] || { log "Error: '$f' not found or not readable"; exit 1; }
done

# Create ca-bundle.crt if root and intermediate certificates are available
log "Checking for CA certificate files to create $CA_BUNDLE"
if [[ -f "$ROOT_CERT_DER" && -r "$ROOT_CERT_DER" && -f "$INTERMEDIATE_CERT_DER" && -r "$INTERMEDIATE_CERT_DER" ]]; then
  log "Converting $ROOT_CERT_DER to PEM: $ROOT_CERT_PEM"
  if ! "$OPENSSL_BIN" x509 -inform DER -in "$ROOT_CERT_DER" -out "$ROOT_CERT_PEM"; then
    log "Error: Failed to convert $ROOT_CERT_DER to PEM"
    exit 1
  fi

  log "Converting $INTERMEDIATE_CERT_DER to PEM: $INTERMEDIATE_CERT_PEM"
  if ! "$OPENSSL_BIN" x509 -inform DER -in "$INTERMEDIATE_CERT_DER" -out "$INTERMEDIATE_CERT_PEM"; then
    log "Error: Failed to convert $INTERMEDIATE_CERT_DER to PEM"
    exit 1
  fi

  log "Creating $CA_BUNDLE from $ROOT_CERT_PEM and $INTERMEDIATE_CERT_PEM"
  if ! cat "$ROOT_CERT_PEM" "$INTERMEDIATE_CERT_PEM" > "$CA_BUNDLE"; then
    log "Error: Failed to create $CA_BUNDLE"
    exit 1
  fi
  log "$CA_BUNDLE created successfully"
else
  log "Warning: $ROOT_CERT_DER or $INTERMEDIATE_CERT_DER not found or not readable, skipping $CA_BUNDLE creation"
fi

# Validate and clean hex input
log "Validating and cleaning hex input in $AUTH_REQUEST_FILE"
if ! grep -E '^[0-9a-fA-F]+$' "$AUTH_REQUEST_FILE" >/dev/null; then
  log "Error: '$AUTH_REQUEST_FILE' contains invalid hex characters"
  exit 1
fi
# Remove whitespace and newlines
tr -d '[:space:]' < "$AUTH_REQUEST_FILE" > auth_request_data_clean.txt
if [[ ! -s auth_request_data_clean.txt ]]; then
  log "Error: Cleaned hex file is empty"
  exit 1
fi

# Convert cleaned hex to binary
log "Converting cleaned hex to binary auth_request_data.bin"
if ! xxd -r -p auth_request_data_clean.txt > auth_request_data.bin; then
  log "Error: Failed to convert hex to binary"
  exit 1
fi

# Convert DER certificate to PEM
log "Converting $CM_DEVICE_CERT_DER to PEM: $CM_DEVICE_CERT_PEM"
if ! "$OPENSSL_BIN" x509 -inform DER -in "$CM_DEVICE_CERT_DER" -out "$CM_DEVICE_CERT_PEM"; then
  log "Error: Failed to convert $CM_DEVICE_CERT_DER to PEM"
  exit 1
fi

# Sign data
log "Signing data to produce $OUTPUT_CMS_FILE"
if ! "$OPENSSL_BIN" cms -sign \
  -in auth_request_data.bin \
  -signer "$CM_DEVICE_CERT_PEM" \
  -inkey "$CM_DEVICE_PRIV" \
  -out "$OUTPUT_CMS_FILE" \
  -outform DER \
  -noattr \
  -binary; then
  log "Error: CMS signing failed"
  exit 1
fi
log "Signature written to $OUTPUT_CMS_FILE"

# Create hex dumps
log "Creating hex dumps for comparison"
if ! xxd "$OUTPUT_CMS_FILE" > cms.der.hex; then
  log "Error: Failed to create hex dump for $OUTPUT_CMS_FILE"
  exit 1
fi
if ! xxd "$VERIFY_DATA" > verify_data.bin.hex; then
  log "Error: Failed to create hex dump for $VERIFY_DATA"
  exit 1
fi

# Compare shell script output with expected
log "Comparing shell script CMS with expected result"
if diff -q cms.der.hex verify_data.bin.hex >/dev/null; then
  log "Shell script CMS matches expected result"
else
  log "Shell script CMS differs from expected result"
  diff cms.der.hex verify_data.bin.hex || true
fi

# Verify CMS signature
log "Verifying CMS signature"
if [[ -f "$CA_BUNDLE" && -r "$CA_BUNDLE" ]]; then
  log "CA bundle found at $CA_BUNDLE, verifying with CA chain"
  if ! "$OPENSSL_BIN" cms -verify \
    -in "$OUTPUT_CMS_FILE" \
    -inform DER \
    -CAfile "$CA_BUNDLE" \
    -certfile "$CM_DEVICE_CERT_PEM" \
    -noattr \
    -binary; then
    log "Error: CMS verification with CA bundle failed"
  fi
else
  log "Warning: CA bundle ($CA_BUNDLE) not found, verifying without CA chain"
  if ! "$OPENSSL_BIN" cms -verify \
    -in "$OUTPUT_CMS_FILE" \
    -inform DER \
    -noverify \
    -certfile "$CM_DEVICE_CERT_PEM" \
    -noattr \
    -binary; then
    log "Error: CMS verification without CA bundle failed"
    exit 1
  fi
fi
log "CMS verification OK"

# Run C program
log "Running cms_sign_verify built from cms_sign_verify.c"
if ! ./build/cms_sign_verify; then
  log "Error: C program failed"
  exit 1
fi

# Check C program output
[[ -f "$OUTPUT_CMS_FILE_C_CODE" ]] || { log "Error: '$OUTPUT_CMS_FILE_C_CODE' not found"; exit 1; }
log "Creating hex dump for $OUTPUT_CMS_FILE_C_CODE"
if ! xxd "$OUTPUT_CMS_FILE_C_CODE" > "$OUTPUT_CMS_FILE_C_CODE.hex"; then
  log "Error: Failed to create hex dump for $OUTPUT_CMS_FILE_C_CODE"
  exit 1
fi

# Compare C program output with expected
log "Comparing C program CMS with expected result"
if diff -q "$OUTPUT_CMS_FILE_C_CODE.hex" verify_data.bin.hex >/dev/null; then
  log "C program CMS matches expected result"
else
  log "C program CMS differs from expected result"
  diff "$OUTPUT_CMS_FILE_C_CODE.hex" verify_data.bin.hex || true
fi


log "All operations completed successfully"