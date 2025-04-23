#!/usr/bin/env bash
# cms-sign-verify.sh: Perform CMS sign/verify and compare with C program output

set -euo pipefail
IFS=$'\n\t'

# Logging helper
log() { echo "[$(date +'%T')] $*" >&2; }

# Pick a hex-dump tool if available
if command -v xxd >/dev/null 2>&1; then
  HDUMP="xxd"
else
  HDUMP="hexdump -v -e '1/1 \"%02X\"'"
fi

# —— File paths —— 
CM_DEVICE_CERT_DER="cm_device_cert.der"
CM_DEVICE_PRIV="cm_device_private.pem"
AUTH_REQUEST_FILE="auth_request_data.txt"
VERIFY_DATA="verify_data.bin"

OUTPUT_CMS_SHELL="cms-computed-by-shell-script.der"
OUTPUT_CMS_CCODE="cms-computed-by-C-code.der"
CA_BUNDLE="ca-bundle.crt"

# CA bundle source DERs and their PEM outputs
ROOT_CERT_DER="root_certificate.der"
INTERMEDIATE_CERT_DER="ca_cert.der"
ROOT_CERT_PEM="root_certificate.pem"
INTERMEDIATE_CERT_PEM="ca_cert.pem"

OPENSSL_BIN_DIR="build/third_party/openssl/install/bin"
OPENSSL_BIN="${OPENSSL_BIN_DIR}/openssl"

# —— Cleanup on exit —— 
trap 'rm -f \
    auth_request_data.bin \
    cm_device_cert.pem \
    "'"${OUTPUT_CMS_SHELL}"'" shell.der.hex \
    verify_data.bin.hex \
    "'"${OUTPUT_CMS_CCODE}"'" cms-computed-by-C-code.der.hex \
    "'"${CA_BUNDLE}"'" \
    "'"${ROOT_CERT_PEM}"'" "'"${INTERMEDIATE_CERT_PEM}"'" \
    auth_request_data_clean.txt' EXIT

# 1) Prereqs
log "Checking for required commands"
for cmd in cmake make grep tr diff; do
  if ! command -v "$cmd" >/dev/null; then
    log "Error: Required command '$cmd' not found"
    exit 1
  fi
done

# 2) Inputs exist?
log "Checking input files"
for f in "$CM_DEVICE_CERT_DER" "$CM_DEVICE_PRIV" "$AUTH_REQUEST_FILE" "$VERIFY_DATA"; do
  [[ -r "$f" ]] || { log "Error: '$f' not found or not readable"; exit 1; }
done

# 3) Build C program
log "Configuring and building cms_sign_verify"
cmake -S . -B build
cmake --build build

# 4) Validate and clean hex input
log "Validating hex input in $AUTH_REQUEST_FILE"
if ! grep -Eq '^[0-9A-Fa-f]+$' "$AUTH_REQUEST_FILE"; then
  log "Error: Invalid hex in $AUTH_REQUEST_FILE"
  exit 1
fi
tr -d '[:space:]' < "$AUTH_REQUEST_FILE" > auth_request_data_clean.txt
[[ -s auth_request_data_clean.txt ]] || { log "Error: Cleaned hex file empty"; exit 1; }

# 5) Convert hex → binary
log "Converting cleaned hex to binary"
xxd -r -p auth_request_data_clean.txt > auth_request_data.bin

# 6) DER→PEM for device cert
log "Converting $CM_DEVICE_CERT_DER to PEM"
"$OPENSSL_BIN" x509 -inform DER -in "$CM_DEVICE_CERT_DER" -out cm_device_cert.pem

# 7) Sign with shell
log "Signing data to produce $OUTPUT_CMS_SHELL"
"$OPENSSL_BIN" cms -sign \
  -in auth_request_data.bin \
  -signer cm_device_cert.pem \
  -inkey "$CM_DEVICE_PRIV" \
  -out "$OUTPUT_CMS_SHELL" \
  -outform DER \
  -noattr \
  -binary

# 8) Hex-dump & compare shell output
log "Creating hex dumps"
$HDUMP "$OUTPUT_CMS_SHELL"     > shell.der.hex
$HDUMP "$VERIFY_DATA"          > verify_data.bin.hex

log "Comparing shell CMS with expected"
if diff -q shell.der.hex verify_data.bin.hex; then
  log "Shell script CMS matches expected result"
else
  log "Shell script CMS differs"
  diff shell.der.hex verify_data.bin.hex || true
fi

# 9) Create & verify with CA bundle if available
log "Checking for CA certificate files to create $CA_BUNDLE"
if [[ -r "$ROOT_CERT_DER" && -r "$INTERMEDIATE_CERT_DER" ]]; then
  log "Converting $ROOT_CERT_DER → $ROOT_CERT_PEM"
  "$OPENSSL_BIN" x509 -inform DER -in "$ROOT_CERT_DER" -out "$ROOT_CERT_PEM"

  log "Converting $INTERMEDIATE_CERT_DER → $INTERMEDIATE_CERT_PEM"
  "$OPENSSL_BIN" x509 -inform DER -in "$INTERMEDIATE_CERT_DER" -out "$INTERMEDIATE_CERT_PEM"

  log "Building CA bundle $CA_BUNDLE"
  cat "$ROOT_CERT_PEM" "$INTERMEDIATE_CERT_PEM" > "$CA_BUNDLE"

  log "Verifying CMS signature with CA chain"
  "$OPENSSL_BIN" cms -verify \
    -in "$OUTPUT_CMS_SHELL" \
    -inform DER \
    -CAfile "$CA_BUNDLE" \
    -certfile cm_device_cert.pem \
    -noattr \
    -binary \
  && log "CMS verify (with CA) succeeded"
else
  log "CA certs not found; skipping CA-chain verification"
fi

# 10) Run the C program & compare its output
log "Running cms_sign_verify (C program)"
./build/cms_sign_verify

[[ -f "$OUTPUT_CMS_CCODE" ]] || { log "Error: '$OUTPUT_CMS_CCODE' not found"; exit 1; }
log "Creating hex dump for C program output"
$HDUMP "$OUTPUT_CMS_CCODE" > cms-computed-by-C-code.der.hex

log "Comparing cms-computed-by-C-code.der.hex verify_data.bin.hex"
if diff -q cms-computed-by-C-code.der.hex verify_data.bin.hex; then
  log "C program CMS matches expected result"
else
  log "C program CMS differs"
  diff cms-computed-by-C-code.der.hex verify_data.bin.hex || true
fi
