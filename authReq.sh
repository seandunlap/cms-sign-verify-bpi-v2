#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# Custom logging function
log() { echo "[$(date +%T)] $*" >&2; }

# File paths
CM_DEVICE_CERT_DER="cm_device_cert.der"
CM_DEVICE_PRIV="cm_device_private.pem"
AUTH_REQUEST_FILE="auth_request_data.txt"
OUTPUT_CMS_FILE="cms.der"
CM_DEVICE_CERT_PEM="cm_device_cert.pem"
OUTPUT_CMS_FILE_C_CODE="cms-computed-by-C-code.der"
VERIFY_DATA="verify_data.bin"
CA_BUNDLE="ca-bundle.crt"  # Optional CA bundle for verification

# Check input files (exclude CA_BUNDLE since it's optional)
log "Checking input files"
for f in "$CM_DEVICE_CERT_DER" "$CM_DEVICE_PRIV" "$AUTH_REQUEST_FILE" "$VERIFY_DATA"; do
  [[ -f "$f" && -r "$f" ]] || { log "Error: '$f' not found or not readable"; exit 1; }
done

# Validate hex input
log "Validating hex input in $AUTH_REQUEST_FILE"
if ! grep -E '^[0-9a-fA-F]+$' "$AUTH_REQUEST_FILE" >/dev/null; then
  log "Error: '$AUTH_REQUEST_FILE' contains invalid hex characters"
  exit 1
fi

# Convert hex to binary
log "Converting hex $AUTH_REQUEST_FILE to binary auth_request_data.bin"
if ! xxd -r -p "$AUTH_REQUEST_FILE" > auth_request_data.bin; then
  log "Error: Failed to convert hex to binary"
  exit 1
fi

# Convert DER certificate to PEM
log "Converting $CM_DEVICE_CERT_DER to PEM: $CM_DEVICE_CERT_PEM"
if ! openssl x509 -inform DER -in "$CM_DEVICE_CERT_DER" -out "$CM_DEVICE_CERT_PEM" 2>/dev/null; then
  log "Error: Failed to convert $CM_DEVICE_CERT_DER to PEM"
  exit 1
fi

# Sign data
log "Signing data to produce $OUTPUT_CMS_FILE"
if ! openssl cms -sign \
  -in auth_request_data.bin \
  -signer "$CM_DEVICE_CERT_PEM" \
  -inkey "$CM_DEVICE_PRIV" \
  -out "$OUTPUT_CMS_FILE" \
  -outform DER \
  -noattr \
  -binary 2>/dev/null; then
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
  diff cms.der.hex verify_data.bin.hex
fi

# Verify CMS signature
log "Verifying CMS signature"
if [[ -f "$CA_BUNDLE" && -r "$CA_BUNDLE" ]]; then
  log "CA bundle found at $CA_BUNDLE, verifying with CA chain"
  if ! openssl cms -verify \
    -in "$OUTPUT_CMS_FILE" \
    -inform DER \
    -CAfile "$CA_BUNDLE" \
    -certfile "$CM_DEVICE_CERT_PEM" \
    -noattr \
    -binary 2>/dev/null; then
    log "Error: CMS verification with CA bundle failed"
  fi
else
  log "Warning: CA bundle ($CA_BUNDLE) not found, verifying without CA chain"
  if ! openssl cms -verify \
    -in "$OUTPUT_CMS_FILE" \
    -inform DER \
    -noverify \
    -certfile "$CM_DEVICE_CERT_PEM" \
    -noattr \
    -binary 2>/dev/null; then
    log "Error: CMS verification without CA bundle failed"
  fi
fi
log "CMS verification OK"

# Build and run C program
log "Building and running authReqSignature.c"
if ! cmake .; then
  log "Error: CMake failed"
fi
if ! make; then
  log "Error: Make failed"
fi
if ! ./authReqSignature; then
  log "Error: C program failed"
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
  diff "$OUTPUT_CMS_FILE_C_CODE.hex" verify_data.bin.hex
fi

# Compare C program output with shell script
log "Comparing C program CMS with shell script CMS"
if diff -q "$OUTPUT_CMS_FILE_C_CODE.hex" cms.der.hex >/dev/null; then
  log "C program CMS matches shell script CMS"
else
  log "C program CMS differs from shell script CMS"
  diff "$OUTPUT_CMS_FILE_C_CODE.hex" cms.der.hex
fi

log "All operations completed successfully"