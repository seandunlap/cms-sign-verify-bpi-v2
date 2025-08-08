#!/usr/bin/env bash
# cms-sign-verify.sh: Perform CMS sign/verify and compare with C program output

set -euo pipefail
IFS="$(printf '\n\t')"

# Configuration
DEBUG_MODE=${DEBUG_MODE:-true}  # Set to true to preserve temporary files
INCLUDE_CMS_ATTRS=${INCLUDE_CMS_ATTRS:-true}  # Set to true to include CMS attributes

# Logging helper
log() { echo "[$(date +'%T')] $*" >&2; }

# Pick a hex-dump tool if available
if command -v xxd >/dev/null 2>&1; then
  HDUMP="xxd"
else
  HDUMP="hexdump -v -e '1/1 \"%02X\"'"
fi

# —— File paths —— 
CM_DEVICE_CERT_PEM="TEST_CABLELABS_DEVICE_CERTIFICATION_AUTHORITY_CRT.PEM"
CM_DEVICE_PRIV_PEM="TEST_CABLELABS_DEVICE_CERTIFICATION_AUTHORITY_PRIVATEKEY.PEM"
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
if [[ "$DEBUG_MODE" != "true" ]]; then
  trap 'rm -f \
      auth_request_data.bin \
      "'"${OUTPUT_CMS_SHELL}"'" shell.der.hex \
      verify_data.bin.hex \
      "'"${OUTPUT_CMS_CCODE}"'" cms-computed-by-C-code.der.hex \
      "'"${CA_BUNDLE}"'" \
      "'"${ROOT_CERT_PEM}"'" "'"${INTERMEDIATE_CERT_PEM}"'" \
      auth_request_data_clean.txt' EXIT
else
  log "Debug mode enabled; temporary files will not be deleted"
fi

# 1) Prereqs
log "Checking for required commands"
for cmd in cmake make grep tr diff "$OPENSSL_BIN"; do
  if ! command -v "$cmd" >/dev/null 2>&1 && [[ "$cmd" != "$OPENSSL_BIN" || ! -x "$cmd" ]]; then
    log "Error: Required command or binary '$cmd' not found or not executable"
    exit 1
  fi
done

# 2) Inputs exist?
log "Checking input files"
for f in "$CM_DEVICE_CERT_PEM" "$CM_DEVICE_PRIV_PEM" "$AUTH_REQUEST_FILE" "$VERIFY_DATA"; do
  [[ -r "$f" ]] || { log "Error: '$f' not found or not readable"; exit 1; }
done

log "Extract the Public Key from the Private Key"
openssl pkey -pubin -in private_derived_pubkey.pem -outform DER | sha256sum

log "Extract the Public Key from the Certificate"
openssl pkey -pubin -in cert_pubkey.pem -outform DER | sha256sum

log "Compare the Public Key from the Private Key and the Certificate by computing and comparing hashes"
openssl pkey -pubin -in private_derived_pubkey.pem -outform DER | sha256sum
openssl pkey -pubin -in cert_pubkey.pem -outform DER | sha256sum

# 3) Validate certificate
log "Validating certificate format and key type"
if ! "$OPENSSL_BIN" x509 -in "$CM_DEVICE_CERT_PEM" -noout 2>/dev/null; then
  log "Error: '$CM_DEVICE_CERT_PEM' is not a valid PEM certificate"
  exit 1
fi
if ! "$OPENSSL_BIN" x509 -in "$CM_DEVICE_CERT_PEM" -text -noout | grep -q "Public Key Algorithm: rsaEncryption"; then
  log "Error: '$CM_DEVICE_CERT_PEM' does not contain an RSA key"
  exit 1
fi


log "Extract the Public Key from the Certificate"
openssl x509 -in TEST_CABLELABS_DEVICE_CERTIFICATION_AUTHORITY_CRT.PEM -pubkey -noout -out cert_pubkey.pem

log "Extract the Public Key from the private key"
openssl pkey -in TEST_CABLELABS_DEVICE_CERTIFICATION_AUTHORITY_PRIVATEKEY.PEM -pubout -out private_derived_pubkey.pem

log "Verify the Signature:  Use the extracted public key to verify the signature:"
openssl dgst -sha256 -verify cert_pubkey.pem -signature test.sig test.txt

openssl pkey -pubin -in private_derived_pubkey.pem -outform DER | sha256sum
openssl pkey -pubin -in cert_pubkey.pem -outform DER | sha256sum


log "Verify the key pair by performing a cryptographic operation, such as signing and verifying a test message.Create a test file"
log "Create a test file test.txt:"
echo "Test message" > test.txt

log "Sign the test file with the private key (for RSA, use rsa or pkey depending on key type):"
openssl dgst -sha256 -sign TEST_CABLELABS_DEVICE_CERTIFICATION_AUTHORITY_PRIVATEKEY.PEM -out test.sig test.txt

log "Step 3: Verify the signature with the public key:"
openssl dgst -sha256 -verify cert_pubkey.pem -signature test.sig test.txt || {
  log "Error: Signature verification failed"
  exit 1
}

# 4) Build C program
log "Configuring and building cms_sign_verify"
cmake -S . -B build
cmake --build build

# 5) Validate and clean hex input
log "Validating hex input in $AUTH_REQUEST_FILE"
if ! grep -Eq '^[0-9A-Fa-f]+$' "$AUTH_REQUEST_FILE"; then
  log "Error: Invalid hex in $AUTH_REQUEST_FILE"
  exit 1
fi
tr -d '[:space:]' < "$AUTH_REQUEST_FILE" > auth_request_data_clean.txt
if [[ $(wc -c < auth_request_data_clean.txt) -eq 0 || $(( $(wc -c < auth_request_data_clean.txt) % 2 )) -ne 0 ]]; then
  log "Error: Hex data in $AUTH_REQUEST_FILE is empty or has odd length"
  exit 1
fi

# 6) Convert hex → binary
log "Converting cleaned hex to binary"
xxd -r -p auth_request_data_clean.txt > auth_request_data.bin

# 7) Sign with shell
log "Signing data to produce $OUTPUT_CMS_SHELL"
cms_sign_cmd=("$OPENSSL_BIN" cms -sign \
  -in auth_request_data.bin \
  -signer "$CM_DEVICE_CERT_PEM" \
  -inkey "$CM_DEVICE_PRIV_PEM" \
  -out "$OUTPUT_CMS_SHELL" \
  -outform DER \
  -binary)
if [[ "$INCLUDE_CMS_ATTRS" != "true" ]]; then
  cms_sign_cmd+=(-noattr)
fi
"${cms_sign_cmd[@]}" || { log "Error: CMS signing failed"; exit 1; }

# 8) Hex-dump & compare with expected output
log "Creating hex dumps for shell and expected output"
$HDUMP "$OUTPUT_CMS_SHELL" > shell.der.hex
$HDUMP "$VERIFY_DATA" > verify_data.bin.hex

log "Comparing shell CMS with expected output ($VERIFY_DATA)"
if diff -q shell.der.hex verify_data.bin.hex; then
  log "Shell script CMS matches expected output"
else
  log "Shell script CMS differs from expected output"
  diff shell.der.hex verify_data.bin.hex || true
fi




# 9) Compare with C program output
if [[ -r "$OUTPUT_CMS_CCODE" ]]; then
  log "Creating hex dump for C program output"
  $HDUMP "$OUTPUT_CMS_CCODE" > cms-computed-by-C-code.der.hex
  log "Comparing shell CMS with C program output ($OUTPUT_CMS_CCODE)"
  if diff -q shell.der.hex cms-computed-by-C-code.der.hex; then
    log "Shell script CMS matches C program output"
  else
    log "Shell script CMS differs from C program output"
    diff shell.der.hex cms-computed-by-C-code.der.hex || true
  fi
else
  log "Warning: C program output '$OUTPUT_CMS_CCODE' not found"
fi

# 10) Create & verify with CA bundle if available
log "Checking for CA certificate files to create $CA_BUNDLE"
if [[ -r "$ROOT_CERT_DER" && -r "$INTERMEDIATE_CERT_DER" ]]; then
  log "Converting $ROOT_CERT_DER → $ROOT_CERT_PEM"
  "$OPENSSL_BIN" x509 -inform DER -in "$ROOT_CERT_DER" -out "$ROOT_CERT_PEM" || {
    log "Error: Failed to convert $ROOT_CERT_DER to PEM"
    exit 1
  }

  log "Converting $INTERMEDIATE_CERT_DER → $INTERMEDIATE_CERT_PEM"
  "$OPENSSL_BIN" x509 -inform DER -in "$INTERMEDIATE_CERT_DER" -out "$INTERMEDIATE_CERT_PEM" || {
    log "Error: Failed to convert $INTERMEDIATE_CERT_DER to PEM"
    exit 1
  }

  log "Building CA bundle $CA_BUNDLE"
  cat "$ROOT_CERT_PEM" "$INTERMEDIATE_CERT_PEM" > "$CA_BUNDLE"

  log "Verifying CMS signature with CA chain"
  if "$OPENSSL_BIN" cms -verify \
    -in "$OUTPUT_CMS_SHELL" \
    -inform DER \
    -CAfile "$CA_BUNDLE" \
    -certfile "$CM_DEVICE_CERT_PEM" \
    -binary \
    -out verified_data.bin; then
    log "CMS verify (with CA) succeeded"
    # Compare verified data with input
    log "Comparing verified data with input"
    if cmp -s auth_request_data.bin verified_data.bin; then
      log "Verified data matches input data"
    else
      log "Verified data differs from input data"
      diff auth_request_data.bin verified_data.bin || true
    fi
  else
    log "Error: CMS verify (with CA) failed"
    exit 1
  fi
else
  log "CA certs not found; skipping CA-chain verification"
fi

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