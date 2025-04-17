#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

CM_DEVICE_CERT_DER="cm_device_cert.der"
CM_DEVICE_PRIV="cm_device_private.pem"
AUTH_REQUEST_FILE="auth_request_data.txt"
OUTPUT_CMS_FILE="auth_request_cms.p7s"

# Convert hex → binary DER
xxd -r -p auth_request_data.txt > auth_request_data.bin

for f in "$CM_DEVICE_CERT_DER" "$CM_DEVICE_PRIV" "$AUTH_REQUEST_FILE"; do
  [[ -f "$f" ]] || { echo "Error: '$f' not found"; exit 1; }
done

# Convert DER → PEM in a temp file
CM_DEVICE_CERT_PEM=$(mktemp /tmp/cm_cert.XXXXXX.pem)
trap 'rm -f "$CM_DEVICE_CERT_PEM"' EXIT
openssl x509 -inform DER -in "$CM_DEVICE_CERT_DER" -out "$CM_DEVICE_CERT_PEM"
echo "Converted DER → PEM: $CM_DEVICE_CERT_PEM"

# Sign (binary mode if needed)
openssl cms -sign \
  -in "$AUTH_REQUEST_FILE" \
  -signer "$CM_DEVICE_CERT_PEM" \
  -inkey "$CM_DEVICE_PRIV" \
  -out "$OUTPUT_CMS_FILE" \
  -outform DER \
  -noattr \
  -binary
echo "Signed CMS output → $OUTPUT_CMS_FILE"

xxd -C "$OUTPUT_CMS_FILE"

# Verify against a CA bundle
#openssl cms -verify \
#  -in "$OUTPUT_CMS_FILE" \
#  -inform DER \
#  -CAfile /path/to/ca-bundle.crt \
#  -certfile "$CM_DEVICE_CERT_PEM" \
#  -noattr \
#  -nodetach \
#  -binary
#echo "CMS verification OK"
