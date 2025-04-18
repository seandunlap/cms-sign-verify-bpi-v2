#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

set -x

CM_DEVICE_CERT_DER="cm_device_cert.der"
CM_DEVICE_PRIV="cm_device_private.pem"
AUTH_REQUEST_FILE="auth_request_data.txt"
OUTPUT_CMS_FILE="cms.der"
CM_DEVICE_CERT_PEM="cm_device_cert.pem"
OUTPUT_CMS_FILE_C_CODE="cms-computed-by-C-code.der" 

set +x 

for f in "$CM_DEVICE_CERT_DER" "$CM_DEVICE_PRIV" "$AUTH_REQUEST_FILE"; do
  [[ -f "$f" ]] || { echo "Error: '$f' not found"; exit 1; }
done

# Convert hex → binary DER
echo "converting hex auth_request_data.txt to binary auth_request_data.bin for openssl"
xxd -r -p auth_request_data.txt > auth_request_data.bin

set -x
openssl x509 -inform DER -in "$CM_DEVICE_CERT_DER" -out "$CM_DEVICE_CERT_PEM"
set +x
echo "Converted $CM_DEVICE_CERT_DER → PEM: $CM_DEVICE_CERT_PEM"

# Sign (binary mode if needed)
set -x
openssl cms -sign \
  -in "$AUTH_REQUEST_FILE" \
  -signer "$CM_DEVICE_CERT_PEM" \
  -inkey "$CM_DEVICE_PRIV" \
  -out "$OUTPUT_CMS_FILE" \
  -outform DER \
  -noattr \
  -binary 
set +x

echo "Signature writtien to $OUTPUT_CMS_FILE"

set -x
xxd cms.der > cms.der.hex
xxd verify_data.bin > verify_data.bin.hex
set +x

echo "Diff of shell script computed CMS signature and Cablelabs expected result:"
set -x
diff cms.der.hex verify_data.bin.hex

# Verify against a CA bundle
openssl cms -verify \
  -in "$OUTPUT_CMS_FILE" \
  -inform DER \
  -CAfile /path/to/ca-bundle.crt \
  -certfile "$CM_DEVICE_CERT_PEM" \
  -noattr \
  -nodetach \
  -binary
set +x
echo "CMS verification OK"

# Make and run the C application to produce cms-computed-from-C-code.der
echo "Building authReqSignature.c"
set -x
cmake .               # generate Makefile
make                  # build C code
./authReqSignature    # run C code

set +x
xxd $OUTPUT_CMS_FILE_C_CODE > $OUTPUT_CMS_FILE_C_CODE.hex

echo "Diff of C code computed CMS signature and Cablelabs expected signature:"
set -x
diff $OUTPUT_CMS_FILE_C_CODE.hex verify_data.bin.hex
set +x

echo "Diff of C code computed CMS signature and shell script computed signature:"
set -x
diff $OUTPUT_CMS_FILE_C_CODE.hex cms.der.hex
set +x