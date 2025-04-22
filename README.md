# CMS Signing and Verification Project

This project implements the CMS signature calculation from the BPI+v2 exmaple Auth-Req message provided in the DOCSIS security spec. 

## QuickStart

1. **Just run the Shell Script**:

   $ ./cms-sign-verify.sh

## Project Overview

The project consists of two main components:
1. **Bash Script (\`cms-sign-verify.sh\`)**: Computes the CMS signature of a sample Auth-Req from the spec and verifies it matches the spec example.  Also builds and executes the C Program and compares the shell script signature with the C program signature. 
2. **C Program (\`cms_sign_verify.c\`)**: Implements CMS signing and verification using the OpenSSL library, producing an equivalent CMS signed message.

Both shell script and C file components:
- Read a hex-encoded input file (\`auth_request_data.txt\`).
- Sign it using a DER certificate (\`cm_device_cert.der\`) and PEM private key (\`cm_device_private.pem\`).
- Produce a CMS signed message in DER format.
- Verify the signature against CA bundle (\`ca-bundle.crt\`).
- Compare the CMS outputs against an expected result (\`verify_data.bin\`).

## Prerequisites

- **Operating System**: Linux or OSx.
- **Dependencies**:
  - **CMake**: For building the C program.
    - Install: \`sudo apt-get install cmake\` or \`sudo yum install cmake\` or  \`brew install cmake\`
  - **Make**: For compiling the C program.
    - Install: \`sudo apt-get install make\` or \`sudo yum install make\` or \`brew install cmake make\`
  - **xxd**: For hex-to-binary conversion in the Bash script.
    - Usually included with \`vim\`: \`sudo apt-get install vim\` or \`sudo yum install vim\` or \`brew install vim\`

- **Verify dependency install**:
  $ cmake --version
  $ gmake --version  # or make --version
  $ xxd --version
  $ ggrep --version  # or grep --version
  $ gtr --version   # or tr --version
  $ diff --version

## Project Structure

- \`cms-sign-verify.sh\`: Bash script to automate CMS signing, verification, and comparison.
- \`cms_sign_verify.c\`: C program to perform CMS signing and verification.
- \`CMakeLists.txt\`: CMake configuration for building the C program.
- Input files:
  - \`cm_device_cert.der\`: Certificate for signing.
  - \`cm_device_private.pem\`: Private key for signing.
  - \`auth_request_data.txt\`:  Auth-Req message data in hex (from spec example) over which the signature is computed.
  - \`verify_data.bin\`: Expected CMS output.
  - \`ca-bundle.crt\` (optional): CA bundle for verification.
- Output files (generated):
  - \`cms-computed-by-shell-script.der\`: CMS signed message from the Bash script.
  - \`cms-computed-by-C-code.der\`: CMS signed message from the C program.
  - \`cms-computed-by-shell-script.der.hex\`, \`cms-computed-by-C-code.der.hex\`, \`verify_data.bin.hex\`: Hex dumps for comparison.
  - \`auth_request_data.bin\`: Auth-Req message data in binary (from spec example) over which the signature is computed.
  - \`cm_device_cert.pem\`: PEM-converted (from cm_device_cert.der) certificate.

## Usage

1. **Run the Bash Script**:
   
   $ ./cms-sign-verify.sh
   
   The script:
   - Downloads and builds OpenSSL (first time only)
   - Builds and runs the C program to produce the signature in \`cms-computed-by-C-code.der\`.
   - Converts the DER certificate to PEM.
   - Signs the data using OpenSSL to produce \`cms-computed-by-C-code.der\`.
   - Verifies the CMS signature using \`ca-bundle.crt\`.
   - Compares bash script computed CMS against C computed CMS against and against the spec example expected value in \`verify_data.bin\`.

2. **Run the C Program by itself**:

   Build and execute the C program:

    $ cmake .
    $ make
    $ ./cms_sign_verify

   The C program:
   - Reads and validates the hex input.
   - Signs the data using the certificate and private key.
   - Produces \`cms-computed-by-C-code.der\`.
   - Verifies the signature, using \`ca-bundle.crt\`