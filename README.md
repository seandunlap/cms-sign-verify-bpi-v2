cat << EOF > README.md
# CMS Signing and Verification Project

This project provides tools to sign and verify data using Cryptographic Message Syntax (CMS) with OpenSSL. It includes a Bash script and a C program that perform equivalent operations: signing a hex-encoded input using a certificate and private key, producing a CMS signed message in DER format, and verifying the signature. The Bash script also compares the outputs to ensure consistency.

## Project Overview

The project consists of two main components:
1. **Bash Script (\`script.sh\`)**: Automates the CMS signing and verification process using OpenSSL commands, builds and runs the C program, and compares the outputs.
2. **C Program (\`cms_sign_verify.c\`)**: Implements CMS signing and verification using the OpenSSL library, producing an equivalent CMS signed message.

Both components:
- Read a hex-encoded input file (\`auth_request_data.txt\`).
- Sign it using a DER certificate (\`cm_device_cert.der\`) and PEM private key (\`cm_device_private.pem\`).
- Produce a CMS signed message in DER format.
- Verify the signature, optionally using a CA bundle (\`ca-bundle.crt\`).
- Compare the CMS outputs against an expected result (\`verify_data.bin\`).

The Bash script ensures that the CMS signatures produced by both implementations are identical and match the expected output.

## Prerequisites

- **Operating System**: Linux or Unix-like system (e.g., Ubuntu, CentOS).
- **Dependencies**:
  - **OpenSSL**: For the Bash script (\`openssl\` command) and C program (OpenSSL development libraries).
    - Install on Ubuntu: \`sudo apt-get install openssl libssl-dev\`
    - Install on CentOS: \`sudo yum install openssl openssl-devel\`
  - **CMake**: For building the C program.
    - Install: \`sudo apt-get install cmake\` or \`sudo yum install cmake\`
  - **Make**: For compiling the C program.
    - Install: \`sudo apt-get install make\` or \`sudo yum install make\`
  - **xxd**: For hex-to-binary conversion in the Bash script.
    - Usually included with \`vim\`: \`sudo apt-get install vim\` or \`sudo yum install vim\`
- **Hardware**: Standard system with sufficient memory and disk space.

## Installation

1. **Clone or Download the Repository**:
   \`\`\`bash
   git clone <repository-url>
   cd <repository-directory>
   \`\`\`

2. **Prepare Input Files**:
   Ensure the following files are in the project directory:
   - \`cm_device_cert.der\`: DER-encoded device certificate.
   - \`cm_device_private.pem\`: PEM-encoded private key.
   - \`auth_request_data.txt\`: Hex-encoded input data (e.g., \`48656C6C6F\` for "Hello").
   - \`verify_data.bin\`: Expected CMS signed message in DER format (for comparison).
   - \`ca-bundle.crt\` (optional): CA certificate bundle for verification. If missing, verification skips CA chain validation.

3. **Set Up Permissions**:
   Make the Bash script executable:
   \`\`\`bash
   chmod +x script.sh
   \`\`\`

## Project Structure

- \`script.sh\`: Bash script to automate CMS signing, verification, and comparison.
- \`cms_sign_verify.c\`: C program to perform CMS signing and verification.
- \`CMakeLists.txt\`: CMake configuration for building the C program.
- Input files:
  - \`cm_device_cert.der\`: Certificate for signing.
  - \`cm_device_private.pem\`: Private key for signing.
  - \`auth_request_data.txt\`: Hex input data.
  - \`verify_data.bin\`: Expected CMS output.
  - \`ca-bundle.crt\` (optional): CA bundle for verification.
- Output files (generated):
  - \`cms.der\`: CMS signed message from the Bash script.
  - \`cms-computed-by-C-code.der\`: CMS signed message from the C program.
  - \`cms.der.hex\`, \`cms-computed-by-C-code.der.hex\`, \`verify_data.bin.hex\`: Hex dumps for comparison.
  - \`auth_request_data.bin\`: Binary input data (temporary).
  - \`cm_device_cert.pem\`: PEM-converted certificate (temporary).

## Usage

1. **Run the Bash Script**:
   \`\`\`bash
   ./script.sh
   \`\`\`
   The script:
   - Validates and cleans the hex input.
   - Converts the hex input to binary.
   - Converts the DER certificate to PEM.
   - Signs the data using OpenSSL to produce \`cms.der\`.
   - Verifies the CMS signature, using \`ca-bundle.crt\` if available or skipping CA verification otherwise.
   - Builds and runs the C program to produce \`cms-computed-by-C-code.der\`.
   - Compares both CMS outputs with each other and \`verify_data.bin\`.

2. **Run the C Program Directly** (Optional):
   Build and execute the C program:
   \`\`\`bash
   cmake .
   make
   ./authReqSignature
   \`\`\`
   The C program:
   - Reads and validates the hex input.
   - Signs the data using the certificate and private key.
   - Produces \`cms-computed-by-C-code.der\`.
   - Verifies the signature, using \`ca-bundle.crt\` if available or skipping CA verification.

3. **Expected Output**:
   - The script logs each step (e.g., file checks, signing, verification).
   - If successful, the CMS signatures (\`cms.der\` and \`cms-computed-by-C-code.der\`) match each other and \`verify_data.bin\`, with no differences in the \`diff\` comparisons.
   - Example output:
     \`\`\`
     [12:34:56] Checking input files
     [12:34:56] Validating and cleaning hex input in auth_request_data.txt
     [12:34:56] Converting cleaned hex to binary auth_request_data.bin
     ...
     [12:34:57] C program CMS matches shell script CMS
     [12:34:57] All operations completed successfully
     \`\`\`

## Error Handling

The Bash script is designed to exit automatically on any failure:
- **File Checks**: Exits if required input files are missing or unreadable.
- **Input Validation**: Exits if the hex input contains invalid characters.
- **Command Failures**: Exits if any command (e.g., \`xxd\`, \`openssl\`, \`cmake\`, \`make\`) fails.
- **Output Comparisons**: Exits if the CMS outputs differ from each other or the expected result.
- **Logging**: Errors are logged with timestamps for debugging.

The C program includes robust error handling:
- Validates hex input and certificate/key compatibility.
- Checks for file and memory allocation failures.
- Provides detailed error messages via \`stderr\`.

## Troubleshooting

1. **CMS Outputs Differ**:
   - **Symptom**: The script reports differences in \`cms.der.hex\` vs. \`cms-computed-by-C-code.der.hex\`.
   - **Cause**: Likely due to inconsistent input data (e.g., whitespace in \`auth_request_data.txt\`.
   - **Fix**:
     - Verify the binary input:
       \`\`\`bash
       xxd auth_request_data.bin
       \`\`\`
       Compare with the C program’s “Binary data (hex)” output.
     - Ensure \`auth_request_data.txt\` contains only valid hex characters (no whitespace):
       \`\`\`bash
       cat -v auth_request_data.txt
       \`\`\`
     - Run with a clean hex input:
       \`\`\`bash
       echo -n "48656C6C6F" > auth_request_data.txt
       ./script.sh
       \`\`\`

2. **Verification Fails**:
   - **Symptom**: CMS verification fails with an error like “CMS verification failed.”
   - **Cause**: Invalid certificate, private key, or CA bundle.
   - **Fix**:
     - Check if \`ca-bundle.crt\` exists and contains the correct CA certificates.
     - If CA verification is not needed, ensure \`ca-bundle.crt\` is absent to skip it.
     - Verify certificate and key compatibility:
       \`\`\`bash
       openssl verify -CAfile ca-bundle.crt cm_device_cert.pem
       \`\`\`

3. **Build Errors**:
   - **Symptom**: \`cmake\` or \`make\` fails.
   - **Cause**: Missing OpenSSL libraries or CMake configuration.
   - **Fix**:
     - Install dependencies:
       \`\`\`bash
       sudo apt-get install libssl-dev cmake make
       \`\`\`
     - Ensure \`CMakeLists.txt\` is correct (see below).

4. **OpenSSL Version Mismatch**:
   - **Symptom**: CMS outputs differ due to different OpenSSL versions.
   - **Fix**:
     - Check versions:
       \`\`\`bash
       openssl version
       ldd ./authReqSignature | grep libcrypto
       \`\`\`
     - Rebuild the C program against the system’s OpenSSL version.

## Example \`CMakeLists.txt\`

\`\`\`cmake
cmake_minimum_required(VERSION 3.10)
project(authReqSignature C)
find_package(OpenSSL REQUIRED)
add_executable(authReqSignature cms_sign_verify.c)
target_link_libraries(authReqSignature OpenSSL::SSL OpenSSL::Crypto)
\`\`\`

## Security Considerations

- **CA Bundle**: If \`ca-bundle.crt\` is missing, both programs skip CA chain verification, reducing security. Use a valid CA bundle in production to ensure the certificate is trusted.
- **Private Key**: Protect \`cm_device_private.pem\` with appropriate permissions (e.g., \`chmod 600 cm_device_private.pem\`).
- **Input Validation**: The script and C program validate hex input, but ensure \`auth_request_data.txt\` is from a trusted source.

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch (\`git checkout -b feature/your-feature\`).
3. Commit changes (\`git commit -m "Add your feature"\`).
4. Push to the branch (\`git push origin feature/your-feature\`).
5. Open a pull request.

Please include tests and update documentation as needed.

## License

This project is licensed under the MIT License. See the \`LICENSE\` file for details.

## Contact

For questions or issues, please open an issue on the repository or contact the maintainer at <sean.dunlap@broadcom.com>.
EOF
