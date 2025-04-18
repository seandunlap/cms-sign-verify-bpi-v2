#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

// Define input and output file names
#define CERT_DER    "cm_device_cert.der"    // Device certificate in DER format
#define KEY_PEM     "cm_device_private.pem" // Private key in PEM format
#define AUTH_HEX    "auth_request_data.txt" // Input hex data file
#define CMS_OUT_DER "cms-computed-by-C-code.der"  // Output CMS signed message
#define CA_BUNDLE   "ca-bundle.crt"         // Optional CA bundle for verification

int main(void) {
    // Indicate program start
    printf("Running authReqSignature executable\n");

    /* 1) Initialize OpenSSL libraries */
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                            OPENSSL_INIT_ADD_ALL_CIPHERS    |
                            OPENSSL_INIT_ADD_ALL_DIGESTS, NULL) != 1) {
        fprintf(stderr, "ERROR: OpenSSL initialization failed\n");
        return 1;
    }
    printf("OpenSSL initialization completed\n");

    /* 2) Load the signer certificate (DER→X509) */
    printf("Loading signer certificate from %s\n", CERT_DER);
    FILE *f = fopen(CERT_DER, "rb");
    if (!f) {
        perror("ERROR: Failed to open DER certificate");
        return 1;
    }
    X509 *cert = d2i_X509_fp(f, NULL);
    fclose(f);
    if (!cert) {
        fprintf(stderr, "ERROR: Failed to parse DER certificate\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* 3) Load the private key (PEM→EVP_PKEY) */
    printf("Loading private key from %s\n", KEY_PEM);
    f = fopen(KEY_PEM, "r");
    if (!f) {
        perror("ERROR: Failed to open PEM key");
        X509_free(cert);
        return 1;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL); // Add passphrase if needed
    fclose(f);
    if (!pkey) {
        fprintf(stderr, "ERROR: Failed to read private key\n");
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return 1;
    }

    /* 4) Verify certificate and private key compatibility */
    printf("Verifying certificate and private key compatibility\n");
    if (!X509_check_private_key(cert, pkey)) {
        fprintf(stderr, "ERROR: Private key does not match certificate\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }

    /* 5) Read and validate hex dump */
    printf("Reading hex data from %s\n", AUTH_HEX);
    FILE *hexf = fopen(AUTH_HEX, "r");
    if (!hexf) {
        perror("ERROR: Failed to open auth hex file");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    // Get file size
    fseek(hexf, 0, SEEK_END);
    long hlen = ftell(hexf);
    fseek(hexf, 0, SEEK_SET);
    printf("Hex file size: %ld bytes\n", hlen);

    // Allocate buffer for hex string
    char *hexstr = malloc(hlen + 1);
    if (!hexstr) {
        fprintf(stderr, "ERROR: Memory allocation for hex string failed\n");
        fclose(hexf);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    fread(hexstr, 1, hlen, hexf);
    hexstr[hlen] = '\0';
    fclose(hexf);

    // Validate hex string
    for (long i = 0; i < hlen; i++) {
        if (!isxdigit((unsigned char)hexstr[i]) && !isspace((unsigned char)hexstr[i])) {
            fprintf(stderr, "ERROR: Invalid hex character at position %ld\n", i);
            free(hexstr);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            return 1;
        }
    }
    printf("Hex string validated successfully\n");

    // Convert hex string to binary
    long binlen = 0;
    unsigned char *bindata = OPENSSL_hexstr2buf(hexstr, &binlen);
    free(hexstr);
    if (!bindata) {
        fprintf(stderr, "ERROR: Hex to binary conversion failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    printf("Converted hex to %ld bytes of binary data\n", binlen);

    // Print binary data in hex format
    printf("Binary data (hex):\n");
    for (long i = 0; i < binlen; i++) {
        printf("%02X ", bindata[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // Create BIO for binary data
    BIO *data_bio = BIO_new_mem_buf(bindata, (int)binlen);
    if (!data_bio) {
        fprintf(stderr, "ERROR: Failed to create data BIO\n");
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    printf("Created BIO for binary data\n");

    /* 6) Sign: Mimic `openssl cms -sign -noattr -binary -outform DER` */
    printf("Creating CMS signed message\n");
    int sign_flags = CMS_BINARY | CMS_NOATTR;
    CMS_ContentInfo *cms = CMS_sign(cert, pkey, NULL, data_bio, sign_flags);
    if (!cms) {
        fprintf(stderr, "ERROR: CMS_sign() failed\n");
        ERR_print_errors_fp(stderr);
        BIO_free(data_bio);
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    printf("CMS signing completed\n");

    // Write CMS message to DER file
    printf("Writing CMS output to %s\n", CMS_OUT_DER);
    BIO *out = BIO_new_file(CMS_OUT_DER, "wb");
    if (!out || i2d_CMS_bio(out, cms) <= 0) {
        fprintf(stderr, "ERROR: Failed to write CMS output\n");
        ERR_print_errors_fp(stderr);
        BIO_free(out);
        CMS_ContentInfo_free(cms);
        BIO_free(data_bio);
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    BIO_free(out);
    CMS_ContentInfo_free(cms);
    printf("CMS signed message written to %s\n", CMS_OUT_DER);

    /* 7) Verify: Mimic `openssl cms -verify -noattr [-CAfile ca-bundle.crt | -noverify]` */
    printf("Verifying CMS signature from %s\n", CMS_OUT_DER);
    BIO *in = BIO_new_file(CMS_OUT_DER, "rb");
    if (!in) {
        perror("ERROR: Failed to open CMS for verification");
        BIO_free(data_bio);
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    CMS_ContentInfo *cms2 = d2i_CMS_bio(in, NULL);
    BIO_free(in);
    if (!cms2) {
        fprintf(stderr, "ERROR: Failed to parse CMS structure\n");
        ERR_print_errors_fp(stderr);
        BIO_free(data_bio);
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    printf("CMS structure successfully parsed for verification\n");

    // Prepare for verification
    STACK_OF(X509) *certs = NULL;
    int verify_flags = CMS_BINARY | CMS_NOATTR;
    int use_ca_verification = 0;

    // Check for CA bundle
    f = fopen(CA_BUNDLE, "r");
    if (f) {
        printf("CA bundle found at %s, verifying with CA chain\n", CA_BUNDLE);
        use_ca_verification = 1;
        certs = sk_X509_new_null();
        if (!certs) {
            fprintf(stderr, "ERROR: Failed to create certificate stack\n");
            fclose(f);
            CMS_ContentInfo_free(cms2);
            BIO_free(data_bio);
            OPENSSL_free(bindata);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            return 1;
        }
        X509 *ca_cert = PEM_read_X509(f, NULL, NULL, NULL);
        fclose(f);
        if (!ca_cert) {
            fprintf(stderr, "ERROR: Failed to read CA certificate\n");
            ERR_print_errors_fp(stderr);
            sk_X509_free(certs);
            CMS_ContentInfo_free(cms2);
            BIO_free(data_bio);
            OPENSSL_free(bindata);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            return 1;
        }
        sk_X509_push(certs, ca_cert);
    } else {
        printf("Warning: CA bundle (%s) not found, verifying without CA chain\n", CA_BUNDLE);
        verify_flags |= CMS_NOVERIFY;
    }

    // Perform verification
    BIO *out_content = BIO_new(BIO_s_mem());
    if (!out_content) {
        fprintf(stderr, "ERROR: Failed to create output BIO\n");
        if (certs) sk_X509_pop_free(certs, X509_free);
        CMS_ContentInfo_free(cms2);
        BIO_free(data_bio);
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    if (!CMS_verify(cms2, use_ca_verification ? certs : NULL, NULL, NULL, out_content, verify_flags)) {
        fprintf(stderr, "ERROR: CMS signature verification failed\n");
        ERR_print_errors_fp(stderr);
        BIO_free(out_content);
        if (certs) sk_X509_pop_free(certs, X509_free);
        CMS_ContentInfo_free(cms2);
        BIO_free(data_bio);
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    printf("CMS signature verification successful\n");

    // Extract and compare verified content
    printf("Comparing verified content with original data\n");
    char *verified_data = NULL;
    long verified_len = BIO_get_mem_data(out_content, &verified_data);
    if (verified_len != binlen || memcmp(verified_data, bindata, binlen) != 0) {
        fprintf(stderr, "ERROR: Verified content does not match original data\n");
        BIO_free(out_content);
        if (certs) sk_X509_pop_free(certs, X509_free);
        CMS_ContentInfo_free(cms2);
        BIO_free(data_bio);
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    printf("Verified content matches original data\n");
    BIO_free(out_content);

    /* 8) Print CMS details */
    STACK_OF(X509) *signers = CMS_get0_signers(cms2);
    if (signers) {
        printf("Number of signers: %d\n", sk_X509_num(signers));
        for (int i = 0; i < sk_X509_num(signers); i++) {
            X509 *signer = sk_X509_value(signers, i);
            char *subject = X509_NAME_oneline(X509_get_subject_name(signer), NULL, 0);
            printf("Signer %d subject: %s\n", i, subject);
            OPENSSL_free(subject);
        }
        sk_X509_free(signers);
    }

    /* 9) Cleanup */
    if (certs) sk_X509_pop_free(certs, X509_free);
    CMS_ContentInfo_free(cms2);
    BIO_free(data_bio);
    OPENSSL_free(bindata);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    printf("Cleanup completed\n");

    printf("Program execution completed successfully\n");
    return 0;
}