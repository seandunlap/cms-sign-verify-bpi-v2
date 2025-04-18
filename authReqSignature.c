// cms_sign_verify.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
#define CMS_OUT_DER "cms-computed-by-C-code.der"  // Output CMS signed message in DER format

int main(void) {
    // Indicate program start
    printf("Running authReqSignature executable\n");

    /* 1) Initialize OpenSSL libraries */
    // Load crypto strings and initialize ciphers and digests
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                        OPENSSL_INIT_ADD_ALL_CIPHERS    |
                        OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    printf("OpenSSL initialization completed\n");

    /* 2) Load the signer certificate (DER→X509) */
    // Open and parse the DER certificate file into an X509 structure
    printf("Loading signer certificate from %s\n", CERT_DER);
    FILE *f = fopen(CERT_DER, "rb");
    if (!f) {
        perror("ERROR: Failed to open DER certificate");
        return 1;
    }
    X509 *cert = d2i_X509_fp(f, NULL);
    fclose(f);
    if (!cert) {
        printf("ERROR: Failed to parse DER certificate\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* 3) Load the private key (PEM→EVP_PKEY) */
    // Open and read the PEM private key into an EVP_PKEY structure
    printf("Loading private key from %s\n", KEY_PEM);
    f = fopen(KEY_PEM, "r");
    if (!f) {
        printf("ERROR: Failed to open PEM key");
        X509_free(cert);
        return 1;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) {
        printf("ERROR: Failed to read private key\n");
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return 1;
    }

    /* 4) Read the hex dump and convert to binary */
    // Read the hex string from file and convert it to binary data
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
        printf("ERROR: Memory allocation for hex string failed\n");
        fclose(hexf);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    fread(hexstr, 1, hlen, hexf);
    hexstr[hlen] = '\0';
    fclose(hexf);
    printf("Successfully read hex string\n");

    // Convert hex string to binary
    long binlen = 0;
    unsigned char *bindata = OPENSSL_hexstr2buf(hexstr, &binlen);
    free(hexstr);
    if (!bindata) {
        printf("ERROR: Hex to binary conversion failed\n");
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

    /* 5) Sign: Mimic `openssl cms -sign -noattr -binary -outform DER` */
    // Create CMS signed message using certificate and private key
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
        perror("ERROR: Failed to write CMS output");
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

    /* 6) Verify: Mimic `openssl cms -verify -noattr -noverify -inform DER` */
    // Read CMS message and verify signature
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
        printf("ERROR: Failed to parse CMS structure\n");
        ERR_print_errors_fp(stderr);
        BIO_free(data_bio);
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    printf("CMS structure successfully parsed for verification\n");

    // Perform verification
    int verify_flags = CMS_BINARY | CMS_NOATTR | CMS_NOVERIFY;
    if (CMS_verify(cms2, NULL, NULL, NULL, NULL, verify_flags)) {
        printf("CMS signature verification successful\n");
    } else {
        printf("ERROR: CMS signature verification failed\n");
        CMS_ContentInfo_free(cms2);
        BIO_free(data_bio);
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }

    /* 7) Cleanup */
    // Free allocated resources and clean up OpenSSL
    CMS_ContentInfo_free(cms2);
    BIO_free(data_bio);
    OPENSSL_free(bindata);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    EVP_cleanup();
    ERR_free_strings();
    printf("Cleanup completed\n");

    // Indicate program completion
    printf("Program execution completed successfully\n");
    return 0;
}