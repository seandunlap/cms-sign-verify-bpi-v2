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
#define CERT_DER      "cm_device_cert.der"       // Device certificate in DER format
#define KEY_PEM       "cm_device_private.pem"    // Private key in PEM format
#define AUTH_HEX      "auth_request_data.txt"    // Input hex data file
#define CMS_OUT_DER   "cms-computed-by-C-code.der" // Output CMS signed message
#define CA_BUNDLE     "ca-bundle.crt"            // CA bundle for verification

// Uniform fatal error handler
static void fatal(const char *msg) {
    fprintf(stderr, "FATAL: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

int main(void) {
    int ret = 0;

    printf("Running cms_sign_verify executable\n");

    /* 1) Initialize OpenSSL libraries */
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                            OPENSSL_INIT_ADD_ALL_CIPHERS    |
                            OPENSSL_INIT_ADD_ALL_DIGESTS, NULL) != 1) {
        fatal("OpenSSL initialization failed");
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
        fatal("Failed to parse DER certificate");
    }

    /* 3) Load the private key (PEM→EVP_PKEY) */
    printf("Loading private key from %s\n", KEY_PEM);
    f = fopen(KEY_PEM, "r");
    if (!f) {
        perror("ERROR: Failed to open PEM key");
        X509_free(cert);
        return 1;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) {
        fatal("Failed to read private key");
    }

    /* 4) Verify certificate and private key compatibility */
    printf("Verifying certificate and private key compatibility\n");
    if (!X509_check_private_key(cert, pkey)) {
        fatal("Private key does not match certificate");
    }

    /* 5) Read and validate hex dump */
    printf("Reading hex data from %s\n", AUTH_HEX);
    f = fopen(AUTH_HEX, "r");
    if (!f) {
        perror("ERROR: Failed to open auth hex file");
        ret = 1;
        goto cleanup_keys;
    }
    fseek(f, 0, SEEK_END);
    long hlen = ftell(f);
    fseek(f, 0, SEEK_SET);
    printf("Hex file size: %ld bytes\n", hlen);

    char *hexstr = malloc(hlen + 1);
    if (!hexstr) {
        fatal("Memory allocation for hex string failed");
    }
    fread(hexstr, 1, hlen, f);
    hexstr[hlen] = '\0';
    fclose(f);

    for (long i = 0; i < hlen; i++) {
        if (!isxdigit((unsigned char)hexstr[i]) && !isspace((unsigned char)hexstr[i])) {
            fprintf(stderr, "ERROR: Invalid hex character at position %ld\n", i);
            ret = 1;
            goto cleanup_hex;
        }
    }
    printf("Hex string validated successfully\n");

    long binlen = 0;
    unsigned char *bindata = OPENSSL_hexstr2buf(hexstr, &binlen);
    free(hexstr);
    if (!bindata) {
        fatal("Hex to binary conversion failed");
    }
    printf("Converted hex to %ld bytes of binary data\n", binlen);

    printf("Binary data (hex):\n");
    for (long i = 0; i < binlen; i++) {
        printf("%02x%c", bindata[i], ((i+1)%16==0)?'\n':' ');
    }
    printf("\n");

    BIO *data_bio = BIO_new_mem_buf(bindata, (int)binlen);
    if (!data_bio) {
        fatal("Failed to create data BIO");
    }
    printf("Created BIO for binary data\n");

    /* 6) Sign: mimic `openssl cms -sign -noattr -binary -outform DER` */
    printf("Creating CMS signed message\n");
    CMS_ContentInfo *cms = CMS_sign(cert, pkey, NULL, data_bio, CMS_BINARY|CMS_NOATTR);
    if (!cms) {
        fatal("CMS_sign() failed");
    }

    printf("Writing CMS output to %s\n", CMS_OUT_DER);
    BIO *out = BIO_new_file(CMS_OUT_DER, "wb");
    if (!out || i2d_CMS_bio(out, cms) <= 0) {
        fatal("Failed to write CMS output");
    }
    BIO_free(out);
    CMS_ContentInfo_free(cms);
    printf("CMS signed message written to %s\n", CMS_OUT_DER);

    /* 7) Verify: load CA bundle into X509_STORE for chain validation */
    printf("Loading CA bundle from %s into trust store\n", CA_BUNDLE);
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        fatal("Unable to create X509_STORE");
    }
    if (X509_STORE_load_locations(store, CA_BUNDLE, NULL) != 1) {
        fatal("Failed to load CA bundle");
    }

    /* Disable EKU/purpose checking by setting purpose to ANY */
    {
        X509_VERIFY_PARAM *vpm = X509_STORE_get0_param(store);
        if (!X509_VERIFY_PARAM_set_purpose(vpm, X509_PURPOSE_ANY)) {
            fatal("Failed to set verification purpose to ANY");
        }
    }

    printf("CA bundle loaded; verifying CMS signature with full chain\n");
    BIO *in = BIO_new_file(CMS_OUT_DER, "rb");
    if (!in) {
        perror("ERROR: Failed to open CMS for verification");
        ret = 1;
        goto cleanup_store;
    }
    CMS_ContentInfo *cms2 = d2i_CMS_bio(in, NULL);
    BIO_free(in);
    if (!cms2) {
        fatal("Failed to parse CMS structure");
    }

    BIO *out_content = BIO_new(BIO_s_mem());
    if (!out_content) {
        fatal("Could not allocate output BIO");
    }

    if (!CMS_verify(cms2, NULL, store, NULL, out_content, CMS_BINARY|CMS_NOATTR)) {
        fprintf(stderr, "ERROR: CMS_verify() failed\n");
        ERR_print_errors_fp(stderr);
        ret = 1;
        goto cleanup_verify;
    }
    printf("CMS signature verification with CA chain succeeded\n");

    /* 8) (Optional) Print signer details */
    {
        STACK_OF(X509) *signers = CMS_get0_signers(cms2);
        if (signers) {
            int n = sk_X509_num(signers);
            printf("Number of signers: %d\n", n);
            for (int i = 0; i < n; i++) {
                X509 *s = sk_X509_value(signers, i);
                char *subj = X509_NAME_oneline(X509_get_subject_name(s), NULL, 0);
                printf("Signer %d subject: %s\n", i, subj);
                OPENSSL_free(subj);
            }
            sk_X509_free(signers);
        }
    }

cleanup_verify:
    BIO_free(out_content);
    CMS_ContentInfo_free(cms2);
cleanup_store:
    X509_STORE_free(store);
cleanup_hex:
    OPENSSL_free(bindata);
cleanup_keys:
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free(data_bio);

    if (ret == 0) {
        printf("Program execution completed successfully\n");
    }
    return ret;
}
