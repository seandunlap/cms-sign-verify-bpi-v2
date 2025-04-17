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

#define CERT_DER    "cm_device_cert.der"
#define KEY_PEM     "cm_device_private.pem"
#define AUTH_HEX    "auth_request_data.txt"
#define CMS_OUT_DER "auth_request_cms.p7s"

int main(void) {
    /* 1) Initialize OpenSSL */
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                        OPENSSL_INIT_ADD_ALL_CIPHERS    |
                        OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    /* 2) Load the signer certificate (DER→X509) */
    FILE *f = fopen(CERT_DER, "rb");
    if (!f) { perror("Opening DER certificate"); return 1; }
    X509 *cert = d2i_X509_fp(f, NULL);
    fclose(f);
    if (!cert) {
        fprintf(stderr, "Error parsing DER certificate\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* 3) Load the private key (PEM→EVP_PKEY) */
    f = fopen(KEY_PEM, "r");
    if (!f) { perror("Opening PEM key"); X509_free(cert); return 1; }
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) {
        fprintf(stderr, "Error reading private key\n");
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return 1;
    }

    /* 4) Read the hex dump and convert to binary */
    FILE *hexf = fopen(AUTH_HEX, "r");
    if (!hexf) { perror("Opening auth hex file"); EVP_PKEY_free(pkey); X509_free(cert); return 1; }
    fseek(hexf, 0, SEEK_END);
    long hlen = ftell(hexf);
    fseek(hexf, 0, SEEK_SET);
    char *hexstr = malloc(hlen + 1);
    fread(hexstr, 1, hlen, hexf);
    hexstr[hlen] = '\0';
    fclose(hexf);

    long binlen = 0;
    unsigned char *bindata = OPENSSL_hexstr2buf(hexstr, &binlen);
    free(hexstr);
    if (!bindata) {
        fprintf(stderr, "Hex→bin conversion failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }

    BIO *data_bio = BIO_new_mem_buf(bindata, (int)binlen);
    if (!data_bio) {
        fprintf(stderr, "Creating data BIO failed\n");
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }

    /* 5) Sign: mimic `openssl cms -sign -noattr -binary -outform DER` */
    int sign_flags = CMS_BINARY | CMS_NOATTR;
    CMS_ContentInfo *cms = CMS_sign(cert, pkey, NULL, data_bio, sign_flags);
    if (!cms) {
        fprintf(stderr, "CMS_sign() failed\n");
        ERR_print_errors_fp(stderr);
        BIO_free(data_bio);
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }

    BIO *out = BIO_new_file(CMS_OUT_DER, "wb");
    if (!out || i2d_CMS_bio(out, cms) <= 0) {
        perror("Writing CMS output");
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

    printf("CMS Signed Message successfully created at %s\n", CMS_OUT_DER);

    /* 6) Verify: mimic `openssl cms -verify -noattr -noverify -inform DER` */
    BIO *in = BIO_new_file(CMS_OUT_DER, "rb");
    if (!in) { perror("Opening CMS for verify"); BIO_free(data_bio); OPENSSL_free(bindata); EVP_PKEY_free(pkey); X509_free(cert); return 1; }
    CMS_ContentInfo *cms2 = d2i_CMS_bio(in, NULL);
    BIO_free(in);
    if (!cms2) {
        fprintf(stderr, "Parsing CMS structure failed\n");
        ERR_print_errors_fp(stderr);
        BIO_free(data_bio);
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }

    int verify_flags = CMS_BINARY | CMS_NOATTR | CMS_NOVERIFY;
    if (CMS_verify(cms2, NULL, NULL, NULL, NULL, verify_flags)) {
        printf("CMS signature verification successful\n");
    } else {
        fprintf(stderr, "CMS signature verification failed\n");
        ERR_print_errors_fp(stderr);
        CMS_ContentInfo_free(cms2);
        BIO_free(data_bio);
        OPENSSL_free(bindata);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }

    /* 7) Cleanup */
    CMS_ContentInfo_free(cms2);
    BIO_free(data_bio);
    OPENSSL_free(bindata);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
