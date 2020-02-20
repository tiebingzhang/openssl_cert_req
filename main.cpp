#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <string.h>

// include on Windows

#ifdef _WIN32
#include <openssl/applink.c>
#endif

#define CERT_REQUEST_KEY_PATH  "cert.key"
#define GENERATED_CERT_REQUEST_SAVE_PATH  "generated_request.csr"

#define CERT_CA_PATH "ca.pem"
#define CERT_CA_KEY_PATH "root.key"
#define GENERATED_CERT_SAVE_PATH "generated_cert.crt"

// the app mimics the following two commands.
//
// openssl req -new -key CERT_REQUEST_KEY_PATH -out GENERATED_CERT_REQUEST_SAVE_PATH
// openssl x509 -req -in GENERATED_CERT_SAVE_PATH -CA CERT_CA_PATH -CAkey CERT_CA_KEY_PATH -CAcreateserial -out GENERATED_CERT_SAVE_PATH -days 5000

X509_REQ *generate_cert_req(const char *p_path) {
    FILE *p_file = NULL;
    EVP_PKEY *p_key = NULL;
    X509_REQ *p_x509_req = NULL;

    if (NULL == (p_file = fopen(p_path, "r"))) {
        printf("failed to open the private key file\n");
        goto CLEANUP;
    }

    if (NULL == (p_key = PEM_read_PrivateKey(p_file, NULL, NULL, NULL))) {
        printf("failed to read the private key file\n");
        goto CLEANUP;
    }

    if (NULL == (p_x509_req = X509_REQ_new())) {
        printf("failed to create a new X509 REQ\n");
        goto CLEANUP;
    }

    if (0 > X509_REQ_set_pubkey(p_x509_req, p_key)) {
        printf("failed to set pub key\n");
        X509_REQ_free(p_x509_req);
        p_x509_req = NULL;
        goto CLEANUP;
    }

    if (0 > X509_REQ_sign(p_x509_req, p_key, EVP_sha256())) {
        printf("failed to sign the certificate\n");
        X509_REQ_free(p_x509_req);
        p_x509_req = NULL;
        goto CLEANUP;
    }

    CLEANUP:
    fclose(p_file);
    EVP_PKEY_free(p_key);

    return p_x509_req;
}

int randSerial(ASN1_INTEGER *ai) {
    BIGNUM *p_bignum = NULL;
    int ret = -1;

    if (NULL == (p_bignum = BN_new())) {
        goto CLEANUP;
    }

    if (!BN_pseudo_rand(p_bignum, 64, 0, 0)) {
        goto CLEANUP;
    }

    if (ai && !BN_to_ASN1_INTEGER(p_bignum, ai)) {
        goto CLEANUP;
    }

    ret = 1;

    CLEANUP:
    BN_free(p_bignum);

    return ret;
}

/*
 * name is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
X509_NAME *parse_name(const char *cp, int canmulti)
{
    int nextismulti = 0;
    char *work;
	long chtype = MBSTRING_ASC;
    X509_NAME *n;

    if (*cp++ != '/') {
        printf( "name is expected to be in the format "
                   "/type0=value0/type1=value1/type2=... where characters may "
                   "be escaped by \\. This name is not in that format: '%s'\n",
                   --cp);
        return NULL;
    }

    n = X509_NAME_new();
    if (n == NULL)
        return NULL;
    work = OPENSSL_strdup(cp);
    if (work == NULL)
        goto err;

    while (*cp) {
        char *bp = work;
        char *typestr = bp;
        unsigned char *valstr;
        int nid;
        int ismulti = nextismulti;
        nextismulti = 0;

        /* Collect the type */
        while (*cp && *cp != '=')
            *bp++ = *cp++;
        if (*cp == '\0') {
            printf( " Hit end of string before finding the equals.\n");
            goto err;
        }
        *bp++ = '\0';
        ++cp;

        /* Collect the value. */
        valstr = (unsigned char *)bp;
        for (; *cp && *cp != '/'; *bp++ = *cp++) {
            if (canmulti && *cp == '+') {
                nextismulti = 1;
                break;
            }
            if (*cp == '\\' && *++cp == '\0') {
                printf("escape character at end of string\n");
                goto err;
            }
        }
        *bp++ = '\0';

        /* If not at EOS (must be + or /), move forward. */
        if (*cp)
            ++cp;

        /* Parse */
        nid = OBJ_txt2nid(typestr);
        if (nid == NID_undef) {
            printf("Skipping unknown attribute \"%s\"\n", typestr);
            continue;
        }
        if (*valstr == '\0') {
            printf( "No value provided for Subject Attribute %s, skipped\n",typestr);
            continue;
        }
        if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                        valstr, strlen((char *)valstr),
                                        -1, ismulti ? -1 : 0))
            goto err;
    }

    OPENSSL_free(work);
    return n;

 err:
    X509_NAME_free(n);
    OPENSSL_free(work);
    return NULL;
}


X509 *generate_cert(X509_REQ *pCertReq, const char *p_ca_path, const char *p_ca_key_path) {
    FILE *p_ca_file = NULL;
    X509 *p_ca_cert = NULL;
    EVP_PKEY *p_ca_pkey = NULL;
    FILE *p_ca_key_file = NULL;
    EVP_PKEY *p_ca_key_pkey = NULL;
    X509 *p_generated_cert = NULL;
    ASN1_INTEGER *p_serial_number = NULL;
    EVP_PKEY *p_cert_req_pkey = NULL;
    FILE *p_file = NULL;
    EVP_PKEY *p_key = NULL;
	X509_NAME *xn = NULL;

    if (NULL == (p_ca_file = fopen(p_ca_path, "r"))) {
        printf("failed to open the ca file\n");
        goto CLEANUP;
    }

    if (NULL == (p_ca_cert = PEM_read_X509(p_ca_file, NULL, 0, NULL))) {
        printf("failed to read X509 CA certificate\n");
        goto CLEANUP;
    }

    if (NULL == (p_ca_pkey = X509_get_pubkey(p_ca_cert))) {
        printf("failed to get X509 CA pkey\n");
        goto CLEANUP;
    }

    if (NULL == (p_ca_key_file = fopen(p_ca_key_path, "r"))) {
        printf("failed to open the private key file\n");
        goto CLEANUP;
    }

    if (NULL == (p_ca_key_pkey = PEM_read_PrivateKey(p_ca_key_file, NULL, NULL, NULL))) {
        printf("failed to read the private key file\n");
        goto CLEANUP;
    }

    if (NULL == (p_generated_cert = X509_new())) {
        printf("failed to allocate a new X509\n");
        goto CLEANUP;
    }

    p_serial_number = ASN1_INTEGER_new();
    randSerial(p_serial_number);
    X509_set_serialNumber(p_generated_cert, p_serial_number);
	xn=parse_name("/C=US/CN=OpenSSL Group Circle/",0);

	/*
	if ((xn = d2i_X509_NAME(NULL, ((const unsigned char **)&namebytes), -1)) == NULL) {
        printf("failed to convert x509 name\n");
        goto CLEANUP;
	}
	*/

    X509_set_subject_name(p_generated_cert, xn);

    X509_gmtime_adj(X509_get_notBefore(p_generated_cert), 0L);
    X509_gmtime_adj(X509_get_notAfter(p_generated_cert), 31536000L);

#if 0
    if (NULL == (p_cert_req_pkey = X509_REQ_get_pubkey(pCertReq))) {
        printf("failed to get certificate req pkey\n");
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        goto CLEANUP;
    }
#endif
    if (NULL == (p_file = fopen(CERT_REQUEST_KEY_PATH, "r"))) {
        printf("failed to open the cert private key file\n");
        goto CLEANUP;
    }

    if (NULL == (p_key = PEM_read_PrivateKey(p_file, NULL, NULL, NULL))) {
        printf("failed to read the private key file\n");
        goto CLEANUP;
    }

    if (0 > X509_set_pubkey(p_generated_cert, p_key /*p_cert_req_pkey*/)) {
        printf("failed to set pkey\n");
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        goto CLEANUP;
    }

    if (0 > EVP_PKEY_copy_parameters(p_ca_pkey, p_ca_key_pkey)) {
        printf("failed to copy parameters\n");
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        goto CLEANUP;
    }

    X509_set_issuer_name(p_generated_cert, X509_get_subject_name(p_ca_cert));

    if (0 > X509_sign(p_generated_cert, p_ca_key_pkey, EVP_sha256())) {
        printf("failed to sign the certificate\n");
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        goto CLEANUP;
    }

    CLEANUP:
    fclose(p_ca_file);
    X509_free(p_ca_cert);
    EVP_PKEY_free(p_ca_pkey);
    fclose(p_ca_key_file);
    EVP_PKEY_free(p_ca_key_pkey);
    ASN1_INTEGER_free(p_serial_number);
    EVP_PKEY_free(p_cert_req_pkey);

    return p_generated_cert;
}

int save_cert_req(X509_REQ *p_cert_req, const char *path) {
    FILE *p_file = NULL;
    if (NULL == (p_file = fopen(path, "w"))) {
        printf("failed to open file for saving csr\n");
        return -1;
    }

    PEM_write_X509_REQ(p_file, p_cert_req);
    fclose(p_file);
    return 0;
}

int save_cert(X509 *p_generated_cert, const char *path) {
    FILE *p_file = NULL;
    if (NULL == (p_file = fopen(path, "w"))) {
        printf("failed to open file for saving csr\n");
        return -1;
    }

    PEM_write_X509(p_file, p_generated_cert);
    fclose(p_file);
    return 0;
}

int main() {
    int ret = 0;
    X509_REQ *p_cert_req = NULL;
    X509 *p_generated_cert = NULL;

#if 0
    p_cert_req = generate_cert_req(CERT_REQUEST_KEY_PATH);
    if (NULL == p_cert_req) {
        printf("failed to generate cert req\n");
        ret = -1;
        goto CLEANUP;
    }

    if (save_cert_req(p_cert_req, GENERATED_CERT_REQUEST_SAVE_PATH)) {
        printf("failed to save generated cert request\n");
        ret = -1;
        goto CLEANUP;
    }
#endif

    p_generated_cert = generate_cert(p_cert_req, CERT_CA_PATH, CERT_CA_KEY_PATH);
    if (NULL == p_generated_cert) {
        printf("failed to generate cert\n");
        ret = -1;
        goto CLEANUP;
    }

    if (save_cert(p_generated_cert, GENERATED_CERT_SAVE_PATH)) {
        printf("failed to save generated cert\n");
        ret = -1;
        goto CLEANUP;
    }

    printf("the certificates have been generated.");

    CLEANUP:
    X509_REQ_free(p_cert_req);
    X509_free(p_generated_cert);

    return ret;
}
