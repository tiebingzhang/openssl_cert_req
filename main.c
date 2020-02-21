#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define CERT_CA_PATH "ca.pem"
#define CERT_CA_KEY_PATH "root.key"
#define GENERATED_CERT_SAVE_PATH "generated_cert.crt"

// Add extension using V3 code: we can set the config file as NULL because we wont reference any other sections.
static int add_ext(X509 *issuer, X509 *cert, int nid, char *value) {
    X509_EXTENSION *ex = NULL;
    X509V3_CTX ctx;

    // This sets the 'context' of the extensions. No configuration database
    X509V3_set_ctx_nodb(&ctx);

    // Issuer and subject certs: both the target since it is self signed, no request and no CRL
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex) {
        return -1;
    }

    int result = X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return (result == 0) ? 0 : -1;
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
X509_NAME *parse_name(const char *cp, int canmulti) {
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


X509 *generate_cert(char *domain, const char *p_ca_path, const char *p_ca_key_path) {
    FILE *p_ca_file = NULL;
    X509 *p_ca_cert = NULL;
    EVP_PKEY *p_ca_pubkey = NULL;
    FILE *p_ca_key_file = NULL;
    EVP_PKEY *p_ca_key_pkey = NULL;
    X509 *p_generated_cert = NULL;
    ASN1_INTEGER *p_serial_number = NULL;
    FILE *p_file = NULL;
    EVP_PKEY *p_key = NULL;
	X509_NAME *xn = NULL;
	RSA *rsa;
	int bits=2048;
	BIGNUM *e;
	char fullname[512];
	char san[256];

	snprintf(fullname,sizeof(fullname),"/C=US/O=Circle/CN=%s/",domain);
	snprintf(san,sizeof(san),"DNS:%s",domain);
    if (NULL == (p_ca_file = fopen(p_ca_path, "r"))) {
        printf("failed to open the ca file\n");
        goto CLEANUP;
    }

    if (NULL == (p_ca_cert = PEM_read_X509(p_ca_file, NULL, 0, NULL))) {
        printf("failed to read X509 CA certificate\n");
        goto CLEANUP;
    }

    if (NULL == (p_ca_pubkey = X509_get_pubkey(p_ca_cert))) {
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

	xn=parse_name(fullname,0);
    X509_set_subject_name(p_generated_cert, xn);


    X509_gmtime_adj(X509_get_notBefore(p_generated_cert), -24*3600);
    X509_gmtime_adj(X509_get_notAfter(p_generated_cert), 730*24*3600);

	e=BN_new();
	BN_set_word(e, RSA_F4);
	rsa = RSA_new();
	RSA_generate_key_ex(rsa, bits, e, NULL);
	if ((p_key=EVP_PKEY_new()) == NULL) {
        printf("failed to new pkey\n");
        goto CLEANUP;
	}
	if (!EVP_PKEY_assign_RSA(p_key,rsa)) {
        printf("failed to assign key\n");
        goto CLEANUP;
	}

    if (0 > X509_set_pubkey(p_generated_cert, p_key )) {
        printf("failed to set pkey\n");
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        goto CLEANUP;
    }


    if (0 > EVP_PKEY_copy_parameters(p_ca_pubkey, p_ca_key_pkey)) {
        printf("failed to copy parameters\n");
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        goto CLEANUP;
    }

    X509_set_issuer_name(p_generated_cert, X509_get_subject_name(p_ca_cert));

	// A CA certificate must include the basicConstraints value with the CA field set to TRUE.
	//add_ext(p_ca_cert, p_generated_cert, NID_basic_constraints, "critical,CA:TRUE" );

	// Key usage is a multi valued extension consisting of a list of names of the permitted key usages.
	add_ext (p_ca_cert, p_generated_cert, NID_key_usage, "digitalSignature, nonRepudiation" );

	// This Extensions consists of a list of usages indicating purposes for which the certificate public key can be used for.
	add_ext (p_ca_cert, p_generated_cert, NID_ext_key_usage, "critical,serverAuth" );

	add_ext(p_ca_cert, p_generated_cert, NID_subject_alt_name, san);

#if 0
	// Adds a new object to the internal table. oid is the numerical form
	// of the object, sn the short name and ln the long name.
	int nid = OBJ_create ( "1.2.3.4", "SAMP_OID", "Test_OID" );
	X509V3_EXT_add_alias ( nid, NID_netscape_comment );
	add_ext (p_ca_cert, p_generated_cert, nid, "MQ Comment Section" );
#endif

    if (0 > X509_sign(p_generated_cert, p_ca_key_pkey, EVP_sha256())) {
        printf("failed to sign the certificate\n");
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        goto CLEANUP;
    }

    CLEANUP:
    fclose(p_ca_file);
    X509_free(p_ca_cert);
    EVP_PKEY_free(p_ca_pubkey);
    fclose(p_ca_key_file);
    EVP_PKEY_free(p_ca_key_pkey);
    ASN1_INTEGER_free(p_serial_number);
	BN_free(e);
	RSA_free(rsa);

    return p_generated_cert;
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
    X509 *p_generated_cert = NULL;

    p_generated_cert = generate_cert("www.facebook.com", CERT_CA_PATH, CERT_CA_KEY_PATH);
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
    X509_free(p_generated_cert);

    return ret;
}
