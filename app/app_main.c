/*****************************************************************************
* Copyright (c) 2016, Cisco Systems, Inc.
* All rights reserved.

* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/
/*
 * This module is not part of libacvp.  Rather, it's a simple app that
 * demonstrates how to use libacvp. Software that use libacvp
 * will need to implement a similar module.
 *
 * It will default to 127.0.0.1 port 443 if no arguments are given.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "acvp.h"
#ifdef USE_MURL
#include <murl/murl.h>
#else
#include <curl/curl.h>
#endif
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#ifdef OPENSSL_KDF_SUPPORT
#include <openssl/kdf.h>
#endif
//#include <openssl/dsa.h>

#ifdef ACVP_NO_RUNTIME
#include "app_lcl.h"
#include <openssl/fips_rand.h>
#include <openssl/fips.h>
extern int fips_selftest_fail;
extern int fips_mode;
int dsa_builtin_paramgen(DSA *ret, size_t bits, size_t qbits,
	const EVP_MD *evpmd, const unsigned char *seed_in, size_t seed_len,
	unsigned char *seed_out,
	int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
/*int dsa_builtin_paramgen2(DSA *ret, size_t L, size_t N,
	const EVP_MD *evpmd, const unsigned char *seed_in, size_t seed_len,
	int idx, unsigned char *seed_out,
	int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);*/
#endif
static void enable_aes(ACVP_CTX *ctx);
static void enable_tdes(ACVP_CTX *ctx);
static void enable_hash(ACVP_CTX *ctx);
static void enable_cmac(ACVP_CTX *ctx);
static void enable_hmac(ACVP_CTX *ctx);
static void enable_kdf(ACVP_CTX *ctx);
static void enable_dsa(ACVP_CTX *ctx);
static void enable_rsa(ACVP_CTX *ctx);
static void enable_ecdsa(ACVP_CTX *ctx);
static void enable_drbg(ACVP_CTX *ctx);

static ACVP_RESULT app_aes_handler_aead(ACVP_TEST_CASE *test_case);
static ACVP_RESULT app_aes_keywrap_handler(ACVP_TEST_CASE *test_case);
static ACVP_RESULT app_aes_handler(ACVP_TEST_CASE *test_case);
static ACVP_RESULT app_des_keywrap_handler(ACVP_TEST_CASE *test_case);
static ACVP_RESULT app_des_handler(ACVP_TEST_CASE *test_case);
static ACVP_RESULT app_sha_handler(ACVP_TEST_CASE *test_case);
static ACVP_RESULT app_hmac_handler(ACVP_TEST_CASE *test_case);
static ACVP_RESULT app_cmac_handler(ACVP_TEST_CASE *test_case);
//static ACVP_RESULT app_dsa_handler(ACVP_TEST_CASE *test_case);

#ifdef OPENSSL_KDF_SUPPORT
static ACVP_RESULT app_kdf135_tls_handler(ACVP_TEST_CASE *test_case);
static ACVP_RESULT app_kdf135_snmp_handler(ACVP_TEST_CASE *test_case);
static ACVP_RESULT app_kdf135_ssh_handler(ACVP_TEST_CASE *test_case);
#endif
#ifdef ACVP_NO_RUNTIME
static ACVP_RESULT app_drbg_handler(ACVP_TEST_CASE *test_case);
static ACVP_RESULT app_rsa_keygen_handler(ACVP_TEST_CASE *test_case);
static ACVP_RESULT app_rsa_sig_handler(ACVP_TEST_CASE *test_case);
static ACVP_RESULT app_ecdsa_handler(ACVP_TEST_CASE *test_case);
#endif

#define DEFAULT_SERVER "127.0.0.1"
#define DEFAULT_PORT 443
#define DEFAULT_CA_CHAIN "certs/acvp-private-root-ca.crt.pem"
#define DEFAULT_CERT "certs/sto-labsrv2-client-cert.pem"
#define DEFAULT_KEY "certs/sto-labsrv2-client-key.pem"

#define TLS_MD_MASTER_SECRET_CONST              "master secret"
#define TLS_MD_MASTER_SECRET_CONST_SIZE         13
#define TLS_MD_KEY_EXPANSION_CONST              "key expansion"
#define TLS_MD_KEY_EXPANSION_CONST_SIZE         13

char *server;
int port;
char *ca_chain_file;
char *cert_file;
char *key_file;
char *path_segment;
static EVP_CIPHER_CTX cipher_ctx;  /* need to maintain across calls for MCT */

#define CHECK_ENABLE_CAP_RV(rv) \
    if (rv != ACVP_SUCCESS) { \
        printf("Failed to register capability with libacvp (rv=%d)\n", rv); \
        exit(1); \
    }


/*
 * Read the operational parameters from the various environment
 * variables.
 */
static void setup_session_parameters()
{
    char *tmp;

    server = getenv("ACV_SERVER");
    if (!server) server = DEFAULT_SERVER;

    tmp = getenv("ACV_PORT");
    if (tmp) port = atoi(tmp);
    if (!port) port = DEFAULT_PORT;

    path_segment = getenv("ACV_URI_PREFIX");
    if (!path_segment) path_segment = "";

    ca_chain_file = getenv("ACV_CA_FILE");
    if (!ca_chain_file) ca_chain_file = DEFAULT_CA_CHAIN;

    cert_file = getenv("ACV_CERT_FILE");
    if (!cert_file) cert_file = DEFAULT_CERT;

    key_file = getenv("ACV_KEY_FILE");
    if (!key_file) key_file = DEFAULT_KEY;

    printf("Using the following parameters:\n\n");
    printf("    ACV_SERVER:     %s\n", server);
    printf("    ACV_PORT:       %d\n", port);
    printf("    ACV_URI_PREFIX: %s\n", path_segment);
    printf("    ACV_CA_FILE:    %s\n", ca_chain_file);
    printf("    ACV_CERT_FILE:  %s\n", cert_file);
    printf("    ACV_KEY_FILE:   %s\n\n", key_file);
}

/*
 * This is a minimal and rudimentary logging handler.
 * libacvp calls this function to for debugs, warnings,
 * and errors.
 */
ACVP_RESULT progress(char *msg)
{
    printf("%s", msg);
    return ACVP_SUCCESS;
}

static void print_usage(void)
{
    printf("\nInvalid usage...\n");
    printf("acvp_app does not require any argument, however logging level can be\n");
    printf("controlled using:\n");
    printf("      -none\n");
    printf("      -error\n");
    printf("      -warn\n");
    printf("      -status(default)\n");
    printf("      -info\n");
    printf("      -verbose\n");
    printf("\n");
    printf("If you are running a sample registration (querying for correct answers\n");
    printf("in addition to the normal registration flow) use:\n");
    printf("      -sample\n");
    printf("\n");
    printf("In addition some options are passed to acvp_app using\n");
    printf("environment variables.  The following variables can be set:\n\n");
    printf("    ACV_SERVER (when not set, defaults to %s)\n", DEFAULT_SERVER);
    printf("    ACV_PORT (when not set, defaults to %d)\n", DEFAULT_PORT);
    printf("    ACV_URI_PREFIX (when not set, defaults to null)\n");
    printf("    ACV_CA_FILE (when not set, defaults to %s)\n", DEFAULT_CA_CHAIN);
    printf("    ACV_CERT_FILE (when not set, defaults to %s)\n", DEFAULT_CERT);
    printf("    ACV_KEY_FILE (when not set, defaults to %s)\n\n", DEFAULT_KEY);
    printf("The CA certificates, cert and key should be PEM encoded. There should be no\n");
    printf("password on the key file.\n");
}

int main(int argc, char **argv)
{
    ACVP_RESULT rv;
    ACVP_CTX *ctx;
    char ssl_version[10];
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;
    int sample = 0;
    
    int aes = 1;
    int tdes = 1;
    int hash = 1;
    int cmac = 1;
    int hmac = 1;
    int kdf = 0;
    int dsa = 0;
    /*
     * these require the fom, off by default
     */
    int rsa = 0;
    int drbg = 0;
    int ecdsa = 1;

    if (argc > 3) {
        print_usage();
        return 1;
    }

    argv++;
    argc--;
    while (argc >= 1) {
        if (strcmp(*argv, "-sample") == 0) {
            sample = 1;
        }
        if (strcmp(*argv, "-info") == 0) {
            level = ACVP_LOG_LVL_INFO;
        }
        if (strcmp(*argv, "-status") == 0) {
            level = ACVP_LOG_LVL_STATUS;
        }
        if (strcmp(*argv, "-warn") == 0) {
            level = ACVP_LOG_LVL_WARN;
        }
        if (strcmp(*argv, "-error") == 0) {
            level = ACVP_LOG_LVL_ERR;
        }
        if (strcmp(*argv, "-none") == 0) {
            level = ACVP_LOG_LVL_NONE;
        }
        if (strcmp(*argv, "-verbose") == 0) {
            level = ACVP_LOG_LVL_VERBOSE;
        }
        if (strcmp(*argv, "-help") == 0) {
            print_usage();
            return 1;
        }
    argv++;
    argc--;
    }

#ifdef ACVP_NO_RUNTIME
    fips_selftest_fail = 0;
    fips_mode = 0;
    fips_algtest_init_nofips();
#endif

    EVP_CIPHER_CTX_cleanup(&cipher_ctx);
    setup_session_parameters();

    /*
     * We begin the libacvp usage flow here.
     * First, we create a test session context.
     */
    rv = acvp_create_test_session(&ctx, &progress, level);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to create ACVP context\n");
        exit(1);
    }

    /*
     * Next we specify the ACVP server address
     */
    rv = acvp_set_server(ctx, server, port);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set server/port\n");
        exit(1);
    }

    /*
     * Setup the vendor attributes
     */
    rv = acvp_set_vendor_info(ctx, "Cisco Systems", "www.cisco.com", "Barry Fussell", "bfussell@cisco.com");
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set vendor info\n");
        exit(1);
    }

    /*
     * Setup the crypto module attributes
     */
    snprintf(ssl_version, 10, "%08x", (unsigned int)SSLeay());
    rv = acvp_set_module_info(ctx, "OpenSSL", "software", ssl_version, "FOM 6.2a");
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set module info\n");
        exit(1);
    }

    /*
     * Set the path segment prefix if needed
     */
     if (strnlen(path_segment, 255) > 0) {
        rv = acvp_set_path_segment(ctx, path_segment);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set URI prefix\n");
            exit(1);
        }
     }

    /*
     * Next we provide the CA certs to be used by libacvp
     * to verify the ACVP TLS certificate.
     */
    rv = acvp_set_cacerts(ctx, ca_chain_file);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set CA certs\n");
        exit(1);
    }

    /*
     * Specify the certificate and private key the client should used
     * for TLS client auth.
     */
    rv = acvp_set_certkey(ctx, cert_file, key_file);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set TLS cert/key\n");
        exit(1);
    }
    
    if (sample) {
        acvp_mark_as_sample(ctx);
    }

    /*
     * We need to register all the crypto module capabilities that will be
     * validated. Each has their own method for readability.
     */
    if (aes) {
        enable_aes(ctx);
    }

    if (tdes) {
        enable_tdes(ctx);
    }

    if (hash) {
        enable_hash(ctx);
    }

    if (cmac) {
        enable_cmac(ctx);
    }

    if (hmac) {
        enable_hmac(ctx);
    }

    if (kdf) {
        enable_kdf(ctx);
    }

    if (dsa) {
        enable_dsa(ctx);
    }

#ifdef ACVP_NO_RUNTIME
    if (rsa) {
        enable_rsa(ctx);
    }
    
    if (ecdsa) {
        enable_ecdsa(ctx);
    }

    if (drbg) {
        enable_drbg(ctx);
    }
#endif

    /*
     * Now that we have a test session, we register with
     * the server to advertise our capabilities and receive
     * the KAT vector sets the server demands that we process.
     */
    rv = acvp_register(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to register with ACVP server (rv=%d)\n", rv);
        exit(1);
    }

    /*
     * Now we process the test cases given to us during
     * registration earlier.
     */
    rv = acvp_process_tests(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to process vectors (%d)\n", rv);
        exit(1);
    }

    printf("\nTests complete, checking results...\n");
    rv = acvp_check_test_results(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Unable to retrieve test results (%d)\n", rv);
        exit(1);
    }
    /*
     * Finally, we free the test session context and cleanup
     */
    rv = acvp_free_test_session(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to free ACVP context\n");
        exit(1);
    }
    acvp_cleanup();
    
    return (0);
}

static void enable_aes (ACVP_CTX *ctx) {
    ACVP_RESULT rv;
    char value[] = "same";
    
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_AES_GCM, ACVP_DIR_BOTH, ACVP_KO_NA, ACVP_IVGEN_SRC_INT,
                                    ACVP_IVGEN_MODE_821, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_AES_GCM, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_AES_GCM, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_IVLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 136);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 136);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    
    /*
     * Enable AES-ECB 128,192,256 bit key
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_AES_ECB, ACVP_DIR_BOTH, ACVP_KO_NA, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PTLEN, 1536);
    CHECK_ENABLE_CAP_RV(rv);
    
    /*
     * Enable AES-CBC 128 bit key
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_AES_CBC, ACVP_DIR_BOTH, ACVP_KO_NA, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PTLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    
    /*
     * Enable AES-CFB8 128,192,256 bit key
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_AES_CFB8, ACVP_DIR_BOTH, ACVP_KO_NA, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PTLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    
    /*
     * Enable AES-CFB128 128,192,256 bit key
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_AES_CFB128, ACVP_DIR_BOTH, ACVP_KO_NA, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PTLEN, 1536);
    CHECK_ENABLE_CAP_RV(rv);
    
    /*
     * Enable AES-OFB 128, 192, 256 bit key
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_AES_OFB, ACVP_DIR_BOTH, ACVP_KO_NA, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PTLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    
    /*
     * Register AES CCM capabilities
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_AES_CCM, ACVP_DIR_BOTH, ACVP_KO_NA, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_AES_CCM, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PTLEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PTLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 56);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, 65536);
    CHECK_ENABLE_CAP_RV(rv);
    
    /*
     * Enable AES-CFB1 128,192,256 bit key
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_AES_CFB1, ACVP_DIR_BOTH, ACVP_KO_NA, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PTLEN, 1536);
    CHECK_ENABLE_CAP_RV(rv);

#if 0
    /*
     * Enable AES keywrap for various key sizes and PT lengths
     * Note: this is with padding disabled, minimum PT length is 128 bits and must be
     *       a multiple of 64 bits. openssl does not support INVERSE mode.
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_AES_KW, ACVP_DIR_BOTH, ACVP_KO_NA, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_aes_keywrap_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_value(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_AES_KWP, ACVP_DIR_BOTH, ACVP_KO_NA, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_aes_keywrap_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_value(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 808);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    
    /*
     * Enable AES-XTS 128 and 256 bit key
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_AES_XTS, ACVP_DIR_BOTH, ACVP_KO_NA, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PTLEN, 65536);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_TWEAK, ACVP_SYM_CIPH_TWEAK_HEX);
    CHECK_ENABLE_CAP_RV(rv);

#ifdef ACVP_V05
    /*
     * Enable AES-CTR 128, 192, 256 bit key
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_AES_CTR, ACVP_DIR_BOTH, ACVP_KO_NA, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PTLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
#endif
}

static void enable_tdes (ACVP_CTX *ctx) {
    ACVP_RESULT rv;
    
    /*
     * Enable 3DES-ECB
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_TDES_ECB, ACVP_DIR_BOTH, ACVP_KO_THREE, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PTLEN, 16 * 8 * 4);
    CHECK_ENABLE_CAP_RV(rv);
    
    /*
     * Enable 3DES-CBC
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_TDES_CBC, ACVP_DIR_BOTH, ACVP_KO_THREE, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_IVLEN, 192 / 3);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 3);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 12);
    CHECK_ENABLE_CAP_RV(rv);
    
    /*
     * Enable 3DES-OFB
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_TDES_OFB, ACVP_DIR_BOTH, ACVP_KO_THREE, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_IVLEN, 192 / 3);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PTLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    
    /*
     * Enable 3DES-CFB64
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_TDES_CFB64, ACVP_DIR_BOTH, ACVP_KO_THREE, ACVP_IVGEN_SRC_NA, ACVP_IVGEN_MODE_NA, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_IVLEN, 192/3);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PTLEN, 64 * 5);
    CHECK_ENABLE_CAP_RV(rv);
    
    /*
     * Enable 3DES-CFB8
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_TDES_CFB8, ACVP_DIR_BOTH, ACVP_KO_THREE, ACVP_IVGEN_SRC_NA, ACVP_IVGEN_MODE_NA, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_IVLEN, 192/3);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PTLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PTLEN, 64 * 4);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable 3DES-CFB1
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_TDES_CFB1, ACVP_DIR_BOTH, ACVP_KO_THREE, ACVP_IVGEN_SRC_NA, ACVP_IVGEN_MODE_NA, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_IVLEN, 192/3);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PTLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
#ifdef ACVP_V05
    /*
     * Enable TDES-CTR 
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_TDES_CTR, ACVP_DIR_BOTH, ACVP_KO_THREE, ACVP_IVGEN_SRC_NA,
                                    ACVP_IVGEN_MODE_NA, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PTLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
#endif
}

static void enable_hash (ACVP_CTX *ctx) {
    ACVP_RESULT rv;
    
    /*
     * Enable SHA-1 and SHA-2
     */
    rv = acvp_enable_hash_cap(ctx, ACVP_SHA1, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA1, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA1, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_enable_hash_cap(ctx, ACVP_SHA224, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA224, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA224, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_enable_hash_cap(ctx, ACVP_SHA256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA256, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA256, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_enable_hash_cap(ctx, ACVP_SHA384, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA384, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA384, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_enable_hash_cap(ctx, ACVP_SHA512, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA512, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA512, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
}

static void enable_cmac (ACVP_CTX *ctx) {
    ACVP_RESULT rv;
    char value[] = "same";
    
    /*
     * Enable CMAC
     */
    rv = acvp_enable_cmac_cap(ctx, ACVP_CMAC_AES, &app_cmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_cmac_cap_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_BLK_DIVISIBLE_1, 1024);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_cmac_cap_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_BLK_NOT_DIVISIBLE_1, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_cmac_cap_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_MACLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_cmac_cap_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_cmac_cap_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_GEN, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_cmac_cap_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_VER, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_CMAC_AES, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_cmac_cap(ctx, ACVP_CMAC_TDES, &app_cmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_cmac_cap_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_BLK_DIVISIBLE_1, 1024);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_cmac_cap_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_BLK_NOT_DIVISIBLE_1, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_cmac_cap_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_MACLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_cmac_cap_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_KEYING_OPTION, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_cmac_cap_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_DIRECTION_GEN, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_cmac_cap_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_DIRECTION_VER, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_CMAC_TDES, ACVP_PREREQ_TDES, value);
    CHECK_ENABLE_CAP_RV(rv);
}

static void enable_hmac (ACVP_CTX *ctx) {
    ACVP_RESULT rv;
    char value[] = "same";
    
    /*
     * Enable HMAC: TODO - need to add increment value in bits, default to 64 now.
     */
    rv = acvp_enable_hmac_cap(ctx, ACVP_HMAC_SHA1, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_KEYLEN_MIN, 32 * 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_KEYLEN_MAX, 56 * 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_MACLEN, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_HMAC_SHA1, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_enable_hmac_cap(ctx, ACVP_HMAC_SHA2_224, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_KEYLEN_MIN, 32 * 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_KEYLEN_MAX, 56 * 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_MACLEN, 224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_HMAC_SHA2_224, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_enable_hmac_cap(ctx, ACVP_HMAC_SHA2_256, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_KEYLEN_MIN, 32 * 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_KEYLEN_MAX, 56 * 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_MACLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_HMAC_SHA2_256, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_enable_hmac_cap(ctx, ACVP_HMAC_SHA2_384, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_KEYLEN_MIN, 32 * 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_KEYLEN_MAX, 56 * 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_MACLEN, 384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_HMAC_SHA2_384, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_enable_hmac_cap(ctx, ACVP_HMAC_SHA2_512, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN_MIN, 32 * 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN_MAX, 56 * 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_hmac_cap_parm(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_MACLEN, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_HMAC_SHA2_512, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
}

static void enable_kdf (ACVP_CTX *ctx) {
#ifdef OPENSSL_KDF_SUPPORT
    ACVP_RESULT rv;
    /*
     * Enable KDF-135
     */
    rv = acvp_enable_kdf135_tls_cap(ctx, ACVP_KDF135_TLS, &app_kdf135_tls_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_KDF135_TLS, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_KDF135_TLS, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_kdf135_tls_cap_parm(ctx, ACVP_KDF135_TLS, ACVP_KDF135_TLS12, ACVP_KDF135_TLS_CAP_SHA256 | ACVP_KDF135_TLS_CAP_SHA384 | ACVP_KDF135_TLS_CAP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_kdf135_snmp_cap(ctx, &app_kdf135_snmp_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_KDF135_SNMP, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_kdf135_ssh_cap(ctx, &app_kdf135_ssh_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_kdf135_ssh_cap_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, ACVP_KDF135_SSH_CAP_SHA256 | ACVP_KDF135_SSH_CAP_SHA384 | ACVP_KDF135_SSH_CAP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_kdf135_ssh_cap_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, ACVP_KDF135_SSH_CAP_SHA256 | ACVP_KDF135_SSH_CAP_SHA384 | ACVP_KDF135_SSH_CAP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_kdf135_ssh_cap_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, ACVP_KDF135_SSH_CAP_SHA256 | ACVP_KDF135_SSH_CAP_SHA384 | ACVP_KDF135_SSH_CAP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_kdf135_ssh_cap_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, ACVP_KDF135_SSH_CAP_SHA256 | ACVP_KDF135_SSH_CAP_SHA384 | ACVP_KDF135_SSH_CAP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
#endif
}

static void enable_dsa (ACVP_CTX *ctx) {
#if 0 /* until DSA is supported on the server side */
    ACVP_RESULT rv;

    /*
     * Enable DSA....
     */
    rv = acvp_enable_dsa_cap(ctx, ACVP_DSA, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_DSA, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_DSA, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_dsa_cap_parm(ctx, ACVP_DSA, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENPQ, ACVP_DSA_PROBABLE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_dsa_cap_parm(ctx, ACVP_DSA, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENPQ, ACVP_DSA_PROVABLE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_dsa_cap_parm(ctx, ACVP_DSA, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENG, ACVP_DSA_UNVERIFIABLE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_dsa_cap_parm(ctx, ACVP_DSA, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENG, ACVP_DSA_CANONICAL);
    CHECK_ENABLE_CAP_RV(rv);


    rv = acvp_enable_dsa_cap_parm(ctx, ACVP_DSA, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_DSA_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_dsa_cap_parm(ctx, ACVP_DSA, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_DSA_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_dsa_cap_parm(ctx, ACVP_DSA, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_DSA_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_dsa_cap_parm(ctx, ACVP_DSA, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_DSA_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_dsa_cap_parm(ctx, ACVP_DSA, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_256, ACVP_DSA_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_dsa_cap_parm(ctx, ACVP_DSA, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN3072_256, ACVP_DSA_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
#endif
}

#ifdef ACVP_NO_RUNTIME
static void enable_rsa (ACVP_CTX *ctx) {
    ACVP_RESULT rv;
    char value[] = "same";
    BIGNUM *expo;
    
    expo = FIPS_bn_new();
    if (!expo || !BN_set_word(expo, 0x10001)) {
        printf("oh no\n");
        exit(1);
    }

    /*
     * Enable RSA keygen...
     */
    rv = acvp_enable_rsa_keygen_cap(ctx, ACVP_RSA_KEYGEN, &app_rsa_keygen_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_keygen_cap_parm(ctx, ACVP_PUB_EXP_MODE, RSA_PUB_EXP_FIXED);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_keygen_cap_parm(ctx, ACVP_RSA_INFO_GEN_BY_SERVER, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_keygen_cap_parm(ctx, ACVP_KEY_FORMAT_CRT, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_rsa_keygen_exp_parm(ctx, ACVP_FIXED_PUB_EXP_VAL, BN_bn2hex(expo));
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_enable_rsa_keygen_mode(ctx, ACVP_RSA_KEYGEN_B34);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_keygen_primes_parm(ctx, ACVP_RSA_KEYGEN_B34, 2048, ACVP_STR_SHA2_256);
    CHECK_ENABLE_CAP_RV(rv);
    // TODO: leaving this in here as a workaround until the server allows it as optional
    rv = acvp_enable_rsa_keygen_primes_parm(ctx, ACVP_RSA_KEYGEN_B34, 2048, PRIME_TEST_TBLC2_NAME);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_keygen_primes_parm(ctx, ACVP_RSA_KEYGEN_B34, 3072, ACVP_STR_SHA2_256);
    CHECK_ENABLE_CAP_RV(rv);
    // TODO: leaving this in here as a workaround until the server allows it as optional
    rv = acvp_enable_rsa_keygen_primes_parm(ctx, ACVP_RSA_KEYGEN_B34, 3072, PRIME_TEST_TBLC2_NAME);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable siggen
     */
    rv = acvp_enable_rsa_siggen_cap(ctx, ACVP_RSA_SIGGEN, &app_rsa_sig_handler);
    CHECK_ENABLE_CAP_RV(rv);
    
    // RSA w/ sigType: X9.31
    rv = acvp_enable_rsa_siggen_type(ctx, RSA_SIG_TYPE_X931);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_X931, 2048, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_X931, 2048, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_X931, 2048, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_X931, 3072, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_X931, 3072, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_X931, 3072, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 // mod 4096 isn't supported by the server just yet
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_X931, 4096, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_X931, 4096, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_X931, 4096, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    // RSA w/ sigType: PKCS1v1.5
    rv = acvp_enable_rsa_siggen_type(ctx, RSA_SIG_TYPE_PKCS1V15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_STR_SHA_1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_STR_SHA2_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_STR_SHA_1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_STR_SHA2_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 // mod 4096 isn't supported by the server just yet
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_STR_SHA_1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_STR_SHA2_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = acvp_enable_rsa_siggen_type(ctx, RSA_SIG_TYPE_PKCS1PSS);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_STR_SHA_1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_STR_SHA2_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_STR_SHA_1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_STR_SHA2_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_siggen_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable sigver
     */
    rv = acvp_enable_rsa_sigver_cap(ctx, ACVP_RSA_SIGVER, &app_rsa_sig_handler);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_enable_rsa_sigver_cap_parm(ctx, ACVP_PUB_EXP_MODE, RSA_PUB_EXP_FIXED);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_exp_parm(ctx, ACVP_FIXED_PUB_EXP_VAL, BN_bn2hex(expo));
    CHECK_ENABLE_CAP_RV(rv);
    
    // RSA w/ sigType: X9.31
    rv = acvp_enable_rsa_sigver_type(ctx, RSA_SIG_TYPE_X931);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_X931, 2048, ACVP_STR_SHA_1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_X931, 2048, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_X931, 2048, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_X931, 2048, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_X931, 3072, ACVP_STR_SHA_1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_X931, 3072, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_X931, 3072, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_X931, 3072, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1v1.5
    rv = acvp_enable_rsa_sigver_type(ctx, RSA_SIG_TYPE_PKCS1V15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_STR_SHA_1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_STR_SHA2_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_STR_SHA_1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_STR_SHA2_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    
    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = acvp_enable_rsa_sigver_type(ctx, RSA_SIG_TYPE_PKCS1PSS);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_STR_SHA_1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_STR_SHA2_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_STR_SHA_1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_STR_SHA2_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_STR_SHA2_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_STR_SHA2_384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_rsa_sigver_caps_parm(ctx, RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_STR_SHA2_512, 0);
    CHECK_ENABLE_CAP_RV(rv);
}

static void enable_ecdsa (ACVP_CTX *ctx) {
    ACVP_RESULT rv;
    char value[] = "same";

    /*
     * Enable ECDSA keyGen...
     */
    rv = acvp_enable_ecdsa_cap(ctx, ACVP_ECDSA_KEYGEN, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_ecdsa_cap_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_CURVE, "k-409");
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_ecdsa_cap_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_CURVE, "p-521");
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_ecdsa_cap_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_SECRET_GEN_MODE, "extra bits");
    CHECK_ENABLE_CAP_RV(rv);
    
    /*
     * Enable ECDSA keyVer...
     */
    rv = acvp_enable_ecdsa_cap(ctx, ACVP_ECDSA_KEYVER, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_ecdsa_cap_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_CURVE, "k-163");
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_ecdsa_cap_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_CURVE, "b-163");
    CHECK_ENABLE_CAP_RV(rv);

#if 0 // for now while hashAlg parsing error persists
    /*
     * Enable ECDSA sigGen...
     */
    rv = acvp_enable_ecdsa_cap(ctx, ACVP_ECDSA_SIGGEN, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_ecdsa_cap_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_CURVE, "k-409");
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_ecdsa_cap_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_CURVE, "p-521");
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_ecdsa_cap_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_HASH_ALG, "SHA2-224");
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable ECDSA sigVer...
     */
    rv = acvp_enable_ecdsa_cap(ctx, ACVP_ECDSA_SIGVER, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_prereq_cap(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_ecdsa_cap_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_CURVE, "k-163");
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_ecdsa_cap_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_CURVE, "b-163");
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_ecdsa_cap_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_HASH_ALG, "SHA2-224");
    CHECK_ENABLE_CAP_RV(rv);
#endif
}

static void enable_drbg (ACVP_CTX *ctx) {
    ACVP_RESULT rv;

    /*
     * Register DRBG
     */
      ERR_load_crypto_strings() ;

      int fips_rc = FIPS_mode_set(1);
      if(!fips_rc) {
          (printf("Failed to enable FIPS mode.\n"));
          exit(1);
      }

    char value[] = "same";
    char value2[] = "123456";
    
#if 0 /* only CTR mode is supported by the server currently */
    rv = acvp_enable_drbg_cap(ctx, ACVP_HASHDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                    ACVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_prereq_cap(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
            ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_drbg_prereq_cap(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
            ACVP_PREREQ_AES, value2);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
            ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
            ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
            ACVP_DRBG_ENTROPY_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
            ACVP_DRBG_NONCE_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
            ACVP_DRBG_PERSO_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
            ACVP_DRBG_ADD_IN_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
            ACVP_DRBG_RET_BITS_LEN, 512);
    CHECK_ENABLE_CAP_RV(rv);


    //ACVP_HMACDRBG

    rv = acvp_enable_drbg_cap(ctx, ACVP_HMACDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                    ACVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_prereq_cap(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_drbg_prereq_cap(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_PREREQ_AES, value2);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_DRBG_ENTROPY_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_DRBG_NONCE_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_DRBG_PERSO_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_DRBG_ADD_IN_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_DRBG_RET_BITS_LEN, 512);
    CHECK_ENABLE_CAP_RV(rv);

    //Add length range
    rv = acvp_enable_drbg_length_cap(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_DRBG_ENTROPY_LEN, (int)0, (int)128,(int) 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_length_cap(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_DRBG_NONCE_LEN, (int)0, (int)128,(int) 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_length_cap(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_length_cap(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_length_cap(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
            ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    CHECK_ENABLE_CAP_RV(rv);

    // ACVP_CTRDRBG
    rv = acvp_enable_drbg_cap(ctx, ACVP_CTRDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);

    //Add length range
    rv = acvp_enable_drbg_length_cap(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_DRBG_ENTROPY_LEN, (int)0, (int)128,(int) 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_length_cap(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_DRBG_NONCE_LEN, (int)0, (int)128,(int) 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_length_cap(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_length_cap(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_length_cap(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                    ACVP_DRBG_DER_FUNC_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_prereq_cap(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_drbg_prereq_cap(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_PREREQ_AES, value2);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_DRBG_ENTROPY_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_DRBG_NONCE_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_DRBG_PERSO_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_DRBG_ADD_IN_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_enable_drbg_cap_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
            ACVP_DRBG_RET_BITS_LEN, 512);
    CHECK_ENABLE_CAP_RV(rv);
#endif

}
#endif

static ACVP_RESULT app_des_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_SYM_CIPHER_TC      *tc;
    const EVP_CIPHER        *cipher;
    int ct_len, pt_len;
    unsigned char *iv = 0;

    if (!test_case) {
        return ACVP_INVALID_ARG;
    }

    tc = test_case->tc.symmetric;

    /*
     * We only support 3 key DES
     */
    if (tc->key_len != 192) {
        printf("Unsupported DES key length\n");
        return ACVP_NO_CAP;
    }

    /* Begin encrypt code section */
    if (cipher_ctx.cipher == NULL) {
        EVP_CIPHER_CTX_init(&cipher_ctx);
    }

    switch (tc->cipher) {
    case ACVP_TDES_ECB:
        cipher = EVP_des_ede3_ecb();
        break;
    case ACVP_TDES_CBC:
        iv = tc->iv;
        cipher = EVP_des_ede3_cbc();
        break;
    case ACVP_TDES_OFB:
        iv = tc->iv;
        cipher = EVP_des_ede3_ofb();
        break;
    case ACVP_TDES_CFB64:
        iv = tc->iv;
        cipher = EVP_des_ede3_cfb64();
        break;
    case ACVP_TDES_CFB8:
        iv = tc->iv;
        cipher = EVP_des_ede3_cfb8();
        break;
    case ACVP_TDES_CFB1:
        iv = tc->iv;
        cipher = EVP_des_ede3_cfb1();
        break;
    case ACVP_TDES_CTR:
        /*
         * IMPORTANT: if this mode is supported in your crypto module,
         * you will need to fill that out here. It is set to fall
         * through as an unsupported mode.
         */
    default:
        printf("Error: Unsupported DES mode requested by ACVP server\n");
        return ACVP_NO_CAP;
        break;
    }

    /* If Monte Carlo we need to be able to init and then update
     * one thousand times before we complete each iteration.
     */
    if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT) {
        if (tc->direction == ACVP_DIR_ENCRYPT) {
            if (tc->mct_index == 0) {
                EVP_EncryptInit_ex(&cipher_ctx, cipher, NULL, tc->key, iv);
            EVP_CIPHER_CTX_set_padding(&cipher_ctx, 0);
            } else {
                /* TDES needs the pre-operation IV returned */
                memcpy(tc->iv_ret, cipher_ctx.iv, 8);
            }
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }

            EVP_EncryptUpdate(&cipher_ctx, tc->ct, &ct_len, tc->pt, tc->pt_len);
            tc->ct_len = ct_len;
            /* TDES needs the post-operation IV returned */
            memcpy(tc->iv_ret_after, cipher_ctx.iv, 8);
        } else if (tc->direction == ACVP_DIR_DECRYPT) {
            if (tc->mct_index == 0) {
                EVP_DecryptInit_ex(&cipher_ctx, cipher, NULL, tc->key, iv);
            EVP_CIPHER_CTX_set_padding(&cipher_ctx, 0);
            } else {
                /* TDES needs the pre-operation IV returned */
                memcpy(tc->iv_ret, cipher_ctx.iv, 8);
            }
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }
            EVP_DecryptUpdate(&cipher_ctx, tc->pt, &pt_len, tc->ct, tc->ct_len);
            tc->pt_len = pt_len;
            /* TDES needs the post-operation IV returned */
            memcpy(tc->iv_ret_after, cipher_ctx.iv, 8);
        } else {
            printf("Unsupported direction\n");
            return ACVP_UNSUPPORTED_OP;
        }
        if (tc->mct_index == 9999) {
            EVP_CIPHER_CTX_cleanup(&cipher_ctx);
        }
    } else {
        if (tc->direction == ACVP_DIR_ENCRYPT) {
            EVP_EncryptInit_ex(&cipher_ctx, cipher, NULL, tc->key, iv);
            EVP_CIPHER_CTX_set_padding(&cipher_ctx, 0);
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }
            EVP_EncryptUpdate(&cipher_ctx, tc->ct, &ct_len, tc->pt, tc->pt_len);
            tc->ct_len = ct_len;
            EVP_EncryptFinal_ex(&cipher_ctx, tc->ct + ct_len, &ct_len);
            tc->ct_len += ct_len;
        } else if (tc->direction == ACVP_DIR_DECRYPT) {
            EVP_DecryptInit_ex(&cipher_ctx, cipher, NULL, tc->key, iv);
            EVP_CIPHER_CTX_set_padding(&cipher_ctx, 0);
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }
            EVP_DecryptUpdate(&cipher_ctx, tc->pt, &pt_len, tc->ct, tc->ct_len);
            tc->pt_len = pt_len;
            EVP_DecryptFinal_ex(&cipher_ctx, tc->pt + pt_len, &pt_len);
            tc->pt_len += pt_len;
        } else {
            printf("Unsupported direction\n");
            return ACVP_UNSUPPORTED_OP;
        }

        EVP_CIPHER_CTX_cleanup(&cipher_ctx);
    }

    return ACVP_SUCCESS;
}


static ACVP_RESULT app_aes_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_SYM_CIPHER_TC      *tc;
    const EVP_CIPHER        *cipher;
    int ct_len, pt_len;
    unsigned char *iv = 0;

    if (!test_case) {
        return ACVP_INVALID_ARG;
    }

    tc = test_case->tc.symmetric;

    /* Begin encrypt code section */
    if ((cipher_ctx.cipher == NULL) || (tc->test_type != ACVP_SYM_TEST_TYPE_MCT)) {
  EVP_CIPHER_CTX_init(&cipher_ctx);
    }

    switch (tc->cipher) {
    case ACVP_AES_ECB:
  switch (tc->key_len) {
  case 128:
      cipher = EVP_aes_128_ecb();
      break;
  case 192:
      cipher = EVP_aes_192_ecb();
      break;
  case 256:
      cipher = EVP_aes_256_ecb();
      break;
  default:
      printf("Unsupported AES key length\n");
      return ACVP_NO_CAP;
      break;
  }
  break;
    case ACVP_AES_CTR:
  iv = tc->iv;
  switch (tc->key_len) {
  case 128:
      cipher = EVP_aes_128_ctr();
      break;
  case 192:
      cipher = EVP_aes_192_ctr();
      break;
  case 256:
      cipher = EVP_aes_256_ctr();
      break;
  default:
      printf("Unsupported AES key length\n");
      return ACVP_NO_CAP;
      break;
  }
  break;
    case ACVP_AES_CFB1:
  iv = tc->iv;
  switch (tc->key_len) {
  case 128:
      cipher = EVP_aes_128_cfb1();
      break;
  case 192:
      cipher = EVP_aes_192_cfb1();
      break;
  case 256:
      cipher = EVP_aes_256_cfb1();
      break;
  default:
      printf("Unsupported AES key length\n");
      return ACVP_NO_CAP;
      break;
  }
  break;
    case ACVP_AES_CFB8:
  iv = tc->iv;
  switch (tc->key_len) {
  case 128:
      cipher = EVP_aes_128_cfb8();
      break;
  case 192:
      cipher = EVP_aes_192_cfb8();
      break;
  case 256:
      cipher = EVP_aes_256_cfb8();
      break;
  default:
      printf("Unsupported AES key length\n");
      return ACVP_NO_CAP;
      break;
  }
  break;
    case ACVP_AES_CFB128:
  iv = tc->iv;
  switch (tc->key_len) {
  case 128:
      cipher = EVP_aes_128_cfb128();
      break;
  case 192:
      cipher = EVP_aes_192_cfb128();
      break;
  case 256:
      cipher = EVP_aes_256_cfb128();
      break;
  default:
      printf("Unsupported AES key length\n");
      return ACVP_NO_CAP;
      break;
  }
  break;
    case ACVP_AES_OFB:
  iv = tc->iv;
  switch (tc->key_len) {
  case 128:
      cipher = EVP_aes_128_ofb();
      break;
  case 192:
      cipher = EVP_aes_192_ofb();
      break;
  case 256:
      cipher = EVP_aes_256_ofb();
      break;
  default:
      printf("Unsupported AES key length\n");
      return ACVP_NO_CAP;
      break;
  }
  break;
    case ACVP_AES_CBC:
  iv = tc->iv;
  switch (tc->key_len) {
  case 128:
      cipher = EVP_aes_128_cbc();
      break;
  case 192:
      cipher = EVP_aes_192_cbc();
      break;
  case 256:
      cipher = EVP_aes_256_cbc();
      break;
  default:
      printf("Unsupported AES key length\n");
      return ACVP_NO_CAP;
      break;
  }
  break;
    case ACVP_AES_XTS:
        iv = tc->iv;
        switch (tc->key_len) {
        case 128:
            cipher = EVP_aes_128_xts();
            break;
        case 256:
            cipher = EVP_aes_256_xts();
            break;
        default:
            printf("Unsupported AES key length\n");
            return ACVP_NO_CAP;
            break;
        }
        break;
  break;
    default:
  printf("Error: Unsupported AES mode requested by ACVP server\n");
  return ACVP_NO_CAP;
  break;
    }

    /* If Monte Carlo we need to be able to init and then update
     * one thousand times before we complete each iteration.
     */
    if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT) {
        if (tc->direction == ACVP_DIR_ENCRYPT) {
            if (tc->mct_index == 0) {
          EVP_EncryptInit_ex(&cipher_ctx, cipher, NULL, tc->key, iv);
  EVP_CIPHER_CTX_set_padding(&cipher_ctx, 0);
     if (tc->cipher == ACVP_AES_CFB1) {
           EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
     }
            }
      EVP_EncryptUpdate(&cipher_ctx, tc->ct, &ct_len, tc->pt, tc->pt_len);
      tc->ct_len = ct_len;
        } else if (tc->direction == ACVP_DIR_DECRYPT) {
            if (tc->mct_index == 0) {
          EVP_DecryptInit_ex(&cipher_ctx, cipher, NULL, tc->key, iv);
          EVP_CIPHER_CTX_set_padding(&cipher_ctx, 0);
     if (tc->cipher == ACVP_AES_CFB1) {
           EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
     }
            }
      EVP_DecryptUpdate(&cipher_ctx, tc->pt, &pt_len, tc->ct, tc->ct_len);
      tc->pt_len = pt_len;
        } else {
            printf("Unsupported direction\n");
      return ACVP_UNSUPPORTED_OP;
        }
        if (tc->mct_index == 999) {
            EVP_CIPHER_CTX_cleanup(&cipher_ctx);
        }

    } else {
        if (tc->direction == ACVP_DIR_ENCRYPT) {
      EVP_EncryptInit_ex(&cipher_ctx, cipher, NULL, tc->key, iv);
           EVP_CIPHER_CTX_set_padding(&cipher_ctx, 0);
     if (tc->cipher == ACVP_AES_CFB1) {
           EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
     }
      EVP_EncryptUpdate(&cipher_ctx, tc->ct, &ct_len, tc->pt, tc->pt_len);
      tc->ct_len = ct_len;
      EVP_EncryptFinal_ex(&cipher_ctx, tc->ct + ct_len, &ct_len);
      tc->ct_len += ct_len;
        } else if (tc->direction == ACVP_DIR_DECRYPT) {
      EVP_DecryptInit_ex(&cipher_ctx, cipher, NULL, tc->key, iv);
      EVP_CIPHER_CTX_set_padding(&cipher_ctx, 0);
     if (tc->cipher == ACVP_AES_CFB1) {
           EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
     }
      EVP_DecryptUpdate(&cipher_ctx, tc->pt, &pt_len, tc->ct, tc->ct_len);
      tc->pt_len = pt_len;
      EVP_DecryptFinal_ex(&cipher_ctx, tc->pt + pt_len, &pt_len);
      tc->pt_len += pt_len;
        } else {
            printf("Unsupported direction\n");
      return ACVP_UNSUPPORTED_OP;
       }
       EVP_CIPHER_CTX_cleanup(&cipher_ctx);
    }

    return ACVP_SUCCESS;
}

/* TODO - openssl does not support inverse option */
#if 0
static ACVP_RESULT app_aes_keywrap_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_SYM_CIPHER_TC      *tc;
    EVP_CIPHER_CTX          cipher_ctx;
    const EVP_CIPHER        *cipher;
    int                     c_len;

    if (!test_case) {
        return ACVP_INVALID_ARG;
    }

    tc = test_case->tc.symmetric;

    if (tc->kwcipher != ACVP_SYM_KW_CIPHER) {
        return ACVP_INVALID_ARG;
    }

    /* Begin encrypt code section */
    EVP_CIPHER_CTX_init(&cipher_ctx);

    switch (tc->cipher) {
    case ACVP_AES_KW:
    case ACVP_AES_KWP:
        switch (tc->key_len) {
        case 128:
            cipher = EVP_aes_128_wrap();
            break;
        case 192:
            cipher = EVP_aes_192_wrap();
            break;
        case 256:
            cipher = EVP_aes_256_wrap();
            break;
        default:
            printf("Unsupported AES keywrap key length\n");
            return ACVP_NO_CAP;
            break;
        }
        break;
    default:
        printf("Error: Unsupported AES keywrap mode requested by ACVP server\n");
        return ACVP_NO_CAP;
        break;
    }


    if (tc->direction == ACVP_DIR_ENCRYPT) {
        EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        EVP_CipherInit_ex(&cipher_ctx, cipher, NULL, tc->key, NULL, 1);
        c_len = EVP_Cipher(&cipher_ctx, tc->ct, tc->pt, tc->pt_len);
        if (c_len <= 0) {
            printf("Error: key wrap operation failed (%d)\n", c_len);
            return ACVP_CRYPTO_MODULE_FAIL;
        } else {
            tc->ct_len = c_len;
        }
    } else if (tc->direction == ACVP_DIR_DECRYPT) {
        EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        EVP_CipherInit_ex(&cipher_ctx, cipher, NULL, tc->key, NULL, 0);

        if (tc->cipher == ACVP_AES_KWP) {
            EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPHER_CTX_FLAG_UNWRAP_WITHPAD);
        }
        c_len = EVP_Cipher(&cipher_ctx, tc->pt, tc->ct, tc->ct_len);
        if (c_len <= 0) {
            return ACVP_CRYPTO_WRAP_FAIL;
        } else {
            tc->pt_len = c_len;
        }
    } else {
        printf("Unsupported direction\n");
        return ACVP_UNSUPPORTED_OP;
    }

    EVP_CIPHER_CTX_cleanup(&cipher_ctx);
    return ACVP_SUCCESS;
}

/* TODO: I don't believe that openssl's 3DES keywrap is FIPS compliant */
static ACVP_RESULT app_des_keywrap_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_SYM_CIPHER_TC      *tc;
    EVP_CIPHER_CTX cipher_ctx;
    const EVP_CIPHER        *cipher;
    int c_len;

    if (!test_case) {
        return ACVP_INVALID_ARG;
    }

    tc = test_case->tc.symmetric;

    /* Begin encrypt code section */
    EVP_CIPHER_CTX_init(&cipher_ctx);

    cipher = EVP_des_ede3_wrap();

    if (tc->direction == ACVP_DIR_ENCRYPT) {
        EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        EVP_CipherInit_ex(&cipher_ctx, cipher, NULL, tc->key, NULL, 1);
        c_len = EVP_Cipher(&cipher_ctx, tc->ct, tc->pt, tc->pt_len);
        if (c_len <= 0) {
            printf("Error: key wrap operation failed (%d)\n", c_len);
            return ACVP_CRYPTO_MODULE_FAIL;
        } else {
            tc->ct_len = c_len;
        }
    } else if (tc->direction == ACVP_DIR_DECRYPT) {
        EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        EVP_CipherInit_ex(&cipher_ctx, cipher, NULL, tc->key, NULL, 0);
        c_len = EVP_Cipher(&cipher_ctx, tc->pt, tc->ct, tc->ct_len);
        if (c_len <= 0) {
            return ACVP_CRYPTO_WRAP_FAIL;
        } else {
            tc->pt_len = c_len;
        }
    } else {
        printf("Unsupported direction\n");
        return ACVP_UNSUPPORTED_OP;
    }

    EVP_CIPHER_CTX_cleanup(&cipher_ctx);

    return ACVP_SUCCESS;
}
#endif

/*
 * This fuction is invoked by libacvp when an AES crypto
 * operation is needed from the crypto module being
 * validated.  This is a callback provided to libacvp when
 * acvp_enable_capability() is invoked to register the
 * AES-GCM capabilitiy with libacvp.  libacvp will in turn
 * invoke this function when it needs to process an AES-GCM
 * test case.
 */
//TODO: I have mixed feelings on returing ACVP_RESULT.  This is
//      application layer code outside of libacvp.  Should we
//      return a simple pass/fail?  Should we provide a separate
//      enum that applications can use?
static ACVP_RESULT app_aes_handler_aead(ACVP_TEST_CASE *test_case)
{
    ACVP_SYM_CIPHER_TC      *tc;
    EVP_CIPHER_CTX cipher_ctx;
    const EVP_CIPHER        *cipher;
    unsigned char iv_fixed[4] = {1,2,3,4};
    int rv;

    if (!test_case) {
        return ACVP_INVALID_ARG;
    }

    tc = test_case->tc.symmetric;

    if (tc->direction != ACVP_DIR_ENCRYPT && tc->direction != ACVP_DIR_DECRYPT) {
        printf("Unsupported direction\n");
        return ACVP_UNSUPPORTED_OP;
    }

    /* Begin encrypt code section */
    EVP_CIPHER_CTX_init(&cipher_ctx);

    /* Validate key length and assign OpenSSL EVP cipher */
    switch (tc->cipher) {
    case ACVP_AES_GCM:
        switch (tc->key_len) {
        case 128:
            cipher = EVP_aes_128_gcm();
            break;
        case 192:
            cipher = EVP_aes_192_gcm();
            break;
        case 256:
            cipher = EVP_aes_256_gcm();
            break;
        default:
            printf("Unsupported AES-GCM key length\n");
            EVP_CIPHER_CTX_cleanup(&cipher_ctx);
            return ACVP_UNSUPPORTED_OP;
        }
        if (tc->direction == ACVP_DIR_ENCRYPT) {
            EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPH_FLAG_NON_FIPS_ALLOW);
            EVP_CipherInit(&cipher_ctx, cipher, NULL, NULL, 1);
            EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, tc->iv_len, 0);
            EVP_CipherInit(&cipher_ctx, NULL, tc->key, NULL, 1);

            EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_SET_IV_FIXED, 4, iv_fixed);
            if (!EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_IV_GEN, tc->iv_len, tc->iv)) {
                printf("acvp_aes_encrypt: iv gen error\n");
                EVP_CIPHER_CTX_cleanup(&cipher_ctx);
                return ACVP_CRYPTO_MODULE_FAIL;
            }
            if (tc->aad_len) {
                EVP_Cipher(&cipher_ctx, NULL, tc->aad, tc->aad_len);
            }
            EVP_Cipher(&cipher_ctx, tc->ct, tc->pt, tc->pt_len);
            EVP_Cipher(&cipher_ctx, NULL, NULL, 0);
            EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_GET_TAG, tc->tag_len, tc->tag);
        } else if (tc->direction == ACVP_DIR_DECRYPT) {
            EVP_CIPHER_CTX_set_flags(&cipher_ctx, EVP_CIPH_FLAG_NON_FIPS_ALLOW);
            EVP_CipherInit_ex(&cipher_ctx, cipher, NULL, tc->key, NULL, 0);
            EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, tc->iv_len, 0);
            EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_SET_IV_FIXED, -1, tc->iv);
            if(!EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_IV_GEN, tc->iv_len, tc->iv)) {
                printf("\nFailed to set IV");
                EVP_CIPHER_CTX_cleanup(&cipher_ctx);
                return ACVP_CRYPTO_MODULE_FAIL;
            }
            if (tc->aad_len) {
                /*
                 * Set dummy tag before processing AAD.  Otherwise the AAD can
                 * not be processed.
                 */
                EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_SET_TAG, tc->tag_len, tc->tag);
                EVP_Cipher(&cipher_ctx, NULL, tc->aad, tc->aad_len);
            }
            /*
             * Set the tag when decrypting
             */
            EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_SET_TAG, tc->tag_len, tc->tag);

            /*
             * Decrypt the CT
             */
            EVP_Cipher(&cipher_ctx, tc->pt, tc->ct, tc->pt_len);
            /*
             * Check the tag
             */
            rv = EVP_Cipher(&cipher_ctx, NULL, NULL, 0);
            if (rv) {
                EVP_CIPHER_CTX_cleanup(&cipher_ctx);
                return ACVP_CRYPTO_TAG_FAIL;
            }
        }
        break;
    case ACVP_AES_CCM:
        switch (tc->key_len) {
        case 128:
          cipher = EVP_aes_128_ccm();
          break;
        case 192:
          cipher = EVP_aes_192_ccm();
          break;
        case 256:
          cipher = EVP_aes_256_ccm();
          break;
        default:
            printf("Unsupported AES-CCM key length\n");
            EVP_CIPHER_CTX_cleanup(&cipher_ctx);
            return ACVP_UNSUPPORTED_OP;
        }
        if (tc->direction == ACVP_DIR_ENCRYPT) {
            EVP_CipherInit(&cipher_ctx, cipher, NULL, NULL, 1);
            EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_CCM_SET_IVLEN, tc->iv_len, 0);
            EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_CCM_SET_TAG, tc->tag_len, 0);
            EVP_CipherInit(&cipher_ctx, NULL, tc->key, tc->iv, 1);
            EVP_Cipher(&cipher_ctx, NULL, NULL, tc->pt_len);
            EVP_Cipher(&cipher_ctx, NULL, tc->aad, tc->aad_len);
            EVP_Cipher(&cipher_ctx, tc->ct, tc->pt, tc->pt_len);
            EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_CCM_GET_TAG, tc->tag_len, tc->ct + tc->ct_len);
            tc->ct_len += tc->tag_len;
        } else if (tc->direction == ACVP_DIR_DECRYPT) {
          EVP_CipherInit(&cipher_ctx, cipher, NULL, NULL, 0);
          EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_CCM_SET_IVLEN, tc->iv_len, 0);
          EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_CCM_SET_TAG, tc->tag_len, tc->ct + tc->pt_len);
          EVP_CipherInit(&cipher_ctx, NULL, tc->key, tc->iv, 0);
          EVP_Cipher(&cipher_ctx, NULL, NULL, tc->pt_len);
          EVP_Cipher(&cipher_ctx, NULL, tc->aad, tc->aad_len);
          /*
           * Decrypt and check the tag
           */
          rv = EVP_Cipher(&cipher_ctx, tc->pt, tc->ct, tc->pt_len);
          if (rv < 0) {
              EVP_CIPHER_CTX_cleanup(&cipher_ctx);
              return ACVP_CRYPTO_TAG_FAIL;
          }
        }
        break;
    default:
        printf("Error: Unsupported AES AEAD mode requested by ACVP server\n");
            EVP_CIPHER_CTX_cleanup(&cipher_ctx);
            return ACVP_NO_CAP;
    }

    EVP_CIPHER_CTX_cleanup(&cipher_ctx);

    return ACVP_SUCCESS;
}

static ACVP_RESULT app_sha_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_HASH_TC    *tc;
    const EVP_MD    *md;
    EVP_MD_CTX          md_ctx;

    if (!test_case) {
        return ACVP_INVALID_ARG;
    }

    tc = test_case->tc.hash;

    switch (tc->cipher) {
    case ACVP_SHA1:
  md = EVP_sha1();
  break;
    case ACVP_SHA224:
  md = EVP_sha224();
  break;
    case ACVP_SHA256:
  md = EVP_sha256();
  break;
    case ACVP_SHA384:
  md = EVP_sha384();
  break;
    case ACVP_SHA512:
  md = EVP_sha512();
  break;
    default:
  printf("Error: Unsupported hash algorithm requested by ACVP server\n");
  return ACVP_NO_CAP;
  break;
    }

    EVP_MD_CTX_init(&md_ctx);

    /* If Monte Carlo we need to be able to init and then update
     * one thousand times before we complete each iteration.
     */
    if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT) {

        if (!EVP_DigestInit_ex(&md_ctx, md, NULL)) {
            printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (!EVP_DigestUpdate(&md_ctx, tc->m1, tc->msg_len)) {
      printf("\nCrypto module error, EVP_DigestUpdate failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }
  if (!EVP_DigestUpdate(&md_ctx, tc->m2, tc->msg_len)) {
      printf("\nCrypto module error, EVP_DigestUpdate failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }
  if (!EVP_DigestUpdate(&md_ctx, tc->m3, tc->msg_len)) {
      printf("\nCrypto module error, EVP_DigestUpdate failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }
  if (!EVP_DigestFinal(&md_ctx, tc->md, &tc->md_len)) {
      printf("\nCrypto module error, EVP_DigestFinal failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }

   } else {
        if (!EVP_DigestInit_ex(&md_ctx, md, NULL)) {
            printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }

  if (!EVP_DigestUpdate(&md_ctx, tc->msg, tc->msg_len)) {
      printf("\nCrypto module error, EVP_DigestUpdate failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }
  if (!EVP_DigestFinal(&md_ctx, tc->md, &tc->md_len)) {
      printf("\nCrypto module error, EVP_DigestFinal failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }
  EVP_MD_CTX_cleanup(&md_ctx);
   }

    return ACVP_SUCCESS;
}

static ACVP_RESULT app_hmac_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_HMAC_TC    *tc;
    const EVP_MD    *md;
    HMAC_CTX       hmac_ctx;
    int msg_len;

    if (!test_case) {
        return ACVP_INVALID_ARG;
    }

    tc = test_case->tc.hmac;

    switch (tc->cipher) {
    case ACVP_HMAC_SHA1:
      md = EVP_sha1();
      break;
    case ACVP_HMAC_SHA2_224:
      md = EVP_sha224();
      break;
    case ACVP_HMAC_SHA2_256:
      md = EVP_sha256();
      break;
    case ACVP_HMAC_SHA2_384:
      md = EVP_sha384();
      break;
    case ACVP_HMAC_SHA2_512:
      md = EVP_sha512();
      break;
    default:
        printf("Error: Unsupported hash algorithm requested by ACVP server\n");
        return ACVP_NO_CAP;
        break;
    }

    HMAC_CTX_init(&hmac_ctx);
    msg_len = tc->msg_len;

    if (!HMAC_Init_ex(&hmac_ctx, tc->key, tc->key_len, md, NULL)) {
        printf("\nCrypto module error, HMAC_Init_ex failed\n");
        return ACVP_CRYPTO_MODULE_FAIL;
    }

    if (!HMAC_Update(&hmac_ctx, tc->msg, msg_len)) {
        printf("\nCrypto module error, HMAC_Update failed\n");
        return ACVP_CRYPTO_MODULE_FAIL;
    }

    /* TODO ? - we only support standard mac lengths so we return it, but
       the mac length was passed in and could be used to define how much to
       return */
    if (!HMAC_Final(&hmac_ctx, tc->mac, &tc->mac_len)) {
        printf("\nCrypto module error, HMAC_Final failed\n");
        return ACVP_CRYPTO_MODULE_FAIL;
    }
    HMAC_CTX_cleanup(&hmac_ctx);

    return ACVP_SUCCESS;
}

static ACVP_RESULT app_cmac_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_CMAC_TC    *tc;
    const EVP_CIPHER    *c;
    CMAC_CTX       *cmac_ctx;
    int key_len, i;
    unsigned char mac_compare[16] = {0};
    char full_key[65] = {0};
    int mac_cmp_len;

    if (!test_case) {
        return ACVP_INVALID_ARG;
    }

    tc = test_case->tc.cmac;

    switch (tc->cipher) {
        case ACVP_CMAC_AES:
            switch (tc->key_len) {
            case 128:
                c = EVP_aes_128_cbc();
                break;
            case 192:
                c = EVP_aes_192_cbc();
                break;
            case 256:
                c = EVP_aes_256_cbc();
                break;
            default:
                break;
            }
            key_len = (tc->key_len)/8;
            for (i = 0; i < key_len; i++) {
                full_key[i] = tc->key[i];
            }
            break;
        case ACVP_CMAC_TDES:
            c = EVP_des_ede3_cbc();
            for (i = 0; i < 8; i++) {
                full_key[i] = tc->key[i];
            }
            for (; i < 16; i++) {
                full_key[i] = tc->key2[i%8];
            }
            for (; i < 24; i++) {
                full_key[i] = tc->key3[i%8];
            }
            key_len = 24;
            break;
        default:
            printf("Error: Unsupported CMAC algorithm requested by ACVP server\n");
            return ACVP_NO_CAP;
            break;
    }
    
    full_key[key_len] = '\0';
    
    cmac_ctx = CMAC_CTX_new();

    if (!CMAC_Init(cmac_ctx, full_key, key_len, c, NULL)) {
        printf("\nCrypto module error, CMAC_Init_ex failed\n");
        return ACVP_CRYPTO_MODULE_FAIL;
    }
    
    if (!CMAC_Update(cmac_ctx, tc->msg, tc->msg_len)) {
        printf("\nCrypto module error, CMAC_Update failed\n");
        return ACVP_CRYPTO_MODULE_FAIL;
    }
    
    if (strncmp((const char *)tc->direction, "ver", 3) == 0) {
        if (!CMAC_Final(cmac_ctx, mac_compare, (size_t *)&mac_cmp_len)) {
            printf("\nCrypto module error, CMAC_Final failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        
        /*
         * Reformat the MAC - in "gen" mode, this formatting happens
         * when we build the response JSON. Since the comparison
         * happens here for "ver" we have to reformat here as well
         */
        unsigned char formatted_mac_compare[tc->mac_len * 2 + 1];
        acvp_bin_to_hexstr(mac_compare, mac_cmp_len, formatted_mac_compare);
        
        if (strncmp((const char *)formatted_mac_compare, (const char *)tc->mac, tc->mac_len * 2) == 0) {
            strncpy((char *)tc->ver_disposition, "pass", 4);
        } else {
            strncpy((char *)tc->ver_disposition, "fail", 4);
        }
    } else {
        if (!CMAC_Final(cmac_ctx, tc->mac, (size_t *)&tc->mac_len)) {
            printf("\nCrypto module error, CMAC_Final failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
    }
    CMAC_CTX_cleanup(cmac_ctx);

    return ACVP_SUCCESS;
}

#ifdef OPENSSL_KDF_SUPPORT
static ACVP_RESULT app_kdf135_tls_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_KDF135_TLS_TC    *tc;
    unsigned char *key_block1, *key_block2, *master_secret1, *master_secret2;
    int olen1 = 0, olen2 = 0, len1, ret, i, len, count, psm_len;
    const EVP_MD *evp_md1 = NULL, *evp_md2 = NULL;

    tc = test_case->tc.kdf135_tls;
    /* We only support TLS12 for now */
    if (tc->method != ACVP_KDF135_TLS12) {
        printf("\nCrypto module error, Bad TLS type\n");
        return ACVP_CRYPTO_MODULE_FAIL;
    }

    olen1 = tc->pm_len;
    olen2 = tc->kb_len;
    key_block1 = tc->kblock1;
    key_block2 = tc->kblock2;
    master_secret1 = tc->msecret1;
    master_secret2 = tc->msecret2;

    if (!key_block1 || !key_block2 || !master_secret1 || !master_secret2) {
        printf("\nCrypto module error, malloc failure\n");
        return ACVP_CRYPTO_MODULE_FAIL;
    }

    switch (tc->md)
    {
    case ACVP_KDF135_TLS_CAP_SHA256:
        evp_md1 = evp_md2 = EVP_sha256();
        break;
    case ACVP_KDF135_TLS_CAP_SHA384:
        evp_md1 = evp_md2 = EVP_sha384();
        break;
    case ACVP_KDF135_TLS_CAP_SHA512:
        evp_md1 = evp_md2 = EVP_sha512();
        break;
    default:
        printf("\nCrypto module error, Bad SHA type\n");
        return ACVP_INVALID_ARG;
    }

    count = 1;
    len = tc->pm_len / count;
    if (count == 1) {
        psm_len = 0;
    }

    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 0;
    if (ret == 0) {
        printf("\nCrypto module error, TLS kdf failure\n");
        return ACVP_CRYPTO_MODULE_FAIL;
    }
    for (i = 0; i < olen1; i++) {
         master_secret1[i] ^= master_secret2[i];
    }

    if (evp_md1 != evp_md2) {
        /*
         * IMPORTANT: Need to set ret = <your KDF API here>
         * The default is set to failure as this is not
         * currently supported in OpenSSL
         */
        ret = 0;
        if (ret == 0) {
            printf("\nCrypto module error, TLS kdf failure\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        for (i = 0; i < olen1; i++) {
            master_secret1[i] ^= master_secret2[i];
        }
    }


    len1 = olen1;
    len = len1 / count;
    if (count == 1) {
        len1 = 0;
    }
    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 0;
    if (ret == 0) {
        printf("\nCrypto module error, TLS kdf failure\n");
        return ACVP_CRYPTO_MODULE_FAIL;
    }
    for (i = 0; i < olen2; i++) {
        key_block1[i] ^= key_block2[i];
    }
    if (evp_md1 != evp_md2) {
        /*
         * IMPORTANT: Need to set ret = <your KDF API here>
         * The default is set to failure as this is not
         * currently supported in OpenSSL
         */
        ret = 0;
        if (ret == 0) {
            printf("\nCrypto module error, TLS kdf failure\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        for (i = 0; i < olen2; i++) {
            key_block1[i] ^= key_block2[i];
        }
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT app_kdf135_snmp_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_KDF135_SNMP_TC    *tc;
    unsigned char *s_key;
    int p_len, ret;

    tc = test_case->tc.kdf135_snmp;
    s_key = tc->s_key;
    p_len = tc->p_len;

    if (!s_key) {
        printf("\nCrypto module error, malloc failure\n");
        return ACVP_CRYPTO_MODULE_FAIL;
    }
    
    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 0;
    if (!ret) {
        printf("\nCrypto module error, kdf snmp failure\n");
        return ACVP_CRYPTO_MODULE_FAIL;
    }

    tc->skey_len = strnlen((const char *)s_key, ACVP_KDF135_SNMP_SKEY_MAX);

    return ACVP_SUCCESS;
}

static ACVP_RESULT app_kdf135_ssh_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_KDF135_SSH_TC *tc;
    ACVP_RESULT rc = ACVP_SUCCESS;

    const EVP_MD *evp_md = NULL, *evp_md2 = NULL;
    int p_len, ret;
    unsigned char* cs_init_iv_buf = NULL;
    unsigned char* sc_init_iv_buf = NULL;
    unsigned char* cs_e_key_buf   = NULL;
    unsigned char* sc_e_key_buf   = NULL;
    unsigned char* cs_i_key_buf   = NULL;
    unsigned char* sc_i_key_buf   = NULL;

    tc = test_case->tc.kdf135_ssh;

    switch (tc->sha_type)
    {
    case ACVP_KDF135_SSH_CAP_SHA256:
        evp_md = evp_md2 = EVP_sha256();
        break;
    case ACVP_KDF135_SSH_CAP_SHA384:
        evp_md = evp_md2 = EVP_sha384();
        break;
    case ACVP_KDF135_SSH_CAP_SHA512:
        evp_md = evp_md2 = EVP_sha512();
        break;
    default:
        evp_md = EVP_sha1(); ///temp for test
        printf("\nCrypto module error, Bad SHA type\n");
        return ACVP_INVALID_ARG;
    }

    /*
       o  Initial IV client to server: HASH(K || H || "A" || session_id)
          (Here K is encoded as mpint and "A" as byte and session_id as raw
          data.  "A" means the single character A, ASCII 65).
       o  Initial IV server to client: HASH(K || H || "B" || session_id)
       o  Encryption key client to server: HASH(K || H || "C" || session_id)
       o  Encryption key server to client: HASH(K || H || "D" || session_id)
       o  Integrity key client to server: HASH(K || H || "E" || session_id)
       o  Integrity key server to client: HASH(K || H || "F" || session_id)
     */
    cs_init_iv_buf = tc->cs_init_iv;
    sc_init_iv_buf = tc->sc_init_iv;
    cs_e_key_buf   = tc->cs_e_key;
    sc_e_key_buf   = tc->sc_e_key;
    cs_i_key_buf   = tc->cs_i_key;
    sc_i_key_buf   = tc->sc_i_key;

    if(!cs_init_iv_buf || !sc_init_iv_buf || !cs_e_key_buf ||
       !sc_e_key_buf || !cs_i_key_buf || !sc_i_key_buf) {
        rc = ACVP_MALLOC_FAIL;
        goto error;
    }
    
    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 1;
    if (ret != 0) {
        printf("\nCrypto module error, kdf ssh cs_init_iv failure\n");
        rc = ACVP_CRYPTO_MODULE_FAIL;
        goto error;
    }
    
    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 1;
    if (ret != 0) {
        printf("\nCrypto module error, kdf ssh sc_init_iv failure\n");
        rc = ACVP_CRYPTO_MODULE_FAIL;
        goto error;
    }
    
    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 1;
    if (ret != 0) {
        printf("\nCrypto module error, kdf ssh cs_e_key failure\n");
        rc = ACVP_CRYPTO_MODULE_FAIL;
        goto error;
    }
    
    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 1;
    if (ret != 0) {
        printf("\nCrypto module error, kdf ssh sc_e_key failure\n");
        rc = ACVP_CRYPTO_MODULE_FAIL;
        goto error;
    }
    
    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 1;
    if (ret != 0) {
       printf("\nCrypto module error, kdf ssh cs_i_key failure\n");
       rc = ACVP_CRYPTO_MODULE_FAIL;
       goto error;
    }
    
    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 1;
    if (ret != 0) {
       printf("\nCrypto module error, kdf ssh sc_i_key failure\n");
       rc = ACVP_CRYPTO_MODULE_FAIL;
       goto error;
    }

error:
    return rc;
}
#endif

//Must be commented out if the user is Making with Makefile.fom
#ifdef ACVP_NO_RUNTIME
/*static ACVP_RESULT app_dsa_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_DSA_PQGGEN_TC *pqggen;
    int                dsa2 = 0, L, N;
    const EVP_MD       *md = NULL;
    ACVP_DSA_TC           *tc;
    unsigned char      seed[1024];
    DSA                *dsa;
    int                counter;
    unsigned long      h;


    tc = test_case->tc.dsa;

    switch (tc->mode)
    {
    case ACVP_DSA_MODE_PQGGEN:
        pqggen = test_case->tc.dsa->mode_tc.pqggen;

        switch (pqggen->sha)
        {
        case ACVP_DSA_SHA1:
            md = EVP_sha1();
            break;
        case ACVP_DSA_SHA224:
            md = EVP_sha224();
            break;
        case ACVP_DSA_SHA256:
            md = EVP_sha256();
            break;
        case ACVP_DSA_SHA384:
            md = EVP_sha384();
            break;
        case ACVP_DSA_SHA512:
            md = EVP_sha512();
            break;
        case ACVP_DSA_SHA512_224:
        case ACVP_DSA_SHA512_256:
        default:
            printf("DSA sha value not supported %d\n", pqggen->sha);
            return ACVP_CRYPTO_MODULE_FAIL;
            break;
        }

        switch (pqggen->gen_pq)
        {
        case ACVP_DSA_UNVERIFIABLE:
            printf("DSA Parameter Generation2 error for %d, not supported\n", pqggen->gen_pq);
                return ACVP_CRYPTO_MODULE_FAIL;
                break;
        case ACVP_DSA_CANONICAL:
        dsa = DSA_new();
        BN_hex2bn(&dsa->p, (const char *)pqggen->p);
        BN_hex2bn(&dsa->q, (const char *)pqggen->q);
        L = pqggen->l;
        N = pqggen->n;
        if (dsa_builtin_paramgen2(dsa, L, N, md,
                      pqggen->seed, pqggen->seedlen, pqggen->index, NULL,
                      NULL, NULL, NULL) <= 0)
            {
                printf("DSA Parameter Generation2 error for %d\n", pqggen->gen_pq);
                    return ACVP_CRYPTO_MODULE_FAIL;
            }
                pqggen->g = (unsigned char *)BN_bn2hex(dsa->g);
        DSA_free(dsa);
                break;

        case ACVP_DSA_PROBABLE:
        case ACVP_DSA_PROVABLE:
            dsa = DSA_new();
        L = pqggen->l;
        N = pqggen->n;
            if (!dsa2 && !dsa_builtin_paramgen(dsa, L, N, md,
                                 NULL, 0, seed,
                               &counter, &h, NULL)) {
            printf("DSA Parameter Generation error for %d\n", pqggen->gen_pq);
                return ACVP_CRYPTO_MODULE_FAIL;
                }
            if (dsa2 && dsa_builtin_paramgen2(dsa, L, N, md,
                                          NULL, 0, -1, seed,
                              &counter, &h, NULL) <= 0) {
                printf("DSA Parameter Generation 2 error for %d\n", pqggen->gen_pq);
                return ACVP_CRYPTO_MODULE_FAIL;
            }

                pqggen->p = (unsigned char *)BN_bn2hex(dsa->p);
                pqggen->q = (unsigned char *)BN_bn2hex(dsa->q);
                pqggen->counter = counter;
                pqggen->h = h;

            if (!dsa2) {
                    pqggen->g = (unsigned char *)BN_bn2hex(dsa->g);
                    memcpy(pqggen->seed, &seed, EVP_MD_size(md));
            pqggen->seedlen = EVP_MD_size(md);
                } else {
                    memcpy(pqggen->seed, &seed, EVP_MD_size(md));
            pqggen->seedlen = EVP_MD_size(md);
                }
            if (!dsa2) {
               pqggen->counter = counter;
               pqggen->h = h;
            } else {
               pqggen->counter = counter;
            }
            DSA_free(dsa);
            break;
        default:
            printf("Invalid DSA gen_pq %d\n", pqggen->gen_pq);
            return ACVP_CRYPTO_MODULE_FAIL;
            break;
        }
    default:
        printf("Invalid DSA mode %d\n", tc->mode);
        return ACVP_CRYPTO_MODULE_FAIL;
        break;
    }
    return ACVP_SUCCESS;
}*/

static ACVP_RESULT app_rsa_keygen_handler(ACVP_TEST_CASE *test_case)
{
    /*
     * custom crypto module handler
     * to be filled in -
     * this handler assumes info gen by server
     * and all the other params registered for
     * in this example app.
     */
    
    ACVP_RSA_KEYGEN_TC    *tc;
    ACVP_RESULT rv = ACVP_SUCCESS;
    RSA       *rsa;
    BIGNUM *e = BN_new();
    int seed_max = 256;
    char seed[seed_max];

    /* keygen vars */
    unsigned int bitlen1, bitlen2, bitlen3, bitlen4, keylen;

    if (!test_case) {
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    tc = test_case->tc.rsa_keygen;

    rsa = FIPS_rsa_new();
    bitlen1 = tc->bitlen1;
    bitlen2 = tc->bitlen2;
    bitlen3 = tc->bitlen3;
    bitlen4 = tc->bitlen4;
    keylen = tc->modulo;
    
    if (!BN_hex2bn(&e, (const char *)tc->e)) {
        printf("Error converting e string to BN\n");
        rv = ACVP_CRYPTO_MODULE_FAIL;
        goto err;
    }
    
    /*
     * IMPORTANT: Placeholder! The RSA keygen vector
     * sets will fail if this handler is left as is.
     *
     * Below, insert your own key generation API that
     * supports specification of all of the params...
     */
    if (!FIPS_rsa_x931_generate_key_ex(rsa, tc->modulo, e, NULL)) {
        printf("\nError: Issue with key generation\n");
        rv = ACVP_CRYPTO_MODULE_FAIL;
        goto err;
    }

    tc->p = (unsigned char *)BN_bn2hex(rsa->p);
    tc->q = (unsigned char *)BN_bn2hex(rsa->q);
    tc->n = (unsigned char *)BN_bn2hex(rsa->n);
    tc->d = (unsigned char *)BN_bn2hex(rsa->d);

    FIPS_rsa_free(rsa);
    
    err:
    return rv;
}

static ACVP_RESULT app_ecdsa_handler(ACVP_TEST_CASE *test_case)
{
    /*
     * custom crypto module handler
     * to be filled in with API for
     * module under test
     *
     * existing code to be used as skeleton...
     */
    
    ACVP_ECDSA_TC    *tc;
    ACVP_RESULT rv = ACVP_CRYPTO_MODULE_FAIL;
    ACVP_CIPHER mode;
    EVP_MD *md;

    if (!test_case) {
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    tc = test_case->tc.ecdsa;
    mode = tc->cipher;
    
    if (!strcmp(tc->hash_alg, "SHA-1"))
        md = EVP_sha1();
    else if (!strcmp(tc->hash_alg, "SHA2-224"))
        md = EVP_sha224();
    else if (!strcmp(tc->hash_alg, "SHA2-256"))
        md = EVP_sha256();
    else if (!strcmp(tc->hash_alg, "SHA2-384"))
        md = EVP_sha384();
    else if (!strcmp(tc->hash_alg, "SHA2-512"))
        md = EVP_sha512();
    
    int nid;
    if (!strcmp(tc->curve, "b-233"))
        nid = NID_sect233r1;
    if (!strcmp(tc->curve, "b-283"))
        nid = NID_sect283r1;
    if (!strcmp(tc->curve, "b-409"))
        nid = NID_sect409r1;
    if (!strcmp(tc->curve, "b-571"))
        nid = NID_sect571r1;
    if (!strcmp(tc->curve, "k-233"))
        nid = NID_sect233k1;
    if (!strcmp(tc->curve, "k-283"))
        nid = NID_sect283k1;
    if (!strcmp(tc->curve, "k-409"))
        nid = NID_sect409k1;
    if (!strcmp(tc->curve, "k-571"))
        nid = NID_sect571k1;
    if (!strcmp(tc->curve, "k-224"))
        nid = NID_secp224r1;
    if (!strcmp(tc->curve, "k-256"))
        nid = NID_X9_62_prime256v1;
    if (!strcmp(tc->curve, "k-384"))
        nid = NID_secp384r1;
    if (!strcmp(tc->curve, "k-521"))
        nid = NID_secp521r1;
    
    err:
    return rv;
}

/*
 * RSA SigGen handler
 * requires Makefile.fom to function
 */
static ACVP_RESULT app_rsa_sig_handler(ACVP_TEST_CASE *test_case)
{
    EVP_MD *tc_md = NULL;
    unsigned char *msg = NULL, *sigbuf = NULL;
    int siglen, pad_mode, msg_len;
    BIGNUM *bn_e = NULL;
    ACVP_RSA_SIG_TC    *tc;
    RSA *rsa = NULL;
    
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!test_case) {
        printf("\nError: test case not found in RSA SigGen handler\n");
        rv = ACVP_INVALID_ARG;
        goto err;
    }

    tc = test_case->tc.rsa_sig;

    if (!tc) {
        printf("\nError: test case not found in RSA SigGen handler\n");
        rv = ACVP_INVALID_ARG;
        goto err;
    }

    /*
     * Set the message digest to the appropriate sha
     */
    int nid;
    if (strncmp(tc->hash_alg, ACVP_STR_SHA_1, strlen(ACVP_STR_SHA_1)) == 0 ) {
        nid = NID_sha1;
        tc_md = (EVP_MD *)EVP_sha1();
    } else if (strncmp(tc->hash_alg, ACVP_STR_SHA2_224, strlen(ACVP_STR_SHA2_224)) == 0 ) {
        nid = NID_sha224;
        tc_md = (EVP_MD *)EVP_sha224();
    } else if (strncmp(tc->hash_alg, ACVP_STR_SHA2_256, strlen(ACVP_STR_SHA2_256)) == 0 ) {
        nid = NID_sha256;
        tc_md = (EVP_MD *)EVP_sha256();
    } else if (strncmp(tc->hash_alg, ACVP_STR_SHA2_384, strlen(ACVP_STR_SHA2_384)) == 0 ) {
        nid = NID_sha384;
        tc_md = (EVP_MD *)EVP_sha384();
    } else if (strncmp(tc->hash_alg, ACVP_STR_SHA2_512, strlen(ACVP_STR_SHA2_512)) == 0 ) {
        nid = NID_sha512;
        tc_md = (EVP_MD *)EVP_sha512();
    } else {
        printf("\nError: hashAlg not supported for RSA SigGen\n");
        rv = ACVP_INVALID_ARG;
        goto err;
    }

    /*
     * Set the message given from the tc to binary form
     */
    msg_len = tc->msg_len;
    msg = calloc(msg_len + 1, sizeof(char));
    if(!msg) {
        printf("\nError: Alloc failure in RSA Sig Handler\n");
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    memcpy(msg, tc->msg, msg_len);
    
    /*
     * Make an RSA object and set a new BN exponent to use to generate a key
     */

    rsa = FIPS_rsa_new();
    if (!rsa) {
        printf("\nError: Issue with RSA obj in RSA Sig\n");
        rv = ACVP_CRYPTO_MODULE_FAIL;
        goto err;
    }
    
    bn_e = BN_new();
    if (!bn_e || !BN_set_word(bn_e, 0x1001)) {
        printf("\nError: Issue with exponent in RSA Sig\n");
        rv = ACVP_CRYPTO_MODULE_FAIL;
        goto err;
    }
    
    if (!tc->modulo) {
        printf("\nError: Issue with modulo in RSA Sig\n");
        rv = ACVP_CRYPTO_MODULE_FAIL;
        goto err;
    }

    /*
     * Set the pad mode and generate a key given the respective sigType
     */
    if(strncmp(tc->sig_type, RSA_SIG_TYPE_X931_NAME, 8) == 0) {
        pad_mode = RSA_X931_PADDING;
    } else if(strncmp(tc->sig_type, RSA_SIG_TYPE_PKCS1V15_NAME, 8) == 0) {
        pad_mode = RSA_PKCS1_PADDING;
    } else if(strncmp(tc->sig_type, RSA_SIG_TYPE_PKCS1PSS_NAME, 8) == 0) {
        pad_mode = RSA_PKCS1_PSS_PADDING;
    } else {
        printf("\nError: sigType not supported\n");
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    
    /*
     * If we are verifying, set RSA to the given public key
     * Else, generate a new key, retrieve and save values
     */
    if (tc->sig_mode == ACVP_RSA_SIGVER) {
        BN_hex2bn(&rsa->e, (const char *)tc->e);
        BN_hex2bn(&rsa->n, (const char *)tc->n);
        tc->ver_disposition = RSA_verify(nid, msg, msg_len, tc->signature, tc->sig_len, rsa);
    } else {
        if (!FIPS_rsa_x931_generate_key_ex(rsa, tc->modulo, bn_e, NULL)) {
            printf("\nError: Issue with keygen during siggen handling\n");
            rv = ACVP_CRYPTO_MODULE_FAIL;
            goto err;
        }
        tc->e = (unsigned char *)BN_bn2hex(rsa->e);
        tc->n = (unsigned char *)BN_bn2hex(rsa->n);
        
        if (msg && tc_md) {
            siglen = RSA_size(rsa);
            sigbuf = calloc(siglen, sizeof(char));
            if (!sigbuf) {
                printf("\nError: SigBuf fail in RSA SigGen\n");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                goto err;
            }
        
            if (!FIPS_rsa_sign(rsa, msg, msg_len, tc_md, pad_mode, 0, NULL,
                                    sigbuf, (unsigned int *)&siglen)) {
                printf("\nError: RSA Signature Generation fail\n");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                goto err;
            }
            
            acvp_bin_to_hexstr(sigbuf, siglen, tc->signature);
            tc->sig_len = siglen;
        }
    }
err:
    if (msg) free(msg);
    if (sigbuf) free(sigbuf);
    if (bn_e) BN_free(bn_e);
    if (rsa) FIPS_rsa_free(rsa);
    
    return rv;
}
#endif

#ifdef ACVP_NO_RUNTIME
typedef struct
{
    unsigned char *ent;
    size_t entlen;
    unsigned char *nonce;
    size_t noncelen;
} DRBG_TEST_ENT;

static size_t drbg_test_entropy(DRBG_CTX *dctx, unsigned char **pout,
        int entropy, size_t min_len, size_t max_len)
{
    if (!dctx || !pout) return 0;
    DRBG_TEST_ENT *t = (DRBG_TEST_ENT *)FIPS_drbg_get_app_data(dctx);
    if (!t) return 0;

    if (t->entlen < min_len) printf("entropy data len < min_len: %zu\n", t->entlen);
    if (t->entlen > max_len) printf("entropy data len > max_len: %zu\n", t->entlen);
    *pout = (unsigned char *)t->ent;
    return t->entlen;
}

static size_t drbg_test_nonce(DRBG_CTX *dctx, unsigned char **pout,
        int entropy, size_t min_len, size_t max_len)
{
    if (!dctx || !pout) return 0;
    DRBG_TEST_ENT *t = (DRBG_TEST_ENT *)FIPS_drbg_get_app_data(dctx);

    if (t->noncelen < min_len) printf("nonce data len < min_len: %zu\n", t->noncelen);
    if (t->noncelen > max_len) printf("nonce data len > max_len: %zu\n", t->noncelen);
    *pout = (unsigned char *)t->nonce;
    return t->noncelen;
}

static ACVP_RESULT app_drbg_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_RESULT     result = ACVP_SUCCESS;
    ACVP_DRBG_TC    *tc;
    unsigned int    nid;
    int             der_func = 0;
    unsigned int    drbg_entropy_len;
    int             fips_rc;

    unsigned char   *nonce = NULL;

    if (!test_case) {
        return ACVP_INVALID_ARG;
    }

    tc = test_case->tc.drbg;
    /*
     * Init entropy length
     */
    drbg_entropy_len = tc->entropy_len;

    switch(tc->cipher) {
    case ACVP_HASHDRBG:
        nonce = tc->nonce;
        switch(tc->mode) {
        case ACVP_DRBG_SHA_1:
            nid = NID_sha1;
            break;
        case ACVP_DRBG_SHA_224:
            nid = NID_sha256;
            break;
        case ACVP_DRBG_SHA_256:
            nid = NID_sha256;
            break;
        case ACVP_DRBG_SHA_384:
            nid = NID_sha384;
            break;
        case ACVP_DRBG_SHA_512:
            nid = NID_sha512;
            break;

        case ACVP_DRBG_SHA_512_224:
        case ACVP_DRBG_SHA_512_256:
        default:
            result = ACVP_UNSUPPORTED_OP;
            printf("%s: Unsupported algorithm/mode %d/%d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
                    tc->cipher, tc->mode);
            return (result);
            break;
    }
    break;

        case ACVP_HMACDRBG:
            nonce = tc->nonce;
            switch(tc->mode) {
            case ACVP_DRBG_SHA_1:
                nid =   NID_hmacWithSHA1;
                break;
            case ACVP_DRBG_SHA_224:
                nid =   NID_hmacWithSHA224;
                break;
            case ACVP_DRBG_SHA_256:
                nid =   NID_hmacWithSHA256;
                break;
            case ACVP_DRBG_SHA_384:
                nid =   NID_hmacWithSHA384;
                break;
            case ACVP_DRBG_SHA_512:
                nid =   NID_hmacWithSHA512;
                break;
            case ACVP_DRBG_SHA_512_224:
            case ACVP_DRBG_SHA_512_256:
            default:
                result = ACVP_UNSUPPORTED_OP;
                printf("%s: Unsupported algorithm/mode %d/%d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
                        tc->cipher, tc->mode);
                return (result);
                break;
            }
        break;

        case ACVP_CTRDRBG:
            /*
             * DR function Only valid in CTR mode
             * if not set nonce is ignored
             */
            if (tc->der_func_enabled) {
                der_func = DRBG_FLAG_CTR_USE_DF;
                nonce = tc->nonce;
            } else {
                /**
                 * Note 5: All DRBGs are tested at their maximum supported security
                 * strength so this is the minimum bit length of the entropy input that
                 * ACVP will accept.  The maximum supported security strength is also
                 * the default value for this input.  Longer entropy inputs are
                 * permitted, with the following exception: for ctrDRBG with no df, the
                 * bit length must equal the seed length.
                 **/
                drbg_entropy_len = 0;
            }

            switch(tc->mode) {
            case ACVP_DRBG_AES_128:
                nid = NID_aes_128_ctr;
                break;
            case ACVP_DRBG_AES_192:
                nid = NID_aes_192_ctr;
                break;
            case ACVP_DRBG_AES_256:
                nid = NID_aes_256_ctr;
                break;
            case ACVP_DRBG_3KEYTDEA:
            default:
                result = ACVP_UNSUPPORTED_OP;
                printf("%s: Unsupported algorithm/mode %d/%d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
                        tc->cipher, tc->mode);
                return (result);
                break;
            }
        break;
        default:
            result = ACVP_UNSUPPORTED_OP;
            printf("%s: Unsupported algorithm %d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
                    tc->cipher);
            return (result);
            break;
    }

    DRBG_CTX *drbg_ctx = NULL;
    DRBG_TEST_ENT entropy_nonce;
    memset(&entropy_nonce, 0, sizeof(DRBG_TEST_ENT));
    drbg_ctx = FIPS_drbg_new(nid, der_func | DRBG_FLAG_TEST);
    if (!drbg_ctx) {
        progress("ERROR: failed to create DRBG Context.");
        return ACVP_MALLOC_FAIL;
    }

    /*
     * Set entropy and nonce
     */
    entropy_nonce.ent = tc->entropy;
    entropy_nonce.entlen = drbg_entropy_len/8;

    entropy_nonce.nonce = nonce;
    entropy_nonce.noncelen = tc->nonce_len/8;

    FIPS_drbg_set_app_data(drbg_ctx, &entropy_nonce);

    fips_rc = FIPS_drbg_set_callbacks(drbg_ctx,
                                      drbg_test_entropy,
                                      0, 0,
                                      drbg_test_nonce,
                                      0);
    if (!fips_rc) {
        progress("ERROR: failed to Set callback DRBG ctx");
        long l = 9;
        char buf[2048]  = {0};
        while ((l = ERR_get_error()))
            printf( "ERROR:%s\n", ERR_error_string(l, buf));

        result = ACVP_CRYPTO_MODULE_FAIL;
        goto end;
    }

    fips_rc = FIPS_drbg_instantiate(drbg_ctx, (const unsigned char *)tc->perso_string,
                                    (size_t) tc->perso_string_len/8);
    if (!fips_rc) {
        progress("ERROR: failed to instantiate DRBG ctx");
        long l = 9;
        char buf[2048]  = {0};
        while ((l = ERR_get_error()))
            printf( "ERROR:%s\n", ERR_error_string(l, buf));

        result = ACVP_CRYPTO_MODULE_FAIL;
        goto end;
    }

    /*
     * Process predictive resistance flag
     */
    if (tc->pred_resist_enabled) {
        entropy_nonce.ent = tc->entropy_input_pr;
        entropy_nonce.entlen = drbg_entropy_len/8;

        fips_rc =  FIPS_drbg_generate(drbg_ctx, (unsigned char *)tc->drb,
                                  (size_t) (tc->drb_len/8),
                                  (int) 1,
                                  (const unsigned char *)tc->additional_input,
                                  (size_t) (tc->additional_input_len/8));
        if (!fips_rc) {
            progress("ERROR: failed to generate drb");
            long l;
            while ((l = ERR_get_error()))
                printf( "ERROR:%s\n", ERR_error_string(l, NULL));
            result = ACVP_CRYPTO_MODULE_FAIL;
            goto end;
        }

        entropy_nonce.ent = tc->entropy_input_pr_1;
        entropy_nonce.entlen = drbg_entropy_len/8;

        fips_rc =  FIPS_drbg_generate(drbg_ctx, (unsigned char *)tc->drb,
                                  (size_t) (tc->drb_len/8),
                                  (int) 1,
                                  (const unsigned char *)tc->additional_input_1,
                                  (size_t) (tc->additional_input_len/8));
        if (!fips_rc) {
            progress("ERROR: failed to generate drb");
            long l;
            while ((l = ERR_get_error()))
                printf( "ERROR:%s\n", ERR_error_string(l, NULL));
            result = ACVP_CRYPTO_MODULE_FAIL;
            goto end;
        }
    } else {
        fips_rc = FIPS_drbg_generate(drbg_ctx, (unsigned char *)tc->drb,
                                     (size_t) (tc->drb_len/8),
                                     (int) 0,
                                     (const unsigned char *)tc->additional_input,
                                     (size_t) (tc->additional_input_len/8));
        if (!fips_rc) {
            progress("ERROR: failed to generate drb");
            long l;
            while ((l = ERR_get_error()))
                printf( "ERROR:%s\n", ERR_error_string(l, NULL));
            result = ACVP_CRYPTO_MODULE_FAIL;
            goto end;
        }
    }

end:
    FIPS_drbg_uninstantiate(drbg_ctx);
    FIPS_drbg_free(drbg_ctx);

    return result;
}
#endif
