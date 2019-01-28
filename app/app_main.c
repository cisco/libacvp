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
#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include <fcntl.h>
#include "acvp/acvp.h"
#include "safe_lib.h"

#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/cmac.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>

#ifdef OPENSSL_KDF_SUPPORT
#include <openssl/kdf.h>
#endif

#ifdef ACVP_NO_RUNTIME
#include <openssl/dsa.h>
#include "app_lcl.h"
#include <openssl/fips_rand.h>
#include <openssl/fips.h>
extern int fips_selftest_fail;
extern int fips_mode;
#endif
static ACVP_RESULT totp(char **token, int token_max);
static int enable_aes(ACVP_CTX *ctx);
static int enable_tdes(ACVP_CTX *ctx);
static int enable_hash(ACVP_CTX *ctx);
static int enable_cmac(ACVP_CTX *ctx);
static int enable_hmac(ACVP_CTX *ctx);

#ifdef OPENSSL_KDF_SUPPORT
static int enable_kdf(ACVP_CTX *ctx);
#endif
#ifdef ACVP_NO_RUNTIME
static int enable_dsa(ACVP_CTX *ctx);
static int enable_rsa(ACVP_CTX *ctx);
static int enable_ecdsa(ACVP_CTX *ctx);
static int enable_drbg(ACVP_CTX *ctx);
static int enable_kas_ecc(ACVP_CTX *ctx);
static int enable_kas_ffc(ACVP_CTX *ctx);
#endif

static int app_aes_handler_aead(ACVP_TEST_CASE *test_case);
static int app_aes_handler(ACVP_TEST_CASE *test_case);
static int app_des_handler(ACVP_TEST_CASE *test_case);
static int app_sha_handler(ACVP_TEST_CASE *test_case);
static int app_hmac_handler(ACVP_TEST_CASE *test_case);
static int app_cmac_handler(ACVP_TEST_CASE *test_case);
static int app_aes_keywrap_handler(ACVP_TEST_CASE *test_case);

#ifdef OPENSSL_KDF_SUPPORT
static int app_kdf135_tls_handler(ACVP_TEST_CASE *test_case);
static int app_kdf135_snmp_handler(ACVP_TEST_CASE *test_case);
static int app_kdf135_ssh_handler(ACVP_TEST_CASE *test_case);
static int app_kdf135_srtp_handler(ACVP_TEST_CASE *test_case);
static int app_kdf135_ikev2_handler(ACVP_TEST_CASE *test_case);
static int app_kdf135_ikev1_handler(ACVP_TEST_CASE *test_case);
static int app_kdf135_x963_handler(ACVP_TEST_CASE *test_case);
static int app_kdf108_handler(ACVP_TEST_CASE *test_case);
#endif
#ifdef ACVP_NO_RUNTIME
static int app_dsa_handler(ACVP_TEST_CASE *test_case);
static int app_kas_ecc_handler(ACVP_TEST_CASE *test_case);
static int app_kas_ffc_handler(ACVP_TEST_CASE *test_case);
static int app_drbg_handler(ACVP_TEST_CASE *test_case);
static int app_rsa_keygen_handler(ACVP_TEST_CASE *test_case);
static int app_rsa_sig_handler(ACVP_TEST_CASE *test_case);
static int app_ecdsa_handler(ACVP_TEST_CASE *test_case);
#endif

#define JSON_FILENAME_LENGTH 24
#define DEFAULT_SERVER "127.0.0.1"
#define DEFAULT_PORT 443
#define DEFAULT_CA_CHAIN "certs/acvp-private-root-ca.crt.pem"
#define DEFAULT_CERT "certs/my-client-cert.pem"
#define DEFAULT_KEY "certs/my-client-key.pem"

#define TLS_MD_MASTER_SECRET_CONST              "master secret"
#define TLS_MD_MASTER_SECRET_CONST_SIZE         13
#define TLS_MD_KEY_EXPANSION_CONST              "key expansion"
#define TLS_MD_KEY_EXPANSION_CONST_SIZE         13

typedef struct app_config {
    ACVP_LOG_LVL level;
    int sample;
    int dev;
    int json;
    char json_file[JSON_FILENAME_LENGTH];

    /*
     * Algorithm Flags
     * 0 is off, 1 is on
     */
    int aes; int tdes;
    int hash; int cmac;
    int hmac;
    /* These require the fom */
#ifdef ACVP_NO_RUNTIME
    int dsa; int rsa;
    int drbg; int ecdsa;
    int kas_ecc; int kas_ffc;
#endif
#ifdef OPENSSL_KDF_SUPPORT
    int kdf;
#endif
} APP_CONFIG;

char *server;
int port;
char *ca_chain_file;
char *cert_file;
char *key_file;
char *path_segment;
char *api_context;
char value[] = "same";

static EVP_CIPHER_CTX *glb_cipher_ctx = NULL; /* need to maintain across calls for MCT */

/* RSA group values */
int rsa_current_tg = 0;
BIGNUM *group_n = NULL;
RSA *group_rsa = NULL;

/* ECDSA group values */
int ecdsa_current_tg = 0;
BIGNUM *ecdsa_group_Qx = NULL;
BIGNUM *ecdsa_group_Qy = NULL;
EC_KEY *ecdsa_group_key = NULL;

/* DSA group values */
DSA *group_dsa = NULL;
int dsa_current_keygen_tg = 0;
int dsa_current_siggen_tg = 0;
BIGNUM *group_p = NULL;
BIGNUM *group_q = NULL;
BIGNUM *group_g = NULL;
BIGNUM *group_pub_key = NULL;

#define CHECK_ENABLE_CAP_RV(rv) \
    if (rv != ACVP_SUCCESS) { \
        printf("Failed to register capability with libacvp (rv=%d: %s)\n", rv, acvp_lookup_error_string(rv)); \
        goto end; \
    }


/*
 * Read the operational parameters from the various environment
 * variables.
 */
static void setup_session_parameters() {
    char *tmp;

    server = getenv("ACV_SERVER");
    if (!server) server = DEFAULT_SERVER;

    tmp = getenv("ACV_PORT");
    if (tmp) port = atoi(tmp);
    if (!port) port = DEFAULT_PORT;

    path_segment = getenv("ACV_URI_PREFIX");
    if (!path_segment) path_segment = "";

    api_context = getenv("ACV_API_CONTEXT");
    if (!api_context) api_context = "";

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
ACVP_RESULT progress(char *msg) {
    printf("%s", msg);
    return ACVP_SUCCESS;
}

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

static void print_usage(int err) {
    if (err) {
        printf("\nInvalid usage...\n");
    } else {
        printf("\n===========================");
        printf("\n===== ACVP_APP USAGE ======");
        printf("\n===========================\n");
    }
    printf("This program does not require any argument, however logging level can be\n");
    printf("controlled using:\n");
    printf("      --none\n");
    printf("      --error\n");
    printf("      --warn\n");
    printf("      --status(default)\n");
    printf("      --info\n");
    printf("      --verbose\n");
    printf("      --version\n");
    printf("\n");
    printf("Algorithm Test Suites:\n");
    printf("      --aes(default)\n");
    printf("      --no_aes\n");
    printf("      --tdes(default)\n");
    printf("      --no_tdes\n");
    printf("      --hash(default)\n");
    printf("      --no_hash\n");
    printf("      --cmac(default)\n");
    printf("      --no_cmac\n");
    printf("      --hmac(default)\n");
    printf("      --no_hmac\n");
#ifdef OPENSSL_KDF_SUPPORT
    printf("      --kdf\n");
    printf("      --no_kdf(default)\n");
#endif
#ifdef ACVP_NO_RUNTIME
    printf("      --dsa\n");
    printf("      --no_dsa(default)\n");
    printf("      --rsa\n");
    printf("      --no_rsa(default)\n");
    printf("      --ecdsa\n");
    printf("      --no_ecdsa(default)\n");
    printf("      --drbg\n");
    printf("      --no_drbg(default)\n");
    printf("      --kas_ecc\n");
    printf("      --no_kas_ecc(default)\n");
    printf("      --kas_ffc\n");
    printf("      --no_kas_ffc(default)\n");
#endif
    printf("\n");
    printf("To register a formatted JSON file use:\n");
    printf("      --json <file>\n");
    printf("\n");
    printf("If you are running a sample registration (querying for correct answers\n");
    printf("in addition to the normal registration flow) use:\n");
    printf("      --sample\n");
    printf("\n");
    printf("If you want to include \"debugRequest\" in your registration, use:\n");
    printf("      --dev\n");
    printf("\n");
    printf("In addition some options are passed to acvp_app using\n");
    printf("environment variables.  The following variables can be set:\n\n");
    printf("    ACV_SERVER (when not set, defaults to %s)\n", DEFAULT_SERVER);
    printf("    ACV_PORT (when not set, defaults to %d)\n", DEFAULT_PORT);
    printf("    ACV_URI_PREFIX (when not set, defaults to null)\n");
    printf("    ACV_CA_FILE (when not set, defaults to %s)\n", DEFAULT_CA_CHAIN);
    printf("    ACV_CERT_FILE (when not set, defaults to %s)\n", DEFAULT_CERT);
    printf("    ACV_KEY_FILE (when not set, defaults to %s)\n", DEFAULT_KEY);
    printf("    ACV_TOTP_SEED (when not set, client will not use Two-factor authentication)\n\n");
    printf("The CA certificates, cert and key should be PEM encoded. There should be no\n");
    printf("password on the key file.\n");
}

static int cli_alg_option(int *alg,
                          int *op_status,
                          int enable,
                          char *enable_str,
                          char *disable_str) {
#define OP_DISABLE 1
#define OP_ENABLE 2
    if (enable) {
        /*
         * Trying to enable this algorithm.
         * Check to see if algorithm has been disabled already.
         */
        if (*op_status == OP_DISABLE) {
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nAlgorithm already disabled by \"%s\"."
                   "\nPlease give only 1 of these options at a time.\n",
                   enable_str, disable_str);
            return 1;
        }
        *op_status = OP_ENABLE;
        *alg = 1;
    } else {
        /*
         * Trying to disable this algorithm.
         * Check to see if algorithm has been disabled already.
         */
        if (*op_status == OP_ENABLE) {
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nAlgorithm already enabled by \"%s\"."
                   "\nPlease give only 1 of these options at a time.\n",
                   disable_str, enable_str);
            return 1;
        }
        *op_status = OP_DISABLE;
        *alg = 0;
    }

    return 0;
}

static void default_config(APP_CONFIG *cfg) {
    cfg->level = ACVP_LOG_LVL_STATUS;
    cfg->aes = 1;
    cfg->tdes = 1;
    cfg->hash = 1;
    cfg->cmac = 1;
    cfg->hmac = 1;
}

static int ingest_cli(APP_CONFIG *cfg, int argc, char **argv) {
    char *log_lvl = NULL;
    int diff = 0;
    int aes_status = 0, tdes_status = 0,
        hash_status = 0, cmac_status = 0,
        hmac_status = 0;

#ifdef ACVP_NO_RUNTIME
    int dsa_status = 0, rsa_status = 0,
        drbg_status = 0, ecdsa_status = 0,
        kas_ecc_status = 0, kas_ffc_status = 0;
#endif
#ifdef OPENSSL_KDF_SUPPORT
    int kdf_status = 0;
#endif

#define ALG_DISABLE 0
#define ALG_ENABLE 1
#define OPTION_STR_MAX 16

    /* Set the default configuration values */
    default_config(cfg);

    argv++;
    argc--;
    while (argc >= 1) {
        /* version option used by itself, ignore remaining command line */
        strcmp_s("--version", strnlen_s("--version", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            printf("\nACVP library version(protocol version): %s(%s)\n", acvp_version(), acvp_protocol_version());
            return 1;
        }

        strcmp_s("--help", strnlen_s("--help", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            print_usage(0);
            return 1;
        }

        strcmp_s("--info", strnlen_s("--info", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (log_lvl) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nLog Level already set to \"%s\"."
                       "\nOnly 1 Log Level can be specified.\n", "--info", log_lvl);
                print_usage(1);
                return 1;
            }
            cfg->level = ACVP_LOG_LVL_INFO;
            log_lvl = "info";
            goto next;
        }

        strcmp_s("--status", strnlen_s("--status", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (log_lvl) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nLog Level already set to \"%s\"."
                       "\nOnly 1 Log Level can be specified.\n", "--status", log_lvl);
                print_usage(1);
                return 1;
            }
            cfg->level = ACVP_LOG_LVL_STATUS;
            log_lvl = "status";
            goto next;
        }

        strcmp_s("--warn", strnlen_s("--warn", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (log_lvl) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nLog Level already set to \"%s\"."
                       "\nOnly 1 Log Level can be specified.\n", "--warn", log_lvl);
                print_usage(1);
                return 1;
            }
            cfg->level = ACVP_LOG_LVL_WARN;
            log_lvl = "warn";
            goto next;
        }

        strcmp_s("--error", strnlen_s("--error", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (log_lvl) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nLog Level already set to \"%s\"."
                       "\nOnly 1 Log Level can be specified.\n", "--error", log_lvl);
                print_usage(1);
                return 1;
            }
            cfg->level = ACVP_LOG_LVL_ERR;
            log_lvl = "error";
            goto next;
        }

        strcmp_s("--none", strnlen_s("--none", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (log_lvl) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nLog Level already set to \"%s\"."
                       "\nOnly 1 Log Level can be specified.\n", "--none", log_lvl);
                print_usage(1);
                return 1;
            }
            cfg->level = ACVP_LOG_LVL_NONE;
            log_lvl = "none";
            goto next;
        }

        strcmp_s("--verbose", strnlen_s("--verbose", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (log_lvl) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nLog Level already set to \"%s\"."
                       "\nOnly 1 Log Level can be specified.\n", "--verbose", log_lvl);
                print_usage(1);
                return 1;
            }
            cfg->level = ACVP_LOG_LVL_VERBOSE;
            log_lvl = "verbose";
            goto next;
        }

        strcmp_s("--json", strnlen_s("--json", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            int filename_len = 0;

            cfg->json = 1;
            argc--;
            argv++;

            if (*argv == NULL) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nMissing <file>.\n", "--json");
                print_usage(1);
                return 1;
            }

            filename_len = strnlen_s(*argv, JSON_FILENAME_LENGTH + 1);
            if (filename_len > JSON_FILENAME_LENGTH) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--json", *argv, JSON_FILENAME_LENGTH);
                print_usage(1);
                return 1;
            }

            strcpy_s(cfg->json_file, JSON_FILENAME_LENGTH, *argv);
        }

        strcmp_s("--sample", strnlen_s("--sample", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            cfg->sample = 1;
            goto next;
        }

        strcmp_s("--dev", strnlen_s("--dev", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            cfg->dev = 1;
            goto next;
        }

        strcmp_s("--aes", strnlen_s("--aes", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->aes, &aes_status, ALG_ENABLE,
                               "--aes", "--no_aes")) return 1;
            goto next;
        }

        strcmp_s("--no_aes", strnlen_s("--no_aes", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->aes, &aes_status, ALG_DISABLE,
                               "--aes", "--no_aes")) return 1;
            goto next;
        }

        strcmp_s("--tdes", strnlen_s("--tdes", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->tdes, &tdes_status, ALG_ENABLE,
                               "--tdes", "--no_tdes")) return 1;
            goto next;
        }

        strcmp_s("--no_tdes", strnlen_s("--no_tdes", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->tdes, &tdes_status, ALG_DISABLE,
                               "--tdes", "--no_tdes")) return 1;
            goto next;
        }

        strcmp_s("--hash", strnlen_s("--hash", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->hash, &hash_status, ALG_ENABLE,
                               "--hash", "--no_hash")) return 1;
            goto next;
        }

        strcmp_s("--no_hash", strnlen_s("--no_hash", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->hash, &hash_status, ALG_DISABLE,
                               "--hash", "--no_hash")) return 1;
            goto next;
        }

        strcmp_s("--cmac", strnlen_s("--cmac", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->cmac, &cmac_status, ALG_ENABLE,
                               "--cmac", "--no_cmac")) return 1;
            goto next;
        }

        strcmp_s("--no_cmac", strnlen_s("--no_cmac", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->cmac, &cmac_status, ALG_DISABLE,
                               "--cmac", "--no_cmac")) return 1;
            goto next;
        }

        strcmp_s("--hmac", strnlen_s("--hmac", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->hmac, &hmac_status, ALG_ENABLE,
                               "--hmac", "--no_hmac")) return 1;
            goto next;
        }

        strcmp_s("--no_hmac", strnlen_s("--no_hmac", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->hmac, &hmac_status, ALG_DISABLE,
                               "--hmac", "--no_hmac")) return 1;
            goto next;
        }

        strcmp_s("--kdf", strnlen_s("--kdf", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef OPENSSL_KDF_SUPPORT
            if (cli_alg_option(&cfg->kdf, &kdf_status, ALG_ENABLE,
                               "--kdf", "--no_kdf")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DOPENSSL_KDF_SUPPORT"
                   "\nThis option will have no effect.\n", "--kdf");
#endif
            goto next;
        }

        strcmp_s("--no_kdf", strnlen_s("--no_kdf", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef OPENSSL_KDF_SUPPORT
            if (cli_alg_option(&cfg->kdf, &kdf_status, ALG_DISABLE,
                               "--kdf", "--no_kdf")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DOPENSSL_KDF_SUPPORT"
                   "\nThis option will have no effect.\n", "--no_kdf");
#endif
            goto next;
        }

        strcmp_s("--dsa", strnlen_s("--dsa", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->dsa, &dsa_status, ALG_ENABLE,
                               "--dsa", "--no_dsa")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--dsa");
#endif
            goto next;
        }

        strcmp_s("--no_dsa", strnlen_s("--no_dsa", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->dsa, &dsa_status, ALG_DISABLE,
                               "--dsa", "--no_dsa")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--no_dsa");
#endif
            goto next;
        }

        strcmp_s("--rsa", strnlen_s("--rsa", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->rsa, &rsa_status, ALG_ENABLE,
                               "--rsa", "--no_rsa")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--rsa");
#endif
            goto next;
        }

        strcmp_s("--no_rsa", strnlen_s("--no_rsa", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->rsa, &rsa_status, ALG_DISABLE,
                               "--rsa", "--no_rsa")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--no_rsa");
#endif
            goto next;
        }

        strcmp_s("--drbg", strnlen_s("--drbg", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->drbg, &drbg_status, ALG_ENABLE,
                               "--drbg", "--no_drbg")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect\n", "--drbg");
#endif
            goto next;
        }

        strcmp_s("--no_drbg", strnlen_s("--no_drbg", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->drbg, &drbg_status, ALG_DISABLE,
                               "--drbg", "--no_drbg")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nTHis option will have no effect.\n", "--no_drbg");
#endif
            goto next;
        }

        strcmp_s("--ecdsa", strnlen_s("--ecdsa", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->ecdsa, &ecdsa_status, ALG_ENABLE,
                               "--ecdsa", "--no_ecdsa")) return 1;
#else
            printf(ANSI_COLOR_YELLOW "Command warning... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--ecdsa");
#endif
            goto next;
        }

        strcmp_s("--no_ecdsa", strnlen_s("--no_ecdsa", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->ecdsa, &ecdsa_status, ALG_DISABLE,
                               "--ecdsa", "--no_ecdsa")) return 1;
#else
            printf(ANSI_COLOR_YELLOW "Command warning... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis options will have no effect.\n", "--no_ecdsa");
#endif
            goto next;
        }

        strcmp_s("--kas_ecc", strnlen_s("--kas_ecc", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->kas_ecc, &kas_ecc_status, ALG_ENABLE,
                               "--kas_ecc", "--no_kas_ecc")) return 1;
#else
            printf(ANSI_COLOR_YELLOW "Command warning... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--kas_ecc");
#endif
            goto next;
        }

        strcmp_s("--no_kas_ecc", strnlen_s("--no_kas_ecc", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->kas_ecc, &kas_ecc_status, ALG_DISABLE,
                               "--kas_ecc", "--no_kas_ecc")) return 1;
#else
            printf(ANSI_COLOR_YELLOW "Command warning... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--no_kas_ecc");
#endif
            goto next;
        }

        strcmp_s("--kas_ffc", strnlen_s("--kas_ffc", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->kas_ffc, &kas_ffc_status, ALG_ENABLE,
                               "--kas_ffc", "--no_kas_ffc")) return 1;
#else
            printf(ANSI_COLOR_YELLOW "Command warning... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--kas_ffc");
#endif
            goto next;
        }

        strcmp_s("--no_kas_ffc", strnlen_s("--no_kas_ffc", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->kas_ffc, &kas_ffc_status, ALG_DISABLE,
                               "--kas_ffc", "--no_kas_ffc")) return 1;
#else
            printf(ANSI_COLOR_YELLOW "Command warning... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--no_kas_ffc");
#endif
            goto next;
        }

        /* If you get here, the command wasn't recognized */
        printf("Command error... Option not recognized: \"%s\"", *argv);
        print_usage(1);
        return 1;
next:
        argv++;
        argc--;
    }
    printf("\n");

    return 0;
}

int main(int argc, char **argv) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_CTX *ctx = NULL;
    char ssl_version[10];
    APP_CONFIG cfg = { 0 };
    char *oe_name = "Ubuntu Linux 3.1 on AMD 6272 Opteron Processor with Acme package installed";
    ACVP_KV_LIST *key_val_list = calloc(1, sizeof(ACVP_KV_LIST));

    if (ingest_cli(&cfg, argc, argv)) {
        return 1;
    }

#ifdef ACVP_NO_RUNTIME
    fips_selftest_fail = 0;
    fips_mode = 0;
    fips_algtest_init_nofips();
#endif

    if (glb_cipher_ctx == NULL) {
        glb_cipher_ctx = EVP_CIPHER_CTX_new();
        if (glb_cipher_ctx == NULL) {
            printf("Failed to allocate global cipher_ctx");
            goto end;
        }
    }
    setup_session_parameters();

    /*
     * We begin the libacvp usage flow here.
     * First, we create a test session context.
     */
    rv = acvp_create_test_session(&ctx, &progress, cfg.level);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to create ACVP context: %s\n", acvp_lookup_error_string(rv));
        goto end;
    }

    if (cfg.dev) {
        rv = acvp_enable_debug_request(ctx);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to enable debug request: %s\n", acvp_lookup_error_string(rv));
            goto end;
        }
    }

    /*
     * Next we specify the ACVP server address
     */
    rv = acvp_set_server(ctx, server, port);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set server/port\n");
        goto end;
    }

    /*
     * Setup the vendor attributes
     */
    rv = acvp_set_vendor_info(ctx, "Acme Fictional Corporation", "www.acme-fictional.com", "Wyle E. Coyote", "wcoyote@acme-fictional.com");
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set vendor info\n");
        goto end;
    }

    /*
     * Setup the crypto module attributes
     */
    snprintf(ssl_version, 10, "%08x", (unsigned int)SSLeay());
    rv = acvp_set_module_info(ctx, "OpenSSL", "software", ssl_version, "FOM 6.2a");
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set module info\n");
        goto end;
    }

    key_val_list->key = calloc(4 + 1, sizeof(char));
    strcpy_s(key_val_list->key, 4, "type");
    key_val_list->value = calloc(8 + 1, sizeof(char));
    strcpy_s(key_val_list->value, 8, "software");

    key_val_list->next = calloc(1, sizeof(ACVP_KV_LIST));

    key_val_list->next->key = calloc(4 + 1, sizeof(char));
    strcpy_s(key_val_list->next->key, 4, "name");
    key_val_list->next->value = calloc(9 + 1, sizeof(char));
    strcpy_s(key_val_list->next->value, 9, "Linux 3.1");

    rv = acvp_add_oe_dependency(ctx, oe_name, key_val_list);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set module info\n");
        goto end;
    }

    /*
     * Set the api context prefix if needed
     */
    rv = acvp_set_api_context(ctx, api_context);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set URI prefix\n");
        goto end;
    }

    /*
     * Set the path segment prefix if needed
     */
    rv = acvp_set_path_segment(ctx, path_segment);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set URI prefix\n");
        goto end;
    }

    /*
     * Next we provide the CA certs to be used by libacvp
     * to verify the ACVP TLS certificate.
     */
    rv = acvp_set_cacerts(ctx, ca_chain_file);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set CA certs\n");
        goto end;
    }

    /*
     * Specify the certificate and private key the client should used
     * for TLS client auth.
     */
    rv = acvp_set_certkey(ctx, cert_file, key_file);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set TLS cert/key\n");
        goto end;
    }

    /*
     * Specify the callback to be used for 2-FA to perform
     * TOTP calculation
     */
    rv = acvp_set_2fa_callback(ctx, &totp);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set Two-factor authentication callback\n");
        goto end;
    }

    if (cfg.sample) {
        acvp_mark_as_sample(ctx);
    }

    if (cfg.json) {
        /*
         * Using a JSON to register allows us to skip the
         * "acvp_enable_*" API calls... could reduce the
         * size of this file if you choose to use this capability.
         */
        rv = acvp_set_json_filename(ctx, cfg.json_file);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set json file within ACVP ctx (rv=%d)\n", rv);
            goto end;
        }
    } else {
        /*
         * We need to register all the crypto module capabilities that will be
         * validated. Each has their own method for readability.
         */
        if (cfg.aes) {
            if (enable_aes(ctx)) goto end;
        }

        if (cfg.tdes) {
            if (enable_tdes(ctx)) goto end;
        }

        if (cfg.hash) {
            if (enable_hash(ctx)) goto end;
        }

        if (cfg.cmac) {
            if (enable_cmac(ctx)) goto end;
        }

        if (cfg.hmac) {
            if (enable_hmac(ctx)) goto end;
        }

#ifdef OPENSSL_KDF_SUPPORT
        if (cfg.kdf) {
            if (enable_kdf(ctx)) goto end;
        }
#endif

#ifdef ACVP_NO_RUNTIME
        if (cfg.dsa) {
            if (enable_dsa(ctx)) goto end;
        }

        if (cfg.rsa) {
            if (enable_rsa(ctx)) goto end;
        }

        if (cfg.ecdsa) {
            if (enable_ecdsa(ctx)) goto end;
        }

        if (cfg.drbg) {
            if (enable_drbg(ctx)) goto end;
        }

        if (cfg.kas_ecc) {
            if (enable_kas_ecc(ctx)) goto end;
        }
        if (cfg.kas_ffc) {
            if (enable_kas_ffc(ctx)) goto end;
        }
#endif
    }
    /*
     * Now that we have a test session, we register with
     * the server to advertise our capabilities and receive
     * the KAT vector sets the server demands that we process.
     */
    rv = acvp_register(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to register with ACVP server (rv=%d)\n", rv);
        goto end;
    }

    /*
     * Now we process the test cases given to us during
     * registration earlier.
     */
    rv = acvp_process_tests(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to process vectors (%d)\n", rv);
        goto end;
    }

    printf("\nTests complete, checking results...\n");
    rv = acvp_check_test_results(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Unable to retrieve test results (%d)\n", rv);
        goto end;
    }

end:
    if (glb_cipher_ctx) EVP_CIPHER_CTX_free(glb_cipher_ctx);
    /* free RSA group vals */
    if (group_rsa) RSA_free(group_rsa);
    if (group_n) BN_free(group_n);
    /* free DSA group vals */
    if (group_dsa) DSA_free(group_dsa);
    if (group_p) BN_free(group_p);
    if (group_q) BN_free(group_q);
    if (group_g) BN_free(group_g);
    if (group_pub_key) BN_free(group_pub_key);
    /* free ECDSA group vals */
    if (ecdsa_group_Qx) BN_free(ecdsa_group_Qx);
    if (ecdsa_group_Qy) BN_free(ecdsa_group_Qy);
    if (ecdsa_group_key) EC_KEY_free(ecdsa_group_key);
    /* Free all memory associated with libacvp */
    rv = acvp_cleanup(ctx);

    return rv;
}

static int enable_aes(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Enable AES_GCM
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_IVLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 136);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 264);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 136);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable AES-ECB 128,192,256 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_ECB, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PTLEN, 1536);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable AES-CBC 128 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PTLEN, 1536);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable AES-CFB1 128,192,256 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB1, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PTLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable AES-CFB8 128,192,256 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB8, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PTLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable AES-CFB128 128,192,256 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB128, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PTLEN, 1536);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable AES-OFB 128, 192, 256 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_OFB, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PTLEN, 1536);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Register AES CCM capabilities
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CCM, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_CCM, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PTLEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PTLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 56);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 104);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable AES keywrap for various key sizes and PT lengths
     * Note: this is with padding disabled, minimum PT length is 128 bits and must be
     *       a multiple of 64 bits. openssl does not support INVERSE mode.
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_KW, &app_aes_keywrap_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 1280);
    CHECK_ENABLE_CAP_RV(rv);
#ifdef OPENSSL_KWP
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_KWP, &app_aes_keywrap_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 72);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 808);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    /*
     * Enable AES-XTS 128 and 256 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_XTS, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PTLEN, 65536);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_TWEAK, ACVP_SYM_CIPH_TWEAK_HEX);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable AES-CTR 128, 192, 256 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CTR, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CTR_INCR, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PTLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

static int enable_tdes(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Enable 3DES-ECB
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_ECB, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PTLEN, 512);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable 3DES-CBC
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CBC, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_IVLEN, 192 / 3);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 3);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 12);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable 3DES-OFB
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_OFB, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_IVLEN, 192 / 3);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PTLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable 3DES-CFB64
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB64, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_IVLEN, 192 / 3);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PTLEN, 64 * 5);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable 3DES-CFB8
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB8, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_IVLEN, 192 / 3);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PTLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PTLEN, 64 * 4);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable 3DES-CFB1
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB1, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_IVLEN, 192 / 3);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PTLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

static int enable_hash(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Enable SHA-1 and SHA-2
     */
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA1, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA1, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA224, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA224, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA224, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA256, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA256, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA384, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA384, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA384, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA512, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

static int enable_cmac(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Enable CMAC
     */
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &app_cmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_AES, ACVP_CMAC_MSGLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_MACLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_AES, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_GEN, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_VER, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_TDES, &app_cmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_TDES, ACVP_CMAC_MSGLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_MACLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_DIRECTION_GEN, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_DIRECTION_VER, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_KEYING_OPTION, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_TDES, ACVP_PREREQ_TDES, value);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

static int enable_hmac(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA1, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_KEYLEN, 256, 448, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_MACLEN, 32, 160, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA1, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_224, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_KEYLEN, 256, 448, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_MACLEN, 32, 224, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_224, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_256, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_KEYLEN, 256, 448, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_MACLEN, 32, 256, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_256, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_384, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_KEYLEN, 256, 448, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_MACLEN, 32, 384, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_384, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN, 256, 448, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_MACLEN, 32, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_512, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

#ifdef OPENSSL_KDF_SUPPORT
#define ENGID1 "800002B805123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
#define ENGID2 "000002b87766554433221100"
static int enable_kdf(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    int i, flags = 0;

    /*
     * Enable KDF-135
     */
    rv = acvp_cap_kdf135_tls_enable(ctx, &app_kdf135_tls_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_TLS, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_TLS, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_tls_set_parm(ctx, ACVP_KDF135_TLS, ACVP_KDF135_TLS12,
                                      ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kdf135_snmp_enable(ctx, &app_kdf135_snmp_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SNMP, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_snmp_set_engid(ctx, ACVP_KDF135_SNMP, ENGID1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_snmp_set_engid(ctx, ACVP_KDF135_SNMP, ENGID2);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kdf135_ssh_enable(ctx, &app_kdf135_ssh_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);

    //Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256
            | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kdf135_srtp_enable(ctx, &app_kdf135_srtp_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SRTP, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_SUPPORT_ZERO_KDR, 0);
    CHECK_ENABLE_CAP_RV(rv);
    for (i = 0; i < 24; i++) {
        rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_KDF_EXPONENT, i + 1);
        CHECK_ENABLE_CAP_RV(rv);
    }
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kdf135_ikev2_enable(ctx, &app_kdf135_ikev2_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV2, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV2, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    // can use len_param or domain_param for these attributes
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_INIT_NONCE_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_INIT_NONCE_LEN, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_RESPOND_NONCE_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_RESPOND_NONCE_LEN, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_DH_SECRET_LEN, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_KEY_MATERIAL_LEN, 1056);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_KEY_MATERIAL_LEN, 3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ikev2_set_parm(ctx, ACVP_KDF_HASH_ALG, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kdf135_ikev1_enable(ctx, &app_kdf135_ikev1_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV1, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV1, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_INIT_NONCE_LEN, 64, 2048, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_RESPOND_NONCE_LEN, 64, 2048, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_DH_SECRET_LEN, 224, 8192, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_PSK_LEN, 8, 8192, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_AUTH_METHOD, ACVP_KDF135_IKEV1_AMETH_PSK);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kdf135_x963_enable(ctx, &app_kdf135_x963_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_KEY_DATA_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_KEY_DATA_LEN, 1024);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_FIELD_SIZE, 224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_FIELD_SIZE, 521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_SHARED_INFO_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_SHARED_INFO_LEN, 1024);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * KDF108 Counter Mode
     */
    rv = acvp_cap_kdf108_enable(ctx, &app_kdf108_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF108, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_COUNTER_LEN, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_AFTER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTS_EMPTY_IV, 0);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}
#endif

#ifdef ACVP_NO_RUNTIME
static int enable_kas_ecc(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Enable KAS-ECC....
     */
    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &app_kas_ecc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_PREREQ_ECDSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_COMP, &app_kas_ecc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_ECDSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CCM, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_KDF, 0, ACVP_KAS_ECC_NOKDFNOKC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EB, ACVP_EC_CURVE_P224, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EC, ACVP_EC_CURVE_P256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ED, ACVP_EC_CURVE_P384, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EE, ACVP_EC_CURVE_P521, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

static int enable_kas_ffc(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Enable KAS-FFC....
     */
    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_COMP, &app_kas_ffc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_DSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_CCM, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_CMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPGEN);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPVAL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_KDF, ACVP_KAS_FFC_NOKDFNOKC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FC, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

static int enable_dsa(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Enable DSA....
     */
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGGEN, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENPQ, ACVP_DSA_PROBABLE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENG, ACVP_DSA_CANONICAL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN3072_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN3072_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN3072_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGVER, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_GENPQ, ACVP_DSA_PROBABLE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_GENG, ACVP_DSA_CANONICAL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN3072_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN3072_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN3072_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);


    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_KEYGEN, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_KEYGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_KEYGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_224, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_224, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_224, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_224, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_256, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN3072_256, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN3072_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN3072_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN3072_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);


    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_SIGGEN, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);


    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_SIGVER, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

static int enable_rsa(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    BIGNUM *expo = NULL;
    char *expo_str = NULL;

    expo = FIPS_bn_new();
    if (!expo || !BN_set_word(expo, RSA_F4)) {
        printf("oh no\n");
        return 1;
    }
    expo_str = BN_bn2hex(expo);
    FIPS_bn_free(expo);

    /*
     * Enable RSA keygen...
     */
    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &app_rsa_keygen_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_INFO_GEN_BY_SERVER, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_KEY_FORMAT_CRT, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_rsa_keygen_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B34);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 2048,
                                        ACVP_RSA_PRIME_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 3072,
                                        ACVP_RSA_PRIME_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable siggen
     */
    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGGEN, &app_rsa_sig_handler);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: X9.31
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 // mod 4096 isn't supported by the server just yet
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    // RSA w/ sigType: PKCS1v1.5
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 // mod 4096 isn't supported by the server just yet
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable sigver
     */
    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGVER, &app_rsa_sig_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_rsa_sigver_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: X9.31
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1v1.5
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

end:
    if (expo_str) free(expo_str);

    return rv;
}

static int enable_ecdsa(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Enable ECDSA keyGen...
     */
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYGEN, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_SECRET_GEN, ACVP_ECDSA_SECRET_GEN_TEST_CAND);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable ECDSA keyVer...
     */
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYVER, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);


    /*
     * Enable ECDSA sigGen...
     */
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGGEN, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Enable ECDSA sigVer...
     */
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGVER, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

static int enable_drbg(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Register DRBG
     */
    ERR_load_crypto_strings();

    int fips_rc = FIPS_mode_set(1);
    if (!fips_rc) {
        (printf("Failed to enable FIPS mode.\n"));
        return 1;
    }

    rv = acvp_cap_drbg_enable(ctx, ACVP_HASHDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                ACVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_prereq(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                  ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                  ACVP_DRBG_ENTROPY_LEN, (int)128, (int)64, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                  ACVP_DRBG_NONCE_LEN, (int)96, (int)32, (int)128);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                  ACVP_DRBG_PERSO_LEN, (int)0, (int)128, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                  ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                ACVP_DRBG_RET_BITS_LEN, 160);
    CHECK_ENABLE_CAP_RV(rv);

#if 0 /* TODO: get DRBG to support multiple instances of each flavor */
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224,
                                ACVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_prereq(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224,
                                  ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224,
                                ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224,
                                ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224,
                                ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224,
                                  ACVP_DRBG_ENTROPY_LEN, (int)192, (int)64, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224,
                                  ACVP_DRBG_NONCE_LEN, (int)128, (int)32, (int)160);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224,
                                  ACVP_DRBG_PERSO_LEN, (int)0, (int)128, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224,
                                  ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224,
                                ACVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256,
                                ACVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_prereq(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256,
                                  ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256,
                                ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256,
                                ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256,
                                ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256,
                                  ACVP_DRBG_ENTROPY_LEN, (int)256, (int)64, (int)320);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256,
                                  ACVP_DRBG_NONCE_LEN, (int)128, (int)32, (int)160);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256,
                                  ACVP_DRBG_PERSO_LEN, (int)0, (int)128, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256,
                                  ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256,
                                ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384,
                                ACVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_prereq(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384,
                                  ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384,
                                ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384,
                                ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384,
                                ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384,
                                  ACVP_DRBG_ENTROPY_LEN, (int)256, (int)64, (int)320);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384,
                                  ACVP_DRBG_NONCE_LEN, (int)128, (int)32, (int)160);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384,
                                  ACVP_DRBG_PERSO_LEN, (int)0, (int)128, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384,
                                  ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384,
                                ACVP_DRBG_RET_BITS_LEN, 384);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512,
                                ACVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_prereq(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512,
                                  ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512,
                                ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512,
                                ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512,
                                ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512,
                                  ACVP_DRBG_ENTROPY_LEN, (int)256, (int)64, (int)320);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512,
                                  ACVP_DRBG_NONCE_LEN, (int)128, (int)32, (int)160);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512,
                                  ACVP_DRBG_PERSO_LEN, (int)0, (int)128, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512,
                                  ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512,
                                ACVP_DRBG_RET_BITS_LEN, 512);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    //ACVP_HMACDRBG

    rv = acvp_cap_drbg_enable(ctx, ACVP_HMACDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_prereq(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                  ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_prereq(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                  ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                ACVP_DRBG_DER_FUNC_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                ACVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);

    //Add length range
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                  ACVP_DRBG_ENTROPY_LEN, (int)192, (int)64, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                  ACVP_DRBG_NONCE_LEN, (int)192, (int)64, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                  ACVP_DRBG_PERSO_LEN, (int)0, (int)128, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                  ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    // ACVP_CTRDRBG
    rv = acvp_cap_drbg_enable(ctx, ACVP_CTRDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_prereq(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                  ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);

    //Add length range
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                  ACVP_DRBG_ENTROPY_LEN, (int)128, (int)128, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                  ACVP_DRBG_NONCE_LEN, (int)64, (int)64, (int)128);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                  ACVP_DRBG_PERSO_LEN, (int)0, (int)256, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                  ACVP_DRBG_ADD_IN_LEN, (int)0, (int)256, (int)256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                ACVP_DRBG_DER_FUNC_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                ACVP_DRBG_RESEED_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}
#endif

static int app_des_handler(ACVP_TEST_CASE *test_case) {
    ACVP_SYM_CIPHER_TC      *tc;
    EVP_CIPHER_CTX *cipher_ctx;
    const EVP_CIPHER        *cipher;
    int ct_len, pt_len;
    unsigned char *iv = 0;

    if (!test_case) {
        return 1;
    }

    tc = test_case->tc.symmetric;

    /*
     * We only support 3 key DES
     */
    if (tc->key_len != 192) {
        printf("Unsupported DES key length\n");
        return 1;
    }

    /* Begin encrypt code section */
    cipher_ctx = glb_cipher_ctx;

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
        return 1;

        break;
    }

    /* If Monte Carlo we need to be able to init and then update
     * one thousand times before we complete each iteration.
     */
    if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT) {
        const unsigned char *ctx_iv = NULL;


#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        ctx_iv = cipher_ctx->iv;
#else
        ctx_iv = EVP_CIPHER_CTX_iv(cipher_ctx);
#endif

#define SYM_IV_BYTE_MAX 128
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
            if (tc->mct_index == 0) {
                EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, tc->key, iv);
                EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            } else {
                /* TDES needs the pre-operation IV returned */
                memcpy_s(tc->iv_ret, SYM_IV_BYTE_MAX, ctx_iv, 8);
            }
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }

            EVP_EncryptUpdate(cipher_ctx, tc->ct, &ct_len, tc->pt, tc->pt_len);
            tc->ct_len = ct_len;
            /* TDES needs the post-operation IV returned */
            memcpy_s(tc->iv_ret_after, SYM_IV_BYTE_MAX, ctx_iv, 8);
        } else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
            if (tc->mct_index == 0) {
                EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, tc->key, iv);
                EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            } else {
                /* TDES needs the pre-operation IV returned */
                memcpy_s(tc->iv_ret, SYM_IV_BYTE_MAX, ctx_iv, 8);
            }
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }
            EVP_DecryptUpdate(cipher_ctx, tc->pt, &pt_len, tc->ct, tc->ct_len);
            tc->pt_len = pt_len;
            /* TDES needs the post-operation IV returned */
            memcpy_s(tc->iv_ret_after, SYM_IV_BYTE_MAX, ctx_iv, 8);
        } else {
            printf("Unsupported direction\n");
            return 1;
        }
        if (tc->mct_index == 9999) {
            EVP_CIPHER_CTX_cleanup(cipher_ctx);
        }
    } else {
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
            EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, tc->key, iv);
            EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }
            EVP_EncryptUpdate(cipher_ctx, tc->ct, &ct_len, tc->pt, tc->pt_len);
            tc->ct_len = ct_len;
            EVP_EncryptFinal_ex(cipher_ctx, tc->ct + ct_len, &ct_len);
            tc->ct_len += ct_len;
        } else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
            EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, tc->key, iv);
            EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }
            EVP_DecryptUpdate(cipher_ctx, tc->pt, &pt_len, tc->ct, tc->ct_len);
            tc->pt_len = pt_len;
            EVP_DecryptFinal_ex(cipher_ctx, tc->pt + pt_len, &pt_len);
            tc->pt_len += pt_len;
        } else {
            printf("Unsupported direction\n");
            return 1;
        }

        EVP_CIPHER_CTX_cleanup(cipher_ctx);
    }

    return 0;
}

static int app_aes_handler(ACVP_TEST_CASE *test_case) {
    ACVP_SYM_CIPHER_TC      *tc;
    EVP_CIPHER_CTX *cipher_ctx;
    const EVP_CIPHER        *cipher;
    int ct_len, pt_len;
    unsigned char *iv = 0;
    /* assume fail at first */
    int rv = 1;

    if (!test_case) {
        return rv;
    }

    tc = test_case->tc.symmetric;

    /* Begin encrypt code section */
    cipher_ctx = glb_cipher_ctx;
    if ((tc->test_type != ACVP_SYM_TEST_TYPE_MCT)) {
        EVP_CIPHER_CTX_init(cipher_ctx);
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
            return rv;

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
            return rv;

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
            return rv;

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
            return rv;

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
            return rv;

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
            return rv;

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
            return rv;

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
            return rv;

            break;
        }
        break;
    default:
        printf("Error: Unsupported AES mode requested by ACVP server\n");
        return rv;

        break;
    }

    /* If Monte Carlo we need to be able to init and then update
     * one thousand times before we complete each iteration.
     */
    if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT) {
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
            if (tc->mct_index == 0) {
                EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, tc->key, iv);
                EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
                if (tc->cipher == ACVP_AES_CFB1) {
                    EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
                }
            }
            EVP_EncryptUpdate(cipher_ctx, tc->ct, &ct_len, tc->pt, tc->pt_len);
            tc->ct_len = ct_len;
        } else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
            if (tc->mct_index == 0) {
                EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, tc->key, iv);
                EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
                if (tc->cipher == ACVP_AES_CFB1) {
                    EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
                }
            }
            EVP_DecryptUpdate(cipher_ctx, tc->pt, &pt_len, tc->ct, tc->ct_len);
            tc->pt_len = pt_len;
        } else {
            printf("Unsupported direction\n");
            return rv;
        }
        if (tc->mct_index == 999) {
            EVP_CIPHER_CTX_cleanup(cipher_ctx);
        }
    } else {
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
            EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, tc->key, iv);
            EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            if (tc->cipher == ACVP_AES_CFB1) {
                EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }
            EVP_EncryptUpdate(cipher_ctx, tc->ct, &ct_len, tc->pt, tc->pt_len);
            tc->ct_len = ct_len;
            EVP_EncryptFinal_ex(cipher_ctx, tc->ct + ct_len, &ct_len);
            tc->ct_len += ct_len;
        } else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
            EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, tc->key, iv);
            EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            if (tc->cipher == ACVP_AES_CFB1) {
                EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }
            EVP_DecryptUpdate(cipher_ctx, tc->pt, &pt_len, tc->ct, tc->ct_len);
            tc->pt_len = pt_len;
            EVP_DecryptFinal_ex(cipher_ctx, tc->pt + pt_len, &pt_len);
            tc->pt_len += pt_len;
        } else {
            printf("Unsupported direction\n");
            return rv;
        }
        EVP_CIPHER_CTX_cleanup(cipher_ctx);
    }

    return 0;
}

/* NOTE - openssl does not support inverse option */
static int app_aes_keywrap_handler(ACVP_TEST_CASE *test_case) {
    ACVP_SYM_CIPHER_TC      *tc;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    const EVP_CIPHER        *cipher;
    int c_len;
    int rc = 1;

    if (!test_case) {
        return rc;
    }

    tc = test_case->tc.symmetric;

    if (tc->kwcipher != ACVP_SYM_KW_CIPHER) {
        return rc;
    }

    /* Begin encrypt code section */
    cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(cipher_ctx);

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
            goto end;
        }
        break;
    default:
        printf("Error: Unsupported AES keywrap mode requested by ACVP server\n");
        goto end;
    }

    if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
        EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, NULL, 1);
        c_len = EVP_Cipher(cipher_ctx, tc->ct, tc->pt, tc->pt_len);
        if (c_len <= 0) {
            printf("Error: key wrap operation failed (%d)\n", c_len);
            goto end;
        } else {
            tc->ct_len = c_len;
        }
    } else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
        EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, NULL, 0);

#ifdef OPENSSL_KWP
        if (tc->cipher == ACVP_AES_KWP) {
            EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPHER_CTX_FLAG_UNWRAP_WITHPAD);
        }
#endif
        c_len = EVP_Cipher(cipher_ctx, tc->pt, tc->ct, tc->ct_len);
        if (c_len <= 0) {
            goto end;
        } else {
            tc->pt_len = c_len;
        }
    } else {
        printf("Unsupported direction\n");
        goto end;
    }
    rc = 0;

end:
    /* Cleanup */
    if (cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);

    return rc;
}

/*
 * This fuction is invoked by libacvp when an AES crypto
 * operation is needed from the crypto module being
 * validated.  This is a callback provided to libacvp when
 * acvp_enable_capability() is invoked to register the
 * AES-GCM capabilitiy with libacvp.  libacvp will in turn
 * invoke this function when it needs to process an AES-GCM
 * test case.
 */
static int app_aes_handler_aead(ACVP_TEST_CASE *test_case) {
    ACVP_SYM_CIPHER_TC      *tc;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    const EVP_CIPHER        *cipher;
    unsigned char iv_fixed[4] = { 1, 2, 3, 4 };
    int rc = 0;
    int ret = 0;

    if (!test_case) {
        return 1;
    }

    tc = test_case->tc.symmetric;

    if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT && tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
        printf("Unsupported direction\n");
        return 1;
    }

    /* Begin encrypt code section */
    cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(cipher_ctx);

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
            rc = 1;
            goto end;
        }
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
            EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_NON_FIPS_ALLOW);
            EVP_CipherInit(cipher_ctx, cipher, NULL, NULL, 1);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, tc->iv_len, 0);
            EVP_CipherInit(cipher_ctx, NULL, tc->key, NULL, 1);

            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IV_FIXED, 4, iv_fixed);
            if (!EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_IV_GEN, tc->iv_len, tc->iv)) {
                printf("acvp_aes_encrypt: iv gen error\n");
                rc = 1;
                goto end;
            }
            if (tc->aad_len) {
                EVP_Cipher(cipher_ctx, NULL, tc->aad, tc->aad_len);
            }
            EVP_Cipher(cipher_ctx, tc->ct, tc->pt, tc->pt_len);
            EVP_Cipher(cipher_ctx, NULL, NULL, 0);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, tc->tag_len, tc->tag);
        } else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
            EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_NON_FIPS_ALLOW);
            EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, NULL, 0);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, tc->iv_len, 0);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IV_FIXED, -1, tc->iv);
            if (!EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_IV_GEN, tc->iv_len, tc->iv)) {
                printf("\nFailed to set IV");
                rc = 1;
                goto end;
            }
            if (tc->aad_len) {
                /*
                 * Set dummy tag before processing AAD.  Otherwise the AAD can
                 * not be processed.
                 */
                EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, tc->tag_len, tc->tag);
                EVP_Cipher(cipher_ctx, NULL, tc->aad, tc->aad_len);
            }
            /*
             * Set the tag when decrypting
             */
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, tc->tag_len, tc->tag);

            /*
             * Decrypt the CT
             */
            EVP_Cipher(cipher_ctx, tc->pt, tc->ct, tc->ct_len);
            /*
             * Check the tag
             */
            ret = EVP_Cipher(cipher_ctx, NULL, NULL, 0);
            if (ret) {
                rc = 1;
                goto end;
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
            rc = 1;
            goto end;
        }
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
            EVP_CipherInit(cipher_ctx, cipher, NULL, NULL, 1);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_CCM_SET_IVLEN, tc->iv_len, 0);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_CCM_SET_TAG, tc->tag_len, 0);
            EVP_CipherInit(cipher_ctx, NULL, tc->key, tc->iv, 1);
            EVP_Cipher(cipher_ctx, NULL, NULL, tc->pt_len);
            EVP_Cipher(cipher_ctx, NULL, tc->aad, tc->aad_len);
            EVP_Cipher(cipher_ctx, tc->ct, tc->pt, tc->pt_len);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_CCM_GET_TAG, tc->tag_len, tc->ct + tc->ct_len);
            tc->ct_len += tc->tag_len;
        } else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
            EVP_CipherInit(cipher_ctx, cipher, NULL, NULL, 0);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_CCM_SET_IVLEN, tc->iv_len, 0);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_CCM_SET_TAG, tc->tag_len, tc->ct + tc->pt_len);
            EVP_CipherInit(cipher_ctx, NULL, tc->key, tc->iv, 0);
            EVP_Cipher(cipher_ctx, NULL, NULL, tc->pt_len);
            EVP_Cipher(cipher_ctx, NULL, tc->aad, tc->aad_len);
            /*
             * Decrypt and check the tag
             */
            ret = EVP_Cipher(cipher_ctx, tc->pt, tc->ct, tc->ct_len);
            if (ret < 0) {
                rc = 1;
                goto end;
            }
        }
        break;
    default:
        printf("Error: Unsupported AES AEAD mode requested by ACVP server\n");
        rc = 1;
        goto end;
    }

end:
    /* Cleanup */
    if (cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);

    return rc;
}

static int app_sha_handler(ACVP_TEST_CASE *test_case) {
    ACVP_HASH_TC    *tc;
    const EVP_MD    *md;
    EVP_MD_CTX *md_ctx = NULL;
    /* assume fail */
    int rc = 1;

    if (!test_case) {
        return 1;
    }

    tc = test_case->tc.hash;
    if (!tc) return rc;

    switch (tc->cipher) {
    case ACVP_HASH_SHA1:
        md = EVP_sha1();
        break;
    case ACVP_HASH_SHA224:
        md = EVP_sha224();
        break;
    case ACVP_HASH_SHA256:
        md = EVP_sha256();
        break;
    case ACVP_HASH_SHA384:
        md = EVP_sha384();
        break;
    case ACVP_HASH_SHA512:
        md = EVP_sha512();
        break;
    default:
        printf("Error: Unsupported hash algorithm requested by ACVP server\n");
        return ACVP_NO_CAP;

        break;
    }
    
    if (!tc->md) {
        printf("\nCrypto module error, md memory not allocated by library\n");
        goto end;
    }
    md_ctx = EVP_MD_CTX_create();

    /* If Monte Carlo we need to be able to init and then update
     * one thousand times before we complete each iteration.
     */
    if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT) {
        if (!tc->m1 || !tc->m2 || !tc->m3) {
            printf("\nCrypto module error, m1, m2, or m3 missing in sha mct test case\n");
            goto end;
        }
        if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
            printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
            goto end;
        }
        if (!EVP_DigestUpdate(md_ctx, tc->m1, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestUpdate(md_ctx, tc->m2, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestUpdate(md_ctx, tc->m3, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestFinal(md_ctx, tc->md, &tc->md_len)) {
            printf("\nCrypto module error, EVP_DigestFinal failed\n");
            goto end;
        }
    } else {
        if (!tc->msg) {
            printf("\nCrypto module error, msg missing in sha test case\n");
            goto end;
        }
        if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
            printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
            goto end;
        }

        if (!EVP_DigestUpdate(md_ctx, tc->msg, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestFinal(md_ctx, tc->md, &tc->md_len)) {
            printf("\nCrypto module error, EVP_DigestFinal failed\n");
            goto end;
        }
    }

    rc = 0;

end:
    if (md_ctx) EVP_MD_CTX_destroy(md_ctx);

    return rc;
}

static int app_hmac_handler(ACVP_TEST_CASE *test_case) {
    ACVP_HMAC_TC    *tc;
    const EVP_MD    *md;
    HMAC_CTX *hmac_ctx = NULL;
    int msg_len;
    int rc = 1;

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    HMAC_CTX static_ctx;
#endif

    if (!test_case) {
        return rc;
    }

    tc = test_case->tc.hmac;
    if (!tc) return rc;
    
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
        return rc;

        break;
    }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    hmac_ctx = &static_ctx;
    HMAC_CTX_init(hmac_ctx);
#else
    hmac_ctx = HMAC_CTX_new();
#endif
    msg_len = tc->msg_len;

    if (!HMAC_Init_ex(hmac_ctx, tc->key, tc->key_len, md, NULL)) {
        printf("\nCrypto module error, HMAC_Init_ex failed\n");
        goto end;
    }

    if (!HMAC_Update(hmac_ctx, tc->msg, msg_len)) {
        printf("\nCrypto module error, HMAC_Update failed\n");
        goto end;
    }

    if (!HMAC_Final(hmac_ctx, tc->mac, &tc->mac_len)) {
        printf("\nCrypto module error, HMAC_Final failed\n");
        goto end;
    }

    rc = 0;

end:
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    HMAC_CTX_cleanup(hmac_ctx);
#else
    if (hmac_ctx) HMAC_CTX_free(hmac_ctx);
#endif

    return rc;
}

static int app_cmac_handler(ACVP_TEST_CASE *test_case) {
    ACVP_CMAC_TC    *tc;
    int rv = 1;
    const EVP_CIPHER    *c = NULL;
    CMAC_CTX       *cmac_ctx = NULL;
    int key_len, i;
    unsigned char mac_compare[16] = { 0 };
    char full_key[32] = { 0 };
    int mac_cmp_len;

    if (!test_case) {
        return rv;
    }

    tc = test_case->tc.cmac;
    if (!tc) return rv;
    if (!tc->key) return rv;

    switch (tc->cipher) {
    case ACVP_CMAC_AES:
        switch (tc->key_len * 8) {
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
        key_len = (tc->key_len);
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
            full_key[i] = tc->key2[i % 8];
        }
        for (; i < 24; i++) {
            full_key[i] = tc->key3[i % 8];
        }
        key_len = 24;
        break;
    default:
        printf("Error: Unsupported CMAC algorithm requested by ACVP server\n");
        return rv;
    }

    full_key[key_len] = '\0';

    cmac_ctx = CMAC_CTX_new();

    if (!CMAC_Init(cmac_ctx, full_key, key_len, c, NULL)) {
        printf("\nCrypto module error, CMAC_Init_ex failed\n");
        goto cleanup;
    }

    if (!CMAC_Update(cmac_ctx, tc->msg, tc->msg_len)) {
        printf("\nCrypto module error, CMAC_Update failed\n");
        goto cleanup;
    }

    if (tc->verify) {
        int diff = 0;

        if (!CMAC_Final(cmac_ctx, mac_compare, (size_t *)&mac_cmp_len)) {
            printf("\nCrypto module error, CMAC_Final failed\n");
            goto cleanup;
        }

        memcmp_s(tc->mac, tc->mac_len, mac_compare, mac_cmp_len, &diff);
        if (!diff) {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_PASS;
        } else {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_FAIL;
        }
    } else {
        if (!CMAC_Final(cmac_ctx, tc->mac, (size_t *)&tc->mac_len)) {
            printf("\nCrypto module error, CMAC_Final failed\n");
            goto cleanup;
        }
    }
    rv = 0;

cleanup:
    if (cmac_ctx) CMAC_CTX_free(cmac_ctx);

    return rv;
}

#ifdef OPENSSL_KDF_SUPPORT
static int app_kdf135_srtp_handler(ACVP_TEST_CASE *test_case) {
    return 1;
}

static int app_kdf135_ikev2_handler(ACVP_TEST_CASE *test_case) {
    return 1;
}

static int app_kdf135_ikev1_handler(ACVP_TEST_CASE *test_case) {
    return 1;
}

static int app_kdf135_x963_handler(ACVP_TEST_CASE *test_case) {
    return 1;
}

static int app_kdf108_handler(ACVP_TEST_CASE *test_case) {
    return 1;
}

static int app_kdf135_tls_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDF135_TLS_TC    *tc;
    unsigned char *key_block1, *key_block2, *master_secret1, *master_secret2;
    int olen1 = 0, olen2 = 0, len1, ret, i, len, count, psm_len;
    const EVP_MD *evp_md1 = NULL, *evp_md2 = NULL;

    tc = test_case->tc.kdf135_tls;
    /* We only support TLS12 for now */
    if (tc->method != ACVP_KDF135_TLS12) {
        printf("\nCrypto module error, Bad TLS type\n");
        return 1;
    }

    olen1 = tc->pm_len;
    olen2 = tc->kb_len;
    key_block1 = tc->kblock1;
    key_block2 = tc->kblock2;
    master_secret1 = tc->msecret1;
    master_secret2 = tc->msecret2;

    if (!key_block1 || !key_block2 || !master_secret1 || !master_secret2) {
        printf("\nCrypto module error, malloc failure\n");
        return 1;
    }

    switch (tc->md) {
    case ACVP_SHA256:
        evp_md1 = evp_md2 = EVP_sha256();
        break;
    case ACVP_SHA384:
        evp_md1 = evp_md2 = EVP_sha384();
        break;
    case ACVP_SHA512:
        evp_md1 = evp_md2 = EVP_sha512();
        break;
    default:
        printf("\nCrypto module error, Bad SHA type\n");
        return 1;
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
        return 1;
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
            return 1;
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
        return 1;
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
            return 1;
        }
        for (i = 0; i < olen2; i++) {
            key_block1[i] ^= key_block2[i];
        }
    }

    return 0;
}

static int app_kdf135_snmp_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDF135_SNMP_TC    *tc;
    unsigned char *s_key;
    /* start with ret = 1 - assume fail */
    int p_len, ret = 1;

    tc = test_case->tc.kdf135_snmp;
    s_key = tc->s_key;
    p_len = tc->p_len;

    if (!s_key) {
        printf("\nCrypto module error, malloc failure\n");
        return ret;
    }

    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    if (ret) {
        printf("\nCrypto module error, kdf snmp failure\n");
        return ret;
    }

    tc->skey_len = strnlen_s((const char *)s_key, ACVP_KDF135_SNMP_SKEY_MAX);

    return ret;
}

static int app_kdf135_ssh_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDF135_SSH_TC *tc = NULL;
    const EVP_MD *evp_md = NULL;
    /* 0 is pass, 1 is fail; start with assumed fail */
    int ret = 1;

    tc = test_case->tc.kdf135_ssh;

    switch (tc->sha_type) {
    case ACVP_SHA1:
        evp_md = EVP_sha1();
        break;
    case ACVP_SHA224:
        evp_md = EVP_sha224();
        break;
    case ACVP_SHA256:
        evp_md = EVP_sha256();
        break;
    case ACVP_SHA384:
        evp_md = EVP_sha384();
        break;
    case ACVP_SHA512:
        evp_md = EVP_sha512();
        break;
    default:
        printf("\nCrypto module error, Bad SHA type\n");
        return 1;
    }

    /*
     * Initial IV client to server: HASH(K || H || "A" || session_id)
     * (Here K is encoded as mpint and "A" as byte and session_id as raw
     * data.  "A" means the single character A, ASCII 65).
     *
     * Initial IV server to client: HASH(K || H || "B" || session_id)
     *
     * Encryption key client to server: HASH(K || H || "C" || session_id)
     *
     * Encryption key server to client: HASH(K || H || "D" || session_id)
     *
     * Integrity key client to server: HASH(K || H || "E" || session_id)
     *
     * Integrity key server to client: HASH(K || H || "F" || session_id)
     */

    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 1;
    if (ret != 0) {
        printf("\nCrypto module error, kdf ssh cs_init_iv failure\n");
        return ret;
    }

    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 1;
    if (ret != 0) {
        printf("\nCrypto module error, kdf ssh sc_init_iv failure\n");
        return ret;
    }

    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 1;
    if (ret != 0) {
        printf("\nCrypto module error, kdf ssh cs_encrypt_key failure\n");
        return ret;
    }

    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 1;
    if (ret != 0) {
        printf("\nCrypto module error, kdf ssh sc_encrypt_key failure\n");
        return ret;
    }

    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 1;
    if (ret != 0) {
        printf("\nCrypto module error, kdf ssh cs_integrity_key failure\n");
        return ret;
    }

    /*
     * IMPORTANT: Need to set ret = <your KDF API here>
     * The default is set to failure as this is not
     * currently supported in OpenSSL
     */
    ret = 1;
    if (ret != 0) {
        printf("\nCrypto module error, kdf ssh sc_integrity_key failure\n");
        return ret;
    }

    return ret;
}
#endif

//Must be commented out if the user is Making with Makefile.fom
#ifdef ACVP_NO_RUNTIME
/*
 * group values are declared near the top so that they
 * can be freed at the end of main execution
 */
static int app_dsa_handler(ACVP_TEST_CASE *test_case) {
    int L, N, n, r;
    const EVP_MD        *md = NULL;
    ACVP_DSA_TC         *tc;
    unsigned char seed[1024];
    DSA                 *dsa = NULL;
    int counter, counter2;
    unsigned long h, h2;
    DSA_SIG             *sig = NULL;
    BIGNUM              *q = NULL, *p = NULL, *g = NULL;
    BIGNUM              *q2 = NULL, *p2 = NULL, *g2 = NULL;
    BIGNUM *priv_key = NULL, *pub_key = NULL;
    BIGNUM *sig_r = NULL, *sig_s = NULL;


    tc = test_case->tc.dsa;
    switch (tc->mode) {
    case ACVP_DSA_MODE_KEYGEN:
        if (dsa_current_keygen_tg != tc->tg_id) {
            dsa_current_keygen_tg = tc->tg_id;

            if (group_dsa) FIPS_dsa_free(group_dsa);
            if (group_p) BN_free(group_p);
            if (group_q) BN_free(group_q);
            if (group_g) BN_free(group_g);
            if (group_pub_key) BN_free(group_pub_key);

            group_dsa = FIPS_dsa_new();
            if (!group_dsa) {
                printf("Failed to allocate DSA strcut\n");
                return 1;
            }
            L = tc->l;
            N = tc->n;

            if (dsa_builtin_paramgen2(group_dsa, L, N, md, NULL, 0, -1,
                                      NULL, NULL, NULL, NULL) <= 0) {
                printf("Parameter Generation error\n");
                FIPS_dsa_free(group_dsa);
                return 1;
            }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            group_p = BN_dup(group_dsa->p);
            group_q = BN_dup(group_dsa->q);
            group_g = BN_dup(group_dsa->g);
#else
            DSA_get0_pqg(group_dsa, (const BIGNUM **)&group_p,
                         (const BIGNUM **)&group_q, (const BIGNUM **)&group_g);
#endif
        }

        tc->p_len = BN_bn2bin(group_p, tc->p);
        tc->q_len = BN_bn2bin(group_q, tc->q);
        tc->g_len = BN_bn2bin(group_g, tc->g);

        if (!DSA_generate_key(group_dsa)) {
            printf("\n DSA_generate_key failed");
            FIPS_dsa_free(group_dsa);
            return 1;
        }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        priv_key = group_dsa->priv_key;
        pub_key = group_dsa->pub_key;
#else
        DSA_get0_key(group_dsa, (const BIGNUM **)&pub_key,
                     (const BIGNUM **)&priv_key);
#endif

        tc->x_len = BN_bn2bin(priv_key, tc->x);
        tc->y_len = BN_bn2bin(pub_key, tc->y);
        break;

    case ACVP_DSA_MODE_PQGVER:
        switch (tc->sha) {
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
        case ACVP_SHA512_224:
        case ACVP_SHA512_256:
        default:
            printf("DSA sha value not supported %d\n", tc->sha);
            return 1;

            break;
        }

        switch (tc->pqg) {
        case ACVP_DSA_PROBABLE:
            dsa = FIPS_dsa_new();
            if (!dsa) {
                printf("Failed to allocate DSA strcut\n");
                return 1;
            }
            L = tc->l;
            N = tc->n;

            p = FIPS_bn_new();
            q = FIPS_bn_new();
            BN_bin2bn(tc->p, tc->p_len, p);
            BN_bin2bn(tc->q, tc->q_len, q);

            if (dsa_builtin_paramgen2(dsa, L, N, md,
                                      tc->seed, tc->seedlen, -1, NULL,
                                      &counter2, &h2, NULL) < 0) {
                printf("Parameter Generation error\n");
                FIPS_dsa_free(dsa);
                return 1;
            }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            p2 = BN_dup(dsa->p);
            q2 = BN_dup(dsa->q);
#else
            DSA_get0_pqg(dsa, (const BIGNUM **)&p2,
                         (const BIGNUM **)&q2, NULL);
#endif

            if (BN_cmp(p2, p) || BN_cmp(q2, q))
                r = 0;
            else
                r = 1;

            FIPS_dsa_free(dsa);
            tc->result = r;
            break;

        case ACVP_DSA_CANONICAL:
            dsa = FIPS_dsa_new();
            if (!dsa) {
                printf("Failed to allocate DSA strcut\n");
                return 1;
            }
            L = tc->l;
            N = tc->n;

            p = FIPS_bn_new();
            q = FIPS_bn_new();
            g = FIPS_bn_new();
            BN_bin2bn(tc->p, tc->p_len, p);
            BN_bin2bn(tc->q, tc->q_len, q);
            BN_bin2bn(tc->g, tc->g_len, g);

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            dsa->p = BN_dup(p);
            dsa->q = BN_dup(q);
#else
            DSA_set0_pqg(dsa, BN_dup(p), BN_dup(q), NULL);
#endif

            if (dsa_builtin_paramgen2(dsa, L, N, md,
                                      tc->seed, tc->seedlen, tc->index, NULL,
                                      &counter2, &h2, NULL) < 0) {
                printf("Parameter Generation error\n");
                FIPS_dsa_free(dsa);
                return 1;
            }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            g2 = BN_dup(dsa->g);
#else
            DSA_get0_pqg(dsa, NULL, NULL, (const BIGNUM **)&g2);
#endif

            if (BN_cmp(g2, g)) {
                r = -1;
            } else {
                r = 1;
            }
            FIPS_dsa_free(dsa);
            tc->result = r;
            break;
        default:
            printf("DSA pqg mode not supported %d\n", tc->pqg);
            return 1;

            break;
        }
        break;

    case ACVP_DSA_MODE_SIGVER:
        switch (tc->sha) {
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
        case ACVP_SHA512_224:
        case ACVP_SHA512_256:
        default:
            printf("DSA sha value not supported %d\n", tc->sha);
            return 1;

            break;
        }

        dsa = FIPS_dsa_new();
        if (!dsa) {
            printf("Failed to allocate DSA strcut\n");
            return 1;
        }
        sig = FIPS_dsa_sig_new();
        if (!sig) {
            printf("Failed to allocate SIG strcut\n");
            FIPS_dsa_free(dsa);
            return 1;
        }
        L = tc->l;
        N = tc->n;

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        dsa->p = BN_new();
        dsa->q = BN_new();
        dsa->g = BN_new();
        dsa->pub_key = BN_new();
        sig->r = BN_new();
        sig->s = BN_new();
        BN_bin2bn(tc->p, tc->p_len, dsa->p);
        BN_bin2bn(tc->q, tc->q_len, dsa->q);
        BN_bin2bn(tc->g, tc->g_len, dsa->g);
        BN_bin2bn(tc->y, tc->y_len, dsa->pub_key);
        BN_bin2bn(tc->r, tc->r_len, sig->r);
        BN_bin2bn(tc->s, tc->s_len, sig->s);
#else
        DSA_get0_pqg(dsa, (const BIGNUM **)&p,
                     (const BIGNUM **)&q, (const BIGNUM **)&g);
        DSA_get0_key(dsa, (const BIGNUM **)&pub_key, NULL);
        DSA_SIG_get0(sig, (const BIGNUM **)&sig_r, (const BIGNUM **)&sig_s);

        BN_bin2bn(tc->p, tc->p_len, p);
        BN_bin2bn(tc->q, tc->q_len, q);
        BN_bin2bn(tc->g, tc->g_len, g);
        BN_bin2bn(tc->y, tc->y_len, pub_key);
        BN_bin2bn(tc->r, tc->r_len, sig_r);
        BN_bin2bn(tc->s, tc->s_len, sig_s);
#endif

        n = tc->msglen;
        r = FIPS_dsa_verify(dsa, (const unsigned char *)tc->msg, n, md, sig);

        FIPS_dsa_free(dsa);
        FIPS_dsa_sig_free(sig);
        /* return result, -1 is failure, 1 is pass */
        tc->result = r;
        break;

    case ACVP_DSA_MODE_SIGGEN:
        switch (tc->sha) {
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
        case ACVP_SHA512_224:
        case ACVP_SHA512_256:
        default:
            printf("DSA sha value not supported %d\n", tc->sha);
            return 1;

            break;
        }

        if (dsa_current_siggen_tg != tc->tg_id) {
            dsa_current_siggen_tg = tc->tg_id;

            if (group_dsa) FIPS_dsa_free(group_dsa);
            if (group_p) BN_free(group_p);
            if (group_q) BN_free(group_q);
            if (group_g) BN_free(group_g);
            if (group_pub_key) BN_free(group_pub_key);

            group_dsa = FIPS_dsa_new();
            if (!group_dsa) {
                printf("Failed to allocate DSA strcut\n");
                return 1;
            }
            L = tc->l;
            N = tc->n;

            if (dsa_builtin_paramgen2(group_dsa, L, N, md, NULL, 0, -1,
                                      NULL, NULL, NULL, NULL) <= 0) {
                printf("Parameter Generation error\n");
                FIPS_dsa_free(group_dsa);
                return 1;
            }

            if (!DSA_generate_key(group_dsa)) {
                printf("\n DSA_generate_key failed");
                FIPS_dsa_free(group_dsa);
                return 1;
            }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            group_p = BN_dup(group_dsa->p);
            group_q = BN_dup(group_dsa->q);
            group_g = BN_dup(group_dsa->g);
#else
            DSA_get0_pqg(group_dsa, (const BIGNUM **)&group_p,
                         (const BIGNUM **)&group_q, (const BIGNUM **)&group_g);
#endif

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            group_pub_key = BN_dup(group_dsa->pub_key);
#else
            DSA_get0_key(group_dsa, (const BIGNUM **)&group_pub_key, NULL);
#endif
        }

        tc->p_len = BN_bn2bin(group_p, tc->p);
        tc->q_len = BN_bn2bin(group_q, tc->q);
        tc->g_len = BN_bn2bin(group_g, tc->g);
        tc->y_len = BN_bn2bin(group_pub_key, tc->y);

        sig = FIPS_dsa_sign(group_dsa, tc->msg, tc->msglen, md);

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        sig_r = sig->r;
        sig_s = sig->s;
#else
        DSA_SIG_get0(sig, (const BIGNUM **)&sig_r, (const BIGNUM **)&sig_s);
#endif

        tc->r_len = BN_bn2bin(sig_r, tc->r);
        tc->s_len = BN_bn2bin(sig_s, tc->s);
        FIPS_dsa_sig_free(sig);
        break;

    case ACVP_DSA_MODE_PQGGEN:
        switch (tc->sha) {
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
        case ACVP_SHA512_224:
        case ACVP_SHA512_256:
        default:
            printf("DSA sha value not supported %d\n", tc->sha);
            return 1;

            break;
        }

        switch (tc->gen_pq) {
        case ACVP_DSA_UNVERIFIABLE:
            printf("DSA Parameter Generation2 error for %d, not supported\n", tc->gen_pq);
            return 1;

            break;
        case ACVP_DSA_CANONICAL:
            dsa = FIPS_dsa_new();

            p = FIPS_bn_new();
            q = FIPS_bn_new();
            BN_bin2bn(tc->p, tc->p_len, p);
            BN_bin2bn(tc->q, tc->q_len, q);

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            dsa->p = BN_dup(p);
            dsa->q = BN_dup(q);
#else
            DSA_set0_pqg(dsa, p, q, g);
#endif
            L = tc->l;
            N = tc->n;
            if (dsa_builtin_paramgen2(dsa, L, N, md,
                                      tc->seed, tc->seedlen, tc->index, NULL,
                                      NULL, NULL, NULL) <= 0) {
                printf("DSA Parameter Generation2 error for %d\n", tc->gen_pq);
                FIPS_dsa_free(dsa);
                return 1;
            }
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            tc->g_len = BN_bn2bin(dsa->g, tc->g);
#else
            tc->g_len = BN_bn2bin(g, tc->g);
#endif
            FIPS_dsa_free(dsa);
            break;

        case ACVP_DSA_PROBABLE:
        case ACVP_DSA_PROVABLE:
            dsa = FIPS_dsa_new();
            L = tc->l;
            N = tc->n;
            if (dsa_builtin_paramgen2(dsa, L, N, md,
                                      NULL, 0, -1, seed,
                                      &counter, &h, NULL) <= 0) {
                printf("DSA Parameter Generation 2 error for %d\n", tc->gen_pq);
                FIPS_dsa_free(dsa);
                return 1;
            }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            p = dsa->p;
            q = dsa->q;
#else
            DSA_get0_pqg(dsa, (const BIGNUM **)&p,
                         (const BIGNUM **)&q, NULL);
#endif

            tc->p_len = BN_bn2bin(p, tc->p);
            tc->q_len = BN_bn2bin(q, tc->q);
            tc->counter = counter;
            tc->h = h;

#define DSA_MAX_SEED 3072
            memcpy_s(tc->seed, DSA_MAX_SEED, &seed, EVP_MD_size(md));
            tc->seedlen = EVP_MD_size(md);
            tc->counter = counter;
            FIPS_dsa_free(dsa);
            break;
        default:
            printf("Invalid DSA gen_pq %d\n", tc->gen_pq);
            return 1;

            break;
        }
        break;
    default:
        printf("Invalid DSA mode %d\n", tc->mode);
        return 1;

        break;
    }
    return 0;
}

static EC_POINT *make_peer(EC_GROUP *group, BIGNUM *x, BIGNUM *y) {
    EC_POINT *peer;
    int rv;
    BN_CTX *c;

    peer = EC_POINT_new(group);
    if (!peer) {
        printf("EC_POINT_new failed\n");
        return NULL;
    }
    c = BN_CTX_new();
    if (!c) {
        printf("BN_CTX_new failed\n");
        return NULL;
    }
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field) {
        rv = EC_POINT_set_affine_coordinates_GFp(group, peer, x, y, c);
    } else {
        rv = EC_POINT_set_affine_coordinates_GF2m(group, peer, x, y, c);
    }

    BN_CTX_free(c);
    if (rv) {
        return peer;
    }
    EC_POINT_free(peer);
    return NULL;
}

static int ec_print_key(ACVP_KAS_ECC_TC *tc, EC_KEY *key, int add_e, int exout) {
    const EC_POINT *pt;
    const EC_GROUP *grp;
    const EC_METHOD *meth;
    int rv = 0;
    BIGNUM *tx, *ty;
    const BIGNUM *d = NULL;
    BN_CTX *ctx;

    ctx = BN_CTX_new();
    if (!ctx) {
        printf("BN_CTX_new failed\n");
        return 0;
    }
    tx = BN_CTX_get(ctx);
    ty = BN_CTX_get(ctx);
    if (!tx || !ty) {
        BN_CTX_free(ctx);
        printf("BN_CTX_get failed\n");
        return 0;
    }
    grp = EC_KEY_get0_group(key);
    pt = EC_KEY_get0_public_key(key);
    d = EC_KEY_get0_private_key(key);
    meth = EC_GROUP_method_of(grp);
    if (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field) {
        rv = EC_POINT_get_affine_coordinates_GFp(grp, pt, tx, ty, ctx);
    } else {
        rv = EC_POINT_get_affine_coordinates_GF2m(grp, pt, tx, ty, ctx);
    }

    if (tc->test_type == ACVP_KAS_ECC_TT_AFT) {
        tc->pixlen = BN_bn2bin(tx, tc->pix);
        tc->piylen = BN_bn2bin(ty, tc->piy);
        if (tc->mode == ACVP_KAS_ECC_MODE_COMPONENT) {
            tc->dlen = BN_bn2bin(d, tc->d);
        }
    }
    BN_CTX_free(ctx);
    return rv;
}

static int app_kas_ecc_handler(ACVP_TEST_CASE *test_case) {
    EC_GROUP *group = NULL;
    ACVP_KAS_ECC_TC         *tc;
    int nid = 0, exout = 0;
    EC_KEY *ec = NULL;
    EC_POINT *peerkey = NULL;
    unsigned char *Z = NULL;
    int Zlen = 0;
    BIGNUM *cx = NULL, *cy = NULL, *ix = NULL, *iy = NULL, *id = NULL;
    const EVP_MD *md = NULL;
    int rv = 1;

    tc = test_case->tc.kas_ecc;

    switch (tc->curve) {
    case ACVP_EC_CURVE_P224:
        nid = NID_secp224r1;
        break;
    case ACVP_EC_CURVE_P256:
        nid = NID_X9_62_prime256v1;
        break;
    case ACVP_EC_CURVE_P384:
        nid = NID_secp384r1;
        break;
    case ACVP_EC_CURVE_P521:
        nid = NID_secp521r1;
        break;
    case ACVP_EC_CURVE_B233:
        nid = NID_sect233r1;
        break;
    case ACVP_EC_CURVE_B283:
        nid = NID_sect283r1;
        break;
    case ACVP_EC_CURVE_B409:
        nid = NID_sect409r1;
        break;
    case ACVP_EC_CURVE_B571:
        nid = NID_sect571r1;
        break;
    case ACVP_EC_CURVE_K233:
        nid = NID_sect233k1;
        break;
    case ACVP_EC_CURVE_K283:
        nid = NID_sect283k1;
        break;
    case ACVP_EC_CURVE_K409:
        nid = NID_sect409k1;
        break;
    case ACVP_EC_CURVE_K571:
        nid = NID_sect571k1;
        break;
    default:
        printf("Invalid curve %d\n", tc->curve);
        return rv;

        break;
    }

    if (tc->mode == ACVP_KAS_ECC_MODE_COMPONENT) {
        switch (tc->md) {
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
            printf("No valid hash name %d\n", tc->md);
            return rv;

            break;
        }
    }
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        printf("No group from curve name %d\n", nid);
        return rv;
    }

    ec = EC_KEY_new();
    if (ec == NULL) {
        EC_GROUP_free(group);
        printf("No EC_KEY_new\n");
        return rv;
    }
    EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH);
    if (!EC_KEY_set_group(ec, group)) {
        EC_GROUP_free(group);
        printf("No EC_KEY_set_group\n");
        return rv;
    }

    cx = FIPS_bn_new();
    cy = FIPS_bn_new();
    BN_bin2bn(tc->psx, tc->psxlen, cx);
    BN_bin2bn(tc->psy, tc->psylen, cy);
    if (!cx || !cy) {
        printf("BN_bin2bn failed psx psy\n");
        goto error;
    }
    peerkey = make_peer(group, cx, cy);
    if (peerkey == NULL) {
        printf("Peerkey failed\n");
        goto error;
    }
    if (tc->test_type == ACVP_KAS_ECC_TT_VAL) {
        ix = FIPS_bn_new();
        iy = FIPS_bn_new();
        id = FIPS_bn_new();
        BN_bin2bn(tc->pix, tc->pixlen, ix);
        BN_bin2bn(tc->piy, tc->piylen, iy);
        BN_bin2bn(tc->d, tc->dlen, id);

        if (!ix || !iy || !id) {
            printf("BN_bin2bn failed pix piy d");
            goto error;
        }

        EC_KEY_set_public_key_affine_coordinates(ec, ix, iy);
        EC_KEY_set_private_key(ec, id);
    } else {
        if (!EC_KEY_generate_key(ec)) {
            printf("EC_KEY_generate_key failed\n");
            goto error;
        }
    }

    exout = md ? 1 : 0;
    ec_print_key(tc, ec, md ? 1 : 0, exout);
    Zlen = (EC_GROUP_get_degree(group) + 7) / 8;
    if (!Zlen) {
        printf("Zlen degree failure\n");
        goto error;
    }
    Z = OPENSSL_malloc(Zlen);
    if (!Z) {
        printf("Malloc failure\n");
        goto error;
    }
    if (!ECDH_compute_key(Z, Zlen, peerkey, ec, 0)) {
        printf("ECDH_compute_key failure\n");
        goto error;
    }

#define KAS_ECC_Z_MAX 512
    if (tc->test_type == ACVP_KAS_ECC_TT_AFT) {
        memcpy_s(tc->z, KAS_ECC_Z_MAX, Z, Zlen);
        tc->zlen = Zlen;
    }
    if (tc->mode == ACVP_KAS_ECC_MODE_COMPONENT) {
        FIPS_digest(Z, Zlen, (unsigned char *)tc->chash, NULL, md);
        tc->chashlen = EVP_MD_size(md);
    }
    rv = 0;

error:
    if (Z) {
        OPENSSL_cleanse(Z, Zlen);
    }
    FIPS_free(Z);
    EC_KEY_free(ec);
    EC_POINT_free(peerkey);
    EC_GROUP_free(group);
    BN_free(cx);
    BN_free(cy);
    BN_free(ix);
    BN_free(iy);
    BN_free(id);
    return rv;
}

static int app_kas_ffc_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KAS_FFC_TC         *tc;
    const EVP_MD *md = NULL;
    int rv = 1;
    unsigned char *Z = NULL;
    int Zlen = 0;
    DH *dh = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;
    BIGNUM *peerkey = NULL;

    tc = test_case->tc.kas_ffc;

    switch (tc->md) {
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
        printf("No valid hash name %d\n", tc->md);
        return rv;

        break;
    }

    dh = FIPS_dh_new();
    if (!dh) {
        return rv;
    }

    p = FIPS_bn_new();
    q = FIPS_bn_new();
    g = FIPS_bn_new();
    BN_bin2bn(tc->p, tc->plen, p);
    BN_bin2bn(tc->q, tc->qlen, q);
    BN_bin2bn(tc->g, tc->glen, g);

    peerkey = FIPS_bn_new();
    BN_bin2bn(tc->eps, tc->epslen, peerkey);

    if (!peerkey || !p || !q || !g) {
        printf("BN_bin2bn failed p q g eps\n");
        goto error;
    }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    dh->p = BN_dup(p);
    dh->q = BN_dup(q);
    dh->g = BN_dup(g);
#else
    DH_set0_pqg(dh, p, q, g);
#endif

    if (tc->test_type == ACVP_KAS_FFC_TT_VAL) {
        pub_key = FIPS_bn_new();
        priv_key = FIPS_bn_new();
        BN_bin2bn(tc->epri, tc->eprilen, priv_key);
        BN_bin2bn(tc->epui, tc->epuilen, pub_key);

        if (!pub_key || !priv_key) {
            printf("BN_bin2bn failed epri epui\n");
            goto error;
        }
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        dh->pub_key = BN_dup(pub_key);
        dh->priv_key = BN_dup(priv_key);
#else
        DH_set0_key(dh, pub_key, priv_key);
#endif
    }

    if (tc->test_type == ACVP_KAS_FFC_TT_AFT) {
        if (!DH_generate_key(dh)) {
            printf("DH_generate_key failed\n");
            goto error;
        }
    }
    Z = OPENSSL_malloc(BN_num_bytes(p));
    if (!Z) {
        printf("Malloc failed for Z\n");
        goto error;
    }

    Zlen = DH_compute_key_padded(Z, peerkey, dh);
    FIPS_digest(Z, Zlen, (unsigned char *)tc->chash, NULL, md);
    tc->chashlen = EVP_MD_size(md);

#define KAS_FFC_Z_MAX 512
    if (tc->test_type == ACVP_KAS_FFC_TT_AFT) {
        memcpy_s(tc->z, KAS_FFC_Z_MAX, Z, Zlen);
        tc->zlen = Zlen;
    }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    tc->piutlen = BN_bn2bin(dh->pub_key, tc->piut);
#else
    tc->piutlen = BN_bn2bin(pub_key, tc->piut);
#endif

    rv = 0;

error:
    if (Z) {
        OPENSSL_cleanse(Z, Zlen);
    }
    FIPS_free(Z);
    BN_clear_free(peerkey);
    FIPS_dh_free(dh);
    return rv;
}

static int app_rsa_keygen_handler(ACVP_TEST_CASE *test_case) {
    /*
     * custom crypto module handler
     * to be filled in -
     * this handler assumes info gen by server
     * and all the other params registered for
     * in this example app.
     */

    ACVP_RSA_KEYGEN_TC    *tc;
    int rv = 1;
    RSA       *rsa;
    BIGNUM *p = NULL, *q = NULL, *n = NULL, *d = NULL;
    BIGNUM *e = BN_new();

    /* keygen vars */
    unsigned int bitlen1, bitlen2, bitlen3, bitlen4, keylen;

    if (!test_case) {
        goto err;
    }
    tc = test_case->tc.rsa_keygen;

    rsa = FIPS_rsa_new();
    bitlen1 = tc->bitlen1;
    bitlen2 = tc->bitlen2;
    bitlen3 = tc->bitlen3;
    bitlen4 = tc->bitlen4;
    keylen = tc->modulo;

    e = FIPS_bn_new();
    BN_bin2bn(tc->e, tc->e_len, e);
    if (!e) {
        printf("Error converting e to BN\n");
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
        goto err;
    }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    p = rsa->p;
    q = rsa->q;
    n = rsa->n;
    d = rsa->d;
#else
    RSA_get0_key(rsa, (const BIGNUM **)&n, NULL,
                 (const BIGNUM **)&d);
    RSA_get0_factors(rsa, (const BIGNUM **)&p,
                     (const BIGNUM **)&q);
#endif

    tc->p_len = BN_bn2bin(p, tc->p);
    tc->q_len = BN_bn2bin(q, tc->q);
    tc->n_len = BN_bn2bin(n, tc->n);
    tc->d_len = BN_bn2bin(d, tc->d);

    FIPS_rsa_free(rsa);
    rv = 0;
err:
    if (e) BN_free(e);
    return rv;
}

static int ec_get_pubkey(EC_KEY *key, BIGNUM *x, BIGNUM *y) {
    const EC_POINT *pt;
    const EC_GROUP *grp;
    const EC_METHOD *meth;
    int rv;
    BN_CTX *ctx;

    ctx = BN_CTX_new();
    if (!ctx)
        return 0;

    grp = EC_KEY_get0_group(key);
    if (!grp) return 0;

    pt = EC_KEY_get0_public_key(key);
    if (!pt) return 0;

    meth = EC_GROUP_method_of(grp);
    if (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field) {
        rv = EC_POINT_get_affine_coordinates_GFp(grp, pt, x, y, ctx);
    } else {
        rv = EC_POINT_get_affine_coordinates_GF2m(grp, pt, x, y, ctx);
    }

    BN_CTX_free(ctx);
    return rv;
}

/*
 * group values are declared near the top so that they
 * can be freed at the end of main execution
 */
static int app_ecdsa_handler(ACVP_TEST_CASE *test_case) {
    ACVP_ECDSA_TC    *tc;
    int rv = 1;
    ACVP_CIPHER mode;
    const EVP_MD *md = NULL;
    ECDSA_SIG *sig = NULL;

    int nid = NID_undef, rc = 0, msg_len = 0;
    BIGNUM *Qx = NULL, *Qy = NULL;
    BIGNUM *r = NULL, *s = NULL;
    const BIGNUM *d = NULL;
    EC_KEY *key = NULL;


    if (!test_case) {
        printf("No test case found\n");
        goto err;
    }
    tc = test_case->tc.ecdsa;
    if (!tc) {
        printf("\nError: test case not found in ECDSA handler\n");
        goto err;
    }
    mode = tc->cipher;

    if (mode == ACVP_ECDSA_SIGGEN || mode == ACVP_ECDSA_SIGVER) {
        switch (tc->hash_alg) {
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
            printf("Unsupported hash alg in ECDSA\n");
            goto err;
        }
    }

    switch (tc->curve) {
    case ACVP_EC_CURVE_B233:
        nid = NID_sect233r1;
        break;
    case ACVP_EC_CURVE_B283:
        nid = NID_sect283r1;
        break;
    case ACVP_EC_CURVE_B409:
        nid = NID_sect409r1;
        break;
    case ACVP_EC_CURVE_B571:
        nid = NID_sect571r1;
        break;
    case ACVP_EC_CURVE_K233:
        nid = NID_sect233k1;
        break;
    case ACVP_EC_CURVE_K283:
        nid = NID_sect283k1;
        break;
    case ACVP_EC_CURVE_K409:
        nid = NID_sect409k1;
        break;
    case ACVP_EC_CURVE_K571:
        nid = NID_sect571k1;
        break;
    case ACVP_EC_CURVE_P224:
        nid = NID_secp224r1;
        break;
    case ACVP_EC_CURVE_P256:
        nid = NID_X9_62_prime256v1;
        break;
    case ACVP_EC_CURVE_P384:
        nid = NID_secp384r1;
        break;
    case ACVP_EC_CURVE_P521:
        nid = NID_secp521r1;
        break;
    default:
        printf("Unsupported curve\n");
        goto err;
    }

    switch (mode) {
    case ACVP_ECDSA_KEYGEN:
        Qx = FIPS_bn_new();
        Qy = FIPS_bn_new();
        if (!Qx || !Qy) {
            printf("Error BIGNUM malloc\n");
            goto err;
        }

        key = EC_KEY_new_by_curve_name(nid);
        if (!key) {
            printf("Failed to instantiate ECDSA key\n");
            goto err;
        }

        if (!EC_KEY_generate_key(key)) {
            printf("Error generating ECDSA key\n");
            goto err;
        }

        if (!ec_get_pubkey(key, Qx, Qy)) {
            printf("Error getting ECDSA key attributes\n");
            goto err;
        }

        d = EC_KEY_get0_private_key(key);

        tc->qx_len = BN_bn2bin(Qx, tc->qx);
        tc->qy_len = BN_bn2bin(Qy, tc->qy);
        tc->d_len = BN_bn2bin(d, tc->d);
        break;
    case ACVP_ECDSA_KEYVER:
        Qx = FIPS_bn_new();
        Qy = FIPS_bn_new();
        if (!tc->qx || !tc->qy) {
            printf("missing qx or qy: ecdsa keyver\n");
            goto err;
        }
        BN_bin2bn(tc->qx, tc->qx_len, Qx);
        BN_bin2bn(tc->qy, tc->qy_len, Qy);
        if (!Qx || !Qy) {
            printf("Error BIGNUM conversion\n");
            goto err;
        }

        key = EC_KEY_new_by_curve_name(nid);
        if (!key) {
            printf("Failed to instantiate ECDSA key\n");
            goto err;
        }

        if (EC_KEY_set_public_key_affine_coordinates(key, Qx, Qy) == 1) {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_PASS;
        } else {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_FAIL;
        }
        break;
    case ACVP_ECDSA_SIGGEN:
        if (ecdsa_current_tg != tc->tg_id) {
            ecdsa_current_tg = tc->tg_id;
            if (ecdsa_group_key) EC_KEY_free(ecdsa_group_key);

            ecdsa_group_Qx = FIPS_bn_new();
            ecdsa_group_Qy = FIPS_bn_new();
            if (!ecdsa_group_Qx || !ecdsa_group_Qy) {
                printf("Error BIGNUM malloc\n");
                goto err;
            }
            ecdsa_group_key = EC_KEY_new_by_curve_name(nid);
            if (!ecdsa_group_key) {
                printf("Failed to instantiate ECDSA key\n");
                goto err;
            }

            if (!EC_KEY_generate_key(ecdsa_group_key)) {
                printf("Error generating ECDSA key\n");
                goto err;
            }

            if (!ec_get_pubkey(ecdsa_group_key, ecdsa_group_Qx, ecdsa_group_Qy)) {
                printf("Error getting ECDSA key attributes\n");
                goto err;
            }
        }
        msg_len = tc->msg_len;
        if (!tc->message) {
            printf("ecdsa siggen missing msg\n");
            goto err;
        }
        sig = FIPS_ecdsa_sign(ecdsa_group_key, tc->message, msg_len, md);
        if (!sig) {
            printf("Error signing message\n");
            goto err;
        }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        r = sig->r;
        s = sig->s;
#else
        ECDSA_SIG_get0(sig, (const BIGNUM **)&r,
                       (const BIGNUM **)&s);
#endif

        tc->qx_len = BN_bn2bin(ecdsa_group_Qx, tc->qx);
        tc->qy_len = BN_bn2bin(ecdsa_group_Qy, tc->qy);
        tc->r_len = BN_bn2bin(r, tc->r);
        tc->s_len = BN_bn2bin(s, tc->s);

        break;
    case ACVP_ECDSA_SIGVER:
        if (!tc->message) {
            printf("missing sigver message - nothing to verify\n");
            goto err;
        }
        if (!tc->r) {
            printf("missing r ecdsa sigver\n");
            goto err;
        }
        if (!tc->s) {
            printf("missing s ecdsa sigver\n");
            goto err;
        }
        sig = ECDSA_SIG_new();
        if (!sig) {
            printf("Error generating ecdsa signature\n");
            goto err;
        }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        r = sig->r;
        s = sig->s;
#else
        ECDSA_SIG_get0(sig, (const BIGNUM **)&r,
                       (const BIGNUM **)&s);
#endif

        Qx = FIPS_bn_new();
        Qy = FIPS_bn_new();

        BN_bin2bn(tc->qx, tc->qx_len, Qx);
        BN_bin2bn(tc->qy, tc->qy_len, Qy);
        if (!Qx || !Qy) {
            printf("Error BIGNUM conversion\n");
            goto err;
        }

        BN_bin2bn(tc->r, tc->r_len, r);
        BN_bin2bn(tc->s, tc->s_len, s);
        if (!r || !s) {
            printf("Error BIGNUM conversion\n");
            goto err;
        }

        key = EC_KEY_new_by_curve_name(nid);
        if (!key) {
            printf("Failed to instantiate ECDSA key\n");
            goto err;
        }

        rc = EC_KEY_set_public_key_affine_coordinates(key, Qx, Qy);
        if (rc != 1) {
            printf("Error setting ECDSA coordinates\n");
            goto points_err;
        }

        if (!tc->message) {
            printf("ecdsa siggen missing msg\n");
            goto err;
        }
        if (FIPS_ecdsa_verify(key, tc->message, tc->msg_len, md, sig) == 1) {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_PASS;
        } else {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_FAIL;
        }
points_err:
        break;
    default:
        printf("Unsupported ECDSA mode\n");
        break;
    }
    rv = 0;

err:
    if (sig) FIPS_ecdsa_sig_free(sig);
    if (Qx) FIPS_bn_free(Qx);
    if (Qy) FIPS_bn_free(Qy);
    if (key) EC_KEY_free(key);
    return rv;
}

/*
 * RSA SigGen handler
 * requires Makefile.fom to function
 *
 * group values are decalred near the top so that they
 * can be freed at the end of main execution
 */
static int app_rsa_sig_handler(ACVP_TEST_CASE *test_case) {
    EVP_MD *tc_md = NULL;
    int siglen, pad_mode;
    BIGNUM *bn_e = NULL, *e = NULL, *n = NULL;
    ACVP_RSA_SIG_TC    *tc;
    RSA *rsa = NULL;
    int salt_len = -1;

    int rv = 1;

    if (!test_case) {
        printf("\nError: test case not found in RSA SigGen handler\n");
        goto err;
    }

    tc = test_case->tc.rsa_sig;

    if (!tc) {
        printf("\nError: test case not found in RSA SigGen handler\n");
        goto err;
    }

    /*
     * Make an RSA object and set a new BN exponent to use to generate a key
     */

    rsa = FIPS_rsa_new();
    if (!rsa) {
        printf("\nError: Issue with RSA obj in RSA Sig\n");
        goto err;
    }

    bn_e = BN_new();
    if (!bn_e || !BN_set_word(bn_e, 0x1001)) {
        printf("\nError: Issue with exponent in RSA Sig\n");
        goto err;
    }

    if (!tc->modulo) {
        printf("\nError: Issue with modulo in RSA Sig\n");
        goto err;
    }

    /*
     * Set the pad mode and generate a key given the respective sigType
     */
    switch (tc->sig_type) {
    case ACVP_RSA_SIG_TYPE_X931:
        pad_mode = RSA_X931_PADDING;
        salt_len = -2;
        break;
    case ACVP_RSA_SIG_TYPE_PKCS1PSS:
        pad_mode = RSA_PKCS1_PSS_PADDING;
        salt_len = tc->salt_len;
        break;
    case ACVP_RSA_SIG_TYPE_PKCS1V15:
        pad_mode = RSA_PKCS1_PADDING;
        break;
    default:
        printf("\nError: sigType not supported\n");
        rv = ACVP_INVALID_ARG;
        goto err;
    }

    /*
     * Set the message digest to the appropriate sha
     */
    switch (tc->hash_alg) {
    case ACVP_SHA1:
        tc_md = (EVP_MD *)EVP_sha1();
        break;
    case ACVP_SHA224:
        tc_md = (EVP_MD *)EVP_sha224();
        break;
    case ACVP_SHA256:
        tc_md = (EVP_MD *)EVP_sha256();
        break;
    case ACVP_SHA384:
        tc_md = (EVP_MD *)EVP_sha384();
        break;
    case ACVP_SHA512:
        tc_md = (EVP_MD *)EVP_sha512();
        break;
    default:
        printf("\nError: hashAlg not supported for RSA SigGen\n");
        goto err;
    }

    /*
     * If we are verifying, set RSA to the given public key
     * Else, generate a new key, retrieve and save values
     */
    if (tc->sig_mode == ACVP_RSA_SIGVER) {
        e = BN_new();
        if (!e) {
            printf("\nBN alloc failure (e)\n");
            goto err;
        }
        BN_bin2bn(tc->e, tc->e_len, e);

        n = BN_new();
        if (!n) {
            printf("\nBN alloc failure (n)\n");
            goto err;
        }
        BN_bin2bn(tc->n, tc->n_len, n);

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        rsa->e = BN_dup(e);
        rsa->n = BN_dup(n);
#else
        RSA_set0_key(rsa, n, e, NULL);
#endif

        tc->ver_disposition = FIPS_rsa_verify(rsa, tc->msg, tc->msg_len, tc_md, pad_mode, salt_len, NULL, tc->signature, tc->sig_len);
    } else {
        if (rsa_current_tg != tc->tg_id) {
            rsa_current_tg = tc->tg_id;
            if (group_rsa) RSA_free(group_rsa);
            group_rsa = RSA_new();
            if (!FIPS_rsa_x931_generate_key_ex(group_rsa, tc->modulo, bn_e, NULL)) {
                printf("\nError: Issue with keygen during siggen handling\n");
                goto err;
            }
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            e = group_rsa->e;
            n = group_rsa->n;
            group_n = BN_dup(n);
#else
            RSA_get0_key(rsa, (const BIGNUM **)&n, (const BIGNUM **)&e, NULL);
#endif
        } else {
            e = BN_dup(bn_e);
            n = BN_dup(group_n);
        }
        tc->e_len = BN_bn2bin(e, tc->e);
        tc->n_len = BN_bn2bin(n, tc->n);

        if (tc->msg && tc_md) {
            siglen = RSA_size(group_rsa);

            if (!FIPS_rsa_sign(group_rsa, tc->msg, tc->msg_len, tc_md, pad_mode, salt_len, NULL,
                               tc->signature, (unsigned int *)&siglen)) {
                printf("\nError: RSA Signature Generation fail\n");
                goto err;
            }

            tc->sig_len = siglen;
        }
    }
    rv = 0;
err:
    if (bn_e) BN_free(bn_e);
    if (rsa) FIPS_rsa_free(rsa);

    return rv;
}
#endif

#ifdef ACVP_NO_RUNTIME
typedef struct {
    unsigned char *ent;
    size_t entlen;
    unsigned char *nonce;
    size_t noncelen;
} DRBG_TEST_ENT;

static size_t drbg_test_entropy(DRBG_CTX *dctx,
                                unsigned char **pout,
                                int entropy,
                                size_t min_len,
                                size_t max_len) {
    if (!dctx || !pout) return 0;

    DRBG_TEST_ENT *t = (DRBG_TEST_ENT *)FIPS_drbg_get_app_data(dctx);
    if (!t) return 0;

    if (t->entlen < min_len) printf("entropy data len < min_len: %zu\n", t->entlen);
    if (t->entlen > max_len) printf("entropy data len > max_len: %zu\n", t->entlen);
    *pout = (unsigned char *)t->ent;
    return t->entlen;
}

static size_t drbg_test_nonce(DRBG_CTX *dctx,
                              unsigned char **pout,
                              int entropy,
                              size_t min_len,
                              size_t max_len) {
    if (!dctx || !pout) return 0;

    DRBG_TEST_ENT *t = (DRBG_TEST_ENT *)FIPS_drbg_get_app_data(dctx);

    if (t->noncelen < min_len) printf("nonce data len < min_len: %zu\n", t->noncelen);
    if (t->noncelen > max_len) printf("nonce data len > max_len: %zu\n", t->noncelen);
    *pout = (unsigned char *)t->nonce;
    return t->noncelen;
}

static int app_drbg_handler(ACVP_TEST_CASE *test_case) {
    int result = 1;
    ACVP_DRBG_TC    *tc;
    unsigned int nid;
    int der_func = 0;
    unsigned int drbg_entropy_len;
    int fips_rc;

    unsigned char   *nonce = NULL;

    if (!test_case) {
        return result;
    }

    tc = test_case->tc.drbg;
    /*
     * Init entropy length
     */
    drbg_entropy_len = tc->entropy_len;

    switch (tc->cipher) {
    case ACVP_HASHDRBG:
        nonce = tc->nonce;
        switch (tc->mode) {
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
            printf("%s: Unsupported algorithm/mode %d/%d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
                   tc->cipher, tc->mode);
            return result;

            break;
        }
        break;

    case ACVP_HMACDRBG:
        nonce = tc->nonce;
        switch (tc->mode) {
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
            printf("%s: Unsupported algorithm/mode %d/%d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
                   tc->cipher, tc->mode);
            return result;

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

        switch (tc->mode) {
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
            printf("%s: Unsupported algorithm/mode %d/%d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
                   tc->cipher, tc->mode);
            return result;

            break;
        }
        break;
    default:
        printf("%s: Unsupported algorithm %d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
               tc->cipher);
        return result;

        break;
    }

    DRBG_CTX *drbg_ctx = NULL;
    DRBG_TEST_ENT entropy_nonce;
    memzero_s(&entropy_nonce, sizeof(DRBG_TEST_ENT));
    drbg_ctx = FIPS_drbg_new(nid, der_func | DRBG_FLAG_TEST);
    if (!drbg_ctx) {
        progress("ERROR: failed to create DRBG Context.");
        return result;
    }

    /*
     * Set entropy and nonce
     */
    entropy_nonce.ent = tc->entropy;
    entropy_nonce.entlen = drbg_entropy_len;

    entropy_nonce.nonce = nonce;
    entropy_nonce.noncelen = tc->nonce_len;

    FIPS_drbg_set_app_data(drbg_ctx, &entropy_nonce);

    fips_rc = FIPS_drbg_set_callbacks(drbg_ctx,
                                      drbg_test_entropy,
                                      0, 0,
                                      drbg_test_nonce,
                                      0);
    if (!fips_rc) {
        progress("ERROR: failed to Set callback DRBG ctx");
        long l = 9;
        char buf[2048]  = { 0 };
        while ((l = ERR_get_error())) {
            printf("ERROR:%s\n", ERR_error_string(l, buf));
        }
        goto end;
    }

    fips_rc = FIPS_drbg_instantiate(drbg_ctx, (const unsigned char *)tc->perso_string,
                                    (size_t)tc->perso_string_len);
    if (!fips_rc) {
        progress("ERROR: failed to instantiate DRBG ctx");
        long l = 9;
        char buf[2048]  = { 0 };
        while ((l = ERR_get_error())) {
            printf("ERROR:%s\n", ERR_error_string(l, buf));
        }
        goto end;
    }

    /*
     * Process predictive resistance flag
     */
    if (tc->pred_resist_enabled) {
        entropy_nonce.ent = tc->entropy_input_pr;
        entropy_nonce.entlen = drbg_entropy_len;

        fips_rc =  FIPS_drbg_generate(drbg_ctx, (unsigned char *)tc->drb,
                                      (size_t)(tc->drb_len),
                                      (int)1,
                                      (const unsigned char *)tc->additional_input,
                                      (size_t)(tc->additional_input_len));
        if (!fips_rc) {
            progress("ERROR: failed to generate drb");
            long l;
            while ((l = ERR_get_error())) {
                printf("ERROR:%s\n", ERR_error_string(l, NULL));
            }
            goto end;
        }

        entropy_nonce.ent = tc->entropy_input_pr_1;
        entropy_nonce.entlen = drbg_entropy_len;

        fips_rc =  FIPS_drbg_generate(drbg_ctx, (unsigned char *)tc->drb,
                                      (size_t)(tc->drb_len),
                                      (int)1,
                                      (const unsigned char *)tc->additional_input_1,
                                      (size_t)(tc->additional_input_len));
        if (!fips_rc) {
            progress("ERROR: failed to generate drb");
            long l;
            while ((l = ERR_get_error())) {
                printf("ERROR:%s\n", ERR_error_string(l, NULL));
            }
            goto end;
        }
    } else {
        fips_rc = FIPS_drbg_generate(drbg_ctx, (unsigned char *)tc->drb,
                                     (size_t)(tc->drb_len),
                                     (int)0,
                                     (const unsigned char *)tc->additional_input,
                                     (size_t)(tc->additional_input_len));
        if (!fips_rc) {
            progress("ERROR: failed to generate drb");
            long l;
            while ((l = ERR_get_error())) {
                printf("ERROR:%s\n", ERR_error_string(l, NULL));
            }
            goto end;
        }
    }
    result = 0;

end:
    FIPS_drbg_uninstantiate(drbg_ctx);
    FIPS_drbg_free(drbg_ctx);

    return result;
}
#endif


/* This is a public domain base64 implementation written by WEI Zhicheng. */

enum { BASE64_OK = 0, BASE64_INVALID };

#define BASE64_ENCODE_OUT_SIZE(s)    (((s) + 2) / 3 * 4)
#define BASE64_DECODE_OUT_SIZE(s)    (((s)) / 4 * 3)

#define BASE64_PAD    '='


#define BASE64DE_FIRST    '+'
#define BASE64DE_LAST    'z'
/* ASCII order for BASE 64 decode, -1 in unused character */
static const signed char base64de[] = {
    /* '+', ',', '-', '.', '/', '0', '1', '2', */
    62, -1, -1, -1, 63, 52, 53, 54,

    /* '3', '4', '5', '6', '7', '8', '9', ':', */
    55, 56, 57, 58, 59, 60, 61, -1,

    /* ';', '<', '=', '>', '?', '@', 'A', 'B', */
    -1, -1, -1, -1, -1, -1, 0,  1,

    /* 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', */
    2,  3,  4,  5,  6,  7,  8,  9,

    /* 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', */
    10, 11, 12, 13, 14, 15, 16, 17,

    /* 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', */
    18, 19, 20, 21, 22, 23, 24, 25,

    /* '[', '\', ']', '^', '_', '`', 'a', 'b', */
    -1, -1, -1, -1, -1, -1, 26, 27,

    /* 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', */
    28, 29, 30, 31, 32, 33, 34, 35,

    /* 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', */
    36, 37, 38, 39, 40, 41, 42, 43,

    /* 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', */
    44, 45, 46, 47, 48, 49, 50, 51,
};

static unsigned int
base64_decode(const char *in, unsigned int inlen, unsigned char *out) {
    unsigned int i, j;

    for (i = j = 0; i < inlen; i++) {
        int c;
        int s = i % 4;             /* from 8/gcd(6, 8) */

        if (in[i] == '=')
            return j;

        if (in[i] < BASE64DE_FIRST || in[i] > BASE64DE_LAST ||
            (c = base64de[in[i] - BASE64DE_FIRST]) == -1)
            return 0;

        switch (s) {
        case 0:
            out[j] = ((unsigned int)c << 2) & 0xFF;
            continue;
        case 1:
            out[j++] += ((unsigned int)c >> 4) & 0x3;

            /* if not last char with padding */
            if (i < (inlen - 3) || in[inlen - 2] != '=')
                out[j] = ((unsigned int)c & 0xF) << 4;
            continue;
        case 2:
            out[j++] += ((unsigned int)c >> 2) & 0xF;

            /* if not last char with padding */
            if (i < (inlen - 2) || in[inlen - 1] != '=')
                out[j] =  ((unsigned int)c & 0x3) << 6;
            continue;
        case 3:
            out[j++] += (unsigned char)c;
        }
    }

    return j;
}

#define T_LEN 8
#define MAX_LEN 512

const int DIGITS_POWER[]
//  0  1   2    3     4      5       6        7         8
    = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

static
int hmac_totp(const char *key,
              const unsigned char *msg,
              char *hash,
              int hash_max,
              const EVP_MD *md,
              unsigned int key_len) {
    int len = 0;
    unsigned char buff[MAX_LEN];
    HMAC_CTX *ctx;

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    HMAC_CTX static_ctx;

    ctx = &static_ctx;
    HMAC_CTX_init(ctx);
#else
    ctx = HMAC_CTX_new();
#endif

    HMAC_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    if (!HMAC_Init_ex(ctx, key, key_len, md, NULL)) goto end;
    if (!HMAC_Update(ctx, msg, T_LEN)) goto end;
    if (!HMAC_Final(ctx, buff, (unsigned int *)&len)) goto end;
    memcpy_s(hash, hash_max, buff, len);

end:
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    HMAC_CTX_cleanup(ctx);
#else
    if (ctx) HMAC_CTX_free(ctx);
#endif

    return len;
}

static ACVP_RESULT totp(char **token, int token_max) {
    char hash[MAX_LEN] = {0};
    int os, bin, otp;
    int md_len;
    char format[5];
    time_t t;
    unsigned char token_buff[T_LEN + 1] = {0};
    char *new_seed = calloc(ACVP_TOTP_TOKEN_MAX, sizeof(char));
    char *seed = NULL;
    int seed_len = 0;

    if (!new_seed) {
        printf("Failed to malloc new_seed\n");
        return ACVP_MALLOC_FAIL;
    }

    seed = getenv("ACV_TOTP_SEED");
    if (!seed) {
        printf("Failed to get TOTP seed\n");
        free(new_seed);
        return ACVP_TOTP_MISSING_SEED;
    }

    t = time(NULL);

    // RFC4226
    t = t / 30;
    token_buff[0] = (t >> T_LEN * 7) & 0xff;
    token_buff[1] = (t >> T_LEN * 6) & 0xff;
    token_buff[2] = (t >> T_LEN * 5) & 0xff;
    token_buff[3] = (t >> T_LEN * 4) & 0xff;
    token_buff[4] = (t >> T_LEN * 3) & 0xff;
    token_buff[5] = (t >> T_LEN * 2) & 0xff;
    token_buff[6] = (t >> T_LEN * 1) & 0xff;
    token_buff[7] = t & 0xff;

#define MAX_SEED_LEN 64
    seed_len = base64_decode(seed, strnlen_s(seed, MAX_SEED_LEN), (unsigned char *)new_seed);
    if (seed_len  == 0) {
        printf("Failed to decode TOTP seed\n");
        free(new_seed);
        return ACVP_TOTP_DECODE_FAIL;
    }


    // use passed hash function
    md_len = hmac_totp(new_seed, token_buff, hash, sizeof(hash), EVP_sha256(), seed_len);
    if (md_len == 0) {
        printf("Failed to create TOTP\n");
        free(new_seed);
        return ACVP_CRYPTO_MODULE_FAIL;
    }
    os = hash[(int)md_len - 1] & 0xf;

    bin = ((hash[os + 0] & 0x7f) << 24) |
          ((hash[os + 1] & 0xff) << 16) |
          ((hash[os + 2] & 0xff) <<  8) |
          ((hash[os + 3] & 0xff) <<  0);

    otp = bin % DIGITS_POWER[ACVP_TOTP_LENGTH];

    // generate format string like "%06d" to fix digits using 0
    sprintf(format, "%c0%ldd", '%', (long int)ACVP_TOTP_LENGTH);

    sprintf((char *)token_buff, format, otp);
    memcpy_s((char *)*token, token_max, token_buff, ACVP_TOTP_LENGTH);
    free(new_seed);
    return ACVP_SUCCESS;
}
