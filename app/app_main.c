/*
 * Copyright (c) 2023, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

/*
 * This module is not part of libacvp.  Rather, it's a simple app that
 * demonstrates how to use libacvp. Software that use libacvp
 * will need to implement a similar module.
 *
 * It will default to 127.0.0.1 port 443 if no arguments are given.
 */
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "app_lcl.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#include <openssl/evp.h>
#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif
#endif

#include "safe_mem_lib.h"
#include "safe_str_lib.h"

#if !defined OPENSSL_NO_DSA && OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_dsa(ACVP_CTX *ctx);
static int enable_kas_ffc(ACVP_CTX *ctx);
static int enable_safe_primes(ACVP_CTX *ctx);
#endif
static int enable_aes(ACVP_CTX *ctx);
static int enable_tdes(ACVP_CTX *ctx);
static int enable_hash(ACVP_CTX *ctx);
static int enable_cmac(ACVP_CTX *ctx);
static int enable_hmac(ACVP_CTX *ctx);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kmac(ACVP_CTX *ctx);
static int enable_rsa(ACVP_CTX *ctx);
static int enable_ecdsa(ACVP_CTX *ctx);
static int enable_drbg(ACVP_CTX *ctx);
static int enable_kas_ecc(ACVP_CTX *ctx);
static int enable_kas_ifc(ACVP_CTX *ctx);
static int enable_kda(ACVP_CTX *ctx);
static int enable_kts_ifc(ACVP_CTX *ctx);
static int enable_kdf(ACVP_CTX *ctx);
#endif
#ifdef ACVPAPP_LMS_SUPPORT
static int enable_lms(ACVP_CTX *ctx);
#endif

const char *server;
int port;
const char *ca_chain_file;
char *cert_file;
char *key_file;
const char *path_segment;
const char *api_context;
char value[JSON_STRING_LENGTH] = "same";

#define CHECK_ENABLE_CAP_RV(rv) \
    if (rv != ACVP_SUCCESS) { \
        printf("Failed to register capability with libacvp (rv=%d: %s)\n", rv, acvp_lookup_error_string(rv)); \
        goto end; \
    }

/*
 * Read the operational parameters from the various environment
 * variables.
 */
static void setup_session_parameters(void) {
    char *tmp;

    server = getenv("ACV_SERVER");
    if (!server) {
         server = DEFAULT_SERVER;
     }

    tmp = getenv("ACV_PORT");
    if (tmp) port = atoi(tmp);
    if (!port) port = DEFAULT_PORT;

    path_segment = getenv("ACV_URI_PREFIX");
    if (!path_segment) path_segment = DEFAULT_URI_PREFIX;

    api_context = getenv("ACV_API_CONTEXT");
    if (!api_context) api_context = "";

    ca_chain_file = getenv("ACV_CA_FILE");
    cert_file = getenv("ACV_CERT_FILE");
    key_file = getenv("ACV_KEY_FILE");

    printf("Using the following parameters:\n\n");
    printf("    ACV_SERVER:     %s\n", server);
    printf("    ACV_PORT:       %d\n", port);
    printf("    ACV_URI_PREFIX: %s\n", path_segment);
    if (ca_chain_file) printf("    ACV_CA_FILE:    %s\n", ca_chain_file);
    if (cert_file) printf("    ACV_CERT_FILE:  %s\n", cert_file);
    if (key_file) printf("    ACV_KEY_FILE:   %s\n", key_file);
    printf("\n");
}

#define CHECK_NON_ALLOWED_ALG(enabled, str) \
    if (enabled != 0) { \
        printf("%s\n", str); \
        rv = 0; \
    }

static int verify_algorithms(APP_CONFIG *cfg) {
    int rv = 1;

    if (!cfg) {
        return 0;
    }

    /* If we are testing "all" then we don't need to tell the user they can't test algs */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!cfg->testall) {
        CHECK_NON_ALLOWED_ALG(cfg->dsa, "This version of OpenSSL does not support DSA testing");
        CHECK_NON_ALLOWED_ALG(cfg->rsa, "This version of OpenSSL does not support RSA testing");
        CHECK_NON_ALLOWED_ALG(cfg->drbg, "This version of OpenSSL does not support DRBG testing");
        CHECK_NON_ALLOWED_ALG(cfg->ecdsa, "This version of OpenSSL does not support ECDSA testing");
        CHECK_NON_ALLOWED_ALG(cfg->kas_ecc, "This version of OpenSSL does not support KAS-ECC testing");
        CHECK_NON_ALLOWED_ALG(cfg->kas_ffc, "This version of OpenSSL does not support KAS-FFC testing");
        CHECK_NON_ALLOWED_ALG(cfg->kas_ifc, "This version of OpenSSL does not support KAS-IFC testing");
        CHECK_NON_ALLOWED_ALG(cfg->kda, "This version of OpenSSL does not support KDA testing");
        CHECK_NON_ALLOWED_ALG(cfg->kts_ifc, "This version of OpenSSL does not support KTS-IFC testing");
        CHECK_NON_ALLOWED_ALG(cfg->kdf, "This version of OpenSSL does not support KDF testing");
        CHECK_NON_ALLOWED_ALG(cfg->safe_primes, "This version of OpenSSL does not support safe primes testing");
    }
#endif
#ifdef OPENSSL_NO_DSA
    if (!cfg->testall) {
        CHECK_NON_ALLOWED_ALG(cfg->dsa, "This version of OpenSSL does not support DSA testing (DSA disabled)");
        CHECK_NON_ALLOWED_ALG(cfg->kas_ffc, "This version of OpenSSL does not support KAS-FFC testing (DSA disabled)");
        CHECK_NON_ALLOWED_ALG(cfg->safe_primes, "This version of OpenSSL does not support safe primes testing");
    }
#endif

    return rv;
}

/* libacvp calls this function for status updates, debugs, warnings, and errors. */
static ACVP_RESULT progress(char *msg, ACVP_LOG_LVL level) {

    printf("[ACVP]");

    switch (level) {
    case ACVP_LOG_LVL_ERR:
        printf(ANSI_COLOR_RED "[ERROR]" ANSI_COLOR_RESET);
        break;
    case ACVP_LOG_LVL_WARN:
        printf(ANSI_COLOR_YELLOW "[WARNING]" ANSI_COLOR_RESET);
        break;
    case ACVP_LOG_LVL_STATUS:
    case ACVP_LOG_LVL_INFO:
    case ACVP_LOG_LVL_VERBOSE:
    case ACVP_LOG_LVL_DEBUG:
    case ACVP_LOG_LVL_NONE:
    case ACVP_LOG_LVL_MAX:
    default:
        break;
    }

    printf(": %s\n", msg);

    return ACVP_SUCCESS;
}

static void app_cleanup(ACVP_CTX *ctx) {
    // Routines for libacvp
    acvp_cleanup(ctx);

    // Routines for this application
    app_aes_cleanup();
    app_des_cleanup();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#ifndef OPENSSL_NO_DSA
    app_dsa_cleanup();
#endif
    app_rsa_cleanup();
    app_ecdsa_cleanup();
#endif
}

#ifndef ACVP_APP_LIB_WRAPPER
int main(int argc, char **argv) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_CTX *ctx = NULL;
    APP_CONFIG cfg;
    int diff = 0;

    memset_s(&cfg, sizeof(APP_CONFIG), 0, sizeof(APP_CONFIG));
    if (ingest_cli(&cfg, argc, argv)) {
        return 1;
    }

    if (!verify_algorithms(&cfg)) {
        printf("\nAlgorithm tests not supported by this crypto module have been requested. Please \n");
        printf("verify your testing capablities and try again.\n");
        return 1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (!cfg.disable_fips) {
        /* sets the property "fips=yes" to be included implicitly in cipher fetches */
        EVP_default_properties_enable_fips(NULL, 1);
        if (!EVP_default_properties_is_fips_enabled(NULL)) {
            printf("Error setting FIPS property at startup\n\n");
            return 1;
        }
        /* Run a quick sanity check to determine that the FIPS provider is functioning properly */
        rv = fips_sanity_check();
        if (rv != ACVP_SUCCESS) {
            printf("Error occured when testing FIPS at startup (rv = %d). Please verify the FIPS provider is\n", rv);
            printf("properly installed and configured. Exiting...\n\n");
            return 1;
        }
    } else {
        printf("***********************************************************************************\n");
        printf("* WARNING: You have chosen to not fetch the FIPS provider for this run. Any tests *\n");
        printf("* created or performed during this run MUST NOT have any validation requested     *\n");
        printf("* on it unless the FIPS provider is exclusively loaded or enabled by default in   *\n");
        printf("* your configuration. Proceed at your own risk. Continuing in 5 seconds...        *\n");
        printf("***********************************************************************************\n");
        printf("\n");
        acvp_sleep(5);
    }
#endif

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

    /* Next we specify the ACVP server address */
    rv = acvp_set_server(ctx, server, port);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set server/port\n");
        goto end;
    }

    /* Set the api context prefix if needed */
    rv = acvp_set_api_context(ctx, api_context);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set URI prefix\n");
        goto end;
    }

    /* Set the path segment prefix if needed */
    rv = acvp_set_path_segment(ctx, path_segment);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set URI prefix\n");
        goto end;
    }

    if (ca_chain_file) {
        /*
         * Next we provide the CA certs to be used by libacvp
         * to verify the ACVP TLS certificate.
         */
        rv = acvp_set_cacerts(ctx, ca_chain_file);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set CA certs\n");
            goto end;
        }
    }

    if (cert_file && key_file) {
        /*
         * Specify the certificate and private key the client should used
         * for TLS client auth.
         */
        rv = acvp_set_certkey(ctx, cert_file, key_file);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set TLS cert/key\n");
            goto end;
        }
    }

    /*
     * Setup the Two-factor authentication
     * This may or may not be turned on...
     */
    if (app_setup_two_factor_auth(ctx)) {
        goto end;
    }

    if (cfg.sample) {
        acvp_mark_as_sample(ctx);
    }

    if (cfg.get) {
        rv = acvp_mark_as_get_only(ctx, cfg.get_string, cfg.save_to ? cfg.save_file : NULL);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to mark as get only.\n");
            goto end;
        }
    }

    if (cfg.post) {
        acvp_mark_as_post_only(ctx, cfg.post_filename);
    }

    if (cfg.delete) {
        acvp_mark_as_delete_only(ctx, cfg.delete_url);
    }

    if (cfg.vector_req && !cfg.vector_rsp) {
        acvp_mark_as_request_only(ctx, cfg.vector_req_file);
    }

    if (!cfg.vector_req && cfg.vector_rsp) {
        printf("Offline vector processing requires both options, --vector_req and --vector_rsp\n");
        goto end;
    }

    if (cfg.manual_reg) {
        /*
         * Using a JSON to register allows us to skip the
         * "acvp_enable_*" API calls... could reduce the
         * size of this file if you choose to use this capability.
         */
        rv = acvp_set_registration_file(ctx, cfg.reg_file);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set json file within ACVP ctx (rv=%d)\n", rv);
            goto end;
        }
    } else {
        /*
         * We need to register all the crypto module capabilities that will be
         * validated. Each has their own method for readability.
         */
        if (cfg.aes) { if (enable_aes(ctx)) goto end; }
        if (cfg.tdes) { if (enable_tdes(ctx)) goto end; }
        if (cfg.hash) { if (enable_hash(ctx)) goto end; }
        if (cfg.cmac) { if (enable_cmac(ctx)) goto end; }
        if (cfg.hmac) { if (enable_hmac(ctx)) goto end; }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (cfg.kmac) { if (enable_kmac(ctx)) goto end; }
        if (cfg.kdf) { if (enable_kdf(ctx)) goto end; }
        if (cfg.rsa) { if (enable_rsa(ctx)) goto end; }
        if (cfg.ecdsa) { if (enable_ecdsa(ctx)) goto end; }
        if (cfg.drbg) { if (enable_drbg(ctx)) goto end; }
        if (cfg.kas_ecc) { if (enable_kas_ecc(ctx)) goto end; }
        if (cfg.kas_ifc) { if (enable_kas_ifc(ctx)) goto end; }
        if (cfg.kts_ifc) { if (enable_kts_ifc(ctx)) goto end; }
        if (cfg.kda) { if (enable_kda(ctx)) goto end; }
#ifndef OPENSSL_NO_DSA
        if (cfg.dsa) { if (enable_dsa(ctx)) goto end; }
        if (cfg.kas_ffc) { if (enable_kas_ffc(ctx)) goto end; }
        if (cfg.safe_primes) { if (enable_safe_primes(ctx)) goto end; }
#endif
#endif
#ifdef ACVPAPP_LMS_SUPPORT
        if (cfg.lms) { if (enable_lms(ctx)) goto end; }
#endif
    }

    if (cfg.get_cost) {
        diff = acvp_get_vector_set_count(ctx);
        if (diff < 0) {
            printf("Unable to get expected vector set count with given test session context.\n\n");
        } else {
            printf("The given test session context is expected to generate %d vector sets.\n\n", diff);
        }
        goto end;
    }

    if (cfg.get_reg) {
        char *reg = NULL;
        reg = acvp_get_current_registration(ctx, NULL);
        if (!reg) {
            printf("Error occured while getting current registration.\n");
            goto end;
        }
        if (cfg.save_to) {
            if (save_string_to_file((const char *)reg, (const char *)&cfg.save_file)) {
                printf("Error occured while saving registration to file. Exiting...\n");
            } else {
                printf("Succesfully saved registration to given file. Exiting...\n");
            }
        } else {
            printf("%s\n", reg);
            printf("Completed output of current registration. Exiting...\n");
        }
        if (reg) free(reg);
        goto end;
    }

    if (cfg.vector_req && cfg.vector_rsp) {
       rv = acvp_run_vectors_from_file(ctx, cfg.vector_req_file, cfg.vector_rsp_file);
       goto end;
    }

    strncmp_s(DEFAULT_SERVER, DEFAULT_SERVER_LEN, server, DEFAULT_SERVER_LEN, &diff);
    if (!diff) {
         printf("Warning: No server set, using default. Please define ACV_SERVER in your environment.\n");
         printf("Run acvp_app --help for more information on this and other environment variables.\n\n");
    }

    if (cfg.fips_validation) {
        unsigned int module_id = 1, oe_id = 1;

        /* Provide the metadata needed for a FIPS validation. */
        rv = acvp_oe_ingest_metadata(ctx, cfg.validation_metadata_file);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to read validation_metadata_file\n");
            goto end;
        }

        /*
         * Tell the library which Module and Operating Environment to use
         * when doing the FIPS validation.
         */
        rv = acvp_oe_set_fips_validation_metadata(ctx, module_id, oe_id);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set metadata for FIPS validation\n");
            goto end;
        }
    }

    if (cfg.vector_upload) {
       rv = acvp_upload_vectors_from_file(ctx, cfg.vector_upload_file, cfg.fips_validation);
       goto end;
    }

    /* PUT without algorithms submits put_filename for validation using save JWT and testSession ID */
    if (cfg.empty_alg && cfg.put) {
         rv = acvp_put_data_from_file(ctx, cfg.put_filename);
         goto end;
    }
    /* PUT with alg testing will submit put_filename with module/oe information */
    if (!cfg.empty_alg && cfg.put) {
        acvp_mark_as_put_after_test(ctx, cfg.put_filename);
    }
    
    if (cfg.get_results) {
        rv = acvp_get_results_from_server(ctx, cfg.session_file);
        goto end;
    }
    
    if (cfg.resume_session) {
        rv = acvp_resume_test_session(ctx, cfg.session_file, cfg.fips_validation);
        goto end;
    }

    if (cfg.cancel_session) {
        if (cfg.save_to) {
            rv = acvp_cancel_test_session(ctx, cfg.session_file, cfg.save_file);
        } else {
            rv = acvp_cancel_test_session(ctx, cfg.session_file, NULL);
        }
        goto end;
    }

    if (cfg.get_expected) {
        if (cfg.save_to) {
            rv = acvp_get_expected_results(ctx, cfg.session_file, cfg.save_file);
        } else {
            rv = acvp_get_expected_results(ctx, cfg.session_file, NULL);
        }
        goto end;
    }
    
    /*
     * Run the test session.
     * Perform a FIPS validation on this test session if specified.
     */
    acvp_run(ctx, cfg.fips_validation);

end:
    /*
     * Free all memory associated with
     * both the application and libacvp.
     */
    app_cleanup(ctx);

    return rv;
}
#endif

static int enable_aes(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /* Enable AES_GCM */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_EITHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_DOMAIN_IVLEN, 96, 1024, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 104);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 112);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 120);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_DOMAIN_PTLEN, 8, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_IVLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_DOMAIN_PTLEN, 0, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable AES-ECB 128,192,256 bit key */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_ECB, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
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

    /* Enable AES-CBC 128 bit key */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* Enable AES-CBC-CS1, CS2, and CS3 */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS1, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS2, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS3, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_DOMAIN_PTLEN, 136, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    /* Enable AES-CFB1 128,192,256 bit key */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB1, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
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

    /* Enable AES-CFB8 128,192,256 bit key */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB8, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
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

    /* Enable AES-CFB128 128,192,256 bit key */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB128, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
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

    /* Enable AES-OFB 128, 192, 256 bit key */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_OFB, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
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

    /* Register AES CCM capabilities */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CCM, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_CCM, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
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
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_DOMAIN_PTLEN, 0, 256, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 80);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 112);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_DOMAIN_IVLEN, 56, 104, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_DOMAIN_AADLEN, 0, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);

    /* AES-KW */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_KW, &app_aes_keywrap_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_INVERSE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 524288, 128);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 64);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L || defined OPENSSL_KWP
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_KWP, &app_aes_keywrap_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_INVERSE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_DOMAIN_PTLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    /* Enable AES-XTS 128 and 256 bit key */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_XTS, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_TWEAK, ACVP_SYM_CIPH_TWEAK_HEX);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 128);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_DOMAIN_PTLEN, 256, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
#endif
#if 0
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_DOMAIN_DULEN, 256, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    /* Enable AES-CTR 128, 192, 256 bit key */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CTR, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);

    //CTR_INCR and CTR_OVRFLW are ignored by server if PERFORM_CTR is false - can remove those calls if so
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_PERFORM_CTR, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CTR_INCR, 1);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CTR_OVRFLW, 0);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    CHECK_ENABLE_CAP_RV(rv);
#endif

#if 0 //Support for AES-CTR RFC3686 conformance
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CONFORMANCE, ACVP_CONFORMANCE_RFC3686);
    CHECK_ENABLE_CAP_RV(rv);
    //if ivGen is internal, ensure generated IV's least significant 32 bits are 1
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
#endif
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_DOMAIN_PTLEN, 8, 128, 8);
    CHECK_ENABLE_CAP_RV(rv);

    //GMAC
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GMAC, &app_aes_handler_gmac);
#else
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GMAC, &app_aes_handler_aead);
#endif
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GMAC, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GMAC, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_EITHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 104);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 112);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 120);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_DOMAIN_AADLEN, 256, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_IVLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);

#if 0 //not currently supported by openSSL
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM_SIV, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM_SIV, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM_SIV, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_DOMAIN_PTLEN, 0, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
#endif

#if 0 //AES-XPN not currently supported by openSSL
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_XPN, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_XPN, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_XPN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_PARM_SALT_SRC, ACVP_SYM_CIPH_SALT_SRC_EXT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_DOMAIN_PTLEN, 0, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
#endif

end:

    return rv;
}

static int enable_tdes(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /* Enable 3DES-ECB */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_ECB, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable 3DES-CBC */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CBC, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

#if 0
    /* Enable 3DES-CBCI */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CBCI, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBCI, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBCI, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_OFBI, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFBI, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFBI, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFBP1, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFBP1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFBP1, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFBP8, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFBP8, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFBP8, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFBP64, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFBP64, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFBP64, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* Enable 3DES-OFB */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_OFB, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable 3DES-CFB64 */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB64, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable 3DES-CFB8 */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB8, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable 3DES-CFB1 */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB1, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);
#endif

end:
    return rv;
}

static int enable_hash(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /* Enable SHA-1 and SHA-2 */
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA1, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA224, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA224, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA256, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA384, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA384, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA512, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA512, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    /* SHA2-512/224 and SHA2-512/256 */
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA512_224, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA512_224, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA512_256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA512_256, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    /* SHA3 and SHAKE */
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA3_224, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_224, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_224, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA3_224, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA3_256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA3_384, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_384, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_384, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA3_384, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA3_512, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_512, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_512, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA3_512, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHAKE_128, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHAKE_128, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHAKE_128, ACVP_HASH_OUT_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHAKE_128, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHAKE_128, ACVP_HASH_OUT_LENGTH, 16, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);


    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHAKE_256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHAKE_256, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHAKE_256, ACVP_HASH_OUT_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHAKE_256, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHAKE_256, ACVP_HASH_OUT_LENGTH, 16, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

#ifdef ACVPAPP_HASH_LDT_SUPPORT
    /* See app_sha.c for details about performing LDT */
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA1, ACVP_HASH_LARGE_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA1, ACVP_HASH_LARGE_DATA, 2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA1, ACVP_HASH_LARGE_DATA, 4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA1, ACVP_HASH_LARGE_DATA, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA224, ACVP_HASH_LARGE_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA224, ACVP_HASH_LARGE_DATA, 2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA224, ACVP_HASH_LARGE_DATA, 4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA224, ACVP_HASH_LARGE_DATA, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA256, ACVP_HASH_LARGE_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA256, ACVP_HASH_LARGE_DATA, 2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA256, ACVP_HASH_LARGE_DATA, 4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA256, ACVP_HASH_LARGE_DATA, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA384, ACVP_HASH_LARGE_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA384, ACVP_HASH_LARGE_DATA, 2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA384, ACVP_HASH_LARGE_DATA, 4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA384, ACVP_HASH_LARGE_DATA, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512, ACVP_HASH_LARGE_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512, ACVP_HASH_LARGE_DATA, 2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512, ACVP_HASH_LARGE_DATA, 4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512, ACVP_HASH_LARGE_DATA, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512_224, ACVP_HASH_LARGE_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512_224, ACVP_HASH_LARGE_DATA, 2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512_224, ACVP_HASH_LARGE_DATA, 4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512_224, ACVP_HASH_LARGE_DATA, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512_256, ACVP_HASH_LARGE_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512_256, ACVP_HASH_LARGE_DATA, 2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512_256, ACVP_HASH_LARGE_DATA, 4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512_256, ACVP_HASH_LARGE_DATA, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_224, ACVP_HASH_LARGE_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_224, ACVP_HASH_LARGE_DATA, 2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_224, ACVP_HASH_LARGE_DATA, 4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_224, ACVP_HASH_LARGE_DATA, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_LARGE_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_LARGE_DATA, 2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_LARGE_DATA, 4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_LARGE_DATA, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_384, ACVP_HASH_LARGE_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_384, ACVP_HASH_LARGE_DATA, 2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_384, ACVP_HASH_LARGE_DATA, 4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_384, ACVP_HASH_LARGE_DATA, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_512, ACVP_HASH_LARGE_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_512, ACVP_HASH_LARGE_DATA, 2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_512, ACVP_HASH_LARGE_DATA, 4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_512, ACVP_HASH_LARGE_DATA, 8);
    CHECK_ENABLE_CAP_RV(rv);
#endif
end:
    return rv;
}

static int enable_cmac(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /* Enable CMAC */
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &app_cmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_AES, ACVP_CMAC_MSGLEN, 0, 524288, 8);
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

#if OPENSSL_VERSION_NUMBER < 0x30000000L
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
#endif
end:

    return rv;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kmac(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /* Enable KMAC */
    rv = acvp_cap_kmac_enable(ctx, ACVP_KMAC_128, &app_kmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_128, ACVP_KMAC_MSGLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_128, ACVP_KMAC_MACLEN, 32, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_128, ACVP_KMAC_KEYLEN, 128, 1024, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_128, ACVP_KMAC_XOF_SUPPORT, ACVP_XOF_SUPPORT_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    /* OpenSSL 3.X supports hex customization strings, but they are not on the FIPS cert, so leaving disabled */
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_128, ACVP_KMAC_HEX_CUSTOM_SUPPORT, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kmac_enable(ctx, ACVP_KMAC_256, &app_kmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_256, ACVP_KMAC_MSGLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_256, ACVP_KMAC_MACLEN, 32, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_256, ACVP_KMAC_KEYLEN, 128, 1024, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_256, ACVP_KMAC_XOF_SUPPORT, ACVP_XOF_SUPPORT_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    /* OpenSSL 3.X supports hex customization strings, but they are not on the FIPS cert, so leaving disabled */
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_256, ACVP_KMAC_HEX_CUSTOM_SUPPORT, 0);
    CHECK_ENABLE_CAP_RV(rv);
end:
    return rv;
}
#endif

static int enable_hmac(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA1, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_MACLEN, 32, 160, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA1, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_224, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_MACLEN, 32, 224, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_224, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_256, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_MACLEN, 32, 256, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_256, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_384, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_MACLEN, 32, 384, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_384, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_MACLEN, 32, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_512, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512_224, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512_224, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512_224, ACVP_HMAC_MACLEN, 32, 224, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_512_224, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512_256, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512_256, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512_256, ACVP_HMAC_MACLEN, 32, 256, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_512_256, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA3_224, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_224, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_224, ACVP_HMAC_MACLEN, 32, 224, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA3_224, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA3_256, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_256, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_256, ACVP_HMAC_MACLEN, 32, 256, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA3_256, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA3_384, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_384, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_384, ACVP_HMAC_MACLEN, 32, 384, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA3_384, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA3_512, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_512, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_512, ACVP_HMAC_MACLEN, 32, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA3_512, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
end:

    return rv;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kdf(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    int flags = 0;

    rv = acvp_cap_kdf_tls12_enable(ctx, &app_kdf_tls12_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

#if 0
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
#endif
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
#if 0
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
#endif
#if 0 // Disabled for now
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
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_kdf135_x942_enable(ctx, &app_kdf135_x942_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X942, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_KDF_TYPE, ACVP_KDF_X942_KDF_TYPE_DER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA3_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA3_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA3_384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA3_512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_domain(ctx, ACVP_KDF_X942_KEY_LEN, 8, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_domain(ctx, ACVP_KDF_X942_OTHER_INFO_LEN, 0, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_domain(ctx, ACVP_KDF_X942_ZZ_LEN, 8, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_domain(ctx, ACVP_KDF_X942_SUPP_INFO_LEN, 0, 120, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_OID, ACVP_KDF_X942_OID_AES128KW);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_OID, ACVP_KDF_X942_OID_AES192KW);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_OID, ACVP_KDF_X942_OID_AES256KW);
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
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_KEY_DATA_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_KEY_DATA_LEN, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_FIELD_SIZE, 224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_FIELD_SIZE, 571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_SHARED_INFO_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_SHARED_INFO_LEN, 1024);
    CHECK_ENABLE_CAP_RV(rv);

    /* KDF108 Counter Mode */
    rv = acvp_cap_kdf108_enable(ctx, &app_kdf108_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF108, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF108, ACVP_PREREQ_CMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 72);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 776);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 3456);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES256);
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
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_COUNTER_LEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_BEFORE);
    CHECK_ENABLE_CAP_RV(rv);
    /* KDF108 Feedback Mode */
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 72);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 776);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 3456);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTS_EMPTY_IV, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_REQUIRES_EMPTY_IV, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_COUNTER_LEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_BEFORE);
    CHECK_ENABLE_CAP_RV(rv);

    /* KDF108 KMAC Mode */
#if 0
    /* Only valid for OpenSSL 3.1 */
    /* Call sequence is very close to regular kdf108, with no creation of fixed data */
    #if OPENSSL_VERSION_NUMBER >= 0x30100000L
	rv = acvp_cap_set_prereq(ctx, ACVP_KDF108, ACVP_PREREQ_KMAC, value);
	CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_KMAC, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_KMAC_128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_KMAC, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_KMAC_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_KMAC, ACVP_KDF108_DERIVATION_KEYLEN, 112, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_KMAC, ACVP_KDF108_DERIVED_KEYLEN, 112, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_KMAC, ACVP_KDF108_CONTEXT_LEN, 8, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_KMAC, ACVP_KDF108_LABEL_LEN, 8, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    #endif
#endif

    /* PBKDF */
    rv = acvp_cap_pbkdf_enable(ctx, &app_pbkdf_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_PBKDF, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_ITERATION_COUNT, 1, 10000, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_KEY_LEN, 112, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_PASSWORD_LEN, 8, 128, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_SALT_LEN, 128, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    rv = acvp_cap_kdf_tls13_enable(ctx, &app_kdf_tls13_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS13, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_DHE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK_DHE);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kas_ecc(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /* Enable KAS-ECC.... */
    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &app_kas_ecc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_PREREQ_ECDSA, value);
    CHECK_ENABLE_CAP_RV(rv);
#ifdef ACVP_ENABLE_DEPRECATED_VERSION
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_REVISION, ACVP_REVISION_SP800_56AR3);
    CHECK_ENABLE_CAP_RV(rv);
#endif
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

#ifdef ACVP_ENABLE_DEPRECATED_VERSION
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
#endif

    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_SSC, &app_kas_ecc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_ECDSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
#if 0
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_HASH, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_HASH, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_HASH, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_HASH, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_HASH, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_HASH, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_HASH, ACVP_SHA3_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_HASH, ACVP_SHA3_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_HASH, ACVP_SHA3_384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_HASH, ACVP_SHA3_512);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_HASH, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
#endif

end:

    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kas_ifc(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    BIGNUM *expo = NULL;
    char *expo_str = NULL;

    expo = BN_new();
    if (!expo || !BN_set_word(expo, RSA_F4)) {
        printf("oh no\n");
        return 1;
    }
    expo_str = BN_bn2hex(expo);
    BN_free(expo);

    rv = acvp_cap_kas_ifc_enable(ctx, ACVP_KAS_IFC_SSC, &app_kas_ifc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_RSA, value);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 /* no longer used, left here for historical purposes */
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_RSADP, value);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_exponent(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_FIXEDPUBEXP, expo_str);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS2, ACVP_KAS_IFC_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS2, ACVP_KAS_IFC_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 8192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG1_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG2_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG1_PRIME_FACTOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG2_PRIME_FACTOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG1_CRT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG2_CRT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA3_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA3_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA3_384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA3_512);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG1_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
#if 0
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
#endif
#endif

end:
    if (expo_str) free(expo_str);
    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kts_ifc(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    BIGNUM *expo = NULL;
    char *expo_str = NULL;
    char iut_id[] = "DEADDEAD";
    char concatenation[] = "concatenation";

    expo = BN_new();
    if (!expo || !BN_set_word(expo, RSA_F4)) {
        printf("oh no\n");
        return 1;
    }
    expo_str = BN_bn2hex(expo);
    BN_free(expo);

    rv = acvp_cap_kts_ifc_enable(ctx, ACVP_KTS_IFC, &app_kts_ifc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_RSA, value);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 /* no longer used, left here for historical purposes */
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_RSADP, value);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_param_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FIXEDPUBEXP, expo_str);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_param_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_IUT_ID, iut_id);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FUNCTION, ACVP_KTS_IFC_KEYPAIR_GEN);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FUNCTION, ACVP_KTS_IFC_PARTIAL_VAL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 4096);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG1_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG2_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG1_PRIME_FACTOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG2_PRIME_FACTOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG1_CRT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG2_CRT);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG1_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_SCHEME, ACVP_KTS_IFC_KAS1_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ROLE, ACVP_KTS_IFC_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ROLE, ACVP_KTS_IFC_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA3_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA3_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA3_384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA3_512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_L, 1024);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_L, 512);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_NULL_ASSOC_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ENCODING, concatenation);
    CHECK_ENABLE_CAP_RV(rv);

end:
    if (expo_str) free(expo_str);
    return rv;
}
#endif

#if !defined OPENSSL_NO_DSA && OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kas_ffc(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

#ifdef ACVP_ENABLE_DEPRECATED_VERSION
    /* Enable KAS-FFC.... */
    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_COMP, &app_kas_ffc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_SAFE_PRIMES, value);
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
#endif

    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_SSC, &app_kas_ffc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_SAFE_PRIMES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_DSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
#if 0
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FB);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_MODP2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_MODP3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_MODP4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_MODP6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_MODP8192);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FFDHE2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FFDHE3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FFDHE4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FFDHE6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FFDHE8192);
    CHECK_ENABLE_CAP_RV(rv);
end:

    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kda(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_HKDF, &app_kda_hkdf_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_HKDF, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 /* example of how hybrid secret usage can be registered */
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_USE_HYBRID_SECRET, 512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_USE_HYBRID_SECRET, 520, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_HKDF, ACVP_KDA_USE_HYBRID_SECRET, 1024, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA1, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_HKDF, ACVP_KDA_Z, 224, 8192, 8);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_REVISION, ACVP_REVISION_SP800_56CR1, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LITERAL, "0123456789ABCDEF");
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_CONTEXT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LABEL, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_HKDF, ACVP_KDA_Z, 224, 1024, 8);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA512_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA512_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA3_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA3_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA3_384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA3_512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_L, 2048, NULL);
    CHECK_ENABLE_CAP_RV(rv);

    // kdf onestep
    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_ONESTEP, &app_kda_onestep_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_ONESTEP, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_ONESTEP, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_ONESTEP, ACVP_PREREQ_KMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_KMAC_128, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_Z, 224, 8192, 8);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_REVISION, ACVP_REVISION_SP800_56CR1, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LITERAL, "0123456789ABCDEF");
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_CONTEXT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LABEL, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA512_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA512_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA3_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA3_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA3_384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA3_512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_512_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_512_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA3_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA3_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA3_384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA3_512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_Z, 224, 1024, 8);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_L, 2048, NULL);
    CHECK_ENABLE_CAP_RV(rv);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_TWOSTEP, &app_kda_twostep_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_TWOSTEP, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 /* example of how hybrid secret usage can be registered */
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_USE_HYBRID_SECRET, 512, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_USE_HYBRID_SECRET, 520, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_domain(ctx, ACVP_KDA_USE_HYBRID_SECRET, 1024, 4096, 8, 0);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_L, 2048, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_domain(ctx, ACVP_KDA_Z, 224, 8192, 8, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);

    /* Most parameters are set in groups based on the KDF108 mode */
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA1, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA224, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA256, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA384, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA512, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA512_224, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA512_256, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA3_224, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA3_256, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA3_384, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA3_512, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_TWOSTEP_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_AFTER, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_TWOSTEP_COUNTER_LEN, 8, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV, 1, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV, 1, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_TWOSTEP_SUPPORTED_LEN, 2048, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
#endif

end:
   return rv;
}
#endif

#if !defined OPENSSL_NO_DSA && OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_dsa(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

#ifndef ACVP_FIPS186_5
    /* Enable DSA.... */
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENG, ACVP_DSA_UNVERIFIABLE);
    CHECK_ENABLE_CAP_RV(rv);
#endif
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN3072_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
#endif
#endif

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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_GENG, ACVP_DSA_UNVERIFIABLE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
#endif

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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN3072_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
#endif

#ifndef ACVP_FIPS186_5
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_KEYGEN, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_KEYGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_KEYGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_224, ACVP_NO_SHA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_256, ACVP_NO_SHA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN3072_256, ACVP_NO_SHA);
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
#endif
#endif

    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_SIGVER, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
#endif
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
#endif
end:

    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_rsa(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    BIGNUM *expo = NULL;
    char *expo_str = NULL;

    expo = BN_new();
    if (!expo || !BN_set_word(expo, RSA_F4)) {
        printf("oh no\n");
        return 1;
    }
    expo_str = BN_bn2hex(expo);
    BN_free(expo);

    /* Enable RSA keygen... */
    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &app_rsa_keygen_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_INFO_GEN_BY_SERVER, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_KEY_FORMAT, ACVP_RSA_KEY_FORMAT_CRT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_RANDOM);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B36);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B36, 2048,
                                        ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B36, 3072,
                                        ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B36, 4096,
                                        ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable siggen */
    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGGEN, &app_rsa_sig_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGGEN, ACVP_PREREQ_DRBG, value);
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
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

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
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable sigver */
    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGVER, &app_rsa_sig_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_RANDOM);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: X9.31
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 1024, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 1024, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 1024, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 1024, ACVP_SHA512, 0);
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
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1v1.5
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 1024, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 1024, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 1024, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 1024, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 1024, ACVP_SHA512, 0);
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
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA1, 20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA512, 62);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA1, 20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA1, 20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA1, 20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 1024, ACVP_SHA512_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 1024, ACVP_SHA512_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA512_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA512_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA512_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA512_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA512_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA512_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);

#ifdef OPENSSL_RSA_PRIMITIVE
    /* Enable Decryption Primitive */
    rv = acvp_cap_rsa_prim_enable(ctx, ACVP_RSA_DECPRIM, &app_rsa_decprim_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_DECPRIM, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_DECPRIM, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    /* Revision 1 should be testable if needed still */
    //rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_DECPRIM, ACVP_RSA_PARM_REVISION, ACVP_REVISION_1_0);
    //CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_DECPRIM, ACVP_RSA_PARM_KEY_FORMAT, ACVP_RSA_KEY_FORMAT_CRT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_DECPRIM, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_DECPRIM, ACVP_RSA_PARM_MODULO, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_DECPRIM, ACVP_RSA_PARM_MODULO, 3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_DECPRIM, ACVP_RSA_PARM_MODULO, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_prim_set_exponent(ctx, ACVP_RSA_DECPRIM, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    /* Enable Signature Primitive */
    rv = acvp_cap_rsa_prim_enable(ctx, ACVP_RSA_SIGPRIM, &app_rsa_sigprim_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGPRIM, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGPRIM, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_SIGPRIM, ACVP_RSA_PARM_KEY_FORMAT, ACVP_RSA_KEY_FORMAT_CRT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_SIGPRIM, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    CHECK_ENABLE_CAP_RV(rv);
    //rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_SIGPRIM, ACVP_RSA_PARM_REVISION, ACVP_REVISION_1_0);
    //CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_SIGPRIM, ACVP_RSA_PARM_MODULO, 2048);
    CHECK_ENABLE_CAP_RV(rv);
#ifdef ACVP_FIPS186_5
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_SIGPRIM, ACVP_RSA_PARM_MODULO, 3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_SIGPRIM, ACVP_RSA_PARM_MODULO, 4096);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_rsa_prim_set_exponent(ctx, ACVP_RSA_SIGPRIM, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    CHECK_ENABLE_CAP_RV(rv);

end:
    if (expo_str) free(expo_str);

    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_ecdsa(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /* Enable ECDSA keyGen... */
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYGEN, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
#ifndef ACVP_FIPS186_5
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_REVISION, ACVP_REVISION_FIPS186_4);
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
#endif
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_SECRET_GEN, ACVP_ECDSA_SECRET_GEN_TEST_CAND);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable ECDSA keyVer... */
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYVER, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
#ifndef ACVP_FIPS186_5
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_REVISION, ACVP_REVISION_FIPS186_4);
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
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B163);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K163);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P192);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable ECDSA sigGen... */
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGGEN, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_COMPONENT_TEST, ACVP_ECDSA_COMPONENT_MODE_BOTH);
    CHECK_ENABLE_CAP_RV(rv);

#ifndef ACVP_FIPS186_5
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_REVISION, ACVP_REVISION_FIPS186_4);
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
#endif
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);

#ifdef ACVP_FIPS186_5
    /* Enable ECDSA sigGen... */
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_DET_ECDSA_SIGGEN, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DET_ECDSA_SIGGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DET_ECDSA_SIGGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_DET_ECDSA_SIGGEN, ACVP_ECDSA_COMPONENT_TEST, ACVP_ECDSA_COMPONENT_MODE_NO);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_DET_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_DET_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_DET_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_DET_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_DET_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_DET_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_DET_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_DET_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_DET_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_DET_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    /* Enable ECDSA sigVer... */
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGVER, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_COMPONENT_TEST, ACVP_ECDSA_COMPONENT_MODE_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
#ifndef ACVP_FIPS186_5
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_REVISION, ACVP_REVISION_FIPS186_4);
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
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B163);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K163);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_drbg(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /* Hash DRBG */
    rv = acvp_cap_drbg_enable(ctx, ACVP_HASHDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_set_prereq(ctx, ACVP_HASHDRBG, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    /* Group number for these should be 0 */
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_ENTROPY_LEN, 128, 64, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_NONCE_LEN, 96, 32, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_RET_BITS_LEN, 160);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_ENTROPY_LEN, 192, 64, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_RET_BITS_LEN, 384);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_RET_BITS_LEN, 512);
    CHECK_ENABLE_CAP_RV(rv);


    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    /* HMAC DRBG */
    rv = acvp_cap_drbg_enable(ctx, ACVP_HMACDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMACDRBG, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMACDRBG,ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);

    /* Group number for these should be 0 */
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_RET_BITS_LEN, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_ENTROPY_LEN, 160, 32, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_ENTROPY_LEN, 192, 64, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_PERSO_LEN, 0, 64, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_ADD_IN_LEN, 0, 0, 192);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_ENTROPY_LEN, 256, 64, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_RET_BITS_LEN, 384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_ENTROPY_LEN, 384, 64, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_RET_BITS_LEN, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_ENTROPY_LEN, 512, 64, 1024);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_ENTROPY_LEN, 512, 64, 1024);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_ENTROPY_LEN, 512, 64, 1024);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    /* CTR DRBG */
    rv = acvp_cap_drbg_enable(ctx, ACVP_CTRDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_CTRDRBG, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);

    /* Group number for these should be 0 */
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_DER_FUNC_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_ENTROPY_LEN, 128, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_PERSO_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_ADD_IN_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 1, ACVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 1, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 1, ACVP_DRBG_ENTROPY_LEN, 256, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 1, ACVP_DRBG_NONCE_LEN, 0, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 1, ACVP_DRBG_PERSO_LEN, 256, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 1, ACVP_DRBG_ADD_IN_LEN, 256, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 0, ACVP_DRBG_DER_FUNC_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 0, ACVP_DRBG_ENTROPY_LEN, 256, 128, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 0, ACVP_DRBG_PERSO_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 0, ACVP_DRBG_ADD_IN_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 1, ACVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 1, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 1, ACVP_DRBG_ENTROPY_LEN, 320, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 1, ACVP_DRBG_NONCE_LEN, 0, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 1, ACVP_DRBG_PERSO_LEN, 320, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 1, ACVP_DRBG_ADD_IN_LEN, 320, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_DER_FUNC_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_ENTROPY_LEN, 256, 128, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_PERSO_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_ADD_IN_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 1, ACVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 1, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 1, ACVP_DRBG_ENTROPY_LEN, 384, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 1, ACVP_DRBG_NONCE_LEN, 0, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 1, ACVP_DRBG_PERSO_LEN, 384, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 1, ACVP_DRBG_ADD_IN_LEN, 384, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
end:
    return rv;
}
#endif

#if !defined OPENSSL_NO_DSA && OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_safe_primes(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /* Register Safe Prime Key Generation testing */
    rv = acvp_cap_safe_primes_enable(ctx, ACVP_SAFE_PRIMES_KEYGEN, &app_safe_primes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE8192);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 /* These should probably be enabled, but missing from OpenSSL cert */
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP8192);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    /* Register Safe Prime Key Verify testing */
    rv = acvp_cap_safe_primes_enable(ctx, ACVP_SAFE_PRIMES_KEYVER, &app_safe_primes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE8192);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 /* These should probably be enabled, but missing from OpenSSL cert */
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP8192);
    CHECK_ENABLE_CAP_RV(rv);
#endif
end:
    return rv;
}
#endif

#ifdef ACVPAPP_LMS_SUPPORT
static int enable_lms(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

#if 0 /* An example of how an LMS and LMOTS mode can be registered as a compatible pair exclusively */
    rv = acvp_cap_lms_set_mode_compatability_pair(ctx, ACVP_LMS_SIGVER, ACVP_LMS_MODE_SHA256_M24_H5, ACVP_LMOTS_MODE_SHA256_N24_W1);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    rv = acvp_cap_lms_enable(ctx, ACVP_LMS_SIGVER, &app_lms_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H5);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H10);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H25);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H5);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H10);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H25);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N24_W1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N24_W2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N24_W4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N24_W8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N32_W1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N32_W2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N32_W4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N32_W8);
    CHECK_ENABLE_CAP_RV(rv);

#if 0
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H5);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H10);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H25);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H5);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H10);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H25);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N24_W1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N24_W2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N24_W4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N24_W8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N32_W1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N32_W2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N32_W4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N32_W8);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    rv = acvp_cap_lms_enable(ctx, ACVP_LMS_KEYGEN, &app_lms_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H5);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H10);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H25);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H5);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H10);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H25);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N24_W1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N24_W2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N24_W4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N24_W8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N32_W1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N32_W2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N32_W4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N32_W8);
    CHECK_ENABLE_CAP_RV(rv);

#if 0
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H5);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H10);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H25);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H5);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H10);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H25);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N24_W1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N24_W2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N24_W4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N24_W8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N32_W1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N32_W2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N32_W4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_KEYGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N32_W8);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    rv = acvp_cap_lms_enable(ctx, ACVP_LMS_SIGGEN, &app_lms_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H5);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H10);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M24_H25);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H5);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H10);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHA256_M32_H25);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N24_W1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N24_W2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N24_W4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N24_W8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N32_W1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N32_W2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N32_W4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHA256_N32_W8);
    CHECK_ENABLE_CAP_RV(rv);

#if 0
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H5);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H10);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M24_H25);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H5);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H10);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMS_MODE, ACVP_LMS_MODE_SHAKE_M32_H25);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N24_W1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N24_W2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N24_W4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N24_W8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N32_W1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N32_W2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N32_W4);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_lms_set_parm(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_LMOTS_MODE, ACVP_LMOTS_MODE_SHAKE_N32_W8);
    CHECK_ENABLE_CAP_RV(rv);
#endif

end:
    return rv;
}
#endif

#ifdef ACVP_APP_LIB_WRAPPER
ACVP_RESULT acvp_app_run_vector_test_file(const char *path, const char *output, ACVP_LOG_LVL lvl, ACVP_RESULT (*logger)(char *)) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_CTX *ctx = NULL;

    /*
     * We begin the libacvp usage flow here.
     * First, we create a test session context.
     */
    rv = acvp_create_test_session(&ctx, logger, lvl);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to create ACVP context: %s\n", acvp_lookup_error_string(rv));
        goto end;
    }

    /*
    * We need to register all possible crypto capabilities; since this code
    * just performs offline testing with already requested vectors
    */
    if (enable_aes(ctx)) goto end;
    if (enable_tdes(ctx)) goto end;
    if (enable_hash(ctx)) goto end;
    if (enable_cmac(ctx)) goto end;
    if (enable_hmac(ctx)) goto end;
    if (enable_kmac(ctx)) goto end;
    if (enable_kdf(ctx)) goto end;
    if (enable_dsa(ctx)) goto end;
    if (enable_rsa(ctx)) goto end;
    if (enable_ecdsa(ctx)) goto end;
    if (enable_drbg(ctx)) goto end;
    if (enable_kas_ecc(ctx)) goto end;
    if (enable_kas_ifc(ctx)) goto end;
    if (enable_kts_ifc(ctx)) goto end;
    if (enable_kas_ffc(ctx)) goto end;
    if (enable_kda(ctx)) goto end;
    if (enable_safe_primes(ctx)) goto end;
    if (enable_lms(ctx)) goto end;

    rv = acvp_run_vectors_from_file(ctx, path, output);

end:
    /*
     * Free all memory associated with
     * both the application and libacvp.
     */
    app_cleanup(ctx);

    return rv;
   }
#endif
