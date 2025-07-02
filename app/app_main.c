/*
 * Copyright (c) 2024, Cisco Systems, Inc.
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
#include <stdlib.h>
#include "app_lcl.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include "safe_mem_lib.h"
#include "safe_str_lib.h"

#ifdef ACVPAPP_LMS_SUPPORT
static int enable_lms(ACVP_CTX *ctx);
#endif
#ifdef ACVPAPP_ML_SUPPORT
static int enable_ml_dsa(ACVP_CTX *ctx);
static int enable_ml_kem(ACVP_CTX *ctx);
#endif

const char *server;
int port;
const char *ca_chain_file;
char *cert_file;
char *key_file;
const char *path_segment;
const char *api_context;

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

/* libacvp calls this function for status updates, debugs, warnings, and errors. */
static ACVP_RESULT progress(char *msg, ACVP_LOG_LVL level) {

    printf("[ACVP]");

#ifdef _WIN32
    switch (level) {
    case ACVP_LOG_LVL_ERR:
        printf("[ERROR]");
        break;
    case ACVP_LOG_LVL_WARN:
        printf("[WARNING]");
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

#else
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
#endif

    printf(": %s\n", msg);

    return ACVP_SUCCESS;
}

#ifndef ACVP_APP_LIB_WRAPPER
int main(int argc, char **argv) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_CTX *ctx = NULL;
    APP_CONFIG cfg;
    int diff = 0;

    //TODO: this shouldn't need to be non-const
    strncpy_s(value, JSON_STRING_LENGTH, "same", 4);

    memset_s(&cfg, sizeof(APP_CONFIG), 0, sizeof(APP_CONFIG));
    if (ingest_cli(&cfg, argc, argv)) {
        return 1;
    }

    if (cfg.output_version) {
        print_version_info(&cfg);
        goto end;
    }

    rv = iut_setup(&cfg);
    if (rv != ACVP_SUCCESS) {
        printf("Error setting up implementation for testing at startup\n");
        goto end;
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
        rv = acvp_mark_as_sample(ctx);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to mark as sample\n");
            goto end;
        }
    }

    if (cfg.get) {
        rv = acvp_mark_as_get_only(ctx, cfg.get_string, cfg.save_to ? cfg.save_file : NULL);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to mark as get only.\n");
            goto end;
        }
    }

    if (cfg.post) {
        rv = acvp_mark_as_post_only(ctx, cfg.post_filename);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to mark as post only\n");
            goto end;
        }
    }

    if (cfg.delete) {
        rv = acvp_mark_as_delete_only(ctx, cfg.delete_url);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to mark as delete only\n");
            goto end;
        }
    }

    if (cfg.vector_req && !cfg.vector_rsp) {
        rv = acvp_mark_as_request_only(ctx, cfg.vector_req_file);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to mark as request only\n");
            goto end;
        }
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
        /* Call the registration code for the given IUT */
        rv = iut_register_capabilities(ctx, &cfg);
        if (rv != ACVP_SUCCESS) {
            printf("Failure occurred while registering capabilities for given implementation\n");
            goto end;
        }
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
            printf("Error occurred while getting current registration.\n");
            goto end;
        }
        if (cfg.save_to) {
            if (save_string_to_file((const char *)reg, (const char *)&cfg.save_file)) {
                printf("Error occurred while saving registration to file. Exiting...\n");
            } else {
                printf("Successfully saved registration to given file. Exiting...\n");
            }
        } else {
            printf("%s\n", reg);
            printf("Completed output of current registration. Exiting...\n");
        }
        if (reg) free(reg);
        goto end;
    }

    if (cfg.vector_req && cfg.vector_rsp) {
        if (!cfg.generic_vector_file) {
            rv = acvp_run_vectors_from_file(ctx, cfg.vector_req_file, cfg.vector_rsp_file);
        } else {
            rv = acvp_run_vectors_from_file_offline(ctx, cfg.vector_req_file, cfg.vector_rsp_file);
        }
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
        rv = acvp_mark_as_put_after_test(ctx, cfg.put_filename);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to mark as put after test\n");
            goto end;
        }
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
    rv = acvp_run(ctx, cfg.fips_validation);

end:
    /*
     * Free all memory associated with
     * both the application and libacvp.
     */
    acvp_cleanup(ctx);
    iut_cleanup();

    return rv;
}
#endif

#ifdef ACVP_APP_LIB_WRAPPER
ACVP_RESULT acvp_app_run_vector_test_file(const char *path, const char *output, ACVP_LOG_LVL lvl, ACVP_RESULT (*logger)(char *)) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_CTX *ctx = NULL;
    APP_CONFIG cfg = {0};
    /*
     * We begin the libacvp usage flow here.
     * First, we create a test session context.
     */
    rv = acvp_create_test_session(&ctx, logger, lvl);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to create ACVP context: %s\n", acvp_lookup_error_string(rv));
        goto end;
    }
    cfg.testall = 1;

    rv = iut_setup();
    if (rv != ACVP_SUCCESS) {
        printf("Error setting up implementation for testing at startup\n");
        goto end;
    }

    rv = iut_register_capabilities(ctx, &cfg);
    if (rv != ACVP_SUCCESS) {
        printf("Failure occurred while registering capabilities for given implementation\n");
        goto end;
    }

    rv = acvp_run_vectors_from_file(ctx, path, output);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to run vectors from file");
    }

end:
    acvp_cleanup(ctx);
    iut_cleanup();
    return rv;
   }
#endif
