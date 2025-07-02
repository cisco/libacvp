/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#ifndef LIBACVP_APP_LCL_H
#define LIBACVP_APP_LCL_H

#ifdef __cplusplus
extern "C"
{
#endif
#include <stdio.h>
#include "acvp/acvp.h"

/* MACROS */
#define DEFAULT_SERVER "127.0.0.1"
#define DEFAULT_SERVER_LEN 9
#define DEFAULT_PORT 443
#define DEFAULT_URI_PREFIX "/acvp/v1/"
#define JSON_FILENAME_LENGTH 128
#define JSON_STRING_LENGTH 32
#define JSON_REQUEST_LENGTH 128
#define PROVIDER_NAME_MAX_LEN 64
#define ALG_STR_MAX_LEN 256 /* arbitrary */
extern char value[JSON_STRING_LENGTH]; /* Non const for API */


#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

typedef struct app_config {
    int output_version;
    ACVP_LOG_LVL level;
    int sample;
    int manual_reg;
    int vector_req;
    int vector_rsp;
    int vector_upload;
    int get;
    int get_results;
    int resume_session;
    int cancel_session;
    int post;
    int put;
    int delete;
    int empty_alg;
    int fips_validation;
    int get_expected;
    int save_to;
    int get_cost;
    int get_reg;
    int disable_fips;
    int generic_vector_file;
    char reg_file[JSON_FILENAME_LENGTH + 1];
    char vector_req_file[JSON_FILENAME_LENGTH + 1];
    char vector_rsp_file[JSON_FILENAME_LENGTH + 1];
    char vector_upload_file[JSON_FILENAME_LENGTH + 1];
    char get_string[JSON_REQUEST_LENGTH + 1];
    char session_file[JSON_FILENAME_LENGTH + 1];
    char post_filename[JSON_FILENAME_LENGTH + 1];
    char put_filename[JSON_FILENAME_LENGTH + 1];
    char delete_url[JSON_REQUEST_LENGTH + 1];
    char validation_metadata_file[JSON_FILENAME_LENGTH + 1];
    char save_file[JSON_FILENAME_LENGTH + 1];

    /* limit in GiB of hash tasting supported on the platform */
    int max_ldt_size;

    /*
     * Algorithm Flags
     * 0 is off, 1 is on
     */
    int aes; int tdes;
    int hash; int cmac; int hmac; int kmac;
    int dsa; int rsa;
    int drbg; int ecdsa; int eddsa;
    int kas_ecc; int kas_ffc; int kas_ifc; int kda; int kts_ifc;
    int kdf;
    int safe_primes;
    int lms;
    int ml_dsa; int ml_kem;
    int slh_dsa;
    int testall; /* So the app can check whether the user indicated to test all possible algorithms */
} APP_CONFIG;

#define CHECK_ENABLE_CAP_RV(rv) \
    if (rv != ACVP_SUCCESS) { \
        printf("Failed to register capability with libacvp (rv=%d: %s)\n", rv, acvp_lookup_error_string(rv)); \
        goto end; \
    }

#define CHECK_NON_ALLOWED_ALG(enabled, str) \
    if (enabled != 0) { \
        printf("%s\n", str); \
        rv = 0; \
    }

ACVP_RESULT totp(char **token, int token_max);

void print_version_info(APP_CONFIG *cfg);
int ingest_cli(APP_CONFIG *cfg, int argc, char **argv);
int app_setup_two_factor_auth(ACVP_CTX *ctx);
unsigned int swap_uint_endian(unsigned int i);
int check_is_little_endian(void);
char *remove_str_const(const char *str);
int save_string_to_file(const char *str, const char *path);

/* These functions need to be provided by IUT handler code */
ACVP_RESULT iut_register_capabilities(ACVP_CTX *ctx, APP_CONFIG *cfg);
ACVP_RESULT iut_cleanup(void);
void iut_print_version(APP_CONFIG *cfg);
ACVP_RESULT iut_setup(APP_CONFIG *cfg);

#ifdef __cplusplus
}
#endif

#endif // LIBACVP_APP_LCL_H

