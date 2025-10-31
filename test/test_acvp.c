/** @file */
/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "ut_common.h"
#include "acvp/acvp_lcl.h"

TEST_GROUP(CHECK_RESULTS);
TEST_GROUP(CREATE_CTX);
TEST_GROUP(FREE_CTX);
TEST_GROUP(FREE_TEST_SESSION);
TEST_GROUP(GET_LIBRARY_VERSION);
TEST_GROUP(GET_PROTOCOL_VERSION);
TEST_GROUP(PROCESS_TESTS);
TEST_GROUP(REFRESH);
TEST_GROUP(RUN);
TEST_GROUP(SET_SESSION_PARAMS);

static ACVP_CTX *ctx = NULL;
static char filename[] = "filename";
static char cvalue[] = "same";
static char *test_server = "demo.acvts.nist.gov";
static char *api_context = "acvp/";
static char *path_segment = "acvp/v1/";
static int port = 443;
static ACVP_RESULT rv = 0;

static ACVP_RESULT dummy_totp_success(char **token, int token_max) {
    strncpy_s(*token, ACVP_TOTP_TOKEN_MAX + 1, "test", 4);
    return ACVP_SUCCESS;
}

static ACVP_RESULT dummy_totp_overflow(char **token, int token_max) {
    memset(*token, 'a', 129);
    return ACVP_SUCCESS;
}

static void free_test_session_setup_helper(void) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PTLEN, 1536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 96);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_IVLEN, 96);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_MACLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_GEN, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_PREREQ_ECDSA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_COMP, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPGEN);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPVAL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_INITIATOR);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_KDF, ACVP_KAS_FFC_NOKDFNOKC);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGGEN, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENPQ, ACVP_DSA_PROBABLE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENG, ACVP_DSA_CANONICAL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA256, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_SECRET_GEN, ACVP_ECDSA_SECRET_GEN_TEST_CAND);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_enable(ctx, ACVP_HASHDRBG, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_DER_FUNC_ENABLED, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HASHDRBG, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

static void set_session_params_setup_helper(void) {
    setup_empty_ctx(&ctx);
}

static void set_session_params_tear_down_helper(void) {
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(CHECK_RESULTS) {
    set_session_params_setup_helper();
}

TEST_TEAR_DOWN(CHECK_RESULTS) {
    set_session_params_tear_down_helper();
}

TEST_SETUP(CREATE_CTX) {}
TEST_TEAR_DOWN(CREATE_CTX) {}

TEST_SETUP(FREE_CTX) {
    free_test_session_setup_helper();
}

TEST_TEAR_DOWN(FREE_CTX) {}

TEST_SETUP(FREE_TEST_SESSION) {
    free_test_session_setup_helper();
}

TEST_TEAR_DOWN(FREE_TEST_SESSION) {
        ctx = NULL;
}

TEST_SETUP(GET_LIBRARY_VERSION) {}
TEST_TEAR_DOWN(GET_LIBRARY_VERSION) {}

TEST_SETUP(GET_PROTOCOL_VERSION) {}
TEST_TEAR_DOWN(GET_PROTOCOL_VERSION) {}

TEST_SETUP(PROCESS_TESTS) {
    free_test_session_setup_helper();
}

TEST_TEAR_DOWN(PROCESS_TESTS) {
    set_session_params_tear_down_helper();
}

TEST_SETUP(REFRESH) {
    free_test_session_setup_helper();
}

TEST_TEAR_DOWN(REFRESH) {
    set_session_params_tear_down_helper();
}

TEST_SETUP(RUN) {
    free_test_session_setup_helper();
}

TEST_TEAR_DOWN(RUN) {
    set_session_params_tear_down_helper();
}

TEST_SETUP(SET_SESSION_PARAMS) {
    set_session_params_setup_helper();
}

TEST_TEAR_DOWN(SET_SESSION_PARAMS) {
    set_session_params_tear_down_helper();
}

// This test sets up a new test session with good params
TEST(CREATE_CTX, good) {
    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_STATUS);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    teardown_ctx(&ctx);
    ctx = NULL;
    
    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_ERR);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    teardown_ctx(&ctx);
    ctx = NULL;
    
    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_WARN);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    teardown_ctx(&ctx);
    ctx = NULL;
    
    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_INFO);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    teardown_ctx(&ctx);
    ctx = NULL;
    
    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_VERBOSE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    teardown_ctx(&ctx);
    ctx = NULL;

    rv = acvp_create_test_session(&ctx, &progress, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    teardown_ctx(&ctx);
    ctx = NULL;

    rv = acvp_create_test_session(&ctx, NULL, ACVP_LOG_LVL_VERBOSE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    teardown_ctx(&ctx);
    ctx = NULL;
}

// This test sets up a new test session with non-null ctx
TEST(CREATE_CTX, dup_ctx) {
    ctx = NULL;

    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_VERBOSE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_VERBOSE);
    TEST_ASSERT_EQUAL(ACVP_CTX_NOT_EMPTY, rv);
    
    teardown_ctx(&ctx);
}

// This test sets up a new test session with null ctx
TEST(CREATE_CTX, null_ctx) {
    rv = acvp_create_test_session(NULL, &progress, ACVP_LOG_LVL_STATUS);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    TEST_ASSERT_EQUAL(NULL, ctx);
}

// This test sets 2fa cb
TEST(SET_SESSION_PARAMS, good_2fa) {
    rv = acvp_set_2fa_callback(ctx, &dummy_totp_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// This test sets 2fa cb with null params
TEST(SET_SESSION_PARAMS, null_params_2fa) {
    rv = acvp_set_2fa_callback(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    
    rv = acvp_set_2fa_callback(NULL, &dummy_totp_success);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// This test sets json filename
TEST(SET_SESSION_PARAMS, set_input_json_good) {
    rv = acvp_mark_as_request_only(ctx, "test.json");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_set_registration_file(ctx, filename);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// This test sets json filename - null params
TEST(SET_SESSION_PARAMS, set_input_json_null_params) {
    rv = acvp_set_registration_file(NULL, filename);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_set_registration_file(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

// This test sets server info
TEST(SET_SESSION_PARAMS, set_server_good) {
    rv = acvp_set_server(ctx, "for test", 1111);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// This test sets server info with NULL params
TEST(SET_SESSION_PARAMS, set_server_null_params) {
    rv = acvp_set_server(NULL, "for test", 1111);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    rv = acvp_set_server(ctx, NULL, 1111);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_set_server(ctx, "for test", -1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// This test sets server info with long params
TEST(SET_SESSION_PARAMS, set_server_overflow) {
    char long_str[1000];
    int i;
    for (i = 0; i < 999; i++) {
        long_str[i] = 'a';
    }
    long_str[999] = '\0';
    
    rv = acvp_set_server(ctx, long_str, -1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// This test sets path_segment info
TEST(SET_SESSION_PARAMS, set_path_segment_good) {
    rv = acvp_set_path_segment(ctx, "for test");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// This test sets path_segment info with NULL params
TEST(SET_SESSION_PARAMS, set_path_segment_null_params) {
    rv = acvp_set_path_segment(NULL, "for test");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    rv = acvp_set_path_segment(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// This test sets path_segment info with long params
TEST(SET_SESSION_PARAMS, set_path_segment_overflow) {
    char long_str[1000];
    int i;
    for (i = 0; i < 999; i++) {
        long_str[i] = 'a';
    }
    long_str[999] = '\0';
    
    rv = acvp_set_path_segment(ctx, long_str);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// This test sets cacerts info
TEST(SET_SESSION_PARAMS, set_cacerts_good) {
    rv = acvp_set_cacerts(ctx, "for test");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// This test sets cacerts info with NULL params
TEST(SET_SESSION_PARAMS, set_cacerts_null_params) {
    rv = acvp_set_cacerts(NULL, "for test");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    rv = acvp_set_cacerts(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

// This test sets cacerts info with long params
TEST(SET_SESSION_PARAMS, set_cacerts_overflow) {
    char long_str[1000];
    int i;
    for (i = 0; i < 999; i++) {
        long_str[i] = 'a';
    }
    long_str[999] = '\0';
    
    rv = acvp_set_cacerts(ctx, long_str);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// This test sets cert_key info
TEST(SET_SESSION_PARAMS, set_cert_key_good) {
    rv = acvp_set_certkey(ctx, "for test", "for test");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// This test sets cert_key info with NULL params
TEST(SET_SESSION_PARAMS, set_cert_key_null_params) {
    rv = acvp_set_certkey(NULL, "for test", "for test");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    rv = acvp_set_certkey(ctx, NULL, "for test");
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    rv = acvp_set_certkey(ctx, "for test", NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

// This test sets cert_key info with long params
TEST(SET_SESSION_PARAMS, set_cert_key_overflow) {
    char long_str[1000];
    int i;
    for (i = 0; i < 999; i++) {
        long_str[i] = 'a';
    }
    long_str[999] = '\0';
    
    rv = acvp_set_certkey(ctx, long_str, "for test");
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_set_certkey(ctx, "for test", long_str);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// This test marks as sample
TEST(SET_SESSION_PARAMS, mark_as_sample_good) {
    rv = acvp_mark_as_sample(ctx);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// This test marks as sample with null ctx
TEST(SET_SESSION_PARAMS, mark_as_sample_null_ctx) {
    rv = acvp_mark_as_sample(NULL);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// This test frees ctx - note: ctx structure itself still needs to be freed by teardown
TEST(FREE_TEST_SESSION, good) {
    rv = acvp_free_test_session(ctx);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// This test frees ctx - should still succeed
TEST(FREE_TEST_SESSION, null_ctx) {
    teardown_ctx(&ctx);    /* it got allocated in setup */
    ctx = NULL;
    rv = acvp_free_test_session(ctx);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// This test frees ctx - should still succeed
TEST(FREE_TEST_SESSION, good_full) {
    rv = acvp_free_test_session(ctx);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// Calls run with missing path segment
TEST(RUN, missing_path) {
    rv = acvp_set_server(ctx, test_server, port);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_set_api_context(ctx, api_context);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_set_server(ctx, test_server, port);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_set_2fa_callback(ctx, &dummy_totp);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_run(ctx, 0);
#ifdef ACVP_OFFLINE
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
#else
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
#endif
}

/**
 * Calls run with mark_as_get_only and save filename. Will fail because no transport
 */
TEST(RUN, marked_as_get) {
    rv = acvp_set_server(ctx, test_server, port);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_set_api_context(ctx, api_context);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_set_path_segment(ctx, path_segment);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_set_2fa_callback(ctx, &dummy_totp);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_mark_as_get_only(ctx, "/acvp/v1/test", "filename.json");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_run(ctx, 0);
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
}

/*
 * Calls run with good values
 * transport fail is exptected - we made it through the register
 * API successfully to try to send the registration. that part
 * will fail - no actual connection to server here.
 * This expects ACVP_TRANSPORT_FAIL because refresh sends
 * but we don't receive HTTP_OK
 */
TEST(RUN, good) {
    rv = acvp_set_server(ctx, test_server, port);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_set_api_context(ctx, api_context);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_set_path_segment(ctx, path_segment);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_set_server(ctx, test_server, port);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_set_2fa_callback(ctx, &dummy_totp);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_run(ctx, 0);
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
}

/*
 * This calls run with an overflow totp that will get
 * triggered in build_login
 */
TEST(RUN, bad_totp_cb) {
    rv = acvp_set_2fa_callback(ctx, &dummy_totp_overflow);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_run(ctx, 0);
    TEST_ASSERT_EQUAL(ACVP_TOTP_FAIL, rv);
}

/*
 * This calls run without adding totp callback - we expect
 * transport fail because we should make it through the rest
 * of the register api, but fail because we aren't going to be
 * able to successfully connect to NIST
 */
TEST(RUN, good_without_totp) {
    rv = acvp_run(ctx, 0);
#ifdef ACVP_OFFLINE
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
#else
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
#endif
}

// Run with null ctx
TEST(RUN, null_ctx) {
    rv = acvp_run(NULL, 0);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// Check test results with empty ctx
TEST(CHECK_RESULTS, no_vs_list) {
    rv = acvp_check_test_results(ctx);
#ifdef ACVP_OFFLINE
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
#else
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
#endif
}

/*
 * Process tests with full ctx - should return ACVP_MISSING_ARG for
 * now, at least until mock server is set up (because we didn't receive
 * any vectors to load in)
 */
TEST(PROCESS_TESTS, good) {
    rv = acvp_process_tests(ctx);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

// process tests with null ctx
TEST(PROCESS_TESTS, null_ctx) {
    rv = acvp_process_tests(NULL);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// process tests with empty ctx
TEST(PROCESS_TESTS, no_vs_list) {
    rv = acvp_process_tests(ctx);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

TEST(GET_LIBRARY_VERSION, good) {
    const char *version = acvp_version();
    TEST_ASSERT_NOT_EQUAL(NULL, version);
    TEST_ASSERT_TRUE(strlen(version) > 0);
}

TEST(GET_PROTOCOL_VERSION, good) {
    const char *version = acvp_protocol_version();
    TEST_ASSERT_NOT_EQUAL(NULL, version);
    TEST_ASSERT_TRUE(strlen(version) > 0);
}

// calls acvp_refresh with good params, didn't add totp callback
TEST(REFRESH, good_without_totp) {
    rv = acvp_set_server(ctx, test_server, port);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_set_path_segment(ctx, path_segment);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_refresh(ctx);
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
}

// calls acvp_refresh with null ctx
TEST(REFRESH, null_ctx) {
    rv = acvp_refresh(NULL);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

/*
 * calls acvp_refresh with good params
 * This expects ACVP_TRANSPORT_FAIL because refresh sends
 * but we don't receive HTTP_OK
 */
TEST(REFRESH, good_with_totp) {
    rv = acvp_set_server(ctx, test_server, port);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_set_api_context(ctx, api_context);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_set_path_segment(ctx, path_segment);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_set_2fa_callback(ctx, &dummy_totp);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_refresh(ctx);
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
}

// Good tests - should still pass even if ctx is null
TEST(FREE_CTX, good) {
    rv = acvp_free_test_session(ctx);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    ctx = NULL;
    rv = acvp_free_test_session(ctx);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// Test acvp_run_vectors_from_file logic
TEST(PROCESS_TESTS, run_vectors_from_file) {

    rv = acvp_run_vectors_from_file(NULL, "test", "test");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_run_vectors_from_file(ctx, NULL, "test");
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_run_vectors_from_file(ctx, "test", NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_run_vectors_from_file(ctx, "json/req.json", "json/rsp1.json");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

}

// Test acvp_upload_vectors_from_file
TEST(PROCESS_TESTS, upload_vectors_from_file) {

    rv = acvp_upload_vectors_from_file(NULL, "test", 0);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_upload_vectors_from_file(ctx, NULL, 0);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_upload_vectors_from_file(ctx, "json/rsp.json", 0);
#ifdef ACVP_OFFLINE
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
#else
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
#endif
}

// Test acvp_put_data_from_file
TEST(PROCESS_TESTS, put_data_from_file) {

    rv = acvp_put_data_from_file(NULL, "test");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_put_data_from_file(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_put_data_from_file(ctx, "json/put.json");
#ifdef ACVP_OFFLINE
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
#else
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
#endif
}

// Test acvp_mark_as_sample
TEST(PROCESS_TESTS, mark_as_sample) {

    rv = acvp_mark_as_sample(NULL);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_mark_as_sample(ctx);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// Test acvp_mark_as_post_only
TEST(PROCESS_TESTS, mark_as_post_only) {

    rv = acvp_mark_as_post_only(NULL, "test");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_mark_as_post_only(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_mark_as_post_only(ctx, "test");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// Test acvp_mark_as_request_only
TEST(PROCESS_TESTS, mark_as_request_only) {

    rv = acvp_mark_as_request_only(NULL, "test");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_mark_as_request_only(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_mark_as_request_only(ctx, "test");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// Test acvp_mark_as_get_only
TEST(PROCESS_TESTS, mark_as_get_only) {

    rv = acvp_mark_as_get_only(NULL, "test", NULL);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_mark_as_get_only(ctx, NULL, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_mark_as_get_only(ctx, "test", NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_mark_as_get_only(ctx, "", NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_mark_as_get_only(ctx, ACVP_TEST_STRING_TOO_LONG, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_mark_as_get_only(ctx, "test", ACVP_TEST_STRING_TOO_LONG);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_mark_as_get_only(ctx, "test", "");
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// Test acvp_mark_as_delete_only
TEST(PROCESS_TESTS, mark_as_delete_only) {

    rv = acvp_mark_as_delete_only(NULL, "test");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_mark_as_delete_only(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_mark_as_delete_only(ctx, "test");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_mark_as_delete_only(ctx, ACVP_TEST_STRING_TOO_LONG);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_mark_as_delete_only(ctx, "");
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// Test acvp_get_vector_set_count
TEST(PROCESS_TESTS, get_vector_set_count) {
    int count = 0;
    count = acvp_get_vector_set_count(NULL);
    TEST_ASSERT_TRUE(count < 0);

    count = acvp_get_vector_set_count(ctx);
    TEST_ASSERT_TRUE(count > 0);
    TEST_ASSERT_TRUE(count < 10000); /* An arbitrarily large number that should never be reached */

}

// Test acvp_mark_as_put_after_test
TEST(PROCESS_TESTS, mark_as_put_after_test) {

    rv = acvp_mark_as_put_after_test(NULL, "test");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_mark_as_put_after_test(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_mark_as_put_after_test(ctx, "test");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// Test acvp_get_results_from_server
TEST(PROCESS_TESTS, acvp_get_results_from_server) {
   
    rv = acvp_get_results_from_server(NULL, "test");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_get_results_from_server(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_get_results_from_server(ctx, ACVP_TEST_STRING_TOO_LONG);
   TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_get_results_from_server(ctx, "json/getResults.json");
    TEST_ASSERT_TRUE(rv = ACVP_MALFORMED_JSON);
}

// Test acvp_resume_test_session
TEST(PROCESS_TESTS, acvp_resume_test_session) {
   
    rv = acvp_resume_test_session(NULL, "test", 0);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_resume_test_session(ctx, NULL, 0);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_resume_test_session(ctx, ACVP_TEST_STRING_TOO_LONG, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_resume_test_session(ctx, "json/getResults.json", 1);
    TEST_ASSERT_TRUE(rv = ACVP_MALFORMED_JSON);
}

// Test acvp_cancel_test_session
TEST(PROCESS_TESTS, acvp_cancel_test_session) {

    rv = acvp_cancel_test_session(NULL, "test", "test");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_cancel_test_session(ctx, NULL, "test");
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_cancel_test_session(ctx, ACVP_TEST_STRING_TOO_LONG, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_cancel_test_session(ctx, "test", ACVP_TEST_STRING_TOO_LONG);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_cancel_test_session(ctx, "", "test");
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);

    rv = acvp_cancel_test_session(ctx, "test", "");
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
}

// Test acvp_get_expected_results
TEST(PROCESS_TESTS, acvp_get_expected_results) {
   
    rv = acvp_get_expected_results(NULL, "json/testSession_0.json", NULL);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    rv = acvp_get_expected_results(NULL, "json/testSession_0.json", "test");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    rv = acvp_get_expected_results(NULL, NULL, "test");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    rv = acvp_get_expected_results(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_get_expected_results(ctx, NULL, "test");
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    rv = acvp_get_expected_results(ctx, NULL, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_get_expected_results(ctx, ACVP_TEST_STRING_TOO_LONG, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_get_expected_results(ctx, "json/testSession_0.json", \
                                        ACVP_TEST_STRING_TOO_LONG);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_get_expected_results(ctx, "json/getResults.json", NULL);
    TEST_ASSERT_TRUE(rv = ACVP_MALFORMED_JSON);
    rv = acvp_get_expected_results(ctx, "json/getResults.json", "");
    TEST_ASSERT_TRUE(rv = ACVP_MALFORMED_JSON);
    rv = acvp_get_expected_results(ctx, "json/getResults_0.json", "");
    TEST_ASSERT_TRUE(rv = ACVP_MALFORMED_JSON);
    rv = acvp_get_expected_results(ctx, "", NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}
