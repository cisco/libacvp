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
#include "app_common.h"
#include "iut_common.h"
#include "acvp/acvp_lcl.h"

TEST_GROUP(APP_KDF_TLS12_HANDLER);

static ACVP_TEST_CASE *test_case = NULL;
static ACVP_KDF_TLS12_TC *kdf_tls12_tc = NULL;
static ACVP_RESULT rv = 0;

void free_kdf_tls12_tc(ACVP_KDF_TLS12_TC *stc) {
    if (stc->pm_secret) free(stc->pm_secret);
    if (stc->session_hash) free(stc->session_hash);
    if (stc->c_rnd) free(stc->c_rnd);
    if (stc->s_rnd) free(stc->s_rnd);
    if (stc->msecret) free(stc->msecret);
    if (stc->kblock) free(stc->kblock);
    free(stc);
}

/*
 * the corrupt variable indicates whether or not we want to
 * properly allocate memory for the answers that the client
 * application will populate
 */
int initialize_kdf_tls12_tc(ACVP_KDF_TLS12_TC *stc,
                             ACVP_HASH_ALG md,
                             unsigned int pm_len,
                             unsigned int kb_len,
                             const char *pm_secret,
                             const char *session_hash,
                             const char *s_rnd,
                             const char *c_rnd,
                             int corrupt) {
    memzero_s(stc, sizeof(ACVP_KDF_TLS12_TC));
    
    if (pm_secret) {
        stc->pm_secret = calloc(1, ACVP_KDF_TLS12_MSG_MAX);
        if (!stc->pm_secret) { goto err; }
        rv = acvp_hexstr_to_bin(pm_secret, stc->pm_secret, ACVP_KDF_TLS12_MSG_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (pm_secret)\n");
            goto err;
        }
    }
    
    if (session_hash) {
        stc->session_hash = calloc(1, ACVP_KDF_TLS12_MSG_MAX);
        if (!stc->session_hash) { goto err; }
        rv = acvp_hexstr_to_bin(session_hash, stc->session_hash, ACVP_KDF_TLS12_MSG_MAX, &(stc->session_hash_len));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (session_hash)\n");
            goto err;
        }
    }
    
    if (c_rnd) {
        stc->c_rnd = calloc(1, ACVP_KDF_TLS12_MSG_MAX);
        if (!stc->c_rnd) { goto err; }
        rv = acvp_hexstr_to_bin(c_rnd, stc->c_rnd, ACVP_KDF_TLS12_MSG_MAX, &(stc->c_rnd_len));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (c_rnd)\n");
            goto err;
        }
    }
    
    if (s_rnd) {
        stc->s_rnd = calloc(1, ACVP_KDF_TLS12_MSG_MAX);
        if (!stc->s_rnd) { goto err; }
        rv = acvp_hexstr_to_bin(s_rnd, stc->s_rnd, ACVP_KDF_TLS12_MSG_MAX, &(stc->s_rnd_len));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (s_rnd)\n");
            goto err;
        }
    }
    
    if (!corrupt) {
        stc->msecret = calloc(1, ACVP_KDF_TLS12_MSG_MAX);
        if (!stc->msecret) { goto err; }
        stc->kblock = calloc(1, ACVP_KDF_TLS12_MSG_MAX);
        if (!stc->kblock) { goto err; }
    }
    
    stc->cipher = ACVP_KDF_TLS12;
    stc->pm_len = pm_len / 8;
    stc->kb_len = kb_len / 8;
    stc->md = md;
    
    return 1;
    
    err:
    free_kdf_tls12_tc(stc);
    return 0;
}

TEST_SETUP(APP_KDF_TLS12_HANDLER) {}
TEST_TEAR_DOWN(APP_KDF_TLS12_HANDLER) {}

// invalid hash alg in kdf_tls12 tc test case
TEST(APP_KDF_TLS12_HANDLER, invalid_hash_alg) {
    /* arbitrary non-zero */
    int pm_len = 8, kb_len = 8;
    char *pm_secret = "aa";
    char *session_hash = "aa";
    char *s_rnd = "aa";
    char *c_rnd = "aa";
    int corrupt = 0;
    
    kdf_tls12_tc = calloc(1, sizeof(ACVP_KDF_TLS12_TC));
    
    if (!initialize_kdf_tls12_tc(kdf_tls12_tc, 0, pm_len, kb_len,
            pm_secret, session_hash, s_rnd, c_rnd, corrupt)) {
        TEST_FAIL_MESSAGE("kdf135 tls init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls12 = kdf_tls12_tc;
    
    rv = app_kdf_tls12_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kdf_tls12_tc(kdf_tls12_tc);
    free(test_case);
}

// missing_pm_secret in kdf_tls12 tc test case
TEST(APP_KDF_TLS12_HANDLER, missing_pm_secret) {
    /* arbitrary non-zero */
    int pm_len = 8, kb_len = 8;
    char *pm_secret = NULL;
    char *session_hash = "aa";
    char *s_rnd = "aa";
    char *c_rnd = "aa";
    int corrupt = 0;
    
    kdf_tls12_tc = calloc(1, sizeof(ACVP_KDF_TLS12_TC));
    
    if (!initialize_kdf_tls12_tc(kdf_tls12_tc, ACVP_SHA256, pm_len, kb_len,
    pm_secret, session_hash, s_rnd, c_rnd, corrupt)) {
        TEST_FAIL_MESSAGE("kdf135 tls init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls12 = kdf_tls12_tc;
    
    rv = app_kdf_tls12_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kdf_tls12_tc(kdf_tls12_tc);
    free(test_case);
}

// missing_session_hash in kdf_tls12 tc test case
TEST(APP_KDF_TLS12_HANDLER, missing_session_hash) {
    /* arbitrary non-zero */
    int pm_len = 8, kb_len = 8;
    char *pm_secret = "aa";
    char *session_hash = NULL;
    char *s_rnd = "aa";
    char *c_rnd = "aa";
    int corrupt = 0;
    
    kdf_tls12_tc = calloc(1, sizeof(ACVP_KDF_TLS12_TC));
    
    if (!initialize_kdf_tls12_tc(kdf_tls12_tc, ACVP_SHA256, pm_len, kb_len,
            pm_secret, session_hash, s_rnd, c_rnd, corrupt)) {
        TEST_FAIL_MESSAGE("kdf135 tls init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls12 = kdf_tls12_tc;
    
    rv = app_kdf_tls12_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kdf_tls12_tc(kdf_tls12_tc);
    free(test_case);
}

// missing_c_rnd in kdf_tls12 tc test case
TEST(APP_KDF_TLS12_HANDLER, missing_c_rnd) {
    /* arbitrary non-zero */
    int pm_len = 8, kb_len = 8;
    char *pm_secret = "aa";
    char *session_hash = "aa";
    char *s_rnd = "aa";
    char *c_rnd = NULL;
    int corrupt = 0;
    
    kdf_tls12_tc = calloc(1, sizeof(ACVP_KDF_TLS12_TC));
    
    if (!initialize_kdf_tls12_tc(kdf_tls12_tc, ACVP_SHA256, pm_len, kb_len,
            pm_secret, session_hash, s_rnd, c_rnd, corrupt)) {
        TEST_FAIL_MESSAGE("kdf135 tls init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls12 = kdf_tls12_tc;
    
    rv = app_kdf_tls12_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kdf_tls12_tc(kdf_tls12_tc);
    free(test_case);
}

// missing_s_rnd in kdf_tls12 tc test case
TEST(APP_KDF_TLS12_HANDLER, missing_s_rnd) {
    /* arbitrary non-zero */
    int pm_len = 8, kb_len = 8;
    char *pm_secret = "aa";
    char *session_hash = "aa";
    char *s_rnd = NULL;
    char *c_rnd = "aa";
    int corrupt = 0;
    
    kdf_tls12_tc = calloc(1, sizeof(ACVP_KDF_TLS12_TC));
    
    if (!initialize_kdf_tls12_tc(kdf_tls12_tc, ACVP_SHA256, pm_len, kb_len,
            pm_secret, session_hash, s_rnd, c_rnd, corrupt)) {
        TEST_FAIL_MESSAGE("kdf135 tls init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls12 = kdf_tls12_tc;
    
    rv = app_kdf_tls12_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kdf_tls12_tc(kdf_tls12_tc);
    free(test_case);
}

// unallocated answer buffers in kdf_tls12 tc test case
TEST(APP_KDF_TLS12_HANDLER, unallocated_ans_bufs) {
    /* arbitrary non-zero */
    int pm_len = 8, kb_len = 8;
    char *pm_secret = "aa";
    char *session_hash = "aa";
    char *s_rnd = "aa";
    char *c_rnd = "aa";
    int corrupt = 1;
    
    kdf_tls12_tc = calloc(1, sizeof(ACVP_KDF_TLS12_TC));
    
    if (!initialize_kdf_tls12_tc(kdf_tls12_tc, ACVP_SHA256, pm_len, kb_len,
            pm_secret, session_hash, s_rnd, c_rnd, corrupt)) {
    TEST_FAIL_MESSAGE("kdf135 tls init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls12 = kdf_tls12_tc;
    
    rv = app_kdf_tls12_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kdf_tls12_tc(kdf_tls12_tc);
    free(test_case);
}
