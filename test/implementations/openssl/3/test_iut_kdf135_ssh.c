/** @file */
/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

//
// Created by edaw on 2019-01-07.
//

#include "ut_common.h"
#include "app_common.h"
#include "iut_common.h"
#include "acvp/acvp_lcl.h"

TEST_GROUP(APP_KDF135_SSH_HANDLER);

static ACVP_TEST_CASE *test_case = NULL;
static ACVP_KDF135_SSH_TC *kdf135_ssh_tc = NULL;
static ACVP_RESULT rv = 0;

void free_kdf135_ssh_tc(ACVP_KDF135_SSH_TC *stc) {
    if (stc->shared_secret_k) free(stc->shared_secret_k);
    if (stc->hash_h) free(stc->hash_h);
    if (stc->session_id) free(stc->session_id);
    if (stc->cs_init_iv) free(stc->cs_init_iv);
    if (stc->sc_init_iv) free(stc->sc_init_iv);
    if (stc->cs_encrypt_key) free(stc->cs_encrypt_key);
    if (stc->sc_encrypt_key) free(stc->sc_encrypt_key);
    if (stc->cs_integrity_key) free(stc->cs_integrity_key);
    if (stc->sc_integrity_key) free(stc->sc_integrity_key);
    free(stc);
}

/*
 * the corrupt variable indicates whether or not we want to
 * properly allocate memory for the answers that the client
 * application will populate
 */
int initialize_kdf135_ssh_tc(ACVP_KDF135_SSH_TC *stc,
                             ACVP_HASH_ALG sha_type,
                             unsigned int e_key_len,
                             unsigned int i_key_len,
                             unsigned int iv_len,
                             unsigned int hash_len,
                             const char *shared_secret_k,
                             const char *hash_h,
                             const char *session_id,
                             int corrupt) {
    unsigned int shared_secret_len = 0;
    unsigned int session_id_len = 0;
    
    memzero_s(stc, sizeof(ACVP_KDF135_SSH_TC));
    
    if (shared_secret_k) {
        shared_secret_len = strnlen_s(shared_secret_k, ACVP_KDF135_SSH_STR_IN_MAX) / 2;
        stc->shared_secret_k = calloc(shared_secret_len, sizeof(unsigned char));
        if (!stc->shared_secret_k) { goto err; }
        rv = acvp_hexstr_to_bin(shared_secret_k, (unsigned char *) stc->shared_secret_k,
                                shared_secret_len, NULL);
        if (rv != ACVP_SUCCESS) goto err;
    }
    
    if (hash_h) {
        stc->hash_h = calloc(hash_len, sizeof(unsigned char));
        if (!stc->hash_h) { goto err; }
        rv = acvp_hexstr_to_bin(hash_h, (unsigned char *) stc->hash_h, hash_len, NULL);
        if (rv != ACVP_SUCCESS) goto err;
    }
    
    if (session_id) {
        session_id_len = strnlen_s(session_id, ACVP_KDF135_SSH_STR_IN_MAX) / 2;
        stc->session_id = calloc(session_id_len, sizeof(unsigned char));
        if (!stc->session_id) { goto err; }
        rv = acvp_hexstr_to_bin(session_id, (unsigned char *) stc->session_id, session_id_len, NULL);
        if (rv != ACVP_SUCCESS) goto err;
    }
    
    if (!corrupt) {
        // Allocate answer buffers
        stc->cs_init_iv = calloc(ACVP_KDF135_SSH_IV_MAX, sizeof(unsigned char));
        if (!stc->cs_init_iv) { goto err; }
        stc->sc_init_iv = calloc(ACVP_KDF135_SSH_IV_MAX, sizeof(unsigned char));
        if (!stc->sc_init_iv) { goto err; }
    
        stc->cs_encrypt_key = calloc(ACVP_KDF135_SSH_EKEY_MAX, sizeof(unsigned char));
        if (!stc->cs_encrypt_key) { goto err; }
        stc->sc_encrypt_key = calloc(ACVP_KDF135_SSH_EKEY_MAX, sizeof(unsigned char));
        if (!stc->sc_encrypt_key) { goto err; }
    
        stc->cs_integrity_key = calloc(ACVP_KDF135_SSH_IKEY_MAX, sizeof(unsigned char));
        if (!stc->cs_integrity_key) { goto err; }
        stc->sc_integrity_key = calloc(ACVP_KDF135_SSH_IKEY_MAX, sizeof(unsigned char));
        if (!stc->sc_integrity_key) { goto err; }
    }
    
    stc->sha_type = sha_type;
    stc->e_key_len = e_key_len;
    stc->i_key_len = i_key_len;
    stc->iv_len = iv_len;
    stc->shared_secret_len = shared_secret_len;
    stc->hash_len = hash_len;
    stc->session_id_len = session_id_len;
    
    return 1;
    
    err:
    free_kdf135_ssh_tc(stc);
    return 0;
}

TEST_SETUP(APP_KDF135_SSH_HANDLER) {}
TEST_TEAR_DOWN(APP_KDF135_SSH_HANDLER) {}

// invalid hash alg in kdf135_ssh tc test case
TEST(APP_KDF135_SSH_HANDLER, invalid_hash_alg) {
    /* arbitrary non-zero */
    int e_key_len = 8, i_key_len = 8, iv_len = 8, hash_len = 8;
    char *shared_secret_k = "aa";
    char *hash_h = "aa";
    char *session_id = "aa";
    int corrupt = 0;
    
    kdf135_ssh_tc = calloc(1, sizeof(ACVP_KDF135_SSH_TC));
    
    if (!initialize_kdf135_ssh_tc(kdf135_ssh_tc, 0, e_key_len, i_key_len, iv_len, hash_len,
            shared_secret_k, hash_h, session_id, corrupt)) {
        TEST_FAIL_MESSAGE("kdf135 ssh init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf135_ssh = kdf135_ssh_tc;
    
    rv = app_kdf135_ssh_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kdf135_ssh_tc(kdf135_ssh_tc);
    free(test_case);
}

// missing shared secret k in kdf135_ssh tc test case
TEST(APP_KDF135_SSH_HANDLER, missing_ssk) {
    /* arbitrary non-zero */
    int e_key_len = 8, i_key_len = 8, iv_len = 8, hash_len = 8;
    char *shared_secret_k = NULL;
    char *hash_h = "aa";
    char *session_id = "aa";
    int corrupt = 0;
    
    kdf135_ssh_tc = calloc(1, sizeof(ACVP_KDF135_SSH_TC));
    
    if (!initialize_kdf135_ssh_tc(kdf135_ssh_tc, ACVP_SHA256, e_key_len, i_key_len, iv_len, hash_len,
            shared_secret_k, hash_h, session_id, corrupt)) {
        TEST_FAIL_MESSAGE("kdf135 ssh init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf135_ssh = kdf135_ssh_tc;
    
    rv = app_kdf135_ssh_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kdf135_ssh_tc(kdf135_ssh_tc);
    free(test_case);
}

// missing hash h in kdf135_ssh tc test case
TEST(APP_KDF135_SSH_HANDLER, missing_hash_h) {
    /* arbitrary non-zero */
    int e_key_len = 8, i_key_len = 8, iv_len = 8, hash_len = 8;
    char *shared_secret_k = "aa";
    char *hash_h = NULL;
    char *session_id = "aa";
    int corrupt = 0;
    
    kdf135_ssh_tc = calloc(1, sizeof(ACVP_KDF135_SSH_TC));
    
    if (!initialize_kdf135_ssh_tc(kdf135_ssh_tc, ACVP_SHA256, e_key_len, i_key_len, iv_len, hash_len,
            shared_secret_k, hash_h, session_id, corrupt)) {
        TEST_FAIL_MESSAGE("kdf135 ssh init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf135_ssh = kdf135_ssh_tc;
    
    rv = app_kdf135_ssh_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kdf135_ssh_tc(kdf135_ssh_tc);
    free(test_case);
}

// missing session id in kdf135_ssh tc test case
TEST(APP_KDF135_SSH_HANDLER, missing_session_id) {
    /* arbitrary non-zero */
    int e_key_len = 8, i_key_len = 8, iv_len = 8, hash_len = 8;
    char *shared_secret_k = "aa";
    char *hash_h = "aa";
    char *session_id = NULL;
    int corrupt = 0;
    
    kdf135_ssh_tc = calloc(1, sizeof(ACVP_KDF135_SSH_TC));
    
    if (!initialize_kdf135_ssh_tc(kdf135_ssh_tc, ACVP_SHA256, e_key_len, i_key_len, iv_len, hash_len,
            shared_secret_k, hash_h, session_id, corrupt)) {
        TEST_FAIL_MESSAGE("kdf135 ssh init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf135_ssh = kdf135_ssh_tc;
    
    rv = app_kdf135_ssh_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kdf135_ssh_tc(kdf135_ssh_tc);
    free(test_case);
}

// unallocated answer bufs in kdf135_ssh tc test case
TEST(APP_KDF135_SSH_HANDLER, unallocated_ans_bufs) {
    /* arbitrary non-zero */
    int e_key_len = 8, i_key_len = 8, iv_len = 8, hash_len = 8;
    char *shared_secret_k = "aa";
    char *hash_h = "aa";
    char *session_id = "aa";
    int corrupt = 1;
    
    kdf135_ssh_tc = calloc(1, sizeof(ACVP_KDF135_SSH_TC));
    
    if (!initialize_kdf135_ssh_tc(kdf135_ssh_tc, ACVP_SHA256, e_key_len, i_key_len, iv_len, hash_len,
            shared_secret_k, hash_h, session_id, corrupt)) {
        TEST_FAIL_MESSAGE("kdf135 ssh init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf135_ssh = kdf135_ssh_tc;
    
    rv = app_kdf135_ssh_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kdf135_ssh_tc(kdf135_ssh_tc);
    free(test_case);
}
