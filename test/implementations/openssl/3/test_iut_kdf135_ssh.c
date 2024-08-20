/** @file */
/*****************************************************************************
* Copyright (c) 2024, Cisco Systems, Inc.
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
//
// Created by edaw on 2019-01-07.
//

#include "ut_common.h"
#include "app_common.h"
#include "iut_common.h"
#include "acvp/acvp_lcl.h"

static ACVP_TEST_CASE *test_case;
static ACVP_KDF135_SSH_TC *kdf135_ssh_tc;
static ACVP_RESULT rv;

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
    ACVP_RESULT rv;
    
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

/*
 * invalid hash alg in kdf135_ssh tc test case
 */
Test(APP_KDF135_SSH_HANDLER, invalid_hash_alg) {
    /* arbitrary non-zero */
    int e_key_len = 8, i_key_len = 8, iv_len = 8, hash_len = 8;
    char *shared_secret_k = "aa";
    char *hash_h = "aa";
    char *session_id = "aa";
    int corrupt = 0;
    
    kdf135_ssh_tc = calloc(1, sizeof(ACVP_KDF135_SSH_TC));
    
    if (!initialize_kdf135_ssh_tc(kdf135_ssh_tc, 0, e_key_len, i_key_len, iv_len, hash_len,
            shared_secret_k, hash_h, session_id, corrupt)) {
        cr_assert_fail("kdf135 ssh init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf135_ssh = kdf135_ssh_tc;
    
    rv = app_kdf135_ssh_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf135_ssh_tc(kdf135_ssh_tc);
    free(test_case);
}

/*
 * missing shared secret k in kdf135_ssh tc test case
 */
Test(APP_KDF135_SSH_HANDLER, missing_ssk) {
    /* arbitrary non-zero */
    int e_key_len = 8, i_key_len = 8, iv_len = 8, hash_len = 8;
    char *shared_secret_k = NULL;
    char *hash_h = "aa";
    char *session_id = "aa";
    int corrupt = 0;
    
    kdf135_ssh_tc = calloc(1, sizeof(ACVP_KDF135_SSH_TC));
    
    if (!initialize_kdf135_ssh_tc(kdf135_ssh_tc, ACVP_SHA256, e_key_len, i_key_len, iv_len, hash_len,
            shared_secret_k, hash_h, session_id, corrupt)) {
        cr_assert_fail("kdf135 ssh init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf135_ssh = kdf135_ssh_tc;
    
    rv = app_kdf135_ssh_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf135_ssh_tc(kdf135_ssh_tc);
    free(test_case);
}

/*
 * missing hash h in kdf135_ssh tc test case
 */
Test(APP_KDF135_SSH_HANDLER, missing_hash_h) {
    /* arbitrary non-zero */
    int e_key_len = 8, i_key_len = 8, iv_len = 8, hash_len = 8;
    char *shared_secret_k = "aa";
    char *hash_h = NULL;
    char *session_id = "aa";
    int corrupt = 0;
    
    kdf135_ssh_tc = calloc(1, sizeof(ACVP_KDF135_SSH_TC));
    
    if (!initialize_kdf135_ssh_tc(kdf135_ssh_tc, ACVP_SHA256, e_key_len, i_key_len, iv_len, hash_len,
            shared_secret_k, hash_h, session_id, corrupt)) {
        cr_assert_fail("kdf135 ssh init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf135_ssh = kdf135_ssh_tc;
    
    rv = app_kdf135_ssh_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf135_ssh_tc(kdf135_ssh_tc);
    free(test_case);
}

/*
 * missing session id in kdf135_ssh tc test case
 */
Test(APP_KDF135_SSH_HANDLER, missing_session_id) {
    /* arbitrary non-zero */
    int e_key_len = 8, i_key_len = 8, iv_len = 8, hash_len = 8;
    char *shared_secret_k = "aa";
    char *hash_h = "aa";
    char *session_id = NULL;
    int corrupt = 0;
    
    kdf135_ssh_tc = calloc(1, sizeof(ACVP_KDF135_SSH_TC));
    
    if (!initialize_kdf135_ssh_tc(kdf135_ssh_tc, ACVP_SHA256, e_key_len, i_key_len, iv_len, hash_len,
            shared_secret_k, hash_h, session_id, corrupt)) {
        cr_assert_fail("kdf135 ssh init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf135_ssh = kdf135_ssh_tc;
    
    rv = app_kdf135_ssh_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf135_ssh_tc(kdf135_ssh_tc);
    free(test_case);
}

/*
 * unallocated answer bufs in kdf135_ssh tc test case
 */
Test(APP_KDF135_SSH_HANDLER, unallocated_ans_bufs) {
    /* arbitrary non-zero */
    int e_key_len = 8, i_key_len = 8, iv_len = 8, hash_len = 8;
    char *shared_secret_k = "aa";
    char *hash_h = "aa";
    char *session_id = "aa";
    int corrupt = 1;
    
    kdf135_ssh_tc = calloc(1, sizeof(ACVP_KDF135_SSH_TC));
    
    if (!initialize_kdf135_ssh_tc(kdf135_ssh_tc, ACVP_SHA256, e_key_len, i_key_len, iv_len, hash_len,
            shared_secret_k, hash_h, session_id, corrupt)) {
        cr_assert_fail("kdf135 ssh init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf135_ssh = kdf135_ssh_tc;
    
    rv = app_kdf135_ssh_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf135_ssh_tc(kdf135_ssh_tc);
    free(test_case);
}
