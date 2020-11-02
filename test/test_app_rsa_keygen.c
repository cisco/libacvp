/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

//
// Created by edaw on 2019-01-07.
//

#ifdef ACVP_NO_RUNTIME

#include "ut_common.h"
#include "app_common.h"
#include "acvp/acvp_lcl.h"

ACVP_CTX *ctx;
ACVP_TEST_CASE *test_case;
ACVP_RSA_KEYGEN_TC *rsa_tc;
ACVP_RESULT rv;

void free_rsa_keygen_tc(ACVP_RSA_KEYGEN_TC *stc) {
    if (stc->e) { free(stc->e); }
    if (stc->seed) { free(stc->seed); }
    if (stc->p) { free(stc->p); }
    if (stc->q) { free(stc->q); }
    if (stc->n) { free(stc->n); }
    if (stc->d) { free(stc->d); }
    free(stc);
}

int initialize_rsa_tc(ACVP_RSA_KEYGEN_TC *stc,
                      int info_gen_by_server,
                      ACVP_HASH_ALG hash_alg,
                      ACVP_RSA_KEY_FORMAT key_format,
                      ACVP_RSA_PUB_EXP_MODE pub_exp_mode,
                      int modulo,
                      ACVP_RSA_PRIME_TEST_TYPE prime_test,
                      int rand_pq,
                      const char *e,
                      const char *seed,
                      int seed_len,
                      int bitlen1,
                      int bitlen2,
                      int bitlen3,
                      int bitlen4,
                      int corrupt) {
    memzero_s(stc, sizeof(ACVP_RSA_KEYGEN_TC));
    ACVP_RESULT rv = ACVP_SUCCESS;
    stc->info_gen_by_server = info_gen_by_server;
    stc->rand_pq = rand_pq;
    stc->modulo = modulo;
    stc->prime_test = prime_test;
    stc->hash_alg = hash_alg;
    stc->pub_exp_mode = pub_exp_mode;
    stc->key_format = key_format;
    
    if (!corrupt) {
        stc->p = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->p) { goto err; }
        stc->q = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->q) { goto err; }
        stc->n = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->n) { goto err; }
        stc->d = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->d) { goto err; }
        stc->seed = calloc(ACVP_RSA_SEEDLEN_MAX, sizeof(unsigned char));
        if (!stc->seed) { goto err; }
    }
    
    if (e) {
        stc->e = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->e) { goto err; }
        rv = acvp_hexstr_to_bin(e, stc->e, ACVP_RSA_EXP_BYTE_MAX, &(stc->e_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (e)");
            goto err;
        }
    }
    
    if (info_gen_by_server) {
        stc->bitlen1 = bitlen1;
        stc->bitlen2 = bitlen2;
        stc->bitlen3 = bitlen3;
        stc->bitlen4 = bitlen4;
        if (seed) {
            stc->seed = calloc(ACVP_RSA_SEEDLEN_MAX, sizeof(unsigned char));
            if (!stc->seed) { goto err; }
            rv = acvp_hexstr_to_bin(seed, stc->seed, seed_len, &(stc->seed_len));
            if (rv != ACVP_SUCCESS) {
                goto err;
            }
        }
    }
    
    return 1;
    
err:
    free_rsa_keygen_tc(stc);
    return 0;
}

/*
 * invalid hash alg rsa keygen handler
 */
Test(APP_RSA_KEYGEN_HANDLER, invalid_hash_alg) {
    int info_gen_by_server = 0, corrupt = 0;
    int bitlen1 = 88, bitlen2 = 88, bitlen3 = 88, bitlen4 = 88;
    int pub_exp_mode = ACVP_RSA_PUB_EXP_MODE_FIXED;
    int modulo = 2048;
    int key_format = ACVP_RSA_KEY_FORMAT_STANDARD;
    int prime_test = ACVP_RSA_PRIME_TEST_TBLC2;
    int rand_pq = ACVP_RSA_KEYGEN_B33;
    int seed_len = 8;
    char *e = "aa";
    char *seed = "aa";
    
    rsa_tc = calloc(1, sizeof(ACVP_RSA_KEYGEN_TC));
    
    if (!initialize_rsa_tc(rsa_tc, info_gen_by_server, 0, key_format,
            pub_exp_mode, modulo, prime_test, rand_pq, e, seed, seed_len,
            bitlen1, bitlen2, bitlen3, bitlen4, corrupt)) {
        cr_assert_fail("rsa keygen init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.rsa_keygen = rsa_tc;
    
    rv = app_rsa_keygen_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_rsa_keygen_tc(rsa_tc);
    free(test_case);
}

/*
 * invalid key format rsa keygen handler
 */
Test(APP_RSA_KEYGEN_HANDLER, invalid_key_format) {
    int info_gen_by_server = 0, corrupt = 0;
    int bitlen1 = 88, bitlen2 = 88, bitlen3 = 88, bitlen4 = 88;
    int pub_exp_mode = ACVP_RSA_PUB_EXP_MODE_FIXED;
    int modulo = 2048;
    int key_format = 0;
    int prime_test = ACVP_RSA_PRIME_TEST_TBLC2;
    int rand_pq = ACVP_RSA_KEYGEN_B33;
    int seed_len = 8;
    char *e = "aa";
    char *seed = "aa";
    
    rsa_tc = calloc(1, sizeof(ACVP_RSA_KEYGEN_TC));
    if (!initialize_rsa_tc(rsa_tc, info_gen_by_server, ACVP_SHA384, key_format,
    pub_exp_mode, modulo, prime_test, rand_pq, e, seed, seed_len,
    bitlen1, bitlen2, bitlen3, bitlen4, corrupt)) {
        cr_assert_fail("rsa keygen init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.rsa_keygen = rsa_tc;
    
    rv = app_rsa_keygen_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_rsa_keygen_tc(rsa_tc);
    free(test_case);
}

/*
 * invalid pub exp mode rsa keygen handler
 */
Test(APP_RSA_KEYGEN_HANDLER, invalid_pub_exp_mode) {
    int info_gen_by_server = 0, corrupt = 0;
    int bitlen1 = 88, bitlen2 = 88, bitlen3 = 88, bitlen4 = 88;
    int pub_exp_mode = 0;
    int modulo = 2048;
    int key_format = ACVP_RSA_KEY_FORMAT_CRT;
    int prime_test = ACVP_RSA_PRIME_TEST_TBLC2;
    int rand_pq = ACVP_RSA_KEYGEN_B33;
    int seed_len = 8;
    char *e = "aa";
    char *seed = "aa";
    
    rsa_tc = calloc(1, sizeof(ACVP_RSA_KEYGEN_TC));
    
    if (!initialize_rsa_tc(rsa_tc, info_gen_by_server, ACVP_SHA384, key_format,
            pub_exp_mode, modulo, prime_test, rand_pq, e, seed, seed_len,
            bitlen1, bitlen2, bitlen3, bitlen4, corrupt)) {
        cr_assert_fail("rsa keygen init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.rsa_keygen = rsa_tc;
    
    rv = app_rsa_keygen_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_rsa_keygen_tc(rsa_tc);
    free(test_case);
}

/*
 * invalid modulo rsa keygen handler
 */
Test(APP_RSA_KEYGEN_HANDLER, invalid_modulo) {
    int info_gen_by_server = 0, corrupt = 0;
    int bitlen1 = 88, bitlen2 = 88, bitlen3 = 88, bitlen4 = 88;
    int pub_exp_mode = ACVP_RSA_PUB_EXP_MODE_FIXED;
    int modulo = 0;
    int key_format = ACVP_RSA_KEY_FORMAT_STANDARD;
    int prime_test = ACVP_RSA_PRIME_TEST_TBLC2;
    int rand_pq = ACVP_RSA_KEYGEN_B33;
    int seed_len = 8;
    char *e = "aa";
    char *seed = "aa";
    
    rsa_tc = calloc(1, sizeof(ACVP_RSA_KEYGEN_TC));
    
    if (!initialize_rsa_tc(rsa_tc, info_gen_by_server, ACVP_SHA384, key_format,
            pub_exp_mode, modulo, prime_test, rand_pq, e, seed, seed_len,
            bitlen1, bitlen2, bitlen3, bitlen4, corrupt)) {
        cr_assert_fail("rsa keygen init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.rsa_keygen = rsa_tc;
    
    rv = app_rsa_keygen_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_rsa_keygen_tc(rsa_tc);
    free(test_case);
}

/*
 * invalid prime test rsa keygen handler
 */
Test(APP_RSA_KEYGEN_HANDLER, invalid_prime_test) {
    int info_gen_by_server = 0, corrupt = 0;
    int bitlen1 = 88, bitlen2 = 88, bitlen3 = 88, bitlen4 = 88;
    int pub_exp_mode = ACVP_RSA_PUB_EXP_MODE_FIXED;
    int modulo = 3072;
    int key_format = ACVP_RSA_KEY_FORMAT_STANDARD;
    int prime_test = 0;
    int rand_pq = ACVP_RSA_KEYGEN_B33;
    int seed_len = 8;
    char *e = "aa";
    char *seed = "aa";
    
    rsa_tc = calloc(1, sizeof(ACVP_RSA_KEYGEN_TC));
    
    if (!initialize_rsa_tc(rsa_tc, info_gen_by_server, ACVP_SHA384, key_format,
            pub_exp_mode, modulo, prime_test, rand_pq, e, seed, seed_len,
            bitlen1, bitlen2, bitlen3, bitlen4, corrupt)) {
        cr_assert_fail("rsa keygen init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.rsa_keygen = rsa_tc;
    
    rv = app_rsa_keygen_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_rsa_keygen_tc(rsa_tc);
    free(test_case);
}

/*
 * invalid rand pq rsa keygen handler
 */
Test(APP_RSA_KEYGEN_HANDLER, invalid_rand_pq) {
    int info_gen_by_server = 0, corrupt = 0;
    int bitlen1 = 88, bitlen2 = 88, bitlen3 = 88, bitlen4 = 88;
    int pub_exp_mode = ACVP_RSA_PUB_EXP_MODE_FIXED;
    int modulo = 3072;
    int key_format = ACVP_RSA_KEY_FORMAT_STANDARD;
    int prime_test = ACVP_RSA_PRIME_TEST_TBLC3;
    int rand_pq = 0;
    int seed_len = 8;
    char *e = "aa";
    char *seed = "aa";
    
    rsa_tc = calloc(1, sizeof(ACVP_RSA_KEYGEN_TC));
    
    if (!initialize_rsa_tc(rsa_tc, info_gen_by_server, ACVP_SHA384, key_format,
            pub_exp_mode, modulo, prime_test, rand_pq, e, seed, seed_len,
            bitlen1, bitlen2, bitlen3, bitlen4, corrupt)) {
        cr_assert_fail("rsa keygen init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.rsa_keygen = rsa_tc;
    
    rv = app_rsa_keygen_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_rsa_keygen_tc(rsa_tc);
    free(test_case);
}

/*
 * missing e rsa keygen handler (only if pub_exp_fixed)
 */
Test(APP_RSA_KEYGEN_HANDLER, missing_e) {
    int info_gen_by_server = 0, corrupt = 0;
    int bitlen1 = 88, bitlen2 = 88, bitlen3 = 88, bitlen4 = 88;
    int pub_exp_mode = ACVP_RSA_PUB_EXP_MODE_FIXED;
    int modulo = 3072;
    int key_format = ACVP_RSA_KEY_FORMAT_STANDARD;
    int prime_test = ACVP_RSA_PRIME_TEST_TBLC3;
    int rand_pq = 0;
    int seed_len = 8;
    char *e = NULL;
    char *seed = "aa";
    
    rsa_tc = calloc(1, sizeof(ACVP_RSA_KEYGEN_TC));
    
    if (!initialize_rsa_tc(rsa_tc, info_gen_by_server, ACVP_SHA384, key_format,
            pub_exp_mode, modulo, prime_test, rand_pq, e, seed, seed_len,
            bitlen1, bitlen2, bitlen3, bitlen4, corrupt)) {
        cr_assert_fail("rsa keygen init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.rsa_keygen = rsa_tc;
    
    rv = app_rsa_keygen_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_rsa_keygen_tc(rsa_tc);
    free(test_case);
}

/*
 * missing seed rsa keygen handler (only if info_gen_by_server = 1)
 */
Test(APP_RSA_KEYGEN_HANDLER, missing_seed) {
    int info_gen_by_server = 1, corrupt = 0;
    int bitlen1 = 88, bitlen2 = 88, bitlen3 = 88, bitlen4 = 88;
    int pub_exp_mode = ACVP_RSA_PUB_EXP_MODE_FIXED;
    int modulo = 3072;
    int key_format = ACVP_RSA_KEY_FORMAT_STANDARD;
    int prime_test = ACVP_RSA_PRIME_TEST_TBLC3;
    int rand_pq = 0;
    int seed_len = 8;
    char *e = "aa";
    char *seed = NULL;
    
    rsa_tc = calloc(1, sizeof(ACVP_RSA_KEYGEN_TC));
    
    if (!initialize_rsa_tc(rsa_tc, info_gen_by_server, ACVP_SHA384, key_format,
            pub_exp_mode, modulo, prime_test, rand_pq, e, seed, seed_len,
            bitlen1, bitlen2, bitlen3, bitlen4, corrupt)) {
        cr_assert_fail("rsa keygen init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.rsa_keygen = rsa_tc;
    
    rv = app_rsa_keygen_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_rsa_keygen_tc(rsa_tc);
    free(test_case);
}

/*
 * unallocated answer buffers rsa keygen tc
 */
Test(APP_RSA_KEYGEN_HANDLER, unallocated_ans_bufs) {
    int info_gen_by_server = 0, corrupt = 1;
    int bitlen1 = 88, bitlen2 = 88, bitlen3 = 88, bitlen4 = 88;
    int pub_exp_mode = ACVP_RSA_PUB_EXP_MODE_FIXED;
    int modulo = 3072;
    int key_format = ACVP_RSA_KEY_FORMAT_STANDARD;
    int prime_test = ACVP_RSA_PRIME_TEST_TBLC3;
    int rand_pq = 0;
    int seed_len = 8;
    char *e = "aa";
    char *seed = "aa";
    
    rsa_tc = calloc(1, sizeof(ACVP_RSA_KEYGEN_TC));
    
    if (!initialize_rsa_tc(rsa_tc, info_gen_by_server, ACVP_SHA384, key_format,
            pub_exp_mode, modulo, prime_test, rand_pq, e, seed, seed_len,
            bitlen1, bitlen2, bitlen3, bitlen4, corrupt)) {
        cr_assert_fail("rsa keygen init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.rsa_keygen = rsa_tc;
    
    rv = app_rsa_keygen_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_rsa_keygen_tc(rsa_tc);
    free(test_case);
}

#endif // ACVP_NO_RUNTIME

