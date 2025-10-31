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

TEST_GROUP(APP_KTS_IFC_HANDLER);

static ACVP_TEST_CASE *test_case = NULL;
static ACVP_KTS_IFC_TC *kts_ifc_tc = NULL;
static ACVP_RESULT rv = 0;

void free_kts_ifc_tc(ACVP_KTS_IFC_TC *stc) {
    if (stc->p) free(stc->p);
    if (stc->q) free(stc->q);
    if (stc->d) free(stc->d);
    if (stc->e) free(stc->e);
    if (stc->n) free(stc->n);
    if (stc->ct) free(stc->ct);
    if (stc->pt) free(stc->pt);
    free(stc);
}

int initialize_kts_ifc_tc(ACVP_KTS_IFC_TC *stc,
                          ACVP_KTS_IFC_KEYGEN key_gen,
                          ACVP_HASH_ALG hash_alg,
                          ACVP_KTS_IFC_ROLES role,
                          const char *ct,
                          const char *p,
                          const char *q,
                          const char *d,
                          const char *n,
                          const char *e,
                          int modulo, 
                          int llen, 
                          ACVP_KTS_IFC_TEST_TYPE test_type,
                          int corrupt) {
    stc->llen = llen/8;
    stc->modulo = modulo;
    stc->test_type = test_type;
    stc->md = hash_alg;
    stc->kts_role = role;
    stc->key_gen = key_gen;

    /* Both test types responder needs these */
    if (stc->kts_role == ACVP_KTS_IFC_RESPONDER) {

      if (ct) {
        stc->ct = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
        if (!stc->ct) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(ct, stc->ct, ACVP_KTS_IFC_BYTE_MAX, &(stc->ct_len));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (p)\n");
            goto err;
        }
      }
      if (p) {
        stc->p = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
        if (!stc->p) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(p, stc->p, ACVP_KTS_IFC_BYTE_MAX, &(stc->plen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (p)\n");
            goto err;
        }
      }
      if (q) {
        stc->q = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
        if (!stc->q) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(q, stc->q, ACVP_KTS_IFC_BYTE_MAX, &(stc->qlen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (q)\n");
            goto err;
        }
      }

      if (d) {
        stc->d = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
        if (!stc->d) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(d, stc->d, ACVP_KTS_IFC_BYTE_MAX, &(stc->dlen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (d)\n");
            goto err;
        }
      }
    } else {

      if (corrupt != 1) {
        stc->pt = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
        if (!stc->pt) { return ACVP_MALLOC_FAIL; }
      }

    }

    /* Both test types both roles needs these */
    if (n) {
        stc->n = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
        if (!stc->n) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(n, stc->n, ACVP_KTS_IFC_BYTE_MAX, &(stc->nlen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (n)\n");
            goto err;
        }
      }
    if (e) {
        stc->e = calloc(1, ACVP_RSA_EXP_LEN_MAX);
        if (!stc->e) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(e, stc->e, ACVP_RSA_EXP_LEN_MAX, &(stc->elen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (e)\n");
            goto err;
        }
    }
    return 1;
err:
    free_kts_ifc_tc(stc);
    return 0;
}

TEST_SETUP(APP_KTS_IFC_HANDLER) {}
TEST_TEAR_DOWN(APP_KTS_IFC_HANDLER) {}

// invalid hash alg kts ifc handler
TEST(APP_KTS_IFC_HANDLER, invalid_hash_alg) {
    int corrupt = 0;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = "aa";
    char *ct = "aa";
    ACVP_HASH_ALG hash_alg = 0;
    int modulo = 2048;
    int llen = 512;
    ACVP_KTS_IFC_KEYGEN key_gen = ACVP_KTS_IFC_RSAKPG1_BASIC;
    ACVP_KTS_IFC_TEST_TYPE test_type = ACVP_KTS_IFC_TT_AFT;
    ACVP_KTS_IFC_ROLES role = ACVP_KTS_IFC_INITIATOR;
    
    kts_ifc_tc = calloc(1, sizeof(ACVP_KTS_IFC_TC));
    
    if (!initialize_kts_ifc_tc(kts_ifc_tc, key_gen, hash_alg, role, ct,
                               p, q, d, n, e, modulo, llen, test_type, corrupt)) {
        TEST_FAIL_MESSAGE("kts ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kts_ifc = kts_ifc_tc;
    
    rv = app_kts_ifc_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kts_ifc_tc(kts_ifc_tc);
    free(test_case);
}

// invalid modulo kts ifc handler
TEST(APP_KTS_IFC_HANDLER, invalid_modulo) {
    int corrupt = 0;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = "aa";
    char *ct = "aa";
    ACVP_HASH_ALG hash_alg = ACVP_SHA256;
    int modulo = 0;
    int llen = 512;
    ACVP_KTS_IFC_KEYGEN key_gen = ACVP_KTS_IFC_RSAKPG1_BASIC;
    ACVP_KTS_IFC_TEST_TYPE test_type = ACVP_KTS_IFC_TT_AFT;
    ACVP_KTS_IFC_ROLES role = ACVP_KTS_IFC_INITIATOR;
    
    kts_ifc_tc = calloc(1, sizeof(ACVP_KTS_IFC_TC));
    
    if (!initialize_kts_ifc_tc(kts_ifc_tc, key_gen, hash_alg, role, ct,
                               p, q, d, n, e, modulo, llen, test_type, corrupt)) {
        TEST_FAIL_MESSAGE("kts ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kts_ifc = kts_ifc_tc;
    
    rv = app_kts_ifc_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kts_ifc_tc(kts_ifc_tc);
    free(test_case);
}

// invalid llen kts ifc handler
TEST(APP_KTS_IFC_HANDLER, invalid_llen) {
    int corrupt = 0;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = "aa";
    char *ct = "aa";
    ACVP_HASH_ALG hash_alg = ACVP_SHA256;
    int modulo = 2048;
    int llen = 0;
    ACVP_KTS_IFC_KEYGEN key_gen = ACVP_KTS_IFC_RSAKPG1_BASIC;
    ACVP_KTS_IFC_TEST_TYPE test_type = ACVP_KTS_IFC_TT_AFT;
    ACVP_KTS_IFC_ROLES role = ACVP_KTS_IFC_INITIATOR;
    
    kts_ifc_tc = calloc(1, sizeof(ACVP_KTS_IFC_TC));
    
    if (!initialize_kts_ifc_tc(kts_ifc_tc, key_gen, hash_alg, role, ct,
                               p, q, d, n, e, modulo, llen, test_type, corrupt)) {
        TEST_FAIL_MESSAGE("kts ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kts_ifc = kts_ifc_tc;
    
    rv = app_kts_ifc_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kts_ifc_tc(kts_ifc_tc);
    free(test_case);
}

// missing e kts ifc handler
TEST(APP_KTS_IFC_HANDLER, missing_e) {
    int corrupt = 0;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = NULL;
    char *ct = "aa";
    ACVP_HASH_ALG hash_alg = ACVP_SHA512;
    int modulo = 2048;
    int llen = 512;
    ACVP_KTS_IFC_KEYGEN key_gen = ACVP_KTS_IFC_RSAKPG1_BASIC;
    ACVP_KTS_IFC_TEST_TYPE test_type = ACVP_KTS_IFC_TT_AFT;
    ACVP_KTS_IFC_ROLES role = ACVP_KTS_IFC_INITIATOR;
    
    kts_ifc_tc = calloc(1, sizeof(ACVP_KTS_IFC_TC));
    
    if (!initialize_kts_ifc_tc(kts_ifc_tc, key_gen, hash_alg, role, ct,
                               p, q, d, n, e, modulo, llen, test_type, corrupt)) {
        TEST_FAIL_MESSAGE("kts ifc init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kts_ifc = kts_ifc_tc;
    
    rv = app_kts_ifc_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kts_ifc_tc(kts_ifc_tc);
    free(test_case);
}

// missing n kts ifc handler
TEST(APP_KTS_IFC_HANDLER, missing_n) {
    int corrupt = 0;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = NULL;
    char *e = "aa";
    char *ct = "aa";
    ACVP_HASH_ALG hash_alg = ACVP_SHA512;
    int modulo = 2048;
    int llen = 512;
    ACVP_KTS_IFC_KEYGEN key_gen = ACVP_KTS_IFC_RSAKPG1_BASIC;
    ACVP_KTS_IFC_TEST_TYPE test_type = ACVP_KTS_IFC_TT_AFT;
    ACVP_KTS_IFC_ROLES role = ACVP_KTS_IFC_INITIATOR;
    
    kts_ifc_tc = calloc(1, sizeof(ACVP_KTS_IFC_TC));
    
    if (!initialize_kts_ifc_tc(kts_ifc_tc, key_gen, hash_alg, role, ct,
                               p, q, d, n, e, modulo, llen, test_type, corrupt)) {
        TEST_FAIL_MESSAGE("kts ifc init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kts_ifc = kts_ifc_tc;
    
    rv = app_kts_ifc_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kts_ifc_tc(kts_ifc_tc);
    free(test_case);
}

// missing p kts ifc handler
TEST(APP_KTS_IFC_HANDLER, missing_p) {
    int corrupt = 0;
    char *p = NULL;
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = "aa";
    char *ct = "aa";
    ACVP_HASH_ALG hash_alg = ACVP_SHA512;
    int modulo = 2048;
    int llen = 512;
    ACVP_KTS_IFC_KEYGEN key_gen = ACVP_KTS_IFC_RSAKPG1_BASIC;
    ACVP_KTS_IFC_TEST_TYPE test_type = ACVP_KTS_IFC_TT_AFT;
    ACVP_KTS_IFC_ROLES role = ACVP_KTS_IFC_RESPONDER;
    
    kts_ifc_tc = calloc(1, sizeof(ACVP_KTS_IFC_TC));
    
    if (!initialize_kts_ifc_tc(kts_ifc_tc, key_gen, hash_alg, role, ct,
                               p, q, d, n, e, modulo, llen, test_type, corrupt)) {
        TEST_FAIL_MESSAGE("kts ifc init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kts_ifc = kts_ifc_tc;
    
    rv = app_kts_ifc_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kts_ifc_tc(kts_ifc_tc);
    free(test_case);
}

// missing q kts ifc handler
TEST(APP_KTS_IFC_HANDLER, missing_q) {
    int corrupt = 0;
    char *p = "aa";
    char *q = NULL;
    char *d = "aa";
    char *n = "aa";
    char *e = "aa";
    char *ct = "aa";
    ACVP_HASH_ALG hash_alg = ACVP_SHA512;
    int modulo = 2048;
    int llen = 512;
    ACVP_KTS_IFC_KEYGEN key_gen = ACVP_KTS_IFC_RSAKPG1_BASIC;
    ACVP_KTS_IFC_TEST_TYPE test_type = ACVP_KTS_IFC_TT_AFT;
    ACVP_KTS_IFC_ROLES role = ACVP_KTS_IFC_RESPONDER;
    
    kts_ifc_tc = calloc(1, sizeof(ACVP_KTS_IFC_TC));
    
    if (!initialize_kts_ifc_tc(kts_ifc_tc, key_gen, hash_alg, role, ct,
                               p, q, d, n, e, modulo, llen, test_type, corrupt)) {
        TEST_FAIL_MESSAGE("kts ifc init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kts_ifc = kts_ifc_tc;
    
    rv = app_kts_ifc_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kts_ifc_tc(kts_ifc_tc);
    free(test_case);
}

// missing d kts ifc handler
TEST(APP_KTS_IFC_HANDLER, missing_d) {
    int corrupt = 0;
    char *p = "aa";
    char *q = "aa";
    char *d = NULL;
    char *n = "aa";
    char *e = "aa";
    char *ct = "aa";
    ACVP_HASH_ALG hash_alg = ACVP_SHA512;
    int modulo = 2048;
    int llen = 512;
    ACVP_KTS_IFC_KEYGEN key_gen = ACVP_KTS_IFC_RSAKPG1_BASIC;
    ACVP_KTS_IFC_TEST_TYPE test_type = ACVP_KTS_IFC_TT_AFT;
    ACVP_KTS_IFC_ROLES role = ACVP_KTS_IFC_RESPONDER;
    
    kts_ifc_tc = calloc(1, sizeof(ACVP_KTS_IFC_TC));
    
    if (!initialize_kts_ifc_tc(kts_ifc_tc, key_gen, hash_alg, role, ct,
                               p, q, d, n, e, modulo, llen, test_type, corrupt)) {
        TEST_FAIL_MESSAGE("kts ifc init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kts_ifc = kts_ifc_tc;
    
    rv = app_kts_ifc_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kts_ifc_tc(kts_ifc_tc);
    free(test_case);
}

// missing ct kts ifc handler
TEST(APP_KTS_IFC_HANDLER, missing_ct) {
    int corrupt = 0;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = "aa";
    char *ct = NULL;
    ACVP_HASH_ALG hash_alg = ACVP_SHA512;
    int modulo = 2048;
    int llen = 512;
    ACVP_KTS_IFC_KEYGEN key_gen = ACVP_KTS_IFC_RSAKPG1_BASIC;
    ACVP_KTS_IFC_TEST_TYPE test_type = ACVP_KTS_IFC_TT_AFT;
    ACVP_KTS_IFC_ROLES role = ACVP_KTS_IFC_RESPONDER;
    
    kts_ifc_tc = calloc(1, sizeof(ACVP_KTS_IFC_TC));
    
    if (!initialize_kts_ifc_tc(kts_ifc_tc, key_gen, hash_alg, role, ct,
                               p, q, d, n, e, modulo, llen, test_type, corrupt)) {
        TEST_FAIL_MESSAGE("kts ifc init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kts_ifc = kts_ifc_tc;
    
    rv = app_kts_ifc_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kts_ifc_tc(kts_ifc_tc);
    free(test_case);
}

// unallocated pt ans buffer handler
TEST(APP_KTS_IFC_HANDLER, unallocated_ans_bufs) {
    int corrupt = 1;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = "aa";
    char *ct = "aa";
    ACVP_HASH_ALG hash_alg = ACVP_SHA512;
    int modulo = 2048;
    int llen = 512;
    ACVP_KTS_IFC_KEYGEN key_gen = ACVP_KTS_IFC_RSAKPG1_BASIC;
    ACVP_KTS_IFC_TEST_TYPE test_type = ACVP_KTS_IFC_TT_AFT;
    ACVP_KTS_IFC_ROLES role = ACVP_KTS_IFC_RESPONDER;
    
    kts_ifc_tc = calloc(1, sizeof(ACVP_KTS_IFC_TC));
    
    if (!initialize_kts_ifc_tc(kts_ifc_tc, key_gen, hash_alg, role, ct,
                               p, q, d, n, e, modulo, llen, test_type, corrupt)) {
        TEST_FAIL_MESSAGE("kts ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kts_ifc = kts_ifc_tc;
    
    rv = app_kts_ifc_handler(test_case);
    TEST_ASSERT_NOT_EQUAL(0, rv);
    
    free_kts_ifc_tc(kts_ifc_tc);
    free(test_case);
}
