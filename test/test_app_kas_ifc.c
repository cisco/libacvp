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
ACVP_KAS_IFC_TC *kas_ifc_tc;
ACVP_RESULT rv;

void free_kas_ifc_tc(ACVP_KAS_IFC_TC *stc) {
    if (stc->z) free(stc->z);
    if (stc->hashz) free(stc->hashz);
    if (stc->chash) free(stc->chash);
    if (stc->p) free(stc->p);
    if (stc->q) free(stc->q);
    if (stc->d) free(stc->d);
    if (stc->e) free(stc->e);
    if (stc->n) free(stc->n);
    if (stc->c) free(stc->c);
    if (stc->ct) free(stc->ct);
    if (stc->pt) free(stc->pt);
    free(stc);
}

int initialize_kas_ifc_tc(ACVP_KAS_IFC_TC *stc,
                          ACVP_KAS_IFC_KEYGEN key_gen,
                          ACVP_HASH_ALG hash_alg,
                          ACVP_KAS_IFC_ROLES role,
                          const char *z,
                          const char *hashz,
                          const char *ct,
                          const char *p,
                          const char *q,
                          const char *d,
                          const char *n,
                          const char *e,
                          const char *c,
                          ACVP_KAS_IFC_TEST_TYPE test_type,
                          int corrupt) {
    ACVP_RESULT rv;
    
    stc->test_type = test_type;
    stc->md = hash_alg;
    stc->kas_role = role;
    stc->key_gen = key_gen;

    /* Both test types responder needs these */
    if (stc->kas_role == ACVP_KAS_IFC_RESPONDER) {

if (ct) {
        stc->ct = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->ct) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(ct, stc->ct, ACVP_KAS_IFC_BYTE_MAX, &(stc->ct_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (ct)");
            goto err;
        }
}
if (p) {
        stc->p = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->p) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(p, stc->p, ACVP_KAS_IFC_BYTE_MAX, &(stc->plen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (p)");
            goto err;
        }
}
if (q) {
        stc->q = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->q) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(q, stc->q, ACVP_KAS_IFC_BYTE_MAX, &(stc->qlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (q)");
            goto err;
        }
}
if (d) {
        stc->d = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->d) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(d, stc->d, ACVP_KAS_IFC_BYTE_MAX, &(stc->dlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (d)");
            goto err;
        }
}
    }
if (n) {
    /* Both test types both roles needs these */
    stc->n = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
    if (!stc->n) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(n, stc->n, ACVP_KAS_IFC_BYTE_MAX, &(stc->nlen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (n)");
        goto err;
    }
}
if (e) {
    stc->e = calloc(1, ACVP_RSA_EXP_LEN_MAX);
    if (!stc->e) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(e, stc->e, ACVP_RSA_EXP_LEN_MAX, &(stc->elen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (e)");
        goto err;
    }
}
    /* VAL test type both roles needs these */
    if (stc->test_type == ACVP_KAS_IFC_TT_VAL) {
if (z) {
        stc->z = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->z) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(z, stc->z, ACVP_KAS_IFC_BYTE_MAX, &(stc->zlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (z)");
            goto err;
        }
}
if (hashz) {
        stc->hashz = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->hashz) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(hashz, stc->hashz, ACVP_KAS_IFC_BYTE_MAX, &(stc->hashzlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (hashz)");
            goto err;
        }
}
        /* VAL test type initiator role needs this one */
        if (stc->kas_role == ACVP_KAS_IFC_INITIATOR) {
if (c) {
            stc->c = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
            if (!stc->c) { return ACVP_MALLOC_FAIL; }
            rv = acvp_hexstr_to_bin(c, stc->c, ACVP_KAS_IFC_BYTE_MAX, &(stc->clen));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (c)");
                goto err;
            }
}
        }
    }

    if (corrupt != 1) {
        stc->pt = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->pt) { return ACVP_MALLOC_FAIL; }
    }
    if (corrupt != 2) {

        stc->chash = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->chash) { return ACVP_MALLOC_FAIL; }
    }
    return 1;
err:
    free_kas_ifc_tc(stc);
    return 0;
}

/*
 * invalid hash alg kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, invalid_hash_alg) {
    int corrupt = 0;
    int hash_alg = 0;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = "aa";
    char *c = "aa";
    char *ct = "aa";
    char *z = "aa";
    char *hashz = "aa";
    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_INITIATOR;
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, key_gen, hash_alg, role, z, hashz, ct,
                               p, q, d, n, e, c, test_type, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing e kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_e) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA512;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = NULL;
    char *c = "aa";
    char *ct = "aa";
    char *z = "aa";
    char *hashz = "aa";
    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_INITIATOR;
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, key_gen, hash_alg, role, z, hashz, ct,
                               p, q, d, n, e, c, test_type, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing n kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_n) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA256;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = NULL;
    char *e = "aa";
    char *c = "aa";
    char *ct = "aa";
    char *z = "aa";
    char *hashz = "aa";
    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_INITIATOR;
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, key_gen, hash_alg, role, z, hashz, ct,
                               p, q, d, n, e, c, test_type, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing p kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_p) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA256;
    char *p = NULL;
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = "aa";
    char *c = "aa";
    char *ct = "aa";
    char *z = "aa";
    char *hashz = "aa";
    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, key_gen, hash_alg, role, z, hashz, ct,
                               p, q, d, n, e, c, test_type, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing q kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_q) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA256;
    char *p = "aa";
    char *n = "aa";
    char *d = "aa";
    char *q = NULL;
    char *e = "aa";
    char *c = "aa";
    char *ct = "aa";
    char *z = "aa";
    char *hashz = "aa";
    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, key_gen, hash_alg, role, z, hashz, ct,
                               p, q, d, n, e, c, test_type, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing d kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_d) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA256;
    char *p = "aa";
    char *q = "aa";
    char *n = "aa";
    char *d = NULL;
    char *e = "aa";
    char *c = "aa";
    char *ct = "aa";
    char *z = "aa";
    char *hashz = "aa";
    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, key_gen, hash_alg, role, z, hashz, ct,
                               p, q, d, n, e, c, test_type, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing ct kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_ct) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA256;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *ct = NULL;
    char *e = "aa";
    char *c = "aa";
    char *n = "aa";
    char *z = "aa";
    char *hashz = "aa";
    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, key_gen, hash_alg, role, z, hashz, ct,
                               p, q, d, n, e, c, test_type, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing pt kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_pt) {
    int corrupt = 1;
    int hash_alg = ACVP_SHA256;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *ct = "aa";
    char *e = "aa";
    char *c = "aa";
    char *n = "aa";
    char *z = "aa";
    char *hashz = "aa";
    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, key_gen, hash_alg, role, z, hashz, ct,
                               p, q, d, n, e, c, test_type, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing chash kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_chash1) {
    int corrupt = 2;
    int hash_alg = ACVP_SHA256;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *ct = "aa";
    char *e = "aa";
    char *c = "aa";
    char *n = "aa";
    char *z = "aa";
    char *hashz = "aa";
    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, key_gen, hash_alg, role, z, hashz, ct,
                               p, q, d, n, e, c, test_type, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing chash kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_chash2) {
    int corrupt = 2;
    int hash_alg = ACVP_SHA256;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *ct = "aa";
    char *e = "aa";
    char *c = "aa";
    char *n = "aa";
    char *z = "aa";
    char *hashz = "aa";
    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_VAL;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, key_gen, hash_alg, role, z, hashz, ct,
                               p, q, d, n, e, c, test_type, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing z kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_z) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA256;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *z = NULL;
    char *e = "aa";
    char *c = "aa";
    char *ct = "aa";
    char *n = "aa";
    char *hashz = "aa";
    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_VAL;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_INITIATOR;
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, key_gen, hash_alg, role, z, hashz, ct,
                               p, q, d, n, e, c, test_type, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}


#if 0
/*
 * missing g kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_g) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA384;
    char *p = "aa";
    char *q = "aa";
    char *g = NULL;
    char *ps = "aa";
    char *epri = "aa";
    char *epui = "aa";
    char *z = "aa";
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, hash_alg, ACVP_KAS_IFC_TT_VAL, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing eps kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_eps) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA384;
    char *p = "aa";
    char *q = "aa";
    char *g = "aa";
    char *ps = NULL;
    char *epri = "aa";
    char *epui = "aa";
    char *z = "aa";
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, hash_alg, ACVP_KAS_IFC_TT_VAL, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing epri kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_epri) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA384;
    char *p = "aa";
    char *q = "aa";
    char *g = "aa";
    char *ps = "aa";
    char *epri = NULL;
    char *epui = "aa";
    char *z = "aa";
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, hash_alg, ACVP_KAS_IFC_TT_VAL, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing epui kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, missing_epui) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA384;
    char *p = "aa";
    char *q = "aa";
    char *g = "aa";
    char *ps = "aa";
    char *epri = "aa";
    char *epui = NULL;
    char *z = "aa";
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, hash_alg, ACVP_KAS_IFC_TT_VAL, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * missing z kas ifc handler
 * only valid for AFT test types
 */
Test(APP_KAS_IFC_HANDLER, missing_z) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA384;
    char *p = "aa";
    char *q = "aa";
    char *g = "aa";
    char *ps = "aa";
    char *epri = "aa";
    char *epui = "aa";
    char *z = NULL;
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, hash_alg, ACVP_KAS_ECC_TT_AFT, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/*
 * unallocated answer buffers kas ifc handler
 */
Test(APP_KAS_IFC_HANDLER, unallocated_ans_bufs) {
    int corrupt = 1;
    int hash_alg = ACVP_SHA384;
    char *p = "aa";
    char *q = "aa";
    char *g = "aa";
    char *ps = "aa";
    char *epri = "aa";
    char *epui = "aa";
    char *z = "aa";
    
    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));
    
    if (!initialize_kas_ifc_tc(kas_ifc_tc, hash_alg, ACVP_KAS_IFC_TT_VAL, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;
    
    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}
#endif
#endif // ACVP_NO_RUNTIME

