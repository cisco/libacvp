/** @file */
/*
 * Copyright (c) 2023, Cisco Systems, Inc.
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
#include "acvp/acvp_lcl.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

/* Note: currently tests KAS1 only, and only basic key formats */

ACVP_CTX *ctx;
ACVP_TEST_CASE *test_case;
ACVP_KAS_IFC_TC *kas_ifc_tc;
ACVP_RESULT rv;

void free_kas_ifc_tc(ACVP_KAS_IFC_TC *stc) {
    if (stc->server_n) free(stc->server_n);
    if (stc->server_e) free(stc->server_e);
    if (stc->p) free(stc->p);
    if (stc->q) free(stc->q);
    if (stc->d) free(stc->d);
    if (stc->n) free(stc->n);
    if (stc->e) free(stc->e);
    if (stc->dmp1) free(stc->dmp1);
    if (stc->dmq1) free(stc->dmq1);
    if (stc->iqmp) free(stc->iqmp);
    if (stc->iut_pt_z) free(stc->iut_pt_z);
    if (stc->iut_ct_z) free(stc->iut_ct_z);
    if (stc->provided_pt_z) free(stc->provided_pt_z);
    if (stc->provided_ct_z) free(stc->provided_ct_z);
    if (stc->server_pt_z) free(stc->server_pt_z);
    if (stc->server_ct_z) free(stc->server_ct_z);
    if (stc->provided_kas2_z) free(stc->provided_kas2_z);
    free(stc);
}

int initialize_kas_ifc_tc(ACVP_KAS_IFC_TC *stc,
                          ACVP_KAS_IFC_TEST_TYPE test_type,
                          ACVP_KAS_IFC_KEYGEN key_gen,
                          ACVP_HASH_ALG hash_alg,
                          ACVP_KAS_IFC_PARAM scheme,
                          ACVP_KAS_IFC_ROLES role,
                          const char *pt_z,
                          const char *ct_z,
                          const char *server_ct_z,
                          const char *kas2_z,
                          const char *server_n,
                          const char *server_e,
                          const char *p,
                          const char *q,
                          const char *d,
                          const char *n,
                          const char *e,
                          const char *dmp1,
                          const char *dmq1,
                          const char *iqmp,
                          int corrupt) {
    ACVP_RESULT rv;

    stc->test_type = test_type;
    stc->md = hash_alg;
    stc->kas_role = role;
    stc->key_gen = key_gen;

    if (p) {
        stc->p = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->p) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(p, stc->p, ACVP_KAS_IFC_BYTE_MAX, &(stc->plen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (p)\n");
            goto err;
        }
    }
    if (q) {
        stc->q = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->q) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(q, stc->q, ACVP_KAS_IFC_BYTE_MAX, &(stc->qlen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (q)\n");
            goto err;
        }
    }
    if (d) {
        stc->d = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->d) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(d, stc->d, ACVP_KAS_IFC_BYTE_MAX, &(stc->dlen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (d)\n");
            goto err;
        }
    }
    if (n) {
        /* Both test types both roles needs these */
        stc->n = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->n) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(n, stc->n, ACVP_KAS_IFC_BYTE_MAX, &(stc->nlen));
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
    if (dmp1) {
        /* Both test types both roles needs these */
        stc->dmp1 = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->dmp1) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(dmp1, stc->dmp1, ACVP_KAS_IFC_BYTE_MAX, &(stc->dmp1_len));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (dmp1)\n");
            goto err;
        }
    }
    if (dmq1) {
        stc->dmq1 = calloc(1, ACVP_RSA_EXP_LEN_MAX);
        if (!stc->dmq1) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(dmq1, stc->dmq1, ACVP_RSA_EXP_LEN_MAX, &(stc->dmq1_len));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (dmq1)\n");
            goto err;
        }
    }
    if (iqmp) {
        stc->iqmp = calloc(1, ACVP_RSA_EXP_LEN_MAX);
        if (!stc->iqmp) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(iqmp, stc->iqmp, ACVP_RSA_EXP_LEN_MAX, &(stc->iqmp_len));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (iqmp)\n");
            goto err;
        }
    }
    if (server_ct_z) {
        stc->server_ct_z = calloc(1, ACVP_RSA_EXP_LEN_MAX);
        if (!stc->server_ct_z) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(server_ct_z, stc->server_ct_z, ACVP_RSA_EXP_LEN_MAX, &(stc->server_ct_z_len));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (server_ct_z)\n");
            goto err;
        }
    }
    if (kas2_z) {
        stc->provided_kas2_z = calloc(1, ACVP_RSA_EXP_LEN_MAX);
        if (!stc->provided_kas2_z) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(kas2_z, stc->provided_kas2_z, ACVP_RSA_EXP_LEN_MAX, &(stc->provided_kas2_z_len));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (kas2_z)\n");
            goto err;
        }
    }
    if (server_n) {
        /* Both test types both roles needs these */
        stc->server_n = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->server_n) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(server_n, stc->server_n, ACVP_KAS_IFC_BYTE_MAX, &(stc->server_nlen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (server_n)\n");
            goto err;
        }
    }
    if (server_e) {
        stc->server_e = calloc(1, ACVP_RSA_EXP_LEN_MAX);
        if (!stc->server_e) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(server_e, stc->server_e, ACVP_RSA_EXP_LEN_MAX, &(stc->server_elen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (server_e)\n");
            goto err;
        }
    }

    /* Both test types responder needs these */
    if (corrupt != 1) {
        stc->iut_ct_z = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->iut_ct_z) { return ACVP_MALLOC_FAIL; }
        if (ct_z) {
            rv = acvp_hexstr_to_bin(ct_z, stc->iut_ct_z, ACVP_KAS_IFC_BYTE_MAX, &(stc->iut_ct_z_len));
            if (rv != ACVP_SUCCESS) {
                printf("Hex conversion failure (iut_ct_z)\n");
                goto err;
            }
        }
    }

    if (corrupt != 2) {
        stc->iut_pt_z = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->iut_pt_z) { return ACVP_MALLOC_FAIL; }
        if (pt_z) {
            rv = acvp_hexstr_to_bin(pt_z, stc->iut_pt_z, ACVP_KAS_IFC_BYTE_MAX, &(stc->iut_pt_z_len));
            if (rv != ACVP_SUCCESS) {
                printf("Hex conversion failure (iut_pt_z)\n");
                goto err;
            }
        }
    }

    if (role == ACVP_KAS_IFC_RESPONDER && corrupt != 3) {
        stc->server_pt_z = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->server_pt_z) { return ACVP_MALLOC_FAIL; }
    }

    /* VAL test type both roles needs these */
    if (stc->test_type == ACVP_KAS_IFC_TT_VAL) {
        /* VAL test type initiator role needs this one */
        if (stc->kas_role == ACVP_KAS_IFC_INITIATOR) {
            if (ct_z) {
                stc->provided_ct_z = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
                if (!stc->provided_ct_z) { return ACVP_MALLOC_FAIL; }
                rv = acvp_hexstr_to_bin(ct_z, stc->provided_ct_z, ACVP_KAS_IFC_BYTE_MAX, &(stc->provided_ct_z_len));
                if (rv != ACVP_SUCCESS) {
                    printf("Hex conversion failure (provided_ct_z)\n");
                    goto err;
                }
            }
        } else {
            if (pt_z) {
                stc->provided_pt_z = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
                if (!stc->provided_pt_z) { return ACVP_MALLOC_FAIL; }
                rv = acvp_hexstr_to_bin(pt_z, stc->provided_pt_z, ACVP_KAS_IFC_BYTE_MAX, &(stc->provided_pt_z_len));
                if (rv != ACVP_SUCCESS) {
                    printf("Hex conversion failure (provided_pt_z)\n");
                    goto err;
                }
            }
        }
    }

    return 1;
err:
    free_kas_ifc_tc(stc);
    return 0;
}

/* invalid hash alg kas ifc handler */
Test(APP_KAS_IFC_HANDLER, invalid_hash_alg) {
    int corrupt = 0;
    int hash_alg = -1;
    char *iut_ct_z = NULL;
    char *iut_pt_z = "aa";
    char *server_ct_z = NULL;
    char *server_n = "aa";
    char *server_e = "aa";
    char *p = NULL;
    char *q = NULL;
    char *d = NULL;
    char *n = NULL;
    char *e = NULL;
    char *dmp1 = NULL;
    char *dmq1 = NULL;
    char *iqmp = NULL;

    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_INITIATOR;

    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));

    if (!initialize_kas_ifc_tc(kas_ifc_tc, test_type, key_gen, hash_alg, ACVP_KAS_IFC_KAS1, role, iut_pt_z, iut_ct_z,
                               server_ct_z, NULL, server_n, server_e, p, q, d, n, e, dmp1, dmq1, iqmp, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;

    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/* Missing server public key e */
Test(APP_KAS_IFC_HANDLER, missing_server_e) {
    int corrupt = 0;
    int hash_alg = ACVP_NO_SHA;
    char *iut_ct_z = NULL;
    char *iut_pt_z = "aa";
    char *server_ct_z = NULL;
    char *server_n = "aa";
    char *server_e = NULL;
    char *p = NULL;
    char *q = NULL;
    char *d = NULL;
    char *n = NULL;
    char *e = NULL;
    char *dmp1 = NULL;
    char *dmq1 = NULL;
    char *iqmp = NULL;

    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_INITIATOR;

    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));

    if (!initialize_kas_ifc_tc(kas_ifc_tc, test_type, key_gen, hash_alg, ACVP_KAS_IFC_KAS1, role, iut_pt_z, iut_ct_z,
                               server_ct_z, NULL, server_n, server_e, p, q, d, n, e, dmp1, dmq1, iqmp, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;

    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/* Missing server public key n */
Test(APP_KAS_IFC_HANDLER, missing_server_n) {
    int corrupt = 0;
    int hash_alg = ACVP_NO_SHA;
    char *iut_ct_z = NULL;
    char *iut_pt_z = "aa";
    char *server_ct_z = NULL;
    char *server_n = NULL;
    char *server_e = "aa";
    char *p = NULL;
    char *q = NULL;
    char *d = NULL;
    char *n = NULL;
    char *e = NULL;
    char *dmp1 = NULL;
    char *dmq1 = NULL;
    char *iqmp = NULL;

    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_INITIATOR;

    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));

    if (!initialize_kas_ifc_tc(kas_ifc_tc, test_type, key_gen, hash_alg, ACVP_KAS_IFC_KAS1, role, iut_pt_z, iut_ct_z,
                               server_ct_z, NULL, server_n, server_e, p, q, d, n, e, dmp1, dmq1, iqmp, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;

    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/* Missing iut_pt_z for VAL */
Test(APP_KAS_IFC_HANDLER, missing_iut_pt_z) {
    int corrupt = 0;
    int hash_alg = ACVP_NO_SHA;
    char *iut_ct_z = NULL;
    char *iut_pt_z = NULL;
    char *server_ct_z = NULL;
    char *server_n = "aa";
    char *server_e = "aa";
    char *p = NULL;
    char *q = NULL;
    char *d = NULL;
    char *n = NULL;
    char *e = NULL;
    char *dmp1 = NULL;
    char *dmq1 = NULL;
    char *iqmp = NULL;

    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_VAL;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_INITIATOR;

    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));

    if (!initialize_kas_ifc_tc(kas_ifc_tc, test_type, key_gen, hash_alg, ACVP_KAS_IFC_KAS1, role, iut_pt_z, iut_ct_z,
                               server_ct_z, NULL, server_n, server_e, p, q, d, n, e, dmp1, dmq1, iqmp, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;

    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/* Missing output buffer - iut_ct_z for initiator */
Test(APP_KAS_IFC_HANDLER, missing_buf_iut_ct_z) {
    int corrupt = 1;
    int hash_alg = ACVP_NO_SHA;
    char *iut_ct_z = NULL;
    char *iut_pt_z = "aa";
    char *server_ct_z = NULL;
    char *server_n = "aa";
    char *server_e = "aa";
    char *p = NULL;
    char *q = NULL;
    char *d = NULL;
    char *n = NULL;
    char *e = NULL;
    char *dmp1 = NULL;
    char *dmq1 = NULL;
    char *iqmp = NULL;

    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_VAL;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_INITIATOR;

    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));

    if (!initialize_kas_ifc_tc(kas_ifc_tc, test_type, key_gen, hash_alg, ACVP_KAS_IFC_KAS1, role, iut_pt_z, iut_ct_z,
                               server_ct_z, NULL, server_n, server_e, p, q, d, n, e, dmp1, dmq1, iqmp, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;

    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/* Missing output buffer - iut_pt_z for initiator */
Test(APP_KAS_IFC_HANDLER, missing_buf_iut_pt_z) {
    int corrupt = 2;
    int hash_alg = ACVP_NO_SHA;
    char *iut_ct_z = NULL;
    char *iut_pt_z = NULL;
    char *server_ct_z = NULL;
    char *server_n = "aa";
    char *server_e = "aa";
    char *p = NULL;
    char *q = NULL;
    char *d = NULL;
    char *n = NULL;
    char *e = NULL;
    char *dmp1 = NULL;
    char *dmq1 = NULL;
    char *iqmp = NULL;

    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_INITIATOR;

    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));

    if (!initialize_kas_ifc_tc(kas_ifc_tc, test_type, key_gen, hash_alg, ACVP_KAS_IFC_KAS1, role, iut_pt_z, iut_ct_z,
                               server_ct_z, NULL, server_n, server_e, p, q, d, n, e, dmp1, dmq1, iqmp, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;

    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/* missing e kas ifc handler */
Test(APP_KAS_IFC_HANDLER, missing_e) {
    int corrupt = 0;
    int hash_alg = ACVP_NO_SHA;
    char *iut_ct_z = NULL;
    char *iut_pt_z = NULL;
    char *server_ct_z = "aa";
    char *server_n = NULL;
    char *server_e = NULL;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = NULL;
    char *dmp1 = NULL;
    char *dmq1 = NULL;
    char *iqmp = NULL;

    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;

    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));

    if (!initialize_kas_ifc_tc(kas_ifc_tc, test_type, key_gen, hash_alg, ACVP_KAS_IFC_KAS1, role, iut_pt_z, iut_ct_z,
                               server_ct_z, NULL, server_n, server_e, p, q, d, n, e, dmp1, dmq1, iqmp, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;

    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}


/* missing n kas ifc handler */
Test(APP_KAS_IFC_HANDLER, missing_n) {
    int corrupt = 0;
    int hash_alg = ACVP_NO_SHA;
    char *iut_ct_z = NULL;
    char *iut_pt_z = NULL;
    char *server_ct_z = "aa";
    char *server_n = NULL;
    char *server_e = NULL;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = NULL;
    char *e = "aa";
    char *dmp1 = NULL;
    char *dmq1 = NULL;
    char *iqmp = NULL;

    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;

    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));

    if (!initialize_kas_ifc_tc(kas_ifc_tc, test_type, key_gen, hash_alg, ACVP_KAS_IFC_KAS1, role, iut_pt_z, iut_ct_z,
                               server_ct_z, NULL, server_n, server_e, p, q, d, n, e, dmp1, dmq1, iqmp, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;

    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}


/* missing p kas ifc handler */
Test(APP_KAS_IFC_HANDLER, missing_p) {
    int corrupt = 0;
    int hash_alg = ACVP_NO_SHA;
    char *iut_ct_z = NULL;
    char *iut_pt_z = NULL;
    char *server_ct_z = "aa";
    char *server_n = NULL;
    char *server_e = NULL;
    char *p = NULL;
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = "aa";
    char *dmp1 = NULL;
    char *dmq1 = NULL;
    char *iqmp = NULL;

    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;

    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));

    if (!initialize_kas_ifc_tc(kas_ifc_tc, test_type, key_gen, hash_alg, ACVP_KAS_IFC_KAS1, role, iut_pt_z, iut_ct_z,
                               server_ct_z, NULL, server_n, server_e, p, q, d, n, e, dmp1, dmq1, iqmp, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;

    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}


/* missing q kas ifc handler */
Test(APP_KAS_IFC_HANDLER, missing_q) {
    int corrupt = 0;
    int hash_alg = ACVP_NO_SHA;
    char *iut_ct_z = NULL;
    char *iut_pt_z = NULL;
    char *server_ct_z = "aa";
    char *server_n = NULL;
    char *server_e = NULL;
    char *p = "aa";
    char *q = NULL;
    char *d = "aa";
    char *n = "aa";
    char *e = "aa";
    char *dmp1 = NULL;
    char *dmq1 = NULL;
    char *iqmp = NULL;

    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;

    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));

    if (!initialize_kas_ifc_tc(kas_ifc_tc, test_type, key_gen, hash_alg, ACVP_KAS_IFC_KAS1, role, iut_pt_z, iut_ct_z,
                               server_ct_z, NULL, server_n, server_e, p, q, d, n, e, dmp1, dmq1, iqmp, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;

    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/* missing d kas ifc handler */
Test(APP_KAS_IFC_HANDLER, missing_d) {
    int corrupt = 0;
    int hash_alg = ACVP_NO_SHA;
    char *iut_ct_z = NULL;
    char *iut_pt_z = NULL;
    char *server_ct_z = "aa";
    char *server_n = NULL;
    char *server_e = NULL;
    char *p = "aa";
    char *q = "aa";
    char *d = NULL;
    char *n = "aa";
    char *e = "aa";
    char *dmp1 = NULL;
    char *dmq1 = NULL;
    char *iqmp = NULL;

    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;

    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));

    if (!initialize_kas_ifc_tc(kas_ifc_tc, test_type, key_gen, hash_alg, ACVP_KAS_IFC_KAS1, role, iut_pt_z, iut_ct_z,
                               server_ct_z, NULL, server_n, server_e, p, q, d, n, e, dmp1, dmq1, iqmp, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;

    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/* missing server_ct_z kas ifc handler */
Test(APP_KAS_IFC_HANDLER, missing_ct) {
    int corrupt = 0;
    int hash_alg = ACVP_NO_SHA;
    char *iut_ct_z = NULL;
    char *iut_pt_z = NULL;
    char *server_ct_z = NULL;
    char *server_n = NULL;
    char *server_e = NULL;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = "aa";
    char *dmp1 = NULL;
    char *dmq1 = NULL;
    char *iqmp = NULL;

    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;

    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));

    if (!initialize_kas_ifc_tc(kas_ifc_tc, test_type, key_gen, hash_alg, ACVP_KAS_IFC_KAS1, role, iut_pt_z, iut_ct_z,
                               server_ct_z, NULL, server_n, server_e, p, q, d, n, e, dmp1, dmq1, iqmp, corrupt)) {
        cr_assert_fail("kas ifc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ifc = kas_ifc_tc;

    rv = app_kas_ifc_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kas_ifc_tc(kas_ifc_tc);
    free(test_case);
}

/* missing output buffer - server_pt_z - responder */
Test(APP_KAS_IFC_HANDLER, missing_buf_serv_pt_z) {
    int corrupt = 3;
    int hash_alg = ACVP_NO_SHA;
    char *iut_ct_z = NULL;
    char *iut_pt_z = NULL;
    char *server_ct_z = "aa";
    char *server_n = NULL;x
    char *server_e = NULL;
    char *p = "aa";
    char *q = "aa";
    char *d = "aa";
    char *n = "aa";
    char *e = "aa";
    char *dmp1 = NULL;
    char *dmq1 = NULL;
    char *iqmp = NULL;

    ACVP_KAS_IFC_KEYGEN key_gen = ACVP_KAS_IFC_RSAKPG1_BASIC;
    ACVP_KAS_IFC_TEST_TYPE test_type = ACVP_KAS_IFC_TT_AFT;
    ACVP_KAS_IFC_ROLES role = ACVP_KAS_IFC_RESPONDER;

    kas_ifc_tc = calloc(1, sizeof(ACVP_KAS_IFC_TC));

    if (!initialize_kas_ifc_tc(kas_ifc_tc, test_type, key_gen, hash_alg, ACVP_KAS_IFC_KAS1, role, iut_pt_z, iut_ct_z,
                               server_ct_z, NULL, server_n, server_e, p, q, d, n, e, dmp1, dmq1, iqmp, corrupt)) {
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

