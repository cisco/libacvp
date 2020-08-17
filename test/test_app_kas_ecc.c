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
ACVP_KAS_ECC_TC *kas_ecc_tc;
ACVP_RESULT rv;

void free_kas_ecc_tc(ACVP_KAS_ECC_TC *stc) {
    if (stc->chash) free(stc->chash);
    if (stc->psx) free(stc->psx);
    if (stc->psy) free(stc->psy);
    if (stc->pix) free(stc->pix);
    if (stc->piy) free(stc->piy);
    if (stc->d) free(stc->d);
    if (stc->z) free(stc->z);
    free(stc);
}

int initialize_kas_ecc_cdh_tc(ACVP_KAS_ECC_TC *stc,
                              ACVP_KAS_ECC_TEST_TYPE test_type,
                              ACVP_EC_CURVE curve,
                              const char *psx,
                              const char *psy,
                              int corrupt) {
    ACVP_RESULT rv;
    
    stc->mode = ACVP_KAS_ECC_MODE_CDH;
    stc->curve = curve;
    stc->test_type = test_type;
    
    if (psx) {
        stc->psx = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->psx) { goto err; }
        rv = acvp_hexstr_to_bin(psx, stc->psx, ACVP_KAS_ECC_BYTE_MAX, &(stc->psxlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (psx)");
            goto err;
        }
    }
    
    if (psy) {
        stc->psy = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->psy) { goto err; }
        rv = acvp_hexstr_to_bin(psy, stc->psy, ACVP_KAS_ECC_BYTE_MAX, &(stc->psylen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (psy)");
            goto err;
        }
    }
    
    if (!corrupt) {
        stc->pix = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->pix) { goto err; }
        stc->piy = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->piy) { goto err; }
    
        stc->z = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->z) { goto err; }
        stc->d = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->d) { goto err; }
        stc->chash = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->chash) { goto err; }
    }
    
    return 1;
    
    err:
    free_kas_ecc_tc(stc);
    return 0;
}

int initialize_kas_ecc_comp_tc(ACVP_KAS_ECC_TC *stc,
                               ACVP_KAS_ECC_TEST_TYPE test_type,
                               ACVP_EC_CURVE curve,
                               ACVP_HASH_ALG hash,
                               const char *psx,
                               const char *psy,
                               const char *d,
                               const char *pix,
                               const char *piy,
                               const char *z,
                               int corrupt) {
    ACVP_RESULT rv;
    
    stc->mode = ACVP_KAS_ECC_MODE_COMPONENT;
    stc->curve = curve;
    stc->md = hash;
    stc->test_type = test_type;
    
    if (psx) {
        stc->psx = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->psx) { goto err; }
        rv = acvp_hexstr_to_bin(psx, stc->psx, ACVP_KAS_ECC_BYTE_MAX, &(stc->psxlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (psx)");
            goto err;
        }
    }
    
    if (psy) {
        stc->psy = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->psy) { goto err; }
        rv = acvp_hexstr_to_bin(psy, stc->psy, ACVP_KAS_ECC_BYTE_MAX, &(stc->psylen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (psy)");
            goto err;
        }
    }
    
    if (!corrupt) {
        stc->chash = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->chash) { goto err; }
    }
    
    if (stc->test_type == ACVP_KAS_ECC_TT_VAL) {
        if (pix) {
            stc->pix = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
            if (!stc->pix) { goto err; }
            rv = acvp_hexstr_to_bin(pix, stc->pix, ACVP_KAS_ECC_BYTE_MAX, &(stc->pixlen));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (pix)");
                goto err;
            }
        }
        
        if (piy) {
            stc->piy = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
            if (!stc->piy) { goto err; }
            rv = acvp_hexstr_to_bin(piy, stc->piy, ACVP_KAS_ECC_BYTE_MAX, &(stc->piylen));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (piy)");
                goto err;
            }
        }
        
        if (d) {
            stc->d = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
            if (!stc->d) { goto err; }
            rv = acvp_hexstr_to_bin(d, stc->d, ACVP_KAS_ECC_BYTE_MAX, &(stc->dlen));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (d)");
                goto err;
            }
        }
        
        if (z) {
            stc->z = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
            if (!stc->z) { goto err; }
            rv = acvp_hexstr_to_bin(z, stc->z, ACVP_KAS_ECC_BYTE_MAX, &(stc->zlen));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (z)");
                goto err;
            }
        }
    } else if (!corrupt) {
        stc->pix = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->pix) { goto err; }
        stc->piy = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->piy) { goto err; }
        stc->d = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->d) { goto err; }
        stc->z = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
        if (!stc->z) { goto err; }
    }
    
    return 1;
    
    err:
    free_kas_ecc_tc(stc);
    return 0;
}

/*
 * invalid curve kas ecc handler
 * this code is shared in the handler between the two
 * modes, so no need to test both initializers
 */
Test(APP_KAS_ECC_HANDLER, invalid_curve) {
    int corrupt = 0;
    int curve = 0;
    char *psx = "aa";
    char *psy = "aa";
    
    kas_ecc_tc = calloc(1, sizeof(ACVP_KAS_ECC_TC));
    
    if (!initialize_kas_ecc_cdh_tc(kas_ecc_tc, ACVP_KAS_ECC_TT_VAL, curve,
            psx, psy, corrupt)) {
        cr_assert_fail("kas ecc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ecc = kas_ecc_tc;
    
    rv = app_kas_ecc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ecc_tc(kas_ecc_tc);
    free(test_case);
}

/*
 * invalid hash alg kas ecc comp handler
 */
Test(APP_KAS_ECC_HANDLER, invalid_hash_ecc_comp) {
    int corrupt = 0;
    int curve = ACVP_EC_CURVE_B283;
    char *psx = "aa";
    char *psy = "aa";
    char *d = "aa";
    char *pix = "aa";
    char *piy = "aa";
    char *z = "aa";
    int hash_alg = 0;
    
    kas_ecc_tc = calloc(1, sizeof(ACVP_KAS_ECC_TC));
    
    if (!initialize_kas_ecc_comp_tc(kas_ecc_tc, ACVP_KAS_ECC_TT_VAL, curve, hash_alg,
            psx, psy, d, pix, piy, z, corrupt)) {
        cr_assert_fail("kas ecc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ecc = kas_ecc_tc;
    
    rv = app_kas_ecc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ecc_tc(kas_ecc_tc);
    free(test_case);
}

/*
 * missing_psx kas ecc handler
 * this code is shared in the handler between the two
 * modes, so no need to test both initializers
 */
Test(APP_KAS_ECC_HANDLER, missing_psx) {
    int corrupt = 0;
    int curve = ACVP_EC_CURVE_B571;
    char *psx = NULL;
    char *psy = "aa";
    
    kas_ecc_tc = calloc(1, sizeof(ACVP_KAS_ECC_TC));
    
    if (!initialize_kas_ecc_cdh_tc(kas_ecc_tc, ACVP_KAS_ECC_TT_VAL, curve,
            psx, psy, corrupt)) {
        cr_assert_fail("kas ecc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ecc = kas_ecc_tc;
    
    rv = app_kas_ecc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ecc_tc(kas_ecc_tc);
    free(test_case);
}

/*
 * missing_psy kas ecc handler
 * this code is shared in the handler between the two
 * modes, so no need to test both initializers
 */
Test(APP_KAS_ECC_HANDLER, missing_psy) {
    int corrupt = 0;
    int curve = ACVP_EC_CURVE_B571;
    char *psx = "aa";
    char *psy = NULL;
    
    kas_ecc_tc = calloc(1, sizeof(ACVP_KAS_ECC_TC));
    
    if (!initialize_kas_ecc_cdh_tc(kas_ecc_tc, ACVP_KAS_ECC_TT_AFT, curve,
            psx, psy, corrupt)) {
        cr_assert_fail("kas ecc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ecc = kas_ecc_tc;
    
    rv = app_kas_ecc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ecc_tc(kas_ecc_tc);
    free(test_case);
}

/*
 * missing pix kas ecc comp handler
 */
Test(APP_KAS_ECC_HANDLER, missing_pix) {
    int corrupt = 0;
    int curve = ACVP_EC_CURVE_B283;
    char *psx = "aa";
    char *psy = "aa";
    char *d = "aa";
    char *pix = NULL;
    char *piy = "aa";
    char *z = "aa";
    int hash_alg = ACVP_SHA256;
    
    kas_ecc_tc = calloc(1, sizeof(ACVP_KAS_ECC_TC));
    
    if (!initialize_kas_ecc_comp_tc(kas_ecc_tc, ACVP_KAS_ECC_TT_VAL, curve, hash_alg,
            psx, psy, d, pix, piy, z, corrupt)) {
        cr_assert_fail("kas ecc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ecc = kas_ecc_tc;
    
    rv = app_kas_ecc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ecc_tc(kas_ecc_tc);
    free(test_case);
}

/*
 * missing piy kas ecc comp handler
 */
Test(APP_KAS_ECC_HANDLER, missing_piy) {
    int corrupt = 0;
    int curve = ACVP_EC_CURVE_B283;
    char *psx = "aa";
    char *psy = "aa";
    char *d = "aa";
    char *pix = "aa";
    char *piy = NULL;
    char *z = "aa";
    int hash_alg = ACVP_SHA256;
    
    kas_ecc_tc = calloc(1, sizeof(ACVP_KAS_ECC_TC));
    
    if (!initialize_kas_ecc_comp_tc(kas_ecc_tc, ACVP_KAS_ECC_TT_VAL, curve, hash_alg,
            psx, psy, d, pix, piy, z, corrupt)) {
        cr_assert_fail("kas ecc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ecc = kas_ecc_tc;
    
    rv = app_kas_ecc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ecc_tc(kas_ecc_tc);
    free(test_case);
}

#endif // ACVP_NO_RUNTIME

