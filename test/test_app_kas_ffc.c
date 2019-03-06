/** @file */
/*****************************************************************************
* Copyright (c) 2019, Cisco Systems, Inc.
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

#ifdef ACVP_NO_RUNTIME

#include "ut_common.h"
#include "acvp_lcl.h"

ACVP_CTX *ctx;
ACVP_TEST_CASE *test_case;
ACVP_KAS_FFC_TC *kas_ffc_tc;
ACVP_RESULT rv;

void free_kas_ffc_tc(ACVP_KAS_FFC_TC *stc) {
    if (stc->piut) free(stc->piut);
    if (stc->epri) free(stc->epri);
    if (stc->epui) free(stc->epui);
    if (stc->eps) free(stc->eps);
    if (stc->z) free(stc->z);
    if (stc->chash) free(stc->chash);
    if (stc->p) free(stc->p);
    if (stc->q) free(stc->q);
    if (stc->g) free(stc->g);
    memzero_s(stc, sizeof(ACVP_KAS_FFC_TC));
}

int initialize_kas_ffc_tc(ACVP_KAS_FFC_TC *stc,
                          ACVP_HASH_ALG hash_alg,
                          int test_type,
                          const char *p,
                          const char *q,
                          const char *g,
                          const char *eps,
                          const char *epri,
                          const char *epui,
                          const char *z,
                          int corrupt) {
    ACVP_RESULT rv;
    
    stc->mode = ACVP_KAS_FFC_MODE_COMPONENT;
    stc->md = hash_alg;
    stc->test_type = test_type;
    
    if (p) {
        stc->p = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
        if (!stc->p) { goto err; }
        rv = acvp_hexstr_to_bin(p, stc->p, ACVP_KAS_FFC_BYTE_MAX, &(stc->plen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (p)");
            goto err;
        }
    }
    
    if (q) {
        stc->q = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
        if (!stc->q) { goto err; }
        rv = acvp_hexstr_to_bin(q, stc->q, ACVP_KAS_FFC_BYTE_MAX, &(stc->qlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (q)");
            goto err;
        }
    }
    
    if (g) {
        stc->g = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
        if (!stc->g) { goto err; }
        rv = acvp_hexstr_to_bin(g, stc->g, ACVP_KAS_FFC_BYTE_MAX, &(stc->glen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (g)");
            goto err;
        }
    }
    
    if (eps) {
        stc->eps = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
        if (!stc->eps) { goto err; }
        rv = acvp_hexstr_to_bin(eps, stc->eps, ACVP_KAS_FFC_BYTE_MAX, &(stc->epslen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (eps)");
            goto err;
        }
    }
    
    if (!corrupt) {
        stc->chash = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
        if (!stc->chash) { goto err; }
        stc->piut = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
        if (!stc->piut) { goto err; }
    }
    
    if (stc->test_type == ACVP_KAS_FFC_TT_VAL) {
        if (z) {
            stc->z = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
            if (!stc->z) { goto err; }
            rv = acvp_hexstr_to_bin(z, stc->z, ACVP_KAS_FFC_BYTE_MAX, &(stc->zlen));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (z)");
                goto err;
            }
        }
        
        if (epri) {
            stc->epri = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
            if (!stc->epri) { goto err; }
            rv = acvp_hexstr_to_bin(epri, stc->epri, ACVP_KAS_FFC_BYTE_MAX, &(stc->eprilen));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (epri)");
                goto err;
            }
        }
        
        if (epui) {
            stc->epui = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
            if (!stc->epui) { goto err; }
            rv = acvp_hexstr_to_bin(epui, stc->epui, ACVP_KAS_FFC_BYTE_MAX, &(stc->epuilen));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (epui)");
                goto err;
            }
        }
    } else if (!corrupt) {
        stc->z = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
        if (!stc->z) { goto err; }
        stc->epri = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
        if (!stc->epri) { goto err; }
        stc->epui = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
        if (!stc->epui) { goto err; }
    }
    
    return 1;
    
    err:
    free_kas_ffc_tc(stc);
    return 0;
}

/*
 * invalid hash alg kas ffc handler
 */
Test(APP_KAS_FFC_HANDLER, invalid_hash_alg) {
    int corrupt = 0;
    int hash_alg = 0;
    char *p = "aa";
    char *q = "aa";
    char *g = "aa";
    char *ps = "aa";
    char *epri = "aa";
    char *epui = "aa";
    char *z = "aa";
    
    kas_ffc_tc = calloc(1, sizeof(ACVP_KAS_FFC_TC));
    
    if (!initialize_kas_ffc_tc(kas_ffc_tc, hash_alg, ACVP_KAS_FFC_TT_VAL, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ffc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ffc = kas_ffc_tc;
    
    rv = app_kas_ffc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ffc_tc(kas_ffc_tc);
}

/*
 * missing p kas ffc handler
 */
Test(APP_KAS_FFC_HANDLER, missing_p) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA384;
    char *p = NULL;
    char *q = "aa";
    char *g = "aa";
    char *ps = "aa";
    char *epri = "aa";
    char *epui = "aa";
    char *z = "aa";
    
    kas_ffc_tc = calloc(1, sizeof(ACVP_KAS_FFC_TC));
    
    if (!initialize_kas_ffc_tc(kas_ffc_tc, hash_alg, ACVP_KAS_FFC_TT_VAL, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ffc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ffc = kas_ffc_tc;
    
    rv = app_kas_ffc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ffc_tc(kas_ffc_tc);
}

/*
 * missing q kas ffc handler
 */
Test(APP_KAS_FFC_HANDLER, missing_q) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA384;
    char *p = "aa";
    char *q = NULL;
    char *g = "aa";
    char *ps = "aa";
    char *epri = "aa";
    char *epui = "aa";
    char *z = "aa";
    
    kas_ffc_tc = calloc(1, sizeof(ACVP_KAS_FFC_TC));
    
    if (!initialize_kas_ffc_tc(kas_ffc_tc, hash_alg, ACVP_KAS_FFC_TT_VAL, p, q, g,
            ps, epri, epui, z, corrupt)) {
    cr_assert_fail("kas ffc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ffc = kas_ffc_tc;
    
    rv = app_kas_ffc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ffc_tc(kas_ffc_tc);
}

/*
 * missing g kas ffc handler
 */
Test(APP_KAS_FFC_HANDLER, missing_g) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA384;
    char *p = "aa";
    char *q = "aa";
    char *g = NULL;
    char *ps = "aa";
    char *epri = "aa";
    char *epui = "aa";
    char *z = "aa";
    
    kas_ffc_tc = calloc(1, sizeof(ACVP_KAS_FFC_TC));
    
    if (!initialize_kas_ffc_tc(kas_ffc_tc, hash_alg, ACVP_KAS_FFC_TT_VAL, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ffc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ffc = kas_ffc_tc;
    
    rv = app_kas_ffc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ffc_tc(kas_ffc_tc);
}

/*
 * missing eps kas ffc handler
 */
Test(APP_KAS_FFC_HANDLER, missing_eps) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA384;
    char *p = "aa";
    char *q = "aa";
    char *g = "aa";
    char *ps = NULL;
    char *epri = "aa";
    char *epui = "aa";
    char *z = "aa";
    
    kas_ffc_tc = calloc(1, sizeof(ACVP_KAS_FFC_TC));
    
    if (!initialize_kas_ffc_tc(kas_ffc_tc, hash_alg, ACVP_KAS_FFC_TT_VAL, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ffc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ffc = kas_ffc_tc;
    
    rv = app_kas_ffc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ffc_tc(kas_ffc_tc);
}

/*
 * missing epri kas ffc handler
 */
Test(APP_KAS_FFC_HANDLER, missing_epri) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA384;
    char *p = "aa";
    char *q = "aa";
    char *g = "aa";
    char *ps = "aa";
    char *epri = NULL;
    char *epui = "aa";
    char *z = "aa";
    
    kas_ffc_tc = calloc(1, sizeof(ACVP_KAS_FFC_TC));
    
    if (!initialize_kas_ffc_tc(kas_ffc_tc, hash_alg, ACVP_KAS_FFC_TT_VAL, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ffc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ffc = kas_ffc_tc;
    
    rv = app_kas_ffc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ffc_tc(kas_ffc_tc);
}

/*
 * missing epui kas ffc handler
 */
Test(APP_KAS_FFC_HANDLER, missing_epui) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA384;
    char *p = "aa";
    char *q = "aa";
    char *g = "aa";
    char *ps = "aa";
    char *epri = "aa";
    char *epui = NULL;
    char *z = "aa";
    
    kas_ffc_tc = calloc(1, sizeof(ACVP_KAS_FFC_TC));
    
    if (!initialize_kas_ffc_tc(kas_ffc_tc, hash_alg, ACVP_KAS_FFC_TT_VAL, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ffc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ffc = kas_ffc_tc;
    
    rv = app_kas_ffc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ffc_tc(kas_ffc_tc);
}

/*
 * missing z kas ffc handler
 * only valid for AFT test types
 */
Test(APP_KAS_FFC_HANDLER, missing_z) {
    int corrupt = 0;
    int hash_alg = ACVP_SHA384;
    char *p = "aa";
    char *q = "aa";
    char *g = "aa";
    char *ps = "aa";
    char *epri = "aa";
    char *epui = "aa";
    char *z = NULL;
    
    kas_ffc_tc = calloc(1, sizeof(ACVP_KAS_FFC_TC));
    
    if (!initialize_kas_ffc_tc(kas_ffc_tc, hash_alg, ACVP_KAS_ECC_TT_AFT, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ffc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ffc = kas_ffc_tc;
    
    rv = app_kas_ffc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ffc_tc(kas_ffc_tc);
}

/*
 * unallocated answer buffers kas ffc handler
 */
Test(APP_KAS_FFC_HANDLER, unallocated_ans_bufs) {
    int corrupt = 1;
    int hash_alg = ACVP_SHA384;
    char *p = "aa";
    char *q = "aa";
    char *g = "aa";
    char *ps = "aa";
    char *epri = "aa";
    char *epui = "aa";
    char *z = "aa";
    
    kas_ffc_tc = calloc(1, sizeof(ACVP_KAS_FFC_TC));
    
    if (!initialize_kas_ffc_tc(kas_ffc_tc, hash_alg, ACVP_KAS_FFC_TT_VAL, p, q, g,
            ps, epri, epui, z, corrupt)) {
        cr_assert_fail("kas ffc init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kas_ffc = kas_ffc_tc;
    
    rv = app_kas_ffc_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kas_ffc_tc(kas_ffc_tc);
}

#endif // ACVP_NO_RUNTIME

