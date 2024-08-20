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

#include "ut_common.h"
#include "app_common.h"
#include "iut_common.h"
#include "acvp/acvp_lcl.h"

static ACVP_TEST_CASE *test_case;
static ACVP_KDF_TLS13_TC *kdf_tls13_tc;
static ACVP_RESULT rv;

void free_kdf_tls13_tc(ACVP_KDF_TLS13_TC *stc) {
    if (stc->psk) free(stc->psk);
    if (stc->dhe) free(stc->dhe);
    if (stc->c_hello_rand) free(stc->c_hello_rand);
    if (stc->s_hello_rand) free(stc->s_hello_rand);
    if (stc->fin_c_hello_rand) free(stc->fin_c_hello_rand);
    if (stc->fin_s_hello_rand) free(stc->fin_s_hello_rand);
    if (stc->c_early_traffic_secret) free(stc->c_early_traffic_secret);
    if (stc->early_expt_master_secret) free(stc->early_expt_master_secret);
    if (stc->c_hs_traffic_secret) free(stc->c_hs_traffic_secret);
    if (stc->s_hs_traffic_secret) free(stc->s_hs_traffic_secret);
    if (stc->c_app_traffic_secret) free(stc->c_app_traffic_secret);
    if (stc->s_app_traffic_secret) free(stc->s_app_traffic_secret);
    if (stc->expt_master_secret) free(stc->expt_master_secret);
    if (stc->resume_master_secret) free(stc->resume_master_secret);
    free(stc);
}

/*
 * the corrupt variable indicates whether or not we want to
 * properly allocate memory for the answers that the client
 * application will populate
 */
int initialize_kdf_tls13_tc(ACVP_KDF_TLS13_TC *stc,
                            ACVP_KDF_TLS13_RUN_MODE run_mode,
                            ACVP_HASH_ALG hmac,
                            const char *psk,
                            const char *dhe,
                            const char *s_hello_rand,
                            const char *c_hello_rand,
                            const char *fin_s_hello_rand,
                            const char *fin_c_hello_rand,
                            int corrupt) {
    ACVP_RESULT rv;
    
    memzero_s(stc, sizeof(ACVP_KDF_TLS13_TC));
    
    if (psk) {
        stc->psk = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->psk) { goto err; }
        rv = acvp_hexstr_to_bin(psk, stc->psk, ACVP_KDF_TLS13_DATA_LEN_STR_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (psk)\n");
            goto err;
        }
    }
    
    if (dhe) {
        stc->dhe = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->dhe) { goto err; }
        rv = acvp_hexstr_to_bin(dhe, stc->dhe, ACVP_KDF_TLS13_DATA_LEN_STR_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (dhe)\n");
            goto err;
        }
    }
    
    if (s_hello_rand) {
        stc->s_hello_rand = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->s_hello_rand) { goto err; }
        rv = acvp_hexstr_to_bin(s_hello_rand, stc->s_hello_rand, ACVP_KDF_TLS13_DATA_LEN_STR_MAX, &(stc->s_hello_rand_len));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (s_hello_rand)\n");
            goto err;
        }
    }
    
    if (c_hello_rand) {
        stc->c_hello_rand = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->c_hello_rand) { goto err; }
        rv = acvp_hexstr_to_bin(c_hello_rand, stc->c_hello_rand, ACVP_KDF_TLS13_DATA_LEN_STR_MAX, &(stc->c_hello_rand_len));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (c_hello_rand)\n");
            goto err;
        }
    }
    
    if (fin_c_hello_rand) {
        stc->fin_c_hello_rand = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->fin_c_hello_rand) { goto err; }
        rv = acvp_hexstr_to_bin(fin_c_hello_rand, stc->fin_c_hello_rand, ACVP_KDF_TLS13_DATA_LEN_STR_MAX, &(stc->fin_c_hello_rand_len));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (fin_c_hello_rand)\n");
            goto err;
        }
    }
    
    if (fin_s_hello_rand) {
        stc->fin_s_hello_rand = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->fin_s_hello_rand) { goto err; }
        rv = acvp_hexstr_to_bin(fin_s_hello_rand, stc->fin_s_hello_rand, ACVP_KDF_TLS13_DATA_LEN_STR_MAX, &(stc->fin_s_hello_rand_len));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (fin_s_hello_rand)\n");
            goto err;
        }
    }
    
    if (!corrupt) {
        stc->c_early_traffic_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->c_early_traffic_secret) { goto err; }
        stc->early_expt_master_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->early_expt_master_secret) { goto err; }
        stc->c_hs_traffic_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->c_hs_traffic_secret) { goto err; }
        stc->s_hs_traffic_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->s_hs_traffic_secret) { goto err; }
        stc->c_app_traffic_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->c_app_traffic_secret) { goto err; }
        stc->s_app_traffic_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->s_app_traffic_secret) { goto err; }
        stc->expt_master_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->expt_master_secret) { goto err; }
        stc->resume_master_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
        if (!stc->resume_master_secret) { goto err; }
    }
    
    stc->cipher = ACVP_KDF_TLS13;
    if (psk) {
        stc->psk_len = strlen(psk) / 8;
    }
    if (dhe) {
        stc->dhe_len = strlen(dhe) / 8;
    }
    stc->running_mode = run_mode;
    stc->hmac_alg = hmac;
    
    return 1;
    
    err:
    free_kdf_tls13_tc(stc);
    return 0;
}

/*
 * invalid_runmode in kdf_tls13 tc test case
 */
Test(APP_TLS13_KDF_HANDLER, invalid_runmode1) {
    char *psk = "aa";
    char *dhe = "aa";
    char *s_hello_rand = "aa";
    char *c_hello_rand = "aa";
    char *fin_s_hello_rand = "aa";
    char *fin_c_hello_rand = "aa";
    ACVP_KDF_TLS13_RUN_MODE running_mode = ACVP_KDF_TLS13_RUN_MODE_MIN;
    int corrupt = 0;
    
    kdf_tls13_tc = calloc(1, sizeof(ACVP_KDF_TLS13_TC));
    
    if (!initialize_kdf_tls13_tc(kdf_tls13_tc, running_mode, ACVP_SHA256, psk, 
                                 dhe, s_hello_rand, c_hello_rand, 
                                 fin_s_hello_rand, fin_c_hello_rand, corrupt)) {
        cr_assert_fail("tls13 kdf init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls13 = kdf_tls13_tc;
    
    rv = app_kdf_tls13_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf_tls13_tc(kdf_tls13_tc);
    free(test_case);
}

/*
 * invalid_runmode in kdf_tls13 tc test case
 */
Test(APP_TLS13_KDF_HANDLER, invalid_runmode2) {
    char *psk = NULL;
    char *dhe = "aa";
    char *s_hello_rand = "aa";
    char *c_hello_rand = "aa";
    char *fin_s_hello_rand = "aa";
    char *fin_c_hello_rand = "aa";
    ACVP_KDF_TLS13_RUN_MODE running_mode = ACVP_KDF_TLS13_RUN_MODE_PSK;
    int corrupt = 0;
    
    kdf_tls13_tc = calloc(1, sizeof(ACVP_KDF_TLS13_TC));
    
    if (!initialize_kdf_tls13_tc(kdf_tls13_tc, running_mode, ACVP_SHA256, psk, 
                                 dhe, s_hello_rand, c_hello_rand, 
                                 fin_s_hello_rand, fin_c_hello_rand, corrupt)) {
        cr_assert_fail("tls13 kdf init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls13 = kdf_tls13_tc;
    
    rv = app_kdf_tls13_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf_tls13_tc(kdf_tls13_tc);
    free(test_case);
}

/*
 * invalid_runmode in kdf_tls13 tc test case
 */
Test(APP_TLS13_KDF_HANDLER, invalid_runmode3) {
    char *psk = "aa";
    char *dhe = "aa";
    char *s_hello_rand = "aa";
    char *c_hello_rand = "aa";
    char *fin_s_hello_rand = "aa";
    char *fin_c_hello_rand = "aa";
    ACVP_KDF_TLS13_RUN_MODE running_mode = ACVP_KDF_TLS13_RUN_MODE_DHE;
    int corrupt = 0;
    
    kdf_tls13_tc = calloc(1, sizeof(ACVP_KDF_TLS13_TC));
    
    if (!initialize_kdf_tls13_tc(kdf_tls13_tc, running_mode, ACVP_SHA256, psk, 
                                 dhe, s_hello_rand, c_hello_rand, 
                                 fin_s_hello_rand, fin_c_hello_rand, corrupt)) {
        cr_assert_fail("tls13 kdf init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls13 = kdf_tls13_tc;
    
    rv = app_kdf_tls13_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf_tls13_tc(kdf_tls13_tc);
    free(test_case);
}

/*
 * invalid_runmode in kdf_tls13 tc test case
 */
Test(APP_TLS13_KDF_HANDLER, invalid_runmode4) {
    char *psk = NULL;
    char *dhe = NULL;
    char *s_hello_rand = "aa";
    char *c_hello_rand = "aa";
    char *fin_s_hello_rand = "aa";
    char *fin_c_hello_rand = "aa";
    ACVP_KDF_TLS13_RUN_MODE running_mode = ACVP_KDF_TLS13_RUN_MODE_DHE;
    int corrupt = 0;
    
    kdf_tls13_tc = calloc(1, sizeof(ACVP_KDF_TLS13_TC));
    
    if (!initialize_kdf_tls13_tc(kdf_tls13_tc, running_mode, ACVP_SHA256, psk, 
                                 dhe, s_hello_rand, c_hello_rand, 
                                 fin_s_hello_rand, fin_c_hello_rand, corrupt)) {
        cr_assert_fail("tls13 kdf init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls13 = kdf_tls13_tc;
    
    rv = app_kdf_tls13_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf_tls13_tc(kdf_tls13_tc);
    free(test_case);
}

/*
 * invalid hash alg in kdf_tls13 tc test case
 */
Test(APP_TLS13_KDF_HANDLER, invalid_hash_alg) {

    char *psk = "aa";
    char *dhe = "aa";
    char *s_hello_rand = "aa";
    char *c_hello_rand = "aa";
    char *fin_s_hello_rand = "aa";
    char *fin_c_hello_rand = "aa";
    ACVP_KDF_TLS13_RUN_MODE running_mode = ACVP_KDF_TLS13_RUN_MODE_PSK_DHE;
    int corrupt = 0;
    
    kdf_tls13_tc = calloc(1, sizeof(ACVP_KDF_TLS13_TC));
    
    if (!initialize_kdf_tls13_tc(kdf_tls13_tc, running_mode, ACVP_SHA512, psk, 
                                 dhe, s_hello_rand, c_hello_rand, 
                                 fin_s_hello_rand, fin_c_hello_rand, corrupt)) {
        cr_assert_fail("tls13 kdf init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls13 = kdf_tls13_tc;
    
    rv = app_kdf_tls13_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf_tls13_tc(kdf_tls13_tc);
    free(test_case);
}

/*
 * missing_psk in kdf_tls13 tc test case
 */
Test(APP_TLS13_KDF_HANDLER, missing_psk) {
    
    char *psk = NULL;
    char *dhe = "aa";
    char *s_hello_rand = "aa";
    char *c_hello_rand = "aa";
    char *fin_s_hello_rand = "aa";
    char *fin_c_hello_rand = "aa";
    ACVP_KDF_TLS13_RUN_MODE running_mode = ACVP_KDF_TLS13_RUN_MODE_PSK_DHE;
    int corrupt = 0;
    
    kdf_tls13_tc = calloc(1, sizeof(ACVP_KDF_TLS13_TC));
    
    if (!initialize_kdf_tls13_tc(kdf_tls13_tc, running_mode, ACVP_SHA256, psk, 
                                 dhe, s_hello_rand, c_hello_rand, 
                                 fin_s_hello_rand, fin_c_hello_rand, corrupt)) {
        cr_assert_fail("tls13 kdf init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls13 = kdf_tls13_tc;
    
    rv = app_kdf_tls13_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf_tls13_tc(kdf_tls13_tc);
    free(test_case);
}

/*
 * missing_s_hello_rand in kdf_tls13 tc test case
 */
Test(APP_TLS13_KDF_HANDLER, missing_s_hello_rand) {

    char *psk = "aa";
    char *dhe = "aa";
    char *s_hello_rand = NULL;
    char *c_hello_rand = "aa";
    char *fin_s_hello_rand = "aa";
    char *fin_c_hello_rand = "aa";
    ACVP_KDF_TLS13_RUN_MODE running_mode = ACVP_KDF_TLS13_RUN_MODE_PSK_DHE;
    int corrupt = 0;
    
    kdf_tls13_tc = calloc(1, sizeof(ACVP_KDF_TLS13_TC));
    
    if (!initialize_kdf_tls13_tc(kdf_tls13_tc, running_mode, ACVP_SHA256, psk, 
                                 dhe, s_hello_rand, c_hello_rand, 
                                 fin_s_hello_rand, fin_c_hello_rand, corrupt)) {
        cr_assert_fail("tls13 kdf init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls13 = kdf_tls13_tc;
    
    rv = app_kdf_tls13_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf_tls13_tc(kdf_tls13_tc);
    free(test_case);
}

/*
 * missing_c_hello_rand in kdf_tls13 tc test case
 */
Test(APP_TLS13_KDF_HANDLER, missing_c_hello_rand) {
    
    char *psk = "aa";
    char *dhe = "aa";
    char *s_hello_rand = "aa";
    char *c_hello_rand = NULL;
    char *fin_s_hello_rand = "aa";
    char *fin_c_hello_rand = "aa";
    ACVP_KDF_TLS13_RUN_MODE running_mode = ACVP_KDF_TLS13_RUN_MODE_PSK_DHE;
    int corrupt = 0;
    
    kdf_tls13_tc = calloc(1, sizeof(ACVP_KDF_TLS13_TC));
    
    if (!initialize_kdf_tls13_tc(kdf_tls13_tc, running_mode, ACVP_SHA256, psk, 
                                 dhe, s_hello_rand, c_hello_rand, 
                                 fin_s_hello_rand, fin_c_hello_rand, corrupt)) {
        cr_assert_fail("tls13 kdf init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls13 = kdf_tls13_tc;
    
    rv = app_kdf_tls13_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf_tls13_tc(kdf_tls13_tc);
    free(test_case);
}

/*
 * missing_fin_c_hello_rand in kdf_tls13 tc test case
 */
Test(APP_TLS13_KDF_HANDLER, missing_fin_c_hello_rand) {
    
    char *psk = "aa";
    char *dhe = "aa";
    char *s_hello_rand = "aa";
    char *c_hello_rand = "aa";
    char *fin_s_hello_rand = "aa";
    char *fin_c_hello_rand = NULL;
    ACVP_KDF_TLS13_RUN_MODE running_mode = ACVP_KDF_TLS13_RUN_MODE_PSK_DHE;
    int corrupt = 0;
    
    kdf_tls13_tc = calloc(1, sizeof(ACVP_KDF_TLS13_TC));
    
    if (!initialize_kdf_tls13_tc(kdf_tls13_tc, running_mode, ACVP_SHA256, psk, 
                                 dhe, s_hello_rand, c_hello_rand, 
                                 fin_s_hello_rand, fin_c_hello_rand, corrupt)) {
        cr_assert_fail("tls13 kdf init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls13 = kdf_tls13_tc;
    
    rv = app_kdf_tls13_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf_tls13_tc(kdf_tls13_tc);
    free(test_case);
}

/*
 * missing_fin_s_hello_rand in kdf_tls13 tc test case
 */
Test(APP_TLS13_KDF_HANDLER, missing_fin_s_hello_rand) {

    char *psk = "aa";
    char *dhe = "aa";
    char *s_hello_rand = "aa";
    char *c_hello_rand = "aa";
    char *fin_s_hello_rand = NULL;
    char *fin_c_hello_rand = "aa";
    ACVP_KDF_TLS13_RUN_MODE running_mode = ACVP_KDF_TLS13_RUN_MODE_PSK_DHE;
    int corrupt = 0;
    
    kdf_tls13_tc = calloc(1, sizeof(ACVP_KDF_TLS13_TC));
    
    if (!initialize_kdf_tls13_tc(kdf_tls13_tc, running_mode, ACVP_SHA256, psk, 
                                 dhe, s_hello_rand, c_hello_rand, 
                                 fin_s_hello_rand, fin_c_hello_rand, corrupt)) {
        cr_assert_fail("tls13 kdf init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls13 = kdf_tls13_tc;
    
    rv = app_kdf_tls13_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf_tls13_tc(kdf_tls13_tc);
    free(test_case);
}

/*
 * unallocated answer buffers in kdf_tls13 tc test case
 */
Test(APP_TLS13_KDF_HANDLER, unallocated_ans_bufs) {

    char *psk = "aa";
    char *dhe = "aa";
    char *s_hello_rand = "aa";
    char *c_hello_rand = "aa";
    char *fin_s_hello_rand = "aa";
    char *fin_c_hello_rand = "aa";
    ACVP_KDF_TLS13_RUN_MODE running_mode = ACVP_KDF_TLS13_RUN_MODE_PSK_DHE;
    int corrupt = 1;
    
    kdf_tls13_tc = calloc(1, sizeof(ACVP_KDF_TLS13_TC));
    
    if (!initialize_kdf_tls13_tc(kdf_tls13_tc, running_mode, ACVP_SHA256, psk, 
                                 dhe, s_hello_rand, c_hello_rand, 
                                 fin_s_hello_rand, fin_c_hello_rand, corrupt)) {
        cr_assert_fail("tls13 kdf init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf_tls13 = kdf_tls13_tc;
    
    rv = app_kdf_tls13_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf_tls13_tc(kdf_tls13_tc);
    free(test_case);
}
