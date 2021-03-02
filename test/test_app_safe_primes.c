/** @file */
/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#ifdef ACVP_NO_RUNTIME
#include "ut_common.h"
#include "app_common.h"
#include "acvp/acvp_lcl.h"
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#ifndef OPENSSL_NO_DSA

ACVP_CTX *ctx;
ACVP_TEST_CASE *test_case;
ACVP_SAFE_PRIMES_TC *safe_primes_tc;
ACVP_RESULT rv;

void free_safe_primes_tc(ACVP_SAFE_PRIMES_TC *stc) {
    if (stc->x) free(stc->x);
    if (stc->y) free(stc->y);
    free(stc);
}

int initialize_safe_primes_tc(ACVP_SAFE_PRIMES_TC *stc,
                          ACVP_CIPHER alg_id,
                          ACVP_SAFE_PRIMES_TEST_TYPE test_type,
                          ACVP_SAFE_PRIMES_PARAM dgm,
                          const char *x,
                          const char *y,
                          int result,
                          int corrupt) {
    ACVP_RESULT rv;
    
    stc->test_type = test_type;
    stc->cipher = alg_id;
    stc->result = result;
    
  if (stc->cipher == ACVP_SAFE_PRIMES_KEYGEN) {
    if (x) {
        stc->x = calloc(1, ACVP_SAFE_PRIMES_BYTE_MAX);
        if (!stc->x) { goto err; }
        rv = acvp_hexstr_to_bin(x, stc->x, ACVP_SAFE_PRIMES_BYTE_MAX, &(stc->xlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (x)");
            goto err;
        }
    }
    
    if (y) {
        stc->y = calloc(1, ACVP_SAFE_PRIMES_BYTE_MAX);
        if (!stc->y) { goto err; }
        rv = acvp_hexstr_to_bin(y, stc->y, ACVP_SAFE_PRIMES_BYTE_MAX, &(stc->ylen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (y)");
            goto err;
        }
    }
  }    
    if (stc->cipher == ACVP_SAFE_PRIMES_KEYVER) {
        if (!corrupt) {
            stc->y = calloc(1, ACVP_SAFE_PRIMES_BYTE_MAX);
            if (!stc->y) { goto err; }
            stc->x = calloc(1, ACVP_SAFE_PRIMES_BYTE_MAX);
            if (!stc->x) { goto err; }
        }
    }
    
    stc->dgm = dgm;
    return 1;
err:
    free_safe_primes_tc(stc);
    return 0;
}

/*
 * invalid dgm safe primes handler
 */
Test(APP_SAFE_PRIMES_HANDLER, invalid_dgm) {
    int corrupt = 0;
    char *x = "aa";
    char *y = "aa";
    
    safe_primes_tc = calloc(1, sizeof(ACVP_SAFE_PRIMES_TC));
    
    if (!initialize_safe_primes_tc(safe_primes_tc, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_TT_VAL, 0, x, y, 0, corrupt)) {
        cr_assert_fail("safe primes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.safe_primes = safe_primes_tc;
    
    rv = app_safe_primes_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_safe_primes_tc(safe_primes_tc);
    free(test_case);
}

/*
 * invalid alg_id safe primes handler
 */
Test(APP_SAFE_PRIMES_HANDLER, invalid_alg_id) {
    int corrupt = 0;
    char *x = "aa";
    char *y = "aa";
    
    safe_primes_tc = calloc(1, sizeof(ACVP_SAFE_PRIMES_TC));
    
    if (!initialize_safe_primes_tc(safe_primes_tc, ACVP_AES_CBC, ACVP_SAFE_PRIMES_TT_VAL, ACVP_SAFE_PRIMES_FFDHE2048, x, y, 0, corrupt)) {
        cr_assert_fail("safe primes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.safe_primes = safe_primes_tc;
    
    rv = app_safe_primes_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_safe_primes_tc(safe_primes_tc);
    free(test_case);
}


/*
 * unallocated answer buffers safe primes handler
 */
Test(APP_SAFE_PRIMES_HANDLER, unallocated_ans_bufs) {
    int corrupt = 1;
    char *x = "aa";
    char *y = "aa";
    
    safe_primes_tc = calloc(1, sizeof(ACVP_SAFE_PRIMES_TC));
    
    if (!initialize_safe_primes_tc(safe_primes_tc, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_TT_VAL, ACVP_SAFE_PRIMES_FFDHE2048, x, y, 0, corrupt)) {
        cr_assert_fail("safe primes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.safe_primes = safe_primes_tc;
    
    rv = app_safe_primes_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_safe_primes_tc(safe_primes_tc);
    free(test_case);
}

/*
 * No results from key verify
 */
Test(APP_SAFE_PRIMES_HANDLER, result) {
    int corrupt = 0;
    char *x = "aa";
    char *y = "aa";
    
    safe_primes_tc = calloc(1, sizeof(ACVP_SAFE_PRIMES_TC));
    
    if (!initialize_safe_primes_tc(safe_primes_tc, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_TT_VAL, ACVP_SAFE_PRIMES_FFDHE2048, x, y, 2, corrupt)) {
        cr_assert_fail("safe primes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.safe_primes = safe_primes_tc;
    
    rv = app_safe_primes_handler(test_case);
    cr_assert_neq(safe_primes_tc->result, 2);
    
    free_safe_primes_tc(safe_primes_tc);
    free(test_case);
}
#endif // OPENSSL_NO_DSA
#endif // OPENSSL VERSION
#endif // ACVP_NO_RUNTIME

