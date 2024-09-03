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
static ACVP_KDF108_TC *kdf108_tc;
static ACVP_RESULT rv;

void free_kdf108_tc(ACVP_KDF108_TC *stc) {
    if (stc->key_in) free(stc->key_in);
    if (stc->key_out) free(stc->key_out);
    if (stc->fixed_data) free(stc->fixed_data);
    if (stc->iv) free(stc->iv);
    free(stc);
}

/*
 * the corrupt variable indicates whether or not we want to
 * properly allocate memory for the answers that the client
 * application will populate
 */
int initialize_kdf108_tc(ACVP_KDF108_TC *stc,
                         ACVP_KDF108_MODE kdf_mode,
                         ACVP_KDF108_MAC_MODE_VAL mac_mode,
                         ACVP_KDF108_FIXED_DATA_ORDER_VAL counter_location,
                         const char *key_in,
                         const char *iv,
                         int key_in_len,
                         int key_out_len,
                         int iv_len,
                         int counter_len,
                         int deferred,
                         int corrupt) {
    ACVP_RESULT rv;
    
    memzero_s(stc, sizeof(ACVP_KDF108_TC));
    
    if (key_in) {
        // Allocate space for the key_in (binary)
        stc->key_in = calloc(key_in_len, sizeof(unsigned char));
        if (!stc->key_in) { goto err; }
    
        // Convert key_in from hex string to binary
        rv = acvp_hexstr_to_bin(key_in, stc->key_in, key_in_len, NULL);
        if (rv != ACVP_SUCCESS) goto err;
    }
    
    if (iv != NULL) {
        /*
         * Feedback mode.
         * Allocate space for the iv.
         */
        stc->iv = calloc(iv_len, sizeof(unsigned char));
        if (!stc->iv) { goto err; }
        
        // Convert iv from hex string to binary
        rv = acvp_hexstr_to_bin(iv, stc->iv, iv_len, NULL);
        if (rv != ACVP_SUCCESS) goto err;
    }
    
    if (!corrupt) {
        /*
         * Allocate space for the key_out
         * User supplies the data.
         */
        stc->key_out = calloc(key_out_len, sizeof(unsigned char));
        if (!stc->key_out) { goto err; }
    
        /*
         * Allocate space for the fixed_data.
         * User supplies the data.
         */
        stc->fixed_data = calloc(ACVP_KDF108_FIXED_DATA_BYTE_MAX,
                                 sizeof(unsigned char));
        if (!stc->fixed_data) { goto err; }
    }
    
    stc->cipher = ACVP_KDF108;
    stc->mode = kdf_mode;
    stc->mac_mode = mac_mode;
    stc->counter_location = counter_location;
    stc->key_in_len = key_in_len;
    stc->key_out_len = key_out_len;
    stc->counter_len = counter_len;
    stc->deferred = deferred;
    
    return 1;
    
    err:
    free_kdf108_tc(stc);
    return 0;
}

/*
 * invalid mode in kdf108 tc test case
 */
Test(APP_KDF108_HANDLER, invalid_mode) {
    /* arbitrary non-zero */
    int key_in_len = 8, key_out_len = 8, iv_len = 8, counter_len = 8;
    ACVP_KDF108_MODE kdf_mode = 0;
    ACVP_KDF108_MAC_MODE_VAL mac_mode = ACVP_KDF108_MAC_MODE_CMAC_AES128;
    ACVP_KDF108_FIXED_DATA_ORDER_VAL counter_location = ACVP_KDF108_FIXED_DATA_ORDER_AFTER;
    char *key_in = "aa";
    char *iv = "aa";
    int deferred = 0;
    int corrupt = 0;
    
    kdf108_tc = calloc(1, sizeof(ACVP_KDF108_TC));
    
    if (!initialize_kdf108_tc(kdf108_tc, kdf_mode, mac_mode, counter_location,
            key_in, iv, key_in_len, key_out_len, iv_len, counter_len,
            deferred, corrupt)) {
        cr_assert_fail("kdf108 init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf108 = kdf108_tc;
    
    rv = app_kdf108_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf108_tc(kdf108_tc);
    free(test_case);
}

/*
 * invalid mac mode in kdf108 tc test case
 */
Test(APP_KDF108_HANDLER, invalid_mac_mode) {
    /* arbitrary non-zero */
    int key_in_len = 8, key_out_len = 8, iv_len = 8, counter_len = 8;
    ACVP_KDF108_MODE kdf_mode = ACVP_KDF108_MODE_COUNTER;
    ACVP_KDF108_MAC_MODE_VAL mac_mode = 0;
    ACVP_KDF108_FIXED_DATA_ORDER_VAL counter_location = ACVP_KDF108_FIXED_DATA_ORDER_AFTER;
    char *key_in = "aa";
    char *iv = "aa";
    int deferred = 0;
    int corrupt = 0;
    
    kdf108_tc = calloc(1, sizeof(ACVP_KDF108_TC));
    
    if (!initialize_kdf108_tc(kdf108_tc, kdf_mode, mac_mode, counter_location,
            key_in, iv, key_in_len, key_out_len, iv_len, counter_len,
            deferred, corrupt)) {
        cr_assert_fail("kdf108 init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf108 = kdf108_tc;
    
    rv = app_kdf108_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf108_tc(kdf108_tc);
    free(test_case);
}

/*
 * invalid counter location (fixed data order) in kdf108 tc test case
 */
Test(APP_KDF108_HANDLER, invalid_counter_loc) {
    /* arbitrary non-zero */
    int key_in_len = 8, key_out_len = 8, iv_len = 8, counter_len = 8;
    ACVP_KDF108_MODE kdf_mode = ACVP_KDF108_MODE_COUNTER;
    ACVP_KDF108_MAC_MODE_VAL mac_mode = ACVP_KDF108_MAC_MODE_HMAC_SHA384;
    ACVP_KDF108_FIXED_DATA_ORDER_VAL counter_location = 0;
    char *key_in = "aa";
    char *iv = "aa";
    int deferred = 0;
    int corrupt = 0;
    
    kdf108_tc = calloc(1, sizeof(ACVP_KDF108_TC));
    
    if (!initialize_kdf108_tc(kdf108_tc, kdf_mode, mac_mode, counter_location,
            key_in, iv, key_in_len, key_out_len, iv_len, counter_len,
            deferred, corrupt)) {
        cr_assert_fail("kdf108 init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf108 = kdf108_tc;
    
    rv = app_kdf108_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf108_tc(kdf108_tc);
    free(test_case);
}

/*
 * missing key in in kdf108 tc test case
 */
Test(APP_KDF108_HANDLER, missing_key_in) {
    /* arbitrary non-zero */
    int key_in_len = 8, key_out_len = 8, iv_len = 8, counter_len = 8;
    ACVP_KDF108_MODE kdf_mode = ACVP_KDF108_MODE_COUNTER;
    ACVP_KDF108_MAC_MODE_VAL mac_mode = ACVP_KDF108_MAC_MODE_HMAC_SHA384;
    ACVP_KDF108_FIXED_DATA_ORDER_VAL counter_location = ACVP_KDF108_FIXED_DATA_ORDER_MIDDLE;
    char *key_in = NULL;
    char *iv = "aa";
    int deferred = 0;
    int corrupt = 0;
    
    kdf108_tc = calloc(1, sizeof(ACVP_KDF108_TC));
    
    if (!initialize_kdf108_tc(kdf108_tc, kdf_mode, mac_mode, counter_location,
            key_in, iv, key_in_len, key_out_len, iv_len, counter_len,
            deferred, corrupt)) {
        cr_assert_fail("kdf108 init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf108 = kdf108_tc;
    
    rv = app_kdf108_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf108_tc(kdf108_tc);
    free(test_case);
}


/*
 * unallocated answer buffers in kdf108 tc test case
 */
Test(APP_KDF108_HANDLER, unallocated_ans_bufs) {
    /* arbitrary non-zero */
    int key_in_len = 8, key_out_len = 8, iv_len = 8, counter_len = 8;
    ACVP_KDF108_MODE kdf_mode = ACVP_KDF108_MODE_COUNTER;
    ACVP_KDF108_MAC_MODE_VAL mac_mode = ACVP_KDF108_MAC_MODE_HMAC_SHA384;
    ACVP_KDF108_FIXED_DATA_ORDER_VAL counter_location = ACVP_KDF108_FIXED_DATA_ORDER_MIDDLE;
    char *key_in = "aa";
    char *iv = "aa";
    int deferred = 0;
    int corrupt = 1;
    
    kdf108_tc = calloc(1, sizeof(ACVP_KDF108_TC));
    
    if (!initialize_kdf108_tc(kdf108_tc, kdf_mode, mac_mode, counter_location,
            key_in, iv, key_in_len, key_out_len, iv_len, counter_len,
            deferred, corrupt)) {
        cr_assert_fail("kdf108 init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kdf108 = kdf108_tc;
    
    rv = app_kdf108_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kdf108_tc(kdf108_tc);
    free(test_case);
}
