/** @file */
/*
 * Copyright (c) 2020, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "ut_common.h"
#include "acvp_lcl.h"

ACVP_CTX *ctx;
ACVP_TEST_CASE *test_case;
ACVP_SYM_CIPHER_TC *des_tc;
ACVP_RESULT rv;

int initialize_des_tc(ACVP_SYM_CIPHER_TC *des_tc, int alg_id, char *pt, 
                      int pt_len, char *ct, int ct_len, char *key, int key_len,
                      char *iv, int iv_len, ACVP_SYM_CIPH_DIR direction, 
                      ACVP_SYM_CIPH_TESTTYPE test_type) {

    des_tc->ct = calloc(ACVP_SYM_CT_BYTE_MAX, sizeof(char));
    if (!des_tc->ct) { return -1; }
    if (ct) {
        rv = acvp_hexstr_to_bin(ct, des_tc->ct, ACVP_SYM_CT_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (ct)");
            return -1;
        }
    }

    des_tc->pt = calloc(ACVP_SYM_PT_BYTE_MAX, sizeof(char));
    if (!des_tc->pt) { return -1; }
    if (pt) {
        rv = acvp_hexstr_to_bin(pt, des_tc->pt, ACVP_SYM_PT_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (pt)");
            return -1;
        }
    }

    des_tc->key = calloc(ACVP_SYM_KEY_MAX_BYTES, sizeof(char));
    if (!des_tc->key) { return -1; }
    if (key) {
        rv = acvp_hexstr_to_bin(key, des_tc->key, ACVP_SYM_KEY_MAX_BYTES, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (key)");
            return -1;
        }
    }

    des_tc->iv = calloc(ACVP_SYM_IV_BYTE_MAX, sizeof(char));
    if (!des_tc->iv) { return -1; }
    if (iv) {
        rv = acvp_hexstr_to_bin(iv, des_tc->iv, ACVP_SYM_IV_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (iv)");
            return -1;
        }
    }

    des_tc->iv_len = iv_len / 8;
    des_tc->direction = direction;
    des_tc->test_type = test_type;
    
    des_tc->pt_len = pt_len / 8;
    des_tc->ct_len = ct_len / 8;
    des_tc->key_len = key_len;
    des_tc->cipher = alg_id;
    des_tc->iv_ret = calloc(1, ACVP_SYM_IV_BYTE_MAX + 1);
    des_tc->iv_ret_after = calloc(1, ACVP_SYM_IV_BYTE_MAX + 1);
    if (!des_tc->iv_ret) return -1;
    if (!des_tc->iv_ret_after) return -1;

    return 1;
}

void free_des_tc(ACVP_SYM_CIPHER_TC *des_tc) {
    if (des_tc->pt) free(des_tc->pt);
    if (des_tc->ct) free(des_tc->ct);
    if (des_tc->key) free(des_tc->key);
    if (des_tc->iv) free(des_tc->iv);
    if (des_tc->iv_ret) free(des_tc->iv_ret);
    if (des_tc->iv_ret_after) free(des_tc->iv_ret_after);
    free(des_tc);
}

/*
 * bad keyLen
 */
Test(APP_DES_HANDLER, bad_keylen) {
    char *payload = "CAC0E8B7";
    char *key = "86FEBF763FD923F956FC8924D67C0DA4";
    char *iv = "B898A83C";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_des_tc(des_tc, ACVP_TDES_CBC, payload, 32, NULL, 0,
        key, 128, iv, 32, ACVP_SYM_CIPH_DIR_ENCRYPT, ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("des init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = des_tc;
    
    rv = app_des_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_des_tc(des_tc);
    free(test_case);
}

/*
 * Test case has bad direction
 */
Test(APP_DES_HANDLER, missing_dir) {
    char *payload = "39B0837B";
    char *key = "56392E22AE93E653DDB2F7CCEB1C5D713DDB2F7CCEB1C5D7";
    char *iv = "00000000";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_des_tc(des_tc, ACVP_TDES_ECB, payload, 32, NULL, 0,
        key, 192, iv, 32, 3, ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("des init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = des_tc;
    
    rv = app_des_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_des_tc(des_tc);
    free(test_case);
}


/*
 * bad payloadLen - undefined, ensure handled smoothly
 */
Test(APP_DES_HANDLER, bad_payload_len) {
    char *payload = "39B0837B";
    char *key = "56392E22AE93E653DDB2F7CCEB1C5D713DDB2F7CCEB1C5D7";
    char *iv = "00000000";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_des_tc(des_tc, ACVP_TDES_ECB, payload, 8, NULL, 0,
        key, 192, iv, 32, ACVP_SYM_CIPH_DIR_ENCRYPT, ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("des init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = des_tc;
    
    rv = app_des_handler(test_case);
    cr_assert_eq(rv, 0);
    
    free_des_tc(des_tc);
    free(test_case);
}

/*
 * Bad cipher
 */
 Test(APP_DES_HANDLER, bad_cipher) {
    char *payload = "C60A1E7BA59E16B3";
    char *key = "F304E382B538B832761576A307EBE5388D9628BBD53C5D37";
    char *iv = "A82CE52D";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));

    if (!initialize_des_tc(des_tc, ACVP_AES_CTR, payload, 64, NULL, 0,
        key, 192, iv, 32, ACVP_SYM_CIPH_DIR_ENCRYPT, ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("des init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = des_tc;
    
    rv = app_des_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_des_tc(des_tc);
    free(test_case);
}

/*
 * No memory allocated for iv_ret and iv_ret_after
 */
 Test(APP_DES_HANDLER, bad_tc_initialization) {
    char *payload = "C60A1E7BA59E16B3";
    char *key = "F304E382B538B832761576A307EBE5388D9628BBD53C5D37";
    char *iv = "A82CE52D";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));

    if (!initialize_des_tc(des_tc, ACVP_TDES_CFB64, payload, 64, NULL, 0,
        key, 192, iv, 32, ACVP_SYM_CIPH_DIR_ENCRYPT, ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("des init tc failure");
    }

    free(des_tc->iv_ret);
    des_tc->iv_ret = NULL;
    free(des_tc->iv_ret_after);
    des_tc->iv_ret_after = NULL;
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = des_tc;
    
    rv = app_des_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_des_tc(des_tc);
    free(test_case);
}

/*
 * test case object or subobject is null
 */
 Test(APP_DES_HANDLER, null_tc) {

    rv = app_des_handler(NULL);
    cr_assert_neq(rv, 0);
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    app_des_handler(test_case);
    cr_assert_neq(rv, 0);

    free(test_case);
}

/*
 * monte carlo bad direction 
 */
 Test(APP_DES_HANDLER, bad_mct_dir) {
    char *payload = "3308D695";
    char *key = "87683ACFBEDC23D25571352E6DA5C70E";
    char *iv = "5A20E1C02";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_des_tc(des_tc, ACVP_TDES_CFB8, NULL, 0, payload, 64,
        key, 192, iv, 32, 3, ACVP_SYM_TEST_TYPE_MCT)) {
        cr_assert_fail("des init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = des_tc;
    
    rv = app_des_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_des_tc(des_tc);
    free(test_case);
}


/*
 * monte carlo bad payload length - undefined behavior (?) ensure that it causes no issues with app
 */
 Test(APP_DES_HANDLER, bad_mct_payloadLen) {
    char *payload = "3ACA556E";
    char *key = "E0CD57A31C3206089EF0C07152B03249";
    char *iv = "5A20E1C025A20E1C02";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_des_tc(des_tc, ACVP_TDES_CFB1, NULL, 0, payload, 8,
        key, 192, iv, 64, ACVP_SYM_CIPH_DIR_DECRYPT, ACVP_SYM_TEST_TYPE_MCT)) {
        cr_assert_fail("des init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = des_tc;
    
    rv = app_des_handler(test_case);
    cr_assert_eq(rv, 0);
    //skip to last iteration to ensure end works normally as well
    des_tc->mct_index = 9999;
    rv = app_des_handler(test_case);
    cr_assert_eq(rv, 0);
    
    free_des_tc(des_tc);
    free(test_case);
}

/*
 * monte carlo without an IV - undefined behavior, ensure that it causes no issues with app
 */
 Test(APP_DES_HANDLER, bad_mct_iv) {
    char *payload = "3ACA556E";
    char *key = "E0CD57A31C3206089EF0C07152B03249";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_des_tc(des_tc, ACVP_TDES_CFB1, payload, 32, NULL, 0,
        key, 192, NULL, 0, ACVP_SYM_CIPH_DIR_ENCRYPT, ACVP_SYM_TEST_TYPE_MCT)) {
        cr_assert_fail("des init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = des_tc;
    
    rv = app_des_handler(test_case);
    cr_assert_eq(rv, 0);
    //skip to last iteration to ensure end works normally as well
    des_tc->mct_index = 9999;
    rv = app_des_handler(test_case);
    cr_assert_eq(rv, 0);
    
    free_des_tc(des_tc);
    free(test_case);
}
