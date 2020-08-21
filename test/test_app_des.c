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
#include "app_common.h"
#include "acvp/acvp_lcl.h"

ACVP_CTX *ctx;
ACVP_TEST_CASE *test_case;
ACVP_SYM_CIPHER_TC *des_tc;
ACVP_RESULT rv;

int initialize_des_tc(ACVP_SYM_CIPHER_TC *des_tc, int alg_id, char *pt, 
                      int pt_len, char *ct, int ct_len, char *key, int key_len,
                      char *iv, int iv_len, ACVP_SYM_CIPH_DIR direction, 
                      ACVP_SYM_CIPH_TESTTYPE test_type) {

    des_tc->ct = calloc(ACVP_SYM_CT_BYTE_MAX, sizeof(char));
    if (!des_tc->ct) { return 0; }
    if (ct) {
        rv = acvp_hexstr_to_bin(ct, des_tc->ct, ACVP_SYM_CT_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (ct)");
            return 0;
        }
    }

    des_tc->pt = calloc(ACVP_SYM_PT_BYTE_MAX, sizeof(char));
    if (!des_tc->pt) { return -1; }
    if (pt) {
        rv = acvp_hexstr_to_bin(pt, des_tc->pt, ACVP_SYM_PT_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (pt)");
            return 0;
        }
    }
    des_tc->key = calloc(ACVP_SYM_KEY_MAX_BYTES, sizeof(char));
    if (!des_tc->key) { return -1; }
    if (key) {
        rv = acvp_hexstr_to_bin(key, des_tc->key, ACVP_SYM_KEY_MAX_BYTES, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (key)");
            return 0;
        }
    }
    des_tc->iv = calloc(ACVP_SYM_IV_BYTE_MAX, sizeof(char));
    if (!des_tc->iv) { return 0; }
    if (iv) {
        rv = acvp_hexstr_to_bin(iv, des_tc->iv, ACVP_SYM_IV_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (iv)");
            return 0;
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
    if (!des_tc->iv_ret) return 0;
    if (!des_tc->iv_ret_after) return 0;

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
 * bad key/keyLen
 */
Test(APP_DES_HANDLER, bad_keylen) {
    char *payload = "CAC0E8B7";
    char *key = "FFF1E477CB35AC73BD9E840DE7C63E40B62F15A5F47A";
    char *iv = "9BEEC63270842C93";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));

    if (!initialize_des_tc(des_tc, ACVP_TDES_CBC, payload, 32, NULL, 0,
        key, 128, iv, 64, ACVP_SYM_CIPH_DIR_ENCRYPT, ACVP_SYM_TEST_TYPE_AFT)) {
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
 * bad iv/len, undefined behavior, ensure no issues
 */
Test(APP_DES_HANDLER, bad_iv) {
    char *payload = "5D6B98F55782F9EB";
    char *key = "70BA2E58F1858D86CD27A9B42D0E87718F2BD0887FFB0325";
    char *iv = "9BEECC93";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));

    if (!initialize_des_tc(des_tc, ACVP_TDES_CBC, payload, 64, NULL, 0,
        key, 192, iv, 4, ACVP_SYM_CIPH_DIR_ENCRYPT, ACVP_SYM_TEST_TYPE_AFT)) {
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
 * Test case has bad direction
 */
Test(APP_DES_HANDLER, missing_dir) {
    char *payload = "39B0837B";
    char *key = "56392E22AE93E653DDB2F7CCEB1C5D713DDB2F7CCEB1C5D7";
    char *iv = "BE241A16F19692D5";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));

    if (!initialize_des_tc(des_tc, ACVP_TDES_ECB, payload, 32, NULL, 0,
        key, 192, iv, 64, 3, ACVP_SYM_TEST_TYPE_AFT)) {
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
    char *payload = "8A20D2";
    char *key = "56392E22AE93E653DDB2F7CCEB1C5D713DDB2F7CCEB1C5D7";
    char *iv = "17B952D703CFD3DC";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));

    if (!initialize_des_tc(des_tc, ACVP_TDES_ECB, NULL, 0, payload, 8,
        key, 192, iv, 64, ACVP_SYM_CIPH_DIR_DECRYPT, ACVP_SYM_TEST_TYPE_AFT)) {
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
    char *iv = "9127AC08DB3F1EBB";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));

    if (!initialize_des_tc(des_tc, ACVP_AES_CTR, payload, 64, NULL, 0,
        key, 192, iv, 64, ACVP_SYM_CIPH_DIR_ENCRYPT, ACVP_SYM_TEST_TYPE_AFT)) {
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
    char *key = "8B189E165BBEBE4CEDB6D0B7101E7BD84877932D6B4E2B80";
    char *iv = "9127AC08DB3F1EBB";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));

    if (!initialize_des_tc(des_tc, ACVP_TDES_CFB64, payload, 64, NULL, 0,
        key, 192, iv, 64, ACVP_SYM_CIPH_DIR_ENCRYPT, ACVP_SYM_TEST_TYPE_AFT)) {
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
    char *key = "BBC602235FDF2445FBA3D87426D5F20BF5F9914C9E75663C";
    char *iv = "0C5B368F1CD7583D";
    des_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));

    if (!initialize_des_tc(des_tc, ACVP_TDES_CFB1, NULL, 0, payload, 64,
        key, 192, iv, 64, 3, ACVP_SYM_TEST_TYPE_MCT)) {
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
    char *payload = "3ACA6E";
    char *key = "F0A24926D420F06356D40613DE5229DCE0F0A9255258D797";
    char *iv = "5A20E1C025A20E1C";
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
    char *key = "B592704C5E2D6EEF442D0C249D290BB8F67AA14A21685186";
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
