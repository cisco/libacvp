/** @file */
/*
 * Copyright (c) 2020, Cisco Systems, Inc.
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
#include "acvp/acvp.h"

ACVP_CTX *ctx;
ACVP_TEST_CASE *test_case;
ACVP_CMAC_TC *cmac_tc;
ACVP_RESULT rv;

int initialize_cmac_tc(ACVP_CMAC_TC *cmac_tc,
                       int alg_id, char *mac,
                       char *msg, int msg_len,
                       char *key, int key_len,
                       char *key2, char *key3,
                       int direction_verify, int corrupt) {
    memset(cmac_tc, 0x0, sizeof(ACVP_CMAC_TC));
    
    if (!corrupt) {
        cmac_tc->mac = calloc(1, ACVP_CMAC_MACLEN_MAX);
        if (!cmac_tc->mac) { return -1; }
    }
    if (direction_verify) {
        cmac_tc->verify = 1;
    
        rv = acvp_hexstr_to_bin(mac, cmac_tc->mac, ACVP_CMAC_MACLEN_MAX, (int *)&(cmac_tc->mac_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (mac)");
            return rv;
        }
    }
    
    if (msg) {
        cmac_tc->msg = calloc(1, ACVP_CMAC_MSGLEN_MAX_STR);
        if (!cmac_tc->msg) { return -1; }
        rv = acvp_hexstr_to_bin(msg, cmac_tc->msg, ACVP_CMAC_MSGLEN_MAX_STR, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (msg)");
            return -1;
        }
    }
    
    if (alg_id == ACVP_CMAC_AES) {
        if (key) {
            cmac_tc->key = calloc(1, ACVP_CMAC_KEY_MAX);
            if (!cmac_tc->key) { return ACVP_MALLOC_FAIL; }
            rv = acvp_hexstr_to_bin(key, cmac_tc->key, ACVP_CMAC_KEY_MAX, (int *) &(cmac_tc->key_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex converstion failure (key)");
                return rv;
            }
        }
    } else if (alg_id == ACVP_CMAC_TDES) {
        if (key) {
            cmac_tc->key = calloc(1, ACVP_CMAC_KEY_MAX);
            if (!cmac_tc->key) { return ACVP_MALLOC_FAIL; }
            rv = acvp_hexstr_to_bin(key, cmac_tc->key, ACVP_CMAC_KEY_MAX, NULL);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex converstion failure (key1)");
                return rv;
            }
        }
        if (key2) {
            cmac_tc->key2 = calloc(1, ACVP_CMAC_KEY_MAX);
            if (!cmac_tc->key2) { return ACVP_MALLOC_FAIL; }
            rv = acvp_hexstr_to_bin(key2, cmac_tc->key2, ACVP_CMAC_KEY_MAX, NULL);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex converstion failure (key2)");
                return rv;
            }
        }
        if (key3) {
            cmac_tc->key3 = calloc(1, ACVP_CMAC_KEY_MAX);
            if (!cmac_tc->key3) { return ACVP_MALLOC_FAIL; }
            rv = acvp_hexstr_to_bin(key3, cmac_tc->key3, ACVP_CMAC_KEY_MAX, NULL);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex converstion failure (key3)");
                return rv;
            }
        }
    }
    
    cmac_tc->msg_len = msg_len;
    cmac_tc->cipher = alg_id;
    
    return 1;
}

void free_cmac_tc(ACVP_CMAC_TC *cmac_tc) {
    if (cmac_tc->msg) free(cmac_tc->msg);
    if (cmac_tc->mac) free(cmac_tc->mac);
    if (cmac_tc->key) free(cmac_tc->key);
    if (cmac_tc->key2) free(cmac_tc->key2);
    if (cmac_tc->key3) free(cmac_tc->key3);
    memset(cmac_tc, 0x0, sizeof(ACVP_CMAC_TC));
}

/*
 * missing msg in cmac tc test case
 */
Test(APP_CMAC_HANDLER, missing_msg) {
    char *msg = NULL;
    char *key = "aaaa";
    cmac_tc = calloc(1, sizeof(ACVP_CMAC_TC));
    
    if (!initialize_cmac_tc(cmac_tc, ACVP_CMAC_AES, NULL, msg, 8, key, 16, NULL, NULL, 0, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.cmac = cmac_tc;
    
    rv = app_cmac_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_cmac_tc(cmac_tc);
    free(cmac_tc);
    free(test_case);
}

/*
 * missing key in cmac tc test case
 */
Test(APP_CMAC_HANDLER, missing_key_aes) {
    char *msg = "aaaa";
    char *key = NULL;
    cmac_tc = calloc(1, sizeof(ACVP_CMAC_TC));

    if (!initialize_cmac_tc(cmac_tc, ACVP_CMAC_AES, NULL, msg, 8, key, 16, NULL, NULL, 0, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.cmac = cmac_tc;
    
    rv = app_cmac_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_cmac_tc(cmac_tc);
    free(cmac_tc);
    free(test_case);
}

/*
 * missing key in cmac tc test case
 */
Test(APP_CMAC_HANDLER, missing_keys_tdes) {
    char *msg = "aaaa";
    char *key = NULL;
    cmac_tc = calloc(1, sizeof(ACVP_CMAC_TC));
    
    if (!initialize_cmac_tc(cmac_tc, ACVP_CMAC_TDES, NULL, msg, 8, key, 16, NULL, NULL, 0, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.cmac = cmac_tc;
    
    rv = app_cmac_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_cmac_tc(cmac_tc);
    free(cmac_tc);
    free(test_case);
}

/*
 * the pointer for mac should be allocated
 * by the library. here we don't allocate it and test
 * to see if the handler gracefully handles it
 */
Test(APP_CMAC_HANDLER, disposition_mem_not_allocated) {
    char key[] = "aaaa";
    char msg[] = "AA";
    cmac_tc = calloc(1, sizeof(ACVP_CMAC_TC));

    if (!initialize_cmac_tc(cmac_tc, ACVP_CMAC_AES, NULL, msg, 8, key, 16, NULL, NULL, 0, 1)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.cmac = cmac_tc;

    rv = app_cmac_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_cmac_tc(cmac_tc);
    free(cmac_tc);
    free(test_case);
}

