/** @file */
/*
 * Copyright (c) 2023, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "ut_common.h"
#include "app_common.h"
#include "acvp/acvp_lcl.h"
#include "acvp/acvp.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

ACVP_CTX *ctx;
ACVP_TEST_CASE *test_case;
ACVP_KMAC_TC *kmac_tc;
ACVP_RESULT rv;

int initialize_kmac_tc(ACVP_KMAC_TC *kmac_tc, int alg_id, ACVP_KMAC_TESTTYPE type,
                       int xof, int custom_is_hex, char *mac, int mac_len, char *msg, char *key,
                       char *custom, int corrupt) {

    kmac_tc->cipher = alg_id;
    kmac_tc->test_type = type;

    if (corrupt != 1) {
        kmac_tc->mac = calloc(1, ACVP_KMAC_MAC_BYTE_MAX);
        if (!kmac_tc->mac) { return ACVP_MALLOC_FAIL; }
        if (mac) {
            rv = acvp_hexstr_to_bin(mac, kmac_tc->mac, ACVP_KMAC_MAC_BYTE_MAX, &(kmac_tc->mac_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex converstion failure (mac)");
                return rv;
            }
        } else {
            kmac_tc->mac_len = mac_len;
        }
    }

    if (msg) {
        kmac_tc->msg = calloc(1, ACVP_KMAC_MSG_BYTE_MAX);
        if (!kmac_tc->msg) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(msg, kmac_tc->msg, ACVP_KMAC_MSG_BYTE_MAX, &(kmac_tc->msg_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (msg)");
            return rv;
        }
    }

    if (key) {
        kmac_tc->key = calloc(1, ACVP_KMAC_KEY_BYTE_MAX);
        if (!kmac_tc->key) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(key, kmac_tc->key, ACVP_KMAC_KEY_BYTE_MAX, (int *) &(kmac_tc->key_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (key)");
            return rv;
        }
    }

    if (custom) {
        if (custom_is_hex) {
            kmac_tc->hex_customization = 1;
            if (corrupt != 2) {
                kmac_tc->custom_hex = calloc(1, ACVP_KMAC_CUSTOM_HEX_BYTE_MAX);
                if (!kmac_tc->custom_hex) { return ACVP_MALLOC_FAIL; }
                rv = acvp_hexstr_to_bin(custom, kmac_tc->custom_hex, ACVP_KMAC_CUSTOM_HEX_BYTE_MAX, (int *) &(kmac_tc->custom_len));
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("Hex converstion failure (custom)");
                    return rv;
                }
            } else {
                kmac_tc->custom_len = 8;
            }
        } else if (corrupt != 2) {
            kmac_tc->custom = calloc(1, ACVP_KMAC_CUSTOM_STR_MAX + 1);
            if (!kmac_tc->custom) { return ACVP_MALLOC_FAIL; }
            if (strncpy_s(kmac_tc->custom, ACVP_KMAC_CUSTOM_STR_MAX + 1, custom, strnlen_s(custom, ACVP_KMAC_CUSTOM_STR_MAX))) {
                ACVP_LOG_ERR("Error copying customization string for KMAC");
                return ACVP_INTERNAL_ERR;
            }
        } else {
             kmac_tc->custom_len = 8;
        }
    }

    return 1;
}

void free_kmac_tc(ACVP_KMAC_TC *kmac_tc) {
    if (kmac_tc->msg) free(kmac_tc->msg);
    if (kmac_tc->mac) free(kmac_tc->mac);
    if (kmac_tc->key) free(kmac_tc->key);
    if (kmac_tc->custom_hex) free(kmac_tc->custom_hex);
    if (kmac_tc->custom) free(kmac_tc->custom);
    memset(kmac_tc, 0x0, sizeof(ACVP_KMAC_TC));
}

/* missing msg in kmac tc test case */
Test(APP_KMAC_HANDLER, missing_msg) {
    char *msg = NULL;
    char *key = "aaaa";
    char *custom = "aaaa";

    kmac_tc = calloc(1, sizeof(ACVP_KMAC_TC));
    
    if (!initialize_kmac_tc(kmac_tc, ACVP_KMAC_128, ACVP_KMAC_TEST_TYPE_AFT, 0, 0, NULL, 32, msg, key, custom, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kmac = kmac_tc;
    
    rv = app_kmac_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kmac_tc(kmac_tc);
    free(kmac_tc);
    free(test_case);
}

/* missing key in kmac tc test case */
Test(APP_KMAC_HANDLER, missing_key) {
    char *msg = "aaaa";
    char *key = NULL;
    char *custom = "aaaa";

    kmac_tc = calloc(1, sizeof(ACVP_KMAC_TC));

    if (!initialize_kmac_tc(kmac_tc, ACVP_KMAC_128, ACVP_KMAC_TEST_TYPE_AFT, 0, 0, NULL, 32, msg, key, custom, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kmac = kmac_tc;
    
    rv = app_kmac_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kmac_tc(kmac_tc);
    free(kmac_tc);
    free(test_case);
}

/* missing mac data (for MVT) in kmac tc test case */
Test(APP_KMAC_HANDLER, missing_mac_mvt) {
    char *msg = "aaaa";
    char *key = "aaaa";
    char *custom = "aaaa";

    kmac_tc = calloc(1, sizeof(ACVP_KMAC_TC));
    
    if (!initialize_kmac_tc(kmac_tc, ACVP_KMAC_128, ACVP_KMAC_TEST_TYPE_MVT, 0, 0, NULL, 32, msg, key, custom, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kmac = kmac_tc;
    
    rv = app_kmac_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kmac_tc(kmac_tc);
    free(kmac_tc);
    free(test_case);
}


/* no maclen given for AFT */
Test(APP_KMAC_HANDLER, missing_maclen) {
    char *msg = "aaaa";
    char *key = "aaaa";
    char *custom = "aaaa";

    kmac_tc = calloc(1, sizeof(ACVP_KMAC_TC));
    
    if (!initialize_kmac_tc(kmac_tc, ACVP_KMAC_128, ACVP_KMAC_TEST_TYPE_AFT, 0, 0, NULL, 0, msg, key, custom, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kmac = kmac_tc;
    
    rv = app_kmac_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kmac_tc(kmac_tc);
    free(kmac_tc);
    free(test_case);
}

/* Custom len is provided, but no customization buffer */
Test(APP_KMAC_HANDLER, missing_customization) {
    char *msg = "aaaa";
    char *key = "aaaa";

    kmac_tc = calloc(1, sizeof(ACVP_KMAC_TC));
    
    if (!initialize_kmac_tc(kmac_tc, ACVP_KMAC_128, ACVP_KMAC_TEST_TYPE_AFT, 0, 0, NULL, 32, msg, key, NULL, 2)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kmac = kmac_tc;
    
    rv = app_kmac_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kmac_tc(kmac_tc);
    free(kmac_tc);
    free(test_case);
}

/* the pointer for mac should be allocated by the library (for AFT). here we don't allocate it and test to see 
   if the handler gracefully handles it */
Test(APP_KMAC_HANDLER, mem_not_allocated) {
    char *key = "aaaa";
    char *msg = "aaaa";
    char *custom = "aaaa";

    kmac_tc = calloc(1, sizeof(ACVP_KMAC_TC));

    if (!initialize_kmac_tc(kmac_tc, ACVP_KMAC_128, ACVP_KMAC_TEST_TYPE_AFT, 0, 0, NULL, 32, msg, key, custom, 1)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kmac = kmac_tc;

    rv = app_kmac_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_kmac_tc(kmac_tc);
    free(kmac_tc);
    free(test_case);
}

#endif
