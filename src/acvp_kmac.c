/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"
#include "safe_lib.h"

static ACVP_RESULT acvp_kmac_init_tc(ACVP_CTX *ctx,
                                     ACVP_KMAC_TC *stc,
                                     ACVP_CIPHER alg_id,
                                     int tc_id,
                                     ACVP_KMAC_TESTTYPE type,
                                     int xof,
                                     int hex_customization,
                                     const char *msg,
                                     int msg_len,
                                     const char *mac,
                                     int mac_len,
                                     const char *key,
                                     int key_len,
                                     const char *custom) {

    ACVP_RESULT rv;
    int len = 0;
    memzero_s(stc, sizeof(ACVP_KMAC_TC));

    stc->msg = calloc(1, ACVP_KMAC_MSG_BYTE_MAX);
    if (!stc->msg) { return ACVP_MALLOC_FAIL; }
    stc->mac = calloc(1, ACVP_KMAC_MAC_BYTE_MAX);
    if (!stc->mac) { return ACVP_MALLOC_FAIL; }
    stc->key = calloc(1, ACVP_KMAC_KEY_BYTE_MAX);
    if (!stc->key) { return ACVP_MALLOC_FAIL; }
    if (hex_customization) {
        stc->custom_hex = calloc(1, ACVP_KMAC_CUSTOM_HEX_BYTE_MAX);
        if (!stc->custom_hex) { return ACVP_MALLOC_FAIL; }
    } else {
        stc->custom = calloc(1, ACVP_KMAC_CUSTOM_STR_MAX);
        if (!stc->custom) { return ACVP_MALLOC_FAIL; }
    }

    rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_KMAC_MSG_BYTE_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex converstion failure (msg)");
        return rv;
    }

    rv = acvp_hexstr_to_bin(key, stc->key, ACVP_KMAC_KEY_BYTE_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex converstion failure (key)");
        return rv;
    }

    if (type == ACVP_KMAC_TEST_TYPE_MVT) {
        rv = acvp_hexstr_to_bin(mac, stc->mac, ACVP_KMAC_MAC_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (mac)");
            return rv;
        }
    }

    if (hex_customization) {
        rv = acvp_hexstr_to_bin(custom, stc->custom_hex, ACVP_KMAC_CUSTOM_HEX_BYTE_MAX, &stc->custom_len);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (customizationHex)");
            return rv;
        }
    } else {
        len = strnlen_s(custom, ACVP_KMAC_CUSTOM_STR_MAX + 1);
        if (len > ACVP_KMAC_CUSTOM_STR_MAX) {
            ACVP_LOG_ERR("customization string too long");
            return ACVP_INVALID_ARG;
        }
        if (strncpy_s(stc->custom, ACVP_KMAC_CUSTOM_STR_MAX, custom, len)) {
            ACVP_LOG_ERR("String copy failure (customization)");
            return ACVP_INVALID_ARG;
        }
        stc->custom_len = len;
    }

    stc->tc_id = tc_id;
    stc->test_type = type;
    stc->xof = xof;
    stc->hex_customization = hex_customization;
    stc->mac_len = mac_len / 8;
    stc->msg_len = msg_len / 8;
    stc->key_len = key_len / 8;
    stc->cipher = alg_id;

    return ACVP_SUCCESS;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_kmac_output_tc(ACVP_CTX *ctx, ACVP_KMAC_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    if (stc->test_type == ACVP_KMAC_TEST_TYPE_AFT) {
        tmp = calloc(ACVP_KMAC_MAC_STR_MAX + 1, sizeof(char));
        if (!tmp) {
            ACVP_LOG_ERR("Unable to malloc in acvp_kmac_output_tc");
            return ACVP_MALLOC_FAIL;
        }

        rv = acvp_bin_to_hexstr(stc->mac, stc->mac_len, tmp, ACVP_KMAC_MAC_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (mac)");
            goto end;
        }
        json_object_set_string(tc_rsp, "mac", tmp);
    } else { /* verify */
        json_object_set_boolean(tc_rsp, "testPassed", stc->disposition);
    }

end:
    if (tmp) free(tmp);
    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kmac_release_tc(ACVP_KMAC_TC *stc) {
    if (stc->msg) free(stc->msg);
    if (stc->mac) free(stc->mac);
    if (stc->key) free(stc->key);
    if (stc->custom) free(stc->custom);
    if (stc->custom_hex) free(stc->custom_hex);
    memzero_s(stc, sizeof(ACVP_KMAC_TC));

    return ACVP_SUCCESS;
}

static ACVP_KMAC_TESTTYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return ACVP_KMAC_TEST_TYPE_AFT;

    strcmp_s("MVT", 3, str, &diff);
    if (!diff) return ACVP_KMAC_TEST_TYPE_MVT;

    return 0;
}

ACVP_RESULT acvp_kmac_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    int tc_id = 0, msglen = 0, keylen = 0, maclen = 0;
    const char *msg = NULL, *key = NULL, *mac = NULL, *type_str = NULL, *custom = NULL;
    int xof = 0, hex_customization = 0;
    ACVP_KMAC_TESTTYPE type;
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *groups;
    JSON_Array *tests;

    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;

    int i, g_cnt;
    int j, t_cnt;

    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL, *r_garr = NULL;  /* Response testarray, grouparray */
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    ACVP_CAPS_LIST *cap;
    ACVP_KMAC_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER alg_id;
    char *json_result;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    if (!obj) {
        ACVP_LOG_ERR("No obj for handler operation");
        return ACVP_MALFORMED_JSON;
    }

    if (!alg_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    /* Get a reference to the abstracted test case */
    tc.tc.kmac = &stc;

    /* Get the crypto module handler for this kmac algorithm */
    alg_id = acvp_lookup_cipher_index(alg_str);
    if (alg_id == 0) {
        ACVP_LOG_ERR("ERROR: unsupported algorithm (%s)", alg_str);
        return ACVP_UNSUPPORTED_OP;
    }
    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ERROR: ACVP server requesting unsupported capability");
        return ACVP_UNSUPPORTED_OP;
    }

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("ERROR: Failed to create JSON response struct. ");
        return rv;
    }

    /*
     * Start to build the JSON response
     */
    rv = acvp_setup_json_rsp_group(&ctx, &reg_arry_val, &r_vs_val, &r_vs, alg_str, &r_garr);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to setup json response");
        return rv;
    }

    groups = json_object_get_array(obj, "testGroups");
    if (!groups) {
        ACVP_LOG_ERR("Failed to include testGroups. ");
        rv = ACVP_MISSING_ARG;
        goto err;
    }
    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        /*
         * Create a new group in the response with the tgid
         * and an array of tests
         */
        r_gval = json_value_init_object();
        r_gobj = json_value_get_object(r_gval);
        tgId = json_object_get_number(groupobj, "tgId");
        if (!tgId) {
            ACVP_LOG_ERR("Missing tgid from server JSON groub obj");
            rv = ACVP_MALFORMED_JSON;
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        type_str = json_object_get_string(groupobj, "testType");
        if (!type_str) {
            ACVP_LOG_ERR("Failed to include testType.");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        type = read_test_type(type_str);
        if (!type) {
            ACVP_LOG_ERR("Error parsing test type.");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        xof = json_object_get_boolean(groupobj, "xof");
        hex_customization = json_object_get_boolean(groupobj, "hexCustomization");

        ACVP_LOG_VERBOSE("    Test group: %d", i);
        ACVP_LOG_VERBOSE("      testType: %s", type_str);
        ACVP_LOG_VERBOSE("           xof: %d", xof);
        ACVP_LOG_VERBOSE("     hexCustom: %d", hex_customization);

        tests = json_object_get_array(groupobj, "tests");
        if (!tests) {
            ACVP_LOG_ERR("Failed to include tests. ");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        t_cnt = json_array_get_count(tests);
        if (!t_cnt) {
            ACVP_LOG_ERR("Failed to include tests in array. ");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_VERBOSE("Found new kmac test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");
            if (!tc_id) {
                ACVP_LOG_ERR("Failed to include tc_id. ");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            msglen = json_object_get_number(testobj, "msgLen");
            if (msglen < 0) {
                ACVP_LOG_ERR("Invalid or missing msgLen");
                rv = ACVP_INVALID_ARG;
                goto err;
            }
            msg = json_object_get_string(testobj, "msg");
            if (!msg) {
                ACVP_LOG_ERR("Failed to include msg.");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
            if ((int)strnlen_s(msg, ACVP_KMAC_MSG_STR_MAX) != msglen >> 2) {
                ACVP_LOG_ERR("msgLen(%d) or msg length(%zu) incorrect",
                             msglen, strnlen_s(msg, ACVP_KMAC_MSG_STR_MAX) >> 2);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            keylen = json_object_get_number(testobj, "keyLen");
            if (keylen <= 0) {
                ACVP_LOG_ERR("Invalid or missing keyLen");
                rv = ACVP_INVALID_ARG;
                goto err;
            }
            key = json_object_get_string(testobj, "key");
            if (!key) {
                ACVP_LOG_ERR("Failed to include key.");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
            if ((int)strnlen_s(key, ACVP_KMAC_KEY_STR_MAX) != (keylen >> 2)) {
                ACVP_LOG_ERR("keyLen(%d) or key length(%zu) incorrect",
                             keylen, strnlen_s(key, ACVP_KMAC_KEY_STR_MAX) >> 2);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            maclen = json_object_get_number(testobj, "macLen");
            if (maclen <= 0) {
                ACVP_LOG_ERR("Invalid or missing keyLen");
                rv = ACVP_INVALID_ARG;
                goto err;
            }
            if (type == ACVP_KMAC_TEST_TYPE_MVT) {
                mac = json_object_get_string(testobj, "mac");
                if (!mac) {
                    ACVP_LOG_ERR("Failed to include mac in MVT test.");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if ((int)strnlen_s(mac, ACVP_KMAC_MAC_STR_MAX) << 2 != maclen) {
                    ACVP_LOG_ERR("macLen(%d) or mac length(%zu) incorrect",
                                maclen, strnlen_s(mac, ACVP_KMAC_MAC_STR_MAX) << 2);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            if (hex_customization) {
                custom = json_object_get_string(testobj, "customizationHex");
                if (!custom) {
                    ACVP_LOG_ERR("Failed to include customizationHex.");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(custom, ACVP_KMAC_CUSTOM_HEX_STR_MAX + 1) > ACVP_KMAC_CUSTOM_HEX_STR_MAX) {
                    ACVP_LOG_ERR("customizationHex string too long in tcid %d", tc_id);
                }
            } else {
                custom = json_object_get_string(testobj, "customization");
                if (!custom) {
                    ACVP_LOG_ERR("Failed to include customization.");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(custom, ACVP_KMAC_CUSTOM_STR_MAX + 1) > ACVP_KMAC_CUSTOM_STR_MAX) {
                    ACVP_LOG_ERR("customization string too long in tcid %d", tc_id);
                }
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("           msgLen: %d", msglen);
            if (type == ACVP_KMAC_TEST_TYPE_MVT) {
                ACVP_LOG_VERBOSE("              mac: %s", mac);
            }
            ACVP_LOG_VERBOSE("           macLen: %d", maclen);
            ACVP_LOG_VERBOSE("              msg: %s", msg);
            ACVP_LOG_VERBOSE("           keyLen: %d", keylen);
            ACVP_LOG_VERBOSE("              key: %s", key);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             */
            rv = acvp_kmac_init_tc(ctx, &stc, alg_id, tc_id, type, xof, hex_customization,
                                     msg, msglen, mac, maclen, key, keylen, custom);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Error initializing KMAC test case");
                acvp_kmac_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                acvp_kmac_release_tc(&stc);
                json_value_free(r_tval);
                rv = ACVP_CRYPTO_MODULE_FAIL;
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kmac_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: JSON output failure in kmac module");
                json_value_free(r_tval);
                acvp_kmac_release_tc(&stc);
                goto err;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_kmac_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
    }

    json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    ACVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        acvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}
