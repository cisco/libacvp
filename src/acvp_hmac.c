/** @file */
/*****************************************************************************
* Copyright (c) 2016-2017, Cisco Systems, Inc.
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"

static ACVP_RESULT acvp_hmac_init_tc(ACVP_CTX *ctx,
                                     ACVP_HMAC_TC *stc,
                                     unsigned int tc_id,
                                     unsigned int msg_len,
                                     char *msg,
                                     unsigned int mac_len,
                                     unsigned int key_len,
                                     char *key,
                                     ACVP_CIPHER alg_id) {
    ACVP_RESULT rv;

    memset(stc, 0x0, sizeof(ACVP_HMAC_TC));

    stc->msg = calloc(1, ACVP_HMAC_MSG_MAX);
    if (!stc->msg) { return ACVP_MALLOC_FAIL; }
    stc->mac = calloc(1, ACVP_HMAC_MAC_BYTE_MAX);
    if (!stc->mac) { return ACVP_MALLOC_FAIL; }
    stc->key = calloc(1, ACVP_HMAC_KEY_BYTE_MAX);
    if (!stc->key) { return ACVP_MALLOC_FAIL; }

    rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_HMAC_MSG_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex converstion failure (msg)");
        return rv;
    }

    rv = acvp_hexstr_to_bin(key, stc->key, ACVP_HMAC_KEY_BYTE_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex converstion failure (key)");
        return rv;
    }

    stc->tc_id = tc_id;
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
static ACVP_RESULT acvp_hmac_output_tc(ACVP_CTX *ctx, ACVP_HMAC_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_HMAC_MAC_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_hmac_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(stc->mac, stc->mac_len, tmp, ACVP_HMAC_MAC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (mac)");
        goto end;
    }
    json_object_set_string(tc_rsp, "mac", tmp);

end:
    if (tmp) free(tmp);

    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_hmac_release_tc(ACVP_HMAC_TC *stc) {
    free(stc->msg);
    free(stc->mac);
    free(stc->key);
    memset(stc, 0x0, sizeof(ACVP_HMAC_TC));

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_hmac_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    unsigned int tc_id = 0, msglen = 0, keylen = 0, maclen = 0;
    char *msg = NULL, *key = NULL;
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
    ACVP_HMAC_TC stc;
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

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.hmac = &stc;

    /*
     * Get the crypto module handler for this hash algorithm
     */
    alg_id = acvp_lookup_cipher_index(alg_str);
    if (alg_id < ACVP_CIPHER_START) {
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
        return ACVP_MISSING_ARG;
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
            return ACVP_MALFORMED_JSON;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        msglen = (unsigned int)json_object_get_number(groupobj, "msgLen");
        if (!msglen) {
            ACVP_LOG_ERR("Failed to include msgLen. ");
            return ACVP_MISSING_ARG;
        }

        keylen = (unsigned int)json_object_get_number(groupobj, "keyLen");
        if (!keylen) {
            ACVP_LOG_ERR("Failed to include keyLen. ");
            return ACVP_MISSING_ARG;
        }

        maclen = (unsigned int)json_object_get_number(groupobj, "macLen");
        if (!maclen) {
            ACVP_LOG_ERR("Failed to include macLen. ");
            return ACVP_MISSING_ARG;
        }

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("        msglen: %d", msglen);

        tests = json_object_get_array(groupobj, "tests");
        if (!tests) {
            ACVP_LOG_ERR("Failed to include tests. ");
            return ACVP_MISSING_ARG;
        }

        t_cnt = json_array_get_count(tests);
        if (!t_cnt) {
            ACVP_LOG_ERR("Failed to include tests in array. ");
            return ACVP_MISSING_ARG;
        }

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new hash test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");
            if (!tc_id) {
                ACVP_LOG_ERR("Failed to include tc_id. ");
                return ACVP_MISSING_ARG;
            }
            msg = (char *)json_object_get_string(testobj, "msg");
            if (!msg) {
                ACVP_LOG_ERR("Failed to include msg. ");
                return ACVP_MISSING_ARG;
            }

            if (strnlen((char *)msg, ACVP_HMAC_MSG_MAX) != msglen * 2 / 8) {
                ACVP_LOG_ERR("msgLen(%d) or msg length(%d) incorrect",
                             msglen, strnlen((char *)msg, ACVP_HMAC_MSG_MAX) * 8 / 2);
                return ACVP_INVALID_ARG;
            }

            key = (char *)json_object_get_string(testobj, "key");
            if (!key) {
                ACVP_LOG_ERR("Failed to include key. ");
                return ACVP_MISSING_ARG;
            }

            if (strnlen((char *)key, ACVP_HMAC_KEY_STR_MAX) != (keylen / 4)) {
                ACVP_LOG_ERR("keyLen(%d) or key length(%d) incorrect",
                             keylen, strnlen((char *)key, ACVP_HMAC_KEY_STR_MAX) * 4);
                return ACVP_INVALID_ARG;
            }

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            ACVP_LOG_INFO("           msgLen: %d", msglen);
            ACVP_LOG_INFO("           macLen: %d", maclen);
            ACVP_LOG_INFO("              msg: %s", msg);
            ACVP_LOG_INFO("           keyLen: %d", keylen);
            ACVP_LOG_INFO("              key: %s", key);

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
            rv = acvp_hmac_init_tc(ctx, &stc, tc_id, msglen, msg, maclen, keylen, key, alg_id);
            if (rv != ACVP_SUCCESS) {
                acvp_hmac_release_tc(&stc);
                return rv;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                acvp_hmac_release_tc(&stc);
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_hmac_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                acvp_hmac_release_tc(&stc);
                return rv;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_hmac_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
    }

    json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp);
    if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
        printf("\n\n%s\n\n", json_result);
    } else {
        ACVP_LOG_INFO("\n\n%s\n\n", json_result);
    }
    json_free_serialized_string(json_result);

    return ACVP_SUCCESS;
}
