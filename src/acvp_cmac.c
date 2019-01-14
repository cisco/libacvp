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
#include "safe_lib.h"

static ACVP_RESULT acvp_cmac_init_tc(ACVP_CTX *ctx,
                                     ACVP_CMAC_TC *stc,
                                     unsigned int tc_id,
                                     char *msg,
                                     unsigned int msg_len,
                                     unsigned int key_len,
                                     char *key,
                                     char *key2,
                                     char *key3,
                                     int direction_verify,
                                     char *mac,
                                     unsigned int mac_len,
                                     ACVP_CIPHER alg_id) {
    ACVP_RESULT rv;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (alg_id != ACVP_CMAC_TDES && alg_id != ACVP_CMAC_AES) {
        return ACVP_INVALID_ARG;
    }
    if (!msg || !stc || !tc_id || !key) {
        return ACVP_INVALID_ARG;
    }
    if (alg_id == ACVP_CMAC_TDES && (!key2 || !key3)) {
        return ACVP_INVALID_ARG;
    }
    if (direction_verify) {
        if (!mac_len || !mac) {
            return ACVP_INVALID_ARG;
        }
    }

    memzero_s(stc, sizeof(ACVP_CMAC_TC));

    stc->msg = calloc(1, ACVP_CMAC_MSGLEN_MAX_STR);
    if (!stc->msg) { return ACVP_MALLOC_FAIL; }

    stc->mac = calloc(ACVP_CMAC_MACLEN_MAX, sizeof(char));
    if (!stc->mac) { return ACVP_MALLOC_FAIL; }
    stc->key = calloc(1, ACVP_CMAC_KEY_MAX);
    if (!stc->key) { return ACVP_MALLOC_FAIL; }
    stc->mac_len = mac_len;

    if (direction_verify) {
        rv = acvp_hexstr_to_bin(mac, stc->mac, ACVP_CMAC_MACLEN_MAX, (int *)&(stc->mac_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (mac)");
            return rv;
        }
    }

    stc->key2 = calloc(1, ACVP_CMAC_KEY_MAX);
    if (!stc->key2) { return ACVP_MALLOC_FAIL; }
    stc->key3 = calloc(1, ACVP_CMAC_KEY_MAX);
    if (!stc->key3) { return ACVP_MALLOC_FAIL; }

    rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_CMAC_MSGLEN_MAX_STR, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex converstion failure (msg)");
        return rv;
    }

    if (alg_id == ACVP_CMAC_AES) {
        rv = acvp_hexstr_to_bin(key, stc->key, ACVP_CMAC_KEY_MAX, (int *)&(stc->key_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (key)");
            return rv;
        }
    } else if (alg_id == ACVP_CMAC_TDES) {
        rv = acvp_hexstr_to_bin(key, stc->key, ACVP_CMAC_KEY_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (key1)");
            return rv;
        }
        rv = acvp_hexstr_to_bin(key2, stc->key2, ACVP_CMAC_KEY_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (key2)");
            return rv;
        }
        rv = acvp_hexstr_to_bin(key3, stc->key3, ACVP_CMAC_KEY_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (key3)");
            return rv;
        }
    }

    if (direction_verify) {
        stc->verify = 1;
    }

    stc->tc_id = tc_id;
    stc->msg_len = msg_len;
    stc->cipher = alg_id;

    return ACVP_SUCCESS;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_cmac_output_tc(ACVP_CTX *ctx, ACVP_CMAC_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_CMAC_MACLEN_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_cmac_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->verify) {
        json_object_set_boolean(tc_rsp, "testPassed", stc->ver_disposition);
    } else {
        rv = acvp_bin_to_hexstr(stc->mac, stc->mac_len, tmp, ACVP_CMAC_MACLEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (mac)");
            goto end;
        }
        json_object_set_string(tc_rsp, "mac", tmp);
    }

end:
    if (tmp) free(tmp);

    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_cmac_release_tc(ACVP_CMAC_TC *stc) {
    if (stc->msg) free(stc->msg);
    if (stc->mac) free(stc->mac);
    if (stc->key) free(stc->key);
    if (stc->key2) free(stc->key2);
    if (stc->key3) free(stc->key3);
    memzero_s(stc, sizeof(ACVP_CMAC_TC));

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cmac_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    unsigned int tc_id, msglen, keyLen = 0, keyingOption = 0, maclen, verify = 0;
    char *msg = NULL, *key1 = NULL, *key2 = NULL, *key3 = NULL, *mac = NULL;
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
    ACVP_CMAC_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER alg_id;
    char *json_result, *direction = NULL;
    int key1_len, key2_len, key3_len, json_msglen;

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
    tc.tc.cmac = &stc;

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
    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        int diff = 0;

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

        if (alg_id == ACVP_CMAC_AES) {
            keyLen = (unsigned int)json_object_get_number(groupobj, "keyLen");
            if (!keyLen) {
                ACVP_LOG_ERR("keylen missing from cmac aes json");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
        } else if (alg_id == ACVP_CMAC_TDES) {
            keyingOption = (unsigned int)json_object_get_number(groupobj, "keyingOption");
            if (keyingOption <= ACVP_CMAC_TDES_KEYING_OPTION_MIN ||
                keyingOption >= ACVP_CMAC_TDES_KEYING_OPTION_MAX) {
                ACVP_LOG_ERR("keyingOption missing or wrong from cmac tdes json");
                rv = ACVP_INVALID_ARG;
                goto err;
            }
        }

        direction = (char *)json_object_get_string(groupobj, "direction");
        if (!direction) {
            ACVP_LOG_ERR("Unable to parse 'direction' from JSON.");
            rv = ACVP_MALFORMED_JSON;
            goto err;
        }

        strcmp_s("ver", 3, direction, &diff);
        if (!diff) {
            verify = 1;
        } else {
            strcmp_s("gen", 3, direction, &diff);
            if (diff) {
                ACVP_LOG_ERR("'direction' should be 'gen' or 'ver'");
                rv = ACVP_UNSUPPORTED_OP;
                goto err;
            }
        }

        msglen = (unsigned int)json_object_get_number(groupobj, "msgLen") / 8;

        maclen = (unsigned int)json_object_get_number(groupobj, "macLen") / 8;
        if (!maclen) {
            ACVP_LOG_ERR("Server JSON missing 'macLen'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        ACVP_LOG_INFO("\n\n    Test group: %d", i);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new cmac test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");
            msg = (char *)json_object_get_string(testobj, "message");

            /* msg can be null if msglen is 0 */
            if (msg) {
                json_msglen = strnlen_s(msg, ACVP_CMAC_MSGLEN_MAX_STR + 1);
                if (json_msglen > ACVP_CMAC_MSGLEN_MAX_STR) {
                    ACVP_LOG_ERR("'msg' too long");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
                if (!msglen && json_msglen > 0) {
                    ACVP_LOG_ERR("Server JSON missing 'msgLen'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
            } else if (msglen) {
                ACVP_LOG_ERR("msglen is nonzero, expected 'msg' in json");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            if (alg_id == ACVP_CMAC_AES) {
                key1 = (char *)json_object_get_string(testobj, "key");
                if (!key1) {
                    ACVP_LOG_ERR("Server JSON missing 'key'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                key1_len = strnlen_s(key1, ACVP_CMAC_KEY_MAX + 1);
                if (key1_len > ACVP_CMAC_KEY_MAX) {
                    ACVP_LOG_ERR("Invalid length for 'key' attribute in CMAC-AES test");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            } else if (alg_id == ACVP_CMAC_TDES) {
                key1 = (char *)json_object_get_string(testobj, "key1");
                key2 = (char *)json_object_get_string(testobj, "key2");
                key3 = (char *)json_object_get_string(testobj, "key3");
                if (!key1 || !key2 || !key3) {
                    ACVP_LOG_ERR("Server JSON missing 'key(1,2,3)' value");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                key1_len = strnlen_s(key1, ACVP_CMAC_KEY_MAX + 1);
                key2_len = strnlen_s(key2, ACVP_CMAC_KEY_MAX + 1);
                key3_len = strnlen_s(key3, ACVP_CMAC_KEY_MAX + 1);
                if (key1_len > ACVP_CMAC_KEY_MAX ||
                    key2_len > ACVP_CMAC_KEY_MAX ||
                    key3_len > ACVP_CMAC_KEY_MAX) {
                    ACVP_LOG_ERR("Invalid length for 'key(1|2|3)' attribute in CMAC-TDES test");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            if (verify) {
                mac = (char *)json_object_get_string(testobj, "mac");
                if (!mac) {
                    ACVP_LOG_ERR("Server JSON missing 'mac'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
            }

            ACVP_LOG_INFO("\n        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            ACVP_LOG_INFO("        direction: %s", direction);

            ACVP_LOG_INFO("           msgLen: %d", msglen);
            ACVP_LOG_INFO("              msg: %s", msg);
            if (alg_id == ACVP_CMAC_AES) {
                ACVP_LOG_INFO("           keyLen: %d", keyLen);
                ACVP_LOG_INFO("              key: %s", key1);
            } else if (alg_id == ACVP_CMAC_TDES) {
                ACVP_LOG_INFO("     keyingOption: %d", keyingOption);
                ACVP_LOG_INFO("             key1: %s", key1);
                ACVP_LOG_INFO("             key2: %s", key2);
                ACVP_LOG_INFO("             key3: %s", key3);
            }

            if (verify) {
                ACVP_LOG_INFO("              mac: %s", mac);
            }

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
            rv = acvp_cmac_init_tc(ctx, &stc, tc_id, msg, msglen, keyLen, key1, key2, key3,
                                   verify, mac, maclen, alg_id);
            if (rv != ACVP_SUCCESS) {
                acvp_cmac_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                acvp_cmac_release_tc(&stc);
                rv = ACVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_cmac_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                acvp_cmac_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_cmac_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
    }

    json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
        printf("\n\n%s\n\n", json_result);
    } else {
        ACVP_LOG_INFO("\n\n%s\n\n", json_result);
    }
    json_free_serialized_string(json_result);
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        acvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}
