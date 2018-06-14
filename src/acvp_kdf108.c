/*****************************************************************************
* Copyright (c) 2017, Cisco Systems, Inc.
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

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_kdf108_output_tc (ACVP_CTX *ctx,
                                          ACVP_KDF108_TC *stc,
                                          JSON_Object *tc_rsp) {
    ACVP_RESULT rv = 0;
    char tmp[ACVP_KDF108_STRING_MAX + 1] = {0}; // Leave space for terminator

    /*
     * Sign check, only accept positive values
     */
    if (stc->key_out_len <= 0 ||
        stc->fixed_data_len <= 0) {
        ACVP_LOG_ERR("stc lengths <= 0");
        return ACVP_INVALID_ARG;
    }

    /*
     * Length check
     */
    if ((stc->key_out_len * 2) > ACVP_KDF108_STRING_MAX ||
        (stc->fixed_data_len * 2) > ACVP_KDF108_STRING_MAX) {
        ACVP_LOG_ERR("stc lengths > ACVP_KDF108_STRING_MAX(%u)", ACVP_KDF108_STRING_MAX);
        return ACVP_INVALID_ARG;
    }

    rv = acvp_bin_to_hexstr(stc->key_out, stc->key_out_len, (unsigned char *) tmp);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("acvp_bin_to_hexstr() failure");
        return rv;
    }
    json_object_set_string(tc_rsp, "keyOut", tmp);

    // Clear the tmp array
    memset(tmp, 0, ACVP_KDF108_STRING_MAX);

    rv = acvp_bin_to_hexstr(stc->fixed_data, stc->fixed_data_len, (unsigned char *) tmp);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("acvp_bin_to_hexstr() failure");
        return rv;
    }
    json_object_set_string(tc_rsp, "fixedData", tmp);

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kdf108_init_tc (ACVP_CTX *ctx,
                                        ACVP_KDF108_TC *stc,
                                        unsigned int tc_id,
                                        ACVP_KDF108_MODE kdf_mode,
                                        ACVP_KDF108_MAC_MODE_VAL mac_mode,
                                        ACVP_KDF108_FIXED_DATA_ORDER_VAL counter_location,
                                        char *key_in,
                                        int key_in_len,
                                        int key_out_len,
                                        int counter_len,
                                        int deferred
) {
    memset(stc, 0x0, sizeof(ACVP_KDF108_TC));

    // Allocate space for the key_in (binary)
    stc->key_in = calloc(key_in_len, sizeof(unsigned char));
    if (!stc->key_in) { return ACVP_MALLOC_FAIL; }

    // Convert key_in from hex string to binary
    acvp_hexstr_to_bin(key_in, stc->key_in, key_in_len);

    // Allocate space for the key_out
    stc->key_out = calloc(key_out_len, sizeof(unsigned char));
    if (!stc->key_out) { return ACVP_MALLOC_FAIL; }

    /*
     * Allocate space for the fixed_data.
     * User supplies the data, set size limit.
     */
    stc->fixed_data = calloc(ACVP_KDF108_FIXED_DATA_MAX, sizeof(unsigned char));
    if (!stc->key_out) { return ACVP_MALLOC_FAIL; }
    
    stc->tc_id = tc_id;
    stc->cipher = ACVP_KDF108;
    stc->mode = kdf_mode;
    stc->mac_mode = mac_mode;
    stc->counter_location = counter_location;
    stc->key_in_len = key_in_len;
    stc->key_out_len = key_out_len;
    stc->counter_len = counter_len;
    stc->deferred = deferred;
    
    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf108_release_tc (ACVP_KDF108_TC *stc) {
    if (stc->key_in) free(stc->key_in);
    if (stc->key_out) free(stc->key_out);
    if (stc->fixed_data) free(stc->fixed_data);
    
    memset(stc, 0x0, sizeof(ACVP_KDF108_TC));
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_kdf108_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
    unsigned int tc_id;
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
    JSON_Array *r_tarr = NULL; /* Response testarray */
    JSON_Value *r_tval = NULL; /* Response testval */
    JSON_Object *r_tobj = NULL; /* Response testobj */

    ACVP_CAPS_LIST *cap;
    ACVP_KDF108_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;

    const char *alg_str = "KDF";
    ACVP_CIPHER alg_id = ACVP_KDF108;
    ACVP_KDF108_MODE kdf_mode = 0;
    ACVP_KDF108_MAC_MODE_VAL mac_mode = 0;
    ACVP_KDF108_FIXED_DATA_ORDER_VAL ctr_loc = 0;
    int key_out_bit_len, key_out_len, key_in_len, ctr_len, deferred;
    unsigned char *key_in = NULL;
    char *kdf_mode_str, *mac_mode_str, *key_in_str, *ctr_loc_str = NULL;
    char *json_result;

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf108 = &stc;

    /*
     * Get the crypto module handler for this hash algorithm
     */
    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        return (ACVP_UNSUPPORTED_OP);
    }

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct. ");
        return (rv);
    }

    /*
     * Start to build the JSON response
     */
    if (ctx->kat_resp) {
        json_value_free(ctx->kat_resp);
    }
    ctx->kat_resp = reg_arry_val;
    r_vs_val = json_value_init_object();
    r_vs = json_value_get_object(r_vs_val);

    json_object_set_number(r_vs, "vsId", ctx->vs_id);
    json_object_set_string(r_vs, "algorithm", alg_str);
    json_object_set_value(r_vs, "testResults", json_value_init_array());
    r_tarr = json_object_get_array(r_vs, "testResults");

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        kdf_mode_str = json_object_get_string(groupobj, "kdfMode");
        mac_mode_str = json_object_get_string(groupobj, "macMode");
        key_out_bit_len = json_object_get_number(groupobj, "keyOutLength");
        ctr_len = json_object_get_number(groupobj, "counterLength");
        ctr_loc_str = json_object_get_string(groupobj, "counterLocation");

        // Get the keyout byte length  (+1 for overflow bits)
        key_out_len = (key_out_bit_len + 7) / 8;

        if (key_out_len > ACVP_KDF108_KEYOUT_MAX) {
            ACVP_LOG_ERR("ACVP server requesting unsupported key_out length (%d)",
                         key_out_len);
            return (ACVP_UNSUPPORTED_OP);
        }

        /*
         * Determine the KDF108 mode to operate.
         * Compare using protocol specified strings.
         */
        if (strncmp(kdf_mode_str, ACVP_MODE_COUNTER, 64) == 0) {
            kdf_mode = ACVP_KDF108_MODE_COUNTER;
        } else if (strncmp(kdf_mode_str, ACVP_MODE_FEEDBACK, 64) == 0) {
            kdf_mode = ACVP_KDF108_MODE_FEEDBACK;
        } else if (strncmp(kdf_mode_str, ACVP_MODE_DPI, 64) == 0) {
            kdf_mode = ACVP_KDF108_MODE_DPI;
        } else {
            ACVP_LOG_ERR("ACVP server requesting unsupported KDF108 mode");
            return (ACVP_UNSUPPORTED_OP);
        }

        /*
         * Determine the mac mode to operate.
         * Compare using protocol specified strings.
         */
        if (strncmp(mac_mode_str, ACVP_ALG_HMAC_SHA1, 64) == 0) {
            mac_mode = ACVP_KDF108_MAC_MODE_HMAC_SHA1;
            key_in_len = ACVP_BYTE_LEN_HMAC_SHA1;
        } else if (strncmp(mac_mode_str, ACVP_ALG_HMAC_SHA2_224, 64) == 0) {
            mac_mode = ACVP_KDF108_MAC_MODE_HMAC_SHA224;
            key_in_len = ACVP_BYTE_LEN_HMAC_SHA224;
        } else if (strncmp(mac_mode_str, ACVP_ALG_HMAC_SHA2_256, 64) == 0) {
            mac_mode = ACVP_KDF108_MAC_MODE_HMAC_SHA256;
            key_in_len = ACVP_BYTE_LEN_HMAC_SHA256;
        } else if (strncmp(mac_mode_str, ACVP_ALG_HMAC_SHA2_384, 64) == 0) {
            mac_mode = ACVP_KDF108_MAC_MODE_HMAC_SHA384;
            key_in_len = ACVP_BYTE_LEN_HMAC_SHA384;
        } else if (strncmp(mac_mode_str, ACVP_ALG_HMAC_SHA2_512, 64) == 0) {
            mac_mode = ACVP_KDF108_MAC_MODE_HMAC_SHA512;
            key_in_len = ACVP_BYTE_LEN_HMAC_SHA512;
        } else if (strncmp(mac_mode_str, ACVP_ALG_CMAC_AES_128, 64) == 0) {
            mac_mode = ACVP_KDF108_MAC_MODE_CMAC_AES128;
            key_in_len = ACVP_BYTE_LEN_CMAC_AES128;
        } else if (strncmp(mac_mode_str, ACVP_ALG_CMAC_AES_192, 64) == 0) {
            mac_mode = ACVP_KDF108_MAC_MODE_CMAC_AES192;
            key_in_len = ACVP_BYTE_LEN_CMAC_AES192;
        } else if (strncmp(mac_mode_str, ACVP_ALG_CMAC_AES_256, 64) == 0) {
            mac_mode = ACVP_KDF108_MAC_MODE_CMAC_AES256;
            key_in_len = ACVP_BYTE_LEN_CMAC_AES256;
        } else if (strncmp(mac_mode_str, ACVP_ALG_CMAC_TDES, 64) == 0) {
            mac_mode = ACVP_KDF108_MAC_MODE_CMAC_TDES;
            key_in_len = ACVP_BYTE_LEN_CMAC_TDES;
        } else {
            ACVP_LOG_ERR("ACVP server requesting unsupported KDF108 mac mode");
            return (ACVP_UNSUPPORTED_OP);
        }

        /*
         * Determine the counter location.
         * Compare using protocol specified strings.
         */
        if (strncmp(ctr_loc_str, ACVP_FIXED_DATA_ORDER_AFTER_STR, 64) == 0) {
            ctr_loc = ACVP_KDF108_FIXED_DATA_ORDER_AFTER;
        } else if (strncmp(ctr_loc_str, ACVP_FIXED_DATA_ORDER_BEFORE_STR, 64) == 0) {
            ctr_loc = ACVP_KDF108_FIXED_DATA_ORDER_BEFORE;
        } else if (strncmp(ctr_loc_str, ACVP_FIXED_DATA_ORDER_MIDDLE_STR, 64) == 0) {
            ctr_loc = ACVP_KDF108_FIXED_DATA_ORDER_MIDDLE;
        } else if (strncmp(ctr_loc_str, ACVP_FIXED_DATA_ORDER_NONE_STR, 64) == 0) {
            ctr_loc = ACVP_KDF108_FIXED_DATA_ORDER_NONE;
        } else if (strncmp(ctr_loc_str, ACVP_FIXED_DATA_ORDER_BEFORE_ITERATOR_STR, 64) == 0) {
            ctr_loc = ACVP_KDF108_FIXED_DATA_ORDER_BEFORE_ITERATOR;
        } else {
            ACVP_LOG_ERR("ACVP server requesting unsupported KDF108 counter location");
            return (ACVP_UNSUPPORTED_OP);
        }

        /*
         * Log Test Group information...
         */
        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("       kdfMode: %s", kdf_mode_str);
        ACVP_LOG_INFO("       macMode: %s", mac_mode_str);
        ACVP_LOG_INFO("     keyOutLen: %d", key_out_bit_len);
        ACVP_LOG_INFO("    counterLen: %d", ctr_len);
        ACVP_LOG_INFO("    counterLoc: %s", ctr_loc_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new kdf108 test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int) json_object_get_number(testobj, "tcId");
            key_in_str = json_object_get_string(testobj, "keyIn");
            deferred = json_object_get_boolean(testobj, "deferred");

            /*
             * Log Test Case information...
             */
            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            ACVP_LOG_INFO("            keyIn: %s", key_in_str);
            ACVP_LOG_INFO("         deferred: %d", deferred);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             * TODO: this does mallocs, we can probably do the mallocs once for
             *       the entire vector set to be more efficient
             */
            acvp_kdf108_init_tc(ctx, &stc, tc_id, kdf_mode, mac_mode,
                                ctr_loc, key_in_str, key_in_len,
                                key_out_len, ctr_len, deferred);

            /* Process the current test vector... */
            rv = (cap->crypto_handler)(&tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("crypto module failed the operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
            */
            rv = acvp_kdf108_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in kdf135 tpm module");
                return rv;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_kdf108_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
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
