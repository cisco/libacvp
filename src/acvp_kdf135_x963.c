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

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_kdf135_x963_output_tc(ACVP_CTX *ctx, ACVP_KDF135_X963_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv;
    char *tmp = NULL;

    tmp = calloc(ACVP_KDF135_X963_KEYDATA_MAX_BYTES + 1, sizeof(char));

    rv = acvp_bin_to_hexstr(stc->key_data, stc->key_data_len, tmp, ACVP_KDF135_X963_KEYDATA_MAX_BYTES);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (key_data)");
        goto err;
    }
    json_object_set_string(tc_rsp, "keyData", (const char *)tmp);
    memzero_s(tmp, ACVP_KDF135_X963_KEYDATA_MAX_BYTES);
err:
    free(tmp);
    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf135_x963_release_tc(ACVP_KDF135_X963_TC *stc) {
    if (stc->z) free(stc->z);
    if (stc->shared_info) free(stc->shared_info);
    if (stc->key_data) free(stc->key_data);
    memzero_s(stc, sizeof(ACVP_KDF135_X963_TC));
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kdf135_x963_init_tc(ACVP_CTX *ctx,
                                            ACVP_KDF135_X963_TC *stc,
                                            unsigned int tc_id,
                                            ACVP_HASH_ALG hash_alg,
                                            int field_size,
                                            int key_data_length,
                                            int shared_info_length,
                                            const char *z,
                                            const char *shared_info) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_KDF135_X963_TC));

    if (!hash_alg || !z || !shared_info) {
        ACVP_LOG_ERR("Missing parameters - initalize KDF135 X963 test case");
        return ACVP_INVALID_ARG;
    }

    stc->tc_id = tc_id;
    stc->hash_alg = hash_alg;
    stc->field_size = ACVP_BIT2BYTE(field_size);
    stc->key_data_len = ACVP_BIT2BYTE(key_data_length);
    stc->shared_info_len = ACVP_BIT2BYTE(shared_info_length);

    stc->z = calloc(ACVP_KDF135_X963_INPUT_MAX, sizeof(char));
    if (!stc->z) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(z, stc->z, ACVP_KDF135_X963_INPUT_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (z)");
        return rv;
    }

    stc->shared_info = calloc(ACVP_KDF135_X963_INPUT_MAX, sizeof(char));
    if (!stc->shared_info) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(shared_info, stc->shared_info, ACVP_KDF135_X963_INPUT_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (shared_info)");
        return rv;
    }

    stc->key_data = calloc(ACVP_KDF135_X963_KEYDATA_MAX_BYTES, sizeof(char));
    if (!stc->key_data) { return ACVP_MALLOC_FAIL; }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_kdf135_x963_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
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
    JSON_Array *r_tarr = NULL, *r_garr = NULL;  /* Response testarray, grouparray */
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_X963_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = NULL;
    const char *mode_str = NULL;
    ACVP_CIPHER alg_id;
    char *json_result;

    int field_size, key_data_length, shared_info_len;
    const char *z = NULL, *shared_info = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    if (!obj) {
        ACVP_LOG_ERR("No obj for handler operation");
        return ACVP_MALFORMED_JSON;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("Server JSON missing 'algorithm'");
        return ACVP_MISSING_ARG;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("Server JSON missing 'mode'");
        return ACVP_MISSING_ARG;
    }
    
    alg_id = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != ACVP_KDF135_X963) {
        ACVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return ACVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_x963 = &stc;
    stc.cipher = alg_id;

    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability %s : %d.", alg_str, alg_id);
        return ACVP_UNSUPPORTED_OP;
    }

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct. ");
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
    json_object_set_string(r_vs, "mode", "ansix9.63");

    groups = json_object_get_array(obj, "testGroups");
    if (!groups) {
        ACVP_LOG_ERR("Failed to include testGroups. ");
        rv = ACVP_MISSING_ARG;
        goto err;
    }

    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        ACVP_HASH_ALG hash_alg = 0;
        const char *hash_alg_str = NULL;

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

        field_size = json_object_get_number(groupobj, "fieldSize");
        if (!field_size) {
            ACVP_LOG_ERR("Failed to include field size. ");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        key_data_length = json_object_get_number(groupobj, "keyDataLength");
        if (!key_data_length) {
            ACVP_LOG_ERR("Failed to include key data length. ");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        shared_info_len = json_object_get_number(groupobj, "sharedInfoLength");

        hash_alg_str = json_object_get_string(groupobj, "hashAlg");
        if (!hash_alg_str) {
            ACVP_LOG_ERR("Failed to include hashAlg. ");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        hash_alg = acvp_lookup_hash_alg(hash_alg_str);
        if (hash_alg != ACVP_SHA224 && hash_alg != ACVP_SHA256 &&
            hash_alg != ACVP_SHA384 && hash_alg != ACVP_SHA512) {
            ACVP_LOG_ERR("Server JSON invalid 'hashAlg'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        ACVP_LOG_VERBOSE("\n    Test group: %d", i);
        ACVP_LOG_VERBOSE("         hashAlg: %s", hash_alg_str);
        ACVP_LOG_VERBOSE("       fieldSize: %d", field_size);
        ACVP_LOG_VERBOSE("   sharedInfoLen: %d", shared_info_len);
        ACVP_LOG_VERBOSE("   keyDataLength: %d", key_data_length);

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
            ACVP_LOG_VERBOSE("Found new KDF135 X963 test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");
            if (!tc_id) {
                ACVP_LOG_ERR("Failed to include tc_id. ");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            z = json_object_get_string(testobj, "z");
            shared_info = json_object_get_string(testobj, "sharedInfo");
            if (!z) {
                ACVP_LOG_ERR("Failed to include z. ");
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            if (!shared_info) {
                ACVP_LOG_ERR("Failed to include shared_info. ");
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);

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
            rv = acvp_kdf135_x963_init_tc(ctx, &stc, tc_id, hash_alg,
                                          field_size, key_data_length,
                                          shared_info_len, z, shared_info);
            if (rv != ACVP_SUCCESS) {
                acvp_kdf135_x963_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("crypto module failed the KDF SSH operation");
                acvp_kdf135_x963_release_tc(&stc);
                rv = ACVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kdf135_x963_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in hash module");
                acvp_kdf135_x963_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_kdf135_x963_release_tc(&stc);

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
