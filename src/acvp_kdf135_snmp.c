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
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_kdf135_snmp_output_tc(ACVP_CTX *ctx, ACVP_KDF135_SNMP_TC *stc, JSON_Object *tc_rsp);

static ACVP_RESULT acvp_kdf135_snmp_init_tc(ACVP_CTX *ctx,
                                            ACVP_KDF135_SNMP_TC *stc,
                                            unsigned int tc_id,
                                            ACVP_CIPHER alg_id,
                                            const char *engine_id,
                                            const char *password,
                                            unsigned int p_len);

static ACVP_RESULT acvp_kdf135_snmp_release_tc(ACVP_KDF135_SNMP_TC *stc);


ACVP_RESULT acvp_kdf135_snmp_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_KDF135_SNMP_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    const char *mode_str = NULL;
    ACVP_CIPHER alg_id;
    const char *password = NULL;
    const char *engine_id = NULL;
    unsigned int p_len;
    char *json_result;


    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("unable to parse 'mode' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    alg_id = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != ACVP_KDF135_SNMP) {
        ACVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return ACVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_snmp = &stc;
    stc.cipher = alg_id;

    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
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

        p_len = json_object_get_number(groupobj, "passwordLength");
        if (!p_len) {
            ACVP_LOG_ERR("pLen incorrect, %d", p_len);
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        engine_id = json_object_get_string(groupobj, "engineId");
        if (!engine_id) {
            ACVP_LOG_ERR("Failed to include engineId. ");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        ACVP_LOG_VERBOSE("    Test group: %d", i);
        ACVP_LOG_VERBOSE("          pLen: %d", p_len);
        ACVP_LOG_VERBOSE("      engineID: %s", engine_id);

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
            ACVP_LOG_VERBOSE("Found new hash test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");
            if (!tc_id) {
                ACVP_LOG_ERR("Failed to include tc_id. ");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            password = json_object_get_string(testobj, "password");
            if (!password) {
                ACVP_LOG_ERR("Failed to include password");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
            unsigned int actual_len = strnlen_s(password, ACVP_KDF135_SNMP_PASS_LEN_MAX);
            if (actual_len != p_len / 8) {
                ACVP_LOG_ERR("pLen(%d) or password length(%d) incorrect", p_len, actual_len);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("         password: %s", password);

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
            rv = acvp_kdf135_snmp_init_tc(ctx, &stc, tc_id, alg_id, engine_id, password, p_len);
            if (rv != ACVP_SUCCESS) {
                acvp_kdf135_snmp_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("crypto module failed the operation");
                acvp_kdf135_snmp_release_tc(&stc);
                json_value_free(r_tval);
                rv = ACVP_CRYPTO_MODULE_FAIL;
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kdf135_snmp_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in hash module");
                acvp_kdf135_snmp_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_kdf135_snmp_release_tc(&stc);

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

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_kdf135_snmp_output_tc(ACVP_CTX *ctx, ACVP_KDF135_SNMP_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_KDF135_SNMP_SKEY_MAX + 1, sizeof(char));

    rv = acvp_bin_to_hexstr(stc->s_key, stc->skey_len, tmp, ACVP_KDF135_SNMP_SKEY_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (s_key)");
        goto err;
    }
    json_object_set_string(tc_rsp, "sharedKey", (const char *)tmp);

err:
    free(tmp);
    return rv;
}

static ACVP_RESULT acvp_kdf135_snmp_init_tc(ACVP_CTX *ctx,
                                            ACVP_KDF135_SNMP_TC *stc,
                                            unsigned int tc_id,
                                            ACVP_CIPHER alg_id,
                                            const char *engine_id,
                                            const char *password,
                                            unsigned int p_len) {
    ACVP_RESULT rv;

    memzero_s(stc, sizeof(ACVP_KDF135_SNMP_TC));

    stc->s_key = calloc(ACVP_KDF135_SNMP_SKEY_MAX * 2, sizeof(char));
    if (!stc->s_key) { return ACVP_MALLOC_FAIL; }

    stc->engine_id = calloc(ACVP_KDF135_SNMP_ENGID_MAX_BYTES, sizeof(char));
    if (!stc->engine_id) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(engine_id, stc->engine_id,
                            ACVP_KDF135_SNMP_ENGID_MAX_BYTES, (int*)&stc->engine_id_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (init_nonce)");
        return rv;
    }

    stc->tc_id = tc_id;
    stc->cipher = alg_id;
    stc->p_len = p_len / 8;
    stc->skey_len = 160 / 8;
    stc->password = password;

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf135_snmp_release_tc(ACVP_KDF135_SNMP_TC *stc) {
    if (stc->s_key) free(stc->s_key);
    if (stc->engine_id) free(stc->engine_id);
    memzero_s(stc, sizeof(ACVP_KDF135_SNMP_TC));
    return ACVP_SUCCESS;
}
