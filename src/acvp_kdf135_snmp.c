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
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_kdf135_snmp_output_tc(ACVP_CTX *ctx, ACVP_KDF135_SNMP_TC *stc, JSON_Object *tc_rsp);

static ACVP_RESULT acvp_kdf135_snmp_init_tc(ACVP_CTX *ctx,
                                            ACVP_KDF135_SNMP_TC *stc,
                                            unsigned int tc_id,
                                            ACVP_CIPHER alg_id,
                                            char *engine_id,
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
    ACVP_CIPHER alg_id;
    const char *password = NULL;
    char *engine_id = NULL;
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

    if (strncmp(alg_str, "kdf-components", 14)) {
        ACVP_LOG_ERR("Invalid algorithm for this function %s", alg_str);
        return ACVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_snmp = &stc;
    alg_id = ACVP_KDF135_SNMP;
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

        p_len = (unsigned int)json_object_get_number(groupobj, "passwordLength");
        if (!p_len) {
            ACVP_LOG_ERR("pLen incorrect, %d", p_len);
            return ACVP_INVALID_ARG;
        }

        engine_id = (char *)json_object_get_string(groupobj, "engineId");
        if (!engine_id) {
            ACVP_LOG_ERR("Failed to include engineId. ");
            return ACVP_MISSING_ARG;
        }

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("          pLen: %d", p_len);
        ACVP_LOG_INFO("      engineID: %s", engine_id);

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

            password = json_object_get_string(testobj, "password");
            if (!password) {
                ACVP_LOG_ERR("Failed to include password");
                return ACVP_MISSING_ARG;
            }
            int actual_len = strnlen(password, ACVP_KDF135_SNMP_PASSWORD_MAX);
            if (actual_len != p_len) {
                ACVP_LOG_ERR("pLen(%d) or password length(%d) incorrect", p_len, actual_len);
                return ACVP_INVALID_ARG;
            }

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            ACVP_LOG_INFO("         password: %s", password);

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
                return rv;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("crypto module failed the operation");
                acvp_kdf135_snmp_release_tc(&stc);
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kdf135_snmp_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in hash module");
                acvp_kdf135_snmp_release_tc(&stc);
                return rv;
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

    json_result = json_serialize_to_string_pretty(ctx->kat_resp);
    if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
        printf("\n\n%s\n\n", json_result);
    } else {
        ACVP_LOG_INFO("\n\n%s\n\n", json_result);
    }
    json_free_serialized_string(json_result);

    return ACVP_SUCCESS;
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
                                            char *engine_id,
                                            const char *password,
                                            unsigned int p_len) {
    ACVP_RESULT rv;

    memset(stc, 0x0, sizeof(ACVP_KDF135_SNMP_TC));

    stc->s_key = calloc(ACVP_KDF135_SNMP_SKEY_MAX * 2, sizeof(char));
    if (!stc->s_key) { return ACVP_MALLOC_FAIL; }

    stc->tc_id = tc_id;
    stc->cipher = alg_id;
    stc->p_len = p_len;
    stc->password = password;
    stc->engine_id_str = engine_id;
    stc->engine_id = calloc(ACVP_KDF135_SNMP_ENGID_MAX_BYTES, sizeof(char));
    stc->skey_len = 160 / 8;
    if (!stc->engine_id) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(engine_id, stc->engine_id, ACVP_KDF135_SNMP_ENGID_MAX_BYTES, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (init_nonce)");
        return rv;
    }

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf135_snmp_release_tc(ACVP_KDF135_SNMP_TC *stc) {
    free(stc->s_key);
    free(stc->engine_id);
    memset(stc, 0x0, sizeof(ACVP_KDF135_SNMP_TC));
    return ACVP_SUCCESS;
}
