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
static ACVP_RESULT acvp_kdf135_tpm_output_tc (ACVP_CTX *ctx, ACVP_KDF135_TPM_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv;
    char *tmp;
    
    tmp = calloc(1, ACVP_KDF135_TPM_SKEY_MAX);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_kdf135 tpm_output_tc");
        return ACVP_MALLOC_FAIL;
    }
    
    rv = acvp_bin_to_hexstr(stc->s_key, stc->skey_len, (unsigned char *) tmp);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (s_key)");
        return rv;
    }
    json_object_set_string(tc_rsp, "sKey", tmp);
    
    free(tmp);
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kdf135_tpm_init_tc (ACVP_CTX *ctx,
                                            ACVP_KDF135_TPM_TC *stc,
                                            unsigned int tc_id,
                                            char *auth,
                                            char *nonce_even,
                                            char *nonce_odd
) {
    memset(stc, 0x0, sizeof(ACVP_KDF135_TPM_TC));
    
    stc->auth = calloc(strlen(auth), sizeof(char));
    if (!stc->auth) { return ACVP_MALLOC_FAIL; }
    
    stc->nonce_even = calloc(strlen(nonce_even), sizeof(char));
    if (!stc->nonce_even) { return ACVP_MALLOC_FAIL; }
    
    stc->nonce_odd = calloc(strlen(nonce_odd), sizeof(char));
    if (!stc->nonce_odd) { return ACVP_MALLOC_FAIL; }
    
    stc->s_key = calloc(ACVP_KDF135_TPM_SKEY_MAX, sizeof(char));
    if (!stc->s_key) { return ACVP_MALLOC_FAIL; }
    
    memset(stc->s_key, 0, ACVP_KDF135_TPM_SKEY_MAX);
    
    stc->tc_id = tc_id;
    stc->cipher = ACVP_KDF135_TPM;
    stc->auth = auth;
    stc->nonce_odd = nonce_odd;
    stc->nonce_even = nonce_even;
    
    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf135_tpm_release_tc (ACVP_KDF135_TPM_TC *stc) {
    free((void *) stc->auth);
    free(stc->s_key);
    free(stc->nonce_even);
    free(stc->nonce_odd);
    
    memset(stc, 0x0, sizeof(ACVP_KDF135_TPM_TC));
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_kdf135_tpm_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_KDF135_TPM_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER alg_id;
    char *auth = NULL, *nonce_even = NULL, *nonce_odd = NULL;
    char *json_result;

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_tpm = &stc;

    /*
     * Get the crypto module handler for this hash algorithm
     */
    alg_id = acvp_lookup_cipher_index(alg_str);
    if (alg_id < ACVP_CIPHER_START) {
        ACVP_LOG_ERR("unsupported algorithm (%s)", alg_str);
        return (ACVP_UNSUPPORTED_OP);
    }
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

        ACVP_LOG_INFO("    Test group: %d", i);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new kdf135 tpm test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int) json_object_get_number(testobj, "tcId");
            auth = json_object_get_string(testobj, "auth");
            nonce_even = json_object_get_string(testobj, "nonceEven");
            nonce_odd = json_object_get_string(testobj, "nonceOdd");

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            ACVP_LOG_INFO("             auth: %d", auth);
            ACVP_LOG_INFO("       nonce_even: %d", nonce_even);
            ACVP_LOG_INFO("        nonce_odd: %d", nonce_odd);

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
            acvp_kdf135_tpm_init_tc(ctx, &stc, tc_id, auth, nonce_even, nonce_odd);

            /* Process the current test vector... */
            rv = (cap->crypto_handler)(&tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("crypto module failed the operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
            */
            rv = acvp_kdf135_tpm_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in kdf135 tpm module");
                return rv;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_kdf135_tpm_release_tc(&stc);

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
