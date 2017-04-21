/** @file */
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
static ACVP_RESULT acvp_drbg_output_tc(ACVP_CTX *ctx, ACVP_DRBG_TC *stc, JSON_Object *tc_rsp);
static ACVP_RESULT acvp_drbg_init_tc(ACVP_CTX *ctx,
        ACVP_DRBG_TC *stc,
        unsigned int tc_id,
        unsigned char  *additional_input,
        unsigned char  *entropy_input_pr,
        unsigned char  *additional_input_1,
        unsigned char  *entropy_input_pr_1,
        unsigned char  *perso_string,
        unsigned char  *entropy,
        unsigned char  *nonce,
        unsigned int    der_func_enabled,
        unsigned int    pred_resist_enabled,
        unsigned int    additional_input_len,
        unsigned int    perso_string_len,
        unsigned int    entropy_len,
        unsigned int    nonce_len,
        unsigned int    drb_len,
        ACVP_DRBG_MODE  mode_id,
        ACVP_CIPHER     alg_id);
static ACVP_RESULT acvp_drbg_release_tc(ACVP_DRBG_TC *stc);

//handle array values
ACVP_RESULT acvp_drbg_kat_handler(ACVP_CTX *ctx, JSON_Object *obj)
{
    unsigned int tc_id;
    unsigned char  *additional_input   = NULL;
    unsigned char  *entropy_input_pr   = NULL;
    unsigned char  *additional_input_1 = NULL;
    unsigned char  *entropy_input_pr_1 = NULL;
    unsigned char  *perso_string;
    unsigned char  *entropy;
    unsigned char  *nonce;
    unsigned int    additional_input_len   = 0;
    unsigned int    perso_string_len;
    unsigned int    entropy_len = 0;
    unsigned int    nonce_len = 0;
    unsigned int    drb_len = 0;
    unsigned int    der_func_enabled;
    unsigned int    pred_resist_enabled;

    char            *der_func_str;
    char            *pred_resist_str;

    JSON_Value          *reg_arry_val  = NULL;
    JSON_Object         *reg_obj       = NULL;
    JSON_Array          *reg_arry      = NULL;

    JSON_Value          *groupval;
    JSON_Object         *groupobj = NULL;
    JSON_Value          *testval;
    JSON_Object         *testobj = NULL;
    JSON_Array          *groups;
    JSON_Array          *tests;
    JSON_Array          *pred_resist_input;
    int i, g_cnt;
    int j, t_cnt;
    JSON_Value          *r_vs_val = NULL;
    JSON_Object         *r_vs = NULL;
    JSON_Array          *r_tarr = NULL; /* Response testarray */
    JSON_Value          *r_tval = NULL; /* Response testval */
    JSON_Object         *r_tobj = NULL; /* Response testobj */
    ACVP_CAPS_LIST      *cap;
    ACVP_DRBG_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char          *alg_str = json_object_get_string(obj, "algorithm");
    char                *mode_str = (char *)json_object_get_string(obj, "mode");
    ACVP_CIPHER	        alg_id;
    ACVP_DRBG_MODE      mode_id;

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }

    if (!mode_str) {
        ACVP_LOG_ERR("unable to parse DRBG 'mode' from JSON");
        return (ACVP_MALFORMED_JSON);
    }

    ACVP_LOG_INFO("    DRBG alg: %s", alg_str);

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.drbg = &stc;

    /*
     * Get the crypto module handler for this DRBG algorithm
     */
    alg_id = acvp_lookup_cipher_index(alg_str);
    if ((alg_id < ACVP_HASHDRBG) || (alg_id > ACVP_CTRDRBG)) {
        ACVP_LOG_ERR("unsupported algorithm (%s)", alg_str);
        return (ACVP_UNSUPPORTED_OP);
    }
    /*
     * Get DRBG Mode index
     */
    mode_id = acvp_lookup_drbg_mode_index(mode_str);
    if (mode_id == ACVP_DRBG_MODE_END) {
        ACVP_LOG_ERR("unsupported DRBG mode (%s)", mode_str);
        return (ACVP_UNSUPPORTED_OP);
    }

    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        return (ACVP_UNSUPPORTED_OP);
    }

    mode_str              = (char*)json_object_get_string(obj, "mode");

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct. ");
        return(rv);
    }

    /*
     * Start to build the JSON response
     * TODO: This code will likely be common to all the algorithms, need to move this
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
    ACVP_LOG_INFO("Number of TestGroups: %d", g_cnt);
    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        char *reg = json_serialize_to_string_pretty(groupval);
        ACVP_LOG_INFO("json groupval count: %d\n %s\n", i, reg);

        /*
         * Handle Group Params
         */
        der_func_str          = (char*)json_object_get_string(groupobj, "derFunc");
        pred_resist_str       = (char*)json_object_get_string(groupobj, "predResistance");
        entropy_len           = (unsigned int)json_object_get_number(groupobj, "entropyInputLen");
        nonce_len             = (unsigned int)json_object_get_number(groupobj, "nonceLen");
        perso_string_len      = (unsigned int)json_object_get_number(groupobj, "persoStringLen");
        drb_len               = (unsigned int)json_object_get_number(groupobj, "returnedBitsLen");

        if ((!der_func_str) || (!pred_resist_str))
        {
            ACVP_LOG_ERR("ACVP server requesting unsupported PR or DF capability");
            return (ACVP_UNSUPPORTED_OP);
        }

        der_func_enabled      = yes_or_no(ctx, der_func_str);
        pred_resist_enabled   = yes_or_no(ctx, pred_resist_str);


        if (pred_resist_enabled) {
            additional_input_len  = json_object_get_number(groupobj, "additionalInputLen");
        }

        ACVP_LOG_INFO("    Test group:");
        ACVP_LOG_INFO("    DRBG mode: %s", mode_str);
        ACVP_LOG_INFO("    derFunc: %s", der_func_str);
        ACVP_LOG_INFO("    predResistance: %s", pred_resist_str);
        ACVP_LOG_INFO("    entropyInputLen: %d", entropy_len);
        ACVP_LOG_INFO("    additionalInputLen: %d", additional_input_len);
        ACVP_LOG_INFO("    persoStringLen: %d", perso_string_len);
        ACVP_LOG_INFO("    nonceLen: %d", nonce_len);
        ACVP_LOG_INFO("    returnedBitsLen: %d", drb_len);
        //TODO: Sanity check alg/mode mismatch

        /*
         * Handle test array
         */
        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        ACVP_LOG_INFO("Number of Tests: %d", g_cnt);
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new DRBG test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            reg = json_serialize_to_string_pretty(testval);

            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");

            perso_string = (unsigned char *)json_object_get_string(testobj, "persoString");
            entropy = (unsigned char *)json_object_get_string(testobj, "entropyInput");
            nonce = (unsigned char *)json_object_get_string(testobj, "nonce");

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            ACVP_LOG_INFO("             entropyInput: %s", entropy);
            ACVP_LOG_INFO("             perso_string: %s", perso_string);
            ACVP_LOG_INFO("             nonce: %s", nonce);

            /*
             * Handle pred_resist_input array. Has at most 2 elements
             */
            pred_resist_input = json_object_get_array(testobj, "predResistanceInput");
            int pr_input_cnt = json_array_get_count(pred_resist_input);
            JSON_Value   *pr_input_val;
            JSON_Object  *pr_input_obj;

            int pr_i = 0;
            ACVP_LOG_INFO("Found new DRBG Prediction Input...");
            pr_input_val = json_array_get_value(pred_resist_input, pr_i);
            pr_input_obj = json_value_get_object(pr_input_val);

            additional_input = (unsigned char *)json_object_get_string(pr_input_obj, "additionalInput");
            entropy_input_pr = (unsigned char *)json_object_get_string(pr_input_obj, "entropyInputPR");

            /*
             * Get 2nd element from the array
             */
            if (pr_input_cnt == 2) {
                pr_i = pr_i + 1;
                pr_input_val = json_array_get_value(pred_resist_input, pr_i);
                pr_input_obj = json_value_get_object(pr_input_val);
                additional_input_1 = (unsigned char *)json_object_get_string(pr_input_obj, "additionalInput");
                entropy_input_pr_1 = (unsigned char *)json_object_get_string(pr_input_obj, "entropyInputPR");
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
             * TODO: this does mallocs, we can probably do the mallocs once for
             *       the entire vector set to be more efficient
             */
            acvp_drbg_init_tc(ctx, &stc, tc_id, additional_input,
                    entropy_input_pr,
                    additional_input_1,
                    entropy_input_pr_1,
                    perso_string,
                    entropy,
                    nonce,
                    der_func_enabled,
                    pred_resist_enabled,
                    additional_input_len,
                    perso_string_len,
                    entropy_len,
                    nonce_len,
                    drb_len,
                    mode_id,
                    alg_id);

            /* Process the current test vector... */
            rv = (cap->crypto_handler)(&tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("crypto module failed the operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_drbg_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in DRBG module");
                return rv;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_drbg_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);

        }
    }
    json_array_append_value(reg_arry, r_vs_val);

    ACVP_LOG_INFO("\n\n%s\n\n", json_serialize_to_string_pretty(ctx->kat_resp));

    return ACVP_SUCCESS;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_drbg_output_tc(ACVP_CTX *ctx, ACVP_DRBG_TC *stc, JSON_Object *tc_rsp)
{
    ACVP_RESULT rv;
    char *tmp = NULL;

    tmp = calloc(1, 2*ACVP_DRB_MAX);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_drbg_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(stc->drb, stc->drb_len, (unsigned char*)tmp);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (returnedBits)");
        return rv;
    }
    json_object_set_string(tc_rsp, "returnedBits", tmp);

    free(tmp);

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_drbg_init_tc(ACVP_CTX *ctx,
        ACVP_DRBG_TC *stc,
        unsigned int tc_id,
        unsigned char  *additional_input,
        unsigned char  *entropy_input_pr,
        unsigned char  *additional_input_1,
        unsigned char  *entropy_input_pr_1,
        unsigned char  *perso_string,
        unsigned char  *entropy,
        unsigned char  *nonce,
        unsigned int    der_func_enabled,
        unsigned int    pred_resist_enabled,
        unsigned int    additional_input_len,
        unsigned int    perso_string_len,
        unsigned int    entropy_len,
        unsigned int    nonce_len,
        unsigned int    drb_len,
        ACVP_DRBG_MODE  mode_id,
        ACVP_CIPHER     alg_id)
{
    ACVP_RESULT rv;
    memset(stc, 0x0, sizeof(ACVP_DRBG_TC));

    //TODO Verify that these MAX values are correct.

    stc->drb = calloc(1, ACVP_DRB_MAX);
    if (!stc->drb) return ACVP_MALLOC_FAIL;
    stc->additional_input = calloc(1, ACVP_DRBG_ADDI_IN_MAX);
    if (!stc->additional_input) return ACVP_MALLOC_FAIL;
    stc->additional_input_1 = calloc(1, ACVP_DRBG_ADDI_IN_MAX);
    if (!stc->additional_input_1) return ACVP_MALLOC_FAIL;
    stc->entropy = calloc(1, ACVP_DRBG_ENTPY_IN_MAX);
    if (!stc->entropy) return ACVP_MALLOC_FAIL;
    stc->entropy_input_pr = calloc(1, ACVP_DRBG_ENTPY_IN_MAX);
    if (!stc->entropy_input_pr) return ACVP_MALLOC_FAIL;
    stc->entropy_input_pr_1 = calloc(1, ACVP_DRBG_ENTPY_IN_MAX);
    if (!stc->entropy_input_pr_1) return ACVP_MALLOC_FAIL;
    stc->nonce = calloc(1, ACVP_DRBG_NONCE_MAX);
    if (!stc->nonce) return ACVP_MALLOC_FAIL;
    stc->perso_string = calloc(1, ACVP_DRBG_PER_SO_MAX);
    if (!stc->perso_string) return ACVP_MALLOC_FAIL;


    if (additional_input) {
        rv = acvp_hexstr_to_bin((const unsigned char *)additional_input,
                stc->additional_input, ACVP_DRBG_ADDI_IN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (additional_input)");
            return rv;
        }
    }

    if (entropy_input_pr) {
        rv = acvp_hexstr_to_bin((const unsigned char *)entropy_input_pr,
                stc->entropy_input_pr, ACVP_DRBG_ENTPY_IN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (entropy_input_pr)");
            return rv;
        }
    }

    if (additional_input_1) {
        rv = acvp_hexstr_to_bin((const unsigned char *)additional_input_1,
                stc->additional_input_1, ACVP_DRBG_ADDI_IN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (2nd additional_input)");
            return rv;
        }
    }

    if (entropy_input_pr_1) {
        rv = acvp_hexstr_to_bin((const unsigned char *)entropy_input_pr_1,
                stc->entropy_input_pr_1, ACVP_DRBG_ENTPY_IN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (2nd entropy_input_pr)");
            return rv;
        }
    }

    if (entropy) {
        rv = acvp_hexstr_to_bin((const unsigned char *)entropy,
                stc->entropy, ACVP_DRBG_ENTPY_IN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (entropy)");
            return rv;
        }
    }

    if (perso_string) {
        rv = acvp_hexstr_to_bin((const unsigned char *)perso_string,
                stc->perso_string, ACVP_DRBG_PER_SO_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (perso_string)");
            return rv;
        }
    }

    if (nonce) {
        rv = acvp_hexstr_to_bin((const unsigned char *)nonce,
                stc->nonce, ACVP_DRBG_NONCE_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (nonce)");
            return rv;
        }
    }

    stc->additional_input_len = additional_input_len;
    stc->pred_resist_enabled = pred_resist_enabled;
    stc->perso_string_len = perso_string_len;
    stc->der_func_enabled = der_func_enabled;
    stc->entropy_len = entropy_len;
    stc->nonce_len = nonce_len;
    stc->drb_len = drb_len;
    stc->tc_id = tc_id;
    stc->mode = mode_id;
    stc->cipher = alg_id;

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_drbg_release_tc(ACVP_DRBG_TC *stc)
{
    free(stc->drb);
    free(stc->additional_input);
    free(stc->additional_input_1);
    free(stc->entropy);
    free(stc->entropy_input_pr);
    free(stc->entropy_input_pr_1);
    free(stc->nonce);
    free(stc->perso_string);

    memset(stc, 0x0, sizeof(ACVP_DRBG_TC));
    return ACVP_SUCCESS;
}
