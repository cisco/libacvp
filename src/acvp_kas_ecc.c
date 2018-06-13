/*****************************************************************************
* Copyright (c) 2018, Cisco Systems, Inc.
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
static ACVP_RESULT acvp_kas_ecc_output_cdh_tc (ACVP_CTX *ctx, ACVP_KAS_ECC_TC *stc,
                                               JSON_Object *tc_rsp) {
    ACVP_RESULT rv;
    char *tmp;

    tmp = calloc(1, ACVP_KAS_ECC_MAX);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_output_mct_tc");
        return ACVP_MALLOC_FAIL;
    }

    json_object_set_string(tc_rsp, "publicIutX", stc->pix);

    json_object_set_string(tc_rsp, "publicIutY", stc->piy);

    memset(tmp, 0x0, ACVP_KAS_ECC_MAX);
    rv = acvp_bin_to_hexstr((const unsigned char *)stc->z, stc->zlen, (unsigned char *) tmp);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (Z)");
        return rv;
    }
    json_object_set_string(tc_rsp, "z", tmp);
    free(tmp);
    return rv;
}

static ACVP_RESULT acvp_kas_ecc_init_cdh_tc (ACVP_CTX *ctx,
                                            ACVP_KAS_ECC_TC *stc,
                                            unsigned int tc_id,
                                            const char *curve,
                                            char *psx,
                                            char *psy,
                                            unsigned int mode
) {

    stc->mode = mode;

    stc->psx = calloc(1, ACVP_KAS_ECC_MAX);
    if (!stc->psx) { return ACVP_MALLOC_FAIL; }
    stc->psy = calloc(1, ACVP_KAS_ECC_MAX);
    if (!stc->psy) { return ACVP_MALLOC_FAIL; }

    stc->z = calloc(1, ACVP_KAS_ECC_MAX);
    if (!stc->z) { return ACVP_MALLOC_FAIL; }
    stc->d = calloc(1, ACVP_KAS_ECC_MAX);
    if (!stc->d) { return ACVP_MALLOC_FAIL; }

    strncpy(stc->psx, psx, strlen((char *)psx));
    strncpy(stc->psy, psy, strlen((char *)psy));

    if (!strcmp(curve, "b-233"))
        stc->curve = ACVP_ECDSA_CURVE_B233;
    if (!strcmp(curve, "b-283"))
        stc->curve = ACVP_ECDSA_CURVE_B283;
    if (!strcmp(curve, "b-409"))
        stc->curve = ACVP_ECDSA_CURVE_B409;
    if (!strcmp(curve, "b-571"))
        stc->curve = ACVP_ECDSA_CURVE_B571;
    if (!strcmp(curve, "k-233"))
        stc->curve = ACVP_ECDSA_CURVE_K233;
    if (!strcmp(curve, "k-283"))
        stc->curve = ACVP_ECDSA_CURVE_K283;
    if (!strcmp(curve, "k-409"))
        stc->curve = ACVP_ECDSA_CURVE_K409;
    if (!strcmp(curve, "k-571"))
        stc->curve = ACVP_ECDSA_CURVE_K571;
    if (!strcmp(curve, "p-224"))
        stc->curve = ACVP_ECDSA_CURVE_P224;
    if (!strcmp(curve, "p-256"))
        stc->curve = ACVP_ECDSA_CURVE_P256;
    if (!strcmp(curve, "p-384"))
        stc->curve = ACVP_ECDSA_CURVE_P384;
    if (!strcmp(curve, "p-521"))
        stc->curve = ACVP_ECDSA_CURVE_P521;

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kas_ecc_release_tc (ACVP_KAS_ECC_TC *stc) {

    free(stc->psx);
    free(stc->psy);
    free(stc->pix);
    free(stc->piy);
    free(stc->d);
    free(stc->z);
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kas_ecc_cdh(ACVP_CTX *ctx, ACVP_CAPS_LIST *cap, ACVP_TEST_CASE *tc,
                                    ACVP_KAS_ECC_TC *stc, JSON_Object *obj, int mode, 
                                    JSON_Array *r_tarr)
{
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Array *groups;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *tests;
    JSON_Value *r_tval = NULL; /* Response testval */
    JSON_Object *r_tobj = NULL; /* Response testobj */
    const char *curve;
    char *psx;
    char *psy;
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id;
    ACVP_RESULT rv;

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);


    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        curve = json_object_get_string(groupobj, "curve");

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("          curve: %s", curve);


        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new KAS-ECC CDH test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = (unsigned int) json_object_get_number(testobj, "tcId");

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            psx = (char *) json_object_get_string(testobj, "publicServerX");
            psy = (char *) json_object_get_string(testobj, "publicServerY");

            ACVP_LOG_INFO("            psx: %s", psx);
            ACVP_LOG_INFO("            psy: %s", psy);
  
            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             * TODO: this does mallocs, we can probably do the mallocs once for
             *       the entire vector set to be more efficient
             */
            acvp_kas_ecc_init_cdh_tc(ctx, stc, tc_id, curve, 
                                     psx, psy, mode);

            /* Process the current AES KAT test vector... */
            rv = (cap->crypto_handler)(tc);
            if (rv != ACVP_SUCCESS) {
                    return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kas_ecc_output_cdh_tc(ctx, stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in AES module");
                return rv;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_kas_ecc_release_tc(stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_kas_ecc_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {

    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    ACVP_CAPS_LIST *cap;
    ACVP_TEST_CASE tc;
    ACVP_KAS_ECC_TC stc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER alg_id;
    int mode;
    char *json_result;
    const char *alg_mode;

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }

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
     * Get a reference to the abstracted test case
     */
    tc.tc.kas_ecc = &stc;
    memset(&stc, 0x0, sizeof(ACVP_KAS_ECC_TC));

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

    alg_mode = json_object_get_string(obj, "mode");
    json_object_set_string(r_vs, "mode", alg_mode);
    json_object_set_value(r_vs, "testResults", json_value_init_array());
    r_tarr = json_object_get_array(r_vs, "testResults");

    stc.cipher = alg_id;

    if (!strncmp(alg_mode, "CDH-Component", 13))
        mode = ACVP_KAS_ECC_MODE_CDH;
    if (!strncmp(alg_mode, "Component", 9))
        mode = ACVP_KAS_ECC_MODE_COMPONENT;
    if (mode == 0)
        mode = ACVP_KAS_ECC_MODE_NONE;

    switch (mode)
    {
    case ACVP_KAS_ECC_MODE_CDH:
        rv = acvp_kas_ecc_cdh(ctx, cap, &tc, &stc, obj, mode, r_tarr);
        break;        
    case ACVP_KAS_ECC_MODE_COMPONENT:
    case ACVP_KAS_ECC_MODE_NONE:
    default:
        break;
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

