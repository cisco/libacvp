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
static ACVP_RESULT acvp_kas_ffc_output_comp_tc (ACVP_CTX *ctx, ACVP_KAS_FFC_TC *stc,
                                               JSON_Object *tc_rsp) {
    ACVP_RESULT rv;
    char *tmp = NULL;

    tmp = calloc(1, ACVP_KAS_FFC_MAX_STR+1);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_output_mct_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->test_type == ACVP_KAS_FFC_TT_VAL) {
        if (!memcmp(stc->z, stc->chash, stc->zlen)) {
            json_object_set_string(tc_rsp, "result", "pass");
        } else {
            json_object_set_string(tc_rsp, "result", "fail");
        }
        return ACVP_SUCCESS;
    }
    
    memset(tmp, 0x0, ACVP_KAS_FFC_MAX_STR);
    rv = acvp_bin_to_hexstr((const unsigned char *)stc->piut, stc->piutlen,
                            tmp);
    if (rv != ACVP_SUCCESS) {
        free(tmp);
        ACVP_LOG_ERR("hex conversion failure (Z)");
        return rv;
    }
    json_object_set_string(tc_rsp, "ephemeralPublicIut", tmp);

    memset(tmp, 0x0, ACVP_KAS_FFC_MAX_STR);
    rv = acvp_bin_to_hexstr((const unsigned char *)stc->chash, stc->chashlen, 
                            tmp);
    if (rv != ACVP_SUCCESS) {
        free(tmp);
        ACVP_LOG_ERR("hex conversion failure (Z)");
        return rv;
    }
    json_object_set_string(tc_rsp, "hashZIut", tmp);

    free(tmp);
    return rv;
}


static ACVP_RESULT acvp_kas_ffc_init_comp_tc (ACVP_CTX *ctx,
                                              ACVP_KAS_FFC_TC *stc,
                                              unsigned int tc_id,
                                              const char *hash,
                                              char *p,
                                              char *q,
                                              char *g,
                                              char *eps,
                                              char *epri,
                                              char *epui,
                                              char *z,
                                              unsigned int mode
) {
    ACVP_RESULT rv;
    stc->mode = mode;
    if (!strcmp(hash, "SHA2-224"))
        stc->md = ACVP_SHA224;
    if (!strcmp(hash, "SHA2-256"))
        stc->md = ACVP_SHA256;
    if (!strcmp(hash, "SHA2-384"))
        stc->md = ACVP_SHA384;
    if (!strcmp(hash, "SHA2-512"))
        stc->md = ACVP_SHA512;
    if (!stc->md) {
        return ACVP_UNSUPPORTED_OP;
    }

    stc->p = calloc(1, ACVP_KAS_FFC_MAX_STR);
    if (!stc->p) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(p, stc->p, ACVP_KAS_FFC_MAX_STR, &(stc->plen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (p)");
        return rv;
    }
    
    stc->q = calloc(1, ACVP_KAS_FFC_MAX_STR);
    if (!stc->q) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(q, stc->q, ACVP_KAS_FFC_MAX_STR, &(stc->qlen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (q)");
        return rv;
    }
    
    stc->g = calloc(1, ACVP_KAS_FFC_MAX_STR);
    if (!stc->g) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(g, stc->g, ACVP_KAS_FFC_MAX_STR, &(stc->glen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (g)");
        return rv;
    }
    
    stc->eps = calloc(1, ACVP_KAS_FFC_MAX_STR);
    if (!stc->eps) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(eps, stc->eps, ACVP_KAS_FFC_MAX_STR, &(stc->epslen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (eps)");
        return rv;
    }
    
    stc->epri = calloc(1, ACVP_KAS_FFC_MAX_STR);
    if (!stc->epri) { return ACVP_MALLOC_FAIL; }
    stc->epui = calloc(1, ACVP_KAS_FFC_MAX_STR);
    if (!stc->epui) { return ACVP_MALLOC_FAIL; }
    stc->chash = calloc(1, ACVP_KAS_FFC_MAX_STR);
    if (!stc->chash) { return ACVP_MALLOC_FAIL; }
    stc->piut = calloc(1, ACVP_KAS_FFC_MAX_STR);
    if (!stc->piut) { return ACVP_MALLOC_FAIL; }
    
    stc->z = calloc(1, ACVP_KAS_FFC_MAX_STR);
    if (!stc->z) { return ACVP_MALLOC_FAIL; }
 
    if (stc->test_type == ACVP_KAS_FFC_TT_VAL) {
        rv = acvp_hexstr_to_bin(z, stc->z, ACVP_KAS_FFC_MAX_STR, &(stc->zlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (z)");
            return rv;
        }
        rv = acvp_hexstr_to_bin(epri, stc->epri, ACVP_KAS_FFC_MAX_STR, &(stc->eprilen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (epri)");
            return rv;
        }
        rv = acvp_hexstr_to_bin(epui, stc->epui, ACVP_KAS_FFC_MAX_STR, &(stc->epuilen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (epui)");
            return rv;
        }
    }
    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kas_ffc_release_tc (ACVP_KAS_FFC_TC *stc) {

    if (stc->piut) free(stc->piut);
    if (stc->epri) free(stc->epri);
    if (stc->epui) free(stc->epui);
    if (stc->eps)free(stc->eps);
    if (stc->z) free(stc->z);
    if (stc->chash) free(stc->chash);
    if (stc->p) free(stc->p);
    if (stc->q) free(stc->q);
    if (stc->g) free(stc->g);
    return ACVP_SUCCESS;
}


static ACVP_RESULT acvp_kas_ffc_comp(ACVP_CTX *ctx, ACVP_CAPS_LIST *cap, ACVP_TEST_CASE *tc,
                                     ACVP_KAS_FFC_TC *stc, JSON_Object *obj, int mode, 
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
    const char *hash;
    char *p = NULL, *q = NULL, *g = NULL, *eps = NULL, *z = NULL, *epri = NULL, *epui = NULL;
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id;
    ACVP_RESULT rv;
    const char *test_type;

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);


    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        hash = json_object_get_string(groupobj, "hashAlg");
        test_type = json_object_get_string(groupobj, "testType");
        if (!test_type) {
            ACVP_LOG_ERR("Unable to parse testType from JSON");
            return ACVP_MALFORMED_JSON;
        }
        if (!strncmp(test_type, "AFT", 3))
            stc->test_type = ACVP_KAS_FFC_TT_AFT;
        if (!strncmp(test_type, "VAL", 3))
            stc->test_type = ACVP_KAS_FFC_TT_VAL;
    

        p = (char *) json_object_get_string(groupobj, "p");
        q = (char *) json_object_get_string(groupobj, "q");
        g = (char *) json_object_get_string(groupobj, "g");
        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("      test type: %s", test_type);
        ACVP_LOG_INFO("           hash: %s", hash);
        ACVP_LOG_INFO("              p: %s", p);
        ACVP_LOG_INFO("              q: %s", q);
        ACVP_LOG_INFO("              g: %s", g);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new KAS-FFC Component test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = (unsigned int) json_object_get_number(testobj, "tcId");

            eps = (char *) json_object_get_string(testobj, "ephemeralPublicServer");
            epri = (char *) json_object_get_string(testobj, "ephemeralPrivateIut");
            epui = (char *) json_object_get_string(testobj, "ephemeralPublicIut");

            z = (char *) json_object_get_string(testobj, "hashZIut");

            ACVP_LOG_INFO("            eps: %s", eps);
            ACVP_LOG_INFO("              z: %s", z);
            ACVP_LOG_INFO("           epri: %s", epri);
            ACVP_LOG_INFO("           epui: %s", epui);


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
            rv = acvp_kas_ffc_init_comp_tc(ctx, stc, tc_id, hash,
                                           p, q, g, eps, epri, epui, z, mode);
            if (rv != ACVP_SUCCESS) {
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /* Process the current KAT test vector... */
            rv = (cap->crypto_handler)(tc);
            if (rv != ACVP_SUCCESS) {
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kas_ffc_output_comp_tc(ctx, stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in KAS-FFC module");
                return rv;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_kas_ffc_release_tc(stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_kas_ffc_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    ACVP_CAPS_LIST *cap;
    ACVP_TEST_CASE tc;
    ACVP_KAS_FFC_TC stc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    int mode = 0;
    char *json_result;
    const char *alg_mode;

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }


    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kas_ffc = &stc;
    memset(&stc, 0x0, sizeof(ACVP_KAS_FFC_TC));

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


    if (!strncmp(alg_mode, "Component", 9)) {
        mode = ACVP_KAS_FFC_MODE_COMPONENT;
        stc.cipher = ACVP_KAS_FFC_COMP;
    }
    if (mode == 0) {
        mode = ACVP_KAS_FFC_MODE_NOCOMP;
        stc.cipher = ACVP_KAS_FFC_NOCOMP;
    }

    switch (mode)
    {
    case ACVP_KAS_FFC_MODE_COMPONENT:
        cap = acvp_locate_cap_entry(ctx, ACVP_KAS_FFC_COMP);
        if (!cap) {
            ACVP_LOG_ERR("ACVP server requesting unsupported capability");
            return ACVP_UNSUPPORTED_OP;
        }
        rv = acvp_kas_ffc_comp(ctx, cap, &tc, &stc, obj, mode, r_tarr);
        break;        
    case ACVP_KAS_FFC_MODE_NOCOMP:
    default:
        ACVP_LOG_ERR("ACVP server requesting unsupported KAS-FFC mode");
        return ACVP_UNSUPPORTED_OP;
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


