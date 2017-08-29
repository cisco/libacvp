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

static ACVP_RESULT acvp_dsa_init_tc(ACVP_CTX *ctx,
                                    ACVP_DSA_TC *stc,
                                    unsigned int tc_id,
                                    ACVP_CIPHER alg_id,
                                    unsigned int gpq,
                                    unsigned int num,
                                    unsigned char *index,
                                    unsigned char *ln,
                                    unsigned char *sha,
                                    unsigned char *p,
                                    unsigned char *q,
                                    unsigned char *seed
                                    )
{
    ACVP_DSA_PQGGEN_TC *pqggen;
    ACVP_RESULT        rv;
    
    switch (stc->mode) {
    case ACVP_DSA_MODE_PQGGEN:
        stc->mode_tc.pqggen = calloc(1, sizeof(ACVP_DSA_PQGGEN_TC));
        if (!stc->mode_tc.pqggen) return ACVP_MALLOC_FAIL;

        pqggen = stc->mode_tc.pqggen;

        if (!strncmp((char *)ln, "2048-224", 8)) {
            pqggen->l = 2048;
            pqggen->n = 224;
        }
        if (!strncmp((char *)ln, "2048-256", 8)) {
            pqggen->l = 2048;
            pqggen->n = 256;
        }
        if (!strncmp((char *)ln, "3072-256", 8)) {
            pqggen->l = 3072;
            pqggen->n = 256;
        }
        if (pqggen->l == 0) {
            return  ACVP_INVALID_ARG;
        }

        if (!strncmp((char *)sha, "SHA-1", 5)) {
            pqggen->sha = ACVP_DSA_SHA1;
        }
        if (!strncmp((char *)sha, "SHA-224", 7)) {
            pqggen->sha = ACVP_DSA_SHA224;
        }
        if (!strncmp((char *)sha, "SHA-256", 7)) {
            pqggen->sha = ACVP_DSA_SHA256;
        }
        if (!strncmp((char *)sha, "SHA-384", 7)) {
            pqggen->sha = ACVP_DSA_SHA384;
        }
        if (!strncmp((char *)sha, "SHA-512", 7)) {
            pqggen->sha = ACVP_DSA_SHA512;
        }
        if (!strncmp((char *)sha, "SHA-512_224", 11)) {
            pqggen->sha = ACVP_DSA_SHA512_224;
        }
        if (!strncmp((char *)sha, "SHA-512_256", 11)) {
            pqggen->sha = ACVP_DSA_SHA512_256;
        }
        if (pqggen->sha == 0) {
            return  ACVP_INVALID_ARG;
        }

        pqggen->p = calloc(1, ACVP_DSA_PQG_MAX);
        if (!pqggen->p) return ACVP_MALLOC_FAIL;
        pqggen->q = calloc(1, ACVP_DSA_PQG_MAX);
        if (!pqggen->q) return ACVP_MALLOC_FAIL;
        pqggen->g = calloc(1, ACVP_DSA_PQG_MAX);
        if (!pqggen->g) return ACVP_MALLOC_FAIL;
        pqggen->seed = calloc(1, ACVP_DSA_SEED_MAX);
        if (!pqggen->seed) return ACVP_MALLOC_FAIL;

        pqggen->gen_pq = gpq;        
        switch (gpq)
        {
        case ACVP_DSA_CANONICAL:
            pqggen->index = strtol((char *)index, NULL, 16);     
            rv = acvp_hexstr_to_bin((const unsigned char *)seed, pqggen->seed, ACVP_DSA_SEED_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (seed)");
                return rv;
            }
            pqggen->seedlen = strlen((char *)pqggen->seed);
            pqggen->p = p;
            pqggen->q = q;
            break;
        case ACVP_DSA_UNVERIFIABLE:
            pqggen->p = p;
            pqggen->q = q;
            break;
        case ACVP_DSA_PROBABLE:
        case ACVP_DSA_PROVABLE:
            pqggen->num = num;
            break;
        default:
            ACVP_LOG_ERR("Invalid GPQ argument %d", gpq);
            return ACVP_INVALID_ARG;
            break;
        }
	break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_dsa_output_tc(ACVP_CTX *ctx, ACVP_DSA_TC *stc, JSON_Object *r_tobj)
{
    ACVP_DSA_PQGGEN_TC *pqggen;
    ACVP_RESULT        rv;
    char               *tmp = NULL;

    switch(stc->mode)
        {
        case ACVP_DSA_MODE_PQGGEN:
            pqggen = stc->mode_tc.pqggen;
            switch (pqggen->gen_pq)
            {
            case ACVP_DSA_CANONICAL: 
            case ACVP_DSA_UNVERIFIABLE: 
                json_object_set_string(r_tobj, "g", (char *)pqggen->g);
                break;
            case ACVP_DSA_PROBABLE:
            case ACVP_DSA_PROVABLE:
                tmp = calloc(1, ACVP_DSA_PQG_MAX);
                if (!tmp) {
                    ACVP_LOG_ERR("Unable to malloc in acvp_aes_mct_output_tc");
                    return ACVP_MALLOC_FAIL;
                }

                json_object_set_string(r_tobj, "p", (char *)pqggen->p);

                json_object_set_string(r_tobj, "q", (char *)pqggen->q);

                memset(tmp, 0x0, ACVP_DSA_SEED_MAX);
                rv = acvp_bin_to_hexstr(pqggen->seed, pqggen->seedlen, (unsigned char*)tmp);
                if (rv != ACVP_SUCCESS) {
	            ACVP_LOG_ERR("hex conversion failure (p)");
	            return rv;
                }
                json_object_set_string(r_tobj, "seed", tmp);

                json_object_set_number(r_tobj, "counter", pqggen->counter);
                break;
            default:
                ACVP_LOG_ERR("Invalid mode argument %d", stc->mode);
                return ACVP_INVALID_ARG;
                break;
            }    
            break;
        default:
            break;
    }

    free(tmp);
    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_dsa_release_tc(ACVP_DSA_TC *stc)
{

    switch (stc->mode)
    {
    case ACVP_DSA_MODE_PQGGEN:
        free(stc->mode_tc.pqggen->p);
        free(stc->mode_tc.pqggen->q);
        free(stc->mode_tc.pqggen->g);
        free(stc->mode_tc.pqggen->seed);
        free(stc->mode_tc.pqggen);
        break;

    default:
        break;
    }

    memset(stc, 0x0, sizeof(ACVP_DSA_TC));
        
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_dsa_pqggen_handler (ACVP_CTX *ctx, ACVP_TEST_CASE tc, ACVP_CAPS_LIST *cap,
                                     JSON_Array *r_tarr, JSON_Object *groupobj)
{
    unsigned char       *ln = NULL, *gen_pq = NULL, *sha = NULL, *index = NULL, *gen_g = NULL;
    JSON_Array          *tests;
    JSON_Value          *testval;
    JSON_Object         *testobj = NULL;
    JSON_Array          *res_array      = NULL;
    JSON_Array          *res_tarr = NULL; /* Response resultsArray */
    JSON_Value          *r_tval = NULL; /* Response testval */
    JSON_Object         *r_tobj = NULL; /* Response testobj */
    int                 j, t_cnt, tc_id;
    ACVP_RESULT         rv = ACVP_SUCCESS;
    JSON_Value          *mval;
    JSON_Object         *mobj = NULL;
    unsigned int        num = 0, gpq = 0;
    unsigned char       *p = NULL, *q = NULL, *seed = NULL;
    ACVP_DSA_PQGGEN_TC  *pqggen;
    ACVP_DSA_TC         *stc;

    gen_pq = (unsigned char *)json_object_get_string(groupobj, "genPQ");   
    gen_g = (unsigned char *)json_object_get_string(groupobj, "genG");   
    ln = (unsigned char *)json_object_get_string(groupobj, "ln");   
    sha = (unsigned char *)json_object_get_string(groupobj, "sha");   

    if (gen_pq) {
        ACVP_LOG_INFO("         genPQ: %s", gen_pq);
    }
    if (gen_g) {
        ACVP_LOG_INFO("          genG: %s", gen_g);
    }
    ACVP_LOG_INFO("            ln: %s", ln);
    ACVP_LOG_INFO("           sha: %s", sha);

    tests = json_object_get_array(groupobj, "tests");
    t_cnt = json_array_get_count(tests);

    stc = tc.tc.dsa;

    for (j = 0; j < t_cnt; j++) {
        ACVP_LOG_INFO("Found new DSA PQGGen test vector...");
        testval = json_array_get_value(tests, j);
        testobj = json_value_get_object(testval);

        tc_id = (unsigned int)json_object_get_number(testobj, "tcId");

        ACVP_LOG_INFO("       Test case: %d", j);
        ACVP_LOG_INFO("            tcId: %d", tc_id);
        if (!strncmp((char *)gen_g, "canonical", 9)) {
            p = (unsigned char *)json_object_get_string(testobj, "p");
            q = (unsigned char *)json_object_get_string(testobj, "q");
            seed = (unsigned char *)json_object_get_string(testobj, "seed");
            index = (unsigned char *)json_object_get_string(testobj, "index");
            gpq = ACVP_DSA_CANONICAL;
            ACVP_LOG_INFO("               p: %s", p);
            ACVP_LOG_INFO("               q: %s", q);
            ACVP_LOG_INFO("            seed: %s", seed);
            ACVP_LOG_INFO("           index: %s", index);
        }

        /* find the mode */
        if (!strncmp((char *)gen_g, "unverifiable", 12)) {
            p = (unsigned char *)json_object_get_string(testobj, "p");
            q = (unsigned char *)json_object_get_string(testobj, "q");
            gpq = ACVP_DSA_UNVERIFIABLE;
            ACVP_LOG_INFO("               p: %s", p);
            ACVP_LOG_INFO("               q: %s", q);
        }
    	if (!strncmp((char *)gen_pq, "probable", 8)) {
            num = json_object_get_number(testobj, "num");
            gpq = ACVP_DSA_PROBABLE;
            ACVP_LOG_INFO("             num: %d", num);
        }
    	if (!strncmp((char *)gen_pq, "provable", 8)) {
            num = json_object_get_number(testobj, "num");
            gpq = ACVP_DSA_PROVABLE;
            ACVP_LOG_INFO("             num: %d", num);
        }


        /*
         * Setup the test case data that will be passed down to
         * the crypto module.
         * TODO: this does mallocs, we can probably do the mallocs once for
         *       the entire vector set to be more efficient
         */

        /* num used to define number of iterations for PROVABLE/PROBABLE */
        switch (gpq)
        {
        case ACVP_DSA_PROBABLE:
        case ACVP_DSA_PROVABLE:
            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);
            json_object_set_number(r_tobj, "tcId", tc_id);

            json_object_set_value(r_tobj, "resultsArray", json_value_init_array());
	    res_tarr = json_object_get_array(r_tobj, "resultsArray");
	    while (num--) {

                acvp_dsa_init_tc(ctx, stc, tc_id, stc->cipher, gpq, num, index, ln, sha, p, q, seed);

                /* Process the current DSA test vector... */
                rv = (cap->crypto_handler)(&tc);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("crypto module failed the operation");
                    return ACVP_CRYPTO_MODULE_FAIL;
                }

                mval = json_value_init_object();
                mobj = json_value_get_object(mval);
                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_dsa_output_tc(ctx, stc, mobj);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("JSON output failure in DSA module");
                    return rv;
                }

                /* Append the test response value to array */
                json_array_append_value(res_tarr, mval);

                pqggen = stc->mode_tc.pqggen;
	     	pqggen->seedlen = 0;
	       	pqggen->counter = 0;
	       	pqggen->seed = 0;
            }
            /* Append the test response value to array */
            json_array_append_value(res_array, mval);
            break;

        case ACVP_DSA_CANONICAL:
        case ACVP_DSA_UNVERIFIABLE:
            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);
            json_object_set_number(r_tobj, "tcId", tc_id);

            /* Process the current DSA test vector... */
            acvp_dsa_init_tc(ctx, stc, tc_id, stc->cipher, gpq, num, index, ln, sha, p, q, seed);
            rv = (cap->crypto_handler)(&tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("crypto module failed the operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_dsa_output_tc(ctx, stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in DSA module");
                return rv;
            }
            /* Append the test response value to array */
            json_array_append_value(res_tarr, r_tval);
            break;
        default:
            ACVP_LOG_ERR("Invalid DSA PQGGen mode");
            rv =  ACVP_INVALID_ARG;
            break;
        }
    }
    /* Append the test response value to array */
    json_array_append_value(r_tarr, r_tval);
    return rv;
}


ACVP_RESULT acvp_dsa_kat_handler(ACVP_CTX *ctx, JSON_Object *obj)
{
    JSON_Value          *groupval;
    JSON_Object         *groupobj = NULL;
    JSON_Value          *r_vs_val = NULL;
    JSON_Object         *r_vs = NULL;
    JSON_Array          *r_tarr = NULL; /* Response testarray */
    JSON_Value          *reg_arry_val  = NULL;
    JSON_Array          *reg_arry      = NULL;
    JSON_Object         *reg_obj       = NULL;
    JSON_Array          *groups;
    ACVP_CAPS_LIST      *cap;
    ACVP_DSA_TC         stc;
    ACVP_TEST_CASE      tc;
    ACVP_RESULT         rv;
    const char          *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER	        alg_id;
    char                *json_result;
    unsigned char       *type;
    unsigned int        g_cnt, i;

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
	return (ACVP_MALFORMED_JSON);
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.dsa = &stc;
    memset(&stc, 0x0, sizeof(ACVP_DSA_TC));

    /*
     * Get the crypto module handler for DSA mode
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

    stc.cipher = alg_id;
    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        type = (unsigned char *)json_object_get_string(groupobj, "type");   
        if (!strncmp((char *)type, "pqgGen", 6)) {
            stc.mode = ACVP_DSA_MODE_PQGGEN;
        }

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("          type: %s", type);

        switch(stc.mode) {
    	case ACVP_DSA_MODE_PQGGEN:
            rv = acvp_dsa_pqggen_handler(ctx, tc, cap, r_tarr, groupobj);
            if (rv != ACVP_SUCCESS) {
                return(rv);
            }
            break;
	default:
	    break;
        }
        acvp_dsa_release_tc(&stc);
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
