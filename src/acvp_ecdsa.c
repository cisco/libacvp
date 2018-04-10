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


/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_ecdsa_output_tc (ACVP_CTX *ctx, ACVP_CIPHER cipher, ACVP_ECDSA_TC *stc, JSON_Object *tc_rsp) {
    if (cipher == ACVP_ECDSA_KEYGEN) {
        json_object_set_string(tc_rsp, "qy", (const char *) stc->qy);
        json_object_set_string(tc_rsp, "qx", (const char *) stc->qx);
        json_object_set_string(tc_rsp, "d", (const char *) stc->d);
    }
    if (cipher == ACVP_ECDSA_KEYVER || cipher == ACVP_ECDSA_SIGVER) {
        json_object_set_string(tc_rsp, "result", stc->ver_disposition);
    }
    if (cipher == ACVP_ECDSA_SIGGEN) {
        json_object_set_string(tc_rsp, "qy", (const char *) stc->qy);
        json_object_set_string(tc_rsp, "qx", (const char *) stc->qx);
        json_object_set_string(tc_rsp, "r", (const char *) stc->r);
        json_object_set_string(tc_rsp, "s", (const char *) stc->s);
    }
    
    return ACVP_SUCCESS;
}


/*
 * This function simply releases the data associated with
 * a test case.
 */

static ACVP_RESULT acvp_ecdsa_release_tc (ACVP_ECDSA_TC *stc) {
    if (stc->curve) { free(stc->curve); }
    if (stc->secret_gen_mode) { free(stc->secret_gen_mode); }
    if (stc->hash_alg) { free(stc->hash_alg); }
    if (stc->qy) { free(stc->qy); }
    if (stc->qx) { free(stc->qx); }
    if (stc->d) { free(stc->d); }
    if (stc->r) { free(stc->r); }
    if (stc->s) { free(stc->s); }
    if (stc->message) { free(stc->message); }
    
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_ecdsa_init_tc (ACVP_CTX *ctx,
                                              ACVP_CIPHER cipher,
                                              ACVP_ECDSA_TC *stc,
                                              unsigned int tc_id,
                                              char *curve,
                                              char *secret_gen_mode,
                                              char *qx,
                                              char *qy,
                                              char *message,
                                              char *r,
                                              char *s
) {
    memset(stc, 0x0, sizeof(ACVP_ECDSA_TC));
    
    stc->tc_id = tc_id;
    stc->cipher = cipher;
    
    stc->curve = calloc(5, sizeof(char));
    if (!stc->curve) { goto err; }
    strncpy(stc->curve, curve, strnlen(curve, 5));
    
    stc->secret_gen_mode = calloc(18, sizeof(char));
    if (!stc->secret_gen_mode) { goto err; }
    strncpy(stc->secret_gen_mode, secret_gen_mode, strnlen(secret_gen_mode, 18));
    
    stc->qy = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->qy) { goto err; }
    stc->qx = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->qx) { goto err; }
    stc->r = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->r) { goto err; }
    stc->s = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->s) { goto err; }
    
    if (cipher == ACVP_ECDSA_KEYVER || cipher == ACVP_ECDSA_SIGVER) {
        strncpy((char *)stc->qx, qx, strnlen(qx, 128));
        strncpy((char *)stc->qy, qy, strnlen(qy, 128));
    }
    if (cipher == ACVP_ECDSA_SIGVER) {
        strncpy((char *)stc->s, s, strnlen(s, 128));
        strncpy((char *)stc->r, r, strnlen(r, 128));
    }
    if (cipher == ACVP_ECDSA_SIGVER || cipher == ACVP_ECDSA_SIGGEN) {
        stc->message = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
        if (!stc->message) {
            ACVP_LOG_ERR("Failed to allocate message buffer in ECDSA sig");
            return ACVP_MALLOC_FAIL;
        }
        strncpy((char *)stc->message, message, strnlen(message, ACVP_RSA_MSGLEN_MAX));
    }
    stc->d = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->d) { goto err; }
    
    return ACVP_SUCCESS;
    
    err:
    ACVP_LOG_ERR("Failed to allocate buffer in ECDSA test case");
    return ACVP_MALLOC_FAIL;
}

ACVP_RESULT acvp_ecdsa_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_ECDSA_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    
    ACVP_CIPHER alg_id;
    char *json_result = NULL;
    char *hash_alg = NULL, *curve = NULL, *secret_gen_mode = NULL;
    char *alg_str, *mode_str, *qx, *qy, *r, *s, *message;
    
    alg_str = (char *) json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }
    
    tc.tc.ecdsa = &stc;
    mode_str = (char *) json_object_get_string(obj, "mode");
    
    
    /*
     * Get the crypto module handler for this hash algorithm
     */
    alg_id = acvp_lookup_cipher_index(mode_str);
    switch(alg_id) {
    case ACVP_ECDSA_KEYGEN:
    case ACVP_ECDSA_KEYVER:
    case ACVP_ECDSA_SIGGEN:
    case ACVP_ECDSA_SIGVER:
        break;
    default:
        ACVP_LOG_ERR("ERROR: unsupported algorithm (%s)", alg_str);
        return (ACVP_UNSUPPORTED_OP);
    }
    
    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ERROR: ACVP server requesting unsupported capability");
        return (ACVP_UNSUPPORTED_OP);
    }
    ACVP_LOG_INFO("    ECDSA mode: %s", mode_str);
    
    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("ERROR: Failed to create JSON response struct. ");
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
    json_object_set_string(r_vs, "mode", mode_str);
    json_object_set_value(r_vs, "testResults", json_value_init_array());
    r_tarr = json_object_get_array(r_vs, "testResults");
    
    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);
    
    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);
        /*
         * Get a reference to the abstracted test case
         */
        curve = (char *) json_object_get_string(groupobj, "curve");
        if (alg_id == ACVP_ECDSA_KEYGEN) {
            secret_gen_mode = (char *) json_object_get_string(groupobj, "secretGenerationMode");
        } else if (alg_id == ACVP_ECDSA_SIGGEN || alg_id == ACVP_ECDSA_SIGVER) {
            hash_alg = (char *) json_object_get_string(groupobj, "hashAlg");
        }
        
        ACVP_LOG_INFO("           Test group: %d", i);
        ACVP_LOG_INFO("                curve: %s", curve);
        ACVP_LOG_INFO(" secretGenerationMode: %s", secret_gen_mode);
        ACVP_LOG_INFO("              hashAlg: %s", hash_alg);
    
    
        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new ECDSA keyGen test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = (unsigned int) json_object_get_number(testobj, "tcId");
            
            if (alg_id == ACVP_ECDSA_KEYVER || alg_id == ACVP_ECDSA_SIGVER) {
                qx = (char *) json_object_get_string(testobj, "qx");
                qy = (char *) json_object_get_string(testobj, "qy");
            }
            if (alg_id == ACVP_ECDSA_SIGGEN || alg_id == ACVP_ECDSA_SIGVER) {
                message = (char *) json_object_get_string(testobj, "message");
            }
            if (alg_id == ACVP_ECDSA_SIGVER) {
                r = (char *) json_object_get_string(testobj, "r");
                s = (char *) json_object_get_string(testobj, "s");
            }
            
            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            
            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);
            
            json_object_set_number(r_tobj, "tcId", tc_id);
            
            rv = acvp_ecdsa_init_tc(ctx, alg_id, &stc, tc_id, curve, secret_gen_mode, qx, qy, message, r, s);
            
            /* Process the current test vector... */
            if (rv == ACVP_SUCCESS) {
                rv = (cap->crypto_handler)(&tc);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    goto key_err;
                }
            } else {
                ACVP_LOG_ERR("Failed to initialize ECDSA test case");
                goto key_err;
            }
            
            /*
             * Output the test case results using JSON
             */
            rv = acvp_ecdsa_output_tc(ctx, alg_id, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                goto key_err;
            }
    
            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
            
            /*
             * Release all the memory associated with the test case
             */
            key_err:
            acvp_ecdsa_release_tc(&stc);
            if (rv != ACVP_SUCCESS) {
                goto end;
            }
        }
    }
    
    end:
    json_array_append_value(reg_arry, r_vs_val);
    
    json_result = json_serialize_to_string_pretty(ctx->kat_resp);
    if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
        printf("\n\n%s\n\n", json_result);
    } else {
        ACVP_LOG_INFO("\n\n%s\n\n", json_result);
    }
    json_free_serialized_string(json_result);
    
    return rv;
}

