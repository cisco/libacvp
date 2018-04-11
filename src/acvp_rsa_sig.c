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
static ACVP_RESULT acvp_rsa_sig_output_tc (ACVP_CTX *ctx, ACVP_RSA_SIG_TC *stc, JSON_Object *tc_rsp) {
    if (stc->sig_mode == ACVP_RSA_SIGVER) {
        json_object_set_string(tc_rsp, "sigResult", stc->ver_disposition ? "passed" : "failed");
    } else {
        json_object_set_string(tc_rsp, "e", (const char *)stc->e);
        json_object_set_string(tc_rsp, "n", (const char *)stc->n);
        json_object_set_string(tc_rsp, "signature", (const char *)stc->signature);
    }

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */

static ACVP_RESULT acvp_rsa_siggen_release_tc (ACVP_RSA_SIG_TC *stc) {
    if (stc->msg) { free(stc->msg); }
    if (stc->hash_alg) { free(stc->hash_alg); }
    if (stc->sig_type) { free(stc->sig_type); }
    if (stc->e) { free(stc->e); }
    if (stc->n) { free(stc->n); }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_rsa_sig_init_tc (ACVP_CTX *ctx,
                                         ACVP_CIPHER cipher,
                                         ACVP_RSA_SIG_TC *stc,
                                         unsigned int tc_id,
                                         char *sig_type,
                                         unsigned int mod,
                                         char *hash_alg,
                                         char *e,
                                         char *n,
                                         unsigned char *msg,
                                         unsigned char *signature,
                                         char *salt) {
    ACVP_RESULT rv;
    memset(stc, 0x0, sizeof(ACVP_RSA_SIG_TC));
    
    stc->msg = calloc(ACVP_RSA_MSGLEN_MAX, sizeof(char));
    if (!stc->msg) { return ACVP_MALLOC_FAIL; }
    stc->sig_type = calloc(ACVP_RSA_SIG_TYPE_LEN_MAX, sizeof(char));
    if (!stc->sig_type) { return ACVP_MALLOC_FAIL; }
    stc->hash_alg = calloc(ACVP_RSA_HASH_ALG_LEN_MAX, sizeof(char));
    if (!stc->hash_alg) { return ACVP_MALLOC_FAIL; }
    stc->signature = calloc(ACVP_RSA_SIGNATURE_MAX, sizeof(char));
    if (!stc->signature) { return ACVP_MALLOC_FAIL; }
    stc->e = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->e) { return ACVP_MALLOC_FAIL; }
    stc->n = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->n) { return ACVP_MALLOC_FAIL; }
    
    stc->msg_len = strnlen((const char*)msg, ACVP_RSA_MSGLEN_MAX)/2;
    
    rv = acvp_hexstr_to_bin((const unsigned char *) msg, stc->msg, ACVP_RSA_MSGLEN_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }
    
    if (cipher == ACVP_RSA_SIGVER) {
        stc->sig_mode = ACVP_RSA_SIGVER;
        
        rv = acvp_hexstr_to_bin((const unsigned char *) e, stc->e, ACVP_RSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (e)");
            return rv;
        }
        rv = acvp_hexstr_to_bin((const unsigned char *) n, stc->n, ACVP_RSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (n)");
            return rv;
        }
        stc->sig_len = strnlen((const char*)signature, ACVP_RSA_SIGNATURE_MAX);
        rv = acvp_hexstr_to_bin((const unsigned char *) signature, stc->signature, ACVP_RSA_SIGNATURE_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (signature)");
            return rv;
        }
    } else {
        stc->sig_mode = ACVP_RSA_SIGGEN;
    }
    
    memcpy(stc->sig_type, sig_type, strnlen((const char *)sig_type, ACVP_RSA_SIG_TYPE_LEN_MAX));
    memcpy(stc->hash_alg, hash_alg, strnlen((const char *)hash_alg, ACVP_RSA_HASH_ALG_LEN_MAX));
    
    stc->tc_id = tc_id;
    stc->modulo = mod;
    
    return rv;
}

ACVP_RESULT acvp_rsa_sig_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_RSA_SIG_TC stc;
    ACVP_TEST_CASE tc;
    
    ACVP_CIPHER alg_id;
    char *json_result = NULL, *mode_str;
    unsigned int mod = 0;
    unsigned char *msg, *signature;
    char *e_str = NULL, *n_str = NULL;
    char *hash_alg = NULL, *sig_type, *salt, *alg_str, *alg_tbl_index;

    ACVP_RESULT rv;
    alg_str = (char *) json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }
    
    tc.tc.rsa_sig = &stc;
    mode_str = (char *) json_object_get_string(obj, "mode");
    
    /* allocate space to concatenate alg and mode strings (and a hyphen) */
    alg_tbl_index = calloc(strnlen(alg_str, 5) + 6 + 1, sizeof(char));
    strncat(alg_tbl_index, alg_str, 5);
    strncat(alg_tbl_index, "-", 1);
    strncat(alg_tbl_index, mode_str, 6);
    
    /*
     * Get the crypto module handler for this hash algorithm
     */
    alg_id = acvp_lookup_cipher_index(alg_tbl_index);
    switch(alg_id) {
    case ACVP_RSA_SIGGEN:
    case ACVP_RSA_SIGVER:
        break;
    default:
        ACVP_LOG_ERR("ERROR: unsupported algorithm (%s)", alg_str);
        return (ACVP_UNSUPPORTED_OP);
    }
    stc.sig_mode = alg_id;
    
    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ERROR: ACVP server requesting unsupported capability");
        return (ACVP_UNSUPPORTED_OP);
    }
    ACVP_LOG_INFO("    RSA mode: %s", mode_str);
    
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
        sig_type = (char *) json_object_get_string(groupobj, "sigType");
        mod = json_object_get_number(groupobj, "modulo");
        hash_alg = (char *) json_object_get_string(groupobj, "hashAlg");
        
        if (alg_id == ACVP_RSA_SIGVER) {
            e_str = (char *) json_object_get_string(groupobj, "e");
            n_str = (char *) json_object_get_string(groupobj, "n");
        }

        ACVP_LOG_INFO("       Test group: %d", i);
        ACVP_LOG_INFO("          sigType: %s", sig_type);
        ACVP_LOG_INFO("           modulo: %d", mod);
        ACVP_LOG_INFO("          hashAlg: %s", hash_alg);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new RSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = (unsigned int) json_object_get_number(testobj, "tcId");

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            
            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);
            
            /*
             * Get a reference to the abstracted test case
             */
        
            msg = (unsigned char *) json_object_get_string(testobj, "message");

            if (alg_id == ACVP_RSA_SIGVER) {
                signature = (unsigned char *) json_object_get_string(testobj, "signature");
                salt = (char *) json_object_get_string(testobj, "salt");
            }
            
            acvp_rsa_sig_init_tc(ctx, alg_id,  &stc, tc_id, sig_type, mod, hash_alg, e_str, n_str, msg, signature, salt);
            
            
            /* Process the current test vector... */
            if (rv == ACVP_SUCCESS) {
                rv = (cap->crypto_handler)(&tc);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    goto key_err;
                }
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_rsa_sig_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                goto key_err;
            }
            
            /*
             * Release all the memory associated with the test case
             */
            key_err:
            acvp_rsa_siggen_release_tc(&stc);


            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
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

