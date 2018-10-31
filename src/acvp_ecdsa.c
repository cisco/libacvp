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

static ACVP_RESULT acvp_ecdsa_kat_handler_internal (ACVP_CTX *ctx, JSON_Object *obj, ACVP_CIPHER cipher);


/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_ecdsa_output_tc (ACVP_CTX *ctx, ACVP_CIPHER cipher, ACVP_ECDSA_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv;
    char *tmp = NULL;
    tmp = calloc(ACVP_ECDSA_EXP_LEN_MAX+1, sizeof(char));
    
    if (cipher == ACVP_ECDSA_KEYGEN) {
        rv = acvp_bin_to_hexstr(stc->qy, stc->qy_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (qy)");
            goto err;
        }
        json_object_set_string(tc_rsp, "qy", (const char *)tmp);
        memset(tmp, 0x0, ACVP_ECDSA_EXP_LEN_MAX);
    
        rv = acvp_bin_to_hexstr(stc->qx, stc->qx_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (qx)");
            goto err;
        }
        json_object_set_string(tc_rsp, "qx", (const char *)tmp);
        memset(tmp, 0x0, ACVP_ECDSA_EXP_LEN_MAX);
    
        rv = acvp_bin_to_hexstr(stc->d, stc->d_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (d)");
            goto err;
        }
        json_object_set_string(tc_rsp, "d", (const char *)tmp);
        memset(tmp, 0x0, ACVP_ECDSA_EXP_LEN_MAX);
    }
    if (cipher == ACVP_ECDSA_KEYVER || cipher == ACVP_ECDSA_SIGVER) {
        json_object_set_string(tc_rsp, "result", stc->ver_disposition ? "passed" : "failed");
    
    }
    if (cipher == ACVP_ECDSA_SIGGEN) {
        rv = acvp_bin_to_hexstr(stc->qy, stc->qy_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (qy)");
            goto err;
        }
        json_object_set_string(tc_rsp, "qy", (const char *)tmp);
        memset(tmp, 0x0, ACVP_ECDSA_EXP_LEN_MAX);
    
        rv = acvp_bin_to_hexstr(stc->qx, stc->qx_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (qx)");
            goto err;
        }
        json_object_set_string(tc_rsp, "qx", (const char *)tmp);
        memset(tmp, 0x0, ACVP_ECDSA_EXP_LEN_MAX);
    
        rv = acvp_bin_to_hexstr(stc->r, stc->r_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (r)");
            goto err;
        }
        json_object_set_string(tc_rsp, "r", (const char *)tmp);
        memset(tmp, 0x0, ACVP_ECDSA_EXP_LEN_MAX);
    
        rv = acvp_bin_to_hexstr(stc->s, stc->s_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (s)");
            goto err;
        }
        json_object_set_string(tc_rsp, "s", (const char *)tmp);
        memset(tmp, 0x0, ACVP_ECDSA_EXP_LEN_MAX);
    }
    
err:
    free(tmp);
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
                                       char *hash_alg,
                                       char *qx,
                                       char *qy,
                                       char *message,
                                       char *r,
                                       char *s
) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    
    memset(stc, 0x0, sizeof(ACVP_ECDSA_TC));
    
    stc->tc_id = tc_id;
    stc->cipher = cipher;
    
    stc->curve = calloc(5, sizeof(char));
    if (!stc->curve) { goto err; }
    strncpy(stc->curve, curve, strnlen(curve, 5));
    
    if (secret_gen_mode) {
        stc->secret_gen_mode = calloc(18, sizeof(char));
        if (!stc->secret_gen_mode) { goto err; }
        strncpy(stc->secret_gen_mode, secret_gen_mode, strnlen(secret_gen_mode, 18));
    }
    
    if (hash_alg) {
        stc->hash_alg = calloc(8, sizeof(char));
        if (!stc->hash_alg) { goto err; }
        strncpy(stc->hash_alg, hash_alg, strnlen(hash_alg, 8));
    }
    
    stc->qx = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->qx) { goto err; }
    stc->qy = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->qy) { goto err; }
    stc->d = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->d) { goto err; }
    stc->s = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->s) { goto err; }
    stc->r = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->r) { goto err; }
    stc->message = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->message) { goto err; }
    
    if (cipher == ACVP_ECDSA_KEYVER || cipher == ACVP_ECDSA_SIGVER) {
        if (!qx || !qy) return ACVP_MISSING_ARG;
        rv = acvp_hexstr_to_bin(qx, stc->qx, ACVP_RSA_EXP_LEN_MAX, &(stc->qx_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (qx)");
            return rv;
        }
        
        rv = acvp_hexstr_to_bin(qy, stc->qy, ACVP_RSA_EXP_LEN_MAX, &(stc->qy_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (qy)");
            return rv;
        }
    }
    if (cipher == ACVP_ECDSA_SIGVER) {
        if (!r || !s) return ACVP_MISSING_ARG;
        rv = acvp_hexstr_to_bin(r, stc->r, ACVP_RSA_EXP_LEN_MAX, &(stc->r_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (r)");
            return rv;
        }
        
        rv = acvp_hexstr_to_bin(s, stc->s, ACVP_RSA_EXP_LEN_MAX, &(stc->s_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (s)");
            return rv;
        }
    }
    if (cipher == ACVP_ECDSA_SIGVER || cipher == ACVP_ECDSA_SIGGEN) {
        if (!message) return ACVP_MISSING_ARG;
        rv = acvp_hexstr_to_bin(message, stc->message, ACVP_RSA_MSGLEN_MAX, &(stc->msg_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (message)");
            return rv;
        }
    }
    
    return ACVP_SUCCESS;
    
err:
    ACVP_LOG_ERR("Failed to allocate buffer in ECDSA test case");
    if (stc->curve) free(stc->curve);
    if (stc->secret_gen_mode) free(stc->secret_gen_mode);
    if (stc->qx) free(stc->qx);
    if (stc->qy) free(stc->qy);
    if (stc->r) free(stc->r);
    if (stc->s) free(stc->s);
    if (stc->d) free(stc->d);
    if (stc->message) free(stc->message);
    return ACVP_MALLOC_FAIL;
}

ACVP_RESULT acvp_ecdsa_keygen_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_ecdsa_kat_handler_internal(ctx, obj, ACVP_ECDSA_KEYGEN);
}

ACVP_RESULT acvp_ecdsa_keyver_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_ecdsa_kat_handler_internal(ctx, obj, ACVP_ECDSA_KEYVER);
}

ACVP_RESULT acvp_ecdsa_siggen_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_ecdsa_kat_handler_internal(ctx, obj, ACVP_ECDSA_SIGGEN);
}

ACVP_RESULT acvp_ecdsa_sigver_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_ecdsa_kat_handler_internal(ctx, obj, ACVP_ECDSA_SIGVER);
}


static ACVP_RESULT acvp_ecdsa_kat_handler_internal (ACVP_CTX *ctx, JSON_Object *obj, ACVP_CIPHER cipher) {
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
    char *alg_str, *mode_str, *qx = NULL, *qy = NULL, *r = NULL, *s = NULL, *message = NULL;
    
    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }
    
    alg_str = (char *) json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }
    if (strncmp(alg_str, ACVP_ALG_ECDSA, strlen(ACVP_ALG_ECDSA))) {
        ACVP_LOG_ERR("Invalid algorithm string in JSON");
        return ACVP_INVALID_ARG;
    }
    
    tc.tc.ecdsa = &stc;
    mode_str = (char *) json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("Server JSON missing 'mode_str'");
        return ACVP_MALFORMED_JSON;
    }
    if (strncmp(mode_str, ACVP_MODE_KEYGEN, strlen(ACVP_MODE_KEYGEN)) &&
        strncmp(mode_str, ACVP_MODE_KEYVER, strlen(ACVP_MODE_KEYVER)) &&
        strncmp(mode_str, ACVP_MODE_SIGGEN, strlen(ACVP_MODE_SIGGEN)) &&
        strncmp(mode_str, ACVP_MODE_SIGVER, strlen(ACVP_MODE_SIGVER))) {
        ACVP_LOG_ERR("Server JSON includes unrecognized mode");
        return ACVP_INVALID_ARG;
    }
    
    alg_id = cipher;
    
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
    if (!groups) {
        ACVP_LOG_ERR("Missing testGroups from server JSON");
        return ACVP_MALFORMED_JSON;
    }
    g_cnt = json_array_get_count(groups);
    
    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);
        /*
         * Get a reference to the abstracted test case
         */
        curve = (char *) json_object_get_string(groupobj, "curve");
        if (!curve) {
            ACVP_LOG_ERR("Server JSON missing 'curve'");
            return ACVP_MISSING_ARG;
        }
        if (!acvp_lookup_ecdsa_curve(alg_id, curve)) {
            ACVP_LOG_ERR("Server JSON includes unrecognized curve");
            return ACVP_INVALID_ARG;
        }
        if (alg_id == ACVP_ECDSA_KEYGEN) {
            secret_gen_mode = (char *) json_object_get_string(groupobj, "secretGenerationMode");
            if (!secret_gen_mode) {
                ACVP_LOG_ERR("Server JSON missing 'secret_gen_mode'");
                return ACVP_MISSING_ARG;
            }
        } else if (alg_id == ACVP_ECDSA_SIGGEN || alg_id == ACVP_ECDSA_SIGVER) {
            hash_alg = (char *) json_object_get_string(groupobj, "hashAlg");
            if (!hash_alg) {
                ACVP_LOG_ERR("Server JSON missing 'hash_alg'");
                return ACVP_MISSING_ARG;
            }
            if (is_valid_hash_alg(hash_alg) == ACVP_INVALID_ARG) {
                ACVP_LOG_ERR("Invalid hash alg");
                return ACVP_INVALID_ARG;
            }
        }
        
        ACVP_LOG_INFO("           Test group: %d", i);
        ACVP_LOG_INFO("                curve: %s", curve);
        ACVP_LOG_INFO(" secretGenerationMode: %s", secret_gen_mode);
        ACVP_LOG_INFO("              hashAlg: %s", hash_alg);
        
        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new ECDSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = (unsigned int) json_object_get_number(testobj, "tcId");
            
            if (alg_id == ACVP_ECDSA_KEYVER || alg_id == ACVP_ECDSA_SIGVER) {
                qx = (char *) json_object_get_string(testobj, "qx");
                qy = (char *) json_object_get_string(testobj, "qy");
                if (!qx || !qy) {
                    ACVP_LOG_ERR("Server JSON missing 'qx' or 'qy'");
                    return ACVP_MISSING_ARG;
                }
                if (strnlen(qx, ACVP_ECDSA_EXP_LEN_MAX + 1) > ACVP_ECDSA_EXP_LEN_MAX ||
                    strnlen(qy, ACVP_ECDSA_EXP_LEN_MAX + 1) > ACVP_ECDSA_EXP_LEN_MAX) {
                    ACVP_LOG_ERR("'qx' or 'qy' too long");
                    return ACVP_INVALID_ARG;
                }
            }
            if (alg_id == ACVP_ECDSA_SIGGEN || alg_id == ACVP_ECDSA_SIGVER) {
                message = (char *) json_object_get_string(testobj, "message");
                if (!message) {
                    ACVP_LOG_ERR("Server JSON missing 'message'");
                    return ACVP_MISSING_ARG;
                }
                if (strnlen(message, ACVP_ECDSA_MSGLEN_MAX + 1) > ACVP_ECDSA_MSGLEN_MAX) {
                    ACVP_LOG_ERR("message string too long");
                    return ACVP_INVALID_ARG;
                }
            }
            if (alg_id == ACVP_ECDSA_SIGVER) {
                r = (char *) json_object_get_string(testobj, "r");
                s = (char *) json_object_get_string(testobj, "s");
                if (!r || !s) {
                    ACVP_LOG_ERR("Server JSON missing 'r' or 's'");
                    return ACVP_MISSING_ARG;
                }
                if (strnlen(r, ACVP_ECDSA_EXP_LEN_MAX + 1) > ACVP_ECDSA_EXP_LEN_MAX ||
                    strnlen(s, ACVP_ECDSA_EXP_LEN_MAX + 1) > ACVP_ECDSA_EXP_LEN_MAX) {
                    ACVP_LOG_ERR("'r' or 's' too long");
                    return ACVP_INVALID_ARG;
                }
            }
            
            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            
            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);
            
            json_object_set_number(r_tobj, "tcId", tc_id);
            
            rv = acvp_ecdsa_init_tc(ctx, alg_id, &stc, tc_id, curve, secret_gen_mode, hash_alg, qx, qy, message, r, s);
            
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

