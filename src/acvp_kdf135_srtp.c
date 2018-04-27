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
static ACVP_RESULT acvp_kdf135_srtp_output_tc (ACVP_CTX *ctx, ACVP_KDF135_SRTP_TC *stc, JSON_Object *tc_rsp) {
    json_object_set_string(tc_rsp, "srtpKe", (const char *)stc->srtp_ke);
    json_object_set_string(tc_rsp, "srtpKa", (const char *)stc->srtp_ka);
    json_object_set_string(tc_rsp, "srtpKs", (const char *)stc->srtp_ks);
    json_object_set_string(tc_rsp, "srtcpKe", (const char *)stc->srtcp_ke);
    json_object_set_string(tc_rsp, "srtcpKa", (const char *)stc->srtcp_ka);
    json_object_set_string(tc_rsp, "srtcpKs", (const char *)stc->srtcp_ks);
    return ACVP_SUCCESS;
}
/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf135_srtp_release_tc (ACVP_KDF135_SRTP_TC *stc) {
    if (stc->kdr) free(stc->kdr);
    if (stc->master_key) free(stc->master_key);
    if (stc->master_salt) free(stc->master_salt);
    if (stc->index) free(stc->index);
    if (stc->srtcp_index) free(stc->srtcp_index);
    if (stc->kdr) free(stc->kdr);
    if (stc->srtp_ke) free(stc->srtp_ke);
    if (stc->srtp_ka) free(stc->srtp_ka);
    if (stc->srtp_ks) free(stc->srtp_ks);
    if (stc->srtcp_ke) free(stc->srtcp_ke);
    if (stc->srtcp_ka) free(stc->srtcp_ka);
    if (stc->srtcp_ks) free(stc->srtcp_ks);
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kdf135_srtp_init_tc (ACVP_CTX *ctx,
                                             ACVP_KDF135_SRTP_TC *stc,
                                             unsigned int tc_id,
                                             int aes_keylen,
                                             unsigned char *kdr,
                                             unsigned char *master_key,
                                             unsigned char *master_salt,
                                             unsigned char *index,
                                             unsigned char *srtcp_index) {
    memset(stc, 0x0, sizeof(ACVP_KDF135_SRTP_TC));
    
    if (!kdr || !master_key || !master_salt || !index || !srtcp_index) {
        ACVP_LOG_ERR("Missing parameters - initalize KDF SRTP test case");
        return ACVP_INVALID_ARG;
    }
    
    stc->tc_id = tc_id;
    stc->aes_keylen = aes_keylen;
    
    stc->kdr = calloc(8, sizeof(char));
    if (!stc->kdr) { return ACVP_MALLOC_FAIL; }
    stc->master_key = calloc(64, sizeof(char));
    if (!stc->master_key) { return ACVP_MALLOC_FAIL; }
    stc->master_salt = calloc(64, sizeof(char));
    if (!stc->master_salt) { return ACVP_MALLOC_FAIL; }
    stc->index = calloc(32, sizeof(char));
    if (!stc->index) { return ACVP_MALLOC_FAIL; }
    stc->srtcp_index = calloc(32, sizeof(char));
    if (!stc->srtcp_index) { return ACVP_MALLOC_FAIL; }
    
    memcpy(stc->kdr, kdr, strnlen((const char *)kdr, 8));
    memcpy(stc->master_key, master_key, strnlen((const char *)master_key, 64));
    memcpy(stc->master_salt, master_salt, strnlen((const char *)master_salt, 64));
    memcpy(stc->index, index, strnlen((const char *)index, 32));
    memcpy(stc->srtcp_index, srtcp_index, strnlen((const char *)srtcp_index, 32));
    
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_kdf135_srtp_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_KDF135_SRTP_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER alg_id;
    char *json_result;
    
    int aes_key_length;
    unsigned char *kdr = NULL, *master_key = NULL, *master_salt = NULL, *index = NULL, *srtcp_index = NULL;
    
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON for KDF SSH.");
        return (ACVP_MALFORMED_JSON);
    }
    
    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_srtp = &stc;
    alg_id = ACVP_KDF135_SRTP;
    stc.cipher = alg_id;
    
    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability %s : %d.", alg_str, alg_id);
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
        
        aes_key_length = (unsigned int) json_object_get_number(groupobj, "aesKeyLength");
        kdr = (unsigned char *)json_object_get_string(groupobj, "kdr");
        
        ACVP_LOG_INFO("\n    Test group: %d", i);
        ACVP_LOG_INFO("           kdr: %d", kdr);
        ACVP_LOG_INFO("    key length: %d", aes_key_length);
        
        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new KDF SRTP test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            
            tc_id = (unsigned int) json_object_get_number(testobj, "tcId");
            master_key = (unsigned char *)json_object_get_string(testobj, "masterKey");
            master_salt = (unsigned char *)json_object_get_string(testobj, "masterSalt");
            index = (unsigned char *)json_object_get_string(testobj, "index");
            srtcp_index = (unsigned char *)json_object_get_string(testobj, "srtcpIndex");
            
            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            
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
            acvp_kdf135_srtp_init_tc(ctx, &stc, tc_id, aes_key_length, kdr, master_key, master_salt, index, srtcp_index);
            
            /* Process the current test vector... */
            rv = (cap->crypto_handler)(&tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("crypto module failed the KDF SSH operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }
            
            /*
             * Output the test case results using JSON
            */
            rv = acvp_kdf135_srtp_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in hash module");
                return rv;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_kdf135_srtp_release_tc(&stc);
            
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
