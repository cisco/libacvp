/*****************************************************************************
* Copyright (c) 2016, Cisco Systems, Inc.
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
static ACVP_RESULT acvp_kdf135_ikev2_output_tc (ACVP_CTX *ctx, ACVP_KDF135_IKEV2_TC *stc, JSON_Object *tc_rsp) {
    json_object_set_string(tc_rsp, "sKeySeed", (const char *)stc->s_key_seed);
    json_object_set_string(tc_rsp, "sKeySeedReKey", (const char *)stc->s_key_seed_rekey);
    json_object_set_string(tc_rsp, "derivedKeyingMaterial", (const char *)stc->derived_keying_material);
    json_object_set_string(tc_rsp, "derivedKeyingMaterialChild", (const char *)stc->derived_keying_material_child);
    json_object_set_string(tc_rsp, "derivedKeyingMaterialChildDh", (const char *)stc->derived_keying_material_child_dh);
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kdf135_ikev2_init_tc (ACVP_CTX *ctx,
                                             ACVP_KDF135_IKEV2_TC *stc,
                                             unsigned int tc_id,
                                             unsigned char *hash_alg,
                                             int init_nonce_len,
                                             int resp_nonce_len,
                                             int dh_secret_len,
                                             int keying_material_len,
                                             unsigned char *init_nonce,
                                             unsigned char *resp_nonce,
                                             unsigned char *init_spi,
                                             unsigned char *resp_spi,
                                             unsigned char *gir,
                                             unsigned char *gir_new) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    memset(stc, 0x0, sizeof(ACVP_KDF135_IKEV2_TC));
    
    stc->tc_id = tc_id;
    
    stc->hash_alg = calloc(ACVP_RSA_HASH_ALG_LEN_MAX, sizeof(char));
    if (!stc->hash_alg) { return ACVP_MALLOC_FAIL; }
    memcpy(stc->hash_alg, hash_alg, strnlen((const char *)hash_alg, ACVP_RSA_HASH_ALG_LEN_MAX));
    
    stc->init_nonce_len = init_nonce_len;
    stc->resp_nonce_len = resp_nonce_len;
    stc->dh_secret_len = dh_secret_len;
    stc->keying_material_len = keying_material_len;
    
    stc->init_nonce = calloc(ACVP_KDF135_IKE_NONCE_LEN_MAX, sizeof(char));
    if (!stc->init_nonce) { return ACVP_MALLOC_FAIL; }
    memcpy(stc->init_nonce, init_nonce, strnlen((const char *)init_nonce, ACVP_KDF135_IKE_NONCE_LEN_MAX));
    
    stc->resp_nonce = calloc(ACVP_KDF135_IKE_NONCE_LEN_MAX, sizeof(char));
    if (!stc->resp_nonce) { return ACVP_MALLOC_FAIL; }
    memcpy(stc->resp_nonce, resp_nonce, strnlen((const char *)resp_nonce, ACVP_KDF135_IKE_NONCE_LEN_MAX));
    
    stc->init_spi = calloc(ACVP_KDF135_IKEV2_SPI_LEN_MAX, sizeof(char));
    if (!stc->init_spi) { return ACVP_MALLOC_FAIL; }
    memcpy(stc->init_spi, init_spi, strnlen((const char *)init_spi, ACVP_KDF135_IKEV2_SPI_LEN_MAX));
    
    stc->resp_spi = calloc(ACVP_KDF135_IKEV2_SPI_LEN_MAX, sizeof(char));
    if (!stc->resp_spi) { return ACVP_MALLOC_FAIL; }
    memcpy(stc->resp_spi, resp_spi, strnlen((const char *)resp_spi, ACVP_KDF135_IKEV2_SPI_LEN_MAX));
    
    stc->gir = calloc(ACVP_KDF135_IKEV2_GIR_LEN_MAX, sizeof(char));
    if (!stc->gir) { return ACVP_MALLOC_FAIL; }
    memcpy(stc->gir, gir, strnlen((const char *)gir, ACVP_KDF135_IKEV2_GIR_LEN_MAX));
    
    stc->gir_new = calloc(ACVP_KDF135_IKEV2_GIR_LEN_MAX, sizeof(char));
    if (!stc->gir_new) { return ACVP_MALLOC_FAIL; }
    memcpy(stc->gir_new, gir_new, strnlen((const char *)gir_new, ACVP_KDF135_IKEV2_GIR_LEN_MAX));
    
    return rv;
}

static ACVP_RESULT acvp_kdf135_ikev2_release_tc (ACVP_KDF135_IKEV2_TC *stc) {
    if (stc->hash_alg) { free(stc->hash_alg); }
    if (stc->init_nonce) { free(stc->init_nonce); }
    if (stc->resp_nonce) { free(stc->resp_nonce); }
    if (stc->init_spi) { free(stc->init_spi); }
    if (stc->resp_spi) { free(stc->resp_spi); }
    if (stc->gir) { free(stc->gir); }
    if (stc->gir_new) { free(stc->gir_new); }
    if (stc->s_key_seed) { free(stc->s_key_seed); }
    if (stc->s_key_seed_rekey) { free(stc->s_key_seed_rekey); }
    if (stc->derived_keying_material) { free(stc->derived_keying_material); }
    if (stc->derived_keying_material_child) { free(stc->derived_keying_material_child); }
    if (stc->derived_keying_material_child_dh) { free(stc->derived_keying_material_child_dh); }
    return ACVP_SUCCESS;
}


ACVP_RESULT acvp_kdf135_ikev2_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_KDF135_IKEV2_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER alg_id;
    char *json_result;
    
    unsigned char *hash_alg = NULL, *init_nonce = NULL, *resp_nonce = NULL, *init_spi = NULL;
    unsigned char *resp_spi = NULL, *gir = NULL, *gir_new = NULL;
    int init_nonce_len = 0, resp_nonce_len = 0, dh_secret_len = 0, keying_material_len = 0;
    
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON for KDF SSH.");
        return (ACVP_MALFORMED_JSON);
    }
    
    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_ikev2 = &stc;
    alg_id = ACVP_KDF135_IKEV2;
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
        
        hash_alg = (unsigned char *) json_object_get_string(groupobj, "hashAlg");
        init_nonce_len = json_object_get_number(groupobj, "nInitLength");
        resp_nonce_len = json_object_get_number(groupobj, "nRespLength");
        dh_secret_len = json_object_get_number(groupobj, "dhLength");
        keying_material_len = json_object_get_number(groupobj, "derivedKeyingMaterialLength");
        
        ACVP_LOG_INFO("\n    Test group: %d", i);
        ACVP_LOG_INFO("        hash alg: %S", hash_alg);
        ACVP_LOG_INFO("  init nonce len: %d", init_nonce_len);
        ACVP_LOG_INFO("  resp nonce len: %d", resp_nonce_len);
        ACVP_LOG_INFO("   dh secret len: %d", dh_secret_len);
        ACVP_LOG_INFO("derived key material: %d", keying_material_len);
        
        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new KDF SRTP test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            
            tc_id = (unsigned int) json_object_get_number(testobj, "tcId");
            init_nonce = (unsigned char *)json_object_get_string(testobj, "nInit");
            resp_nonce = (unsigned char *)json_object_get_string(testobj, "nResp");
            init_spi = (unsigned char *)json_object_get_string(testobj, "spiInit");
            resp_spi = (unsigned char *)json_object_get_string(testobj, "spiResp");
            gir = (unsigned char *)json_object_get_string(testobj, "gir");
            gir_new = (unsigned char *)json_object_get_string(testobj, "girNew");
            
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
            acvp_kdf135_ikev2_init_tc(ctx, &stc, tc_id, hash_alg,
                                      init_nonce_len, resp_nonce_len,
                                      dh_secret_len, keying_material_len,
                                      init_nonce, resp_nonce,
                                      init_spi, resp_spi,
                                      gir, gir_new);
            
            /* Process the current test vector... */
            rv = (cap->crypto_handler)(&tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("crypto module failed the KDF SSH operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }
            
            /*
             * Output the test case results using JSON
            */
            rv = acvp_kdf135_ikev2_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in hash module");
                return rv;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_kdf135_ikev2_release_tc(&stc);
            
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
