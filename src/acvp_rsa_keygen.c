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
static ACVP_RESULT acvp_rsa_output_tc (ACVP_CTX *ctx, ACVP_RSA_KEYGEN_TC *stc, JSON_Object *tc_rsp) {
    
    json_object_set_string(tc_rsp, "p", (const char *)stc->p);
    json_object_set_string(tc_rsp, "q", (const char *)stc->q);
    json_object_set_string(tc_rsp, "n", (const char *)stc->n);
    json_object_set_string(tc_rsp, "d", (const char *)stc->d);
    json_object_set_string(tc_rsp, "e", (const char *)stc->e);
    
    if (strncmp(stc->key_format, "crt", 8) == 0) {
        json_object_set_string(tc_rsp, "xP", (const char *)stc->xp);
        json_object_set_string(tc_rsp, "xP1", (const char *)stc->xp1);
        json_object_set_string(tc_rsp, "xP2", (const char *)stc->xp2);
        json_object_set_string(tc_rsp, "xQ", (const char *)stc->xq);
        json_object_set_string(tc_rsp, "xQ1", (const char *)stc->xq1);
        json_object_set_string(tc_rsp, "xQ2", (const char *)stc->xq2);
    }
    
    if (stc->info_gen_by_server) {
        if (stc->rand_pq == ACVP_RSA_KEYGEN_B33 ||
            stc->rand_pq == ACVP_RSA_KEYGEN_B35 ||
            stc->rand_pq == ACVP_RSA_KEYGEN_B36) {
            json_object_set_string(tc_rsp, "primeResult", (const char *)stc->prime_result);
        }
    } else {
        if (!(stc->rand_pq == ACVP_RSA_KEYGEN_B33)) {
            json_object_set_string(tc_rsp, "seed", (const char *)stc->seed);
            json_object_set_value(tc_rsp, "bitlens", json_value_init_array());
            JSON_Array *bitlens_array = json_object_get_array(tc_rsp, "bitlens");
            json_array_append_number(bitlens_array, stc->bitlen1);
            json_array_append_number(bitlens_array, stc->bitlen2);
            json_array_append_number(bitlens_array, stc->bitlen3);
            json_array_append_number(bitlens_array, stc->bitlen4);
        }
        // TODO: need to handle other rand_pq types
    }
    
    return ACVP_SUCCESS;
}


/*
 * This function simply releases the data associated with
 * a test case.
 */

static ACVP_RESULT acvp_rsa_keygen_release_tc (ACVP_RSA_KEYGEN_TC *stc) {
    if (stc->e) { free(stc->e); }
    if (stc->seed) { free(stc->seed); }
    if (stc->p) { free(stc->p); }
    if (stc->q) { free(stc->q); }
    if (stc->n) { free(stc->n); }
    if (stc->d) { free(stc->d); }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_rsa_keygen_init_tc (ACVP_CTX *ctx,
                                            ACVP_RSA_KEYGEN_TC *stc,
                                            unsigned int tc_id,
                                            int info_gen_by_server,
                                            char *hash_alg,
                                            char *key_format,
                                            char *pub_exp_mode,
                                            int modulo,
                                            char *prime_test,
                                            int rand_pq,
                                            char *e,
                                            char *seed,
                                            int seed_len,
                                            int bitlen1,
                                            int bitlen2,
                                            int bitlen3,
                                            int bitlen4) {
    memset(stc, 0x0, sizeof(ACVP_RSA_KEYGEN_TC));
    
    stc->info_gen_by_server = info_gen_by_server;
    stc->tc_id = tc_id;
    stc->rand_pq = rand_pq;
    stc->modulo = modulo;
    
    stc->e = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->e) { return ACVP_MALLOC_FAIL; }
    strncpy((char *)stc->e, e, strnlen(e, ACVP_RSA_EXP_LEN_MAX));
    stc->p = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->p) { return ACVP_MALLOC_FAIL; }
    stc->q = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->q) { return ACVP_MALLOC_FAIL; }
    stc->n = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->n) { return ACVP_MALLOC_FAIL; }
    stc->d = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->d) { return ACVP_MALLOC_FAIL; }
    
    stc->seed = calloc(ACVP_RSA_SEEDLEN_MAX, sizeof(char));
    if (!stc->seed) { return ACVP_MALLOC_FAIL; }
    
    stc->hash_alg = calloc(ACVP_RSA_HASH_ALG_LEN_MAX, sizeof(char));
    if (!stc->hash_alg) { return ACVP_MALLOC_FAIL; }
    strncpy(stc->hash_alg, hash_alg, strnlen(hash_alg, ACVP_RSA_HASH_ALG_LEN_MAX));
    
    stc->key_format = calloc(8, sizeof(char));
    if (!stc->key_format) { return ACVP_MALLOC_FAIL; }
    strncpy(stc->key_format, key_format, strnlen(key_format, 8));
    
    stc->pub_exp_mode = calloc(6, sizeof(char));
    if (!stc->pub_exp_mode) { return ACVP_MALLOC_FAIL; }
    strncpy(stc->pub_exp_mode, pub_exp_mode, strnlen(pub_exp_mode, 6));
    
    if (prime_test) {
        stc->prime_test = calloc(5, sizeof(char));
        if (!stc->prime_test) { return ACVP_MALLOC_FAIL; }
        strncpy(stc->prime_test, prime_test, strnlen(prime_test, 5));
    }
    if (info_gen_by_server) {
        stc->bitlen1 = bitlen1;
        stc->bitlen2 = bitlen2;
        stc->bitlen3 = bitlen3;
        stc->bitlen4 = bitlen4;
        acvp_hexstr_to_bin((const unsigned char *)seed, stc->seed, seed_len);
        stc->seed_len = seed_len/2;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_rsa_keygen_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
    unsigned int tc_id;
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *groups;
    JSON_Array *tests;
    JSON_Array *bitlens;

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
    ACVP_RSA_KEYGEN_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    
    ACVP_CIPHER alg_id;
    char *json_result = NULL, *rand_pq_str = NULL;
    unsigned int mod = 0;
    int info_gen_by_server, rand_pq, seed_len;
    char *pub_exp_mode, *key_format, *prime_test;
    char *hash_alg = NULL;
    char *e_str = NULL, *alg_str, *mode_str, *seed, *alg_tbl_index;
    int bitlen1, bitlen2, bitlen3, bitlen4;
    
    alg_str = (char *) json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }
    
    tc.tc.rsa_keygen = &stc;
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
    case ACVP_RSA_KEYGEN:
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
        info_gen_by_server = json_object_get_boolean(groupobj, "infoGeneratedByServer");
        pub_exp_mode = (char *) json_object_get_string(groupobj, "pubExpMode");
        e_str = (char *) json_object_get_string(groupobj, "fixedPubExp");

        key_format = (char *) json_object_get_string(groupobj, "keyFormat");
        rand_pq_str = (char *) json_object_get_string(groupobj, "randPQ");
        prime_test = (char *) json_object_get_string(groupobj, "primeTest");
        
        rand_pq = acvp_lookup_rsa_randpq_index(rand_pq_str);
        mod = json_object_get_number(groupobj, "modulo");
        hash_alg = (char *) json_object_get_string(groupobj, "hashAlg");

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("  infoGenByServer: %s", info_gen_by_server ? "true" : "false");
        ACVP_LOG_INFO("       pubExpMode: %s", pub_exp_mode);
        ACVP_LOG_INFO("        keyFormat: %s", key_format);

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
             * Retrieve values from JSON and initialize the tc
             */
            if (info_gen_by_server) {
                if (!e_str) {
                    e_str = (char *) json_object_get_string(testobj, "e");
                }
                bitlens = json_object_get_array(testobj, "bitlens");
                bitlen1 = json_array_get_number(bitlens, 0);
                bitlen2 = json_array_get_number(bitlens, 1);
                bitlen3 = json_array_get_number(bitlens, 2);
                bitlen4 = json_array_get_number(bitlens, 3);
                seed = (char *) json_object_get_string(testobj, "seed");
                seed_len = strnlen(seed, ACVP_RSA_SEEDLEN_MAX);
            }
    
            rv = acvp_rsa_keygen_init_tc(ctx, &stc, tc_id, info_gen_by_server, hash_alg, key_format,
                                         pub_exp_mode, mod, prime_test, rand_pq, e_str, seed, seed_len,
                                         bitlen1, bitlen2, bitlen3, bitlen4);

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
            rv = acvp_rsa_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                goto key_err;
            }
            
            /*
             * Release all the memory associated with the test case
             */
            key_err:
                acvp_rsa_keygen_release_tc(&stc);

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

