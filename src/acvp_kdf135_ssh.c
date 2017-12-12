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
static ACVP_RESULT acvp_kdf135_ssh_output_tc(ACVP_CTX *ctx, ACVP_KDF135_SSH_TC *stc,
                                             JSON_Object *tc_rsp);

static ACVP_RESULT acvp_kdf135_ssh_init_tc(ACVP_CTX *ctx,
                                           ACVP_KDF135_SSH_TC *stc,
                                           unsigned int tc_id,
                                           ACVP_CIPHER alg_id,
                                           unsigned int  sha_type,
                                           unsigned int  sh_sec_len,
                                           unsigned int  iv_len,
                                           unsigned int  key_len,
                                           const unsigned char *shared_sec_k,
                                           const unsigned char *hash_h,
                                           unsigned int hash_len,
                                           const unsigned char *session_id,
                                           unsigned int session_len);
static ACVP_RESULT acvp_kdf135_ssh_release_tc(ACVP_KDF135_SSH_TC *stc);


ACVP_RESULT acvp_kdf135_ssh_kat_handler (ACVP_CTX *ctx, JSON_Object *obj)
{
    unsigned int        tc_id;
    JSON_Value          *groupval;
    JSON_Object         *groupobj = NULL;
    JSON_Value          *testval;
    JSON_Object         *testobj = NULL;
    JSON_Array          *groups;
    JSON_Array          *tests;

    JSON_Value          *reg_arry_val  = NULL;
    JSON_Object         *reg_obj       = NULL;
    JSON_Array          *reg_arry      = NULL;

    int i, g_cnt;
    int j, t_cnt;

    JSON_Value          *r_vs_val = NULL;
    JSON_Object         *r_vs = NULL;
    JSON_Array          *r_tarr = NULL; /* Response testarray */
    JSON_Value          *r_tval = NULL; /* Response testval */
    JSON_Object         *r_tobj = NULL; /* Response testobj */
    ACVP_CAPS_LIST      *cap;
    ACVP_KDF135_SSH_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT         rv;
    const char          *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER	        alg_id;
    const char          *sha = NULL;
    unsigned int        sh_sec_len;
    unsigned int        iv_len;
    unsigned int        key_len;
    unsigned int        hash_len;
    unsigned int        session_len;
    unsigned int        sha_type;
    char                *sh_secret_k;
    char                *session_id;
    char                *hash_h;
    char                *json_result;

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON for KDF SSH.");
        return (ACVP_MALFORMED_JSON);
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_ssh = &stc;

    /*
     * Get the crypto module handler for this hash algorithm
     */
    alg_id = acvp_lookup_cipher_index(alg_str);
    if (alg_id < ACVP_CIPHER_START) {
        ACVP_LOG_ERR("unsupported algorithm (%s)", alg_str);
        return (ACVP_UNSUPPORTED_OP);
    }
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
        return(rv);
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

        sha        = json_object_get_string(testobj, "sha");
        sh_sec_len = (unsigned int)json_object_get_number(groupobj, "shSecLen");
        iv_len     = (unsigned int)json_object_get_number(groupobj, "ivLen");
        key_len    = (unsigned int)json_object_get_number(groupobj, "keyLen");

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("          sha: %s", sha);

        if (!strncmp(sha, "SHA-256", 7)) {
            sha_type = ACVP_KDF135_SSH_CAP_SHA256;
        } else if (!strncmp(sha, "SHA-384", 7)) {
            sha_type = ACVP_KDF135_SSH_CAP_SHA384;
        } else if (!strncmp(sha, "SHA-512", 7)) {
            sha_type = ACVP_KDF135_SSH_CAP_SHA512;
        } else {
            ACVP_LOG_ERR("Not SSH SHA");
            return ACVP_NO_CAP;
        }

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new KDF SSH test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");
            sh_secret_k = (char*)json_object_get_string(testobj, "k");
            hash_h = (char*)json_object_get_string(testobj, "h");
            session_id = (char*)json_object_get_string(testobj, "sessionID");
            hash_len = strlen(hash_h);
            session_len = strlen(session_id);

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
            acvp_kdf135_ssh_init_tc(ctx,
                                    &stc,
                                    tc_id,
                                    alg_id,
                                    sha_type,
                                    sh_sec_len,
                                    iv_len,
                                    key_len,
                                    (const unsigned char*)sh_secret_k,
                                    (const unsigned char*)hash_h,
                                    hash_len,
                                    (const unsigned char*)session_id,
                                    session_len);

            /* Process the current test vector... */
            rv = (cap->crypto_handler)(&tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("crypto module failed the KDF SSH operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
            */
            rv = acvp_kdf135_ssh_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in hash module");
                return rv;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_kdf135_ssh_release_tc(&stc);

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

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_kdf135_ssh_output_tc(ACVP_CTX *ctx, ACVP_KDF135_SSH_TC *stc, JSON_Object *tc_rsp)
{
    char *tmp;

    tmp = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_kdf135_ssh_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    json_object_set_string(tc_rsp, "csInitIV", tmp);

    tmp = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_kdf135_ssh_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    json_object_set_string(tc_rsp, "scInitIV", tmp);

    tmp = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_kdf135_ssh_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    json_object_set_string(tc_rsp, "csEKey", tmp);

    tmp = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_kdf135_ssh_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    json_object_set_string(tc_rsp, "scEKey", tmp);

    tmp = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_kdf135_ssh_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    json_object_set_string(tc_rsp, "csIKey", tmp);

    tmp = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_kdf135_ssh_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    json_object_set_string(tc_rsp, "scIKey", tmp);
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kdf135_ssh_init_tc(ACVP_CTX *ctx,
                                    ACVP_KDF135_SSH_TC *stc,
                                    unsigned int tc_id,
                                    ACVP_CIPHER alg_id,
                                    unsigned int  sha_type,
                                    unsigned int  sh_sec_len,           //bites (spec)
                                    unsigned int  iv_len,               //bites (spec)
                                    unsigned int  key_len,              //bites (spec)
                                    const unsigned char *shared_sec_k,
                                    const unsigned char *hash_h,
                                    unsigned int hash_len,              //bytes
                                    const unsigned char *session_id,
                                    unsigned int session_len)           //bytes
{
    memset(stc, 0x0, sizeof(ACVP_KDF135_SSH_TC));

    if ((sh_sec_len/8 > ACVP_KDF135_SSH_MSG_MAX) ||
        (iv_len/8 > ACVP_KDF135_SSH_MSG_MAX) ||
        (key_len/8 > ACVP_KDF135_SSH_MSG_MAX) ||
        (hash_len > ACVP_KDF135_SSH_MSG_MAX) ||
        (session_len > ACVP_KDF135_SSH_MSG_MAX) ) {
        ACVP_LOG_ERR("Input length too long KDF SSH.");
        return (ACVP_DATA_TOO_LARGE);
    }

    stc->shared_sec_k = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!stc->shared_sec_k) return ACVP_MALLOC_FAIL;
    stc->hash_h = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!stc->hash_h) return ACVP_MALLOC_FAIL;
    stc->session_id = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!stc->session_id) return ACVP_MALLOC_FAIL;

    stc->cs_init_iv = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!stc->cs_init_iv) return ACVP_MALLOC_FAIL;
    stc->sc_init_iv = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!stc->sc_init_iv) return ACVP_MALLOC_FAIL;

    stc->cs_e_key = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!stc->cs_e_key) return ACVP_MALLOC_FAIL;
    stc->sc_e_key = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!stc->sc_e_key) return ACVP_MALLOC_FAIL;

    stc->cs_i_key = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!stc->cs_i_key) return ACVP_MALLOC_FAIL;
    stc->sc_i_key = calloc(1, ACVP_KDF135_SSH_MSG_MAX);
    if (!stc->sc_i_key) return ACVP_MALLOC_FAIL;

    memcpy(stc->shared_sec_k, shared_sec_k, key_len/8);
    memcpy(stc->hash_h, hash_h, hash_len);
    memcpy(stc->session_id, session_id, session_len);

    memset(stc->cs_init_iv, 0, ACVP_KDF135_SSH_MSG_MAX);
    memset(stc->sc_init_iv, 0, ACVP_KDF135_SSH_MSG_MAX);
    memset(stc->cs_e_key,   0, ACVP_KDF135_SSH_MSG_MAX);
    memset(stc->sc_e_key,   0, ACVP_KDF135_SSH_MSG_MAX);
    memset(stc->cs_i_key,   0, ACVP_KDF135_SSH_MSG_MAX);
    memset(stc->sc_i_key,   0, ACVP_KDF135_SSH_MSG_MAX);

    stc->tc_id        = tc_id;
    stc->cipher       = alg_id;
    stc->sha_type     = sha_type;
    stc->sh_sec_len   = sh_sec_len;     //bites
    stc->iv_len       = iv_len;         //bites
    stc->key_len      = key_len;        //bits
    stc->session_len  = session_len;    //bytes
    stc->hash_len     = hash_len;       //bytes
    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf135_ssh_release_tc(ACVP_KDF135_SSH_TC *stc)
{
    free(stc->shared_sec_k);
    free(stc->hash_h);
    free(stc->session_id);
    free(stc->cs_init_iv);
    free(stc->sc_init_iv);
    free(stc->cs_e_key);
    free(stc->sc_e_key);
    free(stc->cs_i_key);
    free(stc->sc_i_key);

    memset(stc, 0x0, sizeof(ACVP_KDF135_SSH_TC));
    return ACVP_SUCCESS;
}
