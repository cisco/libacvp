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

#define ACVP_SYM_KEY_MAX    64
#define ACVP_SYM_PT_MAX     1024
#define ACVP_SYM_CT_MAX     1024
#define ACVP_SYM_IV_MAX     64
#define ACVP_SYM_TAG_MAX    64
#define ACVP_SYM_AAD_MAX    128

extern char *sym_ciph_name[];

/*
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_aes_output_tc(ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, JSON_Object *tc_rsp);
static ACVP_RESULT acvp_aes_init_tc(ACVP_CTX *ctx,
                                    ACVP_SYM_CIPHER_TC *stc,
                                    unsigned int tc_id,
                                    unsigned char *j_key,
                                    unsigned char *j_pt,
                                    unsigned char *j_aad,
                                    unsigned int key_len,
                                    unsigned int iv_len,
                                    unsigned int pt_len,
                                    unsigned int aad_len,
                                    unsigned int tag_len);
static ACVP_RESULT acvp_aes_release_tc(ACVP_SYM_CIPHER_TC *stc);

/*
 * This is the handler for AES-GCM KAT values.  This will parse
 * a JSON encoded vector set for AES-GCM.  Each test case is
 * parsed, processed, and a response is generated to be sent
 * back to the ACV server by the transport layer.
 */
ACVP_RESULT acvp_aes_kat_handler(ACVP_CTX *ctx, JSON_Object *obj)
{
    unsigned int tc_id, keylen, ivlen, ptlen, aadlen, taglen;
    unsigned char *     key, *pt, *aad;
    JSON_Value *        groupval;
    JSON_Object         *groupobj = NULL;
    JSON_Value          *testval;
    JSON_Object         *testobj = NULL;
    JSON_Array          *groups;
    JSON_Array          *tests;
    int i, g_cnt;
    int j, t_cnt;
    JSON_Object         *r_vs = NULL;
    JSON_Array          *r_tarr = NULL; /* Response testarray */
    JSON_Value          *r_tval = NULL; /* Response testval */
    JSON_Object         *r_tobj = NULL; /* Response testobj */
    ACVP_CAPS_LIST      *cap;
    ACVP_SYM_CIPHER_TC stc;
    ACVP_CIPHER_TC tc;
    ACVP_RESULT rv;

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.symmetric = &stc;

    /*
     * Get the crypto module handler for AES-GCM mode
     */
    //TODO: need to support more modes such as CBC, CTR, EBC, etc.
    cap = acvp_locate_cap_entry(ctx, ACVP_AES_GCM);
    if (!cap) {
        acvp_log_msg(ctx, "ERROR: ACVP server requesting unsupported capability");
        return (ACVP_UNSUPPORTED_OP);
    }

    /*
     * Start to build the JSON response
     * TODO: This code will likely be common to all the algorithms, need to move this
     */
    if (ctx->kat_resp) {
        json_value_free(ctx->kat_resp);
    }
    ctx->kat_resp = json_value_init_object();
    r_vs = json_value_get_object(ctx->kat_resp);
    json_object_set_string(r_vs, "acv_version", ACVP_VERSION);
    json_object_set_number(r_vs, "vs_id", ctx->vs_id);
    json_object_set_string(r_vs, "algorithm", sym_ciph_name[ACVP_AES_GCM]);
    json_object_set_string(r_vs, "mode", "encrypt");
    json_object_set_value(r_vs, "test_results", json_value_init_array());
    r_tarr = json_object_get_array(r_vs, "test_results");

    groups = json_object_get_array(obj, "test_groups");
    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        keylen = (unsigned int)json_object_get_number(groupobj, "keylen");
        ivlen = (unsigned int)json_object_get_number(groupobj, "ivlen");
        ptlen = (unsigned int)json_object_get_number(groupobj, "ptlen");
        aadlen = (unsigned int)json_object_get_number(groupobj, "aadlen");
        taglen = (unsigned int)json_object_get_number(groupobj, "taglen");

        acvp_log_msg(ctx, "    Test group: %d", i);
        acvp_log_msg(ctx, "        keylen: %d", keylen);
        acvp_log_msg(ctx, "         ivlen: %d", ivlen);
        acvp_log_msg(ctx, "         ptlen: %d", ptlen);
        acvp_log_msg(ctx, "        aadlen: %d", aadlen);
        acvp_log_msg(ctx, "        taglen: %d", taglen);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            acvp_log_msg(ctx, "Found new AES test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int)json_object_get_number(testobj, "tc_id");
            key = (unsigned char *)json_object_get_string(testobj, "key");
            pt = (unsigned char *)json_object_get_string(testobj, "pt");
            aad = (unsigned char *)json_object_get_string(testobj, "aad");

            acvp_log_msg(ctx, "        Test case: %d", j);
            acvp_log_msg(ctx, "            tc_id: %d", tc_id);
            acvp_log_msg(ctx, "              key: %s", key);
            acvp_log_msg(ctx, "               pt: %s", pt);
            acvp_log_msg(ctx, "              aad: %s", aad);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tc_id", tc_id);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             * TODO: this does mallocs, we can probably do the mallocs once for
             *       the entire vector set to be more efficient
             */
            acvp_aes_init_tc(ctx, &stc, tc_id, key, pt, aad, keylen, ivlen, ptlen, aadlen, taglen);

            /* Process the current AES encrypt test vector... */
            rv = (cap->crypto_handler)(&tc);
            if (rv != ACVP_SUCCESS) {
                acvp_log_msg(ctx, "ERROR: crypto module failed the operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_aes_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                acvp_log_msg(ctx, "ERROR: JSON output failure in AES module");
                return rv;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_aes_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
    }

    //FIXME
    printf("\n\n%s\n\n", json_serialize_to_string_pretty(ctx->kat_resp));

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_aes_output_tc(ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, JSON_Object *tc_rsp)
{
    ACVP_RESULT rv;
    char *tmp;

    tmp = malloc(ACVP_SYM_CT_MAX);
    if (!tmp) {
        acvp_log_msg(ctx, "Unable to malloc in acvp_aes_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    memset(tmp, 0x0, ACVP_SYM_CT_MAX);
    rv = acvp_bin_to_hexstr(stc->iv, stc->iv_len, (unsigned char*)tmp);
    if (rv != ACVP_SUCCESS) {
        acvp_log_msg(ctx, "hex conversion failure (iv)");
        return rv;
    }
    json_object_set_string(tc_rsp, "iv", tmp);

    memset(tmp, 0x0, ACVP_SYM_CT_MAX);
    rv = acvp_bin_to_hexstr(stc->ct, stc->ct_len, (unsigned char*)tmp);
    if (rv != ACVP_SUCCESS) {
        acvp_log_msg(ctx, "hex conversion failure (ct)");
        return rv;
    }
    json_object_set_string(tc_rsp, "ct", tmp);

    memset(tmp, 0x0, ACVP_SYM_CT_MAX);
    rv = acvp_bin_to_hexstr(stc->tag, stc->tag_len, (unsigned char*)tmp);
    if (rv != ACVP_SUCCESS) {
        acvp_log_msg(ctx, "hex conversion failure (tag)");
        return rv;
    }
    json_object_set_string(tc_rsp, "tag", tmp);

    free(tmp);

    return ACVP_SUCCESS;
}


/*
 * This function is used to fill-in the data for an AES
 * test case.  The JSON parsing logic invokes this after the
 * plaintext, key, etc. have been parsed from the vector set.
 * The ACVP_SYM_CIPHER_TC struct will hold all the data for
 * a given test case, which is then passed to the crypto
 * module to perform the actual encryption/decryption for
 * the test case.
 */
static ACVP_RESULT acvp_aes_init_tc(ACVP_CTX *ctx,
                                    ACVP_SYM_CIPHER_TC *stc,
                                    unsigned int tc_id,
                                    unsigned char *j_key,
                                    unsigned char *j_pt,
                                    unsigned char *j_aad,
                                    unsigned int key_len,
                                    unsigned int iv_len,
                                    unsigned int pt_len,
                                    unsigned int aad_len,
                                    unsigned int tag_len)
{
    ACVP_RESULT rv;

    //FIXME:  check lengths do not exceed MAX values below

    memset(stc, 0x0, sizeof(ACVP_SYM_CIPHER_TC));
    //FIXME: need malloc failure checks
    stc->key = malloc(ACVP_SYM_KEY_MAX);
    stc->pt = malloc(ACVP_SYM_PT_MAX);
    stc->ct = malloc(ACVP_SYM_CT_MAX);
    stc->tag = malloc(ACVP_SYM_TAG_MAX);
    stc->iv = malloc(ACVP_SYM_IV_MAX);
    stc->aad = malloc(ACVP_SYM_AAD_MAX);

    //FIXME: need to sanity check input lengths, or we'll crash if input is too large
    rv = acvp_hexstr_to_bin((const unsigned char *)j_key, stc->key);
    if (rv != ACVP_SUCCESS) {
        acvp_log_msg(ctx, "Hex converstion failure (key)");
        return rv;
    }

    rv = acvp_hexstr_to_bin((const unsigned char *)j_pt, stc->pt);
    if (rv != ACVP_SUCCESS) {
        acvp_log_msg(ctx, "Hex converstion failure (pt)");
        return rv;
    }

    rv = acvp_hexstr_to_bin((const unsigned char *)j_aad, stc->aad);
    if (rv != ACVP_SUCCESS) {
        acvp_log_msg(ctx, "Hex converstion failure (aad)");
        return rv;
    }

    /*
     * These lengths come in as bit lengths from the ACVP server.
     * We convert to bytes.
     * TODO: do we need to support bit lengths not a multiple of 8?
     */
    stc->tc_id = tc_id;
    stc->key_len = key_len;
    stc->iv_len = iv_len/8;
    stc->pt_len = pt_len/8;
    stc->ct_len = pt_len/8;
    stc->tag_len = tag_len/8;
    stc->aad_len = aad_len/8;

    //TODO: for now we only support this mode
    stc->cipher = ACVP_AES_GCM;
    stc->direction = ACVP_DIR_ENCRYPT;

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_aes_release_tc(ACVP_SYM_CIPHER_TC *stc)
{
    free(stc->key);
    free(stc->pt);
    free(stc->ct);
    free(stc->tag);
    free(stc->iv);
    free(stc->aad);
    memset(stc, 0x0, sizeof(ACVP_SYM_CIPHER_TC));

    return ACVP_SUCCESS;
}
