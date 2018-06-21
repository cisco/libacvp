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
static ACVP_RESULT acvp_kdf135_ssh_output_tc (ACVP_CTX *ctx, ACVP_KDF135_SSH_TC *stc,
                                              JSON_Object *tc_rsp);

static ACVP_RESULT acvp_kdf135_ssh_init_tc (ACVP_CTX *ctx,
                                            ACVP_KDF135_SSH_TC *stc,
                                            unsigned int tc_id,
                                            ACVP_CIPHER alg_id,
                                            unsigned int sha_type,
                                            unsigned int e_key_len,
                                            unsigned int i_key_len,
                                            unsigned int iv_len,
                                            unsigned int hash_len,
                                            const char *shared_secret_k,
                                            const char *hash_h,
                                            const char *session_id);

static ACVP_RESULT acvp_kdf135_ssh_release_tc (ACVP_KDF135_SSH_TC *stc);


ACVP_RESULT acvp_kdf135_ssh_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_KDF135_SSH_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;

    ACVP_CIPHER alg_id;
    unsigned int e_key_len;
    unsigned int i_key_len;
    unsigned int iv_len;
    unsigned int hash_len;
    unsigned int sha_type;
    const char *alg_str = NULL;
    const char *mode_str = NULL;
    const char *sha_str = NULL;
    const char *cipher_str = NULL;
    const char *shared_secret_str = NULL;
    const char *session_id_str = NULL;
    const char *hash_str = NULL;
    char *json_result;

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("unable to parse 'mode' from JSON");
        return (ACVP_MALFORMED_JSON);
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_ssh = &stc;

    /*
     * Get the crypto module handler for this hash algorithm
     */
    alg_id = acvp_lookup_cipherwithmode_index(alg_str, mode_str);
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

        // Get the expected (user will generate) key and iv lengths
        cipher_str = json_object_get_string(groupobj, "cipher");
        sha_str = json_object_get_string(groupobj, "hashAlg");

        /*
         * Determine the encrypt key_len, inferred from cipher.
         */
        if (!strncmp(cipher_str, "TDES", 4)) {
            e_key_len = ACVP_KEY_LEN_TDES;
            iv_len = ACVP_BLOCK_LEN_TDES;
        } else if (!strncmp(cipher_str, "AES-128", 7)) {
            e_key_len = ACVP_KEY_LEN_AES128;
            iv_len = ACVP_BLOCK_LEN_AES128;
        } else if (!strncmp(cipher_str, "AES-192", 7)) {
            e_key_len = ACVP_KEY_LEN_AES192;
            iv_len = ACVP_BLOCK_LEN_AES192;
        } else if (!strncmp(cipher_str, "AES-256", 7)) {
            e_key_len = ACVP_KEY_LEN_AES256;
            iv_len = ACVP_BLOCK_LEN_AES256;
        } else {
            ACVP_LOG_ERR("Unsupported cipher type");
            return ACVP_NO_CAP;
        }

        /*
         * Determine the sha mode to operate.
         * Also infer the hash_len and integrity key_len.
         */
        if (!strncmp(sha_str, "SHA-1", 5)) {
            sha_type = ACVP_KDF135_SSH_CAP_SHA1;
            i_key_len = hash_len = ACVP_BYTE_LEN_HMAC_SHA1;
        } else if (!strncmp(sha_str, "SHA2-224", 8)) {
            sha_type = ACVP_KDF135_SSH_CAP_SHA224;
            i_key_len = hash_len = ACVP_BYTE_LEN_HMAC_SHA224;
        } else if (!strncmp(sha_str, "SHA2-256", 8)) {
            sha_type = ACVP_KDF135_SSH_CAP_SHA256;
            i_key_len = hash_len = ACVP_BYTE_LEN_HMAC_SHA256;
        } else if (!strncmp(sha_str, "SHA2-384", 8)) {
            sha_type = ACVP_KDF135_SSH_CAP_SHA384;
            i_key_len = hash_len = ACVP_BYTE_LEN_HMAC_SHA384;
        } else if (!strncmp(sha_str, "SHA2-512", 8)) {
            sha_type = ACVP_KDF135_SSH_CAP_SHA512;
            i_key_len = hash_len = ACVP_BYTE_LEN_HMAC_SHA512;
        } else {
            ACVP_LOG_ERR("Unsupported sha type");
            return ACVP_NO_CAP;
        }

        /*
         * Log Test Group information...
         */
        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("        cipher: %s", cipher_str);
        ACVP_LOG_INFO("       hashAlg: %s", sha_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new KDF SSH test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int) json_object_get_number(testobj, "tcId");
            shared_secret_str = json_object_get_string(testobj, "k");
            hash_str = json_object_get_string(testobj, "h");
            session_id_str = json_object_get_string(testobj, "sessionId");

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            ACVP_LOG_INFO("                k: %s", shared_secret_str);
            ACVP_LOG_INFO("                h: %s", hash_str);
            ACVP_LOG_INFO("       session_id: %s", session_id_str);

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
            acvp_kdf135_ssh_init_tc(ctx, &stc, tc_id, alg_id,
                                    sha_type, e_key_len, i_key_len, iv_len, hash_len,
                                    shared_secret_str, hash_str, session_id_str);

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
static ACVP_RESULT acvp_kdf135_ssh_output_tc (ACVP_CTX *ctx,
                                              ACVP_KDF135_SSH_TC *stc,
                                              JSON_Object *tc_rsp) {
    char *tmp = NULL;
    int rv = 0;

    if ((stc->iv_len * 2) > ACVP_KDF135_SSH_STR_OUT_MAX ||
        (stc->e_key_len * 2) > ACVP_KDF135_SSH_STR_OUT_MAX ||
        (stc->i_key_len * 2) > ACVP_KDF135_SSH_STR_OUT_MAX) {
        ACVP_LOG_ERR("iv_len*2(%u) || e_key_len*2(%u) || i_key_len*2(%u) > ACVP_KDF135_SSH_STR_OUT_MAX(%u)",
                     (stc->iv_len * 2), (stc->e_key_len * 2), (stc->i_key_len * 2),
                     ACVP_KDF135_SSH_STR_OUT_MAX);
        ACVP_LOG_ERR("Hint, make sure user isn't modifying those field values");
        return ACVP_DATA_TOO_LARGE;
    }

    tmp = calloc(ACVP_KDF135_SSH_STR_OUT_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr((const unsigned char *)stc->cs_init_iv,
                            stc->iv_len, (unsigned char *)tmp);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("acvp_bin_to_hexstr() failure");
        return rv;
    }
    json_object_set_string(tc_rsp, "initialIvClient", tmp);
    memset(tmp, 0, ACVP_KDF135_SSH_STR_OUT_MAX);

    rv = acvp_bin_to_hexstr((const unsigned char *)stc->cs_encrypt_key,
                            stc->e_key_len, (unsigned char *)tmp);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("acvp_bin_to_hexstr() failure");
        return rv;
    }
    json_object_set_string(tc_rsp, "encryptionKeyClient", tmp);
    memset(tmp, 0, ACVP_KDF135_SSH_STR_OUT_MAX);

    rv = acvp_bin_to_hexstr((const unsigned char *)stc->cs_integrity_key,
                            stc->i_key_len, (unsigned char *)tmp);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("acvp_bin_to_hexstr() failure");
        return rv;
    }
    json_object_set_string(tc_rsp, "integrityKeyClient", tmp);
    memset(tmp, 0, ACVP_KDF135_SSH_STR_OUT_MAX);

    rv = acvp_bin_to_hexstr((const unsigned char *)stc->sc_init_iv,
                            stc->iv_len, (unsigned char *)tmp);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("acvp_bin_to_hexstr() failure");
        return rv;
    }
    json_object_set_string(tc_rsp, "initialIvServer", tmp);
    memset(tmp, 0, ACVP_KDF135_SSH_STR_OUT_MAX);

    rv = acvp_bin_to_hexstr((const unsigned char *)stc->sc_encrypt_key,
                            stc->e_key_len, (unsigned char *)tmp);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("acvp_bin_to_hexstr() failure");
        return rv;
    }
    json_object_set_string(tc_rsp, "encryptionKeyServer", tmp);
    memset(tmp, 0, ACVP_KDF135_SSH_STR_OUT_MAX);

    rv = acvp_bin_to_hexstr((const unsigned char *)stc->sc_integrity_key,
                            stc->i_key_len, (unsigned char *)tmp);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("acvp_bin_to_hexstr() failure");
        return rv;
    }
    json_object_set_string(tc_rsp, "integrityKeyServer", tmp);

    free(tmp);

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kdf135_ssh_init_tc (ACVP_CTX *ctx,
                                            ACVP_KDF135_SSH_TC *stc,
                                            unsigned int tc_id,
                                            ACVP_CIPHER alg_id,
                                            unsigned int sha_type,
                                            unsigned int e_key_len,
                                            unsigned int i_key_len,
                                            unsigned int iv_len,
                                            unsigned int hash_len,
                                            const char *shared_secret_k,
                                            const char *hash_h,
                                            const char *session_id)
{
    unsigned int shared_secret_len = 0;
    unsigned int session_id_len = 0;

    memset(stc, 0x0, sizeof(ACVP_KDF135_SSH_TC));

    // Get the byte lengths
    shared_secret_len = strnlen(shared_secret_k, ACVP_KDF135_SSH_STR_IN_MAX) / 2;
    session_id_len = strnlen(session_id, ACVP_KDF135_SSH_STR_IN_MAX) / 2;

    stc->shared_secret_k = calloc(shared_secret_len, sizeof(unsigned char));
    if (!stc->shared_secret_k) { return ACVP_MALLOC_FAIL; }
    stc->hash_h = calloc(hash_len, sizeof(unsigned char));
    if (!stc->hash_h) { return ACVP_MALLOC_FAIL; }
    stc->session_id = calloc(session_id_len, sizeof(unsigned char));
    if (!stc->session_id) { return ACVP_MALLOC_FAIL; }

    // Convert from hex string to binary
    acvp_hexstr_to_bin(shared_secret_k, stc->shared_secret_k, shared_secret_len);
    acvp_hexstr_to_bin(hash_h, stc->hash_h, hash_len);
    acvp_hexstr_to_bin(session_id, stc->session_id, session_id_len);

    // Allocate answer buffers
    stc->cs_init_iv = calloc(ACVP_KDF135_SSH_IV_MAX, sizeof(unsigned char));
    if (!stc->cs_init_iv) { return ACVP_MALLOC_FAIL; }
    stc->sc_init_iv = calloc(ACVP_KDF135_SSH_IV_MAX, sizeof(unsigned char));
    if (!stc->sc_init_iv) { return ACVP_MALLOC_FAIL; }

    stc->cs_encrypt_key = calloc(ACVP_KDF135_SSH_EKEY_MAX, sizeof(unsigned char));
    if (!stc->cs_encrypt_key) { return ACVP_MALLOC_FAIL; }
    stc->sc_encrypt_key = calloc(ACVP_KDF135_SSH_EKEY_MAX, sizeof(unsigned char));
    if (!stc->sc_encrypt_key) { return ACVP_MALLOC_FAIL; }

    stc->cs_integrity_key = calloc(ACVP_KDF135_SSH_IKEY_MAX, sizeof(unsigned char));
    if (!stc->cs_integrity_key) { return ACVP_MALLOC_FAIL; }
    stc->sc_integrity_key = calloc(ACVP_KDF135_SSH_IKEY_MAX, sizeof(unsigned char));
    if (!stc->sc_integrity_key) { return ACVP_MALLOC_FAIL; }

    stc->tc_id = tc_id;
    stc->cipher = alg_id;
    stc->sha_type = sha_type;
    stc->e_key_len = e_key_len;
    stc->i_key_len = i_key_len;
    stc->iv_len = iv_len;
    stc->shared_secret_len = shared_secret_len;
    stc->hash_len = hash_len;
    stc->session_id_len = session_id_len;

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf135_ssh_release_tc (ACVP_KDF135_SSH_TC *stc) {
    if (stc->shared_secret_k) free(stc->shared_secret_k);
    if (stc->hash_h) free(stc->hash_h);
    if (stc->session_id) free(stc->session_id);
    if (stc->cs_init_iv) free(stc->cs_init_iv);
    if (stc->sc_init_iv) free(stc->sc_init_iv);
    if (stc->cs_encrypt_key) free(stc->cs_encrypt_key);
    if (stc->sc_encrypt_key) free(stc->sc_encrypt_key);
    if (stc->cs_integrity_key) free(stc->cs_integrity_key);
    if (stc->sc_integrity_key) free(stc->sc_integrity_key);

    memset(stc, 0, sizeof(ACVP_KDF135_SSH_TC));

    return ACVP_SUCCESS;
}
