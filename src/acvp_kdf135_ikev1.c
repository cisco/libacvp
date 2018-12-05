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
static ACVP_RESULT acvp_kdf135_ikev1_output_tc(ACVP_CTX *ctx, ACVP_KDF135_IKEV1_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv;
    char *tmp = NULL;

    tmp = calloc(ACVP_KDF135_IKEV1_SKEY_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_kdf135 tpm_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(stc->s_key_id, stc->s_key_id_len, tmp, ACVP_KDF135_IKEV1_SKEY_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (s_key_id)");
        goto err;
    }
    json_object_set_string(tc_rsp, "sKeyId", (const char *)tmp);
    memset(tmp, 0x0, ACVP_KDF135_IKEV1_SKEY_STR_MAX);

    rv = acvp_bin_to_hexstr(stc->s_key_id_d, stc->s_key_id_d_len, tmp, ACVP_KDF135_IKEV1_SKEY_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (s_key_id_d)");
        goto err;
    }
    json_object_set_string(tc_rsp, "sKeyIdD", (const char *)tmp);
    memset(tmp, 0x0, ACVP_KDF135_IKEV1_SKEY_STR_MAX);

    rv = acvp_bin_to_hexstr(stc->s_key_id_a, stc->s_key_id_a_len, tmp, ACVP_KDF135_IKEV1_SKEY_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (s_key_id_a)");
        goto err;
    }
    json_object_set_string(tc_rsp, "sKeyIdA", (const char *)tmp);
    memset(tmp, 0x0, ACVP_KDF135_IKEV1_SKEY_STR_MAX);

    rv = acvp_bin_to_hexstr(stc->s_key_id_e, stc->s_key_id_e_len, tmp, ACVP_KDF135_IKEV1_SKEY_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (s_key_id_e)");
        goto err;
    }
    json_object_set_string(tc_rsp, "sKeyIdE", (const char *)tmp);
    memset(tmp, 0x0, ACVP_KDF135_IKEV1_SKEY_STR_MAX);

err:
    free(tmp);
    return rv;
}

static ACVP_RESULT acvp_kdf135_ikev1_init_tc(ACVP_CTX *ctx,
                                             ACVP_KDF135_IKEV1_TC *stc,
                                             unsigned int tc_id,
                                             ACVP_HASH_ALG hash_alg,
                                             ACVP_KDF135_IKEV1_AUTH_METHOD auth_method,
                                             int init_nonce_len,
                                             int resp_nonce_len,
                                             int dh_secret_len,
                                             int psk_len,
                                             char *init_nonce,
                                             char *resp_nonce,
                                             char *init_ckey,
                                             char *resp_ckey,
                                             char *gxy,
                                             char *psk) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    memset(stc, 0x0, sizeof(ACVP_KDF135_IKEV1_TC));

    stc->tc_id = tc_id;

    stc->hash_alg = hash_alg;
    stc->auth_method = auth_method;

    stc->init_nonce_len = ACVP_BIT2BYTE(init_nonce_len);
    stc->resp_nonce_len = ACVP_BIT2BYTE(resp_nonce_len);
    stc->dh_secret_len = ACVP_BIT2BYTE(dh_secret_len);
    stc->psk_len = ACVP_BIT2BYTE(psk_len);

    stc->init_nonce = calloc(ACVP_KDF135_IKEV1_INIT_NONCE_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->init_nonce) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(init_nonce, stc->init_nonce, ACVP_KDF135_IKEV1_INIT_NONCE_BYTE_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (init_nonce)");
        return rv;
    }

    stc->resp_nonce = calloc(ACVP_KDF135_IKEV1_RESP_NONCE_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->resp_nonce) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(resp_nonce, stc->resp_nonce, ACVP_KDF135_IKEV1_RESP_NONCE_BYTE_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (resp_nonce)");
        return rv;
    }

    stc->init_ckey = calloc(ACVP_KDF135_IKEV1_COOKIE_BYTE_MAX,
                            sizeof(unsigned char));
    if (!stc->init_ckey) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(init_ckey, stc->init_ckey, ACVP_KDF135_IKEV1_COOKIE_BYTE_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (init_ckey)");
        return rv;
    }

    stc->resp_ckey = calloc(ACVP_KDF135_IKEV1_COOKIE_BYTE_MAX,
                            sizeof(unsigned char));
    if (!stc->resp_ckey) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(resp_ckey, stc->resp_ckey, ACVP_KDF135_IKEV1_COOKIE_BYTE_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (resp_ckey)");
        return rv;
    }

    stc->gxy = calloc(ACVP_KDF135_IKEV1_DH_SHARED_SECRET_BYTE_MAX,
                      sizeof(unsigned char));
    if (!stc->gxy) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(gxy, stc->gxy, ACVP_KDF135_IKEV1_DH_SHARED_SECRET_BYTE_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (gxy)");
        return rv;
    }

    if (psk != NULL) {
        /* Only for PSK authentication method */
        stc->psk = calloc(ACVP_KDF135_IKEV1_PSK_BYTE_MAX,
                          sizeof(unsigned char));
        if (!stc->psk) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(psk, stc->psk, ACVP_KDF135_IKEV1_PSK_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (psk)");
            return rv;
        }
    }

    stc->s_key_id = calloc(ACVP_KDF135_IKEV1_SKEY_BYTE_MAX,
                           sizeof(unsigned char));
    if (!stc->s_key_id) { return ACVP_MALLOC_FAIL; }
    stc->s_key_id_a = calloc(ACVP_KDF135_IKEV1_SKEY_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->s_key_id_a) { return ACVP_MALLOC_FAIL; }
    stc->s_key_id_d = calloc(ACVP_KDF135_IKEV1_SKEY_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->s_key_id_d) { return ACVP_MALLOC_FAIL; }
    stc->s_key_id_e = calloc(ACVP_KDF135_IKEV1_SKEY_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->s_key_id_e) { return ACVP_MALLOC_FAIL; }

    return rv;
}

static ACVP_RESULT acvp_kdf135_ikev1_release_tc(ACVP_KDF135_IKEV1_TC *stc) {
    if (stc->init_nonce) { free(stc->init_nonce); }
    if (stc->resp_nonce) { free(stc->resp_nonce); }
    if (stc->init_ckey) { free(stc->init_ckey); }
    if (stc->resp_ckey) { free(stc->resp_ckey); }
    if (stc->gxy) { free(stc->gxy); }
    if (stc->psk) { free(stc->psk); }
    if (stc->s_key_id) { free(stc->s_key_id); }
    if (stc->s_key_id_d) { free(stc->s_key_id_d); }
    if (stc->s_key_id_a) { free(stc->s_key_id_a); }
    if (stc->s_key_id_e) { free(stc->s_key_id_e); }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_kdf135_ikev1_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
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
    JSON_Array *r_tarr = NULL, *r_garr = NULL;  /* Response testarray, grouparray */
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_IKEV1_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER alg_id;
    char *json_result;

    ACVP_HASH_ALG hash_alg = 0;
    ACVP_KDF135_IKEV1_AUTH_METHOD auth_method = 0;
    const char *hash_alg_str = NULL, *auth_method_str = NULL;
    char *init_ckey = NULL, *resp_ckey = NULL, *gxy = NULL, *psk = NULL, *init_nonce = NULL, *resp_nonce = NULL;
    int init_nonce_len = 0, resp_nonce_len = 0, dh_secret_len = 0, psk_len = 0;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON.");
        return ACVP_MALFORMED_JSON;
    }

    if (strncmp(alg_str, "kdf-components", strlen("kdf-components"))) {
        ACVP_LOG_ERR("Invalid algorithm %s", alg_str);
        return ACVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_ikev1 = &stc;
    alg_id = ACVP_KDF135_IKEV1;
    stc.cipher = alg_id;

    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability %s : %d.", alg_str, alg_id);
        return ACVP_UNSUPPORTED_OP;
    }

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct. ");
        return rv;
    }

    /*
     * Start to build the JSON response
     */
    rv = acvp_setup_json_rsp_group(&ctx, &reg_arry_val, &r_vs_val, &r_vs, alg_str, &r_garr);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to setup json response");
        return rv;
    }

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        /*
         * Create a new group in the response with the tgid
         * and an array of tests
         */
        r_gval = json_value_init_object();
        r_gobj = json_value_get_object(r_gval);
        tgId = json_object_get_number(groupobj, "tgId");
        if (!tgId) {
            ACVP_LOG_ERR("Missing tgid from server JSON groub obj");
            return ACVP_MALFORMED_JSON;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        hash_alg_str = json_object_get_string(groupobj, "hashAlg");
        if (!hash_alg_str) {
            ACVP_LOG_ERR("Failed to include hashAlg");
            return ACVP_MISSING_ARG;
        }

        /*
         * Determine the hash algorithm.
         */
        if (strncmp(hash_alg_str, ACVP_STR_SHA_1, strlen(ACVP_STR_SHA_1)) == 0) {
            hash_alg = ACVP_SHA1;
        } else if (strncmp(hash_alg_str, ACVP_STR_SHA2_224, strlen(ACVP_STR_SHA2_224)) == 0) {
            hash_alg = ACVP_SHA224;
        } else if (strncmp(hash_alg_str, ACVP_STR_SHA2_256, strlen(ACVP_STR_SHA2_256)) == 0) {
            hash_alg = ACVP_SHA256;
        } else if (strncmp(hash_alg_str, ACVP_STR_SHA2_384, strlen(ACVP_STR_SHA2_384)) == 0) {
            hash_alg = ACVP_SHA384;
        } else if (strncmp(hash_alg_str, ACVP_STR_SHA2_512, strlen(ACVP_STR_SHA2_512)) == 0) {
            hash_alg = ACVP_SHA512;
        } else {
            ACVP_LOG_ERR("ACVP server requesting invalid hashAlg");
            return ACVP_INVALID_ARG;
        }

        auth_method_str = json_object_get_string(groupobj, "authenticationMethod");
        if (!auth_method_str) {
            ACVP_LOG_ERR("Failed to include authenticationMethod");
            return ACVP_MISSING_ARG;
        }

        /*
         * Determine the authentication method.
         */
        if (strncmp(auth_method_str, ACVP_AUTH_METHOD_DSA_STR,
                    strlen(ACVP_AUTH_METHOD_DSA_STR)) == 0) {
            auth_method = ACVP_KDF135_IKEV1_AMETH_DSA;
        } else if (strncmp(auth_method_str, ACVP_AUTH_METHOD_PSK_STR,
                           strlen(ACVP_AUTH_METHOD_PSK_STR)) == 0) {
            auth_method = ACVP_KDF135_IKEV1_AMETH_PSK;
        } else if (strncmp(auth_method_str, ACVP_AUTH_METHOD_PKE_STR,
                           strlen(ACVP_AUTH_METHOD_PKE_STR)) == 0) {
            auth_method = ACVP_KDF135_IKEV1_AMETH_PKE;
        } else {
            ACVP_LOG_ERR("ACVP server requesting invalid authenticationMethod");
            return ACVP_INVALID_ARG;
        }

        init_nonce_len = json_object_get_number(groupobj, "nInitLength");
        if (!(init_nonce_len >= ACVP_KDF135_IKEV1_INIT_NONCE_BIT_MIN &&
              init_nonce_len <= ACVP_KDF135_IKEV1_INIT_NONCE_BIT_MAX)) {
            ACVP_LOG_ERR("nInitLength incorrect, %d", init_nonce_len);
            return ACVP_INVALID_ARG;
        }

        resp_nonce_len = json_object_get_number(groupobj, "nRespLength");
        if (!(resp_nonce_len >= ACVP_KDF135_IKEV1_RESP_NONCE_BIT_MIN &&
              resp_nonce_len <= ACVP_KDF135_IKEV1_RESP_NONCE_BIT_MAX)) {
            ACVP_LOG_ERR("nRespLength incorrect, %d", resp_nonce_len);
            return ACVP_INVALID_ARG;
        }

        dh_secret_len = json_object_get_number(groupobj, "dhLength");
        if (!(dh_secret_len >= ACVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MIN &&
              dh_secret_len <= ACVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MAX)) {
            ACVP_LOG_ERR("dhLength incorrect, %d", dh_secret_len);
            return ACVP_INVALID_ARG;
        }

        if (auth_method == ACVP_KDF135_IKEV1_AMETH_PSK) {
            /* Only for PSK authentication method */
            psk_len = json_object_get_number(groupobj, "preSharedKeyLength");
            if (!(psk_len >= ACVP_KDF135_IKEV1_PSK_BIT_MIN &&
                  psk_len <= ACVP_KDF135_IKEV1_PSK_BIT_MAX)) {
                ACVP_LOG_ERR("preSharedKeyLength incorrect, %d", psk_len);
                return ACVP_INVALID_ARG;
            }
        }

        ACVP_LOG_INFO("\n    Test group: %d", i);
        ACVP_LOG_INFO("        hash alg: %s", hash_alg_str);
        ACVP_LOG_INFO("     auth method: %s", auth_method_str);
        ACVP_LOG_INFO("  init nonce len: %d", init_nonce_len);
        ACVP_LOG_INFO("  resp nonce len: %d", resp_nonce_len);
        ACVP_LOG_INFO("   dh secret len: %d", dh_secret_len);
        ACVP_LOG_INFO("         psk len: %d", psk_len);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new KDF IKEv1 test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");

            init_nonce = (char *)json_object_get_string(testobj, "nInit");
            if (!init_nonce) {
                ACVP_LOG_ERR("Failed to include nInit");
                return ACVP_MISSING_ARG;
            }
            if (strnlen((char *)init_nonce,
                        ACVP_KDF135_IKEV1_INIT_NONCE_STR_MAX + 1) != ((init_nonce_len + 7) / 8) * 2) {
                ACVP_LOG_ERR("nInit length(%d) incorrect, expected(%d)",
                             strnlen((char *)init_nonce,
                                     ACVP_KDF135_IKEV1_INIT_NONCE_STR_MAX + 1),
                             ((init_nonce_len + 7) / 8) * 2);
                return ACVP_INVALID_ARG;
            }

            resp_nonce = (char *)json_object_get_string(testobj, "nResp");
            if (!resp_nonce) {
                ACVP_LOG_ERR("Failed to include nResp");
                return ACVP_MISSING_ARG;
            }
            if (strnlen((char *)resp_nonce,
                        ACVP_KDF135_IKEV1_RESP_NONCE_STR_MAX + 1) != ((resp_nonce_len + 7) / 8) * 2) {
                ACVP_LOG_ERR("nResp length(%d) incorrect, expected(%d)",
                             strnlen((char *)resp_nonce,
                                     ACVP_KDF135_IKEV1_RESP_NONCE_STR_MAX + 1),
                             ((resp_nonce_len + 7) / 8) * 2);
                return ACVP_INVALID_ARG;
            }

            init_ckey = (char *)json_object_get_string(testobj, "ckyInit");
            if (!init_ckey) {
                ACVP_LOG_ERR("Failed to include ckyInit");
                return ACVP_MISSING_ARG;
            }
            if (strnlen((char *)init_ckey, ACVP_KDF135_IKEV1_COOKIE_STR_MAX + 1)
                > ACVP_KDF135_IKEV1_COOKIE_STR_MAX) {
                ACVP_LOG_ERR("ckyInit too long, max allowed=(%d)",
                             ACVP_KDF135_IKEV1_COOKIE_STR_MAX);
                return ACVP_INVALID_ARG;
            }

            resp_ckey = (char *)json_object_get_string(testobj, "ckyResp");
            if (!resp_ckey) {
                ACVP_LOG_ERR("Failed to include ckyResp");
                return ACVP_MISSING_ARG;
            }
            if (strnlen((char *)resp_ckey, ACVP_KDF135_IKEV1_COOKIE_STR_MAX + 1)
                > ACVP_KDF135_IKEV1_COOKIE_STR_MAX) {
                ACVP_LOG_ERR("ckyResp too long, max allowed=(%d)",
                             ACVP_KDF135_IKEV1_COOKIE_STR_MAX);
                return ACVP_INVALID_ARG;
            }

            gxy = (char *)json_object_get_string(testobj, "gxy");
            if (!gxy) {
                ACVP_LOG_ERR("Failed to include gxy");
                return ACVP_MISSING_ARG;
            }
            if (strnlen((char *)gxy, ACVP_KDF135_IKEV1_DH_SHARED_SECRET_STR_MAX + 1)
                > ACVP_KDF135_IKEV1_DH_SHARED_SECRET_STR_MAX) {
                ACVP_LOG_ERR("gxy too long, max allowed=(%d)",
                             ACVP_KDF135_IKEV1_DH_SHARED_SECRET_STR_MAX);
                return ACVP_INVALID_ARG;
            }


            if (auth_method == ACVP_KDF135_IKEV1_AMETH_PSK) {
                /* Only for PSK authentication method */
                psk = (char *)json_object_get_string(testobj, "preSharedKey");
                if (!psk) {
                    ACVP_LOG_ERR("Failed to include preSharedKey");
                    return ACVP_MISSING_ARG;
                }
                if (strnlen((char *)psk, ACVP_KDF135_IKEV1_PSK_STR_MAX + 1)
                    > ACVP_KDF135_IKEV1_PSK_STR_MAX) {
                    ACVP_LOG_ERR("preSharedKey too long, max allowed=(%d)",
                                 ACVP_KDF135_IKEV1_PSK_STR_MAX);
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

            /*
             * Setup the test case data that will be passed down to
             * the crypto module2
             */
            rv = acvp_kdf135_ikev1_init_tc(ctx, &stc, tc_id, hash_alg, auth_method,
                                           init_nonce_len, resp_nonce_len,
                                           dh_secret_len, psk_len,
                                           init_nonce, resp_nonce,
                                           init_ckey, resp_ckey,
                                           gxy, psk);
            if (rv != ACVP_SUCCESS) {
                acvp_kdf135_ikev1_release_tc(&stc);
                return rv;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("crypto module failed the KDF IKEv1 operation");
                acvp_kdf135_ikev1_release_tc(&stc);
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kdf135_ikev1_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in hash module");
                acvp_kdf135_ikev1_release_tc(&stc);
                return rv;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_kdf135_ikev1_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
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
