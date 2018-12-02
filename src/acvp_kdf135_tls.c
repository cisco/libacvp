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
static ACVP_RESULT acvp_kdf135_tls_output_tc(ACVP_CTX *ctx, ACVP_KDF135_TLS_TC *stc, JSON_Object *tc_rsp);

static ACVP_RESULT acvp_kdf135_tls_init_tc(ACVP_CTX *ctx,
                                           ACVP_KDF135_TLS_TC *stc,
                                           unsigned int tc_id,
                                           ACVP_CIPHER alg_id,
                                           ACVP_KDF135_TLS_METHOD method,
                                           ACVP_HASH_ALG md,
                                           unsigned int pm_len,
                                           unsigned int kb_len,
                                           const char *pm_secret,
                                           const char *sh_rnd,
                                           const char *ch_rnd,
                                           const char *s_rnd,
                                           const char *c_rnd);

static ACVP_RESULT acvp_kdf135_tls_release_tc(ACVP_KDF135_TLS_TC *stc);


ACVP_RESULT acvp_kdf135_tls_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_KDF135_TLS_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER alg_id;
    ACVP_HASH_ALG md = 0;
    ACVP_KDF135_TLS_METHOD meth = 0;
    const char *pm_secret = NULL;
    const char *sh_rnd = NULL;
    const char *ch_rnd = NULL;
    const char *s_rnd = NULL;
    const char *c_rnd = NULL;
    const char *method = NULL;
    const char *sha = NULL;
    unsigned int kb_len, pm_len;
    char *json_result;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    if (strncmp(alg_str, "kdf-components", strlen("kdf-components"))) {
        ACVP_LOG_ERR("Invalid algorithm for this function %s", alg_str);
        return ACVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_tls = &stc;

    /*
     * Get the crypto module handler for this hash algorithm
     */
    alg_id = acvp_lookup_cipher_index(alg_str);
    if (alg_id < ACVP_CIPHER_START) {
        ACVP_LOG_ERR("unsupported algorithm (%s)", alg_str);
        return ACVP_UNSUPPORTED_OP;
    }
    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
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

        pm_len = (unsigned int)json_object_get_number(groupobj, "preMasterSecretLength");
        if (!pm_len) {
            ACVP_LOG_ERR("preMasterSecretLength incorrect, %d", pm_len);
            return ACVP_INVALID_ARG;
        }

        kb_len = (unsigned int)json_object_get_number(groupobj, "keyBlockLength");
        if (!kb_len) {
            ACVP_LOG_ERR("keyBlockLength incorrect, %d", kb_len);
            return ACVP_INVALID_ARG;
        }

        method = json_object_get_string(groupobj, "tlsVersion");
        if (!method) {
            ACVP_LOG_ERR("Failed to include tlsVersion");
            return ACVP_MISSING_ARG;
        }

        sha = json_object_get_string(groupobj, "hashAlg");
        if (!sha) {
            ACVP_LOG_ERR("Failed to include hashAlg");
            return ACVP_MISSING_ARG;
        }

        if (!strncmp(method, "v1.2", 4)) {
            meth = ACVP_KDF135_TLS12;
        } else if (!strncmp(method, "v1.0/1.1", 8)) {
            meth = ACVP_KDF135_TLS10_TLS11;
        } else {
            ACVP_LOG_ERR("Not TLS method");
            return ACVP_NO_CAP;
        }

        if (!strncmp(sha, "SHA2-256", 8)) {
            md = ACVP_SHA256;
        } else if (!strncmp(sha, "SHA2-384", 8)) {
            md = ACVP_SHA384;
        } else if (!strncmp(sha, "SHA2-512", 8)) {
            md = ACVP_SHA512;
        } else {
            ACVP_LOG_ERR("Not TLS SHA");
            return ACVP_NO_CAP;
        }

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("            pmLen: %d", pm_len);
        ACVP_LOG_INFO("            kbLen: %d", kb_len);
        ACVP_LOG_INFO("           method: %d", method);
        ACVP_LOG_INFO("              sha: %d", sha);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new hash test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");

            pm_secret = json_object_get_string(testobj, "preMasterSecret");
            if (!pm_secret) {
                ACVP_LOG_ERR("Failed to include preMasterSecret");
                return ACVP_MISSING_ARG;
            }
            if (strnlen(pm_secret, pm_len) != pm_len / 4) {
                ACVP_LOG_ERR("pmLen(%d) or pmSecret length(%d) incorrect",
                             pm_len / 4, strnlen(pm_secret, ACVP_KDF135_TLS_PMSECRET_STR_MAX));
                return ACVP_INVALID_ARG;
            }

            sh_rnd = json_object_get_string(testobj, "serverHelloRandom");
            if (!sh_rnd) {
                ACVP_LOG_ERR("Failed to include serverHelloRandom");
                return ACVP_MISSING_ARG;
            }

            ch_rnd = json_object_get_string(testobj, "clientHelloRandom");
            if (!ch_rnd) {
                ACVP_LOG_ERR("Failed to include clientHelloRandom");
                return ACVP_MISSING_ARG;
            }

            s_rnd = json_object_get_string(testobj, "serverRandom");
            if (!s_rnd) {
                ACVP_LOG_ERR("Failed to include serverRandom");
                return ACVP_MISSING_ARG;
            }

            c_rnd = json_object_get_string(testobj, "clientRandom");
            if (!c_rnd) {
                ACVP_LOG_ERR("Failed to include clientRandom");
                return ACVP_MISSING_ARG;
            }

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            ACVP_LOG_INFO("         pmSecret: %s", pm_secret);
            ACVP_LOG_INFO("            shRND: %s", sh_rnd);
            ACVP_LOG_INFO("            chRND: %s", ch_rnd);
            ACVP_LOG_INFO("             sRND: %s", s_rnd);
            ACVP_LOG_INFO("             cRND: %s", c_rnd);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             */
            rv = acvp_kdf135_tls_init_tc(ctx, &stc, tc_id, alg_id, meth, md, pm_len,
                                         kb_len, pm_secret, sh_rnd, ch_rnd, s_rnd, c_rnd);
            if (rv != ACVP_SUCCESS) {
                acvp_kdf135_tls_release_tc(&stc);
                return rv;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("crypto module failed the operation");
                acvp_kdf135_tls_release_tc(&stc);
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kdf135_tls_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in hash module");
                acvp_kdf135_tls_release_tc(&stc);
                return rv;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_kdf135_tls_release_tc(&stc);

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

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_kdf135_tls_output_tc(ACVP_CTX *ctx, ACVP_KDF135_TLS_TC *stc, JSON_Object *tc_rsp) {
    char *tmp = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;

    tmp = calloc(1, ACVP_KDF135_TLS_MSG_MAX + 1);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_kdf135_tls_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(stc->msecret1, stc->pm_len, tmp, ACVP_KDF135_TLS_MSG_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (mac)");
        goto err;
    }
    json_object_set_string(tc_rsp, "masterSecret", tmp);
    memset(tmp, 0x0, ACVP_KDF135_TLS_MSG_MAX);

    rv = acvp_bin_to_hexstr(stc->kblock1, stc->kb_len, tmp, ACVP_KDF135_TLS_MSG_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (mac)");
        goto err;
    }
    json_object_set_string(tc_rsp, "keyBlock", tmp);

err:
    free(tmp);

    return rv;
}

static ACVP_RESULT acvp_kdf135_tls_init_tc(ACVP_CTX *ctx,
                                           ACVP_KDF135_TLS_TC *stc,
                                           unsigned int tc_id,
                                           ACVP_CIPHER alg_id,
                                           ACVP_KDF135_TLS_METHOD method,
                                           ACVP_HASH_ALG md,
                                           unsigned int pm_len,
                                           unsigned int kb_len,
                                           const char *pm_secret,
                                           const char *sh_rnd,
                                           const char *ch_rnd,
                                           const char *s_rnd,
                                           const char *c_rnd) {
    ACVP_RESULT rv;

    memset(stc, 0x0, sizeof(ACVP_KDF135_TLS_TC));

    stc->pm_secret = calloc(1, ACVP_KDF135_TLS_MSG_MAX);
    if (!stc->pm_secret) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(pm_secret, stc->pm_secret, ACVP_KDF135_TLS_MSG_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (pm_secret)");
        return rv;
    }

    stc->sh_rnd = calloc(1, ACVP_KDF135_TLS_MSG_MAX);
    if (!stc->sh_rnd) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(sh_rnd, stc->sh_rnd, ACVP_KDF135_TLS_MSG_MAX, &(stc->sh_rnd_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (sh_rnd)");
        return rv;
    }

    stc->ch_rnd = calloc(1, ACVP_KDF135_TLS_MSG_MAX);
    if (!stc->ch_rnd) { return ACVP_MALLOC_FAIL; }

    rv = acvp_hexstr_to_bin(ch_rnd, stc->ch_rnd, ACVP_KDF135_TLS_MSG_MAX, &(stc->ch_rnd_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (ch_rnd)");
        return rv;
    }

    stc->c_rnd = calloc(1, ACVP_KDF135_TLS_MSG_MAX);
    if (!stc->c_rnd) { return ACVP_MALLOC_FAIL; }

    rv = acvp_hexstr_to_bin(c_rnd, stc->c_rnd, ACVP_KDF135_TLS_MSG_MAX, &(stc->c_rnd_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (c_rnd)");
        return rv;
    }

    stc->s_rnd = calloc(1, ACVP_KDF135_TLS_MSG_MAX);
    if (!stc->s_rnd) { return ACVP_MALLOC_FAIL; }

    rv = acvp_hexstr_to_bin(s_rnd, stc->s_rnd, ACVP_KDF135_TLS_MSG_MAX, &(stc->s_rnd_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (s_rnd)");
        return rv;
    }

    stc->msecret1 = calloc(1, ACVP_KDF135_TLS_MSG_MAX);
    if (!stc->msecret1) { return ACVP_MALLOC_FAIL; }
    stc->msecret2 = calloc(1, ACVP_KDF135_TLS_MSG_MAX);
    if (!stc->msecret2) { return ACVP_MALLOC_FAIL; }
    stc->kblock1 = calloc(1, ACVP_KDF135_TLS_MSG_MAX);
    if (!stc->kblock1) { return ACVP_MALLOC_FAIL; }
    stc->kblock2 = calloc(1, ACVP_KDF135_TLS_MSG_MAX);
    if (!stc->kblock2) { return ACVP_MALLOC_FAIL; }

    memset(stc->msecret1, 0, ACVP_KDF135_TLS_MSG_MAX);
    memset(stc->msecret2, 0, ACVP_KDF135_TLS_MSG_MAX);
    memset(stc->kblock1, 0, ACVP_KDF135_TLS_MSG_MAX);
    memset(stc->kblock2, 0, ACVP_KDF135_TLS_MSG_MAX);

    stc->tc_id = tc_id;
    stc->cipher = alg_id;
    stc->pm_len = pm_len / 8;
    stc->kb_len = kb_len / 8;
    stc->method = method;
    stc->md = md;

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf135_tls_release_tc(ACVP_KDF135_TLS_TC *stc) {
    free(stc->pm_secret);
    free(stc->sh_rnd);
    free(stc->ch_rnd);
    free(stc->c_rnd);
    free(stc->s_rnd);
    free(stc->msecret1);
    free(stc->msecret2);
    free(stc->kblock1);
    free(stc->kblock2);

    memset(stc, 0x0, sizeof(ACVP_KDF135_TLS_TC));
    return ACVP_SUCCESS;
}
