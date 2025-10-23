/** @file */
/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"
#include "safe_lib.h"

// Forward prototypes for local functions
static ACVP_RESULT acvp_kdf_tls12_output_tc(ACVP_CTX *ctx, ACVP_KDF_TLS12_TC *stc, JSON_Object *tc_rsp);

static ACVP_RESULT acvp_kdf_tls12_init_tc(ACVP_CTX *ctx,
                                           ACVP_KDF_TLS12_TC *stc,
                                           unsigned int tc_id,
                                           ACVP_CIPHER alg_id,
                                           ACVP_HASH_ALG md,
                                           unsigned int pm_len,
                                           unsigned int kb_len,
                                           const char *pm_secret,
                                           const char *session_hash,
                                           const char *s_rnd,
                                           const char *c_rnd);

static ACVP_RESULT acvp_kdf_tls12_release_tc(ACVP_KDF_TLS12_TC *stc);

ACVP_RESULT acvp_kdf_tls12_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
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
    JSON_Array *r_tarr = NULL, *r_garr = NULL;  // Response testarray, grouparray
    JSON_Value *r_tval = NULL, *r_gval = NULL;  // Response testval, groupval
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; // Response testobj, groupobj
    ACVP_CAPS_LIST *cap;
    ACVP_KDF_TLS12_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    const char *mode_str = NULL;
    ACVP_CIPHER alg_id;
    ACVP_HASH_ALG md = 0;
    const char *pm_secret = NULL;
    const char *session_hash = NULL;
    const char *s_rnd = NULL;
    const char *c_rnd = NULL;
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

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("unable to parse 'mode' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    alg_id = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != ACVP_KDF_TLS12) {
        ACVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return ACVP_INVALID_ARG;
    }

    // Get a reference to the abstracted test case
    tc.tc.kdf_tls12 = &stc;

    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        return ACVP_UNSUPPORTED_OP;
    }

    // Create ACVP array for response
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct.");
        return rv;
    }

    // Start to build the JSON response
    rv = acvp_setup_json_rsp_group(&ctx, &reg_arry_val, &r_vs_val, &r_vs, alg_str, &r_garr);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to setup json response");
        goto err;
    }

    rv = acvp_tc_json_get_array(ctx, alg_id, obj, "testGroups", &groups);
    if (rv != ACVP_SUCCESS) {
        goto err;
    }
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
        rv = acvp_tc_json_get_int(ctx, alg_id, groupobj, "tgId", &tgId);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        rv = acvp_tc_json_get_int(ctx, alg_id, groupobj, "preMasterSecretLength", &pm_len);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        rv = acvp_tc_json_get_int(ctx, alg_id, groupobj, "keyBlockLength", &kb_len);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "hashAlg", &sha);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        md = acvp_lookup_hash_alg(sha);
        if (md != ACVP_SHA256 && md != ACVP_SHA384 &&
            md != ACVP_SHA512) {
            ACVP_LOG_ERR("Not TLS SHA");
            rv = ACVP_NO_CAP;
            goto err;
        }

        ACVP_LOG_VERBOSE("    Test group: %d", i);
        ACVP_LOG_VERBOSE("            pmLen: %d", pm_len);
        ACVP_LOG_VERBOSE("            kbLen: %d", kb_len);
        ACVP_LOG_VERBOSE("              sha: %s", sha);

        rv = acvp_tc_json_get_array(ctx, alg_id, groupobj, "tests", &tests);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_VERBOSE("Found new hash test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "tcId", (int *)&tc_id);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "preMasterSecret", &pm_secret);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            if (strnlen_s(pm_secret, pm_len) != pm_len / 4) {
                ACVP_LOG_ERR("pmLen(%d) or pmSecret length(%d) incorrect",
                             pm_len / 4, (int)strnlen_s(pm_secret, ACVP_KDF_TLS12_PMSECRET_STR_MAX));
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "sessionHash", &session_hash);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "serverRandom", &s_rnd);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "clientRandom", &c_rnd);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("         pmSecret: %s", pm_secret);
            ACVP_LOG_VERBOSE("      sessionHash: %s", session_hash);
            ACVP_LOG_VERBOSE("             sRND: %s", s_rnd);
            ACVP_LOG_VERBOSE("             cRND: %s", c_rnd);

            // Create a new test case in the response
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             */
            rv = acvp_kdf_tls12_init_tc(ctx, &stc, tc_id, alg_id, md, pm_len,
                                         kb_len, pm_secret, session_hash, s_rnd, c_rnd);
            if (rv != ACVP_SUCCESS) {
                acvp_kdf_tls12_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            // Process the current test vector...
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("Crypto module failed the operation");
                acvp_kdf_tls12_release_tc(&stc);
                rv = ACVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            // Output the test case results using JSON
            rv = acvp_kdf_tls12_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure recording test response");
                acvp_kdf_tls12_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            // Release all the memory associated with the test case
            acvp_kdf_tls12_release_tc(&stc);

            // Append the test response value to array
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
    }

    json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    ACVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        acvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formatted to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_kdf_tls12_output_tc(ACVP_CTX *ctx, ACVP_KDF_TLS12_TC *stc, JSON_Object *tc_rsp) {
    char *tmp = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;

    tmp = calloc(1, ACVP_KDF_TLS12_MSG_MAX + 1);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_kdf_tls12_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(stc->msecret, stc->pm_len, tmp, ACVP_KDF_TLS12_MSG_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (mac)");
        goto err;
    }
    json_object_set_string(tc_rsp, "masterSecret", tmp);
    memzero_s(tmp, ACVP_KDF_TLS12_MSG_MAX);

    rv = acvp_bin_to_hexstr(stc->kblock, stc->kb_len, tmp, ACVP_KDF_TLS12_MSG_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (mac)");
        goto err;
    }
    json_object_set_string(tc_rsp, "keyBlock", tmp);

err:
    free(tmp);

    return rv;
}

static ACVP_RESULT acvp_kdf_tls12_init_tc(ACVP_CTX *ctx,
                                           ACVP_KDF_TLS12_TC *stc,
                                           unsigned int tc_id,
                                           ACVP_CIPHER alg_id,
                                           ACVP_HASH_ALG md,
                                           unsigned int pm_len,
                                           unsigned int kb_len,
                                           const char *pm_secret,
                                           const char *session_hash,
                                           const char *s_rnd,
                                           const char *c_rnd) {
    ACVP_RESULT rv;

    memzero_s(stc, sizeof(ACVP_KDF_TLS12_TC));

    stc->pm_secret = calloc(1, ACVP_KDF_TLS12_MSG_MAX);
    if (!stc->pm_secret) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(pm_secret, stc->pm_secret, ACVP_KDF_TLS12_MSG_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (pm_secret)");
        return rv;
    }

    stc->session_hash = calloc(1, ACVP_KDF_TLS12_MSG_MAX);
    if (!stc->session_hash) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(session_hash, stc->session_hash, ACVP_KDF_TLS12_MSG_MAX, &(stc->session_hash_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (session_hash)");
        return rv;
    }

    stc->c_rnd = calloc(1, ACVP_KDF_TLS12_MSG_MAX);
    if (!stc->c_rnd) { return ACVP_MALLOC_FAIL; }

    rv = acvp_hexstr_to_bin(c_rnd, stc->c_rnd, ACVP_KDF_TLS12_MSG_MAX, &(stc->c_rnd_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (c_rnd)");
        return rv;
    }

    stc->s_rnd = calloc(1, ACVP_KDF_TLS12_MSG_MAX);
    if (!stc->s_rnd) { return ACVP_MALLOC_FAIL; }

    rv = acvp_hexstr_to_bin(s_rnd, stc->s_rnd, ACVP_KDF_TLS12_MSG_MAX, &(stc->s_rnd_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (s_rnd)");
        return rv;
    }

    stc->msecret = calloc(1, ACVP_KDF_TLS12_MSG_MAX);
    if (!stc->msecret) { return ACVP_MALLOC_FAIL; }
    stc->kblock = calloc(1, ACVP_KDF_TLS12_MSG_MAX);
    if (!stc->kblock) { return ACVP_MALLOC_FAIL; }

    stc->tc_id = tc_id;
    stc->cipher = alg_id;
    stc->pm_len = pm_len / 8;
    stc->kb_len = kb_len / 8;
    stc->md = md;

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf_tls12_release_tc(ACVP_KDF_TLS12_TC *stc) {
    if (stc->pm_secret) free(stc->pm_secret);
    if (stc->session_hash) free(stc->session_hash);
    if (stc->c_rnd) free(stc->c_rnd);
    if (stc->s_rnd) free(stc->s_rnd);
    if (stc->msecret) free(stc->msecret);
    if (stc->kblock) free(stc->kblock);

    memzero_s(stc, sizeof(ACVP_KDF_TLS12_TC));
    return ACVP_SUCCESS;
}
