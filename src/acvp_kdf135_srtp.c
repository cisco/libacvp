/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
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

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_kdf135_srtp_output_tc(ACVP_CTX *ctx, ACVP_KDF135_SRTP_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_KDF135_SRTP_OUTPUT_MAX + 1, sizeof(char));
    if (!tmp) { return ACVP_MALLOC_FAIL; }

    rv = acvp_bin_to_hexstr(stc->srtp_ke, stc->aes_keylen / 8, tmp, ACVP_KDF135_SRTP_OUTPUT_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (srtp_ke)");
        goto err;
    }
    json_object_set_string(tc_rsp, "srtpKe", (const char *)tmp);
    memzero_s(tmp, ACVP_KDF135_SRTP_OUTPUT_MAX);

    rv = acvp_bin_to_hexstr(stc->srtp_ka, 160 / 8, tmp, ACVP_KDF135_SRTP_OUTPUT_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (srtp_ka)");
        goto err;
    }
    json_object_set_string(tc_rsp, "srtpKa", (const char *)tmp);
    memzero_s(tmp, ACVP_KDF135_SRTP_OUTPUT_MAX);

    rv = acvp_bin_to_hexstr(stc->srtp_ks, 112 / 8, tmp, ACVP_KDF135_SRTP_OUTPUT_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (srtp_ks)");
        goto err;
    }
    json_object_set_string(tc_rsp, "srtpKs", (const char *)tmp);
    memzero_s(tmp, ACVP_KDF135_SRTP_OUTPUT_MAX);

    rv = acvp_bin_to_hexstr(stc->srtcp_ke, stc->aes_keylen / 8, tmp, ACVP_KDF135_SRTP_OUTPUT_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (srtcp_ke)");
        goto err;
    }
    json_object_set_string(tc_rsp, "srtcpKe", (const char *)tmp);
    memzero_s(tmp, ACVP_KDF135_SRTP_OUTPUT_MAX);

    rv = acvp_bin_to_hexstr(stc->srtcp_ka, 160 / 8, tmp, ACVP_KDF135_SRTP_OUTPUT_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (srtcp_ka)");
        goto err;
    }
    json_object_set_string(tc_rsp, "srtcpKa", (const char *)tmp);
    memzero_s(tmp, ACVP_KDF135_SRTP_OUTPUT_MAX);

    rv = acvp_bin_to_hexstr(stc->srtcp_ks, 112 / 8, tmp, ACVP_KDF135_SRTP_OUTPUT_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (srtcp_ks)");
        goto err;
    }
    json_object_set_string(tc_rsp, "srtcpKs", (const char *)tmp);
    memzero_s(tmp, ACVP_KDF135_SRTP_OUTPUT_MAX);

err:
    free(tmp);
    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf135_srtp_release_tc(ACVP_KDF135_SRTP_TC *stc) {
    if (stc->kdr) free(stc->kdr);
    if (stc->master_key) free(stc->master_key);
    if (stc->master_salt) free(stc->master_salt);
    if (stc->idx) free(stc->idx);
    if (stc->srtcp_idx) free(stc->srtcp_idx);
    if (stc->srtp_ke) free(stc->srtp_ke);
    if (stc->srtp_ka) free(stc->srtp_ka);
    if (stc->srtp_ks) free(stc->srtp_ks);
    if (stc->srtcp_ke) free(stc->srtcp_ke);
    if (stc->srtcp_ka) free(stc->srtcp_ka);
    if (stc->srtcp_ks) free(stc->srtcp_ks);
    memzero_s(stc, sizeof(ACVP_KDF135_SRTP_TC));
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kdf135_srtp_init_tc(ACVP_CTX *ctx,
                                            ACVP_KDF135_SRTP_TC *stc,
                                            unsigned int tc_id,
                                            int aes_keylen,
                                            const char *kdr,
                                            const char *master_key,
                                            const char *master_salt,
                                            const char *idx,
                                            const char *srtcp_idx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_KDF135_SRTP_TC));

    if (!kdr || !master_key || !master_salt || !idx || !srtcp_idx) {
        ACVP_LOG_ERR("Missing parameters - initalize KDF SRTP test case");
        return ACVP_INVALID_ARG;
    }

    stc->tc_id = tc_id;
    stc->aes_keylen = aes_keylen;

    stc->kdr = calloc(ACVP_KDF135_SRTP_KDR_STR_MAX, sizeof(char));
    if (!stc->kdr) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(kdr, stc->kdr, ACVP_KDF135_SRTP_KDR_STR_MAX, &(stc->kdr_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (kdr)");
        return rv;
    }

    stc->master_key = calloc(ACVP_KDF135_SRTP_MASTER_MAX, sizeof(char));
    if (!stc->master_key) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(master_key, (unsigned char *)stc->master_key,
                            ACVP_KDF135_SRTP_MASTER_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (master_key)");
        return rv;
    }

    stc->master_salt = calloc(ACVP_KDF135_SRTP_MASTER_MAX, sizeof(char));
    if (!stc->master_salt) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(master_salt, (unsigned char *)stc->master_salt,
                            ACVP_KDF135_SRTP_MASTER_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (master_salt)");
        return rv;
    }

    stc->idx = calloc(ACVP_KDF135_SRTP_INDEX_MAX, sizeof(char));
    if (!stc->idx) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(idx, (unsigned char *)stc->idx, ACVP_KDF135_SRTP_INDEX_MAX,
                            NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (idx)");
        return rv;
    }

    stc->srtcp_idx = calloc(ACVP_KDF135_SRTP_INDEX_MAX, sizeof(char));
    if (!stc->srtcp_idx) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(srtcp_idx, (unsigned char *)stc->srtcp_idx,
                            ACVP_KDF135_SRTP_INDEX_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (srtcp_idx)");
        return rv;
    }

    stc->srtp_ka = calloc(ACVP_KDF135_SRTP_OUTPUT_MAX, sizeof(char));
    if (!stc->srtp_ka) { return ACVP_MALLOC_FAIL; }
    stc->srtp_ke = calloc(ACVP_KDF135_SRTP_OUTPUT_MAX, sizeof(char));
    if (!stc->srtp_ke) { return ACVP_MALLOC_FAIL; }
    stc->srtp_ks = calloc(ACVP_KDF135_SRTP_OUTPUT_MAX, sizeof(char));
    if (!stc->srtp_ks) { return ACVP_MALLOC_FAIL; }
    stc->srtcp_ka = calloc(ACVP_KDF135_SRTP_OUTPUT_MAX, sizeof(char));
    if (!stc->srtcp_ka) { return ACVP_MALLOC_FAIL; }
    stc->srtcp_ke = calloc(ACVP_KDF135_SRTP_OUTPUT_MAX, sizeof(char));
    if (!stc->srtcp_ke) { return ACVP_MALLOC_FAIL; }
    stc->srtcp_ks = calloc(ACVP_KDF135_SRTP_OUTPUT_MAX, sizeof(char));
    if (!stc->srtcp_ks) { return ACVP_MALLOC_FAIL; }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_kdf135_srtp_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_KDF135_SRTP_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    const char *mode_str = NULL;
    ACVP_CIPHER alg_id;
    char *json_result;

    int aes_key_length;
    const char *kdr = NULL, *master_key = NULL, *master_salt = NULL, *idx = NULL, *srtcp_idx = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON.");
        return ACVP_MALFORMED_JSON;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("unable to parse 'mode' from JSON.");
        return ACVP_MALFORMED_JSON;
    }

    alg_id = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != ACVP_KDF135_SRTP) {
        ACVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return ACVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_srtp = &stc;
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
        goto err;
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
            rv = ACVP_MALFORMED_JSON;
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        aes_key_length = json_object_get_number(groupobj, "aesKeyLength");
        if (!aes_key_length) {
            ACVP_LOG_ERR("aesKeyLength incorrect, %d", aes_key_length);
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        kdr = json_object_get_string(groupobj, "kdr");
        if (!kdr) {
            ACVP_LOG_ERR("Failed to include kdr");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        ACVP_LOG_VERBOSE("\n    Test group: %d", i);
        ACVP_LOG_VERBOSE("           kdr: %s", kdr);
        ACVP_LOG_VERBOSE("    key length: %d", aes_key_length);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_VERBOSE("Found new KDF SRTP test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");

            master_key = json_object_get_string(testobj, "masterKey");
            if (!master_key) {
                ACVP_LOG_ERR("Failed to include JSON key:\"masterKey\"");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            master_salt = json_object_get_string(testobj, "masterSalt");
            if (!master_salt) {
                ACVP_LOG_ERR("Failed to include JSON key:\"masterSalt\"");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            idx = json_object_get_string(testobj, "index");
            if (!idx) {
                ACVP_LOG_ERR("Failed to include JSON key:\"idx\"");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            srtcp_idx = json_object_get_string(testobj, "srtcpIndex");
            if (!srtcp_idx) {
                ACVP_LOG_ERR("Failed to include JSON key:\"srtcpIndex\"");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("        masterKey: %s", master_key);
            ACVP_LOG_VERBOSE("       masterSalt: %s", master_salt);
            ACVP_LOG_VERBOSE("            idx: %s", idx);
            ACVP_LOG_VERBOSE("       srtcpIndex: %s", srtcp_idx);

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
            rv = acvp_kdf135_srtp_init_tc(ctx, &stc, tc_id, aes_key_length, kdr, master_key, master_salt, idx, srtcp_idx);
            if (rv != ACVP_SUCCESS) {
                acvp_kdf135_srtp_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("crypto module failed");
                acvp_kdf135_srtp_release_tc(&stc);
                rv = ACVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kdf135_srtp_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure");
                acvp_kdf135_srtp_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_kdf135_srtp_release_tc(&stc);

            /* Append the test response value to array */
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
