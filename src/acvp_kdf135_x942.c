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
 * need to be JSON formatted to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_kdf135_x942_output_tc(ACVP_CTX *ctx, ACVP_KDF135_X942_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv;
    char *tmp = NULL;

    if (stc->dkm_len == stc->key_len) {
        tmp = calloc(ACVP_KDF135_X942_STR_MAX + 1, sizeof(char));
        if (!tmp) {
            ACVP_LOG_ERR("Error allocating memory in X942 KDF TC output");
            return ACVP_MALLOC_FAIL;
        }
        rv = acvp_bin_to_hexstr(stc->dkm, stc->dkm_len, tmp, ACVP_KDF135_X942_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (dkm)");
            goto err;
        }
        json_object_set_string(tc_rsp, "derivedKey", (const char *)tmp);
    } else {
        ACVP_LOG_ERR("Error outputting test case for X942 KDF. Dkm_len MUST equal key_len.");
        rv = ACVP_TC_INVALID_DATA;
        goto err;
    }
    rv = ACVP_SUCCESS;
err:
    if (tmp) free(tmp);
    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf135_x942_release_tc(ACVP_KDF135_X942_TC *stc) {
    if (stc->oid) free(stc->oid);
    if (stc->zz) free(stc->zz);
    if (stc->party_u_info) free(stc->party_u_info);
    if (stc->party_v_info) free(stc->party_v_info);
    if (stc->supp_pub_info) free(stc->supp_pub_info);
    if (stc->supp_priv_info) free(stc->supp_priv_info);
    if (stc->dkm) free(stc->dkm);
    memzero_s(stc, sizeof(ACVP_KDF135_X942_TC));
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kdf135_x942_init_tc(ACVP_CTX *ctx,
                                            ACVP_KDF135_X942_TC *stc,
                                            int tc_id,
                                            ACVP_HASH_ALG hash_alg,
                                            ACVP_KDF_X942_TYPE type,
                                            const char *oid,
                                            const char *zz,
                                            int key_len,
                                            const char *party_u_info,
                                            const char *party_v_info,
                                            const char *supp_pub_info,
                                            const char *supp_priv_info) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_KDF135_X942_TC));

    stc->tc_id = tc_id;
    stc->hash_alg = hash_alg;
    stc->key_len = key_len / 8;
    stc->type = type;

    stc->dkm = calloc(ACVP_KDF135_X942_BYTE_MAX, sizeof(unsigned char));
    if (!stc->dkm) { return ACVP_MALLOC_FAIL; }

    stc->oid = calloc(ACVP_KDF135_X942_BYTE_MAX, sizeof(unsigned char));
    if (!stc->oid) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(oid, stc->oid, ACVP_KDF135_X942_BYTE_MAX, &stc->oid_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (oid)");
        return rv;
    }

    stc->zz = calloc(ACVP_KDF135_X942_BYTE_MAX, sizeof(unsigned char));
    if (!stc->zz) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(zz, stc->zz, ACVP_KDF135_X942_BYTE_MAX, &stc->zz_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (zz)");
        return rv;
    }

    stc->party_u_info = calloc(ACVP_KDF135_X942_BYTE_MAX, sizeof(unsigned char));
    if (!stc->party_u_info) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(party_u_info, stc->party_u_info, ACVP_KDF135_X942_BYTE_MAX, &stc->party_u_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (party_u_info)");
        return rv;
    }

    stc->party_v_info = calloc(ACVP_KDF135_X942_BYTE_MAX, sizeof(unsigned char));
    if (!stc->party_v_info) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(party_v_info, stc->party_v_info, ACVP_KDF135_X942_BYTE_MAX, &stc->party_v_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (party_v_info)");
        return rv;
    }

    stc->supp_pub_info = calloc(ACVP_KDF135_X942_BYTE_MAX, sizeof(unsigned char));
    if (!stc->supp_pub_info) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(supp_pub_info, stc->supp_pub_info, ACVP_KDF135_X942_BYTE_MAX, &stc->supp_pub_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (sup_pub_info)");
        return rv;
    }

    stc->supp_priv_info = calloc(ACVP_KDF135_X942_BYTE_MAX, sizeof(unsigned char));
    if (!stc->supp_priv_info) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(supp_priv_info, stc->supp_priv_info, ACVP_KDF135_X942_BYTE_MAX, &stc->supp_priv_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (supp_priv_info)");
        return rv;
    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_kdf135_x942_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *groups;
    JSON_Array *tests;

    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;

    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL, *r_garr = NULL;  // Response testarray, grouparray
    JSON_Value *r_tval = NULL, *r_gval = NULL;  // Response testval, groupval
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; // Response testobj, groupobj

    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_X942_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    int tc_id = 0, i = 0, g_cnt = 0, j = 0, t_cnt = 0, diff = 0, len = 0, key_len = 0;
    const char *alg_str = NULL, *mode_str = NULL, *kdf_type_str = NULL, *oid = NULL, *party_u = NULL,
               *party_v = NULL, *supp_pub = NULL, *supp_priv = NULL, *zz = NULL;
    ACVP_CIPHER alg_id;
    ACVP_KDF_X942_TYPE kdf_type;
    char *json_result;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    if (!obj) {
        ACVP_LOG_ERR("No obj for handler operation");
        return ACVP_MALFORMED_JSON;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("Server JSON missing 'algorithm'");
        return ACVP_MISSING_ARG;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("Server JSON missing 'mode'");
        return ACVP_MISSING_ARG;
    }

    alg_id = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != ACVP_KDF135_X942) {
        ACVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return ACVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_x942 = &stc;
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
        ACVP_LOG_ERR("Failed to create JSON response struct.");
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
    json_object_set_string(r_vs, "mode", "ansix9.42");

    rv = acvp_tc_json_get_array(ctx, alg_id, obj, "testGroups", &groups);
    if (rv != ACVP_SUCCESS) {
        goto err;
    }

    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        ACVP_HASH_ALG hash_alg = 0;
        const char *hash_alg_str = NULL;

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

        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "kdfType", &kdf_type_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        strncmp_s(kdf_type_str, 13, "DER", 3, &diff);
        if (!diff) {
            kdf_type = ACVP_KDF_X942_KDF_TYPE_DER;
       } else {
            strncmp_s(kdf_type_str, 13, "concatenation", 13, &diff);
            if (!diff) {
                kdf_type = ACVP_KDF_X942_KDF_TYPE_CONCAT;
            } else {
                ACVP_LOG_ERR("Server JSON invalid 'kdfType'");
                rv = ACVP_INVALID_ARG;
                goto err;
            }
       }

        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "hashAlg", &hash_alg_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        hash_alg = acvp_lookup_hash_alg(hash_alg_str);
        if (!hash_alg) {
            ACVP_LOG_ERR("Server JSON invalid 'hashAlg'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "oid", &oid);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        ACVP_LOG_VERBOSE("\n    Test group: %d", i);
        ACVP_LOG_VERBOSE("         kdfType: %s", kdf_type_str);
        ACVP_LOG_VERBOSE("         hashAlg: %s", hash_alg_str);
        ACVP_LOG_VERBOSE("             OID: %s", oid);

        rv = acvp_tc_json_get_array(ctx, alg_id, groupobj, "tests", &tests);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        t_cnt = json_array_get_count(tests);
        if (!t_cnt) {
            ACVP_LOG_ERR("Failed to include tests in array.");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_VERBOSE("Found new KDF135 X942 test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "tcId", (int *)&tc_id);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "zz", &zz);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            len = strnlen_s(zz, ACVP_KDF135_X942_STR_MAX + 1);
            if (len > ACVP_KDF135_X942_STR_MAX) {
                ACVP_LOG_ERR("Server JSON invalid 'zz' (max = %d, given = %d)", ACVP_KDF135_X942_STR_MAX, len);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "keyLen", &key_len);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }
            if (key_len < 1 || key_len > ACVP_KDF135_X942_BIT_MAX) {
                ACVP_LOG_ERR("Server JSON invalid 'keyLen' (given: %d)", key_len);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "partyUInfo", &party_u);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            len = strnlen_s(party_u, ACVP_KDF135_X942_STR_MAX + 1);
            if (len > ACVP_KDF135_X942_STR_MAX) {
                ACVP_LOG_ERR("Server JSON invalid 'partyUInfo' (max = %d, given = %d)", ACVP_KDF135_X942_STR_MAX, len);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "partyVInfo", &party_v);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            len = strnlen_s(party_v, ACVP_KDF135_X942_STR_MAX + 1);
            if (len > ACVP_KDF135_X942_STR_MAX) {
                ACVP_LOG_ERR("Server JSON invalid 'partyVInfo' (max = %d, given = %d)", ACVP_KDF135_X942_STR_MAX, len);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "suppPubInfo", &supp_pub);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            len = strnlen_s(supp_pub, ACVP_KDF135_X942_STR_MAX + 1);
            if (len > ACVP_KDF135_X942_STR_MAX) {
                ACVP_LOG_ERR("Server JSON invalid 'suppPubInfo' (max = %d, given = %d)", ACVP_KDF135_X942_STR_MAX, len);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "suppPrivInfo", &supp_priv);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            len = strnlen_s(supp_priv, ACVP_KDF135_X942_STR_MAX + 1);
            if (len > ACVP_KDF135_X942_STR_MAX) {
                ACVP_LOG_ERR("Server JSON invalid 'suppPrivInfo' (max = %d, given = %d)", ACVP_KDF135_X942_STR_MAX, len);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("               zz: %s", zz);
            ACVP_LOG_VERBOSE("           keyLen: %d", key_len);
            ACVP_LOG_VERBOSE("       partyUInfo: %s", party_u);
            ACVP_LOG_VERBOSE("       partyVInfo: %s", party_v);
            ACVP_LOG_VERBOSE("      suppPubInfo: %s", supp_pub);
            ACVP_LOG_VERBOSE("     suppPrivInfo: %s", supp_priv);

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
            rv = acvp_kdf135_x942_init_tc(ctx, &stc, tc_id, hash_alg,
                                          kdf_type, oid, zz, key_len,
                                          party_u, party_v, supp_pub, supp_priv);
            if (rv != ACVP_SUCCESS) {
                acvp_kdf135_x942_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            // Process the current test vector...
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("Crypto module failed the KDF X942 operation");
                acvp_kdf135_x942_release_tc(&stc);
                rv = ACVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kdf135_x942_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure recording test response");
                acvp_kdf135_x942_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_kdf135_x942_release_tc(&stc);

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
