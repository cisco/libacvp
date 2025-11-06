/** @file */
/*
 * Copyright (c) 2024, Cisco Systems, Inc.
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
static ACVP_RESULT acvp_lms_output_tc(ACVP_CTX *ctx, ACVP_CIPHER cipher, ACVP_LMS_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv;
    ACVP_SUB_LMS mode;
    char *tmp = NULL;

    mode = acvp_get_lms_alg(cipher);
    if (!mode) {
        return ACVP_INTERNAL_ERR;
    }

    tmp = calloc(ACVP_LMS_TMP_MAX + 1, sizeof(char));

    switch (mode) {
    case ACVP_SUB_LMS_KEYGEN:
        memzero_s(tmp, ACVP_LMS_TMP_MAX);
        rv = acvp_bin_to_hexstr(stc->pub_key, stc->pub_key_len, tmp, ACVP_LMS_TMP_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (publicKey)");
            goto end;
        }
        json_object_set_string(tc_rsp, "publicKey", tmp);
        break;
    case ACVP_SUB_LMS_SIGGEN:
        // This also needs publicKey in the test group response, handled elsewhere
        rv = acvp_bin_to_hexstr(stc->sig, stc->sig_len, tmp, ACVP_LMS_TMP_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (signature)");
            goto end;
        }
        json_object_set_string(tc_rsp, "signature", tmp);
        break;
    case ACVP_SUB_LMS_SIGVER:
        json_object_set_boolean(tc_rsp, "testPassed", stc->ver_disposition);
        rv = ACVP_SUCCESS;
        break;
    default:
        rv = ACVP_INTERNAL_ERR;
        break;
    }

end:
    free(tmp);
    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */

static ACVP_RESULT acvp_lms_release_tc(ACVP_LMS_TC *stc) {
    if (stc->pub_key) free(stc->pub_key);
    if (stc->i) free(stc->i);
    if (stc->seed) free(stc->seed);
    if (stc->msg) free(stc->msg);
    if (stc->sig) free(stc->sig);
    memzero_s(stc, sizeof(ACVP_LMS_TC));

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_lms_init_tc(ACVP_CTX *ctx,
                                    ACVP_LMS_TC *stc,
                                    ACVP_CIPHER cipher,
                                    int tc_id,
                                    int tg_id,
                                    ACVP_LMS_TESTTYPE type,
                                    ACVP_LMS_MODE lms_mode,
                                    ACVP_LMOTS_MODE lmots_mode,
                                    const char *pub_key,
                                    const char *i,
                                    const char *seed,
                                    const char *msg,
                                    const char *sig) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_LMS_TC));

    stc->tc_id = tc_id;
    stc->tg_id = tg_id;
    stc->cipher = cipher;
    stc->type = type;
    stc->lms_mode = lms_mode;
    stc->lmots_mode = lmots_mode;

    if (i) {
        stc->i = calloc(ACVP_LMS_TMP_MAX, sizeof(unsigned char));
        if (!stc->i) {
            goto err;
        }
        rv = acvp_hexstr_to_bin(i, stc->i, ACVP_LMS_TMP_MAX, &(stc->i_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (i)");
            return rv;
        }
    }

    if (seed) {
        stc->seed = calloc(ACVP_LMS_TMP_MAX, sizeof(unsigned char));
        if (!stc->seed) {
            goto err;
        }
        rv = acvp_hexstr_to_bin(seed, stc->seed, ACVP_LMS_TMP_MAX, &(stc->seed_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (seed)");
            return rv;
        }
    }

    stc->pub_key = calloc(ACVP_LMS_TMP_MAX, sizeof(unsigned char));
    if (!stc->pub_key) {
        goto err;
    }
    if (pub_key) {
        rv = acvp_hexstr_to_bin(pub_key, stc->pub_key, ACVP_LMS_TMP_MAX, &(stc->pub_key_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (pub_key)");
            return rv;
        }
    }

    if (msg) {
        stc->msg = calloc(ACVP_LMS_TMP_MAX, sizeof(unsigned char));
        if (!stc->msg) {
            goto err;
        }
        rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_LMS_TMP_MAX, &(stc->msg_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (msg)");
            return rv;
        }
    }

    stc->sig = calloc(ACVP_LMS_TMP_MAX, sizeof(unsigned char));
    if (!stc->sig) {
        goto err;
    }
    if (sig) {
        rv = acvp_hexstr_to_bin(sig, stc->sig, ACVP_LMS_TMP_MAX, &(stc->sig_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (sig)");
            return rv;
        }
    }

    return ACVP_SUCCESS;

err:
    ACVP_LOG_ERR("Failed to allocate buffer in LMS test case");
    return ACVP_MALLOC_FAIL;
}


static ACVP_LMS_TESTTYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return ACVP_LMS_TESTTYPE_AFT;

    return 0;
}

ACVP_RESULT acvp_lms_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    unsigned int tc_id = 0, tg_id = 0;
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
    ACVP_CAPS_LIST *cap = NULL;
    ACVP_LMS_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;

    ACVP_CIPHER alg_id;
    char *json_result = NULL;

    ACVP_LMS_MODE lms_mode = 0;
    ACVP_LMOTS_MODE lmots_mode = 0;
    ACVP_LMS_TESTTYPE type = 0;
    const char *alg_str = NULL, *mode_str = NULL, *type_str = NULL, *lms_str = NULL, *lmots_str = NULL,  *pub_str = NULL;
    const char *i_str = NULL, *seed_str = NULL, *msg_str = NULL, *sig_str = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    memzero_s(&stc, sizeof(ACVP_LMS_TC));
    tc.tc.lms = &stc;
    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("Server JSON missing 'mode'");
        return ACVP_MALFORMED_JSON;
    }

    alg_id = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (!alg_id) {
        ACVP_LOG_ERR("Server JSON invalid algorithm or mode");
        return ACVP_TC_INVALID_DATA;
    }

    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        return ACVP_UNSUPPORTED_OP;
    }
    ACVP_LOG_VERBOSE("    LMS mode: %s", mode_str);

    // Create ACVP array for response
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct. ");
        return rv;
    }

    // Start to build the JSON response
    rv = acvp_setup_json_rsp_group(&ctx, &reg_arry_val, &r_vs_val, &r_vs, alg_str, &r_garr);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to setup json response");
        return rv;
    }
    json_object_set_string(r_vs, "mode", mode_str);

    rv = acvp_tc_json_get_array(ctx, alg_id, obj, "testGroups", &groups);
    if (rv != ACVP_SUCCESS) {
        goto err;
    }
    g_cnt = json_array_get_count(groups);

    for (i = 0; i < g_cnt; i++) {

        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        /*
         * Create a new group in the response with the tgid
         * and an array of tests
         */
        r_gval = json_value_init_object();
        r_gobj = json_value_get_object(r_gval);
        rv = acvp_tc_json_get_uint(ctx, alg_id, groupobj, "tgId", &tg_id);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tg_id);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "testType", &type_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        type = read_test_type(type_str);
        if (!type) {
            ACVP_LOG_ERR("invalid testType from server JSON");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "lmsMode", &lms_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        lms_mode = acvp_lookup_lms_mode(lms_str);
        if (!lms_mode) {
            ACVP_LOG_ERR("invalid lmsMode from server JSON");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "lmOtsMode", &lmots_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        lmots_mode = acvp_lookup_lmots_mode(lmots_str);
        if (!lmots_mode) {
            ACVP_LOG_ERR("invalid lmOtsMode from server JSON");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        if (alg_id == ACVP_LMS_SIGVER) {
            rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "publicKey", &pub_str);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }
        }

        ACVP_LOG_VERBOSE("           Test group: %d", i);
        ACVP_LOG_VERBOSE("            Test type: %s", type_str);
        ACVP_LOG_VERBOSE("             LMS mode: %s", lms_str);
        ACVP_LOG_VERBOSE("           LMOTS mode: %s", lmots_str);
        if (pub_str) {
            ACVP_LOG_VERBOSE("            publicKey: %s", pub_str);
        }

        rv = acvp_tc_json_get_array(ctx, alg_id, groupobj, "tests", &tests);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        t_cnt = json_array_get_count(tests);
        if (!t_cnt) {
            ACVP_LOG_ERR("Test array count is zero");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_VERBOSE("Found new LMS test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "tcId", (int *)&tc_id);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            if (alg_id == ACVP_LMS_KEYGEN) {
                rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "i", &i_str);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }

                rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "seed", &seed_str);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }
            } else {
                rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "message", &msg_str);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }
            }

            if (alg_id == ACVP_LMS_SIGVER) {
                rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "signature", &sig_str);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);

            // Create a new test case in the response
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            rv = acvp_lms_init_tc(ctx, &stc, alg_id, tc_id, tg_id, type, lms_mode, lmots_mode, pub_str,
                                  i_str, seed_str, msg_str, sig_str);

            // Process the current test vector...
            if (rv == ACVP_SUCCESS) {
                if ((cap->crypto_handler)(&tc)) {
                    ACVP_LOG_ERR("Crypto module failed the operation");
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }
            } else {
                ACVP_LOG_ERR("Failed to initialize LMS test case");
                json_value_free(r_tval);
                goto err;
            }

            // Output the test case results using JSON

            // For siggen, we need a public key for the test group object, grab from first TC for group
            if (alg_id == ACVP_LMS_SIGGEN && !j) {
                char *tmp = calloc(ACVP_LMS_TMP_MAX + 1, sizeof(char));
                rv = acvp_bin_to_hexstr(stc.pub_key, stc.pub_key_len, tmp, ACVP_LMS_TMP_MAX);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("Hex conversion failure (pub_key)");
                    free(tmp);
                    json_value_free(r_tval);
                    goto err;
                }
                json_object_set_string(r_gobj, "publicKey", (const char *)tmp);
                memzero_s(tmp, ACVP_LMS_TMP_MAX);
                free(tmp);
            }
            rv = acvp_lms_output_tc(ctx, alg_id, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure recording test response");
                json_value_free(r_tval);
                goto err;
            }

            // Append the test response value to array
            json_array_append_value(r_tarr, r_tval);

            // Release all the memory associated with the test case
            acvp_lms_release_tc(&stc);
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
        acvp_lms_release_tc(&stc);
        acvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}
