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

static ACVP_RESULT acvp_eddsa_kat_handler_internal(ACVP_CTX *ctx, JSON_Object *obj, ACVP_CIPHER cipher);

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_eddsa_output_tc(ACVP_CTX *ctx, ACVP_CIPHER cipher, ACVP_EDDSA_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    if (cipher == ACVP_EDDSA_SIGVER || cipher == ACVP_EDDSA_KEYVER) {
        json_object_set_boolean(tc_rsp, "testPassed", stc->ver_disposition);
    } else {
        tmp = calloc(ACVP_EDDSA_MSG_LEN_MAX + 1, sizeof(char));
        if (!tmp) {
            return ACVP_MALLOC_FAIL;
        }
    }

    if (cipher == ACVP_EDDSA_KEYGEN) {
        rv = acvp_bin_to_hexstr(stc->d, stc->d_len, tmp, ACVP_EDDSA_MSG_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (d)");
            goto err;
        }
        json_object_set_string(tc_rsp, "d", (const char *)tmp);
        memzero_s(tmp, ACVP_EDDSA_MSG_LEN_MAX);

        rv = acvp_bin_to_hexstr(stc->q, stc->q_len, tmp, ACVP_EDDSA_MSG_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (q)");
            goto err;
        }
        json_object_set_string(tc_rsp, "q", (const char *)tmp);
        memzero_s(tmp, ACVP_EDDSA_MSG_LEN_MAX);
    }

    if (cipher == ACVP_EDDSA_SIGGEN) {
        rv = acvp_bin_to_hexstr(stc->signature, stc->signature_len, tmp, ACVP_EDDSA_MSG_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (signature)");
            goto err;
        }
        json_object_set_string(tc_rsp, "signature", (const char *)tmp);
        memzero_s(tmp, ACVP_EDDSA_MSG_LEN_MAX);
    }

err:
    if (tmp) free(tmp);
    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */

static ACVP_RESULT acvp_eddsa_release_tc(ACVP_EDDSA_TC *stc) {
    if (stc->d) free(stc->d);
    if (stc->q) free(stc->q);
    if (stc->message) free(stc->message);
    if (stc->context) free(stc->context);
    if (stc->signature) free(stc->signature);

    memzero_s(stc, sizeof(ACVP_EDDSA_TC));

    return ACVP_SUCCESS;
}

static ACVP_EDDSA_TESTTYPE read_test_type(const char *str) {
    int diff = 1;
    strcmp_s(ACVP_TESTTYPE_STR_AFT, sizeof(ACVP_TESTTYPE_STR_AFT) - 1, str, &diff);
    if (!diff) return ACVP_EDDSA_TEST_TYPE_AFT;
    strcmp_s(ACVP_TESTTYPE_STR_BFT, sizeof(ACVP_TESTTYPE_STR_BFT) - 1, str, &diff);
    if (!diff) return ACVP_EDDSA_TEST_TYPE_BFT;

    return 0;
}

static ACVP_RESULT acvp_eddsa_init_tc(ACVP_CTX *ctx,
                                      ACVP_CIPHER cipher,
                                      ACVP_EDDSA_TC *stc,
                                      int tg_id,
                                      unsigned int tc_id,
                                      int use_prehash,
                                      ACVP_ED_CURVE curve,
                                      const char *q,
                                      const char *message,
                                      const char *context,
                                      const char *signature) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_EDDSA_TC));

    stc->tc_id = tc_id;
    stc->tg_id = tg_id;
    stc->cipher = cipher;
    stc->curve = curve;
    stc->use_prehash = use_prehash;

    stc->q = calloc(ACVP_EDDSA_POINT_LEN_MAX, sizeof(char));
    if (!stc->q) { goto err; }
    if (cipher == ACVP_EDDSA_KEYVER || cipher == ACVP_EDDSA_SIGVER) {
        rv = acvp_hexstr_to_bin(q, stc->q, ACVP_EDDSA_POINT_LEN_MAX, &(stc->q_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (q)");
            return rv;
        }
    }

    if (cipher == ACVP_EDDSA_KEYGEN) {
        stc->d = calloc(ACVP_EDDSA_POINT_LEN_MAX, sizeof(char));
        if (!stc->d) { goto err; }
    }

    if (cipher == ACVP_EDDSA_SIGGEN && context) {
        stc->context = calloc(ACVP_EDDSA_POINT_LEN_MAX, sizeof(char));
        if (!stc->context) { goto err; }

        rv = acvp_hexstr_to_bin(context, stc->context, ACVP_EDDSA_POINT_LEN_MAX, &(stc->context_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (context)");
            return rv;
        }
    }

    if (cipher == ACVP_EDDSA_SIGGEN || cipher == ACVP_EDDSA_SIGVER) {
        stc->message = calloc(ACVP_EDDSA_POINT_LEN_MAX, sizeof(char));
        if (!stc->message) { goto err; }
        stc->signature = calloc(ACVP_EDDSA_POINT_LEN_MAX, sizeof(char));
        if (!stc->signature) { goto err; }

        rv = acvp_hexstr_to_bin(message, stc->message, ACVP_EDDSA_POINT_LEN_MAX, &(stc->msg_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (message)");
            return rv;
        }
    }

    if (cipher == ACVP_EDDSA_SIGVER) {
        rv = acvp_hexstr_to_bin(signature, stc->signature, ACVP_EDDSA_POINT_LEN_MAX, &(stc->signature_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (signature)");
            return rv;
        }
    }

    return ACVP_SUCCESS;

err:
    ACVP_LOG_ERR("Failed to allocate buffer in EDDSA test case");
    if (stc->d) free(stc->d);
    if (stc->q) free(stc->q);
    if (stc->message) free(stc->message);
    if (stc->context) free(stc->context);
    if (stc->signature) free(stc->signature);
    return ACVP_MALLOC_FAIL;
}

ACVP_RESULT acvp_eddsa_keygen_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_eddsa_kat_handler_internal(ctx, obj, ACVP_EDDSA_KEYGEN);
}

ACVP_RESULT acvp_eddsa_keyver_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_eddsa_kat_handler_internal(ctx, obj, ACVP_EDDSA_KEYVER);
}

ACVP_RESULT acvp_eddsa_siggen_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_eddsa_kat_handler_internal(ctx, obj, ACVP_EDDSA_SIGGEN);
}

ACVP_RESULT acvp_eddsa_sigver_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_eddsa_kat_handler_internal(ctx, obj, ACVP_EDDSA_SIGVER);
}

static ACVP_RESULT acvp_eddsa_kat_handler_internal(ACVP_CTX *ctx, JSON_Object *obj, ACVP_CIPHER cipher) {
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
    ACVP_EDDSA_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;

    ACVP_CIPHER alg_id;
    ACVP_EDDSA_TESTTYPE test_type;
    char *json_result = NULL;
    const char *alg_str, *mode_str, *q = NULL, *sig = NULL, *message = NULL, *context = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    memzero_s(&stc, sizeof(ACVP_EDDSA_TC));
    tc.tc.eddsa = &stc;
    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("Server JSON missing 'mode_str'");
        return ACVP_MALFORMED_JSON;
    }

    alg_id = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != cipher) {
        ACVP_LOG_ERR("Server JSON invalid algorithm or mode");
        return ACVP_INVALID_ARG;
    }

    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        return ACVP_UNSUPPORTED_OP;
    }
    ACVP_LOG_VERBOSE("    EDDSA mode: %s", mode_str);

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
    json_object_set_string(r_vs, "mode", mode_str);

    groups = json_object_get_array(obj, "testGroups");
    if (!groups) {
        ACVP_LOG_ERR("Missing testGroups from server JSON");
        rv = ACVP_MALFORMED_JSON;
        goto err;
    }
    g_cnt = json_array_get_count(groups);

    for (i = 0; i < g_cnt; i++) {
        int tgId = 0, use_prehash = 0;
        ACVP_ED_CURVE curve = 0;
        const char *curve_str = NULL, *type_str = NULL;

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
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        curve_str = json_object_get_string(groupobj, "curve");
        if (!curve_str) {
            ACVP_LOG_ERR("Server JSON missing 'curve'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        curve = acvp_lookup_ed_curve(curve_str);
        if (!curve) {
            ACVP_LOG_ERR("Server JSON includes unrecognized curve");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        type_str = json_object_get_string(groupobj, "testType");
        test_type = read_test_type(type_str);
        if (!test_type) {
            ACVP_LOG_ERR("Server JSON includes unrecognized testType");
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        if (alg_id != ACVP_EDDSA_SIGGEN && test_type == ACVP_EDDSA_TEST_TYPE_BFT) {
            ACVP_LOG_ERR("Server JSON includes unsupported testType");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        if (alg_id == ACVP_EDDSA_SIGGEN || alg_id == ACVP_EDDSA_SIGVER) {
            use_prehash = json_object_get_boolean(groupobj, "preHash");
            if (use_prehash == -1) {
                ACVP_LOG_ERR("Server JSON missing or invalid 'preHash'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
        }

        ACVP_LOG_VERBOSE("           Test group: %d", i);
        ACVP_LOG_VERBOSE("                curve: %s", curve_str);
        ACVP_LOG_VERBOSE("            Test type: %s", type_str);
        if (alg_id == ACVP_EDDSA_SIGGEN || alg_id == ACVP_EDDSA_SIGVER) {
            ACVP_LOG_VERBOSE("          use_prehash: %s", use_prehash == 1 ? "true" : "false");
        }

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        if (!t_cnt) {
            ACVP_LOG_ERR("Test array count is zero");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_VERBOSE("Found new EDDSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            if (alg_id == ACVP_EDDSA_KEYVER || alg_id == ACVP_EDDSA_SIGVER) {
                q = json_object_get_string(testobj, "q");
                if (!q) {
                    ACVP_LOG_ERR("Server JSON missing 'q'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(q, ACVP_EDDSA_POINT_LEN_MAX + 1) > ACVP_EDDSA_POINT_LEN_MAX) {
                    ACVP_LOG_ERR("'q' too long");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }
            if (alg_id == ACVP_EDDSA_SIGGEN || alg_id == ACVP_EDDSA_SIGVER) {
                message = json_object_get_string(testobj, "message");
                if (!message) {
                    ACVP_LOG_ERR("Server JSON missing 'message'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(message, ACVP_EDDSA_MSG_LEN_MAX + 1) > ACVP_EDDSA_MSG_LEN_MAX) {
                    ACVP_LOG_ERR("message string too long");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            if (alg_id == ACVP_EDDSA_SIGGEN) {
                context = json_object_get_string(testobj, "context");
                if (context && strnlen_s(context, ACVP_EDDSA_MSG_LEN_MAX + 1) > ACVP_EDDSA_MSG_LEN_MAX) {
                    ACVP_LOG_ERR("'context' too long");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            if (alg_id == ACVP_EDDSA_SIGVER) {
                sig = json_object_get_string(testobj, "signature");
                if (!sig) {
                    ACVP_LOG_ERR("Server JSON missing 'signature'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(sig, ACVP_EDDSA_MSG_LEN_MAX + 1) > ACVP_EDDSA_MSG_LEN_MAX) {
                    ACVP_LOG_ERR("'signature' too long");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            if (alg_id == ACVP_EDDSA_KEYVER || alg_id == ACVP_EDDSA_SIGVER) {
                ACVP_LOG_VERBOSE("                q: %s", q);
            }
            if (alg_id == ACVP_EDDSA_SIGGEN || alg_id == ACVP_EDDSA_SIGVER) {
                ACVP_LOG_VERBOSE("           message: %s", message);
            }
            if (context) {
                ACVP_LOG_VERBOSE("          context: %s", context);
            }
            if (alg_id == ACVP_EDDSA_SIGVER) {
                ACVP_LOG_VERBOSE("          signature: %s", sig);
            }
            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            rv = acvp_eddsa_init_tc(ctx, alg_id, &stc, tgId, tc_id, use_prehash, curve, q, message, context, sig);

            /* Process the current test vector... */
            if (rv == ACVP_SUCCESS) {
                if ((cap->crypto_handler)(&tc)) {
                    ACVP_LOG_ERR("crypto module failed the operation");
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }
            } else {
                ACVP_LOG_ERR("Failed to initialize EDDSA test case");
                json_value_free(r_tval);
                goto err;
            }

            /* Output the test case results using JSON. et "q" at the GROUP level for siggen */
            if (cipher == ACVP_EDDSA_SIGGEN) {
                char *tmp = calloc(ACVP_EDDSA_POINT_LEN_MAX + 1, sizeof(char));
                if (!tmp) {
                    ACVP_LOG_ERR("Failed to allocate outbut buffer for 'q' in EDDSA siggen");
                    json_value_free(r_tval);
                    goto err;
                }
                rv = acvp_bin_to_hexstr(stc.q, stc.q_len, tmp, ACVP_EDDSA_POINT_LEN_MAX);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("Hex conversion failure (q)");
                    free(tmp);
                    json_value_free(r_tval);
                    goto err;
                }
                json_object_set_string(r_gobj, "q", (const char *)tmp);
                memzero_s(tmp, ACVP_EDDSA_POINT_LEN_MAX);
                free(tmp);
            }
            rv = acvp_eddsa_output_tc(ctx, alg_id, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in hash module");
                json_value_free(r_tval);
                goto err;
            }

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);

            /*
             * Release all the memory associated with the test case
             */
            acvp_eddsa_release_tc(&stc);
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
        acvp_eddsa_release_tc(&stc);
        acvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}
