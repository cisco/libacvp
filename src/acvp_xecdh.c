/** @file */
/*
 * Copyright (c) 2026, Cisco Systems, Inc.
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

static ACVP_RESULT acvp_xecdh_kat_handler_internal(ACVP_CTX *ctx, JSON_Object *obj, ACVP_CIPHER cipher);

static ACVP_RESULT acvp_xecdh_set_hex(ACVP_CTX *ctx,
                                      JSON_Object *tc_rsp,
                                      const char *name,
                                      const unsigned char *buf,
                                      int len) {
    ACVP_RESULT rv;
    char *tmp = NULL;

    tmp = calloc(ACVP_XECDH_KEY_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(buf, len, tmp, ACVP_XECDH_KEY_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (%s)", name);
    } else {
        json_object_set_string(tc_rsp, name, tmp);
    }

    free(tmp);
    return rv;
}

static ACVP_RESULT acvp_xecdh_output_tc(ACVP_CTX *ctx, ACVP_XECDH_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    switch (stc->cipher) {
    case ACVP_XECDH_KEYGEN:
        rv = acvp_xecdh_set_hex(ctx, tc_rsp, "privateKey", stc->private_key, stc->private_key_len);
        if (rv != ACVP_SUCCESS) {
            return rv;
        }
        rv = acvp_xecdh_set_hex(ctx, tc_rsp, "publicKey", stc->public_key, stc->public_key_len);
        break;
    case ACVP_XECDH_KEYVER:
        json_object_set_boolean(tc_rsp, "testPassed", stc->ver_disposition == ACVP_TEST_DISPOSITION_PASS);
        break;
    case ACVP_XECDH_SSC:
        rv = acvp_xecdh_set_hex(ctx, tc_rsp, "publicIut", stc->public_iut, stc->public_iut_len);
        if (rv != ACVP_SUCCESS) {
            return rv;
        }
        rv = acvp_xecdh_set_hex(ctx, tc_rsp, "z", stc->z, stc->z_len);
        break;
    default:
        rv = ACVP_INVALID_ARG;
        break;
    }

    return rv;
}

static ACVP_RESULT acvp_xecdh_release_tc(ACVP_XECDH_TC *stc) {
    if (stc->private_key) free(stc->private_key);
    if (stc->public_key) free(stc->public_key);
    if (stc->public_server) free(stc->public_server);
    if (stc->public_iut) free(stc->public_iut);
    if (stc->z) free(stc->z);

    memzero_s(stc, sizeof(ACVP_XECDH_TC));

    return ACVP_SUCCESS;
}

static ACVP_XECDH_TESTTYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s(ACVP_TESTTYPE_STR_AFT, sizeof(ACVP_TESTTYPE_STR_AFT) - 1, str, &diff);
    if (!diff) return ACVP_XECDH_TEST_TYPE_AFT;

    return ACVP_XECDH_TEST_TYPE_NONE;
}

static ACVP_RESULT acvp_xecdh_init_tc(ACVP_CTX *ctx,
                                      ACVP_CIPHER cipher,
                                      ACVP_XECDH_TC *stc,
                                      int tg_id,
                                      unsigned int tc_id,
                                      ACVP_X_CURVE curve,
                                      ACVP_XECDH_TESTTYPE test_type,
                                      const char *public_key,
                                      const char *public_server) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_XECDH_TC));

    stc->tc_id = tc_id;
    stc->tg_id = tg_id;
    stc->cipher = cipher;
    stc->curve = curve;
    stc->test_type = test_type;

    switch (cipher) {
    case ACVP_XECDH_KEYGEN:
        stc->private_key = calloc(ACVP_XECDH_KEY_BYTE_MAX, sizeof(unsigned char));
        if (!stc->private_key) goto err;
        stc->public_key = calloc(ACVP_XECDH_KEY_BYTE_MAX, sizeof(unsigned char));
        if (!stc->public_key) goto err;
        break;
    case ACVP_XECDH_KEYVER:
        stc->public_key = calloc(ACVP_XECDH_KEY_BYTE_MAX, sizeof(unsigned char));
        if (!stc->public_key) goto err;
        rv = acvp_hexstr_to_bin(public_key, stc->public_key, ACVP_XECDH_KEY_BYTE_MAX, &stc->public_key_len);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (publicKey)");
            return rv;
        }
        break;
    case ACVP_XECDH_SSC:
        stc->public_server = calloc(ACVP_XECDH_KEY_BYTE_MAX, sizeof(unsigned char));
        if (!stc->public_server) goto err;
        stc->public_iut = calloc(ACVP_XECDH_KEY_BYTE_MAX, sizeof(unsigned char));
        if (!stc->public_iut) goto err;
        stc->z = calloc(ACVP_XECDH_KEY_BYTE_MAX, sizeof(unsigned char));
        if (!stc->z) goto err;
        rv = acvp_hexstr_to_bin(public_server, stc->public_server, ACVP_XECDH_KEY_BYTE_MAX, &stc->public_server_len);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (publicServer)");
            return rv;
        }
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;

err:
    ACVP_LOG_ERR("Failed to allocate buffer in XECDH test case");
    return ACVP_MALLOC_FAIL;
}

ACVP_RESULT acvp_xecdh_keygen_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_xecdh_kat_handler_internal(ctx, obj, ACVP_XECDH_KEYGEN);
}

ACVP_RESULT acvp_xecdh_keyver_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_xecdh_kat_handler_internal(ctx, obj, ACVP_XECDH_KEYVER);
}

ACVP_RESULT acvp_xecdh_ssc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_xecdh_kat_handler_internal(ctx, obj, ACVP_XECDH_SSC);
}

static ACVP_RESULT acvp_xecdh_kat_handler_internal(ACVP_CTX *ctx, JSON_Object *obj, ACVP_CIPHER cipher) {
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
    ACVP_XECDH_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;

    ACVP_CIPHER alg_id;
    char *json_result = NULL;
    const char *alg_str, *mode_str, *public_key = NULL, *public_server = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    memzero_s(&stc, sizeof(ACVP_XECDH_TC));
    tc.tc.xecdh = &stc;
    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("Server JSON missing 'mode'");
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
    ACVP_LOG_VERBOSE("    XECDH mode: %s", mode_str);

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
        return rv;
    }
    json_object_set_string(r_vs, "mode", mode_str);

    rv = acvp_tc_json_get_array(ctx, alg_id, obj, "testGroups", &groups);
    if (rv != ACVP_SUCCESS) {
        goto err;
    }
    g_cnt = json_array_get_count(groups);

    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        ACVP_X_CURVE curve = 0;
        ACVP_XECDH_TESTTYPE test_type;
        const char *curve_str = NULL, *type_str = NULL;

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

        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "curve", &curve_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        curve = acvp_lookup_x_curve(curve_str);
        if (!curve) {
            ACVP_LOG_ERR("Server JSON includes unrecognized curve");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "testType", &type_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        test_type = read_test_type(type_str);
        if (!test_type) {
            ACVP_LOG_ERR("Server JSON includes unrecognized testType");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        ACVP_LOG_VERBOSE("           Test group: %d", i);
        ACVP_LOG_VERBOSE("                curve: %s", curve_str);
        ACVP_LOG_VERBOSE("            Test type: %s", type_str);

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
            ACVP_LOG_VERBOSE("Found new XECDH test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "tcId", (int *)&tc_id);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            if (alg_id == ACVP_XECDH_KEYVER) {
                rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "publicKey", &public_key);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }
                if (strnlen_s(public_key, ACVP_XECDH_KEY_STR_MAX + 1) > ACVP_XECDH_KEY_STR_MAX) {
                    ACVP_LOG_ERR("'publicKey' too long");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            if (alg_id == ACVP_XECDH_SSC) {
                rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "publicServer", &public_server);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }
                if (strnlen_s(public_server, ACVP_XECDH_KEY_STR_MAX + 1) > ACVP_XECDH_KEY_STR_MAX) {
                    ACVP_LOG_ERR("'publicServer' too long");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            if (alg_id == ACVP_XECDH_KEYVER) {
                ACVP_LOG_VERBOSE("        publicKey: %s", public_key);
            }
            if (alg_id == ACVP_XECDH_SSC) {
                ACVP_LOG_VERBOSE("     publicServer: %s", public_server);
            }

            // Create a new test case in the response
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            rv = acvp_xecdh_init_tc(ctx, alg_id, &stc, tgId, tc_id, curve, test_type, public_key, public_server);

            // Process the current test vector...
            if (rv == ACVP_SUCCESS) {
                if ((cap->crypto_handler)(&tc)) {
                    ACVP_LOG_ERR("Crypto module failed the operation");
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }
            } else {
                ACVP_LOG_ERR("Failed to initialize XECDH test case");
                json_value_free(r_tval);
                goto err;
            }

            rv = acvp_xecdh_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure recording test response");
                json_value_free(r_tval);
                goto err;
            }

            // Append the test response value to array
            json_array_append_value(r_tarr, r_tval);

            // Release all the memory associated with the test case
            acvp_xecdh_release_tc(&stc);
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
        acvp_xecdh_release_tc(&stc);
        acvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}
