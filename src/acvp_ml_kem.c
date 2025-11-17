/** @file */
/*
 * Copyright (c) 2025, Cisco Systems, Inc.
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
static ACVP_RESULT acvp_ml_kem_output_tc(ACVP_CTX *ctx, ACVP_CIPHER cipher, ACVP_ML_KEM_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv;
    ACVP_SUB_ML_KEM mode;
    char *tmp = NULL;

    mode = acvp_get_ml_kem_alg(cipher);
    if (!mode) {
        return ACVP_INTERNAL_ERR;
    }

    tmp = calloc(ACVP_ML_KEM_TMP_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Error allocating memory to output ML-KEM test case");
        rv = ACVP_MALLOC_FAIL;
        goto end;
    }

    switch (mode) {
    case ACVP_SUB_ML_KEM_KEYGEN:
        memzero_s(tmp, ACVP_ML_KEM_TMP_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->ek, stc->ek_len, tmp, ACVP_ML_KEM_TMP_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (ek)");
            goto end;
        }
        json_object_set_string(tc_rsp, "ek", tmp);

        memzero_s(tmp, ACVP_ML_KEM_TMP_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->dk, stc->dk_len, tmp, ACVP_ML_KEM_TMP_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (dk)");
            goto end;
        }
        json_object_set_string(tc_rsp, "dk", tmp);
        break;
    case ACVP_SUB_ML_KEM_XCAP:
        switch (stc->function) {
            case ACVP_ML_KEM_FUNCTION_ENCAPSULATE:
            memzero_s(tmp, ACVP_ML_KEM_TMP_STR_MAX);
            rv = acvp_bin_to_hexstr(stc->c, stc->c_len, tmp, ACVP_ML_KEM_TMP_STR_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (c)");
                goto end;
            }
            json_object_set_string(tc_rsp, "c", tmp);
            // fallthru
        case ACVP_ML_KEM_FUNCTION_DECAPSULATE:
		    memzero_s(tmp, ACVP_ML_KEM_TMP_STR_MAX);
		    rv = acvp_bin_to_hexstr(stc->k, stc->k_len, tmp, ACVP_ML_KEM_TMP_STR_MAX);
		    if (rv != ACVP_SUCCESS) {
		        ACVP_LOG_ERR("Hex conversion failure (k)");
		        goto end;
		    }
		    json_object_set_string(tc_rsp, "k", tmp);
            break;
        case ACVP_ML_KEM_FUNCTION_ENC_KEYCHECK:
        case ACVP_ML_KEM_FUNCTION_DEC_KEYCHECK:
            json_object_set_boolean(tc_rsp, "testPassed", stc->keycheck_disposition);
            rv = ACVP_SUCCESS;
            break;
        case ACVP_ML_KEM_FUNCTION_NONE:
        case ACVP_ML_KEM_FUNCTION_MAX:
        default:
            rv = ACVP_INTERNAL_ERR;
            break;
        }
        break;
    default:
        rv = ACVP_INTERNAL_ERR;
        break;
    }

end:
    if (tmp) free(tmp);
    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */

static ACVP_RESULT acvp_ml_kem_release_tc(ACVP_ML_KEM_TC *stc) {
    if (stc->dk) free(stc->dk);
    if (stc->ek) free(stc->ek);
    if (stc->d) free(stc->d);
    if (stc->z) free(stc->z);
    if (stc->m) free(stc->m);
    if (stc->c) free(stc->c);
    if (stc->k) free(stc->k);
    memzero_s(stc, sizeof(ACVP_ML_KEM_TC));

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_ml_kem_init_tc(ACVP_CTX *ctx,
                                    ACVP_ML_KEM_TC *stc,
                                    ACVP_CIPHER cipher,
                                    int tc_id,
                                    int tg_id,
                                    ACVP_ML_KEM_TESTTYPE type,
                                    ACVP_ML_KEM_PARAM_SET param_set,
                                    ACVP_ML_KEM_FUNCTION function,
                                    const char *d,
                                    const char *z,
                                    const char *dk,
                                    const char *ek,
                                    const char *m,
                                    const char *c) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_ML_KEM_TC));

    stc->tc_id = tc_id;
    stc->tg_id = tg_id;
    stc->cipher = cipher;
    stc->type = type;
    stc->param_set = param_set;
    stc->function = function;

    // dk and ek are outputs for keygen, and inputs for encap/decap
    stc->dk = calloc(ACVP_ML_KEM_TMP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->dk) {
        goto err;
    }

    stc->ek = calloc(ACVP_ML_KEM_TMP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->ek) {
        goto err;
    }

    /**
     * Load additional values by operation type
     */
    if (cipher == ACVP_ML_KEM_KEYGEN) {
        stc->d = calloc(ACVP_ML_KEM_TMP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->d) {
            goto err;
        }
        rv = acvp_hexstr_to_bin(d, stc->d, ACVP_ML_KEM_TMP_BYTE_MAX, &(stc->d_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (d)");
            return rv;
        }

        stc->z = calloc(ACVP_ML_KEM_TMP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->z) {
            goto err;
        }
        rv = acvp_hexstr_to_bin(z, stc->z, ACVP_ML_KEM_TMP_BYTE_MAX, &(stc->z_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (z)");
            return rv;
        }
    } else {
        stc->c = calloc(ACVP_ML_KEM_TMP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->c) {
            goto err;
        }
        stc->k = calloc(ACVP_ML_KEM_TMP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->k) {
            goto err;
        }

        switch (function) {
        case ACVP_ML_KEM_FUNCTION_ENCAPSULATE:
            stc->m = calloc(ACVP_ML_KEM_TMP_BYTE_MAX, sizeof(unsigned char));
            if (!stc->m) {
                goto err;
            }
            rv = acvp_hexstr_to_bin(m, stc->m, ACVP_ML_KEM_TMP_BYTE_MAX, &(stc->m_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (m)");
                return rv;
            }
            // fallthru
        case ACVP_ML_KEM_FUNCTION_ENC_KEYCHECK:
            rv = acvp_hexstr_to_bin(ek, stc->ek, ACVP_ML_KEM_TMP_BYTE_MAX, &(stc->ek_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (ek)");
                return rv;
            }
            break;
        case ACVP_ML_KEM_FUNCTION_DECAPSULATE:
            rv = acvp_hexstr_to_bin(c, stc->c, ACVP_ML_KEM_TMP_BYTE_MAX, &(stc->c_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (c)");
                return rv;
            }
            // fallthru
        case ACVP_ML_KEM_FUNCTION_DEC_KEYCHECK:
            rv = acvp_hexstr_to_bin(dk, stc->dk, ACVP_ML_KEM_TMP_BYTE_MAX, &(stc->dk_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (dk)");
                return rv;
            }
            break;
        case ACVP_ML_KEM_FUNCTION_NONE:
        case ACVP_ML_KEM_FUNCTION_MAX:
        default:
            ACVP_LOG_ERR("Bad function type (%d)", function);
            return rv;
        }
    }

    return ACVP_SUCCESS;

err:
    ACVP_LOG_ERR("Failed to allocate buffer in ML-KEM test case");
    return ACVP_MALLOC_FAIL;
}


static ACVP_ML_KEM_TESTTYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return ACVP_ML_KEM_TESTTYPE_AFT;

    strcmp_s("VAL", 3, str, &diff);
    if (!diff) return ACVP_ML_KEM_TESTTYPE_VAL;

    return ACVP_ML_KEM_TESTTYPE_NONE;
}

static ACVP_ML_KEM_FUNCTION read_function(const char *str) {
    int diff = 1;

    strcmp_s("encapsulationKeyCheck", 21, str, &diff);
    if (!diff) return ACVP_ML_KEM_FUNCTION_ENC_KEYCHECK;

    strcmp_s("decapsulationKeyCheck", 21, str, &diff);
    if (!diff) return ACVP_ML_KEM_FUNCTION_DEC_KEYCHECK;

    strcmp_s("encapsulation", 13, str, &diff);
    if (!diff) return ACVP_ML_KEM_FUNCTION_ENCAPSULATE;

    strcmp_s("decapsulation", 13, str, &diff);
    if (!diff) return ACVP_ML_KEM_FUNCTION_DECAPSULATE;

    return ACVP_ML_KEM_FUNCTION_NONE;
}

ACVP_RESULT acvp_ml_kem_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_ML_KEM_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;

    ACVP_CIPHER alg_id;
    char *json_result = NULL;

    ACVP_ML_KEM_TESTTYPE type = 0;
    ACVP_ML_KEM_PARAM_SET param_set = 0;
    ACVP_ML_KEM_FUNCTION function = 0;
    const char *alg_str = NULL, *mode_str = NULL, *type_str = NULL, *param_set_str = NULL,  *func_str = NULL;
    const char *d_str = NULL, *z_str = NULL, *dk_str = NULL, *ek_str = NULL, *m_str = NULL, *c_str = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    memzero_s(&stc, sizeof(ACVP_ML_KEM_TC));
    tc.tc.ml_kem = &stc;
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
    ACVP_LOG_VERBOSE("    ML-KEM mode: %s", mode_str);

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

        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "parameterSet", &param_set_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        param_set = acvp_lookup_ml_kem_param_set(param_set_str);
        if (!param_set) {
            ACVP_LOG_ERR("Server JSON invalid 'parameterSet'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        if (alg_id == ACVP_ML_KEM_XCAP) {
            rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "function", &func_str);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }
            function = read_function(func_str);
            if (!function) {
                ACVP_LOG_ERR("invalid function from server JSON");
                rv = ACVP_INVALID_ARG;
                goto err;
            }
        }

        ACVP_LOG_VERBOSE("           Test group: %d", i);
        ACVP_LOG_VERBOSE("            Test type: %s", type_str);
        if (param_set_str) {
            ACVP_LOG_VERBOSE("            param set: %s", param_set_str);
        }
        if (func_str) {
            ACVP_LOG_VERBOSE("             function: %s", func_str);
        }
        if (dk_str) {
            ACVP_LOG_VERBOSE("                   dk: %s", dk_str);
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
            ACVP_LOG_VERBOSE("Found new ML-KEM test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            rv = acvp_tc_json_get_uint(ctx, alg_id, testobj, "tcId", &tc_id);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            if (alg_id == ACVP_ML_KEM_KEYGEN) {
                rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "d", &d_str);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }

                rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "z", &z_str);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }
            } else { // else is encap/decap/keycheck
                switch (function) {
                case ACVP_ML_KEM_FUNCTION_ENCAPSULATE:
                    rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "m", &m_str);
                    if (rv != ACVP_SUCCESS) {
                        goto err;
                    }
                    // fallthru
                case ACVP_ML_KEM_FUNCTION_ENC_KEYCHECK:
                    rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "ek", &ek_str);
                    if (rv != ACVP_SUCCESS) {
                        goto err;
                    }
                    break;
                case ACVP_ML_KEM_FUNCTION_DECAPSULATE:
                    rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "c", &c_str);
                    if (rv != ACVP_SUCCESS) {
                        goto err;
                    }
                    // fallthru
                case ACVP_ML_KEM_FUNCTION_DEC_KEYCHECK:
                    rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "dk", &dk_str);
                    if (rv != ACVP_SUCCESS) {
                        goto err;
                    }
                    break;
                case ACVP_ML_KEM_FUNCTION_NONE:
                case ACVP_ML_KEM_FUNCTION_MAX:
                default:
                    ACVP_LOG_ERR("Invalid ML-KEM Function (%d)", function);
                        rv = ACVP_MISSING_ARG;
                        goto err;
                }
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            if (d_str) {
                ACVP_LOG_VERBOSE("                d: %s", d_str);
            }
            if (d_str) {
                ACVP_LOG_VERBOSE("                z: %s", z_str);
            }
            if (ek_str) {
                ACVP_LOG_VERBOSE("               ek: %s", ek_str);
            }
            if (m_str) {
                ACVP_LOG_VERBOSE("                m: %s", m_str);
            }
            if (c_str) {
                ACVP_LOG_VERBOSE("                c: %s", c_str);
            }
            if (dk_str) {
                ACVP_LOG_VERBOSE("                   dk: %s", dk_str);
            }

            // Create a new test case in the response
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            rv = acvp_ml_kem_init_tc(ctx, &stc, alg_id, tc_id, tg_id, type, param_set, function,
                                  d_str, z_str, dk_str, ek_str, m_str, c_str);

            // Process the current test vector...
            if (rv == ACVP_SUCCESS) {
                if ((cap->crypto_handler)(&tc)) {
                    ACVP_LOG_ERR("Crypto module failed the operation");
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }
            } else {
                ACVP_LOG_ERR("Failed to initialize ML-KEM test case");
                json_value_free(r_tval);
                goto err;
            }

            // Output the test case results using JSON
            rv = acvp_ml_kem_output_tc(ctx, alg_id, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure recording test response");
                json_value_free(r_tval);
                goto err;
            }

            // Append the test response value to array
            json_array_append_value(r_tarr, r_tval);

            // Release all the memory associated with the test case
            acvp_ml_kem_release_tc(&stc);
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
        acvp_ml_kem_release_tc(&stc);
        acvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}
