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

static ACVP_SAFE_PRIMES_TEST_TYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return ACVP_SAFE_PRIMES_TT_AFT;

    strcmp_s("VAL", 3, str, &diff);
    if (!diff) return ACVP_SAFE_PRIMES_TT_VAL;

    return 0;
}

static ACVP_SAFE_PRIMES_PARAM acvp_convert_dgm_string(const char *dgm_str)
{
    int diff = 0;

    strcmp_s("MODP-2048", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return ACVP_SAFE_PRIMES_MODP2048;
    strcmp_s("MODP-3072", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return ACVP_SAFE_PRIMES_MODP3072;
    strcmp_s("MODP-4096", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return ACVP_SAFE_PRIMES_MODP4096;
    strcmp_s("MODP-6144", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return ACVP_SAFE_PRIMES_MODP6144;
    strcmp_s("MODP-8192", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return ACVP_SAFE_PRIMES_MODP8192;
    strcmp_s("ffdhe2048", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return ACVP_SAFE_PRIMES_FFDHE2048;
    strcmp_s("ffdhe3072", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return ACVP_SAFE_PRIMES_FFDHE3072;
    strcmp_s("ffdhe4096", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return ACVP_SAFE_PRIMES_FFDHE4096;
    strcmp_s("ffdhe6144", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return ACVP_SAFE_PRIMES_FFDHE6144;
    strcmp_s("ffdhe8192", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return ACVP_SAFE_PRIMES_FFDHE8192;

    return 0;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_safe_primes_release_tc(ACVP_SAFE_PRIMES_TC *stc) {
    if (stc->x) free(stc->x);
    if (stc->y) free(stc->y);
    memzero_s(stc, sizeof(ACVP_SAFE_PRIMES_TC));
    return ACVP_SUCCESS;
}


static ACVP_RESULT acvp_safe_primes_output_tc(ACVP_CTX *ctx,
                                              ACVP_SAFE_PRIMES_TC *stc,
                                              JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    if (stc->cipher == ACVP_SAFE_PRIMES_KEYVER) {

        if (stc->result) {
            json_object_set_boolean(tc_rsp, "testPassed", 1);
        } else {
            json_object_set_boolean(tc_rsp, "testPassed", 0);
        }

    } else {
        tmp = calloc(ACVP_SAFE_PRIMES_STR_MAX + 1, sizeof(char));
        if (!tmp) {
            ACVP_LOG_ERR("Unable to malloc in acvp_safe_primes_output_mct_tc");
            return ACVP_MALLOC_FAIL;
        }

        memzero_s(tmp, ACVP_SAFE_PRIMES_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->x, stc->xlen, tmp, ACVP_SAFE_PRIMES_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (x)");
            goto end;
        }
        json_object_set_string(tc_rsp, "x", tmp);

        memzero_s(tmp, ACVP_SAFE_PRIMES_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->y, stc->ylen, tmp, ACVP_SAFE_PRIMES_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (y)");
            goto end;
        }
        json_object_set_string(tc_rsp, "y", tmp);
    }

end:
    if (tmp) free(tmp);

    return rv;
}

static ACVP_RESULT acvp_safe_primes_init_tc(ACVP_CTX *ctx,
                                            int tg_id,
                                            int tc_id,
                                            ACVP_CIPHER alg_id,
                                            ACVP_SAFE_PRIMES_TC *stc,
                                            ACVP_SAFE_PRIMES_PARAM dgm,
                                            const char *x,
                                            const char *y,
                                            ACVP_SAFE_PRIMES_TEST_TYPE test_type) {
    ACVP_RESULT rv;

    stc->tg_id = tg_id;
    stc->tc_id = tc_id;
    stc->dgm = dgm;
    stc->test_type = test_type;
    stc-> cipher = alg_id;

    if (alg_id == ACVP_SAFE_PRIMES_KEYVER) {
        stc->y = calloc(1, ACVP_SAFE_PRIMES_BYTE_MAX);
        if (!stc->y) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(y, stc->y, ACVP_SAFE_PRIMES_BYTE_MAX, &(stc->ylen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (y)");
            return rv;
        }
        stc->x = calloc(1, ACVP_SAFE_PRIMES_BYTE_MAX);
        if (!stc->x) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(x, stc->x, ACVP_SAFE_PRIMES_BYTE_MAX, &(stc->xlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (x)");
            return rv;
        }
    } else {
        stc->x = calloc(1, ACVP_SAFE_PRIMES_BYTE_MAX);
        if (!stc->x) { return ACVP_MALLOC_FAIL; }
        stc->y = calloc(1, ACVP_SAFE_PRIMES_BYTE_MAX);
        if (!stc->y) { return ACVP_MALLOC_FAIL; }
    }
    return ACVP_SUCCESS;
}



ACVP_RESULT acvp_safe_primes_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_garr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *groups;
    JSON_Array *tests, *r_tarr = NULL;
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    ACVP_CAPS_LIST *cap;
    ACVP_TEST_CASE tc;
    ACVP_SAFE_PRIMES_TC stc;
    ACVP_RESULT rv = ACVP_SUCCESS;
    const char *alg_str = NULL, *dgm_str = NULL, *test_type_str = NULL;
    char *json_result = NULL;
    ACVP_CIPHER alg_id;
    ACVP_SAFE_PRIMES_PARAM dgm;
    ACVP_SAFE_PRIMES_TEST_TYPE test_type;
    const char *mode_str = NULL, *x = NULL, *y = NULL;
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id, tg_id;
    ACVP_SUB_KAS alg;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("unable to parse mode' from JSON");
        return ACVP_MALFORMED_JSON;
    }


    alg_id = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id == 0) {
        ACVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return ACVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.safe_primes = &stc;
    memzero_s(&stc, sizeof(ACVP_SAFE_PRIMES_TC));

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
    json_object_set_string(r_vs, "mode", mode_str);

    groups = json_object_get_array(obj, "testGroups");
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
        tg_id = json_object_get_number(groupobj, "tgId");
        if (!tg_id) {
            ACVP_LOG_ERR("Missing tgid from server JSON groub obj");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        json_object_set_number(r_gobj, "tg_id", tg_id);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        dgm_str = json_object_get_string(groupobj, "safePrimeGroup");
        if (!dgm_str) {
            ACVP_LOG_ERR("Server JSON missing 'safePrimeGroup'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        dgm = acvp_convert_dgm_string(dgm_str);
        if (!dgm) {
            ACVP_LOG_ERR("safePrimeGroup invalid");
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        ACVP_LOG_VERBOSE("    Test group: %d", i);
        ACVP_LOG_VERBOSE("      test alg: %s", alg_str);
        ACVP_LOG_VERBOSE("      est mode: %s", mode_str);
        ACVP_LOG_VERBOSE("         group: %s", dgm_str);


        alg = acvp_get_kas_alg(alg_id);
        if (alg == 0) {
            ACVP_LOG_ERR("Invalid cipher value");
            rv = ACVP_INVALID_ARG;
            goto err;
        }
    
        switch (alg) {
        case ACVP_SUB_SAFE_PRIMES_KEYGEN:

            tests = json_object_get_array(groupobj, "tests");
            t_cnt = json_array_get_count(tests);

            for (j = 0; j < t_cnt; j++) {

                ACVP_LOG_VERBOSE("Found new SAFE-PRIMES test vector...");
                testval = json_array_get_value(tests, j);
                testobj = json_value_get_object(testval);
                tc_id = json_object_get_number(testobj, "tcId");
                if (!tc_id) {
                    ACVP_LOG_ERR("Server JSON missing 'tcId'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }

                test_type_str = json_object_get_string(groupobj, "testType");
                if (!test_type_str) {
                    ACVP_LOG_ERR("Server JSON missing 'testType'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }

                test_type = read_test_type(test_type_str);
                if (!test_type) {
                    ACVP_LOG_ERR("Server JSON invalid 'testType'");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
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
                rv = acvp_safe_primes_init_tc(ctx, tg_id, tc_id, alg_id, 
                                              &stc, dgm, x, y, test_type);
                if (rv != ACVP_SUCCESS) {
                    acvp_safe_primes_release_tc(&stc);
                    json_value_free(r_tval);
                    goto err;
                }

                /* Process the current KAT test vector... */
                if ((cap->crypto_handler)(&tc)) {
                    acvp_safe_primes_release_tc(&stc);
                    ACVP_LOG_ERR("crypto module failed the operation");
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }

                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_safe_primes_output_tc(ctx, &stc, r_tobj);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("JSON output failure in KAS-FFC module");
                    acvp_safe_primes_release_tc(&stc);
                    json_value_free(r_tval);
                    goto err;
                }

                /*
                 * Release all the memory associated with the test case
                 */
                acvp_safe_primes_release_tc(&stc);

                /* Append the test response value to array */
                json_array_append_value(r_tarr, r_tval);
            }
            break;
        
        case ACVP_SUB_SAFE_PRIMES_KEYVER:
            tests = json_object_get_array(groupobj, "tests");
            t_cnt = json_array_get_count(tests);

            for (j = 0; j < t_cnt; j++) {

                ACVP_LOG_VERBOSE("Found new SAFE-PRIMES test vector...");
                testval = json_array_get_value(tests, j);
                testobj = json_value_get_object(testval);
                tc_id = json_object_get_number(testobj, "tcId");
                if (!tc_id) {
                    ACVP_LOG_ERR("Server JSON missing 'tcId'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }


                test_type_str = json_object_get_string(groupobj, "testType");
                if (!test_type_str) {
                    ACVP_LOG_ERR("Server JSON missing 'testType'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }

                test_type = read_test_type(test_type_str);
                if (!test_type) {
                    ACVP_LOG_ERR("Server JSON invalid 'testType'");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
                /*
                 * Create a new test case in the response
                 */
                r_tval = json_value_init_object();
                r_tobj = json_value_get_object(r_tval);

                json_object_set_number(r_tobj, "tcId", tc_id);


                x = json_object_get_string(testobj, "x");
                if (!x) {
                    ACVP_LOG_ERR("Server JSON missing 'x'");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                y = json_object_get_string(testobj, "y");
                if (!y) {
                    ACVP_LOG_ERR("Server JSON missing 'y'");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                /*
                 * Setup the test case data that will be passed down to
                 * the crypto module.
                 */
                 rv = acvp_safe_primes_init_tc(ctx, tg_id, tc_id, alg_id, 
                                               &stc, dgm, x, y, test_type);
                if (rv != ACVP_SUCCESS) {
                    acvp_safe_primes_release_tc(&stc);
                    json_value_free(r_tval);
                    goto err;
                }

                /* Process the current KAT test vector... */
                if ((cap->crypto_handler)(&tc)) {
                    acvp_safe_primes_release_tc(&stc);
                    ACVP_LOG_ERR("crypto module failed the operation");
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }

                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_safe_primes_output_tc(ctx, &stc, r_tobj);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("JSON output failure in KAS-FFC module");
                    acvp_safe_primes_release_tc(&stc);
                    json_value_free(r_tval);
                    goto err;
                }

                /*
                 * Release all the memory associated with the test case
                 */
                acvp_safe_primes_release_tc(&stc);

                /* Append the test response value to array */
                json_array_append_value(r_tarr, r_tval);
            }
            break;
        case ACVP_SUB_KAS_ECC_CDH:
        case ACVP_SUB_KAS_ECC_COMP:
        case ACVP_SUB_KAS_ECC_NOCOMP:
        case ACVP_SUB_KAS_ECC_SSC:
        case ACVP_SUB_KAS_FFC_COMP:
        case ACVP_SUB_KAS_FFC_NOCOMP:
        case ACVP_SUB_KAS_FFC_SSC:
        case ACVP_SUB_KAS_IFC_SSC:
        case ACVP_SUB_KTS_IFC:
        case ACVP_SUB_KDA_HKDF:
        case ACVP_SUB_KDA_ONESTEP:
        default:
            break;
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
        json_value_free(r_gval);
        acvp_safe_primes_release_tc(&stc);
        json_value_free(r_vs_val);
    }
    return rv;
}
