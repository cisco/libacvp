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

#include <openssl/evp.h>

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
static ACVP_RESULT acvp_kas_ecc_output_cdh_tc(ACVP_CTX *ctx,
                                              ACVP_KAS_ECC_TC *stc,
                                              JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_KAS_ECC_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_output_mct_tc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(stc->pix, stc->pixlen, tmp, ACVP_KAS_ECC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (pix)");
        goto end;
    }
    json_object_set_string(tc_rsp, "publicIutX", tmp);

    memzero_s(tmp, ACVP_KAS_ECC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->piy, stc->piylen, tmp, ACVP_KAS_ECC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (piy)");
        goto end;
    }
    json_object_set_string(tc_rsp, "publicIutY", tmp);

    memzero_s(tmp, ACVP_KAS_ECC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->z, stc->zlen, tmp, ACVP_KAS_ECC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (Z)");
        goto end;
    }
    json_object_set_string(tc_rsp, "z", tmp);

end:
    if (tmp) free(tmp);

    return rv;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_kas_ecc_output_comp_tc(ACVP_CTX *ctx,
                                               ACVP_KAS_ECC_TC *stc,
                                               JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(1, ACVP_KAS_ECC_STR_MAX + 1);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_output_mct_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->test_type == ACVP_KAS_ECC_TT_VAL) {
        int diff = 1;

        memzero_s(tmp, ACVP_KAS_ECC_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->chash, stc->chashlen, tmp, ACVP_KAS_ECC_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (Z)");
            goto end;
        }
        memcmp_s(stc->chash, ACVP_KAS_ECC_BYTE_MAX, stc->z, stc->zlen, &diff);
        if (!diff) {
            json_object_set_boolean(tc_rsp, "testPassed", 1);
        } else {
            json_object_set_boolean(tc_rsp, "testPassed", 0);
        }
        goto end;
    }

    memzero_s(tmp, ACVP_KAS_ECC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->pix, stc->pixlen, tmp, ACVP_KAS_ECC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (pix)");
        goto end;
    }
    json_object_set_string(tc_rsp, "ephemeralPublicIutX", tmp);

    memzero_s(tmp, ACVP_KAS_ECC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->piy, stc->piylen, tmp, ACVP_KAS_ECC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (piy)");
        goto end;
    }
    json_object_set_string(tc_rsp, "ephemeralPublicIutY", tmp);

    memzero_s(tmp, ACVP_KAS_ECC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->d, stc->dlen, tmp, ACVP_KAS_ECC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (d)");
        goto end;
    }
    json_object_set_string(tc_rsp, "ephemeralPrivateIut", tmp);

    memzero_s(tmp, ACVP_KAS_ECC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->chash, stc->chashlen, tmp, ACVP_KAS_ECC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (Z)");
        goto end;
    }
    json_object_set_string(tc_rsp, "hashZIut", tmp);

end:
    if (tmp) free(tmp);

    return rv;
}

static ACVP_RESULT acvp_kas_ecc_init_cdh_tc(ACVP_CTX *ctx,
                                            ACVP_KAS_ECC_TC *stc,
                                            ACVP_KAS_ECC_TEST_TYPE test_type,
                                            ACVP_EC_CURVE curve,
                                            const char *psx,
                                            const char *psy) {
    ACVP_RESULT rv;

    stc->mode = ACVP_KAS_ECC_MODE_CDH;
    stc->curve = curve;
    stc->test_type = test_type;

    stc->psx = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->psx) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(psx, stc->psx, ACVP_KAS_ECC_BYTE_MAX, &(stc->psxlen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (psx)");
        return rv;
    }

    stc->psy = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->psy) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(psy, stc->psy, ACVP_KAS_ECC_BYTE_MAX, &(stc->psylen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (psy)");
        return rv;
    }

    stc->pix = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->pix) { return ACVP_MALLOC_FAIL; }
    stc->piy = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->piy) { return ACVP_MALLOC_FAIL; }

    stc->z = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->z) { return ACVP_MALLOC_FAIL; }
    stc->d = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->d) { return ACVP_MALLOC_FAIL; }
    stc->chash = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->chash) { return ACVP_MALLOC_FAIL; }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kas_ecc_init_comp_tc(ACVP_CTX *ctx,
                                             ACVP_KAS_ECC_TC *stc,
                                             ACVP_KAS_ECC_TEST_TYPE test_type,
                                             ACVP_EC_CURVE curve,
                                             ACVP_HASH_ALG hash,
                                             const char *psx,
                                             const char *psy,
                                             const char *d,
                                             const char *pix,
                                             const char *piy,
                                             const char *z) {
    ACVP_RESULT rv;

    stc->mode = ACVP_KAS_ECC_MODE_COMPONENT;
    stc->curve = curve;
    stc->md = hash;
    stc->test_type = test_type;

    stc->psx = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->psx) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(psx, stc->psx, ACVP_KAS_ECC_BYTE_MAX, &(stc->psxlen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (psx)");
        return rv;
    }

    stc->psy = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->psy) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(psy, stc->psy, ACVP_KAS_ECC_BYTE_MAX, &(stc->psylen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (psy)");
        return rv;
    }

    stc->pix = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->pix) { return ACVP_MALLOC_FAIL; }
    stc->piy = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->piy) { return ACVP_MALLOC_FAIL; }
    stc->d = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->d) { return ACVP_MALLOC_FAIL; }
    stc->z = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->z) { return ACVP_MALLOC_FAIL; }
    stc->chash = calloc(1, ACVP_KAS_ECC_BYTE_MAX);
    if (!stc->chash) { return ACVP_MALLOC_FAIL; }

    if (stc->test_type == ACVP_KAS_ECC_TT_VAL) {
        if (!pix || !piy || !d || !z) {
            return ACVP_MISSING_ARG;
        }

        rv = acvp_hexstr_to_bin(pix, stc->pix, ACVP_KAS_ECC_BYTE_MAX, &(stc->pixlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (pix)");
            return rv;
        }

        rv = acvp_hexstr_to_bin(piy, stc->piy, ACVP_KAS_ECC_BYTE_MAX, &(stc->piylen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (piy)");
            return rv;
        }

        rv = acvp_hexstr_to_bin(d, stc->d, ACVP_KAS_ECC_BYTE_MAX, &(stc->dlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (d)");
            return rv;
        }

        rv = acvp_hexstr_to_bin(z, stc->z, ACVP_KAS_ECC_BYTE_MAX, &(stc->zlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (z)");
            return rv;
        }
    }

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kas_ecc_release_tc(ACVP_KAS_ECC_TC *stc) {
    if (stc->chash) free(stc->chash);
    if (stc->psx) free(stc->psx);
    if (stc->psy) free(stc->psy);
    if (stc->pix) free(stc->pix);
    if (stc->piy) free(stc->piy);
    if (stc->d) free(stc->d);
    if (stc->z) free(stc->z);

    memzero_s(stc, sizeof(ACVP_KAS_ECC_TC));

    return ACVP_SUCCESS;
}

static ACVP_KAS_ECC_TEST_TYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return ACVP_KAS_ECC_TT_AFT;

    strcmp_s("VAL", 3, str, &diff);
    if (!diff) return ACVP_KAS_ECC_TT_VAL;

    return 0;
}

static ACVP_RESULT acvp_kas_ecc_cdh(ACVP_CTX *ctx,
                                    ACVP_CAPS_LIST *cap,
                                    ACVP_TEST_CASE *tc,
                                    ACVP_KAS_ECC_TC *stc,
                                    JSON_Object *obj,
                                    JSON_Array *r_garr) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Array *groups;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *tests, *r_tarr = NULL;
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id;
    ACVP_RESULT rv;

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);

    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        ACVP_KAS_ECC_TEST_TYPE test_type = 0;
        ACVP_EC_CURVE curve = 0;
        const char *test_type_str = NULL, *curve_str = NULL;

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

        curve_str = json_object_get_string(groupobj, "curve");
        if (!curve_str) {
            ACVP_LOG_ERR("Server JSON missing 'curve'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        curve = acvp_lookup_ec_curve(stc->cipher, curve_str);
        if (!curve) {
            ACVP_LOG_ERR("Server JSON invalid 'curve'");
            rv = ACVP_INVALID_ARG;
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

        ACVP_LOG_VERBOSE("    Test group: %d", i+1);
        ACVP_LOG_VERBOSE("          curve: %s", curve_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            const char *psx = NULL, *psy = NULL;

            ACVP_LOG_VERBOSE("Found new KAS-ECC CDH test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            psx = json_object_get_string(testobj, "publicServerX");
            if (!psx) {
                ACVP_LOG_ERR("Server JSON missing 'publicServerX'");
                rv = ACVP_MISSING_ARG;
                json_value_free(r_tval);
                goto err;
            }
            if (strnlen_s(psx, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                ACVP_LOG_ERR("publicServerX too long, max allowed=(%d)",
                             ACVP_KAS_ECC_STR_MAX);
                rv = ACVP_INVALID_ARG;
                json_value_free(r_tval);
                goto err;
            }

            psy = json_object_get_string(testobj, "publicServerY");
            if (!psy) {
                ACVP_LOG_ERR("Server JSON missing 'publicServerY'");
                rv = ACVP_MISSING_ARG;
                json_value_free(r_tval);
                goto err;
            }
            if (strnlen_s(psy, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                ACVP_LOG_ERR("publicServerY too long, max allowed=(%d)",
                             ACVP_KAS_ECC_STR_MAX);
                rv = ACVP_INVALID_ARG;
                json_value_free(r_tval);
                goto err;
            }

            ACVP_LOG_VERBOSE("            psx: %s", psx);
            ACVP_LOG_VERBOSE("            psy: %s", psy);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             */
            rv = acvp_kas_ecc_init_cdh_tc(ctx, stc, test_type,
                                          curve, psx, psy);
            if (rv != ACVP_SUCCESS) {
                acvp_kas_ecc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current KAT test vector... */
            if ((cap->crypto_handler)(tc)) {
                acvp_kas_ecc_release_tc(stc);
                ACVP_LOG_ERR("crypto module failed the operation");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kas_ecc_output_cdh_tc(ctx, stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in KAS-ECC module");
                acvp_kas_ecc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_kas_ecc_release_tc(stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
    }
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        json_value_free(r_gval);
    }
    return rv;
}

static ACVP_RESULT acvp_kas_ecc_comp(ACVP_CTX *ctx,
                                     ACVP_CAPS_LIST *cap,
                                     ACVP_TEST_CASE *tc,
                                     ACVP_KAS_ECC_TC *stc,
                                     JSON_Object *obj,
                                     JSON_Array *r_garr) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Array *groups;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *tests, *r_tarr = NULL;
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id;
    ACVP_RESULT rv;

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);

    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        ACVP_KAS_ECC_TEST_TYPE test_type = 0;
        ACVP_HASH_ALG hash = 0;
        ACVP_EC_CURVE curve = 0;
        const char *test_type_str = NULL, *curve_str = NULL, *hash_str = NULL;

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

        curve_str = json_object_get_string(groupobj, "curve");
        if (!curve_str) {
            ACVP_LOG_ERR("Server JSON missing 'curve'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        curve = acvp_lookup_ec_curve(stc->cipher, curve_str);
        if (!curve) {
            ACVP_LOG_ERR("Server JSON invalid 'curve'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        hash_str = json_object_get_string(groupobj, "hashAlg");
        if (!hash_str) {
            ACVP_LOG_ERR("Server JSON missing 'hashAlg'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        hash = acvp_lookup_hash_alg(hash_str);
        if (!(hash == ACVP_SHA224 || hash == ACVP_SHA256 ||
              hash == ACVP_SHA384 || hash == ACVP_SHA512)) {
            ACVP_LOG_ERR("Server JSON invalid 'hashAlg'");
            rv = ACVP_INVALID_ARG;
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

        ACVP_LOG_VERBOSE("    Test group: %d", i+1);
        ACVP_LOG_VERBOSE("      test type: %s", test_type_str);
        ACVP_LOG_VERBOSE("          curve: %s", curve_str);
        ACVP_LOG_VERBOSE("           hash: %s", hash_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            const char *psx = NULL, *psy = NULL, *pix = NULL,
                       *piy = NULL, *d = NULL, *z = NULL;

            ACVP_LOG_VERBOSE("Found new KAS-ECC Component test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            psx = json_object_get_string(testobj, "ephemeralPublicServerX");
            if (!psx) {
                ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicServerX'");
                rv = ACVP_MISSING_ARG;
                json_value_free(r_tval);
                goto err;
            }
            if (strnlen_s(psx, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                ACVP_LOG_ERR("ephemeralPublicServerX too long, max allowed=(%d)",
                             ACVP_KAS_ECC_STR_MAX);
                rv = ACVP_INVALID_ARG;
                json_value_free(r_tval);
                goto err;
            }

            psy = json_object_get_string(testobj, "ephemeralPublicServerY");
            if (!psy) {
                ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicServerY'");
                rv = ACVP_MISSING_ARG;
                json_value_free(r_tval);
                goto err;
            }
            if (strnlen_s(psy, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                ACVP_LOG_ERR("ephemeralPublicServerY too long, max allowed=(%d)",
                             ACVP_KAS_ECC_STR_MAX);
                rv = ACVP_INVALID_ARG;
                json_value_free(r_tval);
                goto err;
            }

            ACVP_LOG_VERBOSE("            psx: %s", psx);
            ACVP_LOG_VERBOSE("            psy: %s", psy);

            if (test_type == ACVP_KAS_ECC_TT_VAL) {
                pix = json_object_get_string(testobj, "ephemeralPublicIutX");
                if (!pix) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicIutX'");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                if (strnlen_s(pix, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPublicIutX too long, max allowed=(%d)",
                                 ACVP_KAS_ECC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                piy = json_object_get_string(testobj, "ephemeralPublicIutY");
                if (!piy) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicIutY'");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                if (strnlen_s(piy, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPublicIutY too long, max allowed=(%d)",
                                 ACVP_KAS_ECC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                d = json_object_get_string(testobj, "ephemeralPrivateIut");
                if (!d) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPrivateIut'");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                if (strnlen_s(d, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPrivateIut too long, max allowed=(%d)",
                                 ACVP_KAS_ECC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                z = json_object_get_string(testobj, "hashZIut");
                if (!z) {
                    ACVP_LOG_ERR("Server JSON missing 'hashZIut'");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                if (strnlen_s(z, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                    ACVP_LOG_ERR("hashZIut too long, max allowed=(%d)",
                                 ACVP_KAS_ECC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                ACVP_LOG_VERBOSE("              d: %s", d);
                ACVP_LOG_VERBOSE("            pix: %s", pix);
                ACVP_LOG_VERBOSE("            piy: %s", piy);
                ACVP_LOG_VERBOSE("              z: %s", z);
            }

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             */
            rv = acvp_kas_ecc_init_comp_tc(ctx, stc, test_type,
                                           curve, hash, psx, psy,
                                           d, pix, piy, z);
            if (rv != ACVP_SUCCESS) {
                acvp_kas_ecc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current KAT test vector... */
            if ((cap->crypto_handler)(tc)) {
                acvp_kas_ecc_release_tc(stc);
                ACVP_LOG_ERR("crypto module failed the operation");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kas_ecc_output_comp_tc(ctx, stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in KAS-ECC module");
                acvp_kas_ecc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_kas_ecc_release_tc(stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
    }
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        json_value_free(r_gval);
    }
    return rv;
}

ACVP_RESULT acvp_kas_ecc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_garr = NULL; /* Response testarray, grouparray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    ACVP_CAPS_LIST *cap;
    ACVP_TEST_CASE tc;
    ACVP_KAS_ECC_TC stc;
    ACVP_RESULT rv = ACVP_SUCCESS;
    const char *alg_str = NULL;
    char *json_result = NULL;
    const char *mode_str = NULL;
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

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kas_ecc = &stc;
    memzero_s(&stc, sizeof(ACVP_KAS_ECC_TC));

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

    mode_str = json_object_get_string(obj, "mode");
    json_object_set_string(r_vs, "mode", mode_str);

    if (mode_str) {
        stc.cipher = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
        if (stc.cipher != ACVP_KAS_ECC_CDH &&
            stc.cipher != ACVP_KAS_ECC_COMP) {
            ACVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }
    } else {
        stc.cipher = ACVP_KAS_ECC_NOCOMP;
    }

    alg = acvp_get_kas_alg(stc.cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    
    switch (alg) {
    case ACVP_SUB_KAS_ECC_CDH:
        cap = acvp_locate_cap_entry(ctx, ACVP_KAS_ECC_CDH);
        if (!cap) {
            ACVP_LOG_ERR("ACVP server requesting unsupported capability");
            rv = ACVP_UNSUPPORTED_OP;
            goto err;
        }
        rv = acvp_kas_ecc_cdh(ctx, cap, &tc, &stc, obj, r_garr);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        break;
    case ACVP_SUB_KAS_ECC_COMP:
        cap = acvp_locate_cap_entry(ctx, ACVP_KAS_ECC_COMP);
        if (!cap) {
            ACVP_LOG_ERR("ACVP server requesting unsupported capability");
            rv = ACVP_UNSUPPORTED_OP;
            goto err;
        }
        rv = acvp_kas_ecc_comp(ctx, cap, &tc, &stc, obj, r_garr);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        break;
    case ACVP_SUB_KAS_ECC_NOCOMP:
    case ACVP_SUB_KAS_ECC_SSC:
    case ACVP_SUB_KAS_FFC_COMP:
    case ACVP_SUB_KAS_FFC_NOCOMP:
    case ACVP_SUB_KAS_FFC_SSC:
    case ACVP_SUB_KAS_IFC_SSC:
    case ACVP_SUB_KTS_IFC:
    case ACVP_SUB_KDA_ONESTEP:
    case ACVP_SUB_KDA_TWOSTEP:
    case ACVP_SUB_KDA_HKDF:
    case ACVP_SUB_SAFE_PRIMES_KEYGEN:
    case ACVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        ACVP_LOG_ERR("ACVP server requesting unsupported KAS-ECC mode");
        rv = ACVP_UNSUPPORTED_OP;
        goto err;
        break;
    }
    json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    ACVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        acvp_kas_ecc_release_tc(&stc);
        json_value_free(r_vs_val);
    }
    return rv;
}


/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_kas_ecc_output_ssc_tc(ACVP_CTX *ctx,
                                              ACVP_KAS_ECC_TC *stc,
                                              JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(1, ACVP_KAS_ECC_STR_MAX + 1);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_output_mct_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->test_type == ACVP_KAS_ECC_TT_VAL) {
        int diff = 1;

        memzero_s(tmp, ACVP_KAS_ECC_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->chash, stc->chashlen, tmp, ACVP_KAS_ECC_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (Z)");
            goto end;
        }
        if (stc->md == ACVP_NO_SHA) {
            memcmp_s(stc->chash, ACVP_KAS_ECC_BYTE_MAX, stc->z, stc->zlen, &diff);
        } else {
            unsigned char md[EVP_MAX_MD_SIZE] = {0};
            
            rv = acvp_digest(stc->md, stc->chash, stc->chashlen, md, sizeof(md), NULL);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("digest failure (Z)");
                goto end;
            }

            memcmp_s(md, sizeof(md), stc->z, stc->zlen, &diff);
        }
        if (!diff) {
            json_object_set_boolean(tc_rsp, "testPassed", 1);
        } else {
            json_object_set_boolean(tc_rsp, "testPassed", 0);
        }
        goto end;
    } else {
        memzero_s(tmp, ACVP_KAS_ECC_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->pix, stc->pixlen, tmp, ACVP_KAS_ECC_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (pix)");
            goto end;
        }
        json_object_set_string(tc_rsp, "ephemeralPublicIutX", tmp);

        memzero_s(tmp, ACVP_KAS_ECC_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->piy, stc->piylen, tmp, ACVP_KAS_ECC_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (piy)");
            goto end;
        }
        json_object_set_string(tc_rsp, "ephemeralPublicIutY", tmp);

        memzero_s(tmp, ACVP_KAS_ECC_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->d, stc->dlen, tmp, ACVP_KAS_ECC_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (d)");
            goto end;
        }
        json_object_set_string(tc_rsp, "ephemeralPrivateIut", tmp);

        memzero_s(tmp, ACVP_KAS_ECC_STR_MAX);
        if (stc->md == ACVP_NO_SHA) {
            rv = acvp_bin_to_hexstr(stc->chash, stc->chashlen, tmp, ACVP_KAS_ECC_STR_MAX);
        } else {
            rv = acvp_bin_to_hashstr(stc->md, stc->chash, stc->chashlen, tmp, ACVP_KAS_ECC_STR_MAX);
        }
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (Z)");
            goto end;
        }
        if (stc->md == ACVP_NO_SHA) {
            json_object_set_string(tc_rsp, "Z", tmp);
        } else {
            json_object_set_string(tc_rsp, "hashZ", tmp);
        }
    }
end:
    if (tmp) free(tmp);

    return rv;
}

static ACVP_RESULT acvp_kas_ecc_ssc(ACVP_CTX *ctx,
                                    ACVP_CAPS_LIST *cap,
                                    ACVP_TEST_CASE *tc,
                                    ACVP_KAS_ECC_TC *stc,
                                    JSON_Object *obj,
                                    JSON_Array *r_garr) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Array *groups;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    ACVP_KAS_ECC_CAP_MODE *kas_ecc_mode = NULL;
    JSON_Array *tests, *r_tarr = NULL;
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id;
    ACVP_RESULT rv;

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);

    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        ACVP_KAS_ECC_TEST_TYPE test_type = 0;
        ACVP_HASH_ALG hash = 0;
        ACVP_EC_CURVE curve = 0;
        const char *test_type_str = NULL, *curve_str = NULL, *hash_str = NULL;

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

        curve_str = json_object_get_string(groupobj, "domainParameterGenerationMode");
        if (!curve_str) {
            ACVP_LOG_ERR("Server JSON missing 'domainParameterGenerationMode'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        curve = acvp_lookup_ec_curve(stc->cipher, curve_str);
        if (!curve) {
            ACVP_LOG_ERR("Server JSON invalid 'curve'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        //If the user doesn't specify a hash function, neither does the server
        if (cap && cap->cap.kas_ecc_cap) {
            kas_ecc_mode = &cap->cap.kas_ecc_cap->kas_ecc_mode[ACVP_KAS_ECC_MODE_NONE - 1];
            if (kas_ecc_mode && kas_ecc_mode->hash != ACVP_NO_SHA) {
                hash_str = json_object_get_string(groupobj, "hashFunctionZ");
                if (!hash_str) {
                    ACVP_LOG_ERR("Server JSON missing 'hashFunctionZ'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                hash = acvp_lookup_hash_alg(hash_str);
                switch (hash) {
                case ACVP_SHA224:
                case ACVP_SHA256:
                case ACVP_SHA384:
                case ACVP_SHA512:
                case ACVP_SHA512_224:
                case ACVP_SHA512_256:
                case ACVP_SHA3_224:
                case ACVP_SHA3_256:
                case ACVP_SHA3_384:
                case ACVP_SHA3_512:
                    break;
                case ACVP_SHA1:
                case ACVP_NO_SHA:
                case ACVP_HASH_ALG_MAX:
                default:
                    ACVP_LOG_ERR("Server JSON invalid 'hashAlg'");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }
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

        ACVP_LOG_VERBOSE("    Test group: %d", i+1);
        ACVP_LOG_VERBOSE("      test type: %s", test_type_str);
        ACVP_LOG_VERBOSE("          curve: %s", curve_str);
        ACVP_LOG_VERBOSE("           hash: %s", hash_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            const char *psx = NULL, *psy = NULL, *pix = NULL,
                       *piy = NULL, *d = NULL, *z = NULL;

            ACVP_LOG_VERBOSE("Found new KAS-ECC-SSC Component test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            psx = json_object_get_string(testobj, "ephemeralPublicServerX");
            if (!psx) {
                ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicServerX'");
                rv = ACVP_MISSING_ARG;
                json_value_free(r_tval);
                goto err;
            }
            if (strnlen_s(psx, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                ACVP_LOG_ERR("ephemeralPublicServerX too long, max allowed=(%d)",
                             ACVP_KAS_ECC_STR_MAX);
                rv = ACVP_INVALID_ARG;
                json_value_free(r_tval);
                goto err;
            }

            psy = json_object_get_string(testobj, "ephemeralPublicServerY");
            if (!psy) {
                ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicServerY'");
                rv = ACVP_MISSING_ARG;
                json_value_free(r_tval);
                goto err;
            }
            if (strnlen_s(psy, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                ACVP_LOG_ERR("ephemeralPublicServerY too long, max allowed=(%d)",
                             ACVP_KAS_ECC_STR_MAX);
                rv = ACVP_INVALID_ARG;
                json_value_free(r_tval);
                goto err;
            }

            ACVP_LOG_VERBOSE("            psx: %s", psx);
            ACVP_LOG_VERBOSE("            psy: %s", psy);

            if (test_type == ACVP_KAS_ECC_TT_VAL) {
                pix = json_object_get_string(testobj, "ephemeralPublicIutX");
                if (!pix) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicIutX'");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                if (strnlen_s(pix, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPublicIutX too long, max allowed=(%d)",
                                 ACVP_KAS_ECC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                piy = json_object_get_string(testobj, "ephemeralPublicIutY");
                if (!piy) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicIutY'");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                if (strnlen_s(piy, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPublicIutY too long, max allowed=(%d)",
                                 ACVP_KAS_ECC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                d = json_object_get_string(testobj, "ephemeralPrivateIut");
                if (!d) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPrivateIut'");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                if (strnlen_s(d, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPrivateIut too long, max allowed=(%d)",
                                 ACVP_KAS_ECC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                z = json_object_get_string(testobj, "hashZ");
                if (!z) {
                    //Assume user did not specify hash function if we don't have capability info for some reason
                    if (!kas_ecc_mode || kas_ecc_mode->hash == ACVP_NO_SHA) {
                        z = json_object_get_string(testobj, "z");
                        if (!z) {
                            ACVP_LOG_ERR("Server JSON missing 'z'");
                            rv = ACVP_MISSING_ARG;
                            json_value_free(r_tval);
                            goto err;
                        }
                    } else {
                        ACVP_LOG_ERR("Server JSON missing 'hashZ'");
                        rv = ACVP_MISSING_ARG;
                        json_value_free(r_tval);
                        goto err;
                    }
                }

                if (strnlen_s(z, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                    ACVP_LOG_ERR("hashZ or z too long, max allowed=(%d)",
                                 ACVP_KAS_ECC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                ACVP_LOG_VERBOSE("              d: %s", d);
                ACVP_LOG_VERBOSE("            pix: %s", pix);
                ACVP_LOG_VERBOSE("            piy: %s", piy);
                ACVP_LOG_VERBOSE("              z: %s", z);
            }

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             */
            /* 
             * we can use the comp init since the only difference between
             * ECC_SSC and comp is the keywords used - why NIST did that ???
             */
            rv = acvp_kas_ecc_init_comp_tc(ctx, stc, test_type,
                                           curve, hash, psx, psy,
                                           d, pix, piy, z);
            if (rv != ACVP_SUCCESS) {
                acvp_kas_ecc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current KAT test vector... */
            if ((cap->crypto_handler)(tc)) {
                acvp_kas_ecc_release_tc(stc);
                ACVP_LOG_ERR("crypto module failed the operation");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kas_ecc_output_ssc_tc(ctx, stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in KAS-ECC module");
                acvp_kas_ecc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_kas_ecc_release_tc(stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
    }
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        json_value_free(r_gval);
    }
    return rv;
}

ACVP_RESULT acvp_kas_ecc_ssc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_garr = NULL; /* Response testarray, grouparray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    ACVP_CAPS_LIST *cap;
    ACVP_TEST_CASE tc;
    ACVP_KAS_ECC_TC stc;
    ACVP_RESULT rv = ACVP_SUCCESS;
    const char *alg_str = NULL;
    char *json_result = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kas_ecc = &stc;
    memzero_s(&stc, sizeof(ACVP_KAS_ECC_TC));

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

    cap = acvp_locate_cap_entry(ctx, ACVP_KAS_ECC_SSC);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        rv = ACVP_UNSUPPORTED_OP;
        goto err;
    }
    rv = acvp_kas_ecc_ssc(ctx, cap, &tc, &stc, obj, r_garr);
    if (rv != ACVP_SUCCESS) {
        goto err;
    }
    json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    ACVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        acvp_kas_ecc_release_tc(&stc);
        json_value_free(r_vs_val);
    }
    return rv;
}
