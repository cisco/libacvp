/*****************************************************************************
* Copyright (c) 2018, Cisco Systems, Inc.
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

    memset(tmp, 0x0, ACVP_KAS_ECC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->piy, stc->piylen, tmp, ACVP_KAS_ECC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (piy)");
        goto end;
    }
    json_object_set_string(tc_rsp, "publicIutY", tmp);

    memset(tmp, 0x0, ACVP_KAS_ECC_STR_MAX);
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
        memset(tmp, 0x0, ACVP_KAS_ECC_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->chash, stc->chashlen, tmp, ACVP_KAS_ECC_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (Z)");
            goto end;
        }
        if (!memcmp(stc->z, stc->chash, stc->zlen)) {
            json_object_set_boolean(tc_rsp, "testPassed", 1);
        } else {
            json_object_set_boolean(tc_rsp, "testPassed", 0);
        }
        goto end;
    }

    memset(tmp, 0x0, ACVP_KAS_ECC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->pix, stc->pixlen, tmp, ACVP_KAS_ECC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (pix)");
        goto end;
    }
    json_object_set_string(tc_rsp, "ephemeralPublicIutX", tmp);

    memset(tmp, 0x0, ACVP_KAS_ECC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->piy, stc->piylen, tmp, ACVP_KAS_ECC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (piy)");
        goto end;
    }
    json_object_set_string(tc_rsp, "ephemeralPublicIutY", tmp);

    memset(tmp, 0x0, ACVP_KAS_ECC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->d, stc->dlen, tmp, ACVP_KAS_ECC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (d)");
        goto end;
    }
    json_object_set_string(tc_rsp, "ephemeralPrivateIut", tmp);

    memset(tmp, 0x0, ACVP_KAS_ECC_STR_MAX);
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
                                            unsigned int tc_id,
                                            ACVP_KAS_ECC_TEST_TYPE test_type,
                                            ACVP_KAS_ECC_MODE mode,
                                            ACVP_EC_CURVE curve,
                                            const char *psx,
                                            const char *psy) {
    ACVP_RESULT rv;

    stc->mode = mode;
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
                                             unsigned int tc_id,
                                             ACVP_KAS_ECC_TEST_TYPE test_type,
                                             ACVP_KAS_ECC_MODE mode,
                                             ACVP_EC_CURVE curve,
                                             ACVP_HASH_ALG hash,
                                             const char *psx,
                                             const char *psy,
                                             const char *d,
                                             const char *pix,
                                             const char *piy,
                                             const char *z) {
    ACVP_RESULT rv;

    stc->mode = mode;
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

    memset(stc, 0x0, sizeof(ACVP_KAS_ECC_TC));

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kas_ecc_cdh(ACVP_CTX *ctx,
                                    ACVP_CAPS_LIST *cap,
                                    ACVP_TEST_CASE *tc,
                                    ACVP_KAS_ECC_TC *stc,
                                    JSON_Object *obj,
                                    int mode,
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
            return ACVP_MALFORMED_JSON;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        curve_str = json_object_get_string(groupobj, "curve");
        if (!curve_str) {
            ACVP_LOG_ERR("Server JSON missing 'curve'");
            return ACVP_MISSING_ARG;
        }
        curve = acvp_lookup_ec_curve(stc->cipher, curve_str);
        if (!curve) {
            ACVP_LOG_ERR("Server JSON invalid 'curve'");
            return ACVP_INVALID_ARG;
        }

        test_type_str = json_object_get_string(groupobj, "testType");
        if (!test_type_str) {
            ACVP_LOG_ERR("Server JSON missing 'testType'");
            return ACVP_MISSING_ARG;
        }
        if (!strncmp(test_type_str, "AFT", 3)) {
            test_type = ACVP_KAS_ECC_TT_AFT;
        } else if (!strncmp(test_type_str, "VAL", 3)) {
            test_type = ACVP_KAS_ECC_TT_VAL;
        } else {
            ACVP_LOG_ERR("Server JSON invalid 'testType'");
            return ACVP_INVALID_ARG;
        }

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("          curve: %s", curve_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            const char *psx = NULL, *psy = NULL;

            ACVP_LOG_INFO("Found new KAS-ECC CDH test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            psx = json_object_get_string(testobj, "publicServerX");
            if (!psx) {
                ACVP_LOG_ERR("Server JSON missing 'publicServerX'");
                return ACVP_MISSING_ARG;
            }
            if (strnlen(psx, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                ACVP_LOG_ERR("publicServerX too long, max allowed=(%d)",
                             ACVP_KAS_ECC_STR_MAX);
                return ACVP_INVALID_ARG;
            }

            psy = json_object_get_string(testobj, "publicServerY");
            if (!psy) {
                ACVP_LOG_ERR("Server JSON missing 'publicServerY'");
                return ACVP_MISSING_ARG;
            }
            if (strnlen(psy, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                ACVP_LOG_ERR("publicServerY too long, max allowed=(%d)",
                             ACVP_KAS_ECC_STR_MAX);
                return ACVP_INVALID_ARG;
            }

            ACVP_LOG_INFO("            psx: %s", psx);
            ACVP_LOG_INFO("            psy: %s", psy);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             */
            rv = acvp_kas_ecc_init_cdh_tc(ctx, stc, tc_id, test_type, mode,
                                          curve, psx, psy);
            if (rv != ACVP_SUCCESS) {
                acvp_kas_ecc_release_tc(stc);
                return rv;
            }

            /* Process the current KAT test vector... */
            if ((cap->crypto_handler)(tc)) {
                acvp_kas_ecc_release_tc(stc);
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kas_ecc_output_cdh_tc(ctx, stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in KAS-ECC module");
                acvp_kas_ecc_release_tc(stc);
                return rv;
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
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kas_ecc_comp(ACVP_CTX *ctx,
                                     ACVP_CAPS_LIST *cap,
                                     ACVP_TEST_CASE *tc,
                                     ACVP_KAS_ECC_TC *stc,
                                     JSON_Object *obj,
                                     int mode,
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
            return ACVP_MALFORMED_JSON;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        curve_str = json_object_get_string(groupobj, "curve");
        if (!curve_str) {
            ACVP_LOG_ERR("Server JSON missing 'curve'");
            return ACVP_MISSING_ARG;
        }

        curve = acvp_lookup_ec_curve(stc->cipher, curve_str);
        if (!curve) {
            ACVP_LOG_ERR("Server JSON invalid 'curve'");
            return ACVP_INVALID_ARG;
        }

        hash_str = json_object_get_string(groupobj, "hashAlg");
        if (!hash_str) {
            ACVP_LOG_ERR("Server JSON missing 'hashAlg'");
            return ACVP_MISSING_ARG;
        }
        if (!strncmp(hash_str, "SHA2-224", strlen("SHA2-224"))) {
            hash = ACVP_SHA224;
        } else if (!strncmp(hash_str, "SHA2-256", strlen("SHA2-256"))) {
            hash = ACVP_SHA256;
        } else if (!strncmp(hash_str, "SHA2-384", strlen("SHA2-384"))) {
            hash = ACVP_SHA384;
        } else if (!strncmp(hash_str, "SHA2-512", strlen("SHA2-512"))) {
            hash = ACVP_SHA512;
        } else {
            ACVP_LOG_ERR("Server JSON invalid 'hashAlg'");
            return ACVP_INVALID_ARG;
        }

        test_type_str = json_object_get_string(groupobj, "testType");
        if (!test_type_str) {
            ACVP_LOG_ERR("Server JSON missing 'testType'");
            return ACVP_MISSING_ARG;
        }
        if (!strncmp(test_type_str, "AFT", 3)) {
            test_type = ACVP_KAS_ECC_TT_AFT;
        } else if (!strncmp(test_type_str, "VAL", 3)) {
            test_type = ACVP_KAS_ECC_TT_VAL;
        } else {
            ACVP_LOG_ERR("Server JSON invalid 'testType'");
            return ACVP_INVALID_ARG;
        }

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("      test type: %s", test_type_str);
        ACVP_LOG_INFO("          curve: %s", curve_str);
        ACVP_LOG_INFO("           hash: %s", hash_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            const char *psx = NULL, *psy = NULL, *pix = NULL,
                       *piy = NULL, *d = NULL, *z = NULL;

            ACVP_LOG_INFO("Found new KAS-ECC Component test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            psx = json_object_get_string(testobj, "ephemeralPublicServerX");
            if (!psx) {
                ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicServerX'");
                return ACVP_MISSING_ARG;
            }
            if (strnlen(psx, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                ACVP_LOG_ERR("ephemeralPublicServerX too long, max allowed=(%d)",
                             ACVP_KAS_ECC_STR_MAX);
                return ACVP_INVALID_ARG;
            }

            psy = json_object_get_string(testobj, "ephemeralPublicServerY");
            if (!psy) {
                ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicServerY'");
                return ACVP_MISSING_ARG;
            }
            if (strnlen(psy, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                ACVP_LOG_ERR("ephemeralPublicServerY too long, max allowed=(%d)",
                             ACVP_KAS_ECC_STR_MAX);
                return ACVP_INVALID_ARG;
            }

            ACVP_LOG_INFO("            psx: %s", psx);
            ACVP_LOG_INFO("            psy: %s", psy);

            if (test_type == ACVP_KAS_ECC_TT_VAL) {
                pix = json_object_get_string(testobj, "ephemeralPublicIutX");
                if (!pix) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicIutX'");
                    return ACVP_MISSING_ARG;
                }
                if (strnlen(pix, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPublicIutX too long, max allowed=(%d)",
                                 ACVP_KAS_ECC_STR_MAX);
                    return ACVP_INVALID_ARG;
                }

                piy = json_object_get_string(testobj, "ephemeralPublicIutY");
                if (!piy) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicIutY'");
                    return ACVP_MISSING_ARG;
                }
                if (strnlen(piy, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPublicIutY too long, max allowed=(%d)",
                                 ACVP_KAS_ECC_STR_MAX);
                    return ACVP_INVALID_ARG;
                }

                d = json_object_get_string(testobj, "ephemeralPrivateIut");
                if (!d) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPrivateIut'");
                    return ACVP_MISSING_ARG;
                }
                if (strnlen(d, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPrivateIut too long, max allowed=(%d)",
                                 ACVP_KAS_ECC_STR_MAX);
                    return ACVP_INVALID_ARG;
                }

                z = json_object_get_string(testobj, "hashZIut");
                if (!z) {
                    ACVP_LOG_ERR("Server JSON missing 'hashZIut'");
                    return ACVP_MISSING_ARG;
                }
                if (strnlen(z, ACVP_KAS_ECC_STR_MAX + 1) > ACVP_KAS_ECC_STR_MAX) {
                    ACVP_LOG_ERR("hashZIut too long, max allowed=(%d)",
                                 ACVP_KAS_ECC_STR_MAX);
                    return ACVP_INVALID_ARG;
                }

                ACVP_LOG_INFO("              d: %s", d);
                ACVP_LOG_INFO("            pix: %s", pix);
                ACVP_LOG_INFO("            piy: %s", piy);
                ACVP_LOG_INFO("              z: %s", z);
            }

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             */
            rv = acvp_kas_ecc_init_comp_tc(ctx, stc, tc_id, test_type, mode,
                                           curve, hash, psx, psy,
                                           d, pix, piy, z);
            if (rv != ACVP_SUCCESS) {
                acvp_kas_ecc_release_tc(stc);
                return rv;
            }

            /* Process the current KAT test vector... */
            if ((cap->crypto_handler)(tc)) {
                acvp_kas_ecc_release_tc(stc);
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kas_ecc_output_comp_tc(ctx, stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in KAS-ECC module");
                acvp_kas_ecc_release_tc(stc);
                return rv;
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
    return ACVP_SUCCESS;
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
    int mode = 0;
    char *json_result = NULL;
    const char *mode_str = NULL;

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
    memset(&stc, 0x0, sizeof(ACVP_KAS_ECC_TC));

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
        if (!strncmp(mode_str, "CDH-Component", 13)) {
            mode = ACVP_KAS_ECC_MODE_CDH;
            stc.cipher = ACVP_KAS_ECC_CDH;
        } else if (!strncmp(mode_str, "Component", 9)) {
            mode = ACVP_KAS_ECC_MODE_COMPONENT;
            stc.cipher = ACVP_KAS_ECC_COMP;
        } else {
            ACVP_LOG_ERR("Server JSON invalid 'mode'");
            return ACVP_INVALID_ARG;
        }
    }
    if (mode == 0) {
        mode = ACVP_KAS_ECC_MODE_NOCOMP;
        stc.cipher = ACVP_KAS_ECC_NOCOMP;
    }

    switch (mode) {
    case ACVP_KAS_ECC_MODE_CDH:
        cap = acvp_locate_cap_entry(ctx, ACVP_KAS_ECC_CDH);
        if (!cap) {
            ACVP_LOG_ERR("ACVP server requesting unsupported capability");
            return ACVP_UNSUPPORTED_OP;
        }
        rv = acvp_kas_ecc_cdh(ctx, cap, &tc, &stc, obj, mode, r_garr);
        if (rv != ACVP_SUCCESS) return rv;

        break;
    case ACVP_KAS_ECC_MODE_COMPONENT:
        cap = acvp_locate_cap_entry(ctx, ACVP_KAS_ECC_COMP);
        if (!cap) {
            ACVP_LOG_ERR("ACVP server requesting unsupported capability");
            return ACVP_UNSUPPORTED_OP;
        }
        rv = acvp_kas_ecc_comp(ctx, cap, &tc, &stc, obj, mode, r_garr);
        if (rv != ACVP_SUCCESS) return rv;

        break;
    case ACVP_KAS_ECC_MODE_NOCOMP:
    default:
        ACVP_LOG_ERR("ACVP server requesting unsupported KAS-ECC mode");
        return ACVP_UNSUPPORTED_OP;

        break;
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
