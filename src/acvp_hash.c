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

#define ACVP_HOST_LITTLE_ENDIAN (__BYTE_ORDER == __LITTLE_ENDIAN)
#define SWAP_16(x) ((x>>8) | (x<<8))

/*
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_hash_output_tc(ACVP_CTX *ctx, ACVP_HASH_TC *stc, JSON_Object *tc_rsp);

static ACVP_RESULT acvp_hash_init_tc(ACVP_CTX *ctx,
                                     ACVP_HASH_TC *stc,
                                     unsigned int tc_id,
                                     ACVP_HASH_TESTTYPE test_type,
                                     ACVP_HASH_MCT_VERSION mct_version,
                                     unsigned int min_xof_len,
                                     unsigned int max_xof_len,
                                     unsigned int msg_len,
                                     const char *msg,
                                     unsigned int xof_len,
                                     unsigned long long int exp_len,  // LDT expected data length
                                     ACVP_HASH_EXPANSION_METHOD exp_method,
                                     ACVP_CIPHER alg_id);

static ACVP_RESULT acvp_hash_release_tc(ACVP_HASH_TC *stc);

static ACVP_HASH_TESTTYPE read_test_type(const char *tt_str) {
    int diff = 0;

    strcmp_s("MCT", 3, tt_str, &diff);
    if (!diff) {
        return ACVP_HASH_TEST_TYPE_MCT;
    }

    strcmp_s("AFT", 3, tt_str, &diff);
    if (!diff) {
        return ACVP_HASH_TEST_TYPE_AFT;
    }

    strcmp_s("VOT", 3, tt_str, &diff);
    if (!diff) {
        return ACVP_HASH_TEST_TYPE_VOT;
    }

    strcmp_s("LDT", 3, tt_str, &diff);
    if (!diff) {
        return ACVP_HASH_TEST_TYPE_LDT;
    }

    return 0;
}

static ACVP_HASH_EXPANSION_METHOD read_exp_method(const char *exp_str) {
    int diff = 0;

    strcmp_s("repeating", 9, exp_str, &diff);
    if (!diff) {
        return ACVP_HASH_EXPANSION_REPEATING;
    }

    return 0;
}

static ACVP_HASH_MCT_VERSION read_mct_version(const char *mct_str) {
    int diff = 0;

    strcmp_s(ACVP_STR_HASH_MCT_STANDARD, sizeof(ACVP_STR_HASH_MCT_STANDARD) - 1, mct_str, &diff);
    if (!diff) return ACVP_HASH_MCT_VERSION_STANDARD;
    strcmp_s(ACVP_STR_HASH_MCT_ALTERNATE, sizeof(ACVP_STR_HASH_MCT_ALTERNATE) - 1, mct_str, &diff);
    if (!diff) return ACVP_HASH_MCT_VERSION_ALTERNATE;

    return -1;
}

ACVP_RESULT acvp_hash_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    unsigned int tc_id, msglen;
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *groups;
    JSON_Array *tests;
    JSON_Object *ldtobj = NULL;  // Inner object for LDTs

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
    ACVP_HASH_TC stc;
    ACVP_TEST_CASE tc;
    JSON_Array *res_tarr = NULL; /* Response resultsArray */
    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_CIPHER alg_id = 0;
    ACVP_HASH_EXPANSION_METHOD exp_method = 0;
    ACVP_HASH_MCT_VERSION mct_version = 0;
    ACVP_HASH_TESTTYPE test_type = 0;

    int tgId = 0;
    unsigned int min_xof_len = 0, max_xof_len = 0;
    unsigned long long int exp_len = 0LL;
    char *json_result = NULL;
    const char *alg_str = NULL;
    const char *test_type_str, *msg = NULL;
    const char *exp_method_str = NULL, *mct_version_str = NULL;

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
    tc.tc.hash = &stc;

    /*
     * Get the crypto module handler for this hash algorithm
     */
    alg_id = acvp_lookup_cipher_index(alg_str);
    if (alg_id == 0) {
        ACVP_LOG_ERR("unsupported algorithm (%s)", alg_str);
        return ACVP_UNSUPPORTED_OP;
    }
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
        tgId = json_object_get_number(groupobj, "tgId");
        if (!tgId) {
            ACVP_LOG_ERR("Missing tgid from server JSON groub obj");
            rv = ACVP_MALFORMED_JSON;
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        ACVP_LOG_VERBOSE("    Test group: %d", i);

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
        if (test_type == ACVP_HASH_TEST_TYPE_VOT &&
            !(alg_id == ACVP_HASH_SHAKE_128 || alg_id == ACVP_HASH_SHAKE_256)) {
            ACVP_LOG_ERR("Server JSON 'testType' == VOT, not valid for cipher '%s'",
                         acvp_lookup_cipher_name(alg_id));
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        if (test_type == ACVP_HASH_TEST_TYPE_MCT) {
            mct_version_str = json_object_get_string(groupobj, ACVP_STR_HASH_MCT);
            if (!mct_version_str) {
                ACVP_LOG_ERR("Server JSON missing 'mctVersion'");
                rv = ACVP_TC_MISSING_DATA;
                goto err;
            }
            mct_version = read_mct_version(mct_version_str);
            if (mct_version < 0) {
                ACVP_LOG_ERR("Server JSON invalid 'mctVersion'");
                rv = ACVP_TC_INVALID_DATA;
                goto err;
            }

            if (alg_id == ACVP_HASH_SHAKE_128 || alg_id == ACVP_HASH_SHAKE_256) {
                min_xof_len = json_object_get_number(groupobj, "minOutLen");
                if (min_xof_len < ACVP_HASH_XOF_MD_BIT_MIN) {
                    ACVP_LOG_ERR("Server JSON invalid 'minOutLen' (%u)",
                                 min_xof_len);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
                max_xof_len = json_object_get_number(groupobj, "maxOutLen");
                if (max_xof_len > ACVP_HASH_XOF_MD_BIT_MAX) {
                    ACVP_LOG_ERR("Server JSON invalid 'maxOutLen' (%u)",
                                 max_xof_len);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }
        }

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            unsigned int tmp_msg_len = 0;
            unsigned int xof_len = 0;
            unsigned int max_len = 0;

            ACVP_LOG_VERBOSE("Found new hash test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");

            // Based on test type: LDT vs AFT && VOT
            if (test_type == ACVP_HASH_TEST_TYPE_LDT) {
                if (alg_id < ACVP_HASH_SHA1 || alg_id > ACVP_HASH_SHA3_512) {
                    ACVP_LOG_ERR("Server JSON invalid test type for non-SHA1 or SHA2)");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                ldtobj = json_object_get_object(testobj, "largeMsg");

                msg = json_object_get_string(ldtobj, "content");
                if (!msg) {
                    ACVP_LOG_ERR("Server JSON missing 'content'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                max_len = ACVP_HASH_MSG_STR_MAX;
                tmp_msg_len = strnlen_s(msg, max_len + 1);
                if (tmp_msg_len > max_len) {
                    ACVP_LOG_ERR("'msg' too long, max allowed=(%d)", max_len);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
                msglen = tmp_msg_len/2;  // tmp_msg_len is ASCII chars, we store hex bytes

                max_len = json_object_get_number(ldtobj, "contentLength")/8;  // In bits; store as bytes
                if (msglen != max_len) {
                    ACVP_LOG_ERR("Length of content (%d) does not match stated length (%d)", tmp_msg_len, max_len);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                exp_len = json_object_get_number(ldtobj, "fullLength")/8;  // In bits; store as bytes
                // Variable size, and large; no need to validate

                exp_method_str = json_object_get_string(ldtobj, "expansionTechnique");
                exp_method = read_exp_method(exp_method_str);
                if (exp_method != ACVP_HASH_EXPANSION_REPEATING) {
                    ACVP_LOG_ERR("Invalid LDT expansion technique (only 'repeating' is allowed for Hash/SHA).");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            } else {
                msg = json_object_get_string(testobj, "msg");
                if (!msg) {
                    ACVP_LOG_ERR("Server JSON missing 'msg'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (alg_id != ACVP_HASH_SHAKE_128 && alg_id != ACVP_HASH_SHAKE_256) {
                    max_len = ACVP_HASH_MSG_STR_MAX;
                } else {
                    max_len = ACVP_SHAKE_MSG_STR_MAX;
                }
                tmp_msg_len = strnlen_s(msg, max_len + 1);
                if (tmp_msg_len > max_len) {
                    ACVP_LOG_ERR("'msg' too long, max allowed=(%d)", max_len);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
                // Convert to bits
                msglen = tmp_msg_len * 4;

                if ((alg_id == ACVP_HASH_SHAKE_128 || alg_id == ACVP_HASH_SHAKE_256) &&
                        test_type != ACVP_HASH_TEST_TYPE_MCT) {
                    xof_len = json_object_get_number(testobj, "outLen");
                    if (!(xof_len >= ACVP_HASH_XOF_MD_BIT_MIN &&
                        xof_len <= ACVP_HASH_XOF_MD_BIT_MAX)) {
                        ACVP_LOG_ERR("Server JSON invalid 'outLen'(%d)", xof_len);
                        rv = ACVP_INVALID_ARG;
                        goto err;
                    }
                }
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("              len: %d", msglen);
            ACVP_LOG_VERBOSE("              msg: %s", msg);
            if ((alg_id == ACVP_HASH_SHAKE_128 || alg_id == ACVP_HASH_SHAKE_256) &&
                    test_type != ACVP_HASH_TEST_TYPE_MCT) {
                ACVP_LOG_VERBOSE("    outLen: %d", xof_len);
            }
            if (test_type == ACVP_HASH_TEST_TYPE_LDT) {
                ACVP_LOG_VERBOSE("       fullLength: %llu", exp_len);
            }
            ACVP_LOG_VERBOSE("         testtype: %s", test_type_str);

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
            rv = acvp_hash_init_tc(ctx, &stc, tc_id, test_type, mct_version, min_xof_len, max_xof_len, msglen, msg,
                                   xof_len, exp_len, exp_method, alg_id);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Init for stc (test case) failed");
                acvp_hash_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* If Monte Carlo start that here */
            if (stc.test_type == ACVP_HASH_TEST_TYPE_MCT) {
                json_object_set_value(r_tobj, "resultsArray", json_value_init_array());
                res_tarr = json_object_get_array(r_tobj, "resultsArray");
                rv = acvp_hash_perform_mct(ctx, &tc, cap->crypto_handler, res_tarr);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("crypto module failed the HASH MCT operation");
                    acvp_hash_release_tc(&stc);
                    json_value_free(r_tval);
                    goto err;
                }
            } else {
                /* Process the current test vector... */
                if ((cap->crypto_handler)(&tc)) {
                    ACVP_LOG_ERR("crypto module failed the operation");
                    acvp_hash_release_tc(&stc);
                    json_value_free(r_tval);
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    goto err;
                }

                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_hash_output_tc(ctx, &stc, r_tobj);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("JSON output failure in hash module");
                    acvp_hash_release_tc(&stc);
                    json_value_free(r_tval);
                    goto err;
                }
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_hash_release_tc(&stc);

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

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_hash_output_tc(ACVP_CTX *ctx, ACVP_HASH_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    if (stc->test_type == ACVP_HASH_TEST_TYPE_VOT) {
        tmp = calloc(ACVP_HASH_XOF_MD_STR_MAX + 1, sizeof(char));
    } else {
        tmp = calloc(ACVP_HASH_MD_STR_MAX + 1, sizeof(char));
    }
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_hash_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->test_type == ACVP_HASH_TEST_TYPE_VOT) {
        rv = acvp_bin_to_hexstr(stc->md, stc->md_len, tmp, ACVP_HASH_XOF_MD_STR_MAX);
    } else {
        rv = acvp_bin_to_hexstr(stc->md, stc->md_len, tmp, ACVP_HASH_MD_STR_MAX);
    }
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        goto end;
    }
    json_object_set_string(tc_rsp, "md", tmp);
    if (stc->cipher == ACVP_HASH_SHAKE_128 || stc->cipher == ACVP_HASH_SHAKE_256) {
        json_object_set_number(tc_rsp, "outLen", stc->md_len * 8);
    }

end:
    if (tmp) free(tmp);

    return rv;
}

static ACVP_RESULT acvp_hash_init_tc(ACVP_CTX *ctx,
                                     ACVP_HASH_TC *stc,
                                     unsigned int tc_id,
                                     ACVP_HASH_TESTTYPE test_type,
                                     ACVP_HASH_MCT_VERSION mct_version,
                                     unsigned int min_xof_len,
                                     unsigned int max_xof_len,
                                     unsigned int msg_len,
                                     const char *msg,
                                     unsigned int xof_len,
                                     unsigned long long int exp_len,  // LDT expected data length
                                     ACVP_HASH_EXPANSION_METHOD exp_method,
                                     ACVP_CIPHER alg_id) {
    ACVP_RESULT rv;

    memzero_s(stc, sizeof(ACVP_HASH_TC));

    if (test_type == ACVP_HASH_TEST_TYPE_MCT) {
        stc->mct_version = mct_version;
        if (alg_id == ACVP_HASH_SHAKE_128 || alg_id == ACVP_HASH_SHAKE_256) {
            stc->mct_shake_min_xof_bits = min_xof_len;
            stc->mct_shake_max_xof_bits = max_xof_len;
        }
    }

    if (alg_id != ACVP_HASH_SHAKE_128 && alg_id != ACVP_HASH_SHAKE_256) {
        stc->msg = calloc(1, ACVP_HASH_MSG_BYTE_MAX);
    } else {
        stc->msg = calloc(1, ACVP_SHAKE_MSG_BYTE_MAX);
    }
    if (!stc->msg) { return ACVP_MALLOC_FAIL; }

    if (test_type == ACVP_HASH_TEST_TYPE_AFT ||
        test_type == ACVP_HASH_TEST_TYPE_LDT) {
        /* AFT */
        stc->md = calloc(1, ACVP_HASH_MD_BYTE_MAX);
        if (!stc->md) { return ACVP_MALLOC_FAIL; }
    } else if (test_type == ACVP_HASH_TEST_TYPE_VOT) {
        /* VOT */
        stc->md = calloc(1, ACVP_HASH_XOF_MD_BYTE_MAX);
        if (!stc->md) { return ACVP_MALLOC_FAIL; }
    } else {
        /* MCT */
        if (alg_id == ACVP_HASH_SHA3_224 || alg_id == ACVP_HASH_SHA3_256 ||
            alg_id == ACVP_HASH_SHA3_384 || alg_id == ACVP_HASH_SHA3_512) {
            /* SHA3 only needs the md buffer */
            stc->md = calloc(1, ACVP_HASH_MD_BYTE_MAX);
            if (!stc->md) { return ACVP_MALLOC_FAIL; }
        } else if (alg_id == ACVP_HASH_SHAKE_128 ||
                   alg_id == ACVP_HASH_SHAKE_256) {
            /* SHAKE needs the md to support XOF length */
            stc->md = calloc(1, ACVP_HASH_XOF_MD_BYTE_MAX);
            if (!stc->md) { return ACVP_MALLOC_FAIL; }
        } else {
            /* SHA/SHA2 */
            stc->md = calloc(1, ACVP_HASH_MD_BYTE_MAX);
            if (!stc->md) { return ACVP_MALLOC_FAIL; }

            stc->m1 = calloc(1, ACVP_HASH_MD_BYTE_MAX);
            if (!stc->m1) { return ACVP_MALLOC_FAIL; }

            stc->m2 = calloc(1, ACVP_HASH_MD_BYTE_MAX);
            if (!stc->m2) { return ACVP_MALLOC_FAIL; }

            stc->m3 = calloc(1, ACVP_HASH_MD_BYTE_MAX);
            if (!stc->m3) { return ACVP_MALLOC_FAIL; }
        }
    }
    if (alg_id != ACVP_HASH_SHAKE_128 && alg_id != ACVP_HASH_SHAKE_256) {
        rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_HASH_MSG_BYTE_MAX, NULL);
    } else {
        rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_SHAKE_MSG_BYTE_MAX, NULL);
    }
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    stc->tc_id = tc_id;
    stc->cipher = alg_id;
    stc->test_type = test_type;
    if (alg_id == ACVP_HASH_SHAKE_128 || alg_id == ACVP_HASH_SHAKE_256) {
        stc->xof_len = (xof_len + 7) / 8;
        stc->xof_bit_len = xof_len;
    }
    if (stc->test_type == ACVP_HASH_TEST_TYPE_LDT) {
        stc->msg_len = msg_len;
        stc->exp_len = exp_len;
        stc->exp_method = exp_method;
    } else {
        stc->msg_len = (msg_len + 7) / 8;
    }

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_hash_release_tc(ACVP_HASH_TC *stc) {
    if (stc->msg) free(stc->msg);
    if (stc->md) free(stc->md);
    if (stc->m1) free(stc->m1);
    if (stc->m2) free(stc->m2);
    if (stc->m3) free(stc->m3);
    memzero_s(stc, sizeof(ACVP_HASH_TC));

    return ACVP_SUCCESS;
}
