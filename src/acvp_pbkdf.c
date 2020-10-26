/** @file */
/*
 * Copyright (c) 2020, Cisco Systems, Inc.
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
static ACVP_RESULT acvp_pbkdf_output_tc(ACVP_CTX *ctx,
                                         ACVP_PBKDF_TC *stc,
                                         JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    if ((stc->key_len) > ACVP_PBKDF_KEY_BYTE_MAX) {
        ACVP_LOG_ERR("key len too long. Ensure user is not modifying.");
        return ACVP_DATA_TOO_LARGE;
    } else if (stc->key_len < ACVP_PBKDF_KEY_BYTE_MIN) {
        ACVP_LOG_ERR("key len too short. Ensure user is not modifying.");
        return ACVP_INVALID_ARG;
    }

    tmp = calloc(ACVP_PBKDF_KEY_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(stc->key, stc->key_len,
                            tmp, ACVP_PBKDF_KEY_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (key)");
        goto end;
    }
    json_object_set_string(tc_rsp, "derivedKey", tmp);

end:
    if (tmp) free(tmp);
    return rv;
}

static ACVP_RESULT acvp_pbkdf_init_tc(ACVP_PBKDF_TC *stc,
                                       unsigned int tc_id,
                                       ACVP_HASH_ALG hmacAlg,
                                       ACVP_PBKDF_TESTTYPE testType,
                                       const char *salt,
                                       const char *password,
                                       int iterationCount,
                                       int key_len,
                                       int salt_len,
                                       int password_len) {
    ACVP_RESULT rv;
    int tmp;

    memzero_s(stc, sizeof(ACVP_PBKDF_TC));

    stc->cipher = ACVP_PBKDF;
    stc->tc_id = tc_id;
    stc->hmac_type = hmacAlg;
    stc->test_type = testType;
    stc->key_len = key_len;

    // Allocate space for the salt (binary)
    stc->salt = calloc(salt_len, sizeof(unsigned char));
    if (!stc->salt) { return ACVP_MALLOC_FAIL; }
    stc->salt_len = salt_len;


    // Convert key_in from hex string to binary
    rv = acvp_hexstr_to_bin(salt, stc->salt, salt_len, NULL);
    if (rv != ACVP_SUCCESS) return rv;

    //copy password (string) to TC
    stc->password = calloc(password_len + 1, sizeof(char));
    if (!stc->password) { return ACVP_MALLOC_FAIL; }
    tmp = strncpy_s(stc->password, password_len + 1, password, password_len);
    if (tmp) { return ACVP_DATA_TOO_LARGE; }
    stc->pw_len = password_len;

    stc->iterationCount = iterationCount;

    //Allocate space for output (key)
    stc->key = calloc(ACVP_PBKDF_KEY_BYTE_MAX + 1, sizeof(unsigned char));
    if (!stc->key) { return ACVP_MALLOC_FAIL; }

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_pbkdf_release_tc(ACVP_PBKDF_TC *stc) {
    if (stc->salt) free(stc->salt);
    if (stc->password) free(stc->password);
    if (stc->key) free(stc->key);

    memzero_s(stc, sizeof(ACVP_PBKDF_TC));
    return ACVP_SUCCESS;
}

static ACVP_PBKDF_TESTTYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return ACVP_PBKDF_TEST_TYPE_AFT;

    return 0;
}

static ACVP_PBKDF_HMAC_ALG_VAL read_hmac_alg(const char *str) {
    int diff = 1;

    strcmp_s(ACVP_STR_SHA_1,
             ACVP_STR_SHA_MAX,
             str, &diff);
    if (!diff) return ACVP_PBKDF_HMAC_ALG_SHA1;

    strcmp_s(ACVP_STR_SHA2_224,
             ACVP_STR_SHA_MAX,
             str, &diff);
    if (!diff) return ACVP_PBKDF_HMAC_ALG_SHA224;

    strcmp_s(ACVP_STR_SHA2_256,
             ACVP_STR_SHA_MAX,
             str, &diff);
    if (!diff) return ACVP_PBKDF_HMAC_ALG_SHA256;

    strcmp_s(ACVP_STR_SHA2_384,
             ACVP_STR_SHA_MAX,
             str, &diff);
    if (!diff) return ACVP_PBKDF_HMAC_ALG_SHA384;

    strcmp_s(ACVP_STR_SHA2_512,
             ACVP_STR_SHA_MAX,
             str, &diff);
    if (!diff) return ACVP_PBKDF_HMAC_ALG_SHA512;

    strcmp_s(ACVP_STR_SHA3_224,
             ACVP_STR_SHA_MAX,
             str, &diff);
    if (!diff) return ACVP_PBKDF_HMAC_ALG_SHA3_224;

    strcmp_s(ACVP_STR_SHA3_256,
             ACVP_STR_SHA_MAX,
             str, &diff);
    if (!diff) return ACVP_PBKDF_HMAC_ALG_SHA3_256;

    strcmp_s(ACVP_STR_SHA3_384,
             ACVP_STR_SHA_MAX,
             str, &diff);
    if (!diff) return ACVP_PBKDF_HMAC_ALG_SHA3_384;

    strcmp_s(ACVP_STR_SHA3_512,
             ACVP_STR_SHA_MAX,
             str, &diff);
    if (!diff) return ACVP_PBKDF_HMAC_ALG_SHA3_512;

    return 0;
}

ACVP_RESULT acvp_pbkdf_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_PBKDF_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = NULL;
    ACVP_CIPHER alg_id = 0;
    char *json_result;

    ACVP_PBKDF_TESTTYPE test_type = 0;
    ACVP_PBKDF_HMAC_ALG_VAL hmac_alg = 0;
    int key_len = 0, iteration_count = 0, salt_len = 0,
        password_len = 0;
    const char *hmac_alg_str = NULL, *test_type_str = NULL,
               *salt_str = NULL, *password_str = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON.");
        return ACVP_MALFORMED_JSON;
    }
    alg_id = acvp_lookup_cipher_index(alg_str);
    if (alg_id != ACVP_PBKDF) {
        ACVP_LOG_ERR("Invalid algorithm %s", alg_str);
        return ACVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.pbkdf = &stc;

    /*
     * Get the crypto module handler for this hash algorithm
     */
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

        test_type_str = json_object_get_string(groupobj, "testType");
        if (!test_type_str) {
            ACVP_LOG_ERR("Failed to include testType");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        test_type = read_test_type(test_type_str);
        if (!test_type) {
            ACVP_LOG_ERR("Server JSON invalid testType");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        hmac_alg_str = json_object_get_string(groupobj, "hmacAlg");
        if (!hmac_alg_str) {
            ACVP_LOG_ERR("Server JSON missing hmacAlg");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        hmac_alg = read_hmac_alg(hmac_alg_str);
        if (!hmac_alg) {
            ACVP_LOG_ERR("Server JSON invalid hmacAlg");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        /*
         * Log Test Group information...
         */
        ACVP_LOG_VERBOSE("    Test group: %d", i);
        ACVP_LOG_VERBOSE("       hmacAlg: %s", hmac_alg_str);
        ACVP_LOG_VERBOSE("      testType: %s", test_type_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_VERBOSE("Found new pbkdf test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");
            if (!tc_id) {
                ACVP_LOG_ERR("Server JSON missing 'tcId'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            key_len = json_object_get_number(testobj, "keyLen");
            if (key_len < ACVP_PBKDF_KEY_BIT_MIN) {
                ACVP_LOG_ERR("keyLen too low, given = %d, min = %d", key_len, ACVP_PBKDF_KEY_BIT_MIN);
                rv = ACVP_INVALID_ARG;
                goto err;
            } else if (key_len > ACVP_PBKDF_KEY_BIT_MAX) {
                ACVP_LOG_ERR("keyLen too high, given = %d, max = %d", key_len, ACVP_PBKDF_KEY_BIT_MAX);
                rv = ACVP_INVALID_ARG;
                goto err;
            }
            //convert to byte length
            key_len /= 8;

            salt_str = json_object_get_string(testobj, "salt");
            if (!salt_str) {
                ACVP_LOG_ERR("Server JSON missing salt");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
            salt_len = strnlen_s(salt_str, ACVP_PBKDF_SALT_LEN_STR_MAX + 1);
            if (salt_len > ACVP_PBKDF_SALT_LEN_STR_MAX) {
                ACVP_LOG_ERR("salt too long, max allowed=(%d)", ACVP_PBKDF_SALT_LEN_STR_MAX);
                rv = ACVP_INVALID_ARG;
                goto err;
            }
            //convert to byte length
            salt_len /= 2;

            password_str = json_object_get_string(testobj, "password");
            if (!password_str) {
                ACVP_LOG_ERR("Server JSON missing password");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
            password_len = strnlen_s(password_str, ACVP_PBKDF_PASS_LEN_MAX + 1);
            if (password_len < ACVP_PBKDF_PASS_LEN_MIN) {
                ACVP_LOG_ERR("password to short, min allowed=(%d)", ACVP_PBKDF_PASS_LEN_MIN);
                rv = ACVP_INVALID_ARG;
                goto err;
            } else if (password_len > ACVP_PBKDF_PASS_LEN_MAX) {
                ACVP_LOG_ERR("password too long, max allowed=(%d)", ACVP_PBKDF_PASS_LEN_MAX);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

           iteration_count = json_object_get_number(testobj, "iterationCount");
           if (iteration_count < ACVP_PBKDF_ITERATION_MIN) {
               ACVP_LOG_ERR("iterationCount too short, min allowed=(%d)", ACVP_PBKDF_ITERATION_MIN);
               rv = ACVP_INVALID_ARG;
               goto err;
           } else if (iteration_count > ACVP_PBKDF_ITERATION_MAX) {
               ACVP_LOG_ERR("iterationCount too long, max allowed=(%d)", ACVP_PBKDF_ITERATION_MAX);
               rv = ACVP_INVALID_ARG;
               goto err;
           }

            /*
             * Log Test Case information...
             */
            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("           keyLen: %d", key_len);
            ACVP_LOG_VERBOSE("             salt: %s", salt_str);
            ACVP_LOG_VERBOSE("         password: %s", password_str);
            ACVP_LOG_VERBOSE("   iterationCount: %d", iteration_count);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             */
            rv = acvp_pbkdf_init_tc(&stc, tc_id, hmac_alg, test_type,
                                     salt_str, password_str, iteration_count,
                                     key_len, salt_len, password_len);
            if (rv != ACVP_SUCCESS) {
                acvp_pbkdf_release_tc(&stc);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("crypto module failed the operation");
                acvp_pbkdf_release_tc(&stc);
                rv = ACVP_CRYPTO_MODULE_FAIL;
                goto err;
            }

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Output the test case results using JSON
             */
            rv = acvp_pbkdf_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure for pbkdf tc");
                json_value_free(r_tval);
                acvp_pbkdf_release_tc(&stc);
                goto err;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_pbkdf_release_tc(&stc);

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
