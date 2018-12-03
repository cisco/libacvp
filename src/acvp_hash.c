/** @file */
/*****************************************************************************
* Copyright (c) 2016-2017, Cisco Systems, Inc.
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
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_hash_output_tc(ACVP_CTX *ctx, ACVP_HASH_TC *stc, JSON_Object *tc_rsp);

static ACVP_RESULT acvp_hash_init_tc(ACVP_CTX *ctx,
                                     ACVP_HASH_TC *stc,
                                     unsigned int tc_id,
                                     ACVP_HASH_TESTTYPE test_type,
                                     unsigned int msg_len,
                                     const char *msg,
                                     ACVP_CIPHER alg_id);

static ACVP_RESULT acvp_hash_release_tc(ACVP_HASH_TC *stc);


/*
 * After each hash for a Monte Carlo input
 * information may need to be modified.  This function
 * performs the iteration depdedent upon the hash type
 * and direction.
 */
static ACVP_RESULT acvp_hash_mct_iterate_tc(ACVP_CTX *ctx,
                                            ACVP_HASH_TC *stc,
                                            int i,
                                            JSON_Object *r_tobj) {
    /* feed hash into the next message for MCT */
    memcpy(stc->m1, stc->m2, stc->md_len);
    memcpy(stc->m2, stc->m3, stc->md_len);
    memcpy(stc->m3, stc->md, stc->md_len);

    return ACVP_SUCCESS;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case for MCT.
 */
static ACVP_RESULT acvp_hash_output_mct_tc(ACVP_CTX *ctx, ACVP_HASH_TC *stc, JSON_Object *r_tobj) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(1, ACVP_HASH_MD_STR_MAX + 1);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_hash_output_tc");
        return ACVP_MALLOC_FAIL;
    }
    rv = acvp_bin_to_hexstr(stc->md, stc->md_len, tmp, ACVP_HASH_MD_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (md)");
        goto end;
    }
    json_object_set_string(r_tobj, "md", tmp);

end:
    if (tmp) free(tmp);

    return rv;
}

/*
 * This is the handler for SHA MCT values.  This will parse
 * a JSON encoded vector set for DES.  Each test case is
 * parsed, processed, and a response is generated to be sent
 * back to the ACV server by the transport layer.
 */
static ACVP_RESULT acvp_hash_mct_tc(ACVP_CTX *ctx,
                                    ACVP_CAPS_LIST *cap,
                                    ACVP_TEST_CASE *tc,
                                    ACVP_HASH_TC *stc,
                                    JSON_Array *res_array) {
    int i, j;
    ACVP_RESULT rv;
    JSON_Value *r_tval = NULL;  /* Response testval */
    JSON_Object *r_tobj = NULL; /* Response testobj */
    char *tmp = NULL;
    unsigned char *msg = NULL;

    tmp = calloc(ACVP_HASH_MSG_STR_MAX * 3, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc");
        return ACVP_MALLOC_FAIL;
    }

    memcpy(stc->m1, stc->msg, stc->msg_len);
    memcpy(stc->m2, stc->msg, stc->msg_len);
    memcpy(stc->m3, stc->msg, stc->msg_len);

    for (i = 0; i < ACVP_HASH_MCT_OUTER; ++i) {
        /*
         * Create a new test case in the response
         */
        r_tval = json_value_init_object();
        r_tobj = json_value_get_object(r_tval);

        msg = calloc(ACVP_HASH_MSG_BYTE_MAX * 3, sizeof(unsigned char));
        if (!msg) {
            ACVP_LOG_ERR("Unable to malloc");
            free(tmp);
            return ACVP_MALLOC_FAIL;
        }

        memcpy(msg, stc->m1, stc->msg_len);
        memcpy(msg + stc->msg_len, stc->m2, stc->msg_len);
        memcpy(msg + (stc->msg_len * 2), stc->m3, stc->msg_len);

        rv = acvp_bin_to_hexstr(msg, stc->msg_len * 3, tmp, ACVP_HASH_MSG_STR_MAX * 3);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (msg)");
            free(msg);
            free(tmp);
            return rv;
        }
        json_object_set_string(r_tobj, "msg", tmp);
        for (j = 0; j < ACVP_HASH_MCT_INNER; ++j) {
            /* Process the current SHA test vector... */
            rv = (cap->crypto_handler)(tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("crypto module failed the operation");
                free(msg);
                free(tmp);
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Adjust the parameters for next iteration if needed.
             */
            rv = acvp_hash_mct_iterate_tc(ctx, stc, i, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Failed the MCT iteration changes");
                free(msg);
                free(tmp);
                return rv;
            }
        }
        /*
         * Output the test case request values using JSON
         */
        rv = acvp_hash_output_mct_tc(ctx, stc, r_tobj);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("JSON output failure in HASH module");
            free(msg);
            free(tmp);
            return rv;
        }

        /* Append the test response value to array */
        json_array_append_value(res_array, r_tval);

        memcpy(stc->m1, stc->m3, stc->msg_len);
        memcpy(stc->m2, stc->m3, stc->msg_len);

        free(msg);
    }

    free(tmp);
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_hash_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    unsigned int tc_id, msglen;
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
    ACVP_HASH_TC stc;
    ACVP_TEST_CASE tc;
    JSON_Array *res_tarr = NULL; /* Response resultsArray */
    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_CIPHER alg_id = 0;
    char *json_result = NULL;
    ACVP_HASH_TESTTYPE test_type = 0;
    const char *alg_str = NULL;
    const char *test_type_str, *msg = NULL;

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
    if (alg_id < ACVP_CIPHER_START) {
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
            return ACVP_MALFORMED_JSON;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        ACVP_LOG_INFO("    Test group: %d", i);

        test_type_str = json_object_get_string(groupobj, "testType");
        if (!test_type_str) {
            ACVP_LOG_ERR("Server JSON missing 'testType'");
            return ACVP_MISSING_ARG;
        }

        if (!strncmp(test_type_str, "MCT", strlen("MCT"))) {
            test_type = ACVP_HASH_TEST_TYPE_MCT;
        } else if (!strncmp(test_type_str, "AFT", strlen("AFT"))) {
            test_type = ACVP_HASH_TEST_TYPE_AFT;
        } else {
            return ACVP_INVALID_ARG;
        }

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            unsigned int tmp_msg_len = 0;

            ACVP_LOG_INFO("Found new hash test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");

            msg = json_object_get_string(testobj, "msg");
            if (!msg) {
                ACVP_LOG_ERR("Server JSON missing 'msg'");
                return ACVP_MISSING_ARG;
            }
            tmp_msg_len = strnlen(msg, ACVP_HASH_MSG_STR_MAX + 1);
            if (tmp_msg_len > ACVP_HASH_MSG_STR_MAX) {
                ACVP_LOG_ERR("'msg' too long, max allowed=(%d)",
                             ACVP_HASH_MSG_STR_MAX);
                return ACVP_INVALID_ARG;
            }

            // Convert to bits
            msglen = tmp_msg_len * 4;
#if 0
            msglen = (unsigned int)json_object_get_number(testobj, "len");
            if (!msglen) {
                /*
                 * The "len" can be == 0 if the "msg" string is
                 * empty or equal to "00".
                 */
                if (tmp_msg_len != 0 && strncmp(msg, "00", 2)) {
                    // The msg string is not empty and not equal to "00"
                    ACVP_LOG_ERR("Server JSON 'len' is 0 or missing");
                    return ACVP_INVALID_ARG;
                }
            }
            if (msglen > ACVP_HASH_MSG_BIT_MAX) {
                ACVP_LOG_ERR("'len' too long, max allowed=(%d)",
                             ACVP_HASH_MSG_BIT_MAX);
                return ACVP_INVALID_ARG;
            }
#endif

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            ACVP_LOG_INFO("              len: %d", msglen);
            ACVP_LOG_INFO("              msg: %s", msg);
            ACVP_LOG_INFO("         testtype: %s", test_type_str);

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
            rv = acvp_hash_init_tc(ctx, &stc, tc_id, test_type, msglen, msg, alg_id);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Init for stc (test case) failed");
                acvp_hash_release_tc(&stc);
                json_value_free(r_tval);
                return rv;
            }

            /* If Monte Carlo start that here */
            if (stc.test_type == ACVP_HASH_TEST_TYPE_MCT) {
                json_object_set_value(r_tobj, "resultsArray", json_value_init_array());
                res_tarr = json_object_get_array(r_tobj, "resultsArray");
                rv = acvp_hash_mct_tc(ctx, cap, &tc, &stc, res_tarr);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("crypto module failed the HASH MCT operation");
                    acvp_hash_release_tc(&stc);
                    json_value_free(r_tval);
                    return ACVP_CRYPTO_MODULE_FAIL;
                }
            } else {
                /* Process the current test vector... */
                if ((cap->crypto_handler)(&tc)) {
                    ACVP_LOG_ERR("crypto module failed the operation");
                    acvp_hash_release_tc(&stc);
                    json_value_free(r_tval);
                    return ACVP_CRYPTO_MODULE_FAIL;
                }

                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_hash_output_tc(ctx, &stc, r_tobj);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("JSON output failure in hash module");
                    acvp_hash_release_tc(&stc);
                    json_value_free(r_tval);
                    return rv;
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

    json_result = json_serialize_to_string_pretty(ctx->kat_resp);
    if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
        printf("\n\n%s\n\n", json_result);
    } else {
        ACVP_LOG_INFO("\n\n%s\n\n", json_result);
    }
    json_free_serialized_string(json_result);

    return ACVP_SUCCESS;
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

    tmp = calloc(ACVP_HASH_MD_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_hash_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(stc->md, stc->md_len, tmp, ACVP_HASH_MD_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (msg)");
        goto end;
    }
    json_object_set_string(tc_rsp, "md", tmp);

end:
    if (tmp) free(tmp);

    return rv;
}

static ACVP_RESULT acvp_hash_init_tc(ACVP_CTX *ctx,
                                     ACVP_HASH_TC *stc,
                                     unsigned int tc_id,
                                     ACVP_HASH_TESTTYPE test_type,
                                     unsigned int msg_len,
                                     const char *msg,
                                     ACVP_CIPHER alg_id) {
    ACVP_RESULT rv;

    memset(stc, 0x0, sizeof(ACVP_HASH_TC));

    stc->msg = calloc(1, ACVP_HASH_MSG_BYTE_MAX);
    if (!stc->msg) { return ACVP_MALLOC_FAIL; }

    stc->md = calloc(1, ACVP_HASH_MD_BYTE_MAX);
    if (!stc->md) { return ACVP_MALLOC_FAIL; }

    stc->m1 = calloc(1, ACVP_HASH_MD_BYTE_MAX);
    if (!stc->m1) { return ACVP_MALLOC_FAIL; }

    stc->m2 = calloc(1, ACVP_HASH_MD_BYTE_MAX);
    if (!stc->m2) { return ACVP_MALLOC_FAIL; }

    stc->m3 = calloc(1, ACVP_HASH_MD_BYTE_MAX);
    if (!stc->m3) { return ACVP_MALLOC_FAIL; }

    rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_HASH_MSG_BYTE_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex converstion failure (msg)");
        return rv;
    }

    stc->tc_id = tc_id;
    stc->msg_len = (msg_len + 7) / 8;
    stc->cipher = alg_id;
    stc->test_type = test_type;

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
    memset(stc, 0x0, sizeof(ACVP_HASH_TC));

    return ACVP_SUCCESS;
}
