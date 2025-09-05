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

static ACVP_RESULT acvp_cshake_init_tc(ACVP_CTX *ctx,
                                       ACVP_CSHAKE_TC *stc,
                                       ACVP_CIPHER alg_id,
                                       int tc_id,
                                       ACVP_CSHAKE_TESTTYPE type,
                                       int hex_customization,
                                       const char *msg,
                                       int md_len,
                                       const char *function_name,
                                       const char *custom) {

    ACVP_RESULT rv;
    int len = 0;
    memzero_s(stc, sizeof(ACVP_CSHAKE_TC));
    stc->tc_id = tc_id;
    stc->cipher = alg_id;
    stc->test_type = type;
    stc->hex_customization = hex_customization;
    stc->md_len = md_len / 8;

    stc->msg = calloc(1, ACVP_CSHAKE_MSG_BYTE_MAX);
    if (!stc->msg) { return ACVP_MALLOC_FAIL; }
    stc->md = calloc(1, ACVP_CSHAKE_OUTPUT_BYTE_MAX);
    if (!stc->md) { return ACVP_MALLOC_FAIL; }

    if (hex_customization) {
        stc->custom_hex = calloc(1, ACVP_CSHAKE_CUSTOM_HEX_BYTE_MAX);
        if (!stc->custom_hex) { return ACVP_MALLOC_FAIL; }
    } else {
        stc->custom = calloc(1, ACVP_CSHAKE_CUSTOM_STR_MAX + 1);
        if (!stc->custom) { return ACVP_MALLOC_FAIL; }
    }

    stc->function_name = calloc(1, ACVP_CSHAKE_FUNCTION_STR_MAX + 1);
    if (!stc->function_name) { return ACVP_MALLOC_FAIL; }


    if (msg) {
        len = strnlen_s(msg, ACVP_CSHAKE_MSG_STR_MAX + 1);
        if (len > ACVP_CSHAKE_MSG_STR_MAX) {
            ACVP_LOG_ERR("msg too long");
            return ACVP_INVALID_ARG;
        }
        rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_CSHAKE_MSG_BYTE_MAX, &(stc->msg_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (msg)");
            return rv;
        }
    }

    if (function_name) {
        len = strnlen_s(function_name, ACVP_CSHAKE_FUNCTION_STR_MAX + 1);
        if (len > ACVP_CSHAKE_FUNCTION_STR_MAX) {
            ACVP_LOG_ERR("function name too long");
            return ACVP_INVALID_ARG;
        }
        strcpy_s(stc->function_name, ACVP_CSHAKE_FUNCTION_STR_MAX + 1, function_name);
        stc->function_name_len = len;
    }

    if (custom) {
        if (hex_customization) {
            len = strnlen_s(custom, ACVP_CSHAKE_CUSTOM_HEX_STR_MAX + 1);
            if (len > ACVP_CSHAKE_CUSTOM_HEX_STR_MAX) {
                ACVP_LOG_ERR("custom hex too long");
                return ACVP_INVALID_ARG;
            }
            rv = acvp_hexstr_to_bin(custom, stc->custom_hex, ACVP_CSHAKE_CUSTOM_HEX_BYTE_MAX, &(stc->custom_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (custom_hex)");
                return rv;
            }
        } else {
            len = strnlen_s(custom, ACVP_CSHAKE_CUSTOM_STR_MAX + 1);
            if (len > ACVP_CSHAKE_CUSTOM_STR_MAX) {
                ACVP_LOG_ERR("custom string too long");
                return ACVP_INVALID_ARG;
            }
            strcpy_s(stc->custom, ACVP_CSHAKE_CUSTOM_STR_MAX + 1, custom);
            stc->custom_len = len;
        }
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_cshake_output_tc(ACVP_CTX *ctx, ACVP_CSHAKE_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_CSHAKE_OUTPUT_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->test_type == ACVP_CSHAKE_TEST_TYPE_AFT) {
        rv = acvp_bin_to_hexstr(stc->md, stc->md_len, tmp, ACVP_CSHAKE_OUTPUT_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (md)");
            goto end;
        }
        json_object_set_string(tc_rsp, "md", tmp);
        json_object_set_number(tc_rsp, "outLen", stc->md_len * 8);
    }

end:
    if (tmp) free(tmp);
    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_cshake_release_tc(ACVP_CSHAKE_TC *stc) {
    if (stc->msg) free(stc->msg);
    if (stc->md) free(stc->md);
    if (stc->custom) free(stc->custom);
    if (stc->custom_hex) free(stc->custom_hex);
    if (stc->function_name) free(stc->function_name);
    memzero_s(stc, sizeof(ACVP_CSHAKE_TC));

    return ACVP_SUCCESS;
}

static ACVP_CSHAKE_TESTTYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return ACVP_CSHAKE_TEST_TYPE_AFT;

    strcmp_s("MCT", 3, str, &diff);
    if (!diff) return ACVP_CSHAKE_TEST_TYPE_MCT;

    return 0;
}

/*
 * Helper function to convert bits to ASCII string as specified in XOF draft
 * BitsToString(bits) converts each byte to ASCII character ((byte % 26) + 65)
 */
static ACVP_RESULT acvp_cshake_bits_to_string(const unsigned char *bits, int bits_len,
                                               char *str, int str_max_len) {
    int i;

    if (!bits || !str || bits_len < 0 || str_max_len <= 0) {
        return ACVP_INVALID_ARG;
    }

    if (bits_len >= str_max_len) {
        return ACVP_DATA_TOO_LARGE;
    }

    for (i = 0; i < bits_len; i++) {
        str[i] = (char)((bits[i] % 26) + 65); /* Convert to uppercase ASCII letters A-Z */
    }
    str[bits_len] = '\0'; /* Null terminate */

    return ACVP_SUCCESS;
}

/*
 * MCT-specific output function to handle the resultsArray format
 */
static ACVP_RESULT acvp_cshake_output_mct_tc(ACVP_CTX *ctx, ACVP_CSHAKE_TC *stc,
                                              JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_CSHAKE_OUTPUT_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(stc->md, stc->md_len, tmp, ACVP_CSHAKE_OUTPUT_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (md)");
        goto end;
    }
    json_object_set_string(tc_rsp, "md", tmp);
    json_object_set_number(tc_rsp, "outLen", stc->md_len * 8);

end:
    if (tmp) free(tmp);
    return rv;
}

/*
 * cSHAKE Monte Carlo Test implementation
 * Based on the algorithm specified in draft-celi-acvp-xof.txt Section 6.2.1
 */
static ACVP_RESULT acvp_cshake_mct(ACVP_CTX *ctx,
                                   ACVP_CAPS_LIST *cap,
                                   ACVP_TEST_CASE *tc,
                                   ACVP_CSHAKE_TC *stc,
                                   JSON_Array *res_array,
                                   int min_out_len,
                                   int max_out_len,
                                   int out_len_increment) {
    int i = 0, j = 0;
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *r_tval = NULL;  /* Response testval */
    JSON_Object *r_tobj = NULL; /* Response testobj */

    /* MCT working variables */
    unsigned char *output = NULL;
    unsigned char *inner_msg = NULL;
    unsigned char *rightmost_bits = NULL;
    unsigned char *custom_bits = NULL;
    char *custom_string = NULL;
    int output_len = 0;
    int range = 0;
    uint16_t rightmost_val = 0;
    int leftmost_bytes = 0;

    /* Set leftmost_bytes as per specification (always 128 bits for cSHAKE MCT) */
    leftmost_bytes = 16; /* 128 bits = 16 bytes as per specification */

    /* Allocate working buffers */
    output = calloc(1, ACVP_CSHAKE_OUTPUT_BYTE_MAX);
    inner_msg = calloc(1, leftmost_bytes + 16); /* leftmost_bytes + padding */
    rightmost_bits = calloc(1, 2); /* 16 bits = 2 bytes */
    custom_bits = calloc(1, leftmost_bytes + 2); /* InnerMsg + RightmostBits */
    custom_string = calloc(1, ACVP_CSHAKE_CUSTOM_STR_MAX + 1);

    if (!output || !inner_msg || !rightmost_bits || !custom_bits || !custom_string) {
        rv = ACVP_MALLOC_FAIL;
        goto err;
    }

    /* MCT algorithm implementation */
    range = (max_out_len - min_out_len + 1);
    output_len = max_out_len;

    /* Copy initial message to output[0] */
    memcpy_s(output, ACVP_CSHAKE_OUTPUT_BYTE_MAX, stc->msg, stc->msg_len);
    int current_output_len = stc->msg_len; /* Track current output length */

    /* Outer loop: j = 0 to 99 */
    for (j = 0; j < 100; j++) {
        /* Inner loop: i = 1 to 1000 */
        for (i = 1; i <= 1000; i++) {
            /* InnerMsg = Left(Output[i-1] || ZeroBits(leftmost_bytes*8), leftmost_bytes*8) */
            memzero_s(inner_msg, leftmost_bytes + 16);
            if (current_output_len >= leftmost_bytes) {
                memcpy_s(inner_msg, leftmost_bytes, output, leftmost_bytes);
            } else {
                memcpy_s(inner_msg, leftmost_bytes, output, current_output_len);
                /* Remaining bytes are already zeroed */
            }

            /* Set up test case for crypto handler */
            memcpy_s(stc->msg, ACVP_CSHAKE_MSG_BYTE_MAX, inner_msg, leftmost_bytes);
            stc->msg_len = leftmost_bytes;
            stc->md_len = (output_len + 7) / 8; /* Convert bits to bytes */

            /* Clear md buffer */
            memzero_s(stc->md, ACVP_CSHAKE_OUTPUT_BYTE_MAX);

            /* Call crypto module: Output[i] = CSHAKE(InnerMsg, OutputLen, FunctionName, Customization) */
            rv = (cap->crypto_handler)(tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Crypto module failed the operation");
                goto err;
            }

            /* Copy result to output buffer for next iteration */
            memcpy_s(output, ACVP_CSHAKE_OUTPUT_BYTE_MAX, stc->md, stc->md_len);
            current_output_len = stc->md_len;

            /* Rightmost_Output_bits = Right(Output[i], 16) */
            if (stc->md_len >= 2) {
                memcpy_s(rightmost_bits, 2, &stc->md[stc->md_len - 2], 2);
            } else {
                memzero_s(rightmost_bits, 2);
                if (stc->md_len == 1) {
                    rightmost_bits[0] = stc->md[0];  /* Rightmost byte goes in index 0 */
                }
            }

            /* Convert rightmost bits to integer (little-endian where first 8-bits are MSB) */
            rightmost_val = (uint16_t)(rightmost_bits[1] | (rightmost_bits[0] << 8));

            /* OutputLen = MinOutLen + (floor((Rightmost_Output_bits % Range) / OutLenIncrement) * OutLenIncrement) */
            output_len = min_out_len + ((rightmost_val % range) / out_len_increment) * out_len_increment;

            /* Customization = BitsToString(InnerMsg || Rightmost_Output_bits) */
            memcpy_s(custom_bits, leftmost_bytes + 2, inner_msg, leftmost_bytes);
            memcpy_s(&custom_bits[leftmost_bytes], 2, rightmost_bits, 2);

            rv = acvp_cshake_bits_to_string(custom_bits, leftmost_bytes + 2,
                                            custom_string, ACVP_CSHAKE_CUSTOM_STR_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("BitsToString conversion failed");
                goto err;
            }

            /* Update customization in test case */
            strcpy_s(stc->custom, ACVP_CSHAKE_CUSTOM_STR_MAX + 1, custom_string);
            stc->custom_len = strnlen_s(custom_string, ACVP_CSHAKE_CUSTOM_STR_MAX);
        }

        /* Create response object for this iteration */
        r_tval = json_value_init_object();
        r_tobj = json_value_get_object(r_tval);

        /* Output the result for this outer loop iteration */
        rv = acvp_cshake_output_mct_tc(ctx, stc, r_tobj);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("JSON output failure recording MCT test response");
            json_value_free(r_tval);
            goto err;
        }

        json_array_append_value(res_array, r_tval);

        /* Output[0] = Output[1000] for next iteration (as per spec line 307) */
        /* The output buffer already contains Output[1000] from the last inner loop iteration */
    }

err:
    if (output) free(output);
    if (inner_msg) free(inner_msg);
    if (rightmost_bits) free(rightmost_bits);
    if (custom_bits) free(custom_bits);
    if (custom_string) free(custom_string);

    return rv;
}

ACVP_RESULT acvp_cshake_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    int tc_id = 0, msglen = 0, outlen = 0;
    const char *msg = NULL, *type_str = NULL, *custom = NULL, *function_name = NULL;
    int hex_customization = 0;
    int min_out_len = 0, max_out_len = 0, out_len_increment = 0; /* MCT parameters */
    ACVP_CSHAKE_TESTTYPE type;
    JSON_Value *groupval = NULL;
    JSON_Object *groupobj = NULL;
    JSON_Value *testval = NULL;
    JSON_Object *testobj = NULL;
    JSON_Array *groups = NULL;
    JSON_Array *tests = NULL;

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
    ACVP_CAPS_LIST *cap = NULL;
    ACVP_CSHAKE_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER alg_id;
    char *json_result = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    if (!obj) {
        ACVP_LOG_ERR("No obj for handler operation");
        return ACVP_MALFORMED_JSON;
    }

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.cshake = &stc;

    /*
     * Get the crypto module handler for cSHAKE
     */
    alg_id = acvp_lookup_cipher_index(alg_str);
    if (alg_id < ACVP_CIPHER_START) {
        ACVP_LOG_ERR("unsupported algorithm (%s)", alg_str);
        return ACVP_UNSUPPORTED_OP;
    }
    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability %s : %d.", alg_str, alg_id);
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

        type_str = json_object_get_string(groupobj, "testType");
        if (!type_str) {
            ACVP_LOG_ERR("Server JSON missing 'testType'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        type = read_test_type(type_str);
        if (!type) {
            ACVP_LOG_ERR("Server JSON invalid 'testType'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        hex_customization = json_object_get_boolean(groupobj, "hexCustomization");

        /* Parse MCT-specific parameters if this is an MCT test */
        if (type == ACVP_CSHAKE_TEST_TYPE_MCT) {
            min_out_len = json_object_get_number(groupobj, "minOutLen");
            max_out_len = json_object_get_number(groupobj, "maxOutLen");
            out_len_increment = json_object_get_number(groupobj, "outLenIncrement");

            if (min_out_len <= 0 || max_out_len <= 0 || out_len_increment <= 0) {
                ACVP_LOG_ERR("Invalid MCT parameters in test group");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
        }

        ACVP_LOG_VERBOSE("    Test group: %d", i);
        ACVP_LOG_VERBOSE("      test type: %s", type_str);
        ACVP_LOG_VERBOSE("   hex customization: %s", hex_customization ? "true" : "false");
        if (type == ACVP_CSHAKE_TEST_TYPE_MCT) {
            ACVP_LOG_VERBOSE("      min out len: %d", min_out_len);
            ACVP_LOG_VERBOSE("      max out len: %d", max_out_len);
            ACVP_LOG_VERBOSE("  out len increment: %d", out_len_increment);
        }

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_VERBOSE("Found new cSHAKE test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");

            msg = json_object_get_string(testobj, "msg");
            msglen = json_object_get_number(testobj, "len");
            outlen = json_object_get_number(testobj, "outLen");
            function_name = json_object_get_string(testobj, "functionName");

            if (hex_customization) {
                custom = json_object_get_string(testobj, "customizationHex");
                if (custom && strnlen_s(custom, ACVP_CSHAKE_CUSTOM_HEX_STR_MAX + 1) > ACVP_CSHAKE_CUSTOM_HEX_STR_MAX) {
                    ACVP_LOG_ERR("customization hex too long in tcid %d", tc_id);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            } else {
                custom = json_object_get_string(testobj, "customization");
                if (custom && strnlen_s(custom, ACVP_CSHAKE_CUSTOM_STR_MAX + 1) > ACVP_CSHAKE_CUSTOM_STR_MAX) {
                    ACVP_LOG_ERR("customization string too long in tcid %d", tc_id);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            if (!msg) {
                ACVP_LOG_ERR("Server JSON missing 'msg'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            if (msglen < 0) {
                ACVP_LOG_ERR("Server JSON missing or invalid 'len'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            if (type != ACVP_CSHAKE_TEST_TYPE_MCT && outlen <= 0) {
                ACVP_LOG_ERR("Server JSON missing or invalid 'outLen'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("           msgLen: %d", msglen);
            ACVP_LOG_VERBOSE("           outLen: %d", outlen);
            ACVP_LOG_VERBOSE("              msg: %s", msg);
            ACVP_LOG_VERBOSE("     functionName: %s", function_name ? function_name : "");
            ACVP_LOG_VERBOSE("    customization: %s", custom ? custom : "");

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
            if (msg) {
                int actual_msg_len = strnlen_s(msg, ACVP_CSHAKE_MSG_STR_MAX + 1) / 2;
                if (msglen != actual_msg_len * 8) {
                    ACVP_LOG_ERR("Message length mismatch: JSON says %d bits, actual string is %d bytes (%d bits)",
                                 msglen, actual_msg_len, actual_msg_len * 8);
                    rv = ACVP_TC_INVALID_DATA;
                    goto err;
                }
            }

            if (type == ACVP_CSHAKE_TEST_TYPE_MCT) {
                /* MCT tests don't have outLen, md_len will be set during MCT execution */
                rv = acvp_cshake_init_tc(ctx, &stc, alg_id, tc_id, type, hex_customization,
                                         msg, 0, function_name, custom);
            } else {
                /* AFT tests use outLen from JSON */
                rv = acvp_cshake_init_tc(ctx, &stc, alg_id, tc_id, type, hex_customization,
                                         msg, outlen, function_name, custom);
            }
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Error initializing cSHAKE test case");
                acvp_cshake_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Handle MCT or AFT test types */
            if (type == ACVP_CSHAKE_TEST_TYPE_MCT) {
                /* For MCT, create resultsArray and call MCT handler */
                json_object_set_value(r_tobj, "resultsArray", json_value_init_array());
                JSON_Array *results_array = json_object_get_array(r_tobj, "resultsArray");

                rv = acvp_cshake_mct(ctx, cap, &tc, &stc, results_array,
                                     min_out_len, max_out_len, out_len_increment);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("cSHAKE MCT processing failed");
                    acvp_cshake_release_tc(&stc);
                    json_value_free(r_tval);
                    goto err;
                }

                /*
                 * Release all the memory associated with the test case
                 */
                acvp_cshake_release_tc(&stc);

                /* Append the MCT test case to the main test array */
                json_array_append_value(r_tarr, r_tval);
            } else {
                /* AFT processing */
                if ((cap->crypto_handler)(&tc)) {
                    ACVP_LOG_ERR("Crypto module failed the operation");
                    acvp_cshake_release_tc(&stc);
                    json_value_free(r_tval);
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    goto err;
                }

                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_cshake_output_tc(ctx, &stc, r_tobj);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("JSON output failure recording test response");
                    json_value_free(r_tval);
                    acvp_cshake_release_tc(&stc);
                    goto err;
                }

                /*
                 * Release all the memory associated with the test case
                 */
                acvp_cshake_release_tc(&stc);

                /* Append the AFT test response value to array */
                json_array_append_value(r_tarr, r_tval);
            }
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
