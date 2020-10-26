/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
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
static ACVP_RESULT acvp_rsa_decprim_output_tc(ACVP_CTX *ctx, ACVP_RSA_PRIM_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_RSA_EXP_LEN_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_rsa_decprim tpm_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(stc->e, stc->e_len, tmp, ACVP_RSA_EXP_LEN_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (p)");
        goto err;
    }
    json_object_set_string(tc_rsp, "e", (const char *)tmp);
    memzero_s(tmp, ACVP_RSA_EXP_LEN_MAX);

    rv = acvp_bin_to_hexstr(stc->n, stc->n_len, tmp, ACVP_RSA_EXP_LEN_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (q)");
        goto err;
    }
    json_object_set_string(tc_rsp, "n", (const char *)tmp);
    memzero_s(tmp, ACVP_RSA_EXP_LEN_MAX);

    json_object_set_boolean(tc_rsp, "testPassed", stc->disposition);

    if (stc->disposition) {
        rv = acvp_bin_to_hexstr(stc->pt, stc->pt_len, tmp, ACVP_RSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (q)");
            goto err;
        }
        json_object_set_string(tc_rsp, "plainText", (const char *)tmp);
    }
err:
    if (tmp) free(tmp);

    return rv;
}

static ACVP_RESULT acvp_rsa_sigprim_output_tc(ACVP_CTX *ctx, ACVP_RSA_PRIM_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_RSA_EXP_LEN_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_rsa_decprim tpm_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->disposition) {
        rv = acvp_bin_to_hexstr(stc->signature, stc->sig_len, tmp, ACVP_RSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (q)");
            goto err;
        }
        json_object_set_string(tc_rsp, "signature", (const char *)tmp);
        json_object_set_boolean(tc_rsp, "testPassed", stc->disposition);
    } else {
        json_object_set_boolean(tc_rsp, "testPassed", stc->disposition);
    }

err:
    if (tmp) free(tmp);

    return rv;
}

static ACVP_RESULT acvp_rsa_decprim_release_tc(ACVP_RSA_PRIM_TC *stc) {
    if (stc->e) { free(stc->e); }
    if (stc->n) { free(stc->n); }
    if (stc->pt) { free(stc->pt); }
    if (stc->cipher) { free(stc->cipher); }
    if (stc->plaintext) { free(stc->plaintext); }
    memzero_s(stc, sizeof(ACVP_RSA_PRIM_TC));

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_rsa_sigprim_release_tc(ACVP_RSA_PRIM_TC *stc) {
    if (stc->e) { free(stc->e); }
    if (stc->d) { free(stc->d); }
    if (stc->n) { free(stc->n); }
    if (stc->pt) { free(stc->pt); }
    if (stc->msg) { free(stc->msg); }
    if (stc->signature) { free(stc->signature); }
    memzero_s(stc, sizeof(ACVP_RSA_PRIM_TC));

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_rsa_decprim_init_tc(ACVP_CTX *ctx,
                                            ACVP_RSA_PRIM_TC *stc,
                                            unsigned int tc_id,
                                            int modulo,
                                            int deferred,
                                            int pass,
                                            int fail,
                                            const char *cipher,
                                            int cipher_len) {
 
    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_RSA_PRIM_TC));
    stc->modulo = modulo;
    stc->deferred = deferred;
    stc->pass = pass;
    stc->fail = fail;
    stc->cipher_len = cipher_len;
    stc->cipher = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->cipher) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(cipher, stc->cipher, ACVP_RSA_EXP_BYTE_MAX, &(stc->cipher_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (cipher)");
        return rv;
    }
    stc->plaintext = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->plaintext) { return ACVP_MALLOC_FAIL; }
    stc->e = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->e) { return ACVP_MALLOC_FAIL; }
    stc->n = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->n) { return ACVP_MALLOC_FAIL; }
    stc->pt = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->pt) { return ACVP_MALLOC_FAIL; }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_rsa_sigprim_init_tc(ACVP_CTX *ctx,
                                            ACVP_RSA_PRIM_TC *stc,
                                            unsigned int tc_id,
                                            unsigned int modulo,
                                            unsigned int keyformat,
                                            const char *d_str,
                                            const char *e_str,
                                            const char *n_str,
                                            const char *msg) {
 
    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_RSA_PRIM_TC));

    stc->e = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->e) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(e_str, stc->e, ACVP_RSA_EXP_BYTE_MAX, &(stc->e_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (cipher)");
        return rv;
    }
    stc->d = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->d) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(d_str, stc->d, ACVP_RSA_EXP_BYTE_MAX, &(stc->d_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (cipher)");
        return rv;
    }
    stc->n = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->n) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(n_str, stc->n, ACVP_RSA_EXP_BYTE_MAX, &(stc->n_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (cipher)");
        return rv;
    }

    stc->msg = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->msg) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_RSA_EXP_BYTE_MAX, &(stc->msg_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (cipher)");
        return rv;
    }

    stc->modulo = modulo;
    stc->key_format = keyformat;
    stc->signature = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->signature) { return ACVP_MALLOC_FAIL; }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_rsa_decprim_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    unsigned int tc_id;
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *groups;
    JSON_Array *tests;
    JSON_Value *ciphval;
    JSON_Object *ciphobj = NULL;
    JSON_Array *ciphers;

    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;

    int i, g_cnt;
    int j, t_cnt;
    int c, c_cnt;

    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL, *r_garr = NULL, *r_carr = NULL;  /* Response testarray, grouparray */
    JSON_Value *r_tval = NULL, *r_gval = NULL, *r_cval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL, *r_cobj = NULL; /* Response testobj, groupobj */
    ACVP_CAPS_LIST *cap;
    ACVP_RSA_PRIM_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;

    ACVP_CIPHER alg_id;
    char *json_result = NULL;
    unsigned int mod = 0, total = 0, fail = 0, pass = 0;
    const char *alg_str = NULL, *mode_str, *cipher = NULL;
    int deferred = 0;
    int cipher_len;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("Unable to parse 'algorithm' from JSON.");
        return ACVP_MALFORMED_JSON;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("Unable to parse 'mode' from JSON.");
        return ACVP_MALFORMED_JSON;
    }

    alg_id = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != ACVP_RSA_DECPRIM) {
        ACVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return ACVP_INVALID_ARG;
    }

    tc.tc.rsa_prim = &stc;
    memzero_s(&stc, sizeof(ACVP_RSA_PRIM_TC));

    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("Server requesting unsupported capability");
        return ACVP_UNSUPPORTED_OP;
    }

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("ERROR: Failed to create JSON response struct. ");
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

        mod = json_object_get_number(groupobj, "modulo");
        if (mod != 2048) {
            ACVP_LOG_ERR("Server JSON invalid modulo");
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        total = json_object_get_number(groupobj, "totalTestCases");
        if (total == 0) {
            ACVP_LOG_ERR("Server JSON invalid totalTestCases");
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        fail = json_object_get_number(groupobj, "totalFailingCases");
        if (fail == 0) {
            ACVP_LOG_ERR("Server JSON invalid totalFailingCases");
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        pass = total - fail;

        ACVP_LOG_VERBOSE("    Test group: %d", i);
        ACVP_LOG_VERBOSE("           modulo: %d", mod);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_VERBOSE("Found new RSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("       totalCases: %d", total);
            ACVP_LOG_VERBOSE("     failingCases: %d", fail);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);
            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Retrieve values from JSON and initialize the tc
             */
            deferred = json_object_get_boolean(testobj, "deferred");
            if (deferred == -1) {
                ACVP_LOG_ERR("Server JSON missing 'deferred'");
                rv = ACVP_MISSING_ARG;
                json_value_free(r_tval);
                goto err;
            }

            ciphers = json_object_get_array(testobj, "resultsArray");
            c_cnt = json_array_get_count(ciphers);

            json_object_set_value(r_tobj, "resultsArray", json_value_init_array());
            r_carr = json_object_get_array(r_tobj, "resultsArray");

            for (c = 0; c < c_cnt; c++) {
                ciphval = json_array_get_value(ciphers, c);
                ciphobj = json_value_get_object(ciphval);

                r_cval = json_value_init_object();
                r_cobj = json_value_get_object(r_cval);

                cipher = json_object_get_string(ciphobj, "cipherText");
                if (!cipher) {
                    ACVP_LOG_ERR("Server JSON missing 'cipher'");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                cipher_len = strnlen_s(cipher, ACVP_RSA_EXP_BYTE_MAX + 1);
                if (cipher_len > ACVP_RSA_EXP_BYTE_MAX) {
                    ACVP_LOG_ERR("'cipher' too long, max allowed=(%d)",
                                 ACVP_RSA_SEEDLEN_MAX);
                    rv = ACVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                rv = acvp_rsa_decprim_init_tc(ctx, &stc, tc_id, mod, deferred, pass, 
                                              fail, cipher, cipher_len);

                /* Process the current test vector... */
                if (rv == ACVP_SUCCESS) {
                   fail = stc.fail;
                   pass = stc.pass;
                   do { 
                       if ((cap->crypto_handler)(&tc)) {
                           ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                           rv = ACVP_CRYPTO_MODULE_FAIL;
                           json_value_free(r_tval);
                           goto err;
                       }
                    ACVP_LOG_INFO("Looping on fail/pass %d/%d %d/%d", fail, stc.fail, pass, stc.pass);
                    } while((fail == stc.fail) && (pass == stc.pass));
                }
                fail = stc.fail;
                pass = stc.pass;

                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_rsa_decprim_output_tc(ctx, &stc, r_cobj);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("ERROR: JSON output failure in primitive module");
                    json_value_free(r_tval);
                    goto err;
                }
                /*
                 * Release all the memory associated with the test case
                 */
                acvp_rsa_decprim_release_tc(&stc);

                /* Append the cipher response value to array */
                json_array_append_value(r_carr, r_cval);
            }
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
        acvp_rsa_decprim_release_tc(&stc);
        acvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}

ACVP_RESULT acvp_rsa_sigprim_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_RSA_PRIM_TC stc;
    ACVP_TEST_CASE tc;
    int diff = 0;
    unsigned int mod = 0;
    unsigned int keyformat = 0;
    const char *key_format = NULL;
    ACVP_CIPHER alg_id;
    char *json_result = NULL;
    const char *mode_str;
    const char *msg;
    const char *e_str = NULL, *n_str = NULL, *d_str = NULL;
    const char *alg_str;
    unsigned int json_msglen;
    ACVP_RESULT rv;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("Missing 'mode' from server json");
        return ACVP_MISSING_ARG;
    }

    alg_id = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != ACVP_RSA_SIGPRIM) {
        ACVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return ACVP_INVALID_ARG;
    }

    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ERROR: ACVP server requesting unsupported capability");
        return ACVP_UNSUPPORTED_OP;
    }

    ACVP_LOG_VERBOSE("    RSA mode: %s", mode_str);

    tc.tc.rsa_prim = &stc;
    memzero_s(&stc, sizeof(ACVP_RSA_PRIM_TC));

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("ERROR: Failed to create JSON response struct. ");
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

        mod = json_object_get_number(groupobj, "modulo");
        if (mod != 2048) {
            ACVP_LOG_ERR("Server JSON invalid modulo");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        key_format = json_object_get_string(groupobj, "keyFormat");
        if (!key_format) {
            ACVP_LOG_ERR("Missing keyFormat from server json");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        strcmp_s("standard", 8, key_format, &diff);
        if (!diff) keyformat = ACVP_RSA_PRIM_KEYFORMAT_STANDARD;

        strcmp_s("crt", 3, key_format, &diff);
        if (!diff) keyformat = ACVP_RSA_PRIM_KEYFORMAT_CRT;

        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        ACVP_LOG_VERBOSE("       Test group: %d", i);
        ACVP_LOG_VERBOSE("       key format: %s", key_format);
        ACVP_LOG_VERBOSE("           modulo: %d", mod);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_VERBOSE("Found new RSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");
            if (!tc_id) {
                ACVP_LOG_ERR("Missing tc_id");
                rv = ACVP_MALFORMED_JSON;
                goto err;
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Get a reference to the abstracted test case
             */

            e_str = json_object_get_string(testobj, "e");
            n_str = json_object_get_string(testobj, "n");
            d_str = json_object_get_string(testobj, "d");
            if (!e_str || !n_str || !d_str) {
                ACVP_LOG_ERR("Missing e|n|d from server json");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
            if ((strnlen_s(e_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                (strnlen_s(n_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                (strnlen_s(d_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX)) {
                ACVP_LOG_ERR("server provided d or e or n of invalid length");
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            msg = json_object_get_string(testobj, "message");
            if (!msg) {
                ACVP_LOG_ERR("Missing 'message' from server json");
                rv = ACVP_MISSING_ARG;
                json_value_free(r_tval);
                goto err;
            }
            json_msglen = strnlen_s(msg, ACVP_RSA_MSGLEN_MAX + 1);
            if (json_msglen > ACVP_RSA_MSGLEN_MAX) {
                ACVP_LOG_ERR("'message' too long in server json");
                rv = ACVP_INVALID_ARG;
                json_value_free(r_tval);
                goto err;
            }
            ACVP_LOG_VERBOSE("              msg: %s", msg);



            rv = acvp_rsa_sigprim_init_tc(ctx, &stc, tc_id,
                                          mod, keyformat,
                                          d_str, e_str,
                                          n_str, msg);

            /* Process the current test vector... */
            if (rv == ACVP_SUCCESS) {
                if ((cap->crypto_handler)(&tc)) {
                    ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_rsa_sigprim_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_rsa_sigprim_release_tc(&stc);

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
        acvp_rsa_sigprim_release_tc(&stc);
        acvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}

