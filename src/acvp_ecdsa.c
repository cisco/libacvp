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

static ACVP_RESULT acvp_ecdsa_kat_handler_internal(ACVP_CTX *ctx, JSON_Object *obj, ACVP_CIPHER cipher);


/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_ecdsa_output_tc(ACVP_CTX *ctx, ACVP_CIPHER cipher, ACVP_ECDSA_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv;
    char *tmp = NULL;

    tmp = calloc(ACVP_ECDSA_EXP_LEN_MAX + 1, sizeof(char));

    if (cipher == ACVP_ECDSA_KEYGEN) {
        rv = acvp_bin_to_hexstr(stc->qy, stc->qy_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (qy)");
            goto err;
        }
        json_object_set_string(tc_rsp, "qy", (const char *)tmp);
        memzero_s(tmp, ACVP_ECDSA_EXP_LEN_MAX);

        rv = acvp_bin_to_hexstr(stc->qx, stc->qx_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (qx)");
            goto err;
        }
        json_object_set_string(tc_rsp, "qx", (const char *)tmp);
        memzero_s(tmp, ACVP_ECDSA_EXP_LEN_MAX);

        rv = acvp_bin_to_hexstr(stc->d, stc->d_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (d)");
            goto err;
        }
        json_object_set_string(tc_rsp, "d", (const char *)tmp);
        memzero_s(tmp, ACVP_ECDSA_EXP_LEN_MAX);
    }
    if (cipher == ACVP_ECDSA_KEYVER || cipher == ACVP_ECDSA_SIGVER) {
        json_object_set_boolean(tc_rsp, "testPassed", stc->ver_disposition);
    }
    if (cipher == ACVP_ECDSA_SIGGEN) {
        rv = acvp_bin_to_hexstr(stc->r, stc->r_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (r)");
            goto err;
        }
        json_object_set_string(tc_rsp, "r", (const char *)tmp);
        memzero_s(tmp, ACVP_ECDSA_EXP_LEN_MAX);

        rv = acvp_bin_to_hexstr(stc->s, stc->s_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (s)");
            goto err;
        }
        json_object_set_string(tc_rsp, "s", (const char *)tmp);
        memzero_s(tmp, ACVP_ECDSA_EXP_LEN_MAX);
    }

err:
    free(tmp);
    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */

static ACVP_RESULT acvp_ecdsa_release_tc(ACVP_ECDSA_TC *stc) {
    if (stc->qy) { free(stc->qy); }
    if (stc->qx) { free(stc->qx); }
    if (stc->d) { free(stc->d); }
    if (stc->r) { free(stc->r); }
    if (stc->s) { free(stc->s); }
    if (stc->message) { free(stc->message); }
    memzero_s(stc, sizeof(ACVP_ECDSA_TC));

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_ecdsa_init_tc(ACVP_CTX *ctx,
                                      ACVP_CIPHER cipher,
                                      ACVP_ECDSA_TC *stc,
                                      int tg_id,
                                      unsigned int tc_id,
                                      ACVP_EC_CURVE curve,
                                      ACVP_ECDSA_SECRET_GEN_MODE secret_gen_mode,
                                      ACVP_HASH_ALG hash_alg,
                                      const char *qx,
                                      const char *qy,
                                      const char *message,
                                      const char *r,
                                      const char *s) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_ECDSA_TC));

    stc->tc_id = tc_id;
    stc->tg_id = tg_id;
    stc->cipher = cipher;
    stc->hash_alg = hash_alg;
    stc->curve = curve;
    stc->secret_gen_mode = secret_gen_mode;

    stc->qx = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->qx) { goto err; }
    stc->qy = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->qy) { goto err; }
    stc->d = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->d) { goto err; }
    stc->s = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->s) { goto err; }
    stc->r = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->r) { goto err; }
    stc->message = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->message) { goto err; }

    if (cipher == ACVP_ECDSA_KEYVER || cipher == ACVP_ECDSA_SIGVER) {
        if (!qx || !qy) return ACVP_MISSING_ARG;

        rv = acvp_hexstr_to_bin(qx, stc->qx, ACVP_RSA_EXP_LEN_MAX, &(stc->qx_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (qx)");
            return rv;
        }

        rv = acvp_hexstr_to_bin(qy, stc->qy, ACVP_RSA_EXP_LEN_MAX, &(stc->qy_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (qy)");
            return rv;
        }
    }
    if (cipher == ACVP_ECDSA_SIGVER) {
        if (!r || !s) return ACVP_MISSING_ARG;

        rv = acvp_hexstr_to_bin(r, stc->r, ACVP_RSA_EXP_LEN_MAX, &(stc->r_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (r)");
            return rv;
        }

        rv = acvp_hexstr_to_bin(s, stc->s, ACVP_RSA_EXP_LEN_MAX, &(stc->s_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (s)");
            return rv;
        }
    }
    if (cipher == ACVP_ECDSA_SIGVER || cipher == ACVP_ECDSA_SIGGEN) {
        if (!message) return ACVP_MISSING_ARG;

        rv = acvp_hexstr_to_bin(message, stc->message, ACVP_RSA_MSGLEN_MAX, &(stc->msg_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (message)");
            return rv;
        }
    }

    return ACVP_SUCCESS;

err:
    ACVP_LOG_ERR("Failed to allocate buffer in ECDSA test case");
    if (stc->qx) free(stc->qx);
    if (stc->qy) free(stc->qy);
    if (stc->r) free(stc->r);
    if (stc->s) free(stc->s);
    if (stc->d) free(stc->d);
    if (stc->message) free(stc->message);
    return ACVP_MALLOC_FAIL;
}

ACVP_RESULT acvp_ecdsa_keygen_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_ecdsa_kat_handler_internal(ctx, obj, ACVP_ECDSA_KEYGEN);
}

ACVP_RESULT acvp_ecdsa_keyver_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_ecdsa_kat_handler_internal(ctx, obj, ACVP_ECDSA_KEYVER);
}

ACVP_RESULT acvp_ecdsa_siggen_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_ecdsa_kat_handler_internal(ctx, obj, ACVP_ECDSA_SIGGEN);
}

ACVP_RESULT acvp_ecdsa_sigver_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_ecdsa_kat_handler_internal(ctx, obj, ACVP_ECDSA_SIGVER);
}

static ACVP_ECDSA_SECRET_GEN_MODE read_secret_gen_mode(const char *str) {
    int diff = 1;

    strcmp_s(ACVP_ECDSA_EXTRA_BITS_STR,
             ACVP_ECDSA_EXTRA_BITS_STR_LEN,
             str, &diff);
    if (!diff) return ACVP_ECDSA_SECRET_GEN_EXTRA_BITS;

    strcmp_s(ACVP_ECDSA_TESTING_CANDIDATES_STR,
             ACVP_ECDSA_TESTING_CANDIDATES_STR_LEN,
             str, &diff);
    if (!diff) return ACVP_ECDSA_SECRET_GEN_TEST_CAND;

    return 0;
}

static ACVP_RESULT acvp_ecdsa_kat_handler_internal(ACVP_CTX *ctx, JSON_Object *obj, ACVP_CIPHER cipher) {
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
    ACVP_ECDSA_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;

    ACVP_CIPHER alg_id;
    char *json_result = NULL;
    const char *alg_str, *mode_str, *qx = NULL, *qy = NULL, *r = NULL, *s = NULL, *message = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    memzero_s(&stc, sizeof(ACVP_ECDSA_TC));
    tc.tc.ecdsa = &stc;
    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("Server JSON missing 'mode_str'");
        return ACVP_MALFORMED_JSON;
    }

    alg_id = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != cipher) {
        ACVP_LOG_ERR("Server JSON invalid algorithm or mode");
        return ACVP_INVALID_ARG;
    }

    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ERROR: ACVP server requesting unsupported capability");
        return ACVP_UNSUPPORTED_OP;
    }
    ACVP_LOG_VERBOSE("    ECDSA mode: %s", mode_str);

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
    if (!groups) {
        ACVP_LOG_ERR("Missing testGroups from server JSON");
        rv = ACVP_MALFORMED_JSON;
        goto err;
    }
    g_cnt = json_array_get_count(groups);

    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        ACVP_HASH_ALG hash_alg = 0;
        ACVP_EC_CURVE curve = 0;
        ACVP_ECDSA_SECRET_GEN_MODE secret_gen_mode = 0;
        const char *hash_alg_str = NULL, *curve_str = NULL,
                   *secret_gen_mode_str = NULL;

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
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        /*
         * Get a reference to the abstracted test case
         */
        curve_str = json_object_get_string(groupobj, "curve");
        if (!curve_str) {
            ACVP_LOG_ERR("Server JSON missing 'curve'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        curve = acvp_lookup_ec_curve(alg_id, curve_str);
        if (!curve) {
            ACVP_LOG_ERR("Server JSON includes unrecognized curve");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        if (alg_id == ACVP_ECDSA_KEYGEN) {
            secret_gen_mode_str = json_object_get_string(groupobj, "secretGenerationMode");
            if (!secret_gen_mode_str) {
                ACVP_LOG_ERR("Server JSON missing 'secretGenerationMode'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            secret_gen_mode = read_secret_gen_mode(secret_gen_mode_str);
            if (!secret_gen_mode) {
                ACVP_LOG_ERR("Server JSON invalid 'secretGenerationMode'");
                rv = ACVP_INVALID_ARG;
                goto err;
            }
        } else if (alg_id == ACVP_ECDSA_SIGGEN || alg_id == ACVP_ECDSA_SIGVER) {
            hash_alg_str = json_object_get_string(groupobj, "hashAlg");
            if (!hash_alg_str) {
                ACVP_LOG_ERR("Server JSON missing 'hashAlg'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            hash_alg = acvp_lookup_hash_alg(hash_alg_str);
            if (!hash_alg || (alg_id == ACVP_ECDSA_SIGGEN && hash_alg == ACVP_SHA1)) {
                ACVP_LOG_ERR("Server JSON invalid 'hashAlg'");
                rv = ACVP_INVALID_ARG;
                goto err;
            }
        }

        ACVP_LOG_VERBOSE("           Test group: %d", i);
        ACVP_LOG_VERBOSE("                curve: %s", curve_str);
        ACVP_LOG_VERBOSE(" secretGenerationMode: %s", secret_gen_mode_str);
        ACVP_LOG_VERBOSE("              hashAlg: %s", hash_alg_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        if (!t_cnt) {
            ACVP_LOG_ERR("Test array count is zero");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_VERBOSE("Found new ECDSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            if (alg_id == ACVP_ECDSA_KEYVER || alg_id == ACVP_ECDSA_SIGVER) {
                qx = json_object_get_string(testobj, "qx");
                qy = json_object_get_string(testobj, "qy");
                if (!qx || !qy) {
                    ACVP_LOG_ERR("Server JSON missing 'qx' or 'qy'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(qx, ACVP_ECDSA_EXP_LEN_MAX + 1) > ACVP_ECDSA_EXP_LEN_MAX ||
                    strnlen_s(qy, ACVP_ECDSA_EXP_LEN_MAX + 1) > ACVP_ECDSA_EXP_LEN_MAX) {
                    ACVP_LOG_ERR("'qx' or 'qy' too long");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }
            if (alg_id == ACVP_ECDSA_SIGGEN || alg_id == ACVP_ECDSA_SIGVER) {
                message = json_object_get_string(testobj, "message");
                if (!message) {
                    ACVP_LOG_ERR("Server JSON missing 'message'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(message, ACVP_ECDSA_MSGLEN_MAX + 1) > ACVP_ECDSA_MSGLEN_MAX) {
                    ACVP_LOG_ERR("message string too long");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }
            if (alg_id == ACVP_ECDSA_SIGVER) {
                r = json_object_get_string(testobj, "r");
                s = json_object_get_string(testobj, "s");
                if (!r || !s) {
                    ACVP_LOG_ERR("Server JSON missing 'r' or 's'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(r, ACVP_ECDSA_EXP_LEN_MAX + 1) > ACVP_ECDSA_EXP_LEN_MAX ||
                    strnlen_s(s, ACVP_ECDSA_EXP_LEN_MAX + 1) > ACVP_ECDSA_EXP_LEN_MAX) {
                    ACVP_LOG_ERR("'r' or 's' too long");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            rv = acvp_ecdsa_init_tc(ctx, alg_id, &stc, tgId, tc_id, curve, secret_gen_mode, hash_alg, qx, qy, message, r, s);

            /* Process the current test vector... */
            if (rv == ACVP_SUCCESS) {
                if ((cap->crypto_handler)(&tc)) {
                    ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }
            } else {
                ACVP_LOG_ERR("Failed to initialize ECDSA test case");
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            if (cipher == ACVP_ECDSA_SIGGEN) {
                char *tmp = calloc(ACVP_ECDSA_EXP_LEN_MAX + 1, sizeof(char));
                rv = acvp_bin_to_hexstr(stc.qy, stc.qy_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("hex conversion failure (qy)");
                    free(tmp);
                    json_value_free(r_tval);
                    goto err;
                }
                json_object_set_string(r_gobj, "qy", (const char *)tmp);
                memzero_s(tmp, ACVP_ECDSA_EXP_LEN_MAX);

                rv = acvp_bin_to_hexstr(stc.qx, stc.qx_len, tmp, ACVP_ECDSA_EXP_LEN_MAX);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("hex conversion failure (qx)");
                    free(tmp);
                    json_value_free(r_tval);
                    goto err;
                }
                json_object_set_string(r_gobj, "qx", (const char *)tmp);
                memzero_s(tmp, ACVP_ECDSA_EXP_LEN_MAX);
                free(tmp);
            }
            rv = acvp_ecdsa_output_tc(ctx, alg_id, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                json_value_free(r_tval);
                goto err;
            }

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);

            /*
             * Release all the memory associated with the test case
             */
            acvp_ecdsa_release_tc(&stc);
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
        acvp_ecdsa_release_tc(&stc);
        acvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}
