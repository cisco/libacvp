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
static ACVP_RESULT acvp_ml_dsa_output_tc(ACVP_CTX *ctx, ACVP_CIPHER cipher, ACVP_ML_DSA_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv;
    ACVP_SUB_ML_DSA mode;
    char *tmp = NULL;

    mode = acvp_get_ml_dsa_alg(cipher);
    if (!mode) {
        return ACVP_INTERNAL_ERR;
    }

    tmp = calloc(ACVP_ML_DSA_MSG_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Error allocating memory to output ML-DSA test case");
        rv = ACVP_MALLOC_FAIL;
        goto end;
    }

    switch (mode) {
    case ACVP_SUB_ML_DSA_KEYGEN:
        memzero_s(tmp, ACVP_ML_DSA_MSG_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->pub_key, stc->pub_key_len, tmp, ACVP_ML_DSA_MSG_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (pk)");
            goto end;
        }
        json_object_set_string(tc_rsp, "pk", tmp);

        memzero_s(tmp, ACVP_ML_DSA_MSG_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->secret_key, stc->secret_key_len, tmp, ACVP_ML_DSA_MSG_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (sk)");
            goto end;
        }
        json_object_set_string(tc_rsp, "sk", tmp);
        break;
    case ACVP_SUB_ML_DSA_SIGGEN:
        /* This also needs pk in the test group response for GDT, handled elsewhere */
        rv = acvp_bin_to_hexstr(stc->sig, stc->sig_len, tmp, ACVP_ML_DSA_MSG_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (signature)");
            goto end;
        }
        json_object_set_string(tc_rsp, "signature", tmp);
        break;
    case ACVP_SUB_ML_DSA_SIGVER:
        json_object_set_boolean(tc_rsp, "testPassed", stc->ver_disposition);
        rv = ACVP_SUCCESS;
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

static ACVP_RESULT acvp_ml_dsa_release_tc(ACVP_ML_DSA_TC *stc) {
    if (stc->pub_key) free(stc->pub_key);
    if (stc->secret_key) free(stc->secret_key);
    if (stc->seed) free(stc->seed);
    if (stc->rnd) free(stc->rnd);
    if (stc->msg) free(stc->msg);
    if (stc->sig) free(stc->sig);
    if (stc->mu) free(stc->mu);
    if (stc->context) free(stc->context);
    memzero_s(stc, sizeof(ACVP_ML_DSA_TC));

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_ml_dsa_init_tc(ACVP_CTX *ctx,
                                    ACVP_ML_DSA_TC *stc,
                                    ACVP_CIPHER cipher,
                                    int tc_id,
                                    int tg_id,
                                    ACVP_ML_DSA_TESTTYPE type,
                                    ACVP_ML_DSA_PARAM_SET param_set,
                                    int is_deterministic,
                                    ACVP_SIG_INTERFACE sig_interface,
                                    int is_prehash,
                                    int is_mu_external,
                                    ACVP_HASH_ALG hash_alg,
                                    const char *pub_key,
                                    const char *secret_key,
                                    const char *seed,
                                    const char *rnd,
                                    const char *msg,
                                    const char *sig,
                                    const char *context,
                                    const char *mu) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_ML_DSA_TC));

    stc->tc_id = tc_id;
    stc->tg_id = tg_id;
    stc->cipher = cipher;
    stc->type = type;
    stc->param_set = param_set;
    stc->is_deterministic = is_deterministic;
    stc->sig_interface = sig_interface;
    /* The below values are only used in certain combinations of capabilities */
    stc->is_prehash = is_prehash;
    stc->is_mu_external = is_mu_external;
    stc->hash_alg = hash_alg;

    /* buffers needed for both keys and sigs */
    stc->pub_key = calloc(ACVP_ML_DSA_MSG_BYTE_MAX, sizeof(unsigned char));
    if (!stc->pub_key) {
        goto err;
    }
    stc->secret_key = calloc(ACVP_ML_DSA_MSG_BYTE_MAX, sizeof(unsigned char));
    if (!stc->secret_key) {
        goto err;
    }

    /* pub_key buffer only filled for sigver, output for other two */
    if (cipher == ACVP_ML_DSA_SIGVER) {
        rv = acvp_hexstr_to_bin(pub_key, stc->pub_key, ACVP_ML_DSA_MSG_BYTE_MAX, &(stc->pub_key_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (pk)");
            return rv;
        }
    }

    /* Seed for keyGen only */
    if (cipher == ACVP_ML_DSA_KEYGEN) {
        stc->seed = calloc(ACVP_ML_DSA_MSG_BYTE_MAX, sizeof(unsigned char));
        if (!stc->seed) {
            goto err;
        }
        rv = acvp_hexstr_to_bin(seed, stc->seed, ACVP_ML_DSA_MSG_BYTE_MAX, &(stc->seed_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (seed)");
            return rv;
        }
    }


    /* secret_key (aka sk) only provided for siggen for AFT */
    if (cipher == ACVP_ML_DSA_SIGGEN && secret_key) {
        rv = acvp_hexstr_to_bin(secret_key, stc->secret_key, ACVP_ML_DSA_MSG_BYTE_MAX, &(stc->secret_key_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (sk)");
            return rv;
        }
    }

    /* rnd only for siggen, for AFT tests, when deterministic = false */
    if (cipher == ACVP_ML_DSA_SIGGEN && rnd) {
        stc->rnd = calloc(ACVP_ML_DSA_MSG_BYTE_MAX, sizeof(unsigned char));
        if (!stc->rnd) {
            goto err;
        }
        rv = acvp_hexstr_to_bin(rnd, stc->rnd, ACVP_ML_DSA_MSG_BYTE_MAX, &(stc->rnd_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (rnd)");
            return rv;
        }
    }

    /**
     * msg provided for both siggen and sigver, UNLESS sig interface and mu are both internal
     * sig buffer needed for both, but value only provided for sigver
     * context provided if sig interface is external
     * mu is provided for both, IF the sig interface is internal and mu is not
     */
    if (cipher == ACVP_ML_DSA_SIGGEN || cipher == ACVP_ML_DSA_SIGVER) {
        if (!(sig_interface == ACVP_SIG_INTERFACE_INTERNAL && is_mu_external)) {
            stc->msg = calloc(ACVP_ML_DSA_MSG_BYTE_MAX, sizeof(unsigned char));
            if (!stc->msg) {
                goto err;
            }
            rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_ML_DSA_MSG_BYTE_MAX, &(stc->msg_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (msg)");
                return rv;
            }
        }

        stc->sig = calloc(ACVP_ML_DSA_MSG_BYTE_MAX, sizeof(unsigned char));
        if (!stc->sig) {
            goto err;
        }
        if (cipher == ACVP_ML_DSA_SIGVER) {
            rv = acvp_hexstr_to_bin(sig, stc->sig, ACVP_ML_DSA_MSG_BYTE_MAX, &(stc->sig_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (sig)");
                return rv;
            }
        }

        if (sig_interface == ACVP_SIG_INTERFACE_EXTERNAL) {
            stc->context = calloc(ACVP_ML_DSA_MSG_BYTE_MAX, sizeof(unsigned char));
            if (!stc->context) {
                goto err;
            }
            rv = acvp_hexstr_to_bin(context, stc->context, ACVP_ML_DSA_MSG_BYTE_MAX, &(stc->context_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (context)");
                return rv;
            }
        } else if (is_mu_external) {
            stc->mu = calloc(ACVP_ML_DSA_MSG_BYTE_MAX, sizeof(unsigned char));
            if (!stc->mu) {
                goto err;
            }
            rv = acvp_hexstr_to_bin(mu, stc->mu, ACVP_ML_DSA_MSG_BYTE_MAX, &(stc->mu_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (mu)");
                return rv;
            }
        }
    }

    return ACVP_SUCCESS;

err:
    ACVP_LOG_ERR("Failed to allocate buffer in ML-DSA test case");
    return ACVP_MALLOC_FAIL;
}


static ACVP_ML_DSA_TESTTYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return ACVP_ML_DSA_TESTTYPE_AFT;

    return 0;
}

static ACVP_SIG_INTERFACE read_sig_interface(const char *str) {
    int diff = 0;

    strcmp_s("internal", 8, str, &diff);
    if (!diff) { return ACVP_SIG_INTERFACE_INTERNAL; }
    strcmp_s("external", 8, str, &diff);
    if (!diff) { return ACVP_SIG_INTERFACE_EXTERNAL; }

    return ACVP_SIG_INTERFACE_NOT_SET;
}

static ACVP_SIG_PREHASH read_prehash(const char *str) {
    int diff = 0;

    strcmp_s("pure", 4, str, &diff);
    if (!diff) return ACVP_SIG_PREHASH_NO;
    strcmp_s("preHash", 7, str, &diff);
    if (!diff) return ACVP_SIG_PREHASH_YES;

    return ACVP_SIG_PREHASH_NOT_SET;
}

ACVP_RESULT acvp_ml_dsa_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
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
    JSON_Array *r_tarr = NULL, *r_garr = NULL;  /* Response testarray, grouparray */
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    ACVP_CAPS_LIST *cap = NULL;
    ACVP_ML_DSA_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;

    ACVP_CIPHER alg_id;
    char *json_result = NULL;

    ACVP_ML_DSA_TESTTYPE type = 0;
    ACVP_ML_DSA_PARAM_SET param_set = 0;
    ACVP_SIG_INTERFACE sig_interface = 0;
    const char *alg_str = NULL, *mode_str = NULL, *type_str = NULL, *param_set_str = NULL,  *pub_str = NULL;
    const char *seed_str = NULL, *msg_str = NULL, *sig_str = NULL, *secret_str = NULL, *rnd_str = NULL;
    const char *prehash_str = NULL, *sig_interface_str = NULL, *context_str = NULL, *mu_str = NULL, *hash_alg_str = NULL;
    int is_deterministic = -1, is_mu_external = -1, is_prehash = -1;
    ACVP_HASH_ALG hash_alg = ACVP_NO_SHA;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    memzero_s(&stc, sizeof(ACVP_ML_DSA_TC));
    tc.tc.ml_dsa = &stc;
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

    /* Create ACVP array for response */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct. ");
        return rv;
    }

    /* Start to build the JSON response */
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
            ACVP_LOG_ERR("Missing tgid from server JSON group obj");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tg_id);
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
            ACVP_LOG_ERR("invalid testType from server JSON");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        param_set_str = json_object_get_string(groupobj, "parameterSet");
        if (!param_set_str) {
            ACVP_LOG_ERR("Server JSON missing 'parameterSet'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        param_set = acvp_lookup_ml_dsa_param_set(param_set_str);
        if (!param_set) {
            ACVP_LOG_ERR("Server JSON invalid 'parameterSet'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        if (alg_id == ACVP_ML_DSA_SIGGEN || alg_id == ACVP_ML_DSA_SIGVER) {
            rv = acvp_get_tc_str_from_json(ctx, groupobj, "signatureInterface", &sig_interface_str);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            sig_interface = read_sig_interface(sig_interface_str);
            if (sig_interface == ACVP_SIG_INTERFACE_NOT_SET) {
                ACVP_LOG_ERR("Server JSON invalid 'signatureInterface'");
                goto err;
            }

            if (sig_interface == ACVP_SIG_INTERFACE_EXTERNAL) {
                rv = acvp_get_tc_str_from_json(ctx, groupobj, "preHash", &prehash_str);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }

                switch(read_prehash(prehash_str)) {
                case ACVP_SIG_PREHASH_NO:
                    is_prehash = 0;
                    break;
                case ACVP_SIG_PREHASH_YES:
                    is_prehash = 1;
                    break;
                case ACVP_SIG_PREHASH_NOT_SET:
                case ACVP_SIG_PREHASH_BOTH:
                default:
                    ACVP_LOG_ERR("Server JSON invalid 'preHash' value");
                    rv = ACVP_TC_INVALID_DATA;
                    goto err;
                }
            } else {
                if (json_object_has_value_of_type(groupobj, "externalMu", JSONBoolean)) {
                    is_mu_external = json_object_get_boolean(groupobj, "externalMu");
                } else {
                    if (json_object_has_value(groupobj, "externalMu")) {
                        ACVP_LOG_ERR("Server JSON invalid 'externalMu'");
                        rv = ACVP_TC_INVALID_DATA;
                        goto err;
                    } else {
                        ACVP_LOG_ERR("Server JSON missing 'externalMu'");
                        rv = ACVP_TC_MISSING_DATA;
                        goto err;
                    }
                }
            }
        }

        if (alg_id == ACVP_ML_DSA_SIGGEN) {
            if (!json_object_has_value(groupobj, "deterministic")) {
                ACVP_LOG_ERR("Server JSON missing 'deterministic'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
            is_deterministic = json_object_get_boolean(groupobj, "deterministic");
        }

        ACVP_LOG_VERBOSE("           Test group: %d", i + 1);
        ACVP_LOG_VERBOSE("            Test type: %s", type_str);
        if (param_set_str) {
            ACVP_LOG_VERBOSE("            param set: %s", param_set_str);
        }
        if (pub_str) {
            ACVP_LOG_VERBOSE("                   pk: %s", pub_str);
        }
        if (alg_id == ACVP_ML_DSA_SIGGEN || alg_id == ACVP_ML_DSA_SIGVER) {
            ACVP_LOG_VERBOSE("        sig_interface: %s", sig_interface_str);
            if (prehash_str) {
                ACVP_LOG_VERBOSE("             preHash: %s", prehash_str);
            }
            if (sig_interface == ACVP_SIG_INTERFACE_INTERNAL) {
                ACVP_LOG_VERBOSE("           externalMu: %s", is_mu_external ? "true" : "false");
            }
        }
        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        if (!t_cnt) {
            ACVP_LOG_ERR("Test array count is zero");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_VERBOSE("Found new ML-DSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            if (alg_id == ACVP_ML_DSA_KEYGEN) {
                seed_str = json_object_get_string(testobj, "seed");
                if (!seed_str) {
                    ACVP_LOG_ERR("Server JSON missing 'seed'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
            } else {
                if (sig_interface == ACVP_SIG_INTERFACE_INTERNAL && is_mu_external) {
                    mu_str = json_object_get_string(testobj, "mu");
                    if (!mu_str) {
                        ACVP_LOG_ERR("Server JSON missing 'mu'");
                        rv = ACVP_MISSING_ARG;
                        goto err;
                    }
                } else {
                    msg_str = json_object_get_string(testobj, "message");
                    if (!msg_str) {
                        ACVP_LOG_ERR("Server JSON missing 'message'");
                        rv = ACVP_MISSING_ARG;
                        goto err;
                    }
                }
            }

            if ((alg_id == ACVP_ML_DSA_SIGGEN || alg_id == ACVP_ML_DSA_SIGVER) && sig_interface == ACVP_SIG_INTERFACE_EXTERNAL && is_prehash == 1) {
                rv = acvp_get_tc_str_from_json(ctx, testobj, "hashAlg", &hash_alg_str);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }
                hash_alg = acvp_lookup_hash_alg(hash_alg_str);
                if (hash_alg == ACVP_NO_SHA) {
                    ACVP_LOG_ERR("Server JSON unknown 'hashAlg'");
                    rv = ACVP_TC_INVALID_DATA;
                    goto err;
                }
            }

            if ((alg_id == ACVP_ML_DSA_SIGGEN || alg_id == ACVP_ML_DSA_SIGVER) &&
                (sig_interface == ACVP_SIG_INTERFACE_EXTERNAL)) {
                rv = acvp_get_tc_str_from_json(ctx, testobj, "context", &context_str);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }
            }

            if (alg_id == ACVP_ML_DSA_SIGVER) {
                sig_str = json_object_get_string(testobj, "signature");
                if (!sig_str) {
                    ACVP_LOG_ERR("Server JSON missing 'signature'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }

                pub_str = json_object_get_string(testobj, "pk");
                if (!pub_str) {
                    ACVP_LOG_ERR("Server JSON missing 'pk'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
            }

            if (alg_id== ACVP_ML_DSA_SIGGEN) {
                secret_str = json_object_get_string(testobj, "sk");
                if (!secret_str) {
                    ACVP_LOG_ERR("Server JSON missing 'sk'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }

                if (!is_deterministic) {
                    rnd_str = json_object_get_string(testobj, "rnd");
                    if (!rnd_str) {
                        ACVP_LOG_ERR("Server JSON missing 'rnd'");
                        rv = ACVP_MISSING_ARG;
                        goto err;
                    }
                }
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            if (seed_str) {
                ACVP_LOG_VERBOSE("             seed: %s", seed_str);
            }
            if (msg_str) {
                ACVP_LOG_VERBOSE("          message: %s", msg_str);
            }
            if (sig_str) {
                ACVP_LOG_VERBOSE("        signature: %s", sig_str);
            }
            if (secret_str) {
                ACVP_LOG_VERBOSE("               sk: %s", secret_str);
            }
            if (pub_str) {
                ACVP_LOG_VERBOSE("               pk: %s", pub_str);
            }
            if (rnd_str) {
                ACVP_LOG_VERBOSE("              rnd: %s", rnd_str);
            }
            if (context_str) {
                ACVP_LOG_VERBOSE("          context: %s", context_str);
            }
            if (mu_str) {
                ACVP_LOG_VERBOSE("              mu: %s", mu_str);
            }

            /* Create a new test case in the response */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            rv = acvp_ml_dsa_init_tc(ctx, &stc, alg_id, tc_id, tg_id, type, param_set, is_deterministic,
                                     sig_interface, is_prehash, is_mu_external, hash_alg,
                                     pub_str, secret_str, seed_str, rnd_str, msg_str, sig_str, context_str, mu_str);

            /* Process the current test vector... */
            if (rv == ACVP_SUCCESS) {
                if ((cap->crypto_handler)(&tc)) {
                    ACVP_LOG_ERR("Crypto module failed the operation");
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }
            } else {
                ACVP_LOG_ERR("Failed to initialize ML-DSA test case");
                json_value_free(r_tval);
                goto err;
            }

            /* Output the test case results using JSON */

            rv = acvp_ml_dsa_output_tc(ctx, alg_id, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure recording test response");
                json_value_free(r_tval);
                goto err;
            }

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);

            /* Release all the memory associated with the test case */
            acvp_ml_dsa_release_tc(&stc);
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
        acvp_ml_dsa_release_tc(&stc);
        acvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}
