/** @file */
/*
 * Copyright (c) 2024, Cisco Systems, Inc.
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
static ACVP_RESULT acvp_slh_dsa_output_tc(ACVP_CTX *ctx, ACVP_CIPHER cipher, ACVP_SLH_DSA_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv;
    ACVP_SUB_SLH_DSA mode;
    char *tmp = NULL;

    mode = acvp_get_slh_dsa_alg(cipher);
    if (!mode) {
        return ACVP_INTERNAL_ERR;
    }

    tmp = calloc(ACVP_SLH_DSA_SIG_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Error allocating memory to output SLH-DSA test case");
        rv = ACVP_MALLOC_FAIL;
        goto end;
    }

    switch (mode) {
    case ACVP_SUB_SLH_DSA_KEYGEN:
        memzero_s(tmp, ACVP_SLH_DSA_SIG_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->pub_key, stc->pub_key_len, tmp, ACVP_SLH_DSA_SIG_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (pk)");
            goto end;
        }
        json_object_set_string(tc_rsp, "pk", tmp);

        memzero_s(tmp, ACVP_SLH_DSA_SIG_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->secret_key, stc->secret_key_len, tmp, ACVP_SLH_DSA_SIG_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (sk)");
            goto end;
        }
        json_object_set_string(tc_rsp, "sk", tmp);
        break;
    case ACVP_SUB_SLH_DSA_SIGGEN:
        rv = acvp_bin_to_hexstr(stc->sig, stc->sig_len, tmp, ACVP_SLH_DSA_SIG_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (signature)");
            goto end;
        }
        json_object_set_string(tc_rsp, "signature", tmp);
        break;
    case ACVP_SUB_SLH_DSA_SIGVER:
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

static ACVP_RESULT acvp_slh_dsa_release_tc(ACVP_SLH_DSA_TC *stc) {
    if (stc->pub_key) free(stc->pub_key);
    if (stc->secret_key) free(stc->secret_key);
    if (stc->secret_seed) free(stc->secret_seed);
    if (stc->secret_prf) free(stc->secret_prf);
    if (stc->pub_seed) free(stc->pub_seed);
    if (stc->rnd) free(stc->rnd);
    if (stc->msg) free(stc->msg);
    if (stc->sig) free(stc->sig);
    if (stc->context) free(stc->context);
    memzero_s(stc, sizeof(ACVP_SLH_DSA_TC));

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_slh_dsa_init_tc(ACVP_CTX *ctx,
                                    ACVP_SLH_DSA_TC *stc,
                                    ACVP_CIPHER cipher,
                                    int tc_id,
                                    int tg_id,
                                    ACVP_SLH_DSA_PARAM_SET param_set,
                                    int is_deterministic,
                                    ACVP_SIG_INTERFACE sig_interface,
                                    int is_prehash,
                                    ACVP_HASH_ALG hash_alg,
                                    const char *pub_key,
                                    const char *secret_key,
                                    const char *secret_seed,
                                    const char *secret_prf,
                                    const char *pub_seed,
                                    const char *rnd,
                                    const char *msg,
                                    const char *sig,
                                    const char *context) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_SLH_DSA_TC));

    stc->tc_id = tc_id;
    stc->tg_id = tg_id;
    stc->cipher = cipher;
    stc->param_set = param_set;
    stc->is_deterministic = is_deterministic;
    stc->sig_interface = sig_interface;
    stc->is_prehash = is_prehash;
    stc->hash_alg = hash_alg;

    stc->pub_key = calloc(ACVP_SLH_DSA_KEY_BYTE_MAX, sizeof(unsigned char));
    if (!stc->pub_key) {
        goto err;
    }
    if (cipher == ACVP_SLH_DSA_SIGVER && pub_key) {
        rv = acvp_hexstr_to_bin(pub_key, stc->pub_key, ACVP_SLH_DSA_KEY_BYTE_MAX, &(stc->pub_key_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (pk)");
            return rv;
        }
    }

    stc->secret_key = calloc(ACVP_SLH_DSA_KEY_BYTE_MAX, sizeof(unsigned char));
    if (!stc->secret_key) {
        goto err;
    }
    if (cipher == ACVP_SLH_DSA_SIGGEN && secret_key) {
        rv = acvp_hexstr_to_bin(secret_key, stc->secret_key, ACVP_SLH_DSA_KEY_BYTE_MAX, &(stc->secret_key_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (sk)");
            return rv;
        }
    }

    if (cipher == ACVP_SLH_DSA_SIGGEN && rnd) {
        stc->rnd = calloc(ACVP_SLH_DSA_SEED_BYTE_MAX, sizeof(unsigned char));
        if (!stc->rnd) {
            goto err;
        }
        rv = acvp_hexstr_to_bin(rnd, stc->rnd, ACVP_SLH_DSA_SEED_BYTE_MAX, &(stc->rnd_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (rnd)");
            return rv;
        }
    }

    if (cipher == ACVP_SLH_DSA_KEYGEN) {
        stc->secret_seed = calloc(ACVP_SLH_DSA_SEED_BYTE_MAX, sizeof(unsigned char));
        if (!stc->secret_seed) {
            goto err;
        }
        rv = acvp_hexstr_to_bin(secret_seed, stc->secret_seed, ACVP_SLH_DSA_SEED_BYTE_MAX, &(stc->secret_seed_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (secret_seed)");
            return rv;
        }

        stc->secret_prf = calloc(ACVP_SLH_DSA_SEED_BYTE_MAX, sizeof(unsigned char));
        if (!stc->secret_prf) {
            goto err;
        }
        rv = acvp_hexstr_to_bin(secret_prf, stc->secret_prf, ACVP_SLH_DSA_SEED_BYTE_MAX, &(stc->secret_prf_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (secret_prf)");
            return rv;
        }

        stc->pub_seed = calloc(ACVP_SLH_DSA_SEED_BYTE_MAX, sizeof(unsigned char));
        if (!stc->pub_seed) {
            goto err;
        }
        rv = acvp_hexstr_to_bin(pub_seed, stc->pub_seed, ACVP_SLH_DSA_SEED_BYTE_MAX, &(stc->pub_seed_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (pub_seed)");
            return rv;
        }
    }

    if (cipher == ACVP_SLH_DSA_SIGGEN || cipher == ACVP_SLH_DSA_SIGVER) {
        stc->msg = calloc(ACVP_SLH_DSA_MSG_BYTE_MAX, sizeof(unsigned char));
        if (!stc->msg) {
            goto err;
        }
        rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_SLH_DSA_MSG_BYTE_MAX, &(stc->msg_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (msg)");
            return rv;
        }
    }

    if (cipher == ACVP_SLH_DSA_SIGGEN || cipher == ACVP_SLH_DSA_SIGVER) {
        stc->sig = calloc(ACVP_SLH_DSA_SIG_BYTE_MAX, sizeof(unsigned char));
        if (!stc->sig) {
            goto err;
        }
        if (cipher == ACVP_SLH_DSA_SIGVER) {
            rv = acvp_hexstr_to_bin(sig, stc->sig, ACVP_SLH_DSA_SIG_BYTE_MAX, &(stc->sig_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (sig)");
                return rv;
            }
        }

        if (sig_interface == ACVP_SIG_INTERFACE_EXTERNAL) {
            stc->context = calloc(ACVP_SLH_DSA_CTX_BYTE_MAX, sizeof(unsigned char));
            if (!stc->context) {
                goto err;
            }
            rv = acvp_hexstr_to_bin(context, stc->context, ACVP_SLH_DSA_CTX_BYTE_MAX, &(stc->context_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (context)");
                return rv;
            }
        }
    }

    return ACVP_SUCCESS;

err:
    ACVP_LOG_ERR("Failed to allocate buffer in SLH-DSA test case");
    return ACVP_MALLOC_FAIL;
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

ACVP_RESULT acvp_slh_dsa_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_SLH_DSA_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;

    ACVP_CIPHER alg_id;
    char *json_result = NULL;

    ACVP_SLH_DSA_PARAM_SET param_set = 0;
    const char *alg_str = NULL, *mode_str = NULL, *param_set_str = NULL,  *pub_str = NULL;
    const char *secret_seed_str = NULL, *secret_prf_str = NULL, *pub_seed_str = NULL, *msg_str = NULL,
               *sig_str = NULL, *secret_str = NULL, *rnd_str = NULL, *context_str = NULL, *sig_interface_str = NULL,
               *prehash_str = NULL, *hash_alg_str = NULL;
    int is_deterministic = -1, is_prehash = -1;
    ACVP_SIG_INTERFACE sig_interface = ACVP_SIG_INTERFACE_NOT_SET;
    ACVP_HASH_ALG hash_alg = ACVP_NO_SHA;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    memzero_s(&stc, sizeof(ACVP_SLH_DSA_TC));
    tc.tc.slh_dsa = &stc;
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
        ACVP_LOG_ERR("ERROR: ACVP server requesting unsupported capability");
        return ACVP_UNSUPPORTED_OP;
    }
    ACVP_LOG_VERBOSE("    SLH-DSA mode: %s", mode_str);

    /* Create ACVP array for response */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("ERROR: Failed to create JSON response struct.");
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

        param_set_str = json_object_get_string(groupobj, "parameterSet");
        if (!param_set_str) {
            ACVP_LOG_ERR("Server JSON missing 'parameterSet'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        param_set = acvp_lookup_slh_dsa_param_set(param_set_str);
        if (!param_set) {
            ACVP_LOG_ERR("Server JSON invalid 'parameterSet'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        if (alg_id == ACVP_SLH_DSA_SIGGEN) {
            if (!json_object_has_value(groupobj, "deterministic")) {
                ACVP_LOG_ERR("Server JSON missing 'deterministic'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
            is_deterministic = json_object_get_boolean(groupobj, "deterministic");
        }

        if (alg_id == ACVP_SLH_DSA_SIGGEN || alg_id == ACVP_SLH_DSA_SIGVER) {
            sig_interface_str = json_object_get_string(groupobj, "signatureInterface");
            if (!sig_interface_str) {
                ACVP_LOG_ERR("Server JSON missing 'signatureInterface'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
            sig_interface = read_sig_interface(sig_interface_str);
            if (sig_interface == ACVP_SIG_INTERFACE_NOT_SET) {
                ACVP_LOG_ERR("Server JSON invalid 'signatureInterface'");
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            if (sig_interface == ACVP_SIG_INTERFACE_EXTERNAL) {
                prehash_str = json_object_get_string(groupobj, "preHash");
                if (!prehash_str) {
                    ACVP_LOG_ERR("Server JSON missing 'preHash'");
                    rv = ACVP_MISSING_ARG;
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
            }
        }

        ACVP_LOG_VERBOSE("           Test group: %d", i);
        if (param_set_str) {
            ACVP_LOG_VERBOSE("            param set: %s", param_set_str);
        }
        if (alg_id == ACVP_SLH_DSA_SIGGEN) {
            ACVP_LOG_VERBOSE("     is deterministic: %s", is_deterministic ? "yes" : "no");
        }

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        if (!t_cnt) {
            ACVP_LOG_ERR("Test array count is zero");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_VERBOSE("Found new SLH-DSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            if (alg_id == ACVP_SLH_DSA_KEYGEN) {
                secret_seed_str = json_object_get_string(testobj, "skSeed");
                if (!secret_seed_str) {
                    ACVP_LOG_ERR("Server JSON missing 'skSeed'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }

                secret_prf_str = json_object_get_string(testobj, "skPrf");
                if (!secret_seed_str) {
                    ACVP_LOG_ERR("Server JSON missing 'skPrf'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }

                pub_seed_str = json_object_get_string(testobj, "pkSeed");
                if (!pub_seed_str) {
                    ACVP_LOG_ERR("Server JSON missing 'pkSeed'");
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

                if (sig_interface == ACVP_SIG_INTERFACE_EXTERNAL && is_prehash == 1) {
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
            }

            if (alg_id == ACVP_SLH_DSA_SIGVER) {
                pub_str = json_object_get_string(testobj, "pk");
                if (!pub_str) {
                    ACVP_LOG_ERR("Server JSON missing 'pk'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }

                sig_str = json_object_get_string(testobj, "signature");
                if (!sig_str) {
                    ACVP_LOG_ERR("Server JSON missing 'signature'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
            }

            if (alg_id== ACVP_SLH_DSA_SIGGEN) {
                secret_str = json_object_get_string(testobj, "sk");
                if (!secret_str) {
                    ACVP_LOG_ERR("Server JSON missing 'sk'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }

                if (!is_deterministic) {
                    rnd_str = json_object_get_string(testobj, "additionalRandomness");
                    if (!rnd_str) {
                        ACVP_LOG_ERR("Server JSON missing 'rnd'");
                        rv = ACVP_MISSING_ARG;
                        goto err;
                    }
                }
            }

            if ((alg_id == ACVP_SLH_DSA_SIGGEN || alg_id == ACVP_SLH_DSA_SIGVER) && sig_interface == ACVP_SIG_INTERFACE_EXTERNAL) {
                context_str = json_object_get_string(testobj, "context");
                if (!context_str) {
                    ACVP_LOG_ERR("Server JSON missing 'context'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            if (secret_seed_str) {
                ACVP_LOG_VERBOSE("      secret seed: %s", secret_seed_str);
            }
            if (secret_prf_str) {
                ACVP_LOG_VERBOSE("       secret prf: %s", secret_prf_str);
            }
            if (pub_seed_str) {
                ACVP_LOG_VERBOSE("         pub seed: %s", pub_seed_str);
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

            /* Create a new test case in the response */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            rv = acvp_slh_dsa_init_tc(ctx, &stc, alg_id, tc_id, tg_id, param_set, is_deterministic, sig_interface,
                                      is_prehash, hash_alg, pub_str, secret_str, secret_seed_str, secret_prf_str,
                                      pub_seed_str, rnd_str, msg_str, sig_str, context_str);

            /* Process the current test vector... */
            if (rv == ACVP_SUCCESS) {
                if ((cap->crypto_handler)(&tc)) {
                    ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }
            } else {
                ACVP_LOG_ERR("Failed to initialize SLH-DSA test case");
                json_value_free(r_tval);
                goto err;
            }

            /* Output the test case results using JSON */
            rv = acvp_slh_dsa_output_tc(ctx, alg_id, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                json_value_free(r_tval);
                goto err;
            }

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);

            /* Release all the memory associated with the test case */
            acvp_slh_dsa_release_tc(&stc);
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
        acvp_slh_dsa_release_tc(&stc);
        acvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}
