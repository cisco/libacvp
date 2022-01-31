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

/*
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_kdf_tls13_output_tc(ACVP_CTX *ctx, ACVP_KDF_TLS13_TC *stc, JSON_Object *tc_rsp);

static ACVP_RESULT acvp_kdf_tls13_init_tc(ACVP_CTX *ctx,
                                           ACVP_KDF_TLS13_TC *stc,
                                           unsigned int tc_id,
                                           ACVP_CIPHER alg_id,
                                           ACVP_KDF_TLS13_TESTTYPE type,
                                           ACVP_KDF_TLS13_RUN_MODE run_mode,
                                           ACVP_HASH_ALG hmac,
                                           const char *psk,
                                           const char *dhe,
                                           const char *sh_rnd,
                                           const char *ch_rnd,
                                           const char *s_fin_rnd,
                                           const char *c_fin_rnd);

static ACVP_RESULT acvp_kdf_tls13_release_tc(ACVP_KDF_TLS13_TC *stc);


static ACVP_KDF_TLS13_RUN_MODE read_run_mode(const char *str) {
    int diff = 0;

    strcmp_s(ACVP_STR_KDF_TLS13_PSK, sizeof(ACVP_STR_KDF_TLS13_PSK) -1, str, &diff);
    if (!diff) return ACVP_KDF_TLS13_RUN_MODE_PSK;
    strcmp_s(ACVP_STR_KDF_TLS13_DHE, sizeof(ACVP_STR_KDF_TLS13_DHE) -1, str, &diff);
    if (!diff) return ACVP_KDF_TLS13_RUN_MODE_DHE;
    strcmp_s(ACVP_STR_KDF_TLS13_PSK_DHE, sizeof(ACVP_STR_KDF_TLS13_PSK_DHE) -1, str, &diff);
    if (!diff) return ACVP_KDF_TLS13_RUN_MODE_PSK_DHE;

    return 0;
}

static ACVP_KDF_TLS13_TESTTYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return ACVP_KDF_TLS13_TEST_TYPE_AFT;

    return 0;
}


ACVP_RESULT acvp_kdf_tls13_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
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
    ACVP_KDF_TLS13_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    const char *mode_str = NULL;
    const char *hmac_str = NULL;
    const char *run_str = NULL;
    const char *type_str = NULL;
    ACVP_CIPHER alg_id;
    ACVP_KDF_TLS13_TESTTYPE type = 0;
    ACVP_HASH_ALG hmac = 0;
    ACVP_KDF_TLS13_RUN_MODE runmode = 0;
    char *json_result;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("unable to parse 'mode' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    alg_id = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != ACVP_KDF_TLS13) {
        ACVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return ACVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf_tls13 = &stc;

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
        goto err;
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
            ACVP_LOG_ERR("Missing testType from server JSON group obj");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        type = read_test_type(type_str);
        if (!type) {
            ACVP_LOG_ERR("Invalid testType from server JSON group obj");
            rv = ACVP_MALFORMED_JSON;
            goto err;
        }

        hmac_str = json_object_get_string(groupobj, "hmacAlg");
        if (!hmac_str) {
            ACVP_LOG_ERR("Missing hmacAlg from server JSON group obj");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        hmac = acvp_lookup_hash_alg(hmac_str);
        if (!hmac) {
            ACVP_LOG_ERR("Invalid hmacAlg from server JSON group obj");
            rv = ACVP_MALFORMED_JSON;
            goto err;
        }

        run_str = json_object_get_string(groupobj, "runningMode");
        if (!run_str) {
            ACVP_LOG_ERR("Missing runningMode from server JSON group obj");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        runmode = read_run_mode(run_str);
        if (!runmode) {
            ACVP_LOG_ERR("Invalid runningMode from server JSON group obj");
            rv = ACVP_MALFORMED_JSON;
            goto err;
        }

        ACVP_LOG_VERBOSE("       Test group: %d", i);
        ACVP_LOG_VERBOSE("          hmacAlg: %s", hmac_str);
        ACVP_LOG_VERBOSE("      runningMode: %s", run_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            const char *psk = NULL;
            const char *dhe = NULL;
            const char *sh_rnd = NULL;
            const char *ch_rnd = NULL;
            const char *s_fin_rnd = NULL;
            const char *c_fin_rnd = NULL;
            
            ACVP_LOG_VERBOSE("Found new TLS 1.3 test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");
            if (!tc_id) {
                ACVP_LOG_ERR("Server json missing 'tcId");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            if (runmode == ACVP_KDF_TLS13_RUN_MODE_PSK || runmode == ACVP_KDF_TLS13_RUN_MODE_PSK_DHE) {
                psk = json_object_get_string(testobj, "psk");
                if (!psk) {
                    ACVP_LOG_ERR("Server json missing 'psk'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
            }

            if (runmode == ACVP_KDF_TLS13_RUN_MODE_DHE || runmode == ACVP_KDF_TLS13_RUN_MODE_PSK_DHE) {
                dhe = json_object_get_string(testobj, "dhe");
                if (!dhe) {
                    ACVP_LOG_ERR("Server json missing 'dhe'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
            }


            sh_rnd = json_object_get_string(testobj, "helloServerRandom");
            if (!sh_rnd) {
                ACVP_LOG_ERR("Failed to include helloServeroRandom");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            ch_rnd = json_object_get_string(testobj, "helloClientRandom");
            if (!ch_rnd) {
                ACVP_LOG_ERR("Failed to include helloClientoRandom");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            s_fin_rnd = json_object_get_string(testobj, "finishedServerRandom");
            if (!s_fin_rnd) {
                ACVP_LOG_ERR("Failed to include finishedServerRandom");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            c_fin_rnd = json_object_get_string(testobj, "finishedClientRandom");
            if (!c_fin_rnd) {
                ACVP_LOG_ERR("Failed to include finishedClientRandom");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            ACVP_LOG_VERBOSE("        Test case: %d", j);
            ACVP_LOG_VERBOSE("             tcId: %d", tc_id);
            if (psk) {
                ACVP_LOG_VERBOSE("              psk: %s", psk);
            }
            if (dhe) {
                ACVP_LOG_VERBOSE("              dhe: %s", dhe);
            }
            ACVP_LOG_VERBOSE("  serverHelloRand: %s", sh_rnd);
            ACVP_LOG_VERBOSE("  clientHelloRand: %s", ch_rnd);
            ACVP_LOG_VERBOSE("    serverFinRand: %s", s_fin_rnd);
            ACVP_LOG_VERBOSE("    clientFinRand: %s", c_fin_rnd);

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
            rv = acvp_kdf_tls13_init_tc(ctx, &stc, tc_id, alg_id, type, runmode, hmac, psk, dhe, sh_rnd,
                                        ch_rnd, s_fin_rnd, c_fin_rnd);
            if (rv != ACVP_SUCCESS) {
                acvp_kdf_tls13_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("crypto module failed the operation");
                acvp_kdf_tls13_release_tc(&stc);
                rv = ACVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kdf_tls13_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in hash module");
                acvp_kdf_tls13_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_kdf_tls13_release_tc(&stc);

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
static ACVP_RESULT acvp_kdf_tls13_output_tc(ACVP_CTX *ctx, ACVP_KDF_TLS13_TC *stc, JSON_Object *tc_rsp) {
    char *tmp = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;

    tmp = calloc(1, ACVP_KDF_TLS13_DATA_LEN_STR_MAX + 1);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_kdf_tls13_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    //append client early traffic secret 
    if (stc->cets_len > ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX) {
        ACVP_LOG_ERR("Provided length for test case output too long: cets_len");
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    rv = acvp_bin_to_hexstr(stc->c_early_traffic_secret, stc->cets_len, tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (client early traffic secret)");
        goto err;
    }
    json_object_set_string(tc_rsp, "clientEarlyTrafficSecret", tmp);
    memzero_s(tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);

    //append early export master secret
    if (stc->eems_len > ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX) {
        ACVP_LOG_ERR("Provided length for test case output too long: eems_len");
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    rv = acvp_bin_to_hexstr(stc->early_expt_master_secret, stc->eems_len, tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (early export master secret)");
        goto err;
    }
    json_object_set_string(tc_rsp, "earlyExporterMasterSecret", tmp);
    memzero_s(tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);

    //append client handshake traffic secret
    if (stc->chts_len > ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX) {
        ACVP_LOG_ERR("Provided length for test case output too long: chts_len");
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    rv = acvp_bin_to_hexstr(stc->c_hs_traffic_secret, stc->chts_len, tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (client handshake traffic secret)");
        goto err;
    }
    json_object_set_string(tc_rsp, "clientHandshakeTrafficSecret", tmp);
    memzero_s(tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);

    //append server handshake traffic secret
    if (stc->shts_len > ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX) {
        ACVP_LOG_ERR("Provided length for test case output too long: shts_len");
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    rv = acvp_bin_to_hexstr(stc->s_hs_traffic_secret, stc->shts_len, tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (server handshake traffic secret)");
        goto err;
    }
    json_object_set_string(tc_rsp, "serverHandshakeTrafficSecret", tmp);
    memzero_s(tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);

    //append client app traffic secret
    if (stc->cats_len > ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX) {
        ACVP_LOG_ERR("Provided length for test case output too long: cats_len");
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    rv = acvp_bin_to_hexstr(stc->c_app_traffic_secret, stc->cats_len, tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (client app traffic secret)");
        goto err;
    }
    json_object_set_string(tc_rsp, "clientApplicationTrafficSecret", tmp);
    memzero_s(tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);


    //append server app traffic secret
    if (stc->sats_len > ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX) {
        ACVP_LOG_ERR("Provided length for test case output too long: sats_len");
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    rv = acvp_bin_to_hexstr(stc->s_app_traffic_secret, stc->sats_len, tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (server app traffic secret)");
        goto err;
    }
    json_object_set_string(tc_rsp, "serverApplicationTrafficSecret", tmp);
    memzero_s(tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);


    //append exporter master secret
    if (stc->ems_len > ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX) {
        ACVP_LOG_ERR("Provided length for test case output too long: ems_len");
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    rv = acvp_bin_to_hexstr(stc->expt_master_secret, stc->ems_len, tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (exporter master secret)");
        goto err;
    }
    json_object_set_string(tc_rsp, "exporterMasterSecret", tmp);
    memzero_s(tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);

    //append resumption master secret
    if (stc->rms_len > ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX) {
        ACVP_LOG_ERR("Provided length for test case output too long: rms_len");
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    rv = acvp_bin_to_hexstr(stc->resume_master_secret, stc->rms_len, tmp, ACVP_KDF_TLS13_DATA_LEN_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (resumption master secret)");
        goto err;
    }
    json_object_set_string(tc_rsp, "resumptionMasterSecret", tmp);

err:
    free(tmp);

    return rv;
}

static ACVP_RESULT acvp_kdf_tls13_init_tc(ACVP_CTX *ctx,
                                           ACVP_KDF_TLS13_TC *stc,
                                           unsigned int tc_id,
                                           ACVP_CIPHER alg_id,
                                           ACVP_KDF_TLS13_TESTTYPE type,
                                           ACVP_KDF_TLS13_RUN_MODE run_mode,
                                           ACVP_HASH_ALG hmac,
                                           const char *psk,
                                           const char *dhe,
                                           const char *s_hello_rand,
                                           const char *c_hello_rand,
                                           const char *fin_s_hello_rand,
                                           const char *fin_c_hello_rand) {
    ACVP_RESULT rv;

    memzero_s(stc, sizeof(ACVP_KDF_TLS13_TC));

    stc->tc_id = tc_id;
    stc->cipher = alg_id;
    stc->test_type = type;
    stc->running_mode = run_mode;
    stc->hmac_alg = hmac;

    stc->psk = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->psk) { return ACVP_MALLOC_FAIL; }
    if (psk) {
        rv = acvp_hexstr_to_bin(psk, stc->psk, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX, &(stc->psk_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (psk)");
            return rv;
        }
    } else {
        //either SHA256 or SHA384
        if (hmac == ACVP_SHA256) {
            stc->psk_len = 32;
        } else {
            stc->psk_len = 48;
        }
    }

    stc->dhe = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->dhe) { return ACVP_MALLOC_FAIL; }
    if (dhe) {
        rv = acvp_hexstr_to_bin(dhe, stc->dhe, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX, &(stc->dhe_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (s_hello_rand)");
            return rv;
        }
    } else {
        //either SHA256 or SHA384
        if (hmac == ACVP_SHA256) {
            stc->dhe_len = 32;
        } else {
            stc->dhe_len = 48;
        }
    }


    stc->c_hello_rand = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->c_hello_rand) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(c_hello_rand, stc->c_hello_rand, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX, &(stc->c_hello_rand_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (c_hello_rand)");
        return rv;
    }

    stc->s_hello_rand = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->s_hello_rand) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(s_hello_rand, stc->s_hello_rand, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX, &(stc->s_hello_rand_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (s_hello_rand)");
        return rv;
    }

    stc->fin_c_hello_rand = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->fin_c_hello_rand) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(fin_c_hello_rand, stc->fin_c_hello_rand, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX, &(stc->fin_c_hello_rand_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (fin_c_hello_rand)");
        return rv;
    }

    stc->fin_s_hello_rand = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->fin_s_hello_rand) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(fin_s_hello_rand, stc->fin_s_hello_rand, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX, &(stc->fin_s_hello_rand_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (fin_s_hello_rand)");
        return rv;
    }

    stc->c_early_traffic_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->c_early_traffic_secret) { return ACVP_MALLOC_FAIL; }
    stc->early_expt_master_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->early_expt_master_secret) { return ACVP_MALLOC_FAIL; }
    stc->c_hs_traffic_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->c_hs_traffic_secret) { return ACVP_MALLOC_FAIL; }
    stc->s_hs_traffic_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->s_hs_traffic_secret) { return ACVP_MALLOC_FAIL; }
    stc->c_app_traffic_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->c_app_traffic_secret) { return ACVP_MALLOC_FAIL; }
    stc->s_app_traffic_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->s_app_traffic_secret) { return ACVP_MALLOC_FAIL; }
    stc->expt_master_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->expt_master_secret) { return ACVP_MALLOC_FAIL; }
    stc->resume_master_secret = calloc(1, ACVP_KDF_TLS13_DATA_LEN_BYTE_MAX);
    if (!stc->resume_master_secret) { return ACVP_MALLOC_FAIL; }

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf_tls13_release_tc(ACVP_KDF_TLS13_TC *stc) {
    if (stc->psk) free(stc->psk);
    if (stc->dhe) free(stc->dhe);
    if (stc->c_hello_rand) free(stc->c_hello_rand);
    if (stc->s_hello_rand) free(stc->s_hello_rand);
    if (stc->fin_c_hello_rand) free(stc->fin_c_hello_rand);
    if (stc->fin_s_hello_rand) free(stc->fin_s_hello_rand);
    if (stc->c_early_traffic_secret) free(stc->c_early_traffic_secret);
    if (stc->early_expt_master_secret) free(stc->early_expt_master_secret);
    if (stc->c_hs_traffic_secret) free(stc->c_hs_traffic_secret);
    if (stc->s_hs_traffic_secret) free(stc->s_hs_traffic_secret);
    if (stc->c_app_traffic_secret) free(stc->c_app_traffic_secret);
    if (stc->s_app_traffic_secret) free(stc->s_app_traffic_secret);
    if (stc->expt_master_secret) free(stc->expt_master_secret);
    if (stc->resume_master_secret) free(stc->resume_master_secret);

    memzero_s(stc, sizeof(ACVP_KDF_TLS13_TC));
    return ACVP_SUCCESS;
}
;
