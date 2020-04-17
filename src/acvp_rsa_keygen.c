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
static ACVP_RESULT acvp_rsa_output_tc(ACVP_CTX *ctx, ACVP_RSA_KEYGEN_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_RSA_EXP_LEN_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_kdf135 tpm_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(stc->p, stc->p_len, tmp, ACVP_RSA_EXP_LEN_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (p)");
        goto err;
    }
    json_object_set_string(tc_rsp, "p", (const char *)tmp);
    memzero_s(tmp, ACVP_RSA_EXP_LEN_MAX);

    rv = acvp_bin_to_hexstr(stc->q, stc->q_len, tmp, ACVP_RSA_EXP_LEN_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (q)");
        goto err;
    }
    json_object_set_string(tc_rsp, "q", (const char *)tmp);
    memzero_s(tmp, ACVP_RSA_EXP_LEN_MAX);

    rv = acvp_bin_to_hexstr(stc->n, stc->n_len, tmp, ACVP_RSA_EXP_LEN_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (n)");
        goto err;
    }
    json_object_set_string(tc_rsp, "n", (const char *)tmp);
    memzero_s(tmp, ACVP_RSA_EXP_LEN_MAX);

    rv = acvp_bin_to_hexstr(stc->d, stc->d_len, tmp, ACVP_RSA_EXP_LEN_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (d)");
        goto err;
    }
    json_object_set_string(tc_rsp, "d", (const char *)tmp);
    memzero_s(tmp, ACVP_RSA_EXP_LEN_MAX);

    rv = acvp_bin_to_hexstr(stc->e, stc->e_len, tmp, ACVP_RSA_EXP_LEN_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (e)");
        goto err;
    }
    json_object_set_string(tc_rsp, "e", (const char *)tmp);

    if (stc->key_format == ACVP_RSA_KEY_FORMAT_CRT) {
        rv = acvp_bin_to_hexstr(stc->xp, stc->xp_len, tmp, ACVP_RSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (xp)");
            goto err;
        }
        json_object_set_string(tc_rsp, "xP", (const char *)tmp);
        memzero_s(tmp, ACVP_RSA_EXP_LEN_MAX);

        rv = acvp_bin_to_hexstr(stc->xp1, stc->xp1_len, tmp, ACVP_RSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (xp1)");
            goto err;
        }
        json_object_set_string(tc_rsp, "xP1", (const char *)tmp);
        memzero_s(tmp, ACVP_RSA_EXP_LEN_MAX);

        rv = acvp_bin_to_hexstr(stc->xp2, stc->xp2_len, tmp, ACVP_RSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (xp2)");
            goto err;
        }
        json_object_set_string(tc_rsp, "xP2", (const char *)tmp);
        memzero_s(tmp, ACVP_RSA_EXP_LEN_MAX);

        rv = acvp_bin_to_hexstr(stc->xq, stc->xq_len, tmp, ACVP_RSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (xq)");
            goto err;
        }
        json_object_set_string(tc_rsp, "xQ", (const char *)tmp);
        memzero_s(tmp, ACVP_RSA_EXP_LEN_MAX);

        rv = acvp_bin_to_hexstr(stc->xq1, stc->xq1_len, tmp, ACVP_RSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (xq1)");
            goto err;
        }
        json_object_set_string(tc_rsp, "xQ1", (const char *)tmp);
        memzero_s(tmp, ACVP_RSA_EXP_LEN_MAX);

        rv = acvp_bin_to_hexstr(stc->xq2, stc->xq2_len, tmp, ACVP_RSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (xq2)");
            goto err;
        }
        json_object_set_string(tc_rsp, "xQ2", (const char *)tmp);
        memzero_s(tmp, ACVP_RSA_EXP_LEN_MAX);
    }

    if (stc->info_gen_by_server) {
        if (stc->rand_pq == ACVP_RSA_KEYGEN_B33 ||
            stc->rand_pq == ACVP_RSA_KEYGEN_B35 ||
            stc->rand_pq == ACVP_RSA_KEYGEN_B36) {
            json_object_set_string(tc_rsp, "primeResult", (const char *)stc->prime_result);
        }
    } else {
        if (!(stc->rand_pq == ACVP_RSA_KEYGEN_B33)) {
            rv = acvp_bin_to_hexstr(stc->seed, stc->seed_len, tmp, ACVP_RSA_SEEDLEN_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (seed)");
                goto err;
            }
            json_object_set_string(tc_rsp, "seed", (const char *)tmp);
            memzero_s(tmp, ACVP_RSA_EXP_LEN_MAX);

            json_object_set_value(tc_rsp, "bitlens", json_value_init_array());
            JSON_Array *bitlens_array = json_object_get_array(tc_rsp, "bitlens");
            json_array_append_number(bitlens_array, stc->bitlen1);
            json_array_append_number(bitlens_array, stc->bitlen2);
            json_array_append_number(bitlens_array, stc->bitlen3);
            json_array_append_number(bitlens_array, stc->bitlen4);
        }
    }

err:
    if (tmp) free(tmp);

    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */

static ACVP_RESULT acvp_rsa_keygen_release_tc(ACVP_RSA_KEYGEN_TC *stc) {
    if (stc->e) { free(stc->e); }
    if (stc->seed) { free(stc->seed); }
    if (stc->p) { free(stc->p); }
    if (stc->q) { free(stc->q); }
    if (stc->n) { free(stc->n); }
    if (stc->d) { free(stc->d); }
    memzero_s(stc, sizeof(ACVP_RSA_KEYGEN_TC));

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_rsa_keygen_init_tc(ACVP_CTX *ctx,
                                           ACVP_RSA_KEYGEN_TC *stc,
                                           unsigned int tc_id,
                                           int info_gen_by_server,
                                           ACVP_HASH_ALG hash_alg,
                                           ACVP_RSA_KEY_FORMAT key_format,
                                           ACVP_RSA_PUB_EXP_MODE pub_exp_mode,
                                           int modulo,
                                           ACVP_RSA_PRIME_TEST_TYPE prime_test,
                                           int rand_pq,
                                           const char *e,
                                           const char *seed,
                                           int seed_len,
                                           int bitlen1,
                                           int bitlen2,
                                           int bitlen3,
                                           int bitlen4) {
    memzero_s(stc, sizeof(ACVP_RSA_KEYGEN_TC));
    ACVP_RESULT rv = ACVP_SUCCESS;
    stc->info_gen_by_server = info_gen_by_server;
    stc->tc_id = tc_id;
    stc->rand_pq = rand_pq;
    stc->modulo = modulo;
    stc->prime_test = prime_test;
    stc->hash_alg = hash_alg;
    stc->pub_exp_mode = pub_exp_mode;
    stc->key_format = key_format;

    stc->e = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->e) { return ACVP_MALLOC_FAIL; }
    stc->p = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->p) { return ACVP_MALLOC_FAIL; }
    stc->q = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->q) { return ACVP_MALLOC_FAIL; }
    stc->n = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->n) { return ACVP_MALLOC_FAIL; }
    stc->d = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->d) { return ACVP_MALLOC_FAIL; }

    rv = acvp_hexstr_to_bin(e, stc->e, ACVP_RSA_EXP_BYTE_MAX, &(stc->e_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (e)");
        return rv;
    }

    stc->seed = calloc(ACVP_RSA_SEEDLEN_MAX, sizeof(unsigned char));
    if (!stc->seed) { return ACVP_MALLOC_FAIL; }

    if (info_gen_by_server) {
        stc->bitlen1 = bitlen1;
        stc->bitlen2 = bitlen2;
        stc->bitlen3 = bitlen3;
        stc->bitlen4 = bitlen4;
        if (seed) {
            rv = acvp_hexstr_to_bin(seed, stc->seed, seed_len, &(stc->seed_len));
            if (rv != ACVP_SUCCESS) {
                return rv;
            }
        }
    }

    return ACVP_SUCCESS;
}

static ACVP_RSA_PUB_EXP_MODE read_pub_exp_mode(const char *str){
    int diff = 1;

    strcmp_s(ACVP_RSA_PUB_EXP_MODE_FIXED_STR,
             ACVP_RSA_PUB_EXP_MODE_FIXED_STR_LEN, str, &diff);
    if (!diff) return ACVP_RSA_PUB_EXP_MODE_FIXED;

    strcmp_s(ACVP_RSA_PUB_EXP_MODE_RANDOM_STR,
             ACVP_RSA_PUB_EXP_MODE_RANDOM_STR_LEN, str, &diff);
    if (!diff) return ACVP_RSA_PUB_EXP_MODE_RANDOM;

    return 0;
}

static ACVP_RSA_KEY_FORMAT read_key_format(const char *str){
    int diff = 1;

    strcmp_s(ACVP_RSA_KEY_FORMAT_STD_STR,
             ACVP_RSA_KEY_FORMAT_STD_STR_LEN, str, &diff);
    if (!diff) return ACVP_RSA_KEY_FORMAT_STANDARD;

    strcmp_s(ACVP_RSA_KEY_FORMAT_CRT_STR,
             ACVP_RSA_KEY_FORMAT_CRT_STR_LEN, str, &diff);
    if (!diff) return ACVP_RSA_KEY_FORMAT_CRT;

    return 0;
}

static ACVP_RSA_PRIME_TEST_TYPE read_prime_test_type(const char *str) {
    int diff = 1;

    strcmp_s(ACVP_RSA_PRIME_TEST_TBLC2_STR,
             ACVP_RSA_PRIME_TEST_TBLC2_STR_LEN, str, &diff);
    if (!diff) return ACVP_RSA_PRIME_TEST_TBLC2;

    strcmp_s(ACVP_RSA_PRIME_TEST_TBLC3_STR,
             ACVP_RSA_PRIME_TEST_TBLC3_STR_LEN, str, &diff);
    if (!diff) return ACVP_RSA_PRIME_TEST_TBLC3;

    return 0;
}

ACVP_RESULT acvp_rsa_keygen_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    unsigned int tc_id;
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *groups;
    JSON_Array *tests;
    JSON_Array *bitlens;

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
    ACVP_RSA_KEYGEN_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;

    ACVP_CIPHER alg_id;
    char *json_result = NULL;
    unsigned int mod = 0;
    int info_gen_by_server, rand_pq, seed_len = 0;
    ACVP_HASH_ALG hash_alg = 0;
    ACVP_RSA_PRIME_TEST_TYPE prime_test = 0;
    ACVP_RSA_PUB_EXP_MODE pub_exp_mode = 0;
    ACVP_RSA_KEY_FORMAT key_format = 0;
    const char *e_str = NULL, *alg_str = NULL, *mode_str, *hash_alg_str = NULL,
               *seed = NULL, *pub_exp_mode_str = NULL, *key_format_str = NULL,
               *rand_pq_str = NULL, *prime_test_str = NULL;
    int bitlen1 = 0, bitlen2 = 0, bitlen3 = 0, bitlen4 = 0;

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
    if (alg_id != ACVP_RSA_KEYGEN) {
        ACVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return ACVP_INVALID_ARG;
    }

    tc.tc.rsa_keygen = &stc;
    memzero_s(&stc, sizeof(ACVP_RSA_KEYGEN_TC));

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

        info_gen_by_server = json_object_get_boolean(groupobj, "infoGeneratedByServer");
        if (info_gen_by_server == -1) {
            ACVP_LOG_ERR("Server JSON missing 'infoGeneratedByServer'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        pub_exp_mode_str = json_object_get_string(groupobj, "pubExp");
        if (!pub_exp_mode_str) {
            ACVP_LOG_ERR("Server JSON missing 'pubExpMode'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        pub_exp_mode = read_pub_exp_mode(pub_exp_mode_str);
        if (!pub_exp_mode) {
            ACVP_LOG_ERR("Server JSON invalid 'pubExpMode'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        if (pub_exp_mode == ACVP_RSA_PUB_EXP_MODE_FIXED) {
            e_str = json_object_get_string(groupobj, "fixedPubExp");
            if (!e_str) {
                ACVP_LOG_ERR("Server JSON missing 'fixedPubExp'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
        }

        key_format_str = json_object_get_string(groupobj, "keyFormat");
        if (!key_format_str) {
            ACVP_LOG_ERR("Server JSON missing 'keyFormat'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        key_format = read_key_format(key_format_str);
        if (!key_format) {
            ACVP_LOG_ERR("Server JSON invalid 'keyFormat'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        rand_pq_str = json_object_get_string(groupobj, "randPQ");
        if (!rand_pq_str) {
            ACVP_LOG_ERR("Server JSON missing 'randPQ'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        rand_pq = acvp_lookup_rsa_randpq_index(rand_pq_str);
        if (rand_pq == 0) {
            ACVP_LOG_ERR("Server JSON invalid randPQ");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        if (rand_pq == ACVP_RSA_KEYGEN_B33 ||
            rand_pq == ACVP_RSA_KEYGEN_B35 ||
            rand_pq == ACVP_RSA_KEYGEN_B36) {
            prime_test_str = json_object_get_string(groupobj, "primeTest");
            if (!prime_test_str) {
                ACVP_LOG_ERR("Server JSON missing 'primeTest'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            prime_test = read_prime_test_type(prime_test_str);
            if (!prime_test) {
                ACVP_LOG_ERR("Server JSON invalid 'primeTest'");
                rv = ACVP_INVALID_ARG;
                goto err;
            }
        }

        mod = json_object_get_number(groupobj, "modulo");
        if (!mod) {
            ACVP_LOG_ERR("Server JSON missing 'modulo'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        if (mod != 2048 && mod != 3072 && mod != 4096) {
            ACVP_LOG_ERR("Server JSON invalid 'modulo', (%d)", mod);
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        if (rand_pq == ACVP_RSA_KEYGEN_B32 ||
            rand_pq == ACVP_RSA_KEYGEN_B34 ||
            rand_pq == ACVP_RSA_KEYGEN_B35) {
            hash_alg_str = json_object_get_string(groupobj, "hashAlg");
            if (!hash_alg_str) {
                ACVP_LOG_ERR("Server JSON missing 'hashAlg'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
            hash_alg = acvp_lookup_hash_alg(hash_alg_str);
            if (!hash_alg) {
                ACVP_LOG_ERR("Server JSON invalid 'hashAlg'");
                rv = ACVP_INVALID_ARG;
                goto err;
            }
        }

        ACVP_LOG_VERBOSE("    Test group: %d", i);
        ACVP_LOG_VERBOSE("  infoGenByServer: %s", info_gen_by_server ? "true" : "false");
        ACVP_LOG_VERBOSE("       pubExpMode: %s", pub_exp_mode_str);
        ACVP_LOG_VERBOSE("        keyFormat: %s", key_format_str);
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

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Retrieve values from JSON and initialize the tc
             */
            if (info_gen_by_server) {
                unsigned int count = 0;

                if (!e_str) {
                    e_str = json_object_get_string(testobj, "e");
                    if (!e_str) {
                        ACVP_LOG_ERR("Server JSON missing 'e'");
                        rv = ACVP_MISSING_ARG;
                        json_value_free(r_tval);
                        goto err;
                    }
                    if (strnlen_s(e_str, ACVP_RSA_EXP_LEN_MAX + 1)
                        > ACVP_RSA_EXP_LEN_MAX) {
                        ACVP_LOG_ERR("'e' too long, max allowed=(%d)",
                                     ACVP_RSA_EXP_LEN_MAX);
                        rv = ACVP_INVALID_ARG;
                        json_value_free(r_tval);
                        goto err;
                    }
                }

                bitlens = json_object_get_array(testobj, "bitlens");
                count = json_array_get_count(bitlens);
                if (count != 4) {
                    ACVP_LOG_ERR("Server JSON 'bitlens' list count is (%u). Expected (%u)",
                                 count, 4);
                    rv = ACVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                bitlen1 = json_array_get_number(bitlens, 0);
                bitlen2 = json_array_get_number(bitlens, 1);
                bitlen3 = json_array_get_number(bitlens, 2);
                bitlen4 = json_array_get_number(bitlens, 3);

                seed = json_object_get_string(testobj, "seed");
                if (!seed) {
                    ACVP_LOG_ERR("Server JSON missing 'seed'");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                seed_len = strnlen_s(seed, ACVP_RSA_SEEDLEN_MAX + 1);
                if (seed_len > ACVP_RSA_SEEDLEN_MAX) {
                    ACVP_LOG_ERR("'seed' too long, max allowed=(%d)",
                                 ACVP_RSA_SEEDLEN_MAX);
                    rv = ACVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
            }

            rv = acvp_rsa_keygen_init_tc(ctx, &stc, tc_id, info_gen_by_server, hash_alg, key_format,
                                         pub_exp_mode, mod, prime_test, rand_pq, e_str, seed, seed_len,
                                         bitlen1, bitlen2, bitlen3, bitlen4);

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
            rv = acvp_rsa_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_rsa_keygen_release_tc(&stc);

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
        acvp_rsa_keygen_release_tc(&stc);
        acvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}
