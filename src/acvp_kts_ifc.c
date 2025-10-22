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
 * After the test case has been processed by the DUT, the results
 * need to be JSON formatted to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_kts_ifc_output_tc(ACVP_CTX *ctx,
                                              ACVP_KTS_IFC_TC *stc,
                                              JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_KTS_IFC_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_output_mct_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->kts_role == ACVP_KTS_IFC_INITIATOR) {
        memzero_s(tmp, ACVP_KTS_IFC_STR_MAX);
        rv = acvp_bin_to_hexstr(stc->ct, stc->ct_len, tmp, ACVP_KTS_IFC_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (iutC)");
            goto end;
        }

        json_object_set_string(tc_rsp, "iutC", tmp);
    }

    memzero_s(tmp, ACVP_KTS_IFC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->pt, stc->pt_len, tmp, ACVP_KTS_IFC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (dkm)");
        goto end;
    }

    json_object_set_string(tc_rsp, "dkm", tmp);

end:
    if (tmp) free(tmp);

    return rv;
}

static ACVP_RESULT acvp_kts_ifc_init_tc(ACVP_CTX *ctx,
                                            ACVP_KTS_IFC_TC *stc,
                                            ACVP_KTS_IFC_KEYGEN key_gen,
                                            ACVP_HASH_ALG hash_alg,
                                            ACVP_KTS_IFC_ROLES role,
                                            const char *ct,
                                            const char *p,
                                            const char *q,
                                            const char *d,
                                            const char *n,
                                            const char *e,
                                            const char *dmp1,
                                            const char *dmq1,
                                            const char *iqmp,
                                            int modulo,
                                            int llen,
                                            ACVP_KTS_IFC_TEST_TYPE test_type) {
    ACVP_RESULT rv;

    stc->llen = llen / 8;
    stc->modulo = modulo;
    stc->test_type = test_type;
    stc->md = hash_alg;
    stc->kts_role = role;
    stc->key_gen = key_gen;

    stc->ct = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
    if (!stc->ct) { return ACVP_MALLOC_FAIL; }

    stc->pt = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
    if (!stc->pt) { return ACVP_MALLOC_FAIL; }

    // Both test types responder needs these
    if (stc->kts_role == ACVP_KTS_IFC_RESPONDER) {
        rv = acvp_hexstr_to_bin(ct, stc->ct, ACVP_KTS_IFC_BYTE_MAX, &(stc->ct_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (p)");
            return rv;
        }

        stc->p = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
        if (!stc->p) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(p, stc->p, ACVP_KTS_IFC_BYTE_MAX, &(stc->plen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (p)");
            return rv;
        }

        stc->q = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
        if (!stc->q) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(q, stc->q, ACVP_KTS_IFC_BYTE_MAX, &(stc->qlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (q)");
            return rv;
        }

        if (d) {
            stc->d = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
            if (!stc->d) { return ACVP_MALLOC_FAIL; }
            rv = acvp_hexstr_to_bin(d, stc->d, ACVP_KTS_IFC_BYTE_MAX, &(stc->dlen));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (d)");
                return rv;
            }
        }

        if (key_gen == ACVP_KTS_IFC_RSAKPG1_CRT || key_gen == ACVP_KTS_IFC_RSAKPG2_CRT) {
            stc->dmp1 = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
            if (!stc->dmp1) { return ACVP_MALLOC_FAIL; }
            rv = acvp_hexstr_to_bin(dmp1, stc->dmp1, ACVP_KTS_IFC_BYTE_MAX, &(stc->dmp1_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (dmp1)");
                return rv;
            }

            stc->dmq1 = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
            if (!stc->dmq1) { return ACVP_MALLOC_FAIL; }
            rv = acvp_hexstr_to_bin(dmq1, stc->dmq1, ACVP_KTS_IFC_BYTE_MAX, &(stc->dmq1_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (dmq1)");
                return rv;
            }

            stc->iqmp = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
            if (!stc->iqmp) { return ACVP_MALLOC_FAIL; }
            rv = acvp_hexstr_to_bin(iqmp, stc->iqmp, ACVP_KTS_IFC_BYTE_MAX, &(stc->iqmp_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (iqmp)");
                return rv;
            }
        }
    }

    // Both test types both roles needs these
    stc->n = calloc(1, ACVP_KTS_IFC_BYTE_MAX);
    if (!stc->n) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(n, stc->n, ACVP_KTS_IFC_BYTE_MAX, &(stc->nlen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (n)");
        return rv;
    }

    stc->e = calloc(1, ACVP_RSA_EXP_LEN_MAX);
    if (!stc->e) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(e, stc->e, ACVP_RSA_EXP_LEN_MAX, &(stc->elen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (e)");
        return rv;
    }

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kts_ifc_release_tc(ACVP_KTS_IFC_TC *stc) {
    if (stc->p) free(stc->p);
    if (stc->q) free(stc->q);
    if (stc->d) free(stc->d);
    if (stc->e) free(stc->e);
    if (stc->n) free(stc->n);
    if (stc->dmp1) free(stc->dmp1);
    if (stc->dmq1) free(stc->dmq1);
    if (stc->iqmp) free(stc->iqmp);
    if (stc->ct) free(stc->ct);
    if (stc->pt) free(stc->pt);
    memzero_s(stc, sizeof(ACVP_KTS_IFC_TC));
    return ACVP_SUCCESS;
}

static ACVP_KTS_IFC_TEST_TYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return ACVP_KTS_IFC_TT_AFT;

    strcmp_s("VAL", 3, str, &diff);
    if (!diff) return ACVP_KTS_IFC_TT_VAL;

    return 0;
}

static ACVP_KTS_IFC_KEYGEN read_key_gen(const char *str){
    int diff;

    strcmp_s("rsakpg1-basic", 13, str, &diff);
    if (!diff) return ACVP_KTS_IFC_RSAKPG1_BASIC;
    strcmp_s("rsakpg1-crt", 11, str, &diff);
    if (!diff) return ACVP_KTS_IFC_RSAKPG1_CRT;
    strcmp_s("rsakpg1-prime-factor", 20, str, &diff);
    if (!diff) return ACVP_KTS_IFC_RSAKPG1_PRIME_FACTOR;
    strcmp_s("rsakpg2-basic", 13, str, &diff);
    if (!diff) return ACVP_KTS_IFC_RSAKPG2_BASIC;
    strcmp_s("rsakpg2-crt", 11, str, &diff);
    if (!diff) return ACVP_KTS_IFC_RSAKPG2_CRT;
    strcmp_s("rsakpg2-prime-factor", 20, str, &diff);
    if (!diff) return ACVP_KTS_IFC_RSAKPG2_PRIME_FACTOR;

    return 0;
}

static ACVP_RESULT acvp_kts_ifc(ACVP_CTX *ctx,
                                    ACVP_CAPS_LIST *cap,
                                    ACVP_TEST_CASE *tc,
                                    ACVP_KTS_IFC_TC *stc,
                                    JSON_Object *obj,
                                    JSON_Array *r_garr) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Array *groups;
    JSON_Object *ktsobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *tests, *r_tarr = NULL;
    JSON_Value *r_tval = NULL, *r_gval = NULL;  // Response testval, groupval
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; // Response testobj, groupobj
    const char *p = NULL, *q = NULL, *n = NULL, *d = NULL, *e = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    const char *kts_role = NULL, *scheme = NULL, *hash = NULL;
    const char *ct = NULL;
    ACVP_HASH_ALG hash_alg;
    unsigned int modulo;
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id, diff, llen;
    ACVP_RESULT rv;
    const char *test_type_str, *key_gen_str = NULL, *kc_dir = NULL, *kc_role = NULL;
    const char *iut_id = NULL, *server_id = NULL, *encoding = NULL, *assoc_data = NULL;
    ACVP_KTS_IFC_TEST_TYPE test_type;
    ACVP_KTS_IFC_ROLES role = 0;
    ACVP_KTS_IFC_KEYGEN key_gen = 0;

    rv = acvp_tc_json_get_array(ctx, stc->cipher, obj, "testGroups", &groups);
    if (rv != ACVP_SUCCESS) {
        goto err;
    }
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
        rv = acvp_tc_json_get_int(ctx, stc->cipher, groupobj, "tgId", &tgId);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");


        rv = acvp_tc_json_get_string(ctx, stc->cipher, groupobj, "testType", &test_type_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        test_type = read_test_type(test_type_str);
        if (!test_type) {
            ACVP_LOG_ERR("Server JSON invalid 'testType'");
            rv = ACVP_INVALID_ARG;
            goto err;
        } else if (test_type != ACVP_KTS_IFC_TT_AFT) {
            ACVP_LOG_ERR("Server JSON invalid testType - only AFT tests are supported for KTS-IFC");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, stc->cipher, groupobj, "keyGenerationMethod", &key_gen_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        key_gen = read_key_gen(key_gen_str);
        if (!key_gen) {
            ACVP_LOG_ERR("Server JSON invalid 'key_gen'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, stc->cipher, groupobj, "scheme", &scheme);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, stc->cipher, groupobj, "kasRole", &kts_role);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        strcmp_s("initiator", 9, kts_role, &diff);
        if (!diff) role = ACVP_KTS_IFC_INITIATOR;
        strcmp_s("responder", 9, kts_role, &diff);
        if (!diff) role = ACVP_KTS_IFC_RESPONDER;

        rv = acvp_tc_json_get_string(ctx, stc->cipher, groupobj, "iutId", &iut_id);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, stc->cipher, groupobj, "serverId", &server_id);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        rv = acvp_tc_json_get_int(ctx, stc->cipher, groupobj, "modulo", &modulo);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        rv = acvp_tc_json_get_int(ctx, stc->cipher, groupobj, "l", &llen);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, stc->cipher, groupobj, "keyConfirmationDirection", &kc_dir);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, stc->cipher, groupobj, "keyConfirmationRole", &kc_role);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }


        ktsobj = json_object_get_object(groupobj, "ktsConfiguration");
        rv = acvp_tc_json_get_string(ctx, stc->cipher, ktsobj, "hashAlg", &hash);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        hash_alg = acvp_lookup_hash_alg(hash);
        if (!hash_alg) {
            ACVP_LOG_ERR("Server JSON invalid 'hashAlg'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, stc->cipher, ktsobj, "associatedDataPattern", &assoc_data);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, stc->cipher, ktsobj, "encoding", &encoding);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        if (!encoding) {
            ACVP_LOG_ERR("Server JSON invalid 'encoding'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        ACVP_LOG_VERBOSE("    Test group: %d", i);
        ACVP_LOG_VERBOSE("      test type: %s", test_type_str);
        ACVP_LOG_VERBOSE("         scheme: %s", scheme);
        ACVP_LOG_VERBOSE("       kts role: %s", kts_role);
        ACVP_LOG_VERBOSE("        pub exp: %s", e);
        ACVP_LOG_VERBOSE("        key gen: %s", key_gen_str);
        ACVP_LOG_VERBOSE("           hash: %s", hash);
        ACVP_LOG_VERBOSE("         modulo: %d", modulo);
        ACVP_LOG_VERBOSE("           role: %d", role);

        rv = acvp_tc_json_get_array(ctx, stc->cipher, groupobj, "tests", &tests);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {

            ACVP_LOG_VERBOSE("Found new KTS-IFC Component test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            rv = acvp_tc_json_get_int(ctx, stc->cipher, testobj, "tcId", (int *)&tc_id);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            if (role == ACVP_KTS_IFC_RESPONDER) {
                rv = acvp_tc_json_get_string(ctx, stc->cipher, testobj, "serverC", &ct);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }

                if (strnlen_s(ct, ACVP_KTS_IFC_STR_MAX + 1) > ACVP_KTS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("ct too long, max allowed=(%d)",
                                  ACVP_KTS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                rv = acvp_tc_json_get_string(ctx, stc->cipher, testobj, "iutP", &p);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }

                if (strnlen_s(p, ACVP_KTS_IFC_STR_MAX + 1) > ACVP_KTS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("p too long, max allowed=(%d)",
                                  ACVP_KTS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                rv = acvp_tc_json_get_string(ctx, stc->cipher, testobj, "iutQ", &q);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }

                if (strnlen_s(q, ACVP_KTS_IFC_STR_MAX + 1) > ACVP_KTS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("q too long, max allowed=(%d)",
                                  ACVP_KTS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                rv = acvp_tc_json_get_string(ctx, stc->cipher, testobj, "iutN", &n);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }

                if (strnlen_s(n, ACVP_KTS_IFC_STR_MAX + 1) > ACVP_KTS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("n too long, max allowed=(%d)",
                                  ACVP_KTS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                rv = acvp_tc_json_get_string(ctx, stc->cipher, testobj, "iutE", &e);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }

                if (strnlen_s(e, ACVP_KTS_IFC_STR_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) {
                    ACVP_LOG_ERR("e too long, max allowed=(%d)",
                                  ACVP_KTS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                if (key_gen == ACVP_KTS_IFC_RSAKPG1_CRT || key_gen == ACVP_KTS_IFC_RSAKPG2_CRT) {
                    rv = acvp_tc_json_get_string(ctx, stc->cipher, testobj, "iutDmp1", &dmp1);
                    if (rv != ACVP_SUCCESS) {
                        goto err;
                    }

                    if (strnlen_s(dmp1, ACVP_KTS_IFC_STR_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) {
                        ACVP_LOG_ERR("dmp1 too long, max allowed=(%d)",
                                    ACVP_KTS_IFC_STR_MAX);
                        rv = ACVP_INVALID_ARG;
                        goto err;
                    }

                    rv = acvp_tc_json_get_string(ctx, stc->cipher, testobj, "iutDmq1", &dmq1);
                    if (rv != ACVP_SUCCESS) {
                        goto err;
                    }

                    if (strnlen_s(dmq1, ACVP_KTS_IFC_STR_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) {
                        ACVP_LOG_ERR("dmq1 too long, max allowed=(%d)",
                                    ACVP_KTS_IFC_STR_MAX);
                        rv = ACVP_INVALID_ARG;
                        goto err;
                    }

                    rv = acvp_tc_json_get_string(ctx, stc->cipher, testobj, "iutIqmp", &iqmp);
                    if (rv != ACVP_SUCCESS) {
                        goto err;
                    }

                    if (strnlen_s(iqmp, ACVP_KTS_IFC_STR_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) {
                        ACVP_LOG_ERR("iqmp too long, max allowed=(%d)",
                                    ACVP_KTS_IFC_STR_MAX);
                        rv = ACVP_INVALID_ARG;
                        goto err;
                    }
                } else {
                    rv = acvp_tc_json_get_string(ctx, stc->cipher, testobj, "iutD", &d);
                    if (rv != ACVP_SUCCESS) {
                        goto err;
                    }

                    if (strnlen_s(d, ACVP_KTS_IFC_STR_MAX + 1) > ACVP_KTS_IFC_STR_MAX) {
                        ACVP_LOG_ERR("d too long, max allowed=(%d)",
                                    ACVP_KTS_IFC_STR_MAX);
                        rv = ACVP_INVALID_ARG;
                        goto err;
                }
                }
            } else {
                rv = acvp_tc_json_get_string(ctx, stc->cipher, testobj, "serverN", &n);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }

                if (strnlen_s(n, ACVP_KTS_IFC_STR_MAX + 1) > ACVP_KTS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("n too long, max allowed=(%d)",
                                  ACVP_KTS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                rv = acvp_tc_json_get_string(ctx, stc->cipher, testobj, "serverE", &e);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }

                if (strnlen_s(e, ACVP_KTS_IFC_STR_MAX + 1) > ACVP_KTS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("e too long, max allowed=(%d)",
                                  ACVP_KTS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

            }

            ACVP_LOG_VERBOSE("           tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("              p: %s", p);
            ACVP_LOG_VERBOSE("              q: %s", q);
            ACVP_LOG_VERBOSE("              n: %s", n);
            ACVP_LOG_VERBOSE("              d: %s", d);
            ACVP_LOG_VERBOSE("              e: %s", e);


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
            rv = acvp_kts_ifc_init_tc(ctx, stc, key_gen, hash_alg, role, ct,
                                      p, q, d, n, e, dmp1, dmq1, iqmp, modulo, llen, test_type);
            if (rv != ACVP_SUCCESS) {
                acvp_kts_ifc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            // Process the current KAT test vector...
            if ((cap->crypto_handler)(tc)) {
                acvp_kts_ifc_release_tc(stc);
                ACVP_LOG_ERR("Crypto module failed the operation");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kts_ifc_output_tc(ctx, stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure recording test response");
                acvp_kts_ifc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_kts_ifc_release_tc(stc);

            // Append the test response value to array
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
    }
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        json_value_free(r_gval);
    }
    return rv;
}

ACVP_RESULT acvp_kts_ifc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_garr = NULL; // Response testarray
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    ACVP_CAPS_LIST *cap;
    ACVP_TEST_CASE tc;
    ACVP_KTS_IFC_TC stc;
    ACVP_RESULT rv = ACVP_SUCCESS;
    const char *alg_str = NULL;
    char *json_result = NULL;

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
    tc.tc.kts_ifc = &stc;
    memzero_s(&stc, sizeof(ACVP_KTS_IFC_TC));

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
    cap = acvp_locate_cap_entry(ctx, ACVP_KTS_IFC);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        rv = ACVP_UNSUPPORTED_OP;
        goto err;
    }
    rv = acvp_kts_ifc(ctx, cap, &tc, &stc, obj, r_garr);
    if (rv != ACVP_SUCCESS) {
        goto err;
    }
    json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    ACVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        acvp_kts_ifc_release_tc(&stc);
        json_value_free(r_vs_val);
    }
    return rv;
}
