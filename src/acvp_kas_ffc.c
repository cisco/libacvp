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
static ACVP_RESULT acvp_kas_ffc_output_ssc_tc(ACVP_CTX *ctx,
                                               ACVP_KAS_FFC_TC *stc,
                                               JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_KAS_FFC_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_output_mct_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->test_type == ACVP_KAS_FFC_TT_VAL) {
        int diff = 1;

        memcmp_s(stc->chash, ACVP_KAS_FFC_BYTE_MAX,
                 stc->z, stc->zlen, &diff);
        if (!diff) {
            json_object_set_boolean(tc_rsp, "testPassed", 1);
        } else {
            json_object_set_boolean(tc_rsp, "testPassed", 0);
        }
        goto end;
    }

    memzero_s(tmp, ACVP_KAS_FFC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->piut, stc->piutlen, tmp, ACVP_KAS_FFC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (Z)");
        goto end;
    }
    json_object_set_string(tc_rsp, "ephemeralPublicIut", tmp);

    memzero_s(tmp, ACVP_KAS_FFC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->chash, stc->chashlen, tmp, ACVP_KAS_FFC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (Z)");
        goto end;
    }
    json_object_set_string(tc_rsp, "hashZ", tmp);

end:
    if (tmp) free(tmp);

    return rv;
}

static ACVP_RESULT acvp_kas_ffc_output_comp_tc(ACVP_CTX *ctx,
                                               ACVP_KAS_FFC_TC *stc,
                                               JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_KAS_FFC_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_output_mct_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->test_type == ACVP_KAS_FFC_TT_VAL) {
        int diff = 1;

        memcmp_s(stc->chash, ACVP_KAS_FFC_BYTE_MAX,
                 stc->z, stc->zlen, &diff);
        if (!diff) {
            json_object_set_boolean(tc_rsp, "testPassed", 1);
        } else {
            json_object_set_boolean(tc_rsp, "testPassed", 0);
        }
        goto end;
    }

    memzero_s(tmp, ACVP_KAS_FFC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->piut, stc->piutlen, tmp, ACVP_KAS_FFC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (Z)");
        goto end;
    }
    json_object_set_string(tc_rsp, "ephemeralPublicIut", tmp);

    memzero_s(tmp, ACVP_KAS_FFC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->chash, stc->chashlen, tmp, ACVP_KAS_FFC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (Z)");
        goto end;
    }
    json_object_set_string(tc_rsp, "hashZIut", tmp);

end:
    if (tmp) free(tmp);

    return rv;
}

static ACVP_RESULT acvp_kas_ffc_init_comp_tc(ACVP_CTX *ctx,
                                             ACVP_KAS_FFC_TC *stc,
                                             ACVP_HASH_ALG hash_alg,
                                             const char *p,
                                             const char *q,
                                             const char *g,
                                             const char *eps,
                                             const char *epri,
                                             const char *epui,
                                             const char *z,
                                             ACVP_KAS_FFC_TEST_TYPE test_type) {
    ACVP_RESULT rv;

    stc->mode = ACVP_KAS_FFC_MODE_COMPONENT;
    stc->md = hash_alg;
    stc->test_type = test_type;

    stc->p = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
    if (!stc->p) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(p, stc->p, ACVP_KAS_FFC_BYTE_MAX, &(stc->plen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (p)");
        return rv;
    }

    stc->q = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
    if (!stc->q) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(q, stc->q, ACVP_KAS_FFC_BYTE_MAX, &(stc->qlen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (q)");
        return rv;
    }

    stc->g = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
    if (!stc->g) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(g, stc->g, ACVP_KAS_FFC_BYTE_MAX, &(stc->glen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (g)");
        return rv;
    }

    stc->eps = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
    if (!stc->eps) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(eps, stc->eps, ACVP_KAS_FFC_BYTE_MAX, &(stc->epslen));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (eps)");
        return rv;
    }

    stc->epri = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
    if (!stc->epri) { return ACVP_MALLOC_FAIL; }
    stc->epui = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
    if (!stc->epui) { return ACVP_MALLOC_FAIL; }
    stc->chash = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
    if (!stc->chash) { return ACVP_MALLOC_FAIL; }
    stc->piut = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
    if (!stc->piut) { return ACVP_MALLOC_FAIL; }

    stc->z = calloc(1, ACVP_KAS_FFC_BYTE_MAX);
    if (!stc->z) { return ACVP_MALLOC_FAIL; }

    if (stc->test_type == ACVP_KAS_FFC_TT_VAL) {
        rv = acvp_hexstr_to_bin(z, stc->z, ACVP_KAS_FFC_BYTE_MAX, &(stc->zlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (z)");
            return rv;
        }
        rv = acvp_hexstr_to_bin(epri, stc->epri, ACVP_KAS_FFC_BYTE_MAX, &(stc->eprilen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (epri)");
            return rv;
        }
        rv = acvp_hexstr_to_bin(epui, stc->epui, ACVP_KAS_FFC_BYTE_MAX, &(stc->epuilen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (epui)");
            return rv;
        }
    }
    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kas_ffc_release_tc(ACVP_KAS_FFC_TC *stc) {
    if (stc->piut) free(stc->piut);
    if (stc->epri) free(stc->epri);
    if (stc->epui) free(stc->epui);
    if (stc->eps) free(stc->eps);
    if (stc->z) free(stc->z);
    if (stc->chash) free(stc->chash);
    if (stc->p) free(stc->p);
    if (stc->q) free(stc->q);
    if (stc->g) free(stc->g);
    memzero_s(stc, sizeof(ACVP_KAS_FFC_TC));
    return ACVP_SUCCESS;
}

static ACVP_KAS_FFC_TEST_TYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return ACVP_KAS_FFC_TT_AFT;

    strcmp_s("VAL", 3, str, &diff);
    if (!diff) return ACVP_KAS_FFC_TT_VAL;

    return 0;
}

static ACVP_RESULT acvp_kas_ffc_comp(ACVP_CTX *ctx,
                                     ACVP_CAPS_LIST *cap,
                                     ACVP_TEST_CASE *tc,
                                     ACVP_KAS_FFC_TC *stc,
                                     JSON_Object *obj,
                                     JSON_Array *r_garr) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Array *groups;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *tests, *r_tarr = NULL;
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    const char *hash_str = NULL;
    ACVP_HASH_ALG hash_alg = 0;
    const char *p = NULL, *q = NULL, *g = NULL;
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id;
    ACVP_RESULT rv;
    const char *test_type_str;
    ACVP_KAS_FFC_TEST_TYPE test_type;

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

        hash_str = json_object_get_string(groupobj, "hashAlg");
        if (!hash_str) {
            ACVP_LOG_ERR("Server JSON missing 'hashAlg'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        hash_alg = acvp_lookup_hash_alg(hash_str);
        if (hash_alg != ACVP_SHA224 && hash_alg != ACVP_SHA256 &&
            hash_alg != ACVP_SHA384 && hash_alg != ACVP_SHA512) {
            ACVP_LOG_ERR("Server JSON invalid 'hashAlg'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        test_type_str = json_object_get_string(groupobj, "testType");
        if (!test_type_str) {
            ACVP_LOG_ERR("Server JSON missing 'testType'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        test_type = read_test_type(test_type_str);
        if (!test_type) {
            ACVP_LOG_ERR("Server JSON invalid 'testType'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        p = json_object_get_string(groupobj, "p");
        if (!p) {
            ACVP_LOG_ERR("Server JSON missing 'p'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        if (strnlen_s(p, ACVP_KAS_FFC_STR_MAX + 1) > ACVP_KAS_FFC_STR_MAX) {
            ACVP_LOG_ERR("p too long, max allowed=(%d)",
                         ACVP_KAS_FFC_STR_MAX);
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        q = json_object_get_string(groupobj, "q");
        if (!q) {
            ACVP_LOG_ERR("Server JSON missing 'q'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        if (strnlen_s(q, ACVP_KAS_FFC_STR_MAX + 1) > ACVP_KAS_FFC_STR_MAX) {
            ACVP_LOG_ERR("q too long, max allowed=(%d)",
                         ACVP_KAS_FFC_STR_MAX);
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        g = json_object_get_string(groupobj, "g");
        if (!g) {
            ACVP_LOG_ERR("Server JSON missing 'g'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        if (strnlen_s(g, ACVP_KAS_FFC_STR_MAX + 1) > ACVP_KAS_FFC_STR_MAX) {
            ACVP_LOG_ERR("g too long, max allowed=(%d)",
                         ACVP_KAS_FFC_STR_MAX);
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        ACVP_LOG_VERBOSE("    Test group: %d", i);
        ACVP_LOG_VERBOSE("      test type: %s", test_type_str);
        ACVP_LOG_VERBOSE("           hash: %s", hash_str);
        ACVP_LOG_VERBOSE("              p: %s", p);
        ACVP_LOG_VERBOSE("              q: %s", q);
        ACVP_LOG_VERBOSE("              g: %s", g);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            const char *eps = NULL, *z = NULL, *epri = NULL, *epui = NULL;

            ACVP_LOG_VERBOSE("Found new KAS-FFC Component test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            eps = json_object_get_string(testobj, "ephemeralPublicServer");
            if (!eps) {
                ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicServer'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(eps, ACVP_KAS_FFC_STR_MAX + 1)
                > ACVP_KAS_FFC_STR_MAX) {
                ACVP_LOG_ERR("ephemeralPublicServer too long, max allowed=(%d)",
                             ACVP_KAS_FFC_STR_MAX);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            if (test_type == ACVP_KAS_FFC_TT_VAL) {
                /*
                 * Validate
                 */
                epri = json_object_get_string(testobj, "ephemeralPrivateIut");
                if (!epri) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPrivateIut'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(epri, ACVP_KAS_FFC_STR_MAX + 1)
                    > ACVP_KAS_FFC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPrivateIut too long, max allowed=(%d)",
                                 ACVP_KAS_FFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                epui = json_object_get_string(testobj, "ephemeralPublicIut");
                if (!epui) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicIut'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(epui, ACVP_KAS_FFC_STR_MAX + 1)
                    > ACVP_KAS_FFC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPublicIut too long, max allowed=(%d)",
                                 ACVP_KAS_FFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                z = json_object_get_string(testobj, "hashZIut");
                if (!z) {
                    ACVP_LOG_ERR("Server JSON missing 'hashZIut'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(z, ACVP_KAS_FFC_STR_MAX + 1)
                    > ACVP_KAS_FFC_STR_MAX) {
                    ACVP_LOG_ERR("hashZIut too long, max allowed=(%d)",
                                 ACVP_KAS_FFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            ACVP_LOG_VERBOSE("            eps: %s", eps);
            ACVP_LOG_VERBOSE("              z: %s", z);
            ACVP_LOG_VERBOSE("           epri: %s", epri);
            ACVP_LOG_VERBOSE("           epui: %s", epui);

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
            rv = acvp_kas_ffc_init_comp_tc(ctx, stc, hash_alg,
                                           p, q, g, eps, epri, epui, z, test_type);
            if (rv != ACVP_SUCCESS) {
                acvp_kas_ffc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current KAT test vector... */
            if ((cap->crypto_handler)(tc)) {
                acvp_kas_ffc_release_tc(stc);
                ACVP_LOG_ERR("crypto module failed the operation");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kas_ffc_output_comp_tc(ctx, stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in KAS-FFC module");
                acvp_kas_ffc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_kas_ffc_release_tc(stc);

            /* Append the test response value to array */
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

ACVP_RESULT acvp_kas_ffc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_garr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    ACVP_CAPS_LIST *cap;
    ACVP_TEST_CASE tc;
    ACVP_KAS_FFC_TC stc;
    ACVP_RESULT rv = ACVP_SUCCESS;
    const char *alg_str = NULL;
    char *json_result = NULL;
    const char *mode_str = NULL;

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
    tc.tc.kas_ffc = &stc;
    memzero_s(&stc, sizeof(ACVP_KAS_FFC_TC));

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
    mode_str = json_object_get_string(obj, "mode");
    json_object_set_string(r_vs, "mode", mode_str);

    if (mode_str) {
        stc.cipher = acvp_lookup_cipher_w_mode_index(alg_str, mode_str);
        if (stc.cipher != ACVP_KAS_FFC_COMP) {
            ACVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }
    } else {
        stc.cipher = ACVP_KAS_FFC_NOCOMP;
    }

    switch (stc.cipher) {
    case ACVP_KAS_FFC_COMP:
        cap = acvp_locate_cap_entry(ctx, ACVP_KAS_FFC_COMP);
        if (!cap) {
            ACVP_LOG_ERR("ACVP server requesting unsupported capability");
            rv = ACVP_UNSUPPORTED_OP;
            goto err;
        }
        rv = acvp_kas_ffc_comp(ctx, cap, &tc, &stc, obj, r_garr);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        break;

    case ACVP_KAS_FFC_MODE_NOCOMP:
    case ACVP_CIPHER_START:
    case ACVP_AES_GCM:
    case ACVP_AES_CCM:
    case ACVP_AES_ECB:
    case ACVP_AES_CBC:
    case ACVP_AES_CFB1:
    case ACVP_AES_CFB8:
    case ACVP_AES_CFB128:
    case ACVP_AES_OFB:
    case ACVP_AES_CTR:
    case ACVP_AES_XTS:
    case ACVP_AES_KW:
    case ACVP_AES_KWP:
    case ACVP_AES_GMAC:
    case ACVP_AES_XPN:
    case ACVP_TDES_ECB:
    case ACVP_TDES_CBC:
    case ACVP_TDES_CBCI:
    case ACVP_TDES_OFB:
    case ACVP_TDES_OFBI:
    case ACVP_TDES_CFB1:
    case ACVP_TDES_CFB8:
    case ACVP_TDES_CFB64:
    case ACVP_TDES_CFBP1:
    case ACVP_TDES_CFBP8:
    case ACVP_TDES_CFBP64:
    case ACVP_TDES_CTR:
    case ACVP_TDES_KW:
    case ACVP_HASH_SHA1:
    case ACVP_HASH_SHA224:
    case ACVP_HASH_SHA256:
    case ACVP_HASH_SHA384:
    case ACVP_HASH_SHA512:
    case ACVP_HASH_SHA512_224:
    case ACVP_HASH_SHA512_256:
    case ACVP_HASH_SHA3_224:
    case ACVP_HASH_SHA3_256:
    case ACVP_HASH_SHA3_384:
    case ACVP_HASH_SHA3_512:
    case ACVP_HASH_SHAKE_128:
    case ACVP_HASH_SHAKE_256:
    case ACVP_HASHDRBG:
    case ACVP_HMACDRBG:
    case ACVP_CTRDRBG:
    case ACVP_HMAC_SHA1:
    case ACVP_HMAC_SHA2_224:
    case ACVP_HMAC_SHA2_256:
    case ACVP_HMAC_SHA2_384:
    case ACVP_HMAC_SHA2_512:
    case ACVP_HMAC_SHA2_512_224:
    case ACVP_HMAC_SHA2_512_256:
    case ACVP_HMAC_SHA3_224:
    case ACVP_HMAC_SHA3_256:
    case ACVP_HMAC_SHA3_384:
    case ACVP_HMAC_SHA3_512:
    case ACVP_CMAC_AES:
    case ACVP_CMAC_TDES:
    case ACVP_DSA_KEYGEN:
    case ACVP_DSA_PQGGEN:
    case ACVP_DSA_PQGVER:
    case ACVP_DSA_SIGGEN:
    case ACVP_DSA_SIGVER:
    case ACVP_RSA_KEYGEN:
    case ACVP_RSA_SIGGEN:
    case ACVP_RSA_SIGVER:
    case ACVP_ECDSA_KEYGEN:
    case ACVP_ECDSA_KEYVER:
    case ACVP_ECDSA_SIGGEN:
    case ACVP_ECDSA_SIGVER:
    case ACVP_KDF135_TLS:
    case ACVP_KDF135_SNMP:
    case ACVP_KDF135_SSH:
    case ACVP_KDF135_SRTP:
    case ACVP_KDF135_IKEV2:
    case ACVP_KDF135_IKEV1:
    case ACVP_KDF135_X963:
    case ACVP_KDF108:
    case ACVP_KAS_ECC_CDH:
    case ACVP_KAS_ECC_COMP:
    case ACVP_KAS_ECC_NOCOMP:
    case ACVP_KAS_FFC_NOCOMP:
    case ACVP_CIPHER_END:
    default:
        ACVP_LOG_ERR("ACVP server requesting unsupported KAS-FFC mode");
        rv = ACVP_UNSUPPORTED_OP;
        goto err;
    }
    json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    ACVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        acvp_kas_ffc_release_tc(&stc);
        json_value_free(r_vs_val);
    }
    return rv;
}

static ACVP_RESULT acvp_kas_ffc_ssc(ACVP_CTX *ctx,
                                    ACVP_CAPS_LIST *cap,
                                    ACVP_TEST_CASE *tc,
                                    ACVP_KAS_FFC_TC *stc,
                                    JSON_Object *obj,
                                    JSON_Array *r_garr) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Array *groups;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *tests, *r_tarr = NULL;
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    const char *hash_str = NULL;
    ACVP_HASH_ALG hash_alg = 0;
    const char *p = NULL, *q = NULL, *g = NULL;
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id;
    ACVP_RESULT rv;
    const char *test_type_str;
    ACVP_KAS_FFC_TEST_TYPE test_type;

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

        hash_str = json_object_get_string(groupobj, "hashFunctionZ");
        if (!hash_str) {
            ACVP_LOG_ERR("Server JSON missing 'hashFunctionZ'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        hash_alg = acvp_lookup_hash_alg(hash_str);
        if (hash_alg != ACVP_SHA224 && hash_alg != ACVP_SHA256 &&
            hash_alg != ACVP_SHA384 && hash_alg != ACVP_SHA512) {
            ACVP_LOG_ERR("Server JSON invalid 'hashAlg'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        test_type_str = json_object_get_string(groupobj, "testType");
        if (!test_type_str) {
            ACVP_LOG_ERR("Server JSON missing 'testType'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        test_type = read_test_type(test_type_str);
        if (!test_type) {
            ACVP_LOG_ERR("Server JSON invalid 'testType'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        p = json_object_get_string(groupobj, "p");
        if (!p) {
            ACVP_LOG_ERR("Server JSON missing 'p'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        if (strnlen_s(p, ACVP_KAS_FFC_STR_MAX + 1) > ACVP_KAS_FFC_STR_MAX) {
            ACVP_LOG_ERR("p too long, max allowed=(%d)",
                         ACVP_KAS_FFC_STR_MAX);
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        q = json_object_get_string(groupobj, "q");
        if (!q) {
            ACVP_LOG_ERR("Server JSON missing 'q'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        if (strnlen_s(q, ACVP_KAS_FFC_STR_MAX + 1) > ACVP_KAS_FFC_STR_MAX) {
            ACVP_LOG_ERR("q too long, max allowed=(%d)",
                         ACVP_KAS_FFC_STR_MAX);
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        g = json_object_get_string(groupobj, "g");
        if (!g) {
            ACVP_LOG_ERR("Server JSON missing 'g'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        if (strnlen_s(g, ACVP_KAS_FFC_STR_MAX + 1) > ACVP_KAS_FFC_STR_MAX) {
            ACVP_LOG_ERR("g too long, max allowed=(%d)",
                         ACVP_KAS_FFC_STR_MAX);
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        ACVP_LOG_VERBOSE("    Test group: %d", i);
        ACVP_LOG_VERBOSE("      test type: %s", test_type_str);
        ACVP_LOG_VERBOSE("           hash: %s", hash_str);
        ACVP_LOG_VERBOSE("              p: %s", p);
        ACVP_LOG_VERBOSE("              q: %s", q);
        ACVP_LOG_VERBOSE("              g: %s", g);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            const char *eps = NULL, *z = NULL, *epri = NULL, *epui = NULL;

            ACVP_LOG_VERBOSE("Found new KAS-FFC Component test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            eps = json_object_get_string(testobj, "ephemeralPublicServer");
            if (!eps) {
                ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicServer'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(eps, ACVP_KAS_FFC_STR_MAX + 1)
                > ACVP_KAS_FFC_STR_MAX) {
                ACVP_LOG_ERR("ephemeralPublicServer too long, max allowed=(%d)",
                             ACVP_KAS_FFC_STR_MAX);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            if (test_type == ACVP_KAS_FFC_TT_VAL) {
                /*
                 * Validate
                 */
                epri = json_object_get_string(testobj, "ephemeralPrivateIut");
                if (!epri) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPrivateIut'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(epri, ACVP_KAS_FFC_STR_MAX + 1)
                    > ACVP_KAS_FFC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPrivateIut too long, max allowed=(%d)",
                                 ACVP_KAS_FFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                epui = json_object_get_string(testobj, "ephemeralPublicIut");
                if (!epui) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicIut'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(epui, ACVP_KAS_FFC_STR_MAX + 1)
                    > ACVP_KAS_FFC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPublicIut too long, max allowed=(%d)",
                                 ACVP_KAS_FFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                z = json_object_get_string(testobj, "hashZ");
                if (!z) {
                    ACVP_LOG_ERR("Server JSON missing 'hashZ'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(z, ACVP_KAS_FFC_STR_MAX + 1)
                    > ACVP_KAS_FFC_STR_MAX) {
                    ACVP_LOG_ERR("hashZIut too long, max allowed=(%d)",
                                 ACVP_KAS_FFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            ACVP_LOG_VERBOSE("            eps: %s", eps);
            ACVP_LOG_VERBOSE("              z: %s", z);
            ACVP_LOG_VERBOSE("           epri: %s", epri);
            ACVP_LOG_VERBOSE("           epui: %s", epui);

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
            rv = acvp_kas_ffc_init_comp_tc(ctx, stc, hash_alg,
                                           p, q, g, eps, epri, epui, z, test_type);
            if (rv != ACVP_SUCCESS) {
                acvp_kas_ffc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current KAT test vector... */
            if ((cap->crypto_handler)(tc)) {
                acvp_kas_ffc_release_tc(stc);
                ACVP_LOG_ERR("crypto module failed the operation");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kas_ffc_output_ssc_tc(ctx, stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in KAS-FFC module");
                acvp_kas_ffc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_kas_ffc_release_tc(stc);

            /* Append the test response value to array */
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

ACVP_RESULT acvp_kas_ffc_ssc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_garr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    ACVP_CAPS_LIST *cap;
    ACVP_TEST_CASE tc;
    ACVP_KAS_FFC_TC stc;
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
    tc.tc.kas_ffc = &stc;
    memzero_s(&stc, sizeof(ACVP_KAS_FFC_TC));

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
    cap = acvp_locate_cap_entry(ctx, ACVP_KAS_FFC_SSC);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        rv = ACVP_UNSUPPORTED_OP;
        goto err;
    }
    rv = acvp_kas_ffc_ssc(ctx, cap, &tc, &stc, obj, r_garr);
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
        acvp_kas_ffc_release_tc(&stc);
        json_value_free(r_vs_val);
    }
    return rv;
}
