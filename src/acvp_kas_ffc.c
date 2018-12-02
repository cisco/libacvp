/*****************************************************************************
* Copyright (c) 2018, Cisco Systems, Inc.
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
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
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
        if (!memcmp(stc->z, stc->chash, stc->zlen)) {
            json_object_set_boolean(tc_rsp, "testPassed", 1);
        } else {
            json_object_set_boolean(tc_rsp, "testPassed", 0);
        }
        goto end;
    }

    memset(tmp, 0x0, ACVP_KAS_FFC_STR_MAX);
    rv = acvp_bin_to_hexstr(stc->piut, stc->piutlen, tmp, ACVP_KAS_FFC_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (Z)");
        goto end;
    }
    json_object_set_string(tc_rsp, "ephemeralPublicIut", tmp);

    memset(tmp, 0x0, ACVP_KAS_FFC_STR_MAX);
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
                                             unsigned int tc_id,
                                             ACVP_HASH_ALG hash_alg,
                                             const char *p,
                                             const char *q,
                                             const char *g,
                                             const char *eps,
                                             const char *epri,
                                             const char *epui,
                                             const char *z,
                                             unsigned int mode) {
    ACVP_RESULT rv;

    stc->mode = mode;
    stc->md = hash_alg;

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
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kas_ffc_comp(ACVP_CTX *ctx,
                                     ACVP_CAPS_LIST *cap,
                                     ACVP_TEST_CASE *tc,
                                     ACVP_KAS_FFC_TC *stc,
                                     JSON_Object *obj,
                                     int mode,
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
    char *p = NULL, *q = NULL, *g = NULL;
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id;
    ACVP_RESULT rv;
    const char *test_type;

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

        hash_str = json_object_get_string(groupobj, "hashAlg");
        if (!hash_str) {
            ACVP_LOG_ERR("Server JSON missing 'hashAlg'");
            return ACVP_MISSING_ARG;
        }
        if (!strncmp(hash_str, ACVP_STR_SHA2_224, strlen(ACVP_STR_SHA2_224))) {
            hash_alg = ACVP_SHA224;
        } else if (!strncmp(hash_str, ACVP_STR_SHA2_256, strlen(ACVP_STR_SHA2_256))) {
            hash_alg = ACVP_SHA256;
        } else if (!strncmp(hash_str, ACVP_STR_SHA2_384, strlen(ACVP_STR_SHA2_384))) {
            hash_alg = ACVP_SHA384;
        } else if (!strncmp(hash_str, ACVP_STR_SHA2_512, strlen(ACVP_STR_SHA2_512))) {
            hash_alg = ACVP_SHA512;
        } else {
            ACVP_LOG_ERR("Server JSON invalid 'hashAlg'");
            return ACVP_INVALID_ARG;
        }

        test_type = json_object_get_string(groupobj, "testType");
        if (!test_type) {
            ACVP_LOG_ERR("Server JSON missing 'testType'");
            return ACVP_MISSING_ARG;
        }

        if (!strncmp(test_type, "AFT", 3)) {
            stc->test_type = ACVP_KAS_FFC_TT_AFT;
        } else if (!strncmp(test_type, "VAL", 3)) {
            stc->test_type = ACVP_KAS_FFC_TT_VAL;
        } else {
            ACVP_LOG_ERR("Server JSON invalid 'testType'");
            return ACVP_INVALID_ARG;
        }

        p = (char *)json_object_get_string(groupobj, "p");
        if (!p) {
            ACVP_LOG_ERR("Server JSON missing 'p'");
            return ACVP_MISSING_ARG;
        }
        if (strnlen(p, ACVP_KAS_FFC_STR_MAX + 1) > ACVP_KAS_FFC_STR_MAX) {
            ACVP_LOG_ERR("p too long, max allowed=(%d)",
                         ACVP_KAS_FFC_STR_MAX);
            return ACVP_INVALID_ARG;
        }

        q = (char *)json_object_get_string(groupobj, "q");
        if (!q) {
            ACVP_LOG_ERR("Server JSON missing 'q'");
            return ACVP_MISSING_ARG;
        }
        if (strnlen(q, ACVP_KAS_FFC_STR_MAX + 1) > ACVP_KAS_FFC_STR_MAX) {
            ACVP_LOG_ERR("q too long, max allowed=(%d)",
                         ACVP_KAS_FFC_STR_MAX);
            return ACVP_INVALID_ARG;
        }

        g = (char *)json_object_get_string(groupobj, "g");
        if (!g) {
            ACVP_LOG_ERR("Server JSON missing 'g'");
            return ACVP_MISSING_ARG;
        }
        if (strnlen(g, ACVP_KAS_FFC_STR_MAX + 1) > ACVP_KAS_FFC_STR_MAX) {
            ACVP_LOG_ERR("g too long, max allowed=(%d)",
                         ACVP_KAS_FFC_STR_MAX);
            return ACVP_INVALID_ARG;
        }

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("      test type: %s", test_type);
        ACVP_LOG_INFO("           hash: %s", hash_str);
        ACVP_LOG_INFO("              p: %s", p);
        ACVP_LOG_INFO("              q: %s", q);
        ACVP_LOG_INFO("              g: %s", g);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            const char *eps = NULL, *z = NULL, *epri = NULL, *epui = NULL;

            ACVP_LOG_INFO("Found new KAS-FFC Component test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");

            eps = json_object_get_string(testobj, "ephemeralPublicServer");
            if (!eps) {
                ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicServer'");
                return ACVP_MISSING_ARG;
            }
            if (strnlen(eps, ACVP_KAS_FFC_STR_MAX + 1)
                > ACVP_KAS_FFC_STR_MAX) {
                ACVP_LOG_ERR("ephemeralPublicServer too long, max allowed=(%d)",
                             ACVP_KAS_FFC_STR_MAX);
                return ACVP_INVALID_ARG;
            }

            if (stc->test_type == ACVP_KAS_FFC_TT_VAL) {
                /*
                 * Validate
                 */
                epri = json_object_get_string(testobj, "ephemeralPrivateIut");
                if (!epri) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPrivateIut'");
                    return ACVP_MISSING_ARG;
                }
                if (strnlen(epri, ACVP_KAS_FFC_STR_MAX + 1)
                    > ACVP_KAS_FFC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPrivateIut too long, max allowed=(%d)",
                                 ACVP_KAS_FFC_STR_MAX);
                    return ACVP_INVALID_ARG;
                }

                epui = json_object_get_string(testobj, "ephemeralPublicIut");
                if (!epui) {
                    ACVP_LOG_ERR("Server JSON missing 'ephemeralPublicIut'");
                    return ACVP_MISSING_ARG;
                }
                if (strnlen(epui, ACVP_KAS_FFC_STR_MAX + 1)
                    > ACVP_KAS_FFC_STR_MAX) {
                    ACVP_LOG_ERR("ephemeralPublicIut too long, max allowed=(%d)",
                                 ACVP_KAS_FFC_STR_MAX);
                    return ACVP_INVALID_ARG;
                }

                z = json_object_get_string(testobj, "hashZIut");
                if (!z) {
                    ACVP_LOG_ERR("Server JSON missing 'hashZIut'");
                    return ACVP_MISSING_ARG;
                }
                if (strnlen(z, ACVP_KAS_FFC_STR_MAX + 1)
                    > ACVP_KAS_FFC_STR_MAX) {
                    ACVP_LOG_ERR("hashZIut too long, max allowed=(%d)",
                                 ACVP_KAS_FFC_STR_MAX);
                    return ACVP_INVALID_ARG;
                }
            }

            ACVP_LOG_INFO("            eps: %s", eps);
            ACVP_LOG_INFO("              z: %s", z);
            ACVP_LOG_INFO("           epri: %s", epri);
            ACVP_LOG_INFO("           epui: %s", epui);

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
            rv = acvp_kas_ffc_init_comp_tc(ctx, stc, tc_id, hash_alg,
                                           p, q, g, eps, epri, epui, z, mode);
            if (rv != ACVP_SUCCESS) {
                acvp_kas_ffc_release_tc(stc);
                return rv;
            }

            /* Process the current KAT test vector... */
            if ((cap->crypto_handler)(tc)) {
                acvp_kas_ffc_release_tc(stc);
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kas_ffc_output_comp_tc(ctx, stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in KAS-FFC module");
                acvp_kas_ffc_release_tc(stc);
                return rv;
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

    return ACVP_SUCCESS;
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
    const char *alg_str = json_object_get_string(obj, "algorithm");
    int mode = 0;
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
    memset(&stc, 0x0, sizeof(ACVP_KAS_FFC_TC));

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
        if (!strncmp(mode_str, "Component", strlen("Component"))) {
            mode = ACVP_KAS_FFC_MODE_COMPONENT;
            stc.cipher = ACVP_KAS_FFC_COMP;
        } else {
            ACVP_LOG_ERR("Server JSON invalid 'mode'");
            return ACVP_INVALID_ARG;
        }
    }
    if (mode == 0) {
        mode = ACVP_KAS_FFC_MODE_NOCOMP;
        stc.cipher = ACVP_KAS_FFC_NOCOMP;
    }

    switch (mode) {
    case ACVP_KAS_FFC_MODE_COMPONENT:
        cap = acvp_locate_cap_entry(ctx, ACVP_KAS_FFC_COMP);
        if (!cap) {
            ACVP_LOG_ERR("ACVP server requesting unsupported capability");
            return ACVP_UNSUPPORTED_OP;
        }
        rv = acvp_kas_ffc_comp(ctx, cap, &tc, &stc, obj, mode, r_garr);
        if (rv != ACVP_SUCCESS) return rv;

        break;

    case ACVP_KAS_FFC_MODE_NOCOMP:
    default:
        ACVP_LOG_ERR("ACVP server requesting unsupported KAS-FFC mode");
        return ACVP_UNSUPPORTED_OP;
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
