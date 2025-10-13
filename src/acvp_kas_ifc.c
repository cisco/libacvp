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
static ACVP_RESULT acvp_kas_ifc_ssc_output_tc(ACVP_CTX *ctx,
                                              ACVP_KAS_IFC_TC *stc,
                                              JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_INVALID_ARG;
    char *tmp = NULL;
    unsigned char *merge = NULL;
    int z_len = 0;

    tmp = calloc(ACVP_KAS_IFC_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_output_mct_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->kas_role == ACVP_KAS_IFC_INITIATOR) {
        rv = acvp_bin_to_hexstr(stc->iut_ct_z, stc->iut_ct_z_len, tmp, ACVP_KAS_IFC_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (iut_ct_z)");
            goto end;
        }
        json_object_set_string(tc_rsp, "iutC", tmp);

        rv = acvp_bin_to_hexstr(stc->iut_pt_z, stc->iut_pt_z_len, tmp, ACVP_KAS_IFC_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (iut_pt_z)");
            goto end;
        }
        if (stc->md == ACVP_NO_SHA) {
            json_object_set_string(tc_rsp, "iutZ", tmp);
        } else {
            json_object_set_string(tc_rsp, "iutHashZ", tmp);
        }
        // for KAS1, z is just iutZ. For KAS2, its the combined z.
        if (stc->md == ACVP_NO_SHA) {
            json_object_set_string(tc_rsp, "z", tmp);
        } else {
            json_object_set_string(tc_rsp, "hashZ", tmp);
        }
    } else { // if role = responder
        if (stc->scheme == ACVP_KAS_IFC_KAS2) {
            rv = acvp_bin_to_hexstr(stc->iut_ct_z, stc->iut_ct_z_len, tmp, ACVP_KAS_IFC_STR_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (iut_ct_z)");
                goto end;
            }
            json_object_set_string(tc_rsp, "iutC", tmp);

            rv = acvp_bin_to_hexstr(stc->iut_pt_z, stc->iut_pt_z_len, tmp, ACVP_KAS_IFC_STR_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (iut_pt_z)");
                goto end;
            }
            if (stc->md == ACVP_NO_SHA) {
                json_object_set_string(tc_rsp, "iutZ", tmp);
            } else {
                json_object_set_string(tc_rsp, "iutHashZ", tmp);
            }
        } else {
            rv = acvp_bin_to_hexstr(stc->server_pt_z, stc->server_pt_z_len, tmp, ACVP_KAS_IFC_STR_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (server_pt_z)");
                goto end;
            }
            if (stc->md == ACVP_NO_SHA) {
                json_object_set_string(tc_rsp, "z", tmp);
            } else {
                json_object_set_string(tc_rsp, "hashZ", tmp);
            }
        }
    }

    if (stc->scheme == ACVP_KAS_IFC_KAS2) {
        memzero_s(tmp, ACVP_KAS_IFC_STR_MAX);

        z_len = stc->iut_pt_z_len + stc->server_pt_z_len;
        merge = calloc(z_len, sizeof(unsigned char));
        if (!merge) {
            ACVP_LOG_ERR("Error allocating memory for z combination in KAS-IFC output");
            goto end;
        }
        if (stc->kas_role == ACVP_KAS_IFC_INITIATOR) {
            memcpy_s(merge, z_len, stc->iut_pt_z, stc->iut_pt_z_len);
            memcpy_s(merge + stc->iut_pt_z_len, z_len - stc->iut_pt_z_len,
                        stc->server_pt_z, stc->server_pt_z_len);
        } else {
            memcpy_s(merge, z_len, stc->server_pt_z, stc->server_pt_z_len);
            memcpy_s(merge + stc->server_pt_z_len, z_len - stc->server_pt_z_len,
                        stc->iut_pt_z, stc->iut_pt_z_len);
        }
        rv = acvp_bin_to_hexstr((const unsigned char *)merge, z_len, tmp, ACVP_KAS_IFC_STR_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (KAS2 combined Z)");
            goto end;
        }
        json_object_set_string(tc_rsp, "z", tmp);

    }

end:
    if (tmp) free(tmp);
    if (merge) free(merge);
    return rv;
}

static ACVP_RESULT acvp_kas_ifc_ssc_val_output_tc(ACVP_KAS_IFC_TC *stc,
                                                  JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    rv = 0;
    int diff = 1, len = 0;
    unsigned char *merge = NULL;
    // For initiator tests, check the encapsulated Z. For responder tests, check the decapsulated Z.
    if (stc->kas_role == ACVP_KAS_IFC_INITIATOR) {
        if (stc->iut_ct_z_len == stc->provided_ct_z_len) {
            memcmp_s(stc->iut_ct_z, stc->iut_ct_z_len, stc->provided_ct_z, stc->provided_ct_z_len, &diff);
            rv += abs(diff);
        } else {
            rv++;
        }
    } else if (stc->scheme != ACVP_KAS_IFC_KAS2) {
        if (stc->server_pt_z_len == stc->provided_pt_z_len) {
            memcmp_s(stc->server_pt_z, stc->server_pt_z_len, stc->provided_pt_z, stc->provided_pt_z_len, &diff);
            rv += abs(diff);
        } else {
            rv++;
        }
    }

    /* For KAS2 tests, also check the combined Z. We ideally could check serverZ, but sometimes NIST provides incorrect
    combined Z in VAL tests. */
    if (stc->scheme == ACVP_KAS_IFC_KAS2) {
        len = stc->iut_pt_z_len + stc->server_pt_z_len;

        if (len == stc->provided_kas2_z_len) {
            merge = calloc(len, sizeof(unsigned char));
            if (!merge) {
                return ACVP_MALLOC_FAIL;
            }
            if (stc->kas_role == ACVP_KAS_IFC_INITIATOR) {
                memcpy_s(merge, len, stc->iut_pt_z, stc->iut_pt_z_len);
                memcpy_s(merge + stc->iut_pt_z_len, len - stc->iut_pt_z_len,
                            stc->server_pt_z, stc->server_pt_z_len);
            } else {
                memcpy_s(merge, len, stc->server_pt_z, stc->server_pt_z_len);
                memcpy_s(merge + stc->server_pt_z_len, len - stc->server_pt_z_len,
                            stc->iut_pt_z, stc->iut_pt_z_len);
            }
            memcmp_s(merge, len, stc->provided_kas2_z, stc->provided_kas2_z_len, &diff);
            rv += abs(diff);
        } else {
            rv++;
        }
    }

    if (!rv) {
        json_object_set_boolean(tc_rsp, "testPassed", 1);
    } else {
        json_object_set_boolean(tc_rsp, "testPassed", 0);
    }

    if (merge) free(merge);
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kas_ifc_ssc_init_tc(ACVP_CTX *ctx,
                                            ACVP_KAS_IFC_TC *stc,
                                            ACVP_KAS_IFC_KEYGEN key_gen,
                                            ACVP_HASH_ALG hash_alg,
                                            ACVP_KAS_IFC_PARAM scheme,
                                            ACVP_KAS_IFC_ROLES role,
                                            const char *pt_z,
                                            const char *ct_z,
                                            const char *server_ct_z,
                                            const char *kas2_z,
                                            const char *server_n,
                                            const char *server_e,
                                            const char *p,
                                            const char *q,
                                            const char *d,
                                            const char *n,
                                            const char *e,
                                            const char *dmp1,
                                            const char *dmq1,
                                            const char *iqmp,
                                            unsigned int modulo,
                                            ACVP_KAS_IFC_TEST_TYPE test_type) {
    ACVP_RESULT rv;

    stc->test_type = test_type;
    stc->md = hash_alg;
    stc->scheme = scheme;
    stc->kas_role = role;
    stc->key_gen = key_gen;
    stc->modulo = modulo;

    if (p) {
        stc->p = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->p) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(p, stc->p, ACVP_KAS_IFC_BYTE_MAX, &(stc->plen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (p)");
            return rv;
        }
    }

    if (q) {
        stc->q = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->q) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(q, stc->q, ACVP_KAS_IFC_BYTE_MAX, &(stc->qlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (q)");
            return rv;
        }
    }

    if (d) {
        stc->d = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->d) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(d, stc->d, ACVP_KAS_IFC_BYTE_MAX, &(stc->dlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (d)");
            return rv;
        }
    }

    if (n) {
        stc->n = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->n) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(n, stc->n, ACVP_KAS_IFC_BYTE_MAX, &(stc->nlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (n)");
            return rv;
        }
    }

    if (e) {
        stc->e = calloc(1, ACVP_RSA_EXP_LEN_MAX);
        if (!stc->e) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(e, stc->e, ACVP_RSA_EXP_LEN_MAX, &(stc->elen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (e)");
            return rv;
        }
    }

    if (dmp1) {
        stc->dmp1 = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->dmp1) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(dmp1, stc->dmp1, ACVP_KAS_IFC_BYTE_MAX, &(stc->dmp1_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (dmp1)");
            return rv;
        }
    }

    if (dmq1) {
        stc->dmq1 = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->dmq1) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(dmq1, stc->dmq1, ACVP_KAS_IFC_BYTE_MAX, &(stc->dmq1_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (dmq1)");
            return rv;
        }
    }

    if (iqmp) {
        stc->iqmp = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->iqmp) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(iqmp, stc->iqmp, ACVP_KAS_IFC_BYTE_MAX, &(stc->iqmp_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (iqmp)");
            return rv;
        }
    }

    if (server_ct_z) {
        stc->server_ct_z = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->server_ct_z) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(server_ct_z, stc->server_ct_z, ACVP_KAS_IFC_BYTE_MAX, &(stc->server_ct_z_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (server_ct_z)");
            return rv;
        }
    }

    if (kas2_z) {
        stc->provided_kas2_z = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->provided_kas2_z) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(kas2_z, stc->provided_kas2_z, ACVP_KAS_IFC_BYTE_MAX, &(stc->provided_kas2_z_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (kas2_z)");
            return rv;
        }
    }

    if (server_n) {
        stc->server_n = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->server_n) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(server_n, stc->server_n, ACVP_KAS_IFC_BYTE_MAX, &(stc->server_nlen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (server_n)");
            return rv;
        }
    }

    if (server_e) {
        stc->server_e = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
        if (!stc->server_e) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(server_e, stc->server_e, ACVP_RSA_EXP_LEN_MAX, &(stc->server_elen));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (server_e)");
            return rv;
        }
    }

    stc->iut_ct_z = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
    if (!stc->iut_ct_z) { return ACVP_MALLOC_FAIL; }
    if (ct_z) {
        rv = acvp_hexstr_to_bin(ct_z, stc->iut_ct_z, ACVP_KAS_IFC_BYTE_MAX, &(stc->iut_ct_z_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (ct_z)");
            return rv;
        }
    }
    stc->iut_pt_z = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
    if (!stc->iut_pt_z) { return ACVP_MALLOC_FAIL; }
    if (pt_z) {
        rv = acvp_hexstr_to_bin(pt_z, stc->iut_pt_z, ACVP_KAS_IFC_BYTE_MAX, &(stc->iut_pt_z_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (pt_z)");
            return rv;
        }
    }
    stc->server_pt_z = calloc(1, ACVP_KAS_IFC_BYTE_MAX + 1);
    if (!stc->server_pt_z) { return ACVP_MALLOC_FAIL; }

    if (stc->test_type == ACVP_KAS_IFC_TT_VAL) {
        if (stc->kas_role == ACVP_KAS_IFC_INITIATOR) {
            stc->provided_ct_z = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
            if (!stc->provided_ct_z) { return ACVP_MALLOC_FAIL; }
            rv = acvp_hexstr_to_bin(ct_z, stc->provided_ct_z, ACVP_KAS_IFC_BYTE_MAX, &(stc->provided_ct_z_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (provided_iut_ct_z)");
                return rv;
            }
        } else {
            stc->provided_pt_z = calloc(1, ACVP_KAS_IFC_BYTE_MAX);
            if (!stc->provided_pt_z) { return ACVP_MALLOC_FAIL; }
            rv = acvp_hexstr_to_bin(pt_z, stc->provided_pt_z, ACVP_KAS_IFC_BYTE_MAX, &(stc->provided_pt_z_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (provided_iut_pt_z)");
                return rv;
            }
        }
    }

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kas_ifc_release_tc(ACVP_KAS_IFC_TC *stc) {
    if (stc->server_n) free(stc->server_n);
    if (stc->server_e) free(stc->server_e);
    if (stc->p) free(stc->p);
    if (stc->q) free(stc->q);
    if (stc->d) free(stc->d);
    if (stc->e) free(stc->e);
    if (stc->n) free(stc->n);
    if (stc->dmp1) free(stc->dmp1);
    if (stc->dmq1) free(stc->dmq1);
    if (stc->iqmp) free(stc->iqmp);
    if (stc->iut_ct_z) free(stc->iut_ct_z);
    if (stc->iut_pt_z) free(stc->iut_pt_z);
    if (stc->provided_ct_z) free(stc->provided_ct_z);
    if (stc->provided_pt_z) free(stc->provided_pt_z);
    if (stc->server_pt_z) free(stc->server_pt_z);
    if (stc->server_ct_z) free(stc->server_ct_z);
    if (stc->provided_kas2_z) free(stc->provided_kas2_z);
    memzero_s(stc, sizeof(ACVP_KAS_IFC_TC));
    return ACVP_SUCCESS;
}

static ACVP_KAS_IFC_TEST_TYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return ACVP_KAS_IFC_TT_AFT;

    strcmp_s("VAL", 3, str, &diff);
    if (!diff) return ACVP_KAS_IFC_TT_VAL;

    return 0;
}

static ACVP_KAS_IFC_KEYGEN read_key_gen(const char *str){
    int diff;

    strcmp_s("rsakpg1-basic", 13, str, &diff);
    if (!diff) return ACVP_KAS_IFC_RSAKPG1_BASIC;
    strcmp_s("rsakpg1-crt", 11, str, &diff);
    if (!diff) return ACVP_KAS_IFC_RSAKPG1_CRT;
    strcmp_s("rsakpg1-prime-factor", 20, str, &diff);
    if (!diff) return ACVP_KAS_IFC_RSAKPG1_PRIME_FACTOR;
    strcmp_s("rsakpg2-basic", 13, str, &diff);
    if (!diff) return ACVP_KAS_IFC_RSAKPG2_BASIC;
    strcmp_s("rsakpg2-crt", 11, str, &diff);
    if (!diff) return ACVP_KAS_IFC_RSAKPG2_CRT;
    strcmp_s("rsakpg2-prime-factor", 20, str, &diff);
    if (!diff) return ACVP_KAS_IFC_RSAKPG2_PRIME_FACTOR;

    return 0;
}

static ACVP_RESULT acvp_kas_ifc_ssc(ACVP_CTX *ctx,
                                    ACVP_CAPS_LIST *cap,
                                    ACVP_TEST_CASE *tc,
                                    ACVP_KAS_IFC_TC *stc,
                                    JSON_Object *obj,
                                    JSON_Array *r_garr) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Array *groups;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *tests, *r_tarr = NULL;
    JSON_Value *r_tval = NULL, *r_gval = NULL;  // Response testval, groupval
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; // Response testobj, groupobj
    // KAS key vals
    const char *p = NULL, *q = NULL, *n = NULL, *d = NULL, *e = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    const char *server_n = NULL, *server_e = NULL;
    const char *pub_exp = NULL, *kas_role = NULL, *scheme_str = NULL, *hash = NULL;
    const char *ct_z = NULL, *pt_z = NULL, *kas2_z = NULL;
    const char *server_ct_z = NULL;
    ACVP_HASH_ALG hash_alg = 0;
    unsigned int modulo;
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id, diff;
    ACVP_RESULT rv;
    const char *test_type_str, *key_gen_str = NULL;
    ACVP_KAS_IFC_TEST_TYPE test_type;
    ACVP_KAS_IFC_ROLES role = 0;
    ACVP_KAS_IFC_PARAM scheme = ACVP_KAS_IFC_KAS1;
    ACVP_KAS_IFC_KEYGEN key_gen = 0;

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
            ACVP_LOG_ERR("Missing tgid from server JSON group obj");
            rv = ACVP_MALFORMED_JSON;
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");


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

        key_gen_str = json_object_get_string(groupobj, "keyGenerationMethod");
        if (!key_gen_str) {
            ACVP_LOG_ERR("Server JSON missing 'keyGenerationMethod'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        key_gen = read_key_gen(key_gen_str);
        if (!key_gen) {
            ACVP_LOG_ERR("Server JSON invalid 'key_gen'");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        scheme_str = json_object_get_string(groupobj, "scheme");
        if (!scheme_str) {
            ACVP_LOG_ERR("Server JSON missing 'scheme'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }
        strcmp_s("KAS1", 4, scheme_str, &diff);
        if (!diff) scheme = ACVP_KAS_IFC_KAS1;
        strcmp_s("KAS2", 4, scheme_str, &diff);
        if (!diff) scheme = ACVP_KAS_IFC_KAS2;


        // If the user doesn't specify a hash function, neither does the server
        if (cap && cap->cap.kas_ifc_cap && cap->cap.kas_ifc_cap->hash != ACVP_NO_SHA) {
            hash = json_object_get_string(groupobj, "hashFunctionZ");
            if (!hash) {
                ACVP_LOG_ERR("Server JSON missing 'hashFunctionZ'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            hash_alg = acvp_lookup_hash_alg(hash);
                switch (hash_alg) {
                case ACVP_SHA224:
                case ACVP_SHA256:
                case ACVP_SHA384:
                case ACVP_SHA512:
                case ACVP_SHA512_224:
                case ACVP_SHA512_256:
                case ACVP_SHA3_224:
                case ACVP_SHA3_256:
                case ACVP_SHA3_384:
                case ACVP_SHA3_512:
                    break;
                case ACVP_SHA1:
                case ACVP_SHAKE_128:
                case ACVP_SHAKE_256:
                case ACVP_NO_SHA:
                case ACVP_HASH_ALG_MAX:
                default:
                    ACVP_LOG_ERR("Server JSON invalid 'hashFunctionZ'");
                    rv = ACVP_INVALID_ARG;
                    goto err;
            }
        }

        kas_role = json_object_get_string(groupobj, "kasRole");
        if (!kas_role) {
            ACVP_LOG_ERR("Server JSON missing 'kasRole'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        strcmp_s("initiator", 9, kas_role, &diff);
        if (!diff) role = ACVP_KAS_IFC_INITIATOR;
        strcmp_s("responder", 9, kas_role, &diff);
        if (!diff) role = ACVP_KAS_IFC_RESPONDER;

        pub_exp = json_object_get_string(groupobj, "fixedPubExp");
        if (!pub_exp) {
            ACVP_LOG_ERR("Server JSON missing 'fixedPubExp'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        modulo = json_object_get_number(groupobj, "modulo");
        if (!modulo) {
            ACVP_LOG_ERR("Server JSON missing 'modulo'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }


        ACVP_LOG_VERBOSE("    Test group: %d", i);
        ACVP_LOG_VERBOSE("      test type: %s", test_type_str);
        ACVP_LOG_VERBOSE("         scheme: %s", scheme_str);
        ACVP_LOG_VERBOSE("       kas role: %s", kas_role);
        ACVP_LOG_VERBOSE("        pub exp: %s", pub_exp);
        ACVP_LOG_VERBOSE("        key gen: %s", key_gen_str);
        ACVP_LOG_VERBOSE("           hash: %s", hash);
        ACVP_LOG_VERBOSE("         modulo: %d", modulo);
        ACVP_LOG_VERBOSE("           role: %d", role);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {

            ACVP_LOG_VERBOSE("Found new KAS-IFC Component test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            if (role == ACVP_KAS_IFC_RESPONDER || scheme == ACVP_KAS_IFC_KAS2) {
                p = json_object_get_string(testobj, "iutP");
                if (!p) {
                    ACVP_LOG_ERR("Server JSON missing 'iutP'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(p, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_KAS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("p too long, max allowed=(%d)",
                                  ACVP_KAS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                q = json_object_get_string(testobj, "iutQ");
                if (!q) {
                    ACVP_LOG_ERR("Server JSON missing 'iutQ'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(q, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_KAS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("q too long, max allowed=(%d)",
                                  ACVP_KAS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                if (strnlen_s(d, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_KAS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("d too long, max allowed=(%d)",
                                  ACVP_KAS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                n = json_object_get_string(testobj, "iutN");
                if (!n) {
                    ACVP_LOG_ERR("Server JSON missing 'iutN'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(n, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_KAS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("n too long, max allowed=(%d)",
                                  ACVP_KAS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                e = json_object_get_string(testobj, "iutE");
                if (!e) {
                    ACVP_LOG_ERR("Server JSON missing 'iutE'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(e, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) {
                    ACVP_LOG_ERR("e too long, max allowed=(%d)",
                                  ACVP_KAS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                if (key_gen == ACVP_KAS_IFC_RSAKPG1_CRT || key_gen == ACVP_KAS_IFC_RSAKPG2_CRT) {
                    dmp1 = json_object_get_string(testobj, "iutDmp1");
                    if (!dmp1) {
                        ACVP_LOG_ERR("Server JSON missing 'iutDmp1'");
                        rv = ACVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(dmp1, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_KAS_IFC_STR_MAX) {
                        ACVP_LOG_ERR("dmp1 too long, max allowed=(%d)",
                                    ACVP_KAS_IFC_STR_MAX);
                        rv = ACVP_INVALID_ARG;
                        goto err;
                    }
                    dmq1 = json_object_get_string(testobj, "iutDmq1");
                    if (!dmq1) {
                        ACVP_LOG_ERR("Server JSON missing 'iutDmq1'");
                        rv = ACVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(dmq1, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_KAS_IFC_STR_MAX) {
                        ACVP_LOG_ERR("dmq1 too long, max allowed=(%d)",
                                    ACVP_KAS_IFC_STR_MAX);
                        rv = ACVP_INVALID_ARG;
                        goto err;
                    }
                    iqmp = json_object_get_string(testobj, "iutIqmp");
                    if (!iqmp) {
                        ACVP_LOG_ERR("Server JSON missing 'iutIqmp'");
                        rv = ACVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(iqmp, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_KAS_IFC_STR_MAX) {
                        ACVP_LOG_ERR("iqmp too long, max allowed=(%d)",
                                    ACVP_KAS_IFC_STR_MAX);
                        rv = ACVP_INVALID_ARG;
                        goto err;
                    }
                }

                if (key_gen != ACVP_KAS_IFC_RSAKPG1_CRT && key_gen != ACVP_KAS_IFC_RSAKPG2_CRT) {
                    d = json_object_get_string(testobj, "iutD");
                    if (!d) {
                        ACVP_LOG_ERR("Server JSON missing 'iutD'");
                        rv = ACVP_MISSING_ARG;
                        goto err;
                    }
                }
            }

            if (role == ACVP_KAS_IFC_INITIATOR || scheme == ACVP_KAS_IFC_KAS2) {
                server_n = json_object_get_string(testobj, "serverN");
                if (!server_n) {
                    ACVP_LOG_ERR("Server JSON missing 'serverN'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(server_n, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_KAS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("serverN too long, max allowed=(%d)",
                                  ACVP_KAS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                server_e = json_object_get_string(testobj, "serverE");
                if (!server_e) {
                    ACVP_LOG_ERR("Server JSON missing 'serverE'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(server_e, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_KAS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("serverE too long, max allowed=(%d)",
                                  ACVP_KAS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            if (role == ACVP_KAS_IFC_RESPONDER || scheme == ACVP_KAS_IFC_KAS2) {
                server_ct_z = json_object_get_string(testobj, "serverC");
                if (!server_ct_z) {
                    ACVP_LOG_ERR("Server JSON missing 'serverC'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(server_ct_z, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_KAS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("serverC too long, max allowed=(%d)",
                                  ACVP_KAS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            if (scheme == ACVP_KAS_IFC_KAS2) {
                server_n = json_object_get_string(testobj, "serverN");
                if (!server_n) {
                    ACVP_LOG_ERR("Server JSON missing 'serverN'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(server_n, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_KAS_IFC_STR_MAX) {
                    ACVP_LOG_ERR("n too long, max allowed=(%d)",
                                ACVP_KAS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
                server_e = json_object_get_string(testobj, "serverE");
                if (!server_e) {
                    ACVP_LOG_ERR("Server JSON missing 'serverE'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(server_e, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) {
                    ACVP_LOG_ERR("e too long, max allowed=(%d)",
                                ACVP_KAS_IFC_STR_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            /**
             * Z values can get messy. iutZ and z are the same for KAS1 cases, but for KAS2,
             * z is serverZ || iutZ. Ideally, serverZ would be specified separately in these cases
             * for SSC since SSC should not really cover how the z values are combined in KAS2; handle
             * concatenation ourselves in library for convenience.
             */
            if (test_type == ACVP_KAS_IFC_TT_VAL) {
                if (scheme == ACVP_KAS_IFC_KAS1) {
                    if (role == ACVP_KAS_IFC_INITIATOR) {
                        pt_z = json_object_get_string(testobj, "iutZ");
                    } else {
                        pt_z = json_object_get_string(testobj, "z");
                    }
                } else {
                    pt_z = json_object_get_string(testobj, "iutZ");
                }
                if (!pt_z) {
                    ACVP_LOG_ERR("Server JSON missing 'z' or 'iutZ''");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }

                if (role == ACVP_KAS_IFC_INITIATOR  || scheme == ACVP_KAS_IFC_KAS2) {
                    ct_z = json_object_get_string(testobj, "iutC");
                    if (!ct_z) {
                        ACVP_LOG_ERR("Server JSON missing 'iutC'");
                        rv = ACVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(ct_z, ACVP_KAS_IFC_STR_MAX + 1) > ACVP_KAS_IFC_STR_MAX) {
                        ACVP_LOG_ERR("c too long, max allowed=(%d)",
                                      ACVP_KAS_IFC_STR_MAX);
                        rv = ACVP_INVALID_ARG;
                        goto err;
                    }
                }
            }

            if (scheme == ACVP_KAS_IFC_KAS2 && test_type == ACVP_KAS_IFC_TT_VAL) {
                if (hash) {
                    kas2_z = json_object_get_string(testobj, "hashZ");
                } else {
                    kas2_z = json_object_get_string(testobj, "z");
                }
                if (!kas2_z) {
                    ACVP_LOG_ERR("Server JSON missing 'z'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
            }

            ACVP_LOG_VERBOSE("           tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("              p: %s", p);
            ACVP_LOG_VERBOSE("              q: %s", q);
            ACVP_LOG_VERBOSE("              n: %s", n);
            ACVP_LOG_VERBOSE("              d: %s", d);
            ACVP_LOG_VERBOSE("              e: %s", e);
            if (key_gen == ACVP_KAS_IFC_RSAKPG1_CRT || key_gen == ACVP_KAS_IFC_RSAKPG2_CRT) {
                ACVP_LOG_VERBOSE("           dmp1: %s", dmp1);
                ACVP_LOG_VERBOSE("           dmq1: %s", dmq1);
                ACVP_LOG_VERBOSE("           iqmp: %s", iqmp);
            }
            if (hash) {
                ACVP_LOG_VERBOSE("          hashZ: %s", pt_z);
            } else {
                ACVP_LOG_VERBOSE("              z: %s", pt_z);
            }
            ACVP_LOG_VERBOSE("              c: %s", ct_z);

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
            rv = acvp_kas_ifc_ssc_init_tc(ctx, stc, key_gen, hash_alg, scheme, role, pt_z, ct_z,
                                          server_ct_z, kas2_z, server_n, server_e, p, q, d, n,
                                          e, dmp1, dmq1, iqmp, modulo, test_type);
            if (rv != ACVP_SUCCESS) {
                acvp_kas_ifc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            // Process the current KAT test vector...
            if ((cap->crypto_handler)(tc)) {
                acvp_kas_ifc_release_tc(stc);
                ACVP_LOG_ERR("Crypto module failed the operation");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            if (stc->test_type == ACVP_KAS_IFC_TT_VAL) {
                rv = acvp_kas_ifc_ssc_val_output_tc(stc, r_tobj);
            } else {
                rv = acvp_kas_ifc_ssc_output_tc(ctx, stc, r_tobj);
            }
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure recording test response");
                acvp_kas_ifc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_kas_ifc_release_tc(stc);

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

ACVP_RESULT acvp_kas_ifc_ssc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_garr = NULL; // Response testarray
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    ACVP_CAPS_LIST *cap;
    ACVP_TEST_CASE tc;
    ACVP_KAS_IFC_TC stc;
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
    tc.tc.kas_ifc = &stc;
    memzero_s(&stc, sizeof(ACVP_KAS_IFC_TC));

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
    cap = acvp_locate_cap_entry(ctx, ACVP_KAS_IFC_SSC);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        rv = ACVP_UNSUPPORTED_OP;
        goto err;
    }
    rv = acvp_kas_ifc_ssc(ctx, cap, &tc, &stc, obj, r_garr);
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
        acvp_kas_ifc_release_tc(&stc);
        json_value_free(r_vs_val);
    }
    return rv;
}
