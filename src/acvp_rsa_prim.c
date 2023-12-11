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
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_rsa_decprim_output_tc_rev_1(ACVP_CTX *ctx, ACVP_RSA_PRIM_TC *stc, JSON_Object *tc_rsp) {
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

static ACVP_RESULT acvp_rsa_decprim_output_tc_rev_56br2(ACVP_CTX *ctx, ACVP_RSA_PRIM_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_RSA_EXP_LEN_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_rsa_decprim tpm_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    json_object_set_boolean(tc_rsp, "testPassed", stc->disposition);
    if (stc->disposition) {
        rv = acvp_bin_to_hexstr(stc->pt, stc->pt_len, tmp, ACVP_RSA_EXP_LEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (pt)");
            goto err;
        }
        json_object_set_string(tc_rsp, "pt", (const char *)tmp);
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
    if (stc->d) { free(stc->d); }
    if (stc->p) { free(stc->p); }
    if (stc->q) { free(stc->q); }
    if (stc->iqmp) { free(stc->iqmp); }
    if (stc->dmp1) { free(stc->dmp1); }
    if (stc->dmq1) { free(stc->dmq1); }
    memzero_s(stc, sizeof(ACVP_RSA_PRIM_TC));

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_rsa_sigprim_release_tc(ACVP_RSA_PRIM_TC *stc) {
    if (stc->e) { free(stc->e); }
    if (stc->d) { free(stc->d); }
    if (stc->n) { free(stc->n); }
    if (stc->p) { free(stc->p); }
    if (stc->q) { free(stc->q); }
    if (stc->dmp1) { free(stc->dmp1); }
    if (stc->dmq1) { free(stc->dmq1); }
    if (stc->iqmp) { free(stc->iqmp); }
    if (stc->pt) { free(stc->pt); }
    if (stc->msg) { free(stc->msg); }
    if (stc->signature) { free(stc->signature); }
    memzero_s(stc, sizeof(ACVP_RSA_PRIM_TC));

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_rsa_decprim_init_tc_rev_1(ACVP_CTX *ctx,
                                            ACVP_RSA_PRIM_TC *stc,
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

static ACVP_RESULT acvp_rsa_decprim_init_tc_rev_56br2(ACVP_CTX *ctx,
                                                      ACVP_RSA_PRIM_TC *stc,
                                                      ACVP_RSA_PUB_EXP_MODE exp_mode,
                                                      int modulo,
                                                      ACVP_RSA_KEY_FORMAT format,
                                                      const char *d,
                                                      const char *e,
                                                      const char *n,
                                                      const char *p,
                                                      const char *q,
                                                      const char *dmp1,
                                                      const char *dmq1,
                                                      const char *iqmp,
                                                      const char *ct) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_RSA_PRIM_TC));
    stc->modulo = modulo;
    stc->pub_exp_mode = exp_mode;
    stc->key_format = format;

    stc->pt = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->pt) {
        return ACVP_MALLOC_FAIL;
    }

    stc->cipher = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->cipher) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(ct, stc->cipher, ACVP_RSA_EXP_BYTE_MAX, &(stc->cipher_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (cipher)");
        return rv;
    }


    stc->n = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->n) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(n, stc->n, ACVP_RSA_EXP_BYTE_MAX, &(stc->n_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (n)");
        return rv;
    }

    stc->e = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->e) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(e, stc->e, ACVP_RSA_EXP_BYTE_MAX, &(stc->e_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (e)");
        return rv;
    }

    stc->d = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->d) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(d, stc->d, ACVP_RSA_EXP_BYTE_MAX, &(stc->d_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (d)");
        return rv;
    }

    stc->p = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->p) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(p, stc->p, ACVP_RSA_EXP_BYTE_MAX, &(stc->p_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (p)");
        return rv;
    }

    stc->q = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->q) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(q, stc->q, ACVP_RSA_EXP_BYTE_MAX, &(stc->q_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (q");
        return rv;
    }

    if (dmp1) {
        stc->dmp1 = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->dmp1) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(dmp1, stc->dmp1, ACVP_RSA_EXP_BYTE_MAX, &(stc->dmp1_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (dmp1)");
            return rv;
        }
    }

    if (dmq1) {
        stc->dmq1 = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->dmq1) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(dmq1, stc->dmq1, ACVP_RSA_EXP_BYTE_MAX, &(stc->dmq1_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (dmq1)");
            return rv;
        }
    }

    if (iqmp) {
        stc->iqmp = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->iqmp) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(iqmp, stc->iqmp, ACVP_RSA_EXP_BYTE_MAX, &(stc->iqmp_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (iqmp)");
            return rv;
        }
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_rsa_sigprim_init_tc(ACVP_CTX *ctx,
                                            ACVP_RSA_PRIM_TC *stc,
                                            unsigned int modulo,
                                            unsigned int keyformat,
                                            const char *d_str,
                                            const char *e_str,
                                            const char *n_str,
                                            const char *p_str,
                                            const char *q_str,
                                            const char *dmp1_str,
                                            const char *dmq1_str,
                                            const char *iqmp_str,
                                            const char *msg) {

    ACVP_RESULT rv = ACVP_SUCCESS;

    memzero_s(stc, sizeof(ACVP_RSA_PRIM_TC));

    stc->e = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->e) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(e_str, stc->e, ACVP_RSA_EXP_BYTE_MAX, &(stc->e_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (e)");
        return rv;
    }

    if (d_str) {
        stc->d = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->d) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(d_str, stc->d, ACVP_RSA_EXP_BYTE_MAX, &(stc->d_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (d)");
            return rv;
        }
    }

    stc->n = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->n) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(n_str, stc->n, ACVP_RSA_EXP_BYTE_MAX, &(stc->n_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (n)");
        return rv;
    }

    if (p_str) {
        stc->p = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->p) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(p_str, stc->p, ACVP_RSA_EXP_BYTE_MAX, &(stc->p_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (p)");
            return rv;
        }
    }

    if (q_str) {
        stc->q = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->q) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(q_str, stc->q, ACVP_RSA_EXP_BYTE_MAX, &(stc->q_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (q");
            return rv;
        }
    }

    if (dmp1_str) {
        stc->dmp1 = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->dmp1) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(dmp1_str, stc->dmp1, ACVP_RSA_EXP_BYTE_MAX, &(stc->dmp1_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (dmp1)");
            return rv;
        }
    }

    if (dmq1_str) {
        stc->dmq1 = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->dmq1) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(dmq1_str, stc->dmq1, ACVP_RSA_EXP_BYTE_MAX, &(stc->dmq1_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (dmq1)");
            return rv;
        }
    }

    if (iqmp_str) {
        stc->iqmp = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->iqmp) { return ACVP_MALLOC_FAIL; }
        rv = acvp_hexstr_to_bin(iqmp_str, stc->iqmp, ACVP_RSA_EXP_BYTE_MAX, &(stc->iqmp_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (iqmp)");
            return rv;
        }
    }

    stc->msg = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->msg) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_RSA_EXP_BYTE_MAX, &(stc->msg_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    stc->modulo = modulo;
    stc->key_format = keyformat;
    stc->signature = calloc(ACVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->signature) { return ACVP_MALLOC_FAIL; }

    return ACVP_SUCCESS;
}

ACVP_RSA_KEY_FORMAT acvp_rsa_get_key_format(const char *key_format) {
    ACVP_RSA_KEY_FORMAT keyformat = 0;
    int diff = 0;

    strcmp_s("standard", 8, key_format, &diff);
    if (!diff) keyformat = ACVP_RSA_KEY_FORMAT_STANDARD;

    strcmp_s("crt", 3, key_format, &diff);
    if (!diff) keyformat = ACVP_RSA_KEY_FORMAT_CRT;

    return keyformat;
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
    ACVP_RSA_KEY_FORMAT keyformat = 0;

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
    ACVP_RSA_PUB_EXP_MODE pub_exp_mode = 0;
    char *json_result = NULL;
    unsigned int mod = 0, total = 0, fail = 0, pass = 0;
    const char *alg_str = NULL, *mode_str = NULL, *cipher = NULL, *rev_str = NULL, *key_format = NULL, *pub_exp_mode_str = NULL,
               *e_str = NULL, *n_str = NULL, *d_str = NULL, *p_str = NULL, *q_str = NULL,
               *dmp1_str = NULL, *dmq1_str = NULL, *iqmp_str = NULL;

    int deferred = 0, old_rev = 0;
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

    rev_str = json_object_get_string(obj, "revision");
    if (!rev_str) {
        ACVP_LOG_ERR("Missing 'revision' from server json");
        return ACVP_MISSING_ARG;
    }
    if (acvp_lookup_alt_revision(rev_str) == ACVP_REVISION_1_0) {
        old_rev = 1;
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
        if (old_rev) {
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
        } else {
            mod = json_object_get_number(groupobj, "modulo");
            if (mod != 2048 && mod != 3072 && mod != 4096) {
                ACVP_LOG_ERR("Server JSON invalid modulo");
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            key_format = json_object_get_string(groupobj, "keyMode");
            if (!key_format) {
                ACVP_LOG_ERR("Missing keyMode from server json");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            keyformat = acvp_rsa_get_key_format(key_format);
            if (!keyformat) {
                ACVP_LOG_ERR("Invalid key format/mode from server");
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            pub_exp_mode_str = json_object_get_string(groupobj, "pubExpMode");
            if (!pub_exp_mode_str) {
                ACVP_LOG_ERR("Server JSON missing 'pubExpMode'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            /* Even if fixed, we don't need to parse the pubExp value, its included in each test case as e */
            pub_exp_mode = acvp_lookup_rsa_pub_exp_mode(pub_exp_mode_str);
            if (!pub_exp_mode) {
                ACVP_LOG_ERR("Server JSON invalid 'pubExpMode'");
                rv = ACVP_INVALID_ARG;
                goto err;
            }
        }

        ACVP_LOG_VERBOSE("       Test Group: %d", i);
        ACVP_LOG_VERBOSE("           Modulo: %d", mod);
        if (key_format) {
            ACVP_LOG_VERBOSE("       Key Format: %s", key_format);
        }
        if (pub_exp_mode) {
            ACVP_LOG_VERBOSE("       Pub Exp Mode: %s", pub_exp_mode_str);
        }

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

            if (old_rev) {
                /* Retrieve values from JSON and initialize the tc */
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
                        json_value_free(r_cval);
                        goto err;
                    }
                    cipher_len = strnlen_s(cipher, ACVP_RSA_EXP_BYTE_MAX + 1);
                    if (cipher_len > ACVP_RSA_EXP_BYTE_MAX) {
                        ACVP_LOG_ERR("'cipher' too long, max allowed=(%d)",
                                     ACVP_RSA_SEEDLEN_MAX);
                        rv = ACVP_INVALID_ARG;
                        json_value_free(r_tval);
                        json_value_free(r_cval);
                        goto err;
                    }

                    rv = acvp_rsa_decprim_init_tc_rev_1(ctx, &stc, mod, deferred, pass, fail, cipher, cipher_len);
                    if (rv == ACVP_SUCCESS) {
                       fail = stc.fail;
                       pass = stc.pass;
                       do {
                           if ((cap->crypto_handler)(&tc)) {
                               ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                               rv = ACVP_CRYPTO_MODULE_FAIL;
                               json_value_free(r_tval);
                               json_value_free(r_cval);
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
                    rv = acvp_rsa_decprim_output_tc_rev_1(ctx, &stc, r_cobj);
                    if (rv != ACVP_SUCCESS) {
                        ACVP_LOG_ERR("ERROR: JSON output failure in primitive module");
                        json_value_free(r_tval);
                        json_value_free(r_cval);
                        goto err;
                    }
                    json_array_append_value(r_carr, r_cval);

                    /* Release all the memory associated with the test case */
                    acvp_rsa_decprim_release_tc(&stc);
                }
            } else {
                e_str = json_object_get_string(testobj, "e");
                n_str = json_object_get_string(testobj, "n");
                p_str = json_object_get_string(testobj, "p");
                q_str = json_object_get_string(testobj, "q");
                d_str = json_object_get_string(testobj, "d");
                if (!e_str || !n_str || !p_str || !q_str || !d_str) {
                    ACVP_LOG_ERR("Missing e|n|p|q|d from server json");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                if ((strnlen_s(e_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                    (strnlen_s(n_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                    (strnlen_s(p_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                    (strnlen_s(q_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                    (strnlen_s(d_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX)) {
                    ACVP_LOG_ERR("server provided e/n/p/q/d of invalid length");
                    rv = ACVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                if (keyformat == ACVP_RSA_KEY_FORMAT_CRT) {
                    dmp1_str = json_object_get_string(testobj, "dmp1");
                    dmq1_str = json_object_get_string(testobj, "dmq1");
                    iqmp_str = json_object_get_string(testobj, "iqmp");
                    if (!p_str || !q_str || !dmp1_str || !dmq1_str || !iqmp_str) {
                        ACVP_LOG_ERR("Missing p|q|dmp1|dmq1|iqmp from server json");
                        rv = ACVP_MISSING_ARG;
                        json_value_free(r_tval);
                        goto err;
                    }
                    if ((strnlen_s(dmp1_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                        (strnlen_s(dmq1_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                        (strnlen_s(iqmp_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX)) {
                        ACVP_LOG_ERR("server provided p/q/dmp1/dmq1/iqmp of invalid length");
                        rv = ACVP_INVALID_ARG;
                        json_value_free(r_tval);
                        goto err;
                    }
                }
                cipher = json_object_get_string(testobj, "ct");
                if (!cipher) {
                    ACVP_LOG_ERR("Server JSON missing 'ct'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }

                rv = acvp_rsa_decprim_init_tc_rev_56br2(ctx, &stc, keyformat, mod, keyformat, d_str, e_str, n_str, p_str,
                                                        q_str, dmp1_str, dmq1_str, iqmp_str, cipher);
                if (rv == ACVP_SUCCESS) {
                    if ((cap->crypto_handler)(&tc)) {
                        ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                        rv = ACVP_CRYPTO_MODULE_FAIL;
                        json_value_free(r_tval);
                        goto err;
                    }
                }

                /* Output the test case results using JSON */
                rv = acvp_rsa_decprim_output_tc_rev_56br2(ctx, &stc, r_tobj);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("ERROR: JSON output failure in primitive module");
                    json_value_free(r_tval);
                    goto err;
                }

                /* Release all the memory associated with the test case */
                acvp_rsa_decprim_release_tc(&stc);
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
    int old_rev = 0;
    unsigned int mod = 0;
    unsigned int keyformat = 0;
    const char *key_format = NULL;
    ACVP_CIPHER alg_id;
    char *json_result = NULL;
    const char *mode_str;
    const char *msg;
    const char *e_str = NULL, *n_str = NULL, *d_str = NULL, *p_str = NULL, *q_str = NULL,
               *dmp1_str = NULL, *dmq1_str = NULL, *iqmp_str = NULL, *rev_str = NULL;
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

    /* Assume alternate revision is 1.0, need to handle a few things differently */
    rev_str = json_object_get_string(obj, "revision");
    if (!rev_str) {
        ACVP_LOG_ERR("Missing 'revision' from server json");
        return ACVP_MISSING_ARG;
    }
    if (acvp_lookup_alt_revision(rev_str) == ACVP_REVISION_1_0) {
        old_rev = 1;
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

        if (old_rev) {
            mod = json_object_get_number(groupobj, "modulus");
            if (mod != 2048) {
                ACVP_LOG_ERR("Server JSON invalid modulus");
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            key_format = json_object_get_string(groupobj, "keyFormat");
            if (!key_format) {
                ACVP_LOG_ERR("Missing keyFormat from server json");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
        } else {
            mod = json_object_get_number(groupobj, "modulo");
            if (mod != 2048 && mod != 3072 && mod != 4096) {
                ACVP_LOG_ERR("Server JSON invalid modulo");
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            key_format = json_object_get_string(groupobj, "keyMode");
            if (!key_format) {
                ACVP_LOG_ERR("Missing keyMode from server json");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
        }

        keyformat = acvp_rsa_get_key_format(key_format);
        if (!keyformat) {
            ACVP_LOG_ERR("Invalid key format/mode from server");
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        ACVP_LOG_VERBOSE("       Test Group: %d", i);
        ACVP_LOG_VERBOSE("       Key Format: %s", key_format);
        ACVP_LOG_VERBOSE("           Modulo: %d", mod);

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
            if (!e_str || !n_str) {
                ACVP_LOG_ERR("Missing e|n from server json");
                rv = ACVP_MISSING_ARG;
                json_value_free(r_tval);
                goto err;
            }
            if ((strnlen_s(e_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                (strnlen_s(n_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX)) {
                ACVP_LOG_ERR("server provided e/n of invalid length");
                rv = ACVP_INVALID_ARG;
                json_value_free(r_tval);
                goto err;
            }
            if (keyformat == ACVP_RSA_KEY_FORMAT_CRT) {
                p_str = json_object_get_string(testobj, "p");
                q_str = json_object_get_string(testobj, "q");
                dmp1_str = json_object_get_string(testobj, "dmp1");
                dmq1_str = json_object_get_string(testobj, "dmq1");
                iqmp_str = json_object_get_string(testobj, "iqmp");
                if (!p_str || !q_str || !dmp1_str || !dmq1_str || !iqmp_str) {
                    ACVP_LOG_ERR("Missing p|q|dmp1|dmq1|iqmp from server json");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                if ((strnlen_s(p_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                    (strnlen_s(q_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                    (strnlen_s(dmp1_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                    (strnlen_s(dmq1_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                    (strnlen_s(iqmp_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX)) {
                    ACVP_LOG_ERR("server provided p/q/dmp1/dmq1/iqmp of invalid length");
                    rv = ACVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
            } else {
                d_str = json_object_get_string(testobj, "d");
                if (!d_str) {
                    ACVP_LOG_ERR("Missing d from server json");
                    rv = ACVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                if (strnlen_s(d_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) {
                    ACVP_LOG_ERR("server provided d of invalid length");
                }
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

            rv = acvp_rsa_sigprim_init_tc(ctx, &stc, mod, keyformat, d_str, e_str, n_str, p_str,
                                          q_str, dmp1_str, dmq1_str, iqmp_str, msg);

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

