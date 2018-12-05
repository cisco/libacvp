/** @file */
/*****************************************************************************
* Copyright (c) 2016-2017, Cisco Systems, Inc.
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

static ACVP_RESULT acvp_rsa_sig_kat_handler_internal(ACVP_CTX *ctx, JSON_Object *obj, ACVP_CIPHER cipher);

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_rsa_sig_output_tc(ACVP_CTX *ctx, ACVP_RSA_SIG_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    if (stc->sig_mode == ACVP_RSA_SIGVER) {
        json_object_set_boolean(tc_rsp, "testPassed", stc->ver_disposition);
    } else {
        tmp = calloc(ACVP_RSA_SIGNATURE_MAX + 1, sizeof(char));
        if (!tmp) {
            ACVP_LOG_ERR("Unable to malloc in rsa_sigver tpm_output_tc");
            return ACVP_MALLOC_FAIL;
        }
        rv = acvp_bin_to_hexstr(stc->signature, stc->sig_len, tmp, ACVP_RSA_SIGNATURE_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (signature)");
            goto err;
        }
        json_object_set_string(tc_rsp, "signature", (const char *)tmp);
    }

err:
    if (tmp) free(tmp);
    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */

static ACVP_RESULT acvp_rsa_siggen_release_tc(ACVP_RSA_SIG_TC *stc) {
    if (stc->msg) { free(stc->msg); }
    if (stc->e) { free(stc->e); }
    if (stc->n) { free(stc->n); }
    if (stc->signature) { free(stc->signature); }
    if (stc->salt) { free(stc->salt); }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_rsa_sig_init_tc(ACVP_CTX *ctx,
                                        ACVP_CIPHER cipher,
                                        ACVP_RSA_SIG_TC *stc,
                                        int tgId,
                                        unsigned int tc_id,
                                        ACVP_RSA_SIG_TYPE sig_type,
                                        unsigned int mod,
                                        ACVP_HASH_ALG hash_alg,
                                        char *e,
                                        char *n,
                                        char *msg,
                                        char *signature,
                                        char *salt,
                                        int salt_len) {
    ACVP_RESULT rv;

    memset(stc, 0x0, sizeof(ACVP_RSA_SIG_TC));

    stc->msg = calloc(ACVP_RSA_MSGLEN_MAX, sizeof(char));
    if (!stc->msg) { return ACVP_MALLOC_FAIL; }
    stc->signature = calloc(ACVP_RSA_SIGNATURE_MAX, sizeof(char));
    if (!stc->signature) { return ACVP_MALLOC_FAIL; }
    stc->salt = calloc(ACVP_RSA_SIGNATURE_MAX, sizeof(char));
    if (!stc->salt) { return ACVP_MALLOC_FAIL; }

    stc->e = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->e) { return ACVP_MALLOC_FAIL; }
    stc->n = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->n) { goto err; }

    rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_RSA_MSGLEN_MAX, &(stc->msg_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    if (cipher == ACVP_RSA_SIGVER) {
        stc->sig_mode = ACVP_RSA_SIGVER;
        rv = acvp_hexstr_to_bin(e, stc->e, ACVP_RSA_EXP_LEN_MAX, &(stc->e_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (e)");
            return rv;
        }
        rv = acvp_hexstr_to_bin(n, stc->n, ACVP_RSA_EXP_LEN_MAX, &(stc->n_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (n)");
            return rv;
        }
        rv = acvp_hexstr_to_bin(signature, stc->signature, ACVP_RSA_SIGNATURE_MAX, &stc->sig_len);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (signature)");
            return rv;
        }
    } else {
        stc->sig_mode = ACVP_RSA_SIGGEN;
    }

    if (salt_len) {
        if (salt) {
            memcpy(stc->salt, salt, strnlen((const char *)salt, 256));
        }
    }
    stc->salt_len = salt_len;

    stc->tc_id = tc_id;
    stc->tg_id = tgId;
    stc->modulo = mod;
    stc->hash_alg = hash_alg;
    stc->sig_type = sig_type;

    return rv;

err:
    ACVP_LOG_ERR("Failed to allocate buffer in RSA test case");
    if (stc->n) free(stc->n);
    return ACVP_MALLOC_FAIL;
}

ACVP_RESULT acvp_rsa_siggen_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_rsa_sig_kat_handler_internal(ctx, obj, ACVP_RSA_SIGGEN);
}

ACVP_RESULT acvp_rsa_sigver_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    return acvp_rsa_sig_kat_handler_internal(ctx, obj, ACVP_RSA_SIGVER);
}

static ACVP_RESULT acvp_rsa_sig_kat_handler_internal(ACVP_CTX *ctx, JSON_Object *obj, ACVP_CIPHER cipher) {
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
    ACVP_RSA_SIG_TC stc;
    ACVP_TEST_CASE tc;

    ACVP_CIPHER alg_id;
    char *json_result = NULL, *mode_str;
    unsigned int mod = 0;
    char *msg, *signature = NULL;
    char *e_str = NULL, *n_str = NULL;
    char *salt = NULL, *alg_str;
    int salt_len = 0, json_msglen, json_siglen;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    ACVP_RESULT rv;
    alg_str = (char *)json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }
    if (strncmp(alg_str, ACVP_ALG_RSA, strlen(ACVP_ALG_RSA))) {
        ACVP_LOG_ERR("Invalid algorithm %s", alg_str);
        return ACVP_INVALID_ARG;
    }

    tc.tc.rsa_sig = &stc;
    alg_id = cipher;
    stc.sig_mode = alg_id;

    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ERROR: ACVP server requesting unsupported capability");
        return ACVP_UNSUPPORTED_OP;
    }

    mode_str = (char *)json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("Missing 'mode' from server json");
        return ACVP_MISSING_ARG;
    }
    if (strncmp(mode_str, ACVP_MODE_SIGGEN, strlen(ACVP_MODE_SIGGEN)) &&
        strncmp(mode_str, ACVP_MODE_SIGVER, strlen(ACVP_MODE_SIGVER))) {
        ACVP_LOG_ERR("Wrong 'mode' JSON value. Expected '%s' or '%s'",
                     ACVP_MODE_SIGGEN, ACVP_MODE_SIGVER);
        return ACVP_INVALID_ARG;
    }

    ACVP_LOG_INFO("    RSA mode: %s", mode_str);

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
        ACVP_RSA_SIG_TYPE sig_type = 0;
        ACVP_HASH_ALG hash_alg = 0;
        const char *sig_type_str = NULL, *hash_alg_str = NULL;
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

        /*
         * Get a reference to the abstracted test case
         */
        sig_type_str = (char *)json_object_get_string(groupobj, "sigType");
        if (!sig_type_str) {
            ACVP_LOG_ERR("Missing sigType from rsa_siggen json");
            return ACVP_MISSING_ARG;
        }
        if (strncmp(sig_type_str, ACVP_RSA_SIG_TYPE_X931_STR,
                    strlen(ACVP_RSA_SIG_TYPE_X931_STR)) == 0) {
            sig_type = ACVP_RSA_SIG_TYPE_X931;
        } else if (strncmp(sig_type_str, ACVP_RSA_SIG_TYPE_PKCS1V15_STR,
                           strlen(ACVP_RSA_SIG_TYPE_PKCS1V15_STR)) == 0) {
            sig_type = ACVP_RSA_SIG_TYPE_PKCS1V15;
        } else if (strncmp(sig_type_str, ACVP_RSA_SIG_TYPE_PKCS1PSS_STR,
                           strlen(ACVP_RSA_SIG_TYPE_PKCS1PSS_STR)) == 0) {
            sig_type = ACVP_RSA_SIG_TYPE_PKCS1PSS;
        } else {
            ACVP_LOG_ERR("Server JSON invalid 'sigType'");
            return ACVP_INVALID_ARG;
        }

        mod = json_object_get_number(groupobj, "modulo");
        if (!mod) {
            ACVP_LOG_ERR("Server JSON missing 'modulo'");
            return ACVP_MISSING_ARG;
        }
        if (mod != 2048 && mod != 3072 && mod != 4096) {
            ACVP_LOG_ERR("Server JSON invalid 'modulo', (%d)", mod);
            return ACVP_INVALID_ARG;
        }

        hash_alg_str = json_object_get_string(groupobj, "hashAlg");
        if (!hash_alg_str) {
            ACVP_LOG_ERR("Server JSON missing 'hashAlg'");
            return ACVP_MISSING_ARG;
        }
        hash_alg = acvp_lookup_hash_alg(hash_alg_str);
        if (!hash_alg || (alg_id == ACVP_RSA_SIGGEN && hash_alg == ACVP_SHA1)) {
            ACVP_LOG_ERR("Server JSON invalid 'hashAlg'");
            return ACVP_INVALID_ARG;
        }

        salt_len = json_object_get_number(groupobj, "saltLen");

        if (alg_id == ACVP_RSA_SIGVER) {
            e_str = (char *)json_object_get_string(groupobj, "e");
            n_str = (char *)json_object_get_string(groupobj, "n");
            if (!e_str || !n_str) {
                ACVP_LOG_ERR("Missing e|n from server json");
                return ACVP_MISSING_ARG;
            }
            if ((strnlen(e_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX) ||
                (strnlen(n_str, ACVP_RSA_EXP_LEN_MAX + 1) > ACVP_RSA_EXP_LEN_MAX)) {
                ACVP_LOG_ERR("server provided e or n of invalid length");
                return ACVP_INVALID_ARG;
            }
        }

        ACVP_LOG_INFO("       Test group: %d", i);
        ACVP_LOG_INFO("          sigType: %s", sig_type_str);
        ACVP_LOG_INFO("           modulo: %d", mod);
        ACVP_LOG_INFO("          hashAlg: %s", hash_alg_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new RSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");
            if (!tc_id) {
                ACVP_LOG_ERR("Missing tc_id");
                return ACVP_MALFORMED_JSON;
            }

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Get a reference to the abstracted test case
             */

            msg = (char *)json_object_get_string(testobj, "message");
            if (!msg) {
                ACVP_LOG_ERR("Missing 'message' from server json");
                return ACVP_MISSING_ARG;
            }
            json_msglen = strnlen(msg, ACVP_RSA_MSGLEN_MAX + 1);
            if (json_msglen > ACVP_RSA_MSGLEN_MAX) {
                ACVP_LOG_ERR("'message' too long in server json");
                return ACVP_INVALID_ARG;
            }
            ACVP_LOG_INFO("              msg: %s", msg);


            if (alg_id == ACVP_RSA_SIGVER) {
                signature = (char *)json_object_get_string(testobj, "signature");
                if (!signature) {
                    ACVP_LOG_ERR("Missing 'signature' from server json");
                    return ACVP_MISSING_ARG;
                }
                json_siglen = strnlen(signature, ACVP_RSA_SIGNATURE_MAX + 1);
                if (json_siglen > ACVP_RSA_SIGNATURE_MAX) {
                    ACVP_LOG_ERR("'signature' too long in server json");
                    return ACVP_INVALID_ARG;
                }
                salt = (char *)json_object_get_string(testobj, "salt");
            }

            rv = acvp_rsa_sig_init_tc(ctx, alg_id, &stc, tgId, tc_id, sig_type, mod, hash_alg, e_str, n_str, msg, signature, salt, salt_len);

            /* Process the current test vector... */
            if (rv == ACVP_SUCCESS) {
                if ((cap->crypto_handler)(&tc)) {
                    ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                    rv = ACVP_CRYPTO_MODULE_FAIL;
                    goto key_err;
                }
            }
            if (alg_id == ACVP_RSA_SIGGEN) {
                char *tmp = calloc(ACVP_RSA_EXP_LEN_MAX + 1, sizeof(char));
                if (!tmp) {
                    ACVP_LOG_ERR("Unable to malloc in rsa_siggen tpm_output_tc");
                    return ACVP_MALLOC_FAIL;
                }
                rv = acvp_bin_to_hexstr(stc.e, stc.e_len, tmp, ACVP_RSA_EXP_LEN_MAX);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("hex conversion failure (e)");
                    free(tmp);
                    goto end;
                }
                json_object_set_string(r_gobj, "e", (const char *)tmp);
                memset(tmp, 0x0, ACVP_RSA_EXP_LEN_MAX);

                rv = acvp_bin_to_hexstr(stc.n, stc.n_len, tmp, ACVP_RSA_EXP_LEN_MAX);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("hex conversion failure (n)");
                    free(tmp);
                    goto end;
                }
                json_object_set_string(r_gobj, "n", (const char *)tmp);
                free(tmp);
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_rsa_sig_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                goto key_err;
            }

            /*
             * Release all the memory associated with the test case
             */
key_err:
            acvp_rsa_siggen_release_tc(&stc);


            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
            if (rv != ACVP_SUCCESS) {
                goto end;
            }
        }
        json_array_append_value(r_garr, r_gval);
    }

end:
    json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp);
    if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
        printf("\n\n%s\n\n", json_result);
    } else {
        ACVP_LOG_INFO("\n\n%s\n\n", json_result);
    }
    json_free_serialized_string(json_result);
    return rv;
}
