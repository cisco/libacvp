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

/*
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_aes_output_tc (ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, JSON_Object *tc_rsp,
                                       ACVP_RESULT opt_rv);

static ACVP_RESULT acvp_aes_init_tc (ACVP_CTX *ctx,
                                     ACVP_SYM_CIPHER_TC *stc,
                                     unsigned int tc_id,
                                     ACVP_SYM_CIPH_TESTTYPE test_type,
                                     const char *j_key,
                                     const char *j_pt,
                                     const char *j_ct,
                                     const char *j_iv,
                                     const char *j_tag,
                                     const char *j_aad,
                                     ACVP_SYM_KW_MODE kwcipher,
                                     unsigned int key_len,
                                     unsigned int iv_len,
                                     unsigned int pt_len,
                                     unsigned int aad_len,
                                     unsigned int tag_len,
                                     ACVP_CIPHER alg_id,
                                     ACVP_SYM_CIPH_DIR dir);

static ACVP_RESULT acvp_aes_release_tc (ACVP_SYM_CIPHER_TC *stc);


static unsigned char key[101][32];
static unsigned char iv[101][16];
static unsigned char ptext[1001][32];
static unsigned char ctext[1001][32];

#define gb(a, b) (((a)[(b)/8] >> (7-(b)%8))&1)
#define sb(a, b, v) ((a)[(b)/8]=((a)[(b)/8]&~(1 << (7-(b)%8)))|(!!(v) << (7-(b)%8)))

/*
 * After each encrypt/decrypt for a Monte Carlo test the iv
 * and/or pt/ct information may need to be modified.  This function
 * performs the iteration depdedent upon the cipher type and direction.
 */
static ACVP_RESULT acvp_aes_mct_iterate_tc (ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, int i) {
    int j = stc->mct_index;


    if (stc->cipher != ACVP_AES_CFB1) {
        memcpy(ctext[j], stc->ct, stc->ct_len);
        memcpy(ptext[j], stc->pt, stc->pt_len);
    } else {
        ctext[j][0] = stc->ct[0];
        ptext[j][0] = stc->pt[0];
    }
    if (j == 0) {
        memcpy(key[j], stc->key, stc->key_len / 8);
    }

    switch (stc->cipher) {
    case ACVP_AES_ECB:

        if (stc->direction == ACVP_DIR_ENCRYPT) {
            memcpy(stc->pt, ctext[j], stc->ct_len);
        } else {
            memcpy(stc->ct, ptext[j], stc->ct_len);
        }
        break;

    case ACVP_AES_CBC:
    case ACVP_AES_OFB:
    case ACVP_AES_CFB128:
        if (j == 0) {
            if (stc->direction == ACVP_DIR_ENCRYPT) {
                memcpy(stc->pt, stc->iv, stc->ct_len);
            } else {
                memcpy(stc->ct, stc->iv, stc->ct_len);
            }
        } else {

            if (stc->direction == ACVP_DIR_ENCRYPT) {
                memcpy(stc->pt, ctext[j - 1], stc->ct_len);
                memcpy(stc->iv, ctext[j], stc->ct_len);
            } else {
                memcpy(stc->ct, ptext[j - 1], stc->ct_len);
                memcpy(stc->iv, ptext[j], stc->ct_len);
            }
        }
        break;

    case ACVP_AES_CFB8:
        if (stc->direction == ACVP_DIR_ENCRYPT) {
            if (j < 16) {
                memcpy(stc->pt, &stc->iv[j], stc->pt_len);
            } else {
                memcpy(stc->pt, ctext[j - 16], stc->pt_len);
            }
        } else {
            if (j < 16) {
                memcpy(stc->ct, &stc->iv[j], stc->ct_len);
            } else {
                memcpy(stc->ct, ptext[j - 16], stc->ct_len);
            }
        }
        break;

    case ACVP_AES_CFB1:
        if (stc->direction == ACVP_DIR_ENCRYPT) {
            if (j < 128) {
                sb(ptext[j + 1], 0, gb(iv[i], j));
            } else {
                sb(ptext[j + 1], 0, gb(ctext[j - 128], 0));
            }
            stc->pt[0] = ptext[j + 1][0];
        } else {

            if (j < 128) {
                sb(ctext[j + 1], 0, gb(iv[i], j));
            } else {
                sb(ctext[j + 1], 0, gb(ptext[j - 128], 0));
            }
            stc->ct[0] = ctext[j + 1][0];
        }
        break;
    default:
        break;
    }

    return ACVP_SUCCESS;
}


/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case for MCT.
 */
static ACVP_RESULT acvp_aes_output_mct_tc (ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, JSON_Object *r_tobj) {
    ACVP_RESULT rv;
    char *tmp = NULL;

    tmp = calloc(1, ACVP_SYM_CT_MAX+1);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_output_mct_tc");
        return ACVP_MALLOC_FAIL;
    }

    memset(tmp, 0x0, ACVP_SYM_CT_MAX);
    rv = acvp_bin_to_hexstr(stc->key, stc->key_len / 8, tmp, ACVP_SYM_CT_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (key)");
        return rv;
    }
    json_object_set_string(r_tobj, "key", tmp);

    if (stc->cipher != ACVP_AES_ECB) {
        memset(tmp, 0x0, ACVP_SYM_CT_MAX);
        rv = acvp_bin_to_hexstr(stc->iv, stc->iv_len, tmp, ACVP_SYM_CT_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (iv)");
            free(tmp);
            return rv;
        }
        json_object_set_string(r_tobj, "iv", tmp);
    }

    if (stc->direction == ACVP_DIR_ENCRYPT) {
        memset(tmp, 0x0, ACVP_SYM_CT_MAX);

        if (stc->cipher == ACVP_AES_CFB1) {
            rv = acvp_bin_to_bit(stc->pt, 1, (unsigned char *) tmp);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (pt)");
                free(tmp);
                return rv;
            }
        } else {
            rv = acvp_bin_to_hexstr(stc->pt, stc->pt_len, tmp, ACVP_SYM_CT_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (pt)");
                free(tmp);
                return rv;
            }
        }
        json_object_set_string(r_tobj, "pt", tmp);

    } else {
        memset(tmp, 0x0, ACVP_SYM_CT_MAX);

        if (stc->cipher == ACVP_AES_CFB1) {
            rv = acvp_bin_to_bit(stc->ct, 1, (unsigned char *) tmp);

            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (ct)");
                free(tmp);
                return rv;
            }
        } else {
            rv = acvp_bin_to_hexstr(stc->ct, stc->ct_len, tmp, ACVP_SYM_CT_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (ct)");
                free(tmp);
                return rv;
            }
        }
       json_object_set_string(r_tobj, "ct", tmp);
    }

    free(tmp);

    return ACVP_SUCCESS;
}


/*
 * This is the handler for AES MCT values.  This will parse
 * a JSON encoded vector set for AES.  Each test case is
 * parsed, processed, and a response is generated to be sent
 * back to the ACV server by the transport layer.
 */
static ACVP_RESULT acvp_aes_mct_tc (ACVP_CTX *ctx, ACVP_CAPS_LIST *cap,
                                    ACVP_TEST_CASE *tc, ACVP_SYM_CIPHER_TC *stc,
                                    JSON_Array *res_array) {
    int i, j, n, n1, n2;
    ACVP_RESULT rv;
    JSON_Value *r_tval = NULL; /* Response testval */
    JSON_Object *r_tobj = NULL; /* Response testobj */
    char *tmp = NULL;
    unsigned char ciphertext[64 + 4];

    tmp = calloc(1, ACVP_SYM_CT_MAX+1);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_mct_tc");
        return ACVP_MALLOC_FAIL;
    }

    memcpy(iv[0], stc->iv, stc->iv_len);
    for (i = 0; i < ACVP_AES_MCT_OUTER; ++i) {

        /*
         * Create a new test case in the response
         */
        r_tval = json_value_init_object();
        r_tobj = json_value_get_object(r_tval);

        /*
         * Output the test case request values using JSON
         */
        rv = acvp_aes_output_mct_tc(ctx, stc, r_tobj);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("JSON output failure in AES module");
            free(tmp);
            return rv;
        }

        for (j = 0; j < ACVP_AES_MCT_INNER; ++j) {

            stc->mct_index = j;    /* indicates init vs. update */
            /* Process the current AES encrypt test vector... */
            rv = (cap->crypto_handler)(tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("crypto module failed the operation");
                free(tmp);
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Adjust the parameters for next iteration if needed.
             */
            rv = acvp_aes_mct_iterate_tc(ctx, stc, i);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Failed the MCT iteration changes");
                free(tmp);
                return rv;
            }
        }

        j = 999;
        if (stc->direction == ACVP_DIR_ENCRYPT) {

            memset(tmp, 0x0, ACVP_SYM_CT_MAX);
            if (stc->cipher == ACVP_AES_CFB1) {
                rv = acvp_bin_to_bit(stc->ct, 1, (unsigned char *) tmp);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("hex conversion failure (ct)");
                    free(tmp);
                    return rv;
                }
            } else {
                rv = acvp_bin_to_hexstr(stc->ct, stc->ct_len, tmp, ACVP_SYM_CT_MAX);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("hex conversion failure (ct)");
                    free(tmp);
                    return rv;
                }
            }
            json_object_set_string(r_tobj, "ct", tmp);

            if (stc->cipher == ACVP_AES_CFB8) {
                /* ct = CT[j-15] || CT[j-14] || ... || CT[j] */
                for (n1 = 0, n2 = stc->key_len / 8 - 1; n1 < stc->key_len / 8; ++n1, --n2) {
                    ciphertext[n1] = ctext[j - n2][0];
                }

                /* IV[i+1] = ct */
                for (n1 = 0, n2 = 15; n1 < 16; ++n1, --n2) {
                    stc->iv[n1] = ctext[j - n2][0];
                }
                ptext[0][0] = ctext[j - 16][0];

            } else if (stc->cipher == ACVP_AES_CFB1) {
                for (n1 = 0, n2 = stc->key_len - 1; n1 < stc->key_len; ++n1, --n2)
                    sb(ciphertext, n1, gb(ctext[j - n2], 0));

                for (n1 = 0, n2 = 127; n1 < 128; ++n1, --n2)
                    sb(iv[i + 1], n1, gb(ctext[j - n2], 0));
                ptext[0][0] = ctext[j - 128][0] & 0x80;
                stc->pt[0] = ptext[0][0];
                memcpy(stc->iv, iv[i + 1], stc->iv_len);
            } else {

                switch (stc->key_len) {
                case 128:
                    memcpy(ciphertext, ctext[j], 16);
                    break;
                case 192:
                    memcpy(ciphertext, ctext[j - 1] + 8, 8);
                    memcpy(ciphertext + 8, ctext[j], 16);
                    break;
                case 256:
                    memcpy(ciphertext, ctext[j - 1], 16);
                    memcpy(ciphertext + 16, ctext[j], 16);
                    break;
                }
            }

        } else {

            memset(tmp, 0x0, ACVP_SYM_CT_MAX);

            if (stc->cipher == ACVP_AES_CFB1) {
                rv = acvp_bin_to_bit(stc->pt, 1, (unsigned char *) tmp);

                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("hex conversion failure (pt)");
                    free(tmp);
                    return rv;
                }
            } else {
                rv = acvp_bin_to_hexstr(stc->pt, stc->pt_len, tmp, ACVP_SYM_CT_MAX);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("hex conversion failure (pt)");
                    free(tmp);
                    return rv;
                }
            }
            json_object_set_string(r_tobj, "pt", tmp);

            if (stc->cipher == ACVP_AES_CFB8) {
                /* ct = CT[j-15] || CT[j-14] || ... || CT[j] */
                for (n1 = 0, n2 = stc->key_len / 8 - 1; n1 < stc->key_len / 8; ++n1, --n2) {
                    ciphertext[n1] = ptext[j - n2][0];
                }

                for (n1 = 0, n2 = 15; n1 < 16; ++n1, --n2) {
                    stc->iv[n1] = ptext[j - n2][0];
                }
                ctext[0][0] = ptext[j - 16][0];

            } else if (stc->cipher == ACVP_AES_CFB1) {
                for (n1 = 0, n2 = stc->key_len - 1; n1 < stc->key_len; ++n1, --n2)
                    sb(ciphertext, n1, gb(ptext[j - n2], 0));

                for (n1 = 0, n2 = 127; n1 < 128; ++n1, --n2)
                    sb(iv[i + 1], n1, gb(ptext[j - n2], 0));
                ctext[0][0] = ptext[j - 128][0] & 0x80;
                stc->ct[0] = ctext[0][0];
                memcpy(stc->iv, iv[i + 1], stc->iv_len);

            } else {

                switch (stc->key_len) {
                case 128:
                    memcpy(ciphertext, ptext[j], 16);
                    break;
                case 192:
                    memcpy(ciphertext, ptext[j - 1] + 8, 8);
                    memcpy(ciphertext + 8, ptext[j], 16);
                    break;
                case 256:
                    memcpy(ciphertext, ptext[j - 1], 16);
                    memcpy(ciphertext + 16, ptext[j], 16);
                    break;
                }
            }
        }

        /* create the key for the next loop */
        for (n = 0; n < stc->key_len / 8; ++n) {
            stc->key[n] = key[0][n] ^ ciphertext[n];
        }

        /* Append the test response value to array */
        json_array_append_value(res_array, r_tval);
    }

    free(tmp);
    return ACVP_SUCCESS;
}


/*
 * This is the handler for AES KAT values.  This will parse
 * a JSON encoded vector set for AES.  Each test case is
 * parsed, processed, and a response is generated to be sent
 * back to the ACV server by the transport layer.
 */
ACVP_RESULT acvp_aes_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
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
    JSON_Array *r_tarr = NULL; /* Response testarray */
    JSON_Array *res_tarr = NULL; /* Response resultsArray */
    JSON_Value *r_tval = NULL; /* Response testval */
    JSON_Object *r_tobj = NULL; /* Response testobj */
    ACVP_CAPS_LIST *cap;
    ACVP_SYM_CIPHER_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;

    char *json_result = NULL;
    const char *alg_str = NULL;
    ACVP_CIPHER alg_id = 0;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }

    tc.tc.symmetric = &stc;

    /*
     * Get the crypto module handler for AES mode
     */
    alg_id = acvp_lookup_cipher_index(alg_str);
    if (alg_id < ACVP_CIPHER_START) {
        ACVP_LOG_ERR("unsupported algorithm (%s)", alg_str);
        return (ACVP_UNSUPPORTED_OP);
    }
    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        return (ACVP_UNSUPPORTED_OP);
    }

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct. ");
        return (rv);
    }

    /*
     * Start to build the JSON response
     * TODO: This code will likely be common to all the algorithms, need to move this
     */
    if (ctx->kat_resp) {
        json_value_free(ctx->kat_resp);
    }
    ctx->kat_resp = reg_arry_val;
    r_vs_val = json_value_init_object();
    r_vs = json_value_get_object(r_vs_val);
    json_object_set_number(r_vs, "vsId", ctx->vs_id);
    json_object_set_string(r_vs, "algorithm", alg_str);
    json_object_set_value(r_vs, "testResults", json_value_init_array());
    r_tarr = json_object_get_array(r_vs, "testResults");

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        const char *test_type_str = NULL, *dir_str = NULL, *kwcipher_str = NULL;
        unsigned int keylen = 0, ivlen = 0, ptlen = 0, aadlen = 0, taglen = 0;
        ACVP_SYM_CIPH_DIR dir = 0;
        ACVP_SYM_CIPH_TESTTYPE test_type = 0;
        ACVP_SYM_KW_MODE kwcipher = 0;

        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        dir_str = json_object_get_string(groupobj, "direction");
        if (!dir_str) {
            ACVP_LOG_ERR("Server JSON missing 'direction'");
            return ACVP_MISSING_ARG;
        }
        if (!strncmp(dir_str, "encrypt", strlen("encrypt"))) {
            dir = ACVP_DIR_ENCRYPT;
        } else if (!strncmp(dir_str, "decrypt", strlen("decrypt"))) {
            dir = ACVP_DIR_DECRYPT;
        } else {
            ACVP_LOG_ERR("Server JSON invalid 'direction'");
            return ACVP_INVALID_ARG;
        }

        test_type_str = json_object_get_string(groupobj, "testType");
        if (!test_type_str) {
            ACVP_LOG_ERR("Server JSON missing 'testType'");
            return ACVP_MISSING_ARG;
        }
        if (!strcmp(test_type_str, "MCT")) {
            test_type = ACVP_SYM_TEST_TYPE_MCT;
        } else if (!strcmp(test_type_str, "AFT")) {
            test_type = ACVP_SYM_TEST_TYPE_AFT;
        } else if (!strcmp(test_type_str, "aft")) {
            // FIXME this is only temporary fix for XTS
            test_type = ACVP_SYM_TEST_TYPE_AFT;
        } else if (!strcmp(test_type_str, "counter")) {
            test_type = ACVP_SYM_TEST_TYPE_CTR;
        } else {
            ACVP_LOG_ERR("Server JSON invalid 'testType'");
            return ACVP_INVALID_ARG;
        }

        if ((alg_id == ACVP_AES_KW) || (alg_id == ACVP_TDES_KW) ||
            (alg_id == ACVP_AES_KWP)) {

            kwcipher_str = json_object_get_string(groupobj, "kwCipher");
            if (!kwcipher_str) {
                ACVP_LOG_ERR("Server JSON missing 'kwCipher'");
                return ACVP_MISSING_ARG;
            }

            if (!strncmp(kwcipher_str, "cipher", strlen("cipher"))) {
                kwcipher = ACVP_SYM_KW_CIPHER;
            } else if (!strncmp(kwcipher_str, "inverse", strlen("inverse"))) {
                kwcipher = ACVP_SYM_KW_INVERSE;
            } else {
                ACVP_LOG_ERR("Server JSON invalid 'kwCipher'");
                return ACVP_INVALID_ARG;
            }
        }

        keylen = (unsigned int) json_object_get_number(groupobj, "keyLen");
        if (keylen != 128 && keylen != 192 && keylen != 256) {
            ACVP_LOG_ERR("Server JSON invalid 'keyLen', (%u)", keylen);
            return ACVP_INVALID_ARG;
        }

        if ((alg_id != ACVP_AES_ECB) && (alg_id != ACVP_AES_KW) && 
            (alg_id != ACVP_AES_KWP)) {
            ivlen = 128;
        }
        if (alg_id == ACVP_AES_GCM || alg_id == ACVP_AES_CCM) {
            ivlen = (unsigned int) json_object_get_number(groupobj, "ivLen");
            if (!ivlen) {
                ACVP_LOG_ERR("Server JSON missing 'ivlen'");
                return ACVP_MISSING_ARG;
            }

            if (alg_id == ACVP_AES_GCM) {
                if (!(ivlen >= ACVP_AES_GCM_IV_BIT_MIN &&
                      ivlen <= ACVP_AES_GCM_IV_BIT_MAX)) {
                    ACVP_LOG_ERR("Server JSON invalid 'ivlen', (%u)", ivlen);
                    return ACVP_INVALID_ARG;
                }
            } else {
                if (ivlen >= ACVP_AES_CCM_IV_BIT_MIN &&
                    ivlen <= ACVP_AES_CCM_IV_BIT_MAX) {
                    if (ivlen % 8 != 0) {
                        // Only increments of 8 allowed
                        ACVP_LOG_ERR("Server JSON 'ivlen' (%u) mod 8 != 0", ivlen);
                        return ACVP_INVALID_ARG;
                    }
                } else {
                    ACVP_LOG_ERR("Server JSON invalid 'ivlen', (%u)", ivlen);
                    return ACVP_INVALID_ARG;
                }
            }

            aadlen = (unsigned int) json_object_get_number(groupobj, "aadLen");
            if (aadlen > ACVP_SYM_AAD_BIT_MAX) {
                ACVP_LOG_ERR("'aadLen' too large (%u), max allowed=(%d)",
                             aadlen, ACVP_SYM_AAD_BIT_MAX);
                return ACVP_INVALID_ARG;
            }

            taglen = (unsigned int) json_object_get_number(groupobj, "tagLen");
            if (!(taglen >= ACVP_SYM_TAG_BIT_MIN &&
                  taglen <= ACVP_SYM_TAG_BIT_MAX)) {
                ACVP_LOG_ERR("Server JSON invalid 'taglen', (%u)", taglen);
                return ACVP_INVALID_ARG;
            }
        }

        ptlen = (unsigned int) json_object_get_number(groupobj, "ptLen");
        if (ptlen > ACVP_SYM_PT_BIT_MAX) {
            ACVP_LOG_ERR("'ptLen' too large (%u), max allowed=(%d)",
                         ptlen, ACVP_SYM_PT_BIT_MAX);
            return ACVP_INVALID_ARG;
        }

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("           dir: %d", dir_str);
        ACVP_LOG_INFO("            kw: %s", kwcipher_str);
        ACVP_LOG_INFO("        keylen: %d", keylen);
        ACVP_LOG_INFO("         ivlen: %d", ivlen);
        ACVP_LOG_INFO("         ptlen: %d", ptlen);
        ACVP_LOG_INFO("        aadlen: %d", aadlen);
        ACVP_LOG_INFO("        taglen: %d", taglen);
        ACVP_LOG_INFO("      testtype: %s", test_type_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            const char *pt = NULL, *ct = NULL, *iv = NULL,
                       *key = NULL, *tag = NULL, *aad = NULL;
            unsigned int tc_id = 0;

            ACVP_LOG_INFO("Found new AES test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int) json_object_get_number(testobj, "tcId");

            key = json_object_get_string(testobj, "key");

            if (dir == ACVP_DIR_ENCRYPT) {
                unsigned int tmp_pt_len = 0;

                pt = json_object_get_string(testobj, "pt");
                if (!pt) {
                    ACVP_LOG_ERR("Server JSON missing 'pt'");
                    return ACVP_MISSING_ARG;
                }
                tmp_pt_len = strnlen(pt, ACVP_SYM_PT_MAX + 1);
                if (tmp_pt_len > ACVP_SYM_PT_MAX) {
                    ACVP_LOG_ERR("'pt' too long, max allowed=(%d)",
                                 ACVP_SYM_PT_MAX);
                    return ACVP_INVALID_ARG;
                }

                if (alg_id != ACVP_AES_GCM && alg_id != ACVP_AES_CCM
                    && alg_id != ACVP_AES_CFB1) {

                    if (alg_id == ACVP_AES_CFB1) {
                        ptlen = tmp_pt_len * 8;
                    } else {
                        ptlen = tmp_pt_len * (8 / 2);
                    }
                }
            } else {
                unsigned int tmp_ct_len = 0;

                ct = json_object_get_string(testobj, "ct");
                if (!ct) {
                    ACVP_LOG_ERR("Server JSON missing 'ct'");
                    return ACVP_MISSING_ARG;
                }
                tmp_ct_len = strnlen(ct, ACVP_SYM_CT_MAX + 1);
                if (tmp_ct_len > ACVP_SYM_CT_MAX) {
                    ACVP_LOG_ERR("'ct' too long, max allowed=(%d)",
                                 ACVP_SYM_CT_MAX);
                    return ACVP_INVALID_ARG;
                }

                if (alg_id == ACVP_AES_GCM || alg_id == ACVP_AES_CCM) {
                    tag = json_object_get_string(testobj, "tag");
                    if (!tag) {
                        ACVP_LOG_ERR("Server JSON missing 'tag'");
                        return ACVP_MISSING_ARG;
                    }
                    if (strnlen(tag, ACVP_SYM_TAG_MAX + 1) > ACVP_SYM_TAG_MAX) {
                        ACVP_LOG_ERR("'tag' too long, max allowed=(%d)",
                                     ACVP_SYM_TAG_MAX);
                        return ACVP_INVALID_ARG;
                    }
                }

                if (alg_id != ACVP_AES_GCM && alg_id != ACVP_AES_CCM
                    && alg_id != ACVP_AES_CFB1) {

                    if (alg_id == ACVP_AES_CFB1) {
                        ptlen = tmp_ct_len * 8;
                    } else {
                        ptlen = tmp_ct_len * (8 / 2);
                    }
                }
            }

            if (ivlen) {
                if (alg_id == ACVP_AES_XTS) {
                    /* XTS may call it tweak value "i", but we treat it as an IV */
                    iv = json_object_get_string(testobj, "i");
                    if (!iv) {
                        ACVP_LOG_ERR("Server JSON missing 'i'");
                        return ACVP_MISSING_ARG;
                    }
                    if (strnlen(iv, ACVP_SYM_IV_MAX + 1) > ACVP_SYM_IV_MAX) {
                        ACVP_LOG_ERR("'i' too long, max allowed=(%d)",
                                     ACVP_SYM_IV_MAX);
                        return ACVP_INVALID_ARG;
                    }
                } else {
                    iv = json_object_get_string(testobj, "iv");
                    if (!iv) {
                        ACVP_LOG_ERR("Server JSON missing 'iv'");
                        return ACVP_MISSING_ARG;
                    }
                    if (strnlen(iv, ACVP_SYM_IV_MAX + 1) > ACVP_SYM_IV_MAX) {
                        ACVP_LOG_ERR("'iv' too long, max allowed=(%d)",
                                     ACVP_SYM_IV_MAX);
                        return ACVP_INVALID_ARG;
                    }
                }
            }

            if (alg_id == ACVP_AES_GCM || alg_id == ACVP_AES_CCM) {
                aad = json_object_get_string(testobj, "aad");
                if (!aad) {
                    ACVP_LOG_ERR("Server JSON missing 'aad'");
                    return ACVP_MISSING_ARG;
                }
                if (strnlen(aad, ACVP_SYM_AAD_MAX + 1) > ACVP_SYM_AAD_MAX) {
                    ACVP_LOG_ERR("'aad' too long, max allowed=(%d)",
                                 ACVP_SYM_AAD_MAX);
                    return ACVP_INVALID_ARG;
                }
            }

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("            tcId: %d", tc_id);
            ACVP_LOG_INFO("              key: %s", key);
            ACVP_LOG_INFO("               pt: %s", pt);
            ACVP_LOG_INFO("               ct: %s", ct);
            ACVP_LOG_INFO("               iv: %s", iv);
            ACVP_LOG_INFO("              tag: %s", tag);
            ACVP_LOG_INFO("              aad: %s", aad);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             * TODO: this does mallocs, we can probably do the mallocs once for
             *       the entire vector set to be more efficient
             */
            acvp_aes_init_tc(ctx, &stc, tc_id, test_type, key, pt, ct, iv, tag, aad,
                             kwcipher, keylen, ivlen, ptlen, aadlen, taglen, alg_id, dir);

            /* If Monte Carlo start that here */
            if (stc.test_type == ACVP_SYM_TEST_TYPE_MCT) {
                json_object_set_value(r_tobj, "resultsArray", json_value_init_array());
                res_tarr = json_object_get_array(r_tobj, "resultsArray");
                rv = acvp_aes_mct_tc(ctx, cap, &tc, &stc, res_tarr);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("crypto module failed the MCT operation");
                    acvp_aes_release_tc(&stc);
                    return ACVP_CRYPTO_MODULE_FAIL;
                }

            } else {

                /* Process the current AES KAT test vector... */
                rv = (cap->crypto_handler)(&tc);
                if (rv != ACVP_SUCCESS) {
                    if ((rv != ACVP_CRYPTO_TAG_FAIL) && (rv != ACVP_CRYPTO_WRAP_FAIL)) {
                        ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                        acvp_aes_release_tc(&stc);
                        return ACVP_CRYPTO_MODULE_FAIL;
                    }
                }

                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_aes_output_tc(ctx, &stc, r_tobj, rv);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("JSON output failure in AES module");
                    acvp_aes_release_tc(&stc);
                    return rv;
                }
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_aes_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
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

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_aes_output_tc (ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc,
                                       JSON_Object *tc_rsp, ACVP_RESULT opt_rv) {
    ACVP_RESULT rv;
    char *tmp = NULL;
    JSON_Array *ivs_array = NULL; /* IVs testarray */
    int i;

    tmp = calloc(ACVP_SYM_CT_MAX+1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->direction == ACVP_DIR_ENCRYPT) {
        /*
         * Only return IV on AES-GCM ciphers
         */
        if (stc->cipher == ACVP_AES_GCM) {
            rv = acvp_bin_to_hexstr(stc->iv, stc->iv_len, tmp, ACVP_SYM_CT_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (iv)");
                goto err;
            }
            json_object_set_string(tc_rsp, "iv", tmp);
        }

        memset(tmp, 0x0, ACVP_SYM_CT_MAX);
        if (stc->cipher == ACVP_AES_CFB1) {
            rv = acvp_bin_to_bit(stc->ct, stc->ct_len, (unsigned char *) tmp);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (ct)");
                goto err;
            }

        } else {
            rv = acvp_bin_to_hexstr(stc->ct, stc->ct_len, tmp, ACVP_SYM_CT_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (ct)");
                goto err;
            }
        }
        if (stc->cipher == ACVP_AES_CTR) {
            json_object_set_string(tc_rsp, "cipherText", tmp);
            if (stc->test_type == ACVP_SYM_TEST_TYPE_CTR) {
                json_object_set_value(tc_rsp, "ivs", json_value_init_array());
                ivs_array = json_object_get_array(tc_rsp, "ivs");
                for (i=0; i<(stc->pt_len/16); i++) {
                    rv = acvp_bin_to_hexstr(stc->iv, stc->iv_len, tmp, ACVP_SYM_CT_MAX);
                    if (rv != ACVP_SUCCESS) {
                        ACVP_LOG_ERR("hex conversion failure (tag)");
                        goto err;
                    }
                    json_array_append_string(ivs_array, tmp);
                    ctr128_inc(stc->iv);
                }
            }
        } else {
            json_object_set_string(tc_rsp, "ct", tmp);
        }

        /*
         * AES-GCM ciphers need to include the tag
         */
        if (stc->cipher == ACVP_AES_GCM) {
            memset(tmp, 0x0, ACVP_SYM_CT_MAX);
            rv = acvp_bin_to_hexstr(stc->tag, stc->tag_len, tmp, ACVP_SYM_CT_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (tag)");
                goto err;
            }
            json_object_set_string(tc_rsp, "tag", tmp);
        }
    } else {
        if ((stc->cipher == ACVP_AES_GCM || stc->cipher == ACVP_AES_CCM) &&
            (opt_rv == ACVP_CRYPTO_TAG_FAIL)) {
            json_object_set_boolean(tc_rsp, "decryptFail", 1);
            free(tmp);
            return ACVP_SUCCESS;
        }

        if ((stc->cipher == ACVP_AES_KW || stc->cipher == ACVP_AES_KWP) &&
            (opt_rv == ACVP_CRYPTO_WRAP_FAIL)) {
            json_object_set_boolean(tc_rsp, "decryptFail", 1);
            free(tmp);
            return ACVP_SUCCESS;
        }

        if (stc->cipher == ACVP_AES_CFB1) {
            rv = acvp_bin_to_bit(stc->pt, stc->pt_len, (unsigned char *) tmp);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (pt)");
                goto err;
            }
        } else {
            rv = acvp_bin_to_hexstr(stc->pt, stc->pt_len, tmp, ACVP_SYM_CT_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (pt)");
                goto err;
            }
        }
        if (stc->cipher == ACVP_AES_CTR) {
            json_object_set_string(tc_rsp, "plainText", tmp);
            if (stc->test_type == ACVP_SYM_TEST_TYPE_CTR) {
                json_object_set_value(tc_rsp, "ivs", json_value_init_array());
                ivs_array = json_object_get_array(tc_rsp, "ivs");
                for (i=0; i<(stc->pt_len/16); i++) {
                    rv = acvp_bin_to_hexstr(stc->iv, stc->iv_len, tmp, ACVP_SYM_CT_MAX);
                    json_array_append_string(ivs_array, tmp);
                    ctr128_inc(stc->iv);
                }
            }
        } else {
            json_object_set_string(tc_rsp, "pt", tmp);
        }
    }
    free(tmp);

    return ACVP_SUCCESS;

err:
    free(tmp);
    return rv;
}


/*
 * This function is used to fill-in the data for an AES
 * test case.  The JSON parsing logic invokes this after the
 * plaintext, key, etc. have been parsed from the vector set.
 * The ACVP_SYM_CIPHER_TC struct will hold all the data for
 * a given test case, which is then passed to the crypto
 * module to perform the actual encryption/decryption for
 * the test case.
 */
static ACVP_RESULT acvp_aes_init_tc (ACVP_CTX *ctx,
                                     ACVP_SYM_CIPHER_TC *stc,
                                     unsigned int tc_id,
                                     ACVP_SYM_CIPH_TESTTYPE test_type,
                                     const char *j_key,
                                     const char *j_pt,
                                     const char *j_ct,
                                     const char *j_iv,
                                     const char *j_tag,
                                     const char *j_aad,
                                     ACVP_SYM_KW_MODE kwcipher,
                                     unsigned int key_len,
                                     unsigned int iv_len,
                                     unsigned int pt_len,
                                     unsigned int aad_len,
                                     unsigned int tag_len,
                                     ACVP_CIPHER alg_id,
                                     ACVP_SYM_CIPH_DIR dir) {
    ACVP_RESULT rv;

    //FIXME:  check lengths do not exceed MAX values below

    memset(stc, 0x0, sizeof(ACVP_SYM_CIPHER_TC));

    stc->key = calloc(1, ACVP_SYM_KEY_MAX);
    if (!stc->key) { return ACVP_MALLOC_FAIL; }
    stc->pt = calloc(1, ACVP_SYM_PT_BYTE_MAX);
    if (!stc->pt) { return ACVP_MALLOC_FAIL; }
    stc->ct = calloc(1, ACVP_SYM_CT_BYTE_MAX);
    if (!stc->ct) { return ACVP_MALLOC_FAIL; }
    stc->tag = calloc(1, ACVP_SYM_TAG_BYTE_MAX);
    if (!stc->tag) { return ACVP_MALLOC_FAIL; }
    stc->iv = calloc(1, ACVP_SYM_IV_BYTE_MAX);
    if (!stc->iv) { return ACVP_MALLOC_FAIL; }
    stc->aad = calloc(1, ACVP_SYM_AAD_BYTE_MAX);
    if (!stc->aad) { return ACVP_MALLOC_FAIL; }

    rv = acvp_hexstr_to_bin(j_key, stc->key, ACVP_SYM_KEY_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (key)");
        return rv;
    }

    if (j_pt) {
        if (alg_id == ACVP_AES_CFB1) {
            rv = acvp_bit_to_bin((const unsigned char *) j_pt, pt_len / 8, stc->pt);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (pt)");
                return rv;
            }
        } else {

            rv = acvp_hexstr_to_bin(j_pt, stc->pt, ACVP_SYM_PT_BYTE_MAX, NULL);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (pt)");
                return rv;
            }
        }
    }

    if (j_ct) {
        if (alg_id == ACVP_AES_CFB1) {
            rv = acvp_bit_to_bin((const unsigned char *) j_ct, pt_len / 8, stc->ct);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (ct)");
                return rv;
            }
        } else {
            rv = acvp_hexstr_to_bin(j_ct, stc->ct, ACVP_SYM_CT_BYTE_MAX, NULL);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (ct)");
                return rv;
            }
        }
    }
    if (j_iv) {
        rv = acvp_hexstr_to_bin(j_iv, stc->iv, ACVP_SYM_IV_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (iv)");
            return rv;
        }
    }

    if (j_tag) {
        rv = acvp_hexstr_to_bin(j_tag, stc->tag, ACVP_SYM_TAG_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (tag)");
            return rv;
        }
    }

    if (j_aad) {
        rv = acvp_hexstr_to_bin(j_aad, stc->aad, ACVP_SYM_AAD_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (aad)");
            return rv;
        }
    }

    /*
     * These lengths come in as bit lengths from the ACVP server.
     * We convert to bytes.
     * TODO: do we need to support bit lengths not a multiple of 8?
     */
    stc->tc_id = tc_id;
    stc->kwcipher = kwcipher;
    stc->test_type = test_type;
    stc->key_len = key_len;
    stc->iv_len = iv_len / 8;
    stc->pt_len = pt_len / 8;
    stc->ct_len = pt_len / 8;
    stc->tag_len = tag_len / 8;
    stc->aad_len = aad_len / 8;

    stc->cipher = alg_id;
    stc->direction = dir;

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_aes_release_tc (ACVP_SYM_CIPHER_TC *stc) {
    if (stc->key) free(stc->key);
    if (stc->pt) free(stc->pt);
    if (stc->ct) free(stc->ct);
    if (stc->tag) free(stc->tag);
    if (stc->iv) free(stc->iv);
    if (stc->aad) free(stc->aad);
    memset(stc, 0x0, sizeof(ACVP_SYM_CIPHER_TC));

    return ACVP_SUCCESS;
}
