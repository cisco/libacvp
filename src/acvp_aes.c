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
#include "safe_lib.h"

/*
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_aes_output_tc(ACVP_CTX *ctx,
                                      ACVP_SYM_CIPHER_TC *stc,
                                      JSON_Object *tc_rsp,
                                      int opt_rv);

static ACVP_RESULT acvp_aes_init_tc(ACVP_CTX *ctx,
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
                                    unsigned int data_len,
                                    int pt_len,
                                    unsigned int tag_len,
                                    ACVP_CIPHER alg_id,
                                    ACVP_SYM_CIPH_DIR dir,
                                    ACVP_SYM_CIPH_IVGEN_SRC iv_gen,
                                    ACVP_SYM_CIPH_IVGEN_MODE iv_gen_mode,
                                    unsigned int aad_len,
                                    unsigned int incr_ctr,
                                    unsigned int ovrflw_ctr);

static ACVP_RESULT acvp_aes_release_tc(ACVP_SYM_CIPHER_TC *stc);

#define KEY_COL_LEN 101
#define KEY_ROW_LEN 32
#define IV_COL_LEN 101
#define IV_ROW_LEN 16
#define TEXT_COL_LEN 1001
#define TEXT_ROW_LEN 32
static unsigned char key[KEY_COL_LEN][KEY_ROW_LEN];
static unsigned char iv[IV_COL_LEN][IV_ROW_LEN];
static unsigned char ptext[TEXT_COL_LEN][TEXT_ROW_LEN];
static unsigned char ctext[TEXT_COL_LEN][TEXT_ROW_LEN];

#define gb(a, b) (((a)[(b) / 8] >> (7 - (b) % 8)) & 1)
#define sb(a, b, v) ((a)[(b) / 8] = ((a)[(b) / 8] & ~(1 << (7 - (b) % 8))) | (!!(v) << (7 - (b) % 8)))

/*
 * After each encrypt/decrypt for a Monte Carlo test the iv
 * and/or pt/ct information may need to be modified.  This function
 * performs the iteration depdedent upon the cipher type and direction.
 */
static ACVP_RESULT acvp_aes_mct_iterate_tc(ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, int i) {
    int j = stc->mct_index;


    if (stc->cipher != ACVP_AES_CFB1) {
        memcpy_s(ctext[j], TEXT_ROW_LEN, stc->ct, stc->ct_len);
        memcpy_s(ptext[j], TEXT_ROW_LEN, stc->pt, stc->pt_len);
    } else {
        ctext[j][0] = stc->ct[0];
        ptext[j][0] = stc->pt[0];
    }
    if (j == 0) {
        memcpy_s(key[j], KEY_ROW_LEN, stc->key, stc->key_len / 8);
    }

    switch (stc->cipher) {
    case ACVP_AES_ECB:

        if (stc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
            memcpy_s(stc->pt, ACVP_SYM_PT_BYTE_MAX, ctext[j], stc->ct_len);
        } else {
            memcpy_s(stc->ct, ACVP_SYM_CT_BYTE_MAX, ptext[j], stc->ct_len);
        }
        break;

    case ACVP_AES_CBC:
    case ACVP_AES_OFB:
    case ACVP_AES_CFB128:
        if (j == 0) {
            if (stc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
                memcpy_s(stc->pt, ACVP_SYM_PT_BYTE_MAX, stc->iv, stc->ct_len);
            } else {
                memcpy_s(stc->ct, ACVP_SYM_CT_BYTE_MAX, stc->iv, stc->ct_len);
            }
        } else {
            if (stc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
                memcpy_s(stc->pt, ACVP_SYM_PT_BYTE_MAX, ctext[j - 1], stc->ct_len);
                memcpy_s(stc->iv, ACVP_SYM_IV_BYTE_MAX, ctext[j], stc->ct_len);
            } else {
                memcpy_s(stc->ct, ACVP_SYM_CT_BYTE_MAX, ptext[j - 1], stc->ct_len);
                memcpy_s(stc->iv, ACVP_SYM_IV_BYTE_MAX, ptext[j], stc->ct_len);
            }
        }
        break;

    case ACVP_AES_CFB8:
        if (stc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
            if (j < 16) {
                memcpy_s(stc->pt, ACVP_SYM_PT_BYTE_MAX, &stc->iv[j], stc->pt_len);
            } else {
                memcpy_s(stc->pt, ACVP_SYM_PT_BYTE_MAX, ctext[j - 16], stc->pt_len);
            }
        } else {
            if (j < 16) {
                memcpy_s(stc->ct, ACVP_SYM_CT_BYTE_MAX, &stc->iv[j], stc->ct_len);
            } else {
                memcpy_s(stc->ct, ACVP_SYM_CT_BYTE_MAX, ptext[j - 16], stc->ct_len);
            }
        }
        break;

    case ACVP_AES_CFB1:
        if (stc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
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
static ACVP_RESULT acvp_aes_output_mct_tc(ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, JSON_Object *r_tobj) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(1, ACVP_SYM_CT_MAX + 1);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_output_mct_tc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(stc->key, stc->key_len / 8, tmp, ACVP_SYM_CT_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (key)");
        goto end;
    }
    json_object_set_string(r_tobj, "key", tmp);

    if (stc->cipher != ACVP_AES_ECB) {
        memzero_s(tmp, ACVP_SYM_CT_MAX);
        rv = acvp_bin_to_hexstr(stc->iv, stc->iv_len, tmp, ACVP_SYM_CT_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (iv)");
            goto end;
        }
        json_object_set_string(r_tobj, "iv", tmp);
    }

    if (stc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
        memzero_s(tmp, ACVP_SYM_CT_MAX);

        if (stc->cipher == ACVP_AES_CFB1) {
            rv = acvp_bin_to_hexstr(stc->pt, 1, tmp, ACVP_SYM_PT_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (pt)");
                goto end;
            }
        } else {
            rv = acvp_bin_to_hexstr(stc->pt, stc->pt_len, tmp, ACVP_SYM_PT_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (pt)");
                goto end;
            }
        }
        json_object_set_string(r_tobj, "pt", tmp);
    } else {
        memzero_s(tmp, ACVP_SYM_CT_MAX);

        if (stc->cipher == ACVP_AES_CFB1) {
            rv = acvp_bin_to_hexstr(stc->ct, 1, tmp, ACVP_SYM_CT_MAX);

            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (ct)");
                goto end;
            }
        } else {
            rv = acvp_bin_to_hexstr(stc->ct, stc->ct_len, tmp, ACVP_SYM_CT_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (ct)");
                goto end;
            }
        }
        json_object_set_string(r_tobj, "ct", tmp);
    }

end:
    if (tmp) free(tmp);

    return rv;
}

/*
 * This is the handler for AES MCT values.  This will parse
 * a JSON encoded vector set for AES.  Each test case is
 * parsed, processed, and a response is generated to be sent
 * back to the ACV server by the transport layer.
 */
static ACVP_RESULT acvp_aes_mct_tc(ACVP_CTX *ctx,
                                   ACVP_CAPS_LIST *cap,
                                   ACVP_TEST_CASE *tc,
                                   ACVP_SYM_CIPHER_TC *stc,
                                   JSON_Array *res_array) {
    int i, j, n, n1, n2;
    ACVP_RESULT rv;
    JSON_Value *r_tval = NULL;  /* Response testval */
    JSON_Object *r_tobj = NULL; /* Response testobj */
    char *tmp = NULL;
#define MCT_CT_LEN 68 /* 64 + 4 */
    unsigned char ciphertext[MCT_CT_LEN] = { 0 };

    tmp = calloc(1, ACVP_SYM_CT_MAX + 1);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_mct_tc");
        return ACVP_MALLOC_FAIL;
    }

    memcpy_s(iv[0], IV_ROW_LEN, stc->iv, stc->iv_len);
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
            json_value_free(r_tval);
            free(tmp);
            return rv;
        }

        for (j = 0; j < ACVP_AES_MCT_INNER; ++j) {
            stc->mct_index = j;    /* indicates init vs. update */
            /* Process the current AES encrypt test vector... */
            if ((cap->crypto_handler)(tc)) {
                ACVP_LOG_ERR("crypto module failed the operation");
                free(tmp);
                json_value_free(r_tval);
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
        if (stc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
            memzero_s(tmp, ACVP_SYM_CT_MAX);
            if (stc->cipher == ACVP_AES_CFB1) {
                rv = acvp_bin_to_hexstr(stc->ct, 1, tmp, ACVP_SYM_CT_MAX);
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
                for (n1 = 0, n2 = stc->key_len - 1; n1 < stc->key_len; ++n1, --n2) {
                    sb(ciphertext, n1, gb(ctext[j - n2], 0));
                }

                for (n1 = 0, n2 = 127; n1 < 128; ++n1, --n2) {
                    sb(iv[i + 1], n1, gb(ctext[j - n2], 0));
                }
                ptext[0][0] = ctext[j - 128][0] & 0x80;
                stc->pt[0] = ptext[0][0];
                memcpy_s(stc->iv, ACVP_SYM_IV_BYTE_MAX, iv[i + 1], stc->iv_len);
            } else {
                switch (stc->key_len) {
                case 128:
                    memcpy_s(ciphertext, MCT_CT_LEN, ctext[j], 16);
                    break;
                case 192:
                    memcpy_s(ciphertext, MCT_CT_LEN, ctext[j - 1] + 8, 8);
                    memcpy_s(ciphertext + 8, (MCT_CT_LEN - 8), ctext[j], 16);
                    break;
                case 256:
                    memcpy_s(ciphertext, MCT_CT_LEN, ctext[j - 1], 16);
                    memcpy_s(ciphertext + 16, (MCT_CT_LEN - 16), ctext[j], 16);
                    break;
                }
            }
        } else {
            memzero_s(tmp, ACVP_SYM_CT_MAX);

            if (stc->cipher == ACVP_AES_CFB1) {
                rv = acvp_bin_to_hexstr(stc->pt, 1, tmp, ACVP_SYM_PT_MAX);

                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("hex conversion failure (pt)");
                    json_value_free(r_tval);
                    free(tmp);
                    return rv;
                }
            } else {
                rv = acvp_bin_to_hexstr(stc->pt, stc->pt_len, tmp, ACVP_SYM_CT_MAX);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("hex conversion failure (pt)");
                    free(tmp);
                    json_value_free(r_tval);
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
                for (n1 = 0, n2 = stc->key_len - 1; n1 < stc->key_len; ++n1, --n2) {
                    sb(ciphertext, n1, gb(ptext[j - n2], 0));
                }

                for (n1 = 0, n2 = 127; n1 < 128; ++n1, --n2) {
                    sb(iv[i + 1], n1, gb(ptext[j - n2], 0));
                }
                ctext[0][0] = ptext[j - 128][0] & 0x80;
                stc->ct[0] = ctext[0][0];
                memcpy_s(stc->iv, ACVP_SYM_IV_BYTE_MAX, iv[i + 1], stc->iv_len);
            } else {
                switch (stc->key_len) {
                case 128:
                    memcpy_s(ciphertext, MCT_CT_LEN, ptext[j], 16);
                    break;
                case 192:
                    memcpy_s(ciphertext, MCT_CT_LEN, ptext[j - 1] + 8, 8);
                    memcpy_s(ciphertext + 8, (MCT_CT_LEN - 8), ptext[j], 16);
                    break;
                case 256:
                    memcpy_s(ciphertext, MCT_CT_LEN, ptext[j - 1], 16);
                    memcpy_s(ciphertext + 16, (MCT_CT_LEN - 16), ptext[j], 16);
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

/**
 * @brief Read the \p str reprenting the ivgen mode and
 *        convert to enum.
 *
 * @param[in] str The char* string representing the ivgen mode.
 *
 * @return ACVP_SYM_CIPH_IVGEN_MODE
 * @return 0 for fail
 */
static ACVP_SYM_CIPH_IVGEN_MODE read_ivgen_mode(const char *str) {
    int diff = 0;

    strcmp_s("8.2.1", 5, str, &diff);
    if (!diff) {
        return ACVP_SYM_CIPH_IVGEN_MODE_821;
    }
    strcmp_s("8.2.2", 5, str, &diff);
    if (!diff) {
        return ACVP_SYM_CIPH_IVGEN_MODE_822;
    }

    return 0;
}

/**
 * @brief Read the \p str reprenting the ivgen source and
 *        convert to enum.
 *
 * @param[in] str The char* string representing the ivgen source.
 *
 * @return ACVP_SYM_CIPH_IVGEN_SRC
 * @return 0 for fail
 */
static ACVP_SYM_CIPH_IVGEN_SRC read_ivgen_source(const char *str) {
    int diff = 0;

    strcmp_s("internal", 8, str, &diff);
    if (!diff) {
        return ACVP_SYM_CIPH_IVGEN_SRC_INT;
    }
    strcmp_s("external", 8, str, &diff);
    if (!diff) {
        return ACVP_SYM_CIPH_IVGEN_SRC_EXT;
    }

    return 0;
}

/**
 * @brief Read the \p str reprenting the keywrap mode and
 *        convert to enum.
 *
 * @param[in] str The char* string representing the keywrap mode.
 *
 * @return ACVP_SYM_KW_MODE
 * @return 0 for fail
 */
static ACVP_SYM_KW_MODE read_kw_mode(const char *str) {
    int diff = 0;

    strcmp_s("cipher", 6, str, &diff);
    if (!diff) {
        return ACVP_SYM_KW_CIPHER;
    }
    strcmp_s("inverse", 7, str, &diff);
    if (!diff) {
        return ACVP_SYM_KW_INVERSE;
    }

    return 0;
}

/**
 * @brief Read the \p str reprenting the test type and
 *        convert to enum.
 *
 * @param[in] str The char* string representing the test type.
 *
 * @return ACVP_SYM_CIPH_TESTTYPE
 * @return 0 for fail
 */
static ACVP_SYM_CIPH_TESTTYPE read_test_type(const char *str) {
    int diff = 0;

    strcmp_s("MCT", 3, str, &diff);
    if (!diff) {
        return ACVP_SYM_TEST_TYPE_MCT;
    }
    strcmp_s("AFT", 3, str, &diff);
    if (!diff) {
        return ACVP_SYM_TEST_TYPE_AFT;
    }
    strcmp_s("CTR", 3, str, &diff);
    if (!diff) {
        return ACVP_SYM_TEST_TYPE_CTR;
    }

    return 0;
}

/**
 * @brief Read the \p str reprenting the direction and
 *        convert to enum.
 *
 * @param[in] str The char* string representing the direction.
 *
 * @return ACVP_SYM_CIPH_DIR
 * @return 0 for fail
 */
static ACVP_SYM_CIPH_DIR read_direction(const char *str) {
    int diff = 0;

    strcmp_s("encrypt", 7, str, &diff);
    if (!diff) {
        return ACVP_SYM_CIPH_DIR_ENCRYPT;
    }
    strcmp_s("decrypt", 7, str, &diff);
    if (!diff) {
        return ACVP_SYM_CIPH_DIR_DECRYPT;
    }

    return 0;
}

/*
 * This is the handler for AES KAT values.  This will parse
 * a JSON encoded vector set for AES.  Each test case is
 * parsed, processed, and a response is generated to be sent
 * back to the ACV server by the transport layer.
 */
ACVP_RESULT acvp_aes_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
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
    JSON_Array *res_tarr = NULL;                /* Response resultsArray */
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    ACVP_CAPS_LIST *cap;
    ACVP_SYM_CIPHER_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    unsigned int ovrflw_ctr = 0, incr_ctr = 0;  /* assume false */
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
        return ACVP_MALFORMED_JSON;
    }

    tc.tc.symmetric = &stc;

    /*
     * Get the crypto module handler for AES mode
     */
    alg_id = acvp_lookup_cipher_index(alg_str);
    if (alg_id < ACVP_CIPHER_START) {
        ACVP_LOG_ERR("unsupported algorithm (%s)", alg_str);
        return ACVP_UNSUPPORTED_OP;
    }
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
        return rv;
    }

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        const char *test_type_str = NULL, *dir_str = NULL, *kwcipher_str = NULL,
                   *iv_gen_str = NULL, *iv_gen_mode_str = NULL;
        unsigned int keylen = 0, ivlen = 0, ptlen = 0, datalen = 0, aadlen = 0, taglen = 0;
        int tgId = 0;
        ACVP_SYM_CIPH_DIR dir = 0;
        ACVP_SYM_CIPH_TESTTYPE test_type = 0;
        ACVP_SYM_KW_MODE kwcipher = 0;
        ACVP_SYM_CIPH_IVGEN_SRC iv_gen = ACVP_SYM_CIPH_IVGEN_SRC_NA;
        ACVP_SYM_CIPH_IVGEN_MODE iv_gen_mode = ACVP_SYM_CIPH_IVGEN_MODE_NA;

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

        dir_str = json_object_get_string(groupobj, "direction");
        if (!dir_str) {
            ACVP_LOG_ERR("Server JSON missing 'direction'");
            rv = ACVP_MISSING_ARG;
            goto err;
        }

        dir = read_direction(dir_str);
        if (!dir) {
            ACVP_LOG_ERR("Server JSON invalid 'direction'");
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
        if (test_type == ACVP_SYM_TEST_TYPE_CTR) {
            /* TODO: NIST needs to fix these keywords, ie add Counter at the end */
            incr_ctr = json_object_get_boolean(groupobj, "incremental");
            ovrflw_ctr = json_object_get_boolean(groupobj, "overflow");
            if (ovrflw_ctr != 0 && ovrflw_ctr != 1) {
                ACVP_LOG_ERR("Server JSON invalid 'overflowCounter'");
                rv = ACVP_MALFORMED_JSON;
                goto err;
            }
            if (incr_ctr != 0 && incr_ctr != 1) {
                ACVP_LOG_ERR("Server JSON invalid 'incrementalCounter'");
                rv = ACVP_MALFORMED_JSON;
                goto err;
            }
        }

        if ((alg_id == ACVP_AES_KW) || (alg_id == ACVP_TDES_KW) ||
            (alg_id == ACVP_AES_KWP)) {
            kwcipher_str = json_object_get_string(groupobj, "kwCipher");
            if (!kwcipher_str) {
                ACVP_LOG_ERR("Server JSON missing 'kwCipher'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            kwcipher = read_kw_mode(kwcipher_str);
            if (!kwcipher) {
                ACVP_LOG_ERR("Server JSON invalid 'kwCipher'");
                rv = ACVP_INVALID_ARG;
                goto err;
            }
        }

        keylen = (unsigned int)json_object_get_number(groupobj, "keyLen");
        if (keylen != 128 && keylen != 192 && keylen != 256) {
            ACVP_LOG_ERR("Server JSON invalid 'keyLen', (%u)", keylen);
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        if ((alg_id != ACVP_AES_ECB) && (alg_id != ACVP_AES_KW) &&
            (alg_id != ACVP_AES_KWP)) {
            ivlen = 128;
        }
        if (alg_id == ACVP_AES_GCM || alg_id == ACVP_AES_CCM) {
            ivlen = (unsigned int)json_object_get_number(groupobj, "ivLen");
            if (!ivlen) {
                ACVP_LOG_ERR("Server JSON missing 'ivlen'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }

            if (alg_id == ACVP_AES_GCM) {
                if (!(ivlen >= ACVP_AES_GCM_IV_BIT_MIN &&
                      ivlen <= ACVP_AES_GCM_IV_BIT_MAX)) {
                    ACVP_LOG_ERR("Server JSON invalid 'ivlen', (%u)", ivlen);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                iv_gen_str = json_object_get_string(groupobj, "ivGen");
                if (!iv_gen_str) {
                    ACVP_LOG_ERR("Server JSON missing 'ivGen'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                iv_gen = read_ivgen_source(iv_gen_str);
                if (!iv_gen) {
                    ACVP_LOG_ERR("Server JSON invalid 'ivGen'");
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                if (iv_gen == ACVP_SYM_CIPH_IVGEN_SRC_INT) {
                    iv_gen_mode_str = json_object_get_string(groupobj, "ivGenMode");
                    if (!iv_gen_mode_str) {
                        ACVP_LOG_ERR("Server JSON missing 'ivGenMode'");
                        rv = ACVP_MISSING_ARG;
                        goto err;
                    }
                    iv_gen_mode = read_ivgen_mode(iv_gen_mode_str);
                    if (!iv_gen_mode) {
                        ACVP_LOG_ERR("Server JSON invalid 'ivGenMode'");
                        rv = ACVP_INVALID_ARG;
                        goto err;
                    }
                }
            } else {
                if (ivlen >= ACVP_AES_CCM_IV_BIT_MIN &&
                    ivlen <= ACVP_AES_CCM_IV_BIT_MAX) {
                    if (ivlen % 8 != 0) {
                        // Only increments of 8 allowed
                        ACVP_LOG_ERR("Server JSON 'ivlen' (%u) mod 8 != 0", ivlen);
                        rv = ACVP_INVALID_ARG;
                        goto err;
                    }
                } else {
                    ACVP_LOG_ERR("Server JSON invalid 'ivlen', (%u)", ivlen);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            aadlen = (unsigned int)json_object_get_number(groupobj, "aadLen");
            if (aadlen > ACVP_SYM_AAD_BIT_MAX) {
                ACVP_LOG_ERR("'aadLen' too large (%u), max allowed=(%d)",
                             aadlen, ACVP_SYM_AAD_BIT_MAX);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            taglen = (unsigned int)json_object_get_number(groupobj, "tagLen");
            if (!(taglen >= ACVP_SYM_TAG_BIT_MIN &&
                  taglen <= ACVP_SYM_TAG_BIT_MAX)) {
                ACVP_LOG_ERR("Server JSON invalid 'taglen', (%u)", taglen);
                rv = ACVP_INVALID_ARG;
                goto err;
            }
        }

        ptlen = (unsigned int)json_object_get_number(groupobj, "payloadLen");
        if (ptlen > ACVP_SYM_PT_BIT_MAX) {
            ACVP_LOG_ERR("'ptLen' too large (%u), max allowed=(%d)",
                         ptlen, ACVP_SYM_PT_BIT_MAX);
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("           dir: %s", dir_str);
        ACVP_LOG_INFO("            kw: %s", kwcipher_str);
        ACVP_LOG_INFO("        keylen: %d", keylen);
        ACVP_LOG_INFO("         ivlen: %d", ivlen);
        ACVP_LOG_INFO("         ptlen: %d", ptlen);
        ACVP_LOG_INFO("        aadlen: %d", aadlen);
        ACVP_LOG_INFO("        taglen: %d", taglen);
        ACVP_LOG_INFO("      testtype: %s", test_type_str);
        ACVP_LOG_INFO("      incr_ctr: %d", incr_ctr);
        ACVP_LOG_INFO("    ovrflw_ctr: %d", ovrflw_ctr);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            const char *pt = NULL, *ct = NULL, *iv = NULL,
                       *key = NULL, *tag = NULL, *aad = NULL;
            unsigned int tc_id = 0;

            ACVP_LOG_INFO("Found new AES test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");

            key = json_object_get_string(testobj, "key");
            if (!key) {
                ACVP_LOG_ERR("Server JSON missing 'key'");
                rv = ACVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(key, ACVP_SYM_KEY_MAX_STR + 1) > ACVP_SYM_KEY_MAX_STR) {
                ACVP_LOG_ERR("'key' length exceeds max aes key string length (%d)", ACVP_SYM_KEY_MAX_STR);
                rv = ACVP_INVALID_ARG;
                goto err;
            }

            if (alg_id == ACVP_AES_CFB1) {
                datalen = (unsigned int)json_object_get_number(testobj, "payloadLen");
                if (datalen > ACVP_SYM_PT_BIT_MAX) {
                    ACVP_LOG_ERR("'dataLen' too large (%u), max allowed=(%d)",
                                 datalen, ACVP_SYM_PT_BIT_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            if (dir == ACVP_SYM_CIPH_DIR_ENCRYPT) {
                unsigned int tmp_pt_len = 0;
                pt = json_object_get_string(testobj, "pt");
                if (!pt) {
                    ACVP_LOG_ERR("Server JSON missing 'pt'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                tmp_pt_len = strnlen_s(pt, ACVP_SYM_PT_MAX + 1);
                if (tmp_pt_len > ACVP_SYM_PT_MAX) {
                    ACVP_LOG_ERR("'pt' too long, max allowed=(%d)",
                                 ACVP_SYM_PT_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            } else {
                unsigned int tmp_ct_len = 0;

                ct = json_object_get_string(testobj, "ct");
                if (!ct) {
                    ACVP_LOG_ERR("Server JSON missing 'ct'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                tmp_ct_len = strnlen_s(ct, ACVP_SYM_CT_MAX + 1);
                if (tmp_ct_len > ACVP_SYM_CT_MAX) {
                    ACVP_LOG_ERR("'ct' too long, max allowed=(%d)",
                                 ACVP_SYM_CT_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }

                if (alg_id == ACVP_AES_GCM) {
                    tag = json_object_get_string(testobj, "tag");
                    if (!tag) {
                        ACVP_LOG_ERR("Server JSON missing 'tag'");
                        rv = ACVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(tag, ACVP_SYM_TAG_MAX + 1) > ACVP_SYM_TAG_MAX) {
                        ACVP_LOG_ERR("'tag' too long, max allowed=(%d)",
                                     ACVP_SYM_TAG_MAX);
                        rv = ACVP_INVALID_ARG;
                        goto err;
                    }
                }
            }

            /*
             * If GCM, direction is encrypt, and the generation is internal
             * then iv is not provided.
             */
            if (ivlen && !(alg_id == ACVP_AES_GCM && dir == ACVP_SYM_CIPH_DIR_ENCRYPT &&
                           iv_gen == ACVP_SYM_CIPH_IVGEN_SRC_INT)) {
                if (alg_id == ACVP_AES_XTS) {
                    /* XTS may call it tweak value, but we treat it as an IV */
                    iv = json_object_get_string(testobj, "tweakValue");
                    if (!iv) {
                        ACVP_LOG_ERR("Server JSON missing 'tweakValue'");
                        rv = ACVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(iv, ACVP_SYM_IV_MAX + 1) > ACVP_SYM_IV_MAX) {
                        ACVP_LOG_ERR("'i' too long, max allowed=(%d)",
                                     ACVP_SYM_IV_MAX);
                        rv = ACVP_INVALID_ARG;
                        goto err;
                    }
                } else {
                    iv = json_object_get_string(testobj, "iv");
                    if (!iv) {
                        ACVP_LOG_ERR("Server JSON missing 'iv'");
                        rv = ACVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(iv, ACVP_SYM_IV_MAX + 1) > ACVP_SYM_IV_MAX) {
                        ACVP_LOG_ERR("'iv' too long, max allowed=(%d)",
                                     ACVP_SYM_IV_MAX);
                        rv = ACVP_INVALID_ARG;
                        goto err;
                    }
                }
            }

            if (alg_id == ACVP_AES_GCM || alg_id == ACVP_AES_CCM) {
                aad = json_object_get_string(testobj, "aad");
                if (!aad) {
                    ACVP_LOG_ERR("Server JSON missing 'aad'");
                    rv = ACVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(aad, ACVP_SYM_AAD_MAX + 1) > ACVP_SYM_AAD_MAX) {
                    ACVP_LOG_ERR("'aad' too long, max allowed=(%d)",
                                 ACVP_SYM_AAD_MAX);
                    rv = ACVP_INVALID_ARG;
                    goto err;
                }
            }

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("            tcId: %d", tc_id);
            ACVP_LOG_INFO("              key: %s", key);
            ACVP_LOG_INFO("               pt: %s", pt);
            ACVP_LOG_INFO("          dataLen: %d", datalen);
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
             */
            rv = acvp_aes_init_tc(ctx, &stc, tc_id, test_type, key, pt, ct, iv, tag, 
                                  aad, kwcipher, keylen, ivlen, datalen, ptlen,
                                  taglen, alg_id, dir, iv_gen, iv_gen_mode, aadlen,
                                  incr_ctr, ovrflw_ctr);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Init for stc (test case) failed");
                acvp_aes_release_tc(&stc);
                goto err;
            }

            /* If Monte Carlo start that here */
            if (stc.test_type == ACVP_SYM_TEST_TYPE_MCT) {
                json_object_set_value(r_tobj, "resultsArray", json_value_init_array());
                res_tarr = json_object_get_array(r_tobj, "resultsArray");
                rv = acvp_aes_mct_tc(ctx, cap, &tc, &stc, res_tarr);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("crypto module failed the MCT operation");
                    json_value_free(r_tval);
                    acvp_aes_release_tc(&stc);
                    goto err;
                }
            } else {
                /* Process the current AES KAT test vector... */
                int t_rv = (cap->crypto_handler)(&tc);
                if (t_rv) {
                    if (alg_id != ACVP_AES_KW && alg_id != ACVP_AES_GCM &&
                        alg_id != ACVP_AES_CCM && alg_id != ACVP_AES_KWP) {
                        ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                        acvp_aes_release_tc(&stc);
                        json_value_free(r_tval);
                        rv = ACVP_CRYPTO_MODULE_FAIL;
                        goto err;
                    }
                }

                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_aes_output_tc(ctx, &stc, r_tobj, t_rv);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("JSON output failure in AES module");
                    json_value_free(r_tval);
                    acvp_aes_release_tc(&stc);
                    goto err;
                }
            }

            /*
             * Release all the memory associated with the test case
             */
            acvp_aes_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
    }
    json_array_append_value(reg_arry, r_vs_val);
    rv = ACVP_SUCCESS;

    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
        printf("\n\n%s\n\n", json_result);
    } else {
        ACVP_LOG_INFO("\n\n%s\n\n", json_result);
    }
    json_free_serialized_string(json_result);

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
static ACVP_RESULT acvp_aes_output_tc(ACVP_CTX *ctx,
                                      ACVP_SYM_CIPHER_TC *stc,
                                      JSON_Object *tc_rsp,
                                      int opt_rv) {
    ACVP_RESULT rv;
    char *tmp = NULL;

    tmp = calloc(ACVP_SYM_CT_MAX + 1, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_aes_output_tc");
        return ACVP_MALLOC_FAIL;
    }

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

    if (stc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
        memzero_s(tmp, ACVP_SYM_CT_MAX);
        if (stc->cipher == ACVP_AES_CFB1) {
            rv = acvp_bin_to_hexstr(stc->ct, (stc->ct_len + 7) / 8, tmp, ACVP_SYM_CT_MAX);
        } else if (stc->cipher == ACVP_AES_GCM) {
            rv = acvp_bin_to_hexstr(stc->ct, stc->pt_len, tmp, ACVP_SYM_CT_MAX);
        } else {
            rv = acvp_bin_to_hexstr(stc->ct, stc->ct_len, tmp, ACVP_SYM_CT_MAX);
        }
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (ct)");
            goto err;
        }
        json_object_set_string(tc_rsp, "ct", tmp);

        /*
         * AES-GCM ciphers need to include the tag
         */
        if (stc->cipher == ACVP_AES_GCM) {
            memzero_s(tmp, ACVP_SYM_CT_MAX);
            rv = acvp_bin_to_hexstr(stc->tag, stc->tag_len, tmp, ACVP_SYM_CT_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (tag)");
                goto err;
            }
            json_object_set_string(tc_rsp, "tag", tmp);
        }
    } else {
        if (stc->cipher == ACVP_AES_GCM || stc->cipher == ACVP_AES_CCM ||
            stc->cipher == ACVP_AES_KW || stc->cipher == ACVP_AES_KWP) {
            if (opt_rv != 0) {
                json_object_set_boolean(tc_rsp, "testPassed", 0);
                free(tmp);
                return ACVP_SUCCESS;
            } else {
                json_object_set_boolean(tc_rsp, "testPassed", 1);
            }
        }

        if (stc->cipher == ACVP_AES_CFB1) {
            rv = acvp_bin_to_hexstr(stc->pt, (stc->pt_len + 7) / 8, tmp, ACVP_SYM_PT_MAX);
        } else if (stc->cipher == ACVP_AES_GCM) {
            rv = acvp_bin_to_hexstr(stc->pt, stc->ct_len, tmp, ACVP_SYM_PT_MAX);
        } else {
            rv = acvp_bin_to_hexstr(stc->pt, stc->pt_len, tmp, ACVP_SYM_PT_MAX);
        }
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("hex conversion failure (pt)");
            goto err;
        }
        json_object_set_string(tc_rsp, "pt", tmp);
    }
    free(tmp);

    return ACVP_SUCCESS;

err:
    if (tmp) free(tmp);
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
static ACVP_RESULT acvp_aes_init_tc(ACVP_CTX *ctx,
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
                                    unsigned int data_len,
                                    int pt_len,
                                    unsigned int tag_len,
                                    ACVP_CIPHER alg_id,
                                    ACVP_SYM_CIPH_DIR dir,
                                    ACVP_SYM_CIPH_IVGEN_SRC iv_gen,
                                    ACVP_SYM_CIPH_IVGEN_MODE iv_gen_mode,
                                    unsigned int aad_len,
                                    unsigned int incr_ctr,
                                    unsigned int ovrflw_ctr) {

    ACVP_RESULT rv;

    memzero_s(stc, sizeof(ACVP_SYM_CIPHER_TC));

    stc->key = calloc(1, ACVP_SYM_KEY_MAX_BYTES);
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

    rv = acvp_hexstr_to_bin(j_key, stc->key, ACVP_SYM_KEY_MAX_BYTES, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (key)");
        return rv;
    }

    if (j_pt) {
        if (alg_id == ACVP_AES_CFB1) {
            rv = acvp_hexstr_to_bin(j_pt, stc->pt, ACVP_SYM_PT_BYTE_MAX, NULL);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (pt)");
                return rv;
            }
            stc->data_len = data_len;
            stc->pt_len = data_len;
        } else {
            rv = acvp_hexstr_to_bin(j_pt, stc->pt, ACVP_SYM_PT_BYTE_MAX, NULL);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (pt)");
                return rv;
            }
            if (alg_id == ACVP_AES_CCM) {
                stc->pt_len = pt_len / 8;
            } else {
                stc->pt_len = strnlen_s(j_pt, ACVP_SYM_PT_MAX) / 2;
            }
        }
    }

    if (j_ct) {
        if (alg_id == ACVP_AES_CFB1) {
            rv = acvp_hexstr_to_bin(j_ct, stc->ct, ACVP_SYM_CT_BYTE_MAX, NULL);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (ct)");
                return rv;
            }
            stc->data_len = data_len;
            stc->ct_len = data_len;
        } else {
            rv = acvp_hexstr_to_bin(j_ct, stc->ct, ACVP_SYM_CT_BYTE_MAX, NULL);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (ct)");
                return rv;
            }
            if (alg_id == ACVP_AES_CCM) {
                stc->ct_len = pt_len / 8;
            } else {
                stc->ct_len = strnlen_s(j_ct, ACVP_SYM_CT_MAX) / 2;
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
    stc->tag_len = tag_len / 8;
    stc->aad_len = aad_len / 8;
    if (!stc->pt_len) stc->pt_len = pt_len / 8;
    if (!stc->ct_len) stc->ct_len = pt_len / 8;

    stc->cipher = alg_id;
    stc->direction = dir;
    stc->ivgen_source = iv_gen;
    stc->ivgen_mode = iv_gen_mode;
    stc->incr_ctr = incr_ctr;
    stc->ovrflw_ctr = ovrflw_ctr;

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_aes_release_tc(ACVP_SYM_CIPHER_TC *stc) {
    if (stc->key) free(stc->key);
    if (stc->pt) free(stc->pt);
    if (stc->ct) free(stc->ct);
    if (stc->tag) free(stc->tag);
    if (stc->iv) free(stc->iv);
    if (stc->aad) free(stc->aad);
    memzero_s(stc, sizeof(ACVP_SYM_CIPHER_TC));

    return ACVP_SUCCESS;
}
