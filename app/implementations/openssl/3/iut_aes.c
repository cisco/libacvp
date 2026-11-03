/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include "acvp/acvp.h"
#include "app_lcl.h"
#include "safe_lib.h"
#include "implementations/openssl/3/iut.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>


static APP_MCT_CTX *glb_mct_contexts = NULL;

static void app_aes_free_mct_context(void *context) {
    EVP_CIPHER_CTX_free(context);
}

void app_aes_cleanup(void) {
    app_mct_context_cleanup(&glb_mct_contexts);
}

int app_aes_handler(ACVP_TEST_CASE *test_case) {
    ACVP_SYM_CIPHER_TC *tc = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    const char *alg_name = NULL;
    unsigned char *iv = NULL, *out = NULL;
    const unsigned char *in = NULL;
    unsigned int in_len = 0;
    int rv = 1, direction = 0, out_len = 0, final_len = 0;
    int is_mct = 0, finish = 0;
    const char *cts_mode = NULL;
    ACVP_SUB_AES alg;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;

    if (!test_case || !test_case->tc.symmetric) {
        printf("Missing AES test case\n");
        goto err;
    }

    tc = test_case->tc.symmetric;
    is_mct = tc->test_type == ACVP_SYM_TEST_TYPE_MCT;
    finish = !is_mct || tc->mct_index == ACVP_AES_MCT_INNER - 1;
    if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
        tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
        printf("Unsupported direction\n");
        goto err;
    }
    direction = tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT;
    if (direction) {
        in = tc->pt;
        out = tc->ct;
        in_len = tc->pt_len;
    } else {
        in = tc->ct;
        out = tc->pt;
        in_len = tc->ct_len;
    }
    /* Create a fresh context for non-MCT tests or the first MCT inner iteration. */
    if (!is_mct || tc->mct_index == 0) {
        cipher_ctx = EVP_CIPHER_CTX_new();
        if (!cipher_ctx) {
            printf("Failed to allocate AES cipher context\n");
            goto err;
        }
        if (is_mct) {
            if (app_mct_context_add(&glb_mct_contexts, tc, cipher_ctx, app_aes_free_mct_context) != 0) {
                EVP_CIPHER_CTX_free(cipher_ctx);
                cipher_ctx = NULL;
                goto err;
            }
        }
    } else {
        cipher_ctx = app_mct_context_find(glb_mct_contexts, tc);
        if (!cipher_ctx) {
            printf("Missing AES MCT cipher context\n");
            goto err;
        }
    }

    alg = acvp_get_aes_alg(tc->cipher);
    if (alg == 0) {
        printf("Invalid cipher value\n");
        goto err;
    }

    switch (alg) {
    case ACVP_SUB_AES_ECB:
        switch (tc->key_len) {
        case 128:
            alg_name = "AES-128-ECB";
            break;
        case 192:
            alg_name = "AES-192-ECB";
            break;
        case 256:
            alg_name = "AES-256-ECB";
            break;
        default:
            printf("Unsupported AES-ECB key length\n");
            goto err;
        }
        break;
    case ACVP_SUB_AES_CTR:
        switch (tc->key_len) {
        case 128:
            alg_name = "AES-128-CTR";
            break;
        case 192:
            alg_name = "AES-192-CTR";
            break;
        case 256:
            alg_name = "AES-256-CTR";
            break;
        default:
            printf("Unsupported AES-CTR key length\n");
            goto err;
        }
        iv = tc->iv;
        break;
    case ACVP_SUB_AES_CFB1:
        switch (tc->key_len) {
        case 128:
            alg_name = "AES-128-CFB1";
            break;
        case 192:
            alg_name = "AES-192-CFB1";
            break;
        case 256:
            alg_name = "AES-256-CFB1";
            break;
        default:
            printf("Unsupported AES-CFB1 key length\n");
            goto err;
        }
        iv = tc->iv;
        break;
    case ACVP_SUB_AES_CFB8:
        switch (tc->key_len) {
        case 128:
            alg_name = "AES-128-CFB8";
            break;
        case 192:
            alg_name = "AES-192-CFB8";
            break;
        case 256:
            alg_name = "AES-256-CFB8";
            break;
        default:
            printf("Unsupported AES-CFB8 key length\n");
            goto err;
        }
        iv = tc->iv;
        break;
    case ACVP_SUB_AES_CFB128:
        switch (tc->key_len) {
        case 128:
            alg_name = "AES-128-CFB";
            break;
        case 192:
            alg_name = "AES-192-CFB";
            break;
        case 256:
            alg_name = "AES-256-CFB";
            break;
        default:
            printf("Unsupported AES-CFB key length\n");
            goto err;
        }
        iv = tc->iv;
        break;
    case ACVP_SUB_AES_OFB:
        switch (tc->key_len) {
        case 128:
            alg_name = "AES-128-OFB";
            break;
        case 192:
            alg_name = "AES-192-OFB";
            break;
        case 256:
            alg_name = "AES-256-OFB";
            break;
        default:
            printf("Unsupported AES-OFB key length\n");
            goto err;
        }
        iv = tc->iv;
        break;
    case ACVP_SUB_AES_CBC:
        switch (tc->key_len) {
        case 128:
            alg_name = "AES-128-CBC";
            break;
        case 192:
            alg_name = "AES-192-CBC";
            break;
        case 256:
            alg_name = "AES-256-CBC";
            break;
        default:
            printf("Unsupported AES-CBC key length\n");
            goto err;
        }
        iv = tc->iv;
        break;
    case ACVP_SUB_AES_CBC_CS1:
    case ACVP_SUB_AES_CBC_CS2:
    case ACVP_SUB_AES_CBC_CS3:
        switch (tc->key_len) {
        case 128:
            alg_name = "AES-128-CBC-CTS";
            break;
        case 192:
            alg_name = "AES-192-CBC-CTS";
            break;
        case 256:
            alg_name = "AES-256-CBC-CTS";
            break;
        default:
            printf("Unsupported AES-CTS key length\n");
            goto err;
        }
        iv = tc->iv;
        if (alg == ACVP_SUB_AES_CBC_CS1) {
            cts_mode = "CS1";
        } else if (alg == ACVP_SUB_AES_CBC_CS2) {
            cts_mode = "CS2";
        } else {
            cts_mode = "CS3";
        }
        break;
    case ACVP_SUB_AES_XTS:
        switch (tc->key_len) {
        case 128:
            alg_name = "AES-128-XTS";
            break;
        case 256:
            alg_name = "AES-256-XTS";
            break;
        default:
            printf("Unsupported AES-XTS key length\n");
            goto err;
        }
        if (tc->tw_mode == ACVP_SYM_CIPH_TWEAK_HEX) {
            iv = tc->iv;
        }
        break;
    case ACVP_SUB_AES_GCM:
    case ACVP_SUB_AES_GCM_SIV:
    case ACVP_SUB_AES_CCM:
    case ACVP_SUB_AES_XPN:
    case ACVP_SUB_AES_KW:
    case ACVP_SUB_AES_KWP:
    case ACVP_SUB_AES_GMAC:
    case ACVP_SUB_AES_FF1:
    case ACVP_SUB_AES_FF3:
    default:
        printf("Error: Unsupported AES mode requested by ACVP server\n");
        rv = 1;
        goto err;
    }

    /* Initialize normally for non-MCT tests, or only on the first MCT inner iteration. */
    if (!is_mct || tc->mct_index == 0) {
        cipher = EVP_CIPHER_fetch(NULL, alg_name, NULL);
        if (!cipher) {
            printf("Unable to fetch AES cipher\n");
            goto err;
        }

        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in AES\n");
            goto err;
        }
        if (OSSL_PARAM_BLD_push_uint(pbld, OSSL_CIPHER_PARAM_PADDING, 0) != 1) {
            printf("Error building AES padding parameter\n");
            goto err;
        }
        if (alg == ACVP_SUB_AES_CFB1) {
            if (OSSL_PARAM_BLD_push_uint(pbld, OSSL_CIPHER_PARAM_USE_BITS, 1) != 1) {
                printf("Error building AES-CFB1 bit-length parameter\n");
                goto err;
            }
        }
        if (cts_mode) {
            if (OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_CIPHER_PARAM_CTS_MODE, cts_mode, 0) != 1) {
                printf("Error building AES-CTS mode parameter\n");
                goto err;
            }
        }
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in AES\n");
            goto err;
        }
        if (EVP_CipherInit_ex2(cipher_ctx, cipher, tc->key, iv, direction, params) != 1) {
            printf("Error initializing cipher in AES\n");
            goto err;
        }
    }
    if (EVP_CipherUpdate(cipher_ctx, out, &out_len, in, (int)in_len) != 1) {
        printf("Error processing AES payload\n");
        goto err;
    }
    /*
     * Finalize for non-MCT tests, or only on the last MCT inner iteration. With
     * padding disabled, these modes produce all output in Update.
     */
    if (finish) {
        if (EVP_CipherFinal_ex(cipher_ctx, out, &final_len) != 1) {
            printf("Error finalizing AES cipher\n");
            goto err;
        }
    }
    if (is_mct && out_len != (int)in_len) {
        printf("AES MCT iteration did not produce the complete result\n");
        goto err;
    }
    if (direction) {
        tc->ct_len = (unsigned int)out_len;
    } else {
        tc->pt_len = (unsigned int)out_len;
    }
    rv = 0;

err:
    if (rv != 0) {
        ERR_print_errors_fp(stderr);
    }
    /* Stop tracking this mct test on completion or failure */
    if (is_mct && (rv != 0 || finish)) {
        app_mct_context_remove(&glb_mct_contexts, tc);
    }
    if (!is_mct && cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
    if (cipher) EVP_CIPHER_free(cipher);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    ERR_clear_error();
    return rv;
}

int app_aes_keywrap_handler(ACVP_TEST_CASE *test_case) {
    ACVP_SYM_CIPHER_TC *tc = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int out_len = 0, final_len = 0;
    int rv = 1, direction = 0;
    unsigned int in_len = 0;
    unsigned char *out = NULL;
    const unsigned char *in = NULL;
    ACVP_SUB_AES alg;
    const char *alg_name = NULL;

    if (!test_case || !test_case->tc.symmetric) {
        printf("Missing AES keywrap test case\n");
        return rv;
    }

    tc = test_case->tc.symmetric;

    if (!tc->pt || !tc->ct || (!tc->pt_len && !tc->ct_len)) {
        printf("Missing payload or output buffer from AES KW test case\n");
        goto err;
    }
    if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
        tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
        printf("Unsupported AES keywrap direction\n");
        goto err;
    }
    direction = tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT;
    if (direction) {
        in = tc->pt;
        out = tc->ct;
        in_len = tc->pt_len;
    } else {
        in = tc->ct;
        out = tc->pt;
        in_len = tc->ct_len;
    }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        printf("Error creating CTX in AES keywrap\n");
        goto err;
    }

    alg = acvp_get_aes_alg(tc->cipher);
    if (alg == 0) {
        printf("Invalid cipher value\n");
        goto err;
    }

    switch (alg) {
    case ACVP_SUB_AES_KW:
        switch (tc->key_len) {
        case 128:
            if (tc->kwcipher == ACVP_SYM_KW_INVERSE) {
                alg_name = "AES-128-WRAP-INV";
            } else {
                alg_name = "AES-128-WRAP";
            }
            break;
        case 192:
            if (tc->kwcipher == ACVP_SYM_KW_INVERSE) {
                alg_name = "AES-192-WRAP-INV";
            } else {
                alg_name = "AES-192-WRAP";
            }
            break;
        case 256:
            if (tc->kwcipher == ACVP_SYM_KW_INVERSE) {
                alg_name = "AES-256-WRAP-INV";
            } else {
                alg_name = "AES-256-WRAP";
            }
            break;
        default:
            printf("Unsupported AES-KW key length\n");
            goto err;
        }
        break;
    case ACVP_SUB_AES_KWP:
        switch (tc->key_len) {
        case 128:
            if (tc->kwcipher == ACVP_SYM_KW_INVERSE) {
                alg_name = "AES-128-WRAP-PAD-INV";
            } else {
                alg_name = "AES-128-WRAP-PAD";
            }
            break;
        case 192:
            if (tc->kwcipher == ACVP_SYM_KW_INVERSE) {
                alg_name = "AES-192-WRAP-PAD-INV";
            } else {
                alg_name = "AES-192-WRAP-PAD";
            }
            break;
        case 256:
            if (tc->kwcipher == ACVP_SYM_KW_INVERSE) {
                alg_name = "AES-256-WRAP-PAD-INV";
            } else {
                alg_name = "AES-256-WRAP-PAD";
            }
            break;
        default:
            printf("Unsupported AES-KWP key length\n");
            goto err;
        }
        break;
    case ACVP_SUB_AES_ECB:
    case ACVP_SUB_AES_CTR:
    case ACVP_SUB_AES_CFB1:
    case ACVP_SUB_AES_CFB8:
    case ACVP_SUB_AES_CFB128:
    case ACVP_SUB_AES_OFB:
    case ACVP_SUB_AES_CBC:
    case ACVP_SUB_AES_CBC_CS1:
    case ACVP_SUB_AES_CBC_CS2:
    case ACVP_SUB_AES_CBC_CS3:
    case ACVP_SUB_AES_XTS:
    case ACVP_SUB_AES_GCM:
    case ACVP_SUB_AES_GCM_SIV:
    case ACVP_SUB_AES_CCM:
    case ACVP_SUB_AES_XPN:
    case ACVP_SUB_AES_GMAC:
    case ACVP_SUB_AES_FF1:
    case ACVP_SUB_AES_FF3:
    default:
        printf("Error: Unsupported AES mode requested by ACVP server\n");
        rv = 1;
        goto err;
    }

    cipher = EVP_CIPHER_fetch(NULL, alg_name, NULL);
    if (!cipher) {
        printf("Unable to fetch AES cipher\n");
        goto err;
    }

    if (EVP_CipherInit_ex2(cipher_ctx, cipher, tc->key, NULL, direction, NULL) != 1) {
        printf("Error initializing AES keywrap cipher\n");
        goto err;
    }
    /* WRAP and WRAP-PAD require the complete input in one Update. */
    if (EVP_CipherUpdate(cipher_ctx, out, &out_len, in, (int)in_len) != 1) {
        if (direction) {
            printf("AES keywrap operation failed\n");
        }
        goto err;
    }
    if (EVP_CipherFinal_ex(cipher_ctx, out + out_len, &final_len) != 1) {
        printf("Error finalizing AES keywrap cipher\n");
        goto err;
    }
    out_len += final_len;
    if (direction) {
        tc->ct_len = (unsigned int)out_len;
    } else {
        tc->pt_len = (unsigned int)out_len;
    }
    rv = 0;
err:
    if (rv != 0) {
        if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
            tc->pt_len = 0;
        } else {
            tc->ct_len = 0;
        }
    }
    // Cleanup
    if (cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
    if (cipher) EVP_CIPHER_free(cipher);
    ERR_clear_error();
    return rv;
}

int app_aes_handler_aead(ACVP_TEST_CASE *test_case) {
    ACVP_SYM_CIPHER_TC *tc = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char iv_fixed[4] = { 1, 2, 3, 4 };
    unsigned char *out = NULL, *tag = NULL;
    const unsigned char *in = NULL;
    int rv = 1, direction = 0, len = 0, out_len = 0, final_len = 0;
    unsigned int in_len = 0;
    size_t iv_len = 0;
    ACVP_SUB_AES alg;
    const char *alg_name = NULL;
    OSSL_PARAM params[3];

    if (!test_case || !test_case->tc.symmetric) {
        printf("Missing AES AEAD test case\n");
        return 1;
    }

    tc = test_case->tc.symmetric;

    if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT && tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
        printf("Unsupported direction\n");
        goto err;
    }
    direction = tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT;
    alg = acvp_get_aes_alg(tc->cipher);
    if (direction) {
        in = tc->pt;
        out = tc->ct;
        in_len = tc->pt_len;
    } else {
        in = tc->ct;
        out = tc->pt;
        in_len = tc->ct_len;
    }
    iv_len = tc->iv_len;
    switch (alg) {
    case ACVP_SUB_AES_CCM:
        switch (tc->key_len) {
        case 128:
            alg_name = "AES-128-CCM";
            break;
        case 192:
            alg_name = "AES-192-CCM";
            break;
        case 256:
            alg_name = "AES-256-CCM";
            break;
        default:
            printf("Unsupported AES-CCM key length\n");
            goto err;
        }
        break;
    case ACVP_SUB_AES_GCM:
        switch (tc->key_len) {
        case 128:
            alg_name = "AES-128-GCM";
            break;
        case 192:
            alg_name = "AES-192-GCM";
            break;
        case 256:
            alg_name = "AES-256-GCM";
            break;
        default:
            printf("Unsupported AES-GCM key length\n");
            goto err;
        }
        break;
    case ACVP_SUB_AES_GCM_SIV:
    case ACVP_SUB_AES_ECB:
    case ACVP_SUB_AES_CBC:
    case ACVP_SUB_AES_CBC_CS1:
    case ACVP_SUB_AES_CBC_CS2:
    case ACVP_SUB_AES_CBC_CS3:
    case ACVP_SUB_AES_CFB1:
    case ACVP_SUB_AES_CFB8:
    case ACVP_SUB_AES_CFB128:
    case ACVP_SUB_AES_OFB:
    case ACVP_SUB_AES_CTR:
    case ACVP_SUB_AES_XTS:
    case ACVP_SUB_AES_XPN:
    case ACVP_SUB_AES_KW:
    case ACVP_SUB_AES_KWP:
    case ACVP_SUB_AES_GMAC:
    case ACVP_SUB_AES_FF1:
    case ACVP_SUB_AES_FF3:
    default:
        printf("Unsupported AES AEAD mode\n");
        goto err;
    }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        printf("Error initializing cipher CTX\n");
        goto err;
    }
    cipher = EVP_CIPHER_fetch(NULL, alg_name, NULL);
    if (!cipher) {
        printf("Error fetching AES AEAD cipher\n");
        goto err;
    }

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &iv_len);
    params[1] = OSSL_PARAM_construct_end();
    params[2] = OSSL_PARAM_construct_end();
    if (alg == ACVP_SUB_AES_CCM) {
        /* CCM ciphertext is the payload followed by the tag; there's no separate tag field. */
        if (!direction) {
            tag = tc->ct + in_len;
        }
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                    tag, tc->tag_len);
    }
    if (EVP_CipherInit_ex2(cipher_ctx, cipher, tc->key, NULL, direction, params) != 1) {
        printf("Error configuring AES AEAD cipher\n");
        goto err;
    }
    if (alg == ACVP_SUB_AES_GCM && direction &&
        tc->ivgen_source == ACVP_SYM_CIPH_IVGEN_SRC_INT) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED,
                                                    iv_fixed, sizeof(iv_fixed));
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_CIPHER_CTX_set_params(cipher_ctx, params) != 1) {
            printf("Error setting AES-GCM fixed IV\n");
            goto err;
        }
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN,
                                                    tc->iv, tc->iv_len);
        if (EVP_CIPHER_CTX_get_params(cipher_ctx, params) != 1) {
            printf("Error generating AES-GCM IV\n");
            goto err;
        }
    } else {
        /* Decryption always consumes the supplied IV, even for internal-IV groups. */
        if (EVP_CipherInit_ex2(cipher_ctx, NULL, tc->key, tc->iv, direction, NULL) != 1) {
            printf("Error setting AES AEAD key and IV\n");
            goto err;
        }
    }
    if (alg == ACVP_SUB_AES_GCM && !direction) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                    tc->tag, tc->tag_len);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_CIPHER_CTX_set_params(cipher_ctx, params) != 1) {
            printf("Error setting AES-GCM tag\n");
            goto err;
        }
    }
    /* EVP_EncryptInit(3), CCM Mode: declare length before processing AAD. */
    if (alg == ACVP_SUB_AES_CCM) {
        if (EVP_CipherUpdate(cipher_ctx, NULL, &len, NULL, (int)in_len) != 1) {
            printf("Error declaring AES-CCM payload length\n");
            goto err;
        }
    }
    if (tc->aad_len) {
        if (EVP_CipherUpdate(cipher_ctx, NULL, &len, tc->aad, (int)tc->aad_len) != 1) {
            printf("Error processing AES AEAD AAD\n");
            goto err;
        }
    }
    if (EVP_CipherUpdate(cipher_ctx, out, &out_len, in, (int)in_len) != 1) {
        if (direction) {
            printf("AES AEAD payload processing failed\n");
        }
        goto err;
    }
    if (EVP_CipherFinal_ex(cipher_ctx, out + out_len, &final_len) != 1) {
        if (direction) {
            printf("AES AEAD finalization failed\n");
        }
        goto err;
    }
    out_len += final_len;
    if (direction) {
        tag = tc->tag;
        if (alg == ACVP_SUB_AES_CCM) {
            tag = tc->ct + out_len;
        }
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                    tag, tc->tag_len);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_CIPHER_CTX_get_params(cipher_ctx, params) != 1) {
            printf("Error retrieving AES AEAD tag\n");
            goto err;
        }
        tc->ct_len = (unsigned int)out_len;
        if (alg == ACVP_SUB_AES_CCM) {
            tc->ct_len += tc->tag_len;
        }
    } else {
        tc->pt_len = (unsigned int)out_len;
    }
    rv = 0;
err:
    if (rv != 0) {
        if (direction) {
            tc->ct_len = 0;
            ERR_print_errors_fp(stderr);
        } else {
            tc->pt_len = 0;
        }
    }
    // Cleanup
    if (cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
    if (cipher) EVP_CIPHER_free(cipher);
    ERR_clear_error();
    return rv;
}

int app_aes_handler_gmac(ACVP_TEST_CASE *test_case) {
    ACVP_SYM_CIPHER_TC *tc = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    const char *alg_name = NULL;
    unsigned char iv_fixed[4] = { 1, 2, 3, 4 };
    unsigned char out[16];
    size_t iv_len = 0;
    OSSL_PARAM params[2];
    int rv = 1, direction = 0, len = 0;

    if (!test_case || !test_case->tc.symmetric) {
        printf("Missing AES-GMAC test case\n");
        return rv;
    }

    tc = test_case->tc.symmetric;
    if (!tc->tag_len || tc->tag_len > sizeof(out)) {
        printf("Invalid AES-GMAC tag length\n");
        goto err;
    }
    if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
        tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
        printf("Unsupported AES-GMAC direction\n");
        goto err;
    }
    if (tc->pt_len || tc->ct_len) {
        printf("Invalid AES-GMAC payload\n");
        goto err;
    }
    direction = tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT;

    switch (tc->key_len) {
    case 128:
        alg_name = "AES-128-GCM";
        break;
    case 192:
        alg_name = "AES-192-GCM";
        break;
    case 256:
        alg_name = "AES-256-GCM";
        break;
    default:
        printf("Unsupported AES-GMAC key length\n");
        goto err;
    }

    cipher = EVP_CIPHER_fetch(NULL, alg_name, NULL);
    if (!cipher) {
        printf("Error fetching AES-GMAC cipher\n");
        goto err;
    }
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        printf("Error creating AES-GMAC context\n");
        goto err;
    }

    iv_len = tc->iv_len;
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &iv_len);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_CipherInit_ex2(cipher_ctx, cipher, tc->key, NULL, direction, params) != 1) {
        printf("Error configuring AES-GMAC cipher\n");
        goto err;
    }
    if (direction && tc->ivgen_source == ACVP_SYM_CIPH_IVGEN_SRC_INT) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED,
                                                    iv_fixed, sizeof(iv_fixed));
        if (EVP_CIPHER_CTX_set_params(cipher_ctx, params) != 1) {
            printf("Error setting AES-GMAC fixed IV\n");
            goto err;
        }
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN,
                                                    tc->iv, tc->iv_len);
        if (EVP_CIPHER_CTX_get_params(cipher_ctx, params) != 1) {
            printf("Error generating AES-GMAC IV\n");
            goto err;
        }
    } else {
        if (EVP_CipherInit_ex2(cipher_ctx, NULL, tc->key, tc->iv, direction, NULL) != 1) {
            printf("Error setting AES-GMAC key and IV\n");
            goto err;
        }
    }

    /* GMAC authenticates AAD without processing any payload. */
    if (tc->aad_len) {
        if (EVP_CipherUpdate(cipher_ctx, NULL, &len, tc->aad, (int)tc->aad_len) != 1) {
            printf("Error processing AES-GMAC AAD\n");
            goto err;
        }
    }
    if (!direction) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                    tc->tag, tc->tag_len);
        if (EVP_CIPHER_CTX_set_params(cipher_ctx, params) != 1) {
            printf("Error setting AES-GMAC tag\n");
            goto err;
        }
    }
    if (EVP_CipherFinal_ex(cipher_ctx, out, &len) != 1) {
        goto err;
    }
    if (direction) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                    tc->tag, tc->tag_len);
        if (EVP_CIPHER_CTX_get_params(cipher_ctx, params) != 1) {
            printf("Error getting AES-GMAC tag\n");
            goto err;
        }
    }
    rv = 0;

err:
    if (rv != 0 && tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) ERR_print_errors_fp(stderr);
    if (cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
    if (cipher) EVP_CIPHER_free(cipher);
    ERR_clear_error();
    return rv;
}
