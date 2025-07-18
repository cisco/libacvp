/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "acvp/acvp.h"
#include "app_lcl.h"
#include "safe_lib.h"

#include <openssl/evp.h>
#include <openssl/err.h>

static EVP_CIPHER_CTX *glb_cipher_ctx = NULL; /* need to maintain across calls for MCT */

void app_des_cleanup(void) {
    if (glb_cipher_ctx) EVP_CIPHER_CTX_free(glb_cipher_ctx);
    glb_cipher_ctx = NULL;
}

int app_des_handler(ACVP_TEST_CASE *test_case) {
    ACVP_SYM_CIPHER_TC *tc = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    unsigned char *iv = 0;
    unsigned char *ctx_iv = NULL;
    ACVP_SUB_TDES alg = 0;
    int rv = 1;

    if (!test_case) {
        goto err;
    }

    tc = test_case->tc.symmetric;
    
    if (!tc) {
        goto err;
    }

    /*
     * We only support 3 key DES
     */
    if (tc->key_len != 192) {
        printf("Unsupported DES key length\n");
        goto err;
    }

    if (glb_cipher_ctx == NULL) {
        glb_cipher_ctx = EVP_CIPHER_CTX_new();
        if (glb_cipher_ctx == NULL) {
            printf("Failed to allocate global cipher_ctx\n");
            goto err;
        }
    }

    if (!tc->iv_ret || !tc->iv_ret_after) {
        printf("iv_ret or iv_ret_after not initialized; unable to process test case\n");
        goto err;
    }

    /* Begin encrypt code section */
    cipher_ctx = glb_cipher_ctx;

    alg = acvp_get_tdes_alg(tc->cipher);
    if (alg == 0) {
        printf("Invalid cipher value");
        return 1;
    }
    
    switch (alg) {
    case ACVP_SUB_TDES_ECB:
        cipher = EVP_des_ede3_ecb();
        break;
    case ACVP_SUB_TDES_CBC:
        iv = tc->iv;
        cipher = EVP_des_ede3_cbc();
        break;
    case ACVP_SUB_TDES_OFB:
        iv = tc->iv;
        cipher = EVP_des_ede3_ofb();
        break;
    case ACVP_SUB_TDES_CFB64:
        iv = tc->iv;
        cipher = EVP_des_ede3_cfb64();
        break;
    case ACVP_SUB_TDES_CFB8:
        iv = tc->iv;
        cipher = EVP_des_ede3_cfb8();
        break;
    case ACVP_SUB_TDES_CFB1:
        iv = tc->iv;
        cipher = EVP_des_ede3_cfb1();
        break;
    case ACVP_SUB_TDES_CTR:
    /*
     * IMPORTANT: if this mode is supported in your crypto module,
     * you will need to fill that out here. It is set to fall
     * through as an unsupported mode.
     */
    case ACVP_SUB_TDES_CBCI:
    case ACVP_SUB_TDES_OFBI:
    case ACVP_SUB_TDES_CFBP1:
    case ACVP_SUB_TDES_CFBP8:
    case ACVP_SUB_TDES_CFBP64:
    case ACVP_SUB_TDES_KW:
    default:
        printf("Error: Unsupported DES mode requested by ACVP server\n");
        goto err;

        break;
    }

    /* If Monte Carlo we need to be able to init and then update
     * one thousand times before we complete each iteration.
     */
    if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT) {
        ctx_iv = calloc(8, sizeof(unsigned char));
        if (!ctx_iv) {
            printf("Error allocating memory for TDES test\n");
            goto err;
        }

#define SYM_IV_BYTE_MAX 128
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
            if (tc->mct_index == 0) {
                EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, iv, 1);
                EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            } else {
                /* TDES needs the pre-operation IV returned */
                EVP_CIPHER_CTX_get_updated_iv(cipher_ctx, (void *)ctx_iv, 8);
                memcpy_s(tc->iv_ret, SYM_IV_BYTE_MAX, ctx_iv, 8);
            }
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }

            EVP_Cipher(cipher_ctx, tc->ct, tc->pt, tc->pt_len);
            tc->ct_len = tc->pt_len;
            /* TDES needs the post-operation IV returned */
            EVP_CIPHER_CTX_get_updated_iv(cipher_ctx, (void *)ctx_iv, 8);
            memcpy_s(tc->iv_ret_after, SYM_IV_BYTE_MAX, ctx_iv, 8);
        } else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
            if (tc->mct_index == 0) {
                EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, iv, 0);
                EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            } else {
                /* TDES needs the pre-operation IV returned */
                EVP_CIPHER_CTX_get_updated_iv(cipher_ctx, (void *)ctx_iv, 8);
                memcpy_s(tc->iv_ret, SYM_IV_BYTE_MAX, ctx_iv, 8);
            }
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }
            EVP_Cipher(cipher_ctx, tc->pt, tc->ct, tc->ct_len);
            tc->pt_len = tc->ct_len;
            /* TDES needs the post-operation IV returned */
            EVP_CIPHER_CTX_get_updated_iv(cipher_ctx, (void *)ctx_iv, 8);
            memcpy_s(tc->iv_ret_after, SYM_IV_BYTE_MAX, ctx_iv, 8);
        } else {
            printf("Unsupported direction\n");
            goto err;
        }
    } else {
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
            EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, iv, 1);
            EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }
            EVP_Cipher(cipher_ctx, tc->ct, tc->pt, tc->pt_len);
            tc->ct_len = tc->pt_len;
        } else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
            EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, iv, 0);
            EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }
            EVP_Cipher(cipher_ctx, tc->pt, tc->ct, tc->ct_len);
            tc->pt_len = tc->ct_len;
        } else {
            printf("Unsupported direction\n");
            goto err;
        }
    }

    rv = 0;
err:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (ctx_iv) free(ctx_iv);
    //free global if not MCT, or if we are at at a specific point in MCT
    if (glb_cipher_ctx && (tc->test_type != ACVP_SYM_TEST_TYPE_MCT || tc->mct_index == ACVP_DES_MCT_INNER - 1)) {
        EVP_CIPHER_CTX_free(glb_cipher_ctx);
        glb_cipher_ctx = NULL;
    }
    return rv;
}

