/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include <openssl/evp.h>

#include "acvp/acvp.h"
#include "app_lcl.h"
#include "safe_lib.h"
#ifdef ACVP_NO_RUNTIME
# include "app_fips_lcl.h"
#endif

static EVP_CIPHER_CTX *glb_cipher_ctx = NULL; /* need to maintain across calls for MCT */

void app_des_cleanup(void) {
    if (glb_cipher_ctx) EVP_CIPHER_CTX_free(glb_cipher_ctx);
    glb_cipher_ctx = NULL;
}

int app_des_handler(ACVP_TEST_CASE *test_case) {
    ACVP_SYM_CIPHER_TC      *tc;
    EVP_CIPHER_CTX *cipher_ctx;
    const EVP_CIPHER        *cipher;
    unsigned char *iv = 0;

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

    switch (tc->cipher) {
    case ACVP_TDES_ECB:
        cipher = EVP_des_ede3_ecb();
        break;
    case ACVP_TDES_CBC:
        iv = tc->iv;
        cipher = EVP_des_ede3_cbc();
        break;
    case ACVP_TDES_OFB:
        iv = tc->iv;
        cipher = EVP_des_ede3_ofb();
        break;
    case ACVP_TDES_CFB64:
        iv = tc->iv;
        cipher = EVP_des_ede3_cfb64();
        break;
    case ACVP_TDES_CFB8:
        iv = tc->iv;
        cipher = EVP_des_ede3_cfb8();
        break;
    case ACVP_TDES_CFB1:
        iv = tc->iv;
        cipher = EVP_des_ede3_cfb1();
        break;
    case ACVP_TDES_CTR:
    /*
     * IMPORTANT: if this mode is supported in your crypto module,
     * you will need to fill that out here. It is set to fall
     * through as an unsupported mode.
     */
    case ACVP_CIPHER_START:
    case ACVP_AES_GCM:
    case ACVP_AES_GCM_SIV:
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
    case ACVP_TDES_CBCI:
    case ACVP_TDES_OFBI:
    case ACVP_TDES_CFBP1:
    case ACVP_TDES_CFBP8:
    case ACVP_TDES_CFBP64:
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
    case ACVP_KAS_FFC_COMP:
    case ACVP_KAS_FFC_NOCOMP:
    case ACVP_CIPHER_END:
    default:
        printf("Error: Unsupported DES mode requested by ACVP server\n");
        goto err;

        break;
    }

    /* If Monte Carlo we need to be able to init and then update
     * one thousand times before we complete each iteration.
     */
    if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT) {
        const unsigned char *ctx_iv = NULL;


#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        ctx_iv = cipher_ctx->iv;
#else
        ctx_iv = EVP_CIPHER_CTX_iv(cipher_ctx);
#endif

#define SYM_IV_BYTE_MAX 128
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
            if (tc->mct_index == 0) {
                EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, iv, 1);
                EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            } else {
                /* TDES needs the pre-operation IV returned */
                memcpy_s(tc->iv_ret, SYM_IV_BYTE_MAX, ctx_iv, 8);
            }
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }

            EVP_Cipher(cipher_ctx, tc->ct, tc->pt, tc->pt_len);
            tc->ct_len = tc->pt_len;
            /* TDES needs the post-operation IV returned */
            memcpy_s(tc->iv_ret_after, SYM_IV_BYTE_MAX, ctx_iv, 8);
        } else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
            if (tc->mct_index == 0) {
                EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, iv, 0);
                EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            } else {
                /* TDES needs the pre-operation IV returned */
                memcpy_s(tc->iv_ret, SYM_IV_BYTE_MAX, ctx_iv, 8);
            }
            if (tc->cipher == ACVP_TDES_CFB1) {
                EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            }
            EVP_Cipher(cipher_ctx, tc->pt, tc->ct, tc->ct_len);
            tc->pt_len = tc->ct_len;
            /* TDES needs the post-operation IV returned */
            memcpy_s(tc->iv_ret_after, SYM_IV_BYTE_MAX, ctx_iv, 8);
        } else {
            printf("Unsupported direction\n");
            goto err;
        }
        if (tc->mct_index == ACVP_DES_MCT_INNER - 1) {
            EVP_CIPHER_CTX_free(cipher_ctx);
            glb_cipher_ctx = NULL;
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

        EVP_CIPHER_CTX_free(glb_cipher_ctx);
        glb_cipher_ctx = NULL;
    }

    return 0;
err:
    if (glb_cipher_ctx) EVP_CIPHER_CTX_free(glb_cipher_ctx);
    glb_cipher_ctx = NULL;
    return 1;
}

