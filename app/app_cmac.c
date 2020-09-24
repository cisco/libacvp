/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include <openssl/evp.h>
#include <openssl/cmac.h>
#include "acvp/acvp.h"
#include "app_lcl.h"
#include "safe_lib.h"

#ifdef ACVP_NO_RUNTIME
# include "app_fips_lcl.h"
#endif

int app_cmac_handler(ACVP_TEST_CASE *test_case) {
    ACVP_CMAC_TC    *tc;
    int rv = 1;
    const EVP_CIPHER    *c = NULL;
    CMAC_CTX       *cmac_ctx = NULL;
    int key_len, i;
    unsigned char mac_compare[16] = { 0 };
    char full_key[33] = { 0 };
    size_t mac_cmp_len;

    if (!test_case) {
        return rv;
    }

    tc = test_case->tc.cmac;
    if (!tc) return rv;
    if (!tc->key) return rv;

    switch (tc->cipher) {
    case ACVP_CMAC_AES:
        switch (tc->key_len * 8) {
        case 128:
            c = EVP_aes_128_cbc();
            break;
        case 192:
            c = EVP_aes_192_cbc();
            break;
        case 256:
            c = EVP_aes_256_cbc();
            break;
        default:
            break;
        }
        key_len = (tc->key_len);
        for (i = 0; i < key_len; i++) {
            full_key[i] = tc->key[i];
        }
        break;
    case ACVP_CMAC_TDES:
        c = EVP_des_ede3_cbc();
        for (i = 0; i < 8; i++) {
            full_key[i] = tc->key[i];
        }
        for (; i < 16; i++) {
            full_key[i] = tc->key2[i % 8];
        }
        for (; i < 24; i++) {
            full_key[i] = tc->key3[i % 8];
        }
        key_len = 24;
        break;
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
        printf("Error: Unsupported CMAC algorithm requested by ACVP server\n");
        return rv;
    }

    full_key[key_len] = '\0';

    cmac_ctx = CMAC_CTX_new();

    if (!CMAC_Init(cmac_ctx, full_key, key_len, c, NULL)) {
        printf("\nCrypto module error, CMAC_Init_ex failed\n");
        goto cleanup;
    }

    if (!CMAC_Update(cmac_ctx, tc->msg, tc->msg_len)) {
        printf("\nCrypto module error, CMAC_Update failed\n");
        goto cleanup;
    }

    if (tc->verify) {
        int diff = 0;

        if (!CMAC_Final(cmac_ctx, mac_compare, &mac_cmp_len)) {
            printf("\nCrypto module error, CMAC_Final failed\n");
            goto cleanup;
        }

        memcmp_s(tc->mac, tc->mac_len, mac_compare, mac_cmp_len, &diff);
        if (!diff) {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_PASS;
        } else {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_FAIL;
        }
    } else {
        if (!CMAC_Final(cmac_ctx, tc->mac, &mac_cmp_len)) {
            printf("\nCrypto module error, CMAC_Final failed\n");
            goto cleanup;
        }
        tc->mac_len = (int)mac_cmp_len;
    }
    rv = 0;

cleanup:
    if (cmac_ctx) CMAC_CTX_free(cmac_ctx);

    return rv;
}

