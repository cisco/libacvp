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
#ifdef ACVP_NO_RUNTIME
# include "app_fips_lcl.h"
#endif

int app_sha_handler(ACVP_TEST_CASE *test_case) {
    ACVP_HASH_TC    *tc;
    const EVP_MD    *md;
    EVP_MD_CTX *md_ctx = NULL;
    /* assume fail */
    int rc = 1;
    int sha3 = 0, shake = 0;

    if (!test_case) {
        return 1;
    }

    tc = test_case->tc.hash;
    if (!tc) return rc;

    switch (tc->cipher) {
    case ACVP_HASH_SHA1:
        md = EVP_sha1();
        break;
    case ACVP_HASH_SHA224:
        md = EVP_sha224();
        break;
    case ACVP_HASH_SHA256:
        md = EVP_sha256();
        break;
    case ACVP_HASH_SHA384:
        md = EVP_sha384();
        break;
    case ACVP_HASH_SHA512:
        md = EVP_sha512();
        break;
#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
    case ACVP_HASH_SHA512_224:
        md = EVP_sha512_224();
        break;
    case ACVP_HASH_SHA512_256:
        md = EVP_sha512_256();
        break;
    case ACVP_HASH_SHA3_224:
        md = EVP_sha3_224();
        sha3 = 1;
        break;
    case ACVP_HASH_SHA3_256:
        md = EVP_sha3_256();
        sha3 = 1;
        break;
    case ACVP_HASH_SHA3_384:
        md = EVP_sha3_384();
        sha3 = 1;
        break;
    case ACVP_HASH_SHA3_512:
        md = EVP_sha3_512();
        sha3 = 1;
        break;
    case ACVP_HASH_SHAKE_128:
        md = EVP_shake128();
        shake = 1;
        break;
    case ACVP_HASH_SHAKE_256:
        md = EVP_shake256();
        shake = 1;
        break;
#else
    case ACVP_HASH_SHA512_224:
    case ACVP_HASH_SHA512_256:
    case ACVP_HASH_SHA3_224:
    case ACVP_HASH_SHA3_256:
    case ACVP_HASH_SHA3_384:
    case ACVP_HASH_SHA3_512:
    case ACVP_HASH_SHAKE_128:
    case ACVP_HASH_SHAKE_256:
#endif
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
        printf("Error: Unsupported hash algorithm requested by ACVP server\n");
        return ACVP_NO_CAP;
    }

    if (!tc->md) {
        printf("\nCrypto module error, md memory not allocated by library\n");
        goto end;
    }
    md_ctx = EVP_MD_CTX_create();

    if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT && !sha3 && !shake) {
        /* If Monte Carlo we need to be able to init and then update
         * one thousand times before we complete each iteration.
         * This style doesn't apply to sha3 MCT.
         */
        if (!tc->m1 || !tc->m2 || !tc->m3) {
            printf("\nCrypto module error, m1, m2, or m3 missing in sha mct test case\n");
            goto end;
        }
        if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
            printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
            goto end;
        }
        if (!EVP_DigestUpdate(md_ctx, tc->m1, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestUpdate(md_ctx, tc->m2, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestUpdate(md_ctx, tc->m3, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestFinal(md_ctx, tc->md, &tc->md_len)) {
            printf("\nCrypto module error, EVP_DigestFinal failed\n");
            goto end;
        }
    } else {
        if (!tc->msg) {
            printf("\nCrypto module error, msg missing in sha test case\n");
            goto end;
        }
        if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
            printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
            goto end;
        }

        if (!EVP_DigestUpdate(md_ctx, tc->msg, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
        if (tc->test_type == ACVP_HASH_TEST_TYPE_VOT ||
            (tc->test_type == ACVP_HASH_TEST_TYPE_MCT && shake)) {
            /*
             * Use the XOF oriented function.
             * Skip past the other "EVP_DigestFinal".
             */
            if (!EVP_DigestFinalXOF(md_ctx, tc->md, tc->xof_len)) {
                printf("\nCrypto module error, EVP_DigestFinal failed\n");
                goto end;
            }
            tc->md_len = tc->xof_len;
            rc = 0;
            goto end;
        }
#endif

        if (!EVP_DigestFinal(md_ctx, tc->md, &tc->md_len)) {
            printf("\nCrypto module error, EVP_DigestFinal failed\n");
            goto end;
        }
    }

    rc = 0;

end:
    if (md_ctx) EVP_MD_CTX_destroy(md_ctx);

    return rc;
}

