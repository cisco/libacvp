/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */



#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "app_fips_lcl.h" /* All regular OpenSSL headers must come before here */
#include "app_lcl.h"
#include "safe_mem_lib.h"
#ifdef ACVP_NO_RUNTIME

typedef struct {
    unsigned char *ent;
    size_t entlen;
    unsigned char *nonce;
    size_t noncelen;
} DRBG_TEST_ENT;

static size_t drbg_test_entropy(DRBG_CTX *dctx,
                                unsigned char **pout,
                                int entropy,
                                size_t min_len,
                                size_t max_len) {
    if (!dctx || !pout || !entropy) return 0;

    DRBG_TEST_ENT *t = (DRBG_TEST_ENT *)FIPS_drbg_get_app_data(dctx);
    if (!t) return 0;

    if (t->entlen < min_len) printf("entropy data len %zu < min_len: %zu\n", t->entlen, min_len);
    if (t->entlen > max_len) printf("entropy data len %zu > max_len: %zu\n", t->entlen, max_len);
    *pout = (unsigned char *)t->ent;
    return t->entlen;
}

static size_t drbg_test_nonce(DRBG_CTX *dctx,
                              unsigned char **pout,
                              int entropy,
                              size_t min_len,
                              size_t max_len) {
    if (!dctx || !pout || !entropy) return 0;

    DRBG_TEST_ENT *t = (DRBG_TEST_ENT *)FIPS_drbg_get_app_data(dctx);

    if (t->noncelen < min_len) printf("nonce data len %zu < min_len: %zu\n", t->noncelen, min_len);
    if (t->noncelen > max_len) printf("nonce data len %zu > max_len: %zu\n", t->noncelen, max_len);
    *pout = (unsigned char *)t->nonce;
    return t->noncelen;
}

int app_drbg_handler(ACVP_TEST_CASE *test_case) {
    int result = 1;
    ACVP_DRBG_TC    *tc;
    unsigned int nid;
    int der_func = 0;
    unsigned int drbg_entropy_len;
    int fips_rc;

    unsigned char   *nonce = NULL;

    if (!test_case) {
        return result;
    }

    tc = test_case->tc.drbg;
    /*
     * Init entropy length
     */
    drbg_entropy_len = tc->entropy_len;

    switch (tc->cipher) {
    case ACVP_HASHDRBG:
        nonce = tc->nonce;
        switch (tc->mode) {
        case ACVP_DRBG_SHA_1:
            nid = NID_sha1;
            break;
        case ACVP_DRBG_SHA_224:
            nid = NID_sha224;
            break;
        case ACVP_DRBG_SHA_256:
            nid = NID_sha256;
            break;
        case ACVP_DRBG_SHA_384:
            nid = NID_sha384;
            break;
        case ACVP_DRBG_SHA_512:
            nid = NID_sha512;
            break;
#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
        case ACVP_DRBG_SHA_512_224:
            nid = NID_sha512_224;
            break;
        case ACVP_DRBG_SHA_512_256:
            nid = NID_sha512_256;
            break;
#endif
        case ACVP_DRBG_TDES:
        case ACVP_DRBG_AES_128:
        case ACVP_DRBG_AES_192:
        case ACVP_DRBG_AES_256:
#if OPENSSL_VERSION_NUMBER < 0x10101010L /* Not OpenSSL */
        case ACVP_DRBG_SHA_512_224:
        case ACVP_DRBG_SHA_512_256:
#endif
        default:
            printf("%s: Unsupported algorithm/mode %d/%d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
                   tc->cipher, tc->mode);
            return result;

            break;
        }
        break;

    case ACVP_HMACDRBG:
        nonce = tc->nonce;
        switch (tc->mode) {
        case ACVP_DRBG_SHA_1:
            nid =   NID_hmacWithSHA1;
            break;
        case ACVP_DRBG_SHA_224:
            nid =   NID_hmacWithSHA224;
            break;
        case ACVP_DRBG_SHA_256:
            nid =   NID_hmacWithSHA256;
            break;
        case ACVP_DRBG_SHA_384:
            nid =   NID_hmacWithSHA384;
            break;
        case ACVP_DRBG_SHA_512:
            nid =   NID_hmacWithSHA512;
            break;
#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
        case ACVP_DRBG_SHA_512_224:
            nid =   NID_hmacWithSHA512_224;
            break;
        case ACVP_DRBG_SHA_512_256:
            nid =   NID_hmacWithSHA512_256;
            break;
#endif
        case ACVP_DRBG_TDES:
        case ACVP_DRBG_AES_128:
        case ACVP_DRBG_AES_192:
        case ACVP_DRBG_AES_256:
#if OPENSSL_VERSION_NUMBER < 0x10101010L /* Not OpenSSL */
        case ACVP_DRBG_SHA_512_224:
        case ACVP_DRBG_SHA_512_256:
#endif
        default:
            printf("%s: Unsupported algorithm/mode %d/%d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
                   tc->cipher, tc->mode);
            return result;

            break;
        }
        break;

    case ACVP_CTRDRBG:
        /*
         * DR function Only valid in CTR mode
         * if not set nonce is ignored
         */
        if (tc->der_func_enabled) {
            der_func = DRBG_FLAG_CTR_USE_DF;
            nonce = tc->nonce;
        } else {
            /**
             * Note 5: All DRBGs are tested at their maximum supported security
             * strength so this is the minimum bit length of the entropy input that
             * ACVP will accept.  The maximum supported security strength is also
             * the default value for this input.  Longer entropy inputs are
             * permitted, with the following exception: for ctrDRBG with no df, the
             * bit length must equal the seed length.
             **/
            drbg_entropy_len = 0;
        }

        switch (tc->mode) {
        case ACVP_DRBG_AES_128:
            nid = NID_aes_128_ctr;
            break;
        case ACVP_DRBG_AES_192:
            nid = NID_aes_192_ctr;
            break;
        case ACVP_DRBG_AES_256:
            nid = NID_aes_256_ctr;
            break;
        case ACVP_DRBG_TDES:
        case ACVP_DRBG_SHA_1:
        case ACVP_DRBG_SHA_224:
        case ACVP_DRBG_SHA_256:
        case ACVP_DRBG_SHA_384:
        case ACVP_DRBG_SHA_512:
        case ACVP_DRBG_SHA_512_224:
        case ACVP_DRBG_SHA_512_256:
        default:
            printf("%s: Unsupported algorithm/mode %d/%d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
                   tc->cipher, tc->mode);
            return result;

            break;
        }
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
        printf("%s: Unsupported algorithm %d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
               tc->cipher);
        return result;

        break;
    }

    DRBG_CTX *drbg_ctx = NULL;
    DRBG_TEST_ENT entropy_nonce;
    memzero_s(&entropy_nonce, sizeof(DRBG_TEST_ENT));
    drbg_ctx = FIPS_drbg_new(nid, der_func | DRBG_FLAG_TEST);
    if (!drbg_ctx) {
        printf("ERROR: failed to create DRBG Context.\n");
        return result;
    }

    /*
     * Set entropy and nonce
     */
    entropy_nonce.ent = tc->entropy;
    entropy_nonce.entlen = drbg_entropy_len;

    entropy_nonce.nonce = nonce;
    entropy_nonce.noncelen = tc->nonce_len;

    FIPS_drbg_set_app_data(drbg_ctx, &entropy_nonce);

    fips_rc = FIPS_drbg_set_callbacks(drbg_ctx,
                                      drbg_test_entropy,
                                      0, 0,
                                      drbg_test_nonce,
                                      0);
    if (!fips_rc) {
        printf("ERROR: failed to Set callback DRBG ctx\n");
        long l = 9;
        char buf[2048]  = { 0 };
        while ((l = ERR_get_error())) {
            printf("ERROR:%s\n", ERR_error_string(l, buf));
        }
        goto end;
    }

    fips_rc = FIPS_drbg_instantiate(drbg_ctx, (const unsigned char *)tc->perso_string,
                                    (size_t)tc->perso_string_len);
    if (!fips_rc) {
        printf("ERROR: failed to instantiate DRBG ctx\n");
        long l = 9;
        char buf[2048]  = { 0 };
        while ((l = ERR_get_error())) {
            printf("ERROR:%s\n", ERR_error_string(l, buf));
        }
        goto end;
    }

    /*
     * Process predictive resistance flag
     */
    if (!tc->pred_resist_enabled && tc->reseed) {

        entropy_nonce.ent = tc->entropy_input_pr_0;
        entropy_nonce.entlen = drbg_entropy_len;

        fips_rc =  FIPS_drbg_reseed(drbg_ctx, (const unsigned char *)tc->additional_input_0,
                                      (size_t)(tc->additional_input_len));
        if (!fips_rc) {
            printf("ERROR: failed to generate drbg reseed\n");
            long l;
            while ((l = ERR_get_error())) {
                printf("ERROR:%s\n", ERR_error_string(l, NULL));
            }
            goto end;
        }
    }

    entropy_nonce.ent = tc->entropy_input_pr_1;
    entropy_nonce.entlen = tc->pr1_len;

    fips_rc =  FIPS_drbg_generate(drbg_ctx, (unsigned char *)tc->drb,
                                  (size_t)(tc->drb_len),
                                  (int)tc->pred_resist_enabled,
                                  (const unsigned char *)tc->additional_input_1,
                                  (size_t)(tc->additional_input_len));
    if (!fips_rc) {
        printf("ERROR: failed to generate drbg gen1\n");
        long l;
        while ((l = ERR_get_error())) {
            printf("ERROR:%s\n", ERR_error_string(l, NULL));
        }
        goto end;
    }

    entropy_nonce.ent = tc->entropy_input_pr_2;
    entropy_nonce.entlen = tc->pr2_len;

    fips_rc =  FIPS_drbg_generate(drbg_ctx, (unsigned char *)tc->drb,
                                  (size_t)(tc->drb_len),
                                  (int)tc->pred_resist_enabled,
                                  (const unsigned char *)tc->additional_input_2,
                                  (size_t)(tc->additional_input_len));
    if (!fips_rc) {
        printf("ERROR: failed to generate drbg gen2\n");
        long l;
        while ((l = ERR_get_error())) {
            printf("ERROR:%s\n", ERR_error_string(l, NULL));
        }
        goto end;
    }

    result = 0;

end:
    FIPS_drbg_uninstantiate(drbg_ctx);
    FIPS_drbg_free(drbg_ctx);

    return result;
}
#else
int app_drbg_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

#endif // ACVP_NO_RUNTIME

