/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#ifdef ACVP_NO_RUNTIME

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include "app_fips_lcl.h" /* All regular OpenSSL headers must come before here */
#include <openssl/fips.h>
#include "app_lcl.h"

BIGNUM *group_n = NULL;
RSA *group_rsa = NULL;
int rsa_current_tg = 0;

void app_rsa_cleanup(void) {
    if (group_rsa) RSA_free(group_rsa);
    group_rsa = NULL;
    if (group_n) BN_free(group_n);
    group_n = NULL;
}

int app_rsa_keygen_handler(ACVP_TEST_CASE *test_case) {
    /*
     * custom crypto module handler
     * to be filled in -
     * this handler assumes info gen by server
     * and all the other params registered for
     * in this example app.
     */

    ACVP_RSA_KEYGEN_TC *tc = NULL;
    int rv = 1;
    RSA *rsa = NULL;
    BIGNUM *p = NULL, *q = NULL, *n = NULL, *d = NULL;
    BIGNUM *e = NULL;

    if (!test_case) {
        printf("Missing test_case\n");
        return 1;
    }
    tc = test_case->tc.rsa_keygen;

    rsa = FIPS_rsa_new();
    if (!rsa) {
        printf("Rsa_new failure\n");
        return 1;
    }

    e = FIPS_bn_new();
    if (!e) {
        printf("Failed to allocate BN for e\n");
        goto err;
    }
    BN_bin2bn(tc->e, tc->e_len, e);
    if (!tc->e_len) {
        printf("Error converting e to BN\n");
        goto err;
    }

    /*
     * IMPORTANT: Placeholder! The RSA keygen vector
     * sets will fail if this handler is left as is.
     *
     * Below, insert your own key generation API that
     * supports specification of all of the params...
     */
    if (!FIPS_rsa_x931_generate_key_ex(rsa, tc->modulo, e, NULL)) {
        printf("\nError: Issue with key generation\n");
        goto err;
    }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L /* OpenSSL 1.1.0 or less */
    p = rsa->p;
    q = rsa->q;
    n = rsa->n;
    d = rsa->d;
#else
    RSA_get0_key(rsa, (const BIGNUM **)&n, NULL,
                 (const BIGNUM **)&d);
    RSA_get0_factors(rsa, (const BIGNUM **)&p,
                     (const BIGNUM **)&q);
#endif

    tc->p_len = BN_bn2bin(p, tc->p);
    tc->q_len = BN_bn2bin(q, tc->q);
    tc->n_len = BN_bn2bin(n, tc->n);
    tc->d_len = BN_bn2bin(d, tc->d);

    rv = 0;
err:
    if (rsa) FIPS_rsa_free(rsa);
    if (e) BN_free(e);
    return rv;
}

int app_rsa_sig_handler(ACVP_TEST_CASE *test_case) {
    EVP_MD *tc_md = NULL;
    int siglen, pad_mode;
    BIGNUM *bn_e = NULL, *e = NULL, *n = NULL;
    ACVP_RSA_SIG_TC    *tc;
    RSA *rsa = NULL;
    int salt_len = -1;

    int rv = 1;

    if (!test_case) {
        printf("\nError: test case not found in RSA SigGen handler\n");
        goto err;
    }

    tc = test_case->tc.rsa_sig;

    if (!tc) {
        printf("\nError: test case not found in RSA SigGen handler\n");
        goto err;
    }

    /*
     * Make an RSA object and set a new BN exponent to use to generate a key
     */

    rsa = FIPS_rsa_new();
    if (!rsa) {
        printf("\nError: Issue with RSA obj in RSA Sig\n");
        goto err;
    }

    bn_e = BN_new();
    if (!bn_e || !BN_set_word(bn_e, 0x1001)) {
        printf("\nError: Issue with exponent in RSA Sig\n");
        goto err;
    }

    if (!tc->modulo) {
        printf("\nError: Issue with modulo in RSA Sig\n");
        goto err;
    }

    /*
     * Set the pad mode and generate a key given the respective sigType
     */
    switch (tc->sig_type) {
    case ACVP_RSA_SIG_TYPE_X931:
        pad_mode = RSA_X931_PADDING;
        salt_len = -2;
        break;
    case ACVP_RSA_SIG_TYPE_PKCS1PSS:
        pad_mode = RSA_PKCS1_PSS_PADDING;
        salt_len = tc->salt_len;
        break;
    case ACVP_RSA_SIG_TYPE_PKCS1V15:
        pad_mode = RSA_PKCS1_PADDING;
        break;
    default:
        printf("\nError: sigType not supported\n");
        rv = ACVP_INVALID_ARG;
        goto err;
    }

    /*
     * Set the message digest to the appropriate sha
     */
    switch (tc->hash_alg) {
    case ACVP_SHA1:
        tc_md = (EVP_MD *)EVP_sha1();
        break;
    case ACVP_SHA224:
        tc_md = (EVP_MD *)EVP_sha224();
        break;
    case ACVP_SHA256:
        tc_md = (EVP_MD *)EVP_sha256();
        break;
    case ACVP_SHA384:
        tc_md = (EVP_MD *)EVP_sha384();
        break;
    case ACVP_SHA512:
        tc_md = (EVP_MD *)EVP_sha512();
        break;
    case ACVP_SHA512_224:
        tc_md = (EVP_MD *)EVP_sha512_224();
        break;
    case ACVP_SHA512_256:
        tc_md = (EVP_MD *)EVP_sha512_256();
        break;
    default:
        printf("\nError: hashAlg not supported for RSA SigGen\n");
        goto err;
    }

    /*
     * If we are verifying, set RSA to the given public key
     * Else, generate a new key, retrieve and save values
     */
    if (tc->sig_mode == ACVP_RSA_SIGVER) {
        e = BN_new();
        if (!e) {
            printf("\nBN alloc failure (e)\n");
            goto err;
        }
        BN_bin2bn(tc->e, tc->e_len, e);

        n = BN_new();
        if (!n) {
            printf("\nBN alloc failure (n)\n");
            goto err;
        }
        BN_bin2bn(tc->n, tc->n_len, n);

#if OPENSSL_VERSION_NUMBER <= 0x10100000L /* OpenSSL 1.1.0 or less */
        rsa->e = BN_dup(e);
        rsa->n = BN_dup(n);
#else
        RSA_set0_key(rsa, n, e, NULL);
#endif

        tc->ver_disposition = FIPS_rsa_verify(rsa, tc->msg, tc->msg_len, tc_md, pad_mode, salt_len, NULL, tc->signature, tc->sig_len);
    } else {
        if (rsa_current_tg != tc->tg_id) {
            rsa_current_tg = tc->tg_id;

            /* Free the group objects before re-allocation */
            if (group_rsa) RSA_free(group_rsa);
            group_rsa = NULL;
            if (group_n) BN_free(group_n);
            group_n = NULL;

            group_rsa = RSA_new();

            if (!FIPS_rsa_x931_generate_key_ex(group_rsa, tc->modulo, bn_e, NULL)) {
                printf("\nError: Issue with keygen during siggen handling\n");
                goto err;
            }
#if OPENSSL_VERSION_NUMBER <= 0x10100000L /* OpenSSL 1.1.0 or less */
            e = BN_dup(group_rsa->e);
            n = BN_dup(group_rsa->n);
#else
            RSA_get0_key(group_rsa, (const BIGNUM **)&n, (const BIGNUM **)&e, NULL);
#endif
            group_n = BN_dup(n);
        } else {
            e = BN_dup(bn_e);
            n = BN_dup(group_n);
        }
        tc->e_len = BN_bn2bin(e, tc->e);
        tc->n_len = BN_bn2bin(n, tc->n);

        if (tc->msg && tc_md) {
            siglen = RSA_size(group_rsa);

            if (!FIPS_rsa_sign(group_rsa, tc->msg, tc->msg_len, tc_md, pad_mode, salt_len, NULL,
                               tc->signature, (unsigned int *)&siglen)) {
                printf("\nError: RSA Signature Generation fail\n");
                goto err;
            }

            tc->sig_len = siglen;
        }
    }

    /* Success */
    rv = 0;

err:
    if (bn_e) BN_free(bn_e);
    if (rsa) FIPS_rsa_free(rsa);
    if (e) BN_free(e);
    if (n) BN_free(n);

    return rv;
}

#endif // ACVP_NO_RUNTIME
