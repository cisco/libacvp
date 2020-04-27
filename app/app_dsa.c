/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */



#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>

#include "app_lcl.h"
#include "safe_lib.h"
#ifdef ACVP_NO_RUNTIME
#include "app_fips_lcl.h" /* All regular OpenSSL headers must come before here */
#ifndef OPENSSL_NO_DSA

static DSA *group_dsa = NULL;
static BIGNUM *group_p = NULL;
static BIGNUM *group_q = NULL;
static BIGNUM *group_g = NULL;
static BIGNUM *group_pub_key = NULL;
static int dsa_current_keygen_tg = 0;
static int dsa_current_siggen_tg = 0;

void app_dsa_cleanup(void) {
    if (group_dsa) FIPS_dsa_free(group_dsa);
    group_dsa = NULL;
    if (group_p) BN_free(group_p);
    group_p = NULL;
    if (group_q) BN_free(group_q);
    group_q = NULL;
    if (group_g) BN_free(group_g);
    group_g = NULL;
    if (group_pub_key) BN_free(group_pub_key);
    group_pub_key = NULL;
}

int app_dsa_handler(ACVP_TEST_CASE *test_case) {
    int L, N, n, r;
    const EVP_MD        *md = NULL;
    ACVP_DSA_TC         *tc;
    unsigned char seed[1024];
    DSA                 *dsa = NULL;
    int counter, counter2;
    unsigned long h, h2;
    DSA_SIG             *sig = NULL;
    BIGNUM              *q = NULL, *p = NULL, *g = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    BIGNUM              *tmp_q = NULL, *tmp_p = NULL, *tmp_g = NULL;
    const BIGNUM              *tmp_q1 = NULL, *tmp_p1 = NULL, *tmp_g1 = NULL;
    const BIGNUM              *tmp_q2 = NULL, *tmp_p2 = NULL, *tmp_g2 = NULL;
    const BIGNUM *tmp_r = NULL, *tmp_s = NULL;
    const BIGNUM *tmp_priv_key = NULL, *tmp_pub_key = NULL;
    const BIGNUM              *q1 = NULL, *p1 = NULL;
#endif
    BIGNUM              *q2 = NULL, *p2 = NULL, *g2 = NULL;
    BIGNUM *priv_key = NULL, *pub_key = NULL;
    BIGNUM *sig_r = NULL, *sig_s = NULL;

    tc = test_case->tc.dsa;
    switch (tc->mode) {
    case ACVP_DSA_MODE_KEYGEN:
        if (dsa_current_keygen_tg != tc->tg_id) {
            dsa_current_keygen_tg = tc->tg_id;

            /* Free the global "group" variables before re-allocating */
            app_dsa_cleanup();

            group_dsa = FIPS_dsa_new();
            if (!group_dsa) {
                printf("Failed to allocate DSA strcut\n");
                return 1;
            }
            L = tc->l;
            N = tc->n;

            if (dsa_builtin_paramgen2(group_dsa, L, N, md, NULL, 0, -1,
                                      NULL, NULL, NULL, NULL) <= 0) {
                printf("Parameter Generation error\n");
                return 1;
            }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            group_p = BN_dup(group_dsa->p);
            group_q = BN_dup(group_dsa->q);
            group_g = BN_dup(group_dsa->g);
#else
            DSA_get0_pqg(group_dsa, &tmp_p1,
                         &tmp_q1, &tmp_g1);
            group_p = BN_dup(tmp_p1);
            group_q = BN_dup(tmp_q1);
            group_g = BN_dup(tmp_g1);
#endif
        }

        tc->p_len = BN_bn2bin(group_p, tc->p);
        tc->q_len = BN_bn2bin(group_q, tc->q);
        tc->g_len = BN_bn2bin(group_g, tc->g);

        if (!DSA_generate_key(group_dsa)) {
            printf("\n DSA_generate_key failed");
            return 1;
        }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        priv_key = group_dsa->priv_key;
        pub_key = group_dsa->pub_key;
#else
        DSA_get0_key(group_dsa, &tmp_pub_key, &tmp_priv_key);
        pub_key = BN_dup(tmp_pub_key);
        priv_key = BN_dup(tmp_priv_key);
#endif

        tc->x_len = BN_bn2bin(priv_key, tc->x);
        tc->y_len = BN_bn2bin(pub_key, tc->y);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        if (tmp_pub_key && tmp_priv_key) {
            FIPS_bn_free(pub_key);
            FIPS_bn_free(priv_key);
        }
#endif
        break;

    case ACVP_DSA_MODE_PQGVER:
        switch (tc->sha) {
        case ACVP_SHA1:
            md = EVP_sha1();
            break;
        case ACVP_SHA224:
            md = EVP_sha224();
            break;
        case ACVP_SHA256:
            md = EVP_sha256();
            break;
        case ACVP_SHA384:
            md = EVP_sha384();
            break;
        case ACVP_SHA512:
            md = EVP_sha512();
            break;
#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
        case ACVP_SHA512_224:
            md = EVP_sha512_224();
            break;
        case ACVP_SHA512_256:
            md = EVP_sha512_256();
            break;
#else
        case ACVP_SHA512_224:
        case ACVP_SHA512_256:
#endif
        case ACVP_HASH_ALG_MAX:
        default:
            printf("DSA sha value not supported %d\n", tc->sha);
            return 1;

            break;
        }

        switch (tc->pqg) {
        case ACVP_DSA_PROBABLE:
            dsa = FIPS_dsa_new();
            if (!dsa) {
                printf("Failed to allocate DSA strcut\n");
                return 1;
            }
            L = tc->l;
            N = tc->n;

            p = FIPS_bn_new();
            q = FIPS_bn_new();
            BN_bin2bn(tc->p, tc->p_len, p);
            BN_bin2bn(tc->q, tc->q_len, q);

            if (dsa_builtin_paramgen2(dsa, L, N, md,
                                      tc->seed, tc->seedlen, -1, NULL,
                                      &counter2, &h2, NULL) < 0) {
                printf("Parameter Generation error\n");
                FIPS_dsa_free(dsa);
                return 1;
            }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            p2 = BN_dup(dsa->p);
            q2 = BN_dup(dsa->q);
#else
            DSA_get0_pqg(dsa, &tmp_p2, &tmp_q2, NULL);
            p2 = BN_dup(tmp_p2);
            q2 = BN_dup(tmp_q2);
#endif

            if (BN_cmp(p2, p) || BN_cmp(q2, q))
                r = 0;
            else
                r = 1;

            FIPS_bn_free(p);              
            FIPS_bn_free(q);              
            FIPS_bn_free(p2);              
            FIPS_bn_free(q2);              
            FIPS_dsa_free(dsa);
            tc->result = r;
            break;

        case ACVP_DSA_CANONICAL:
            dsa = FIPS_dsa_new();
            if (!dsa) {
                printf("Failed to allocate DSA strcut\n");
                return 1;
            }
            L = tc->l;
            N = tc->n;

            p = FIPS_bn_new();
            q = FIPS_bn_new();
            g = FIPS_bn_new();
            BN_bin2bn(tc->p, tc->p_len, p);
            BN_bin2bn(tc->q, tc->q_len, q);
            BN_bin2bn(tc->g, tc->g_len, g);

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            dsa->p = BN_dup(p);
            dsa->q = BN_dup(q);
#else
            DSA_set0_pqg(dsa, BN_dup(p), BN_dup(q), BN_dup(g));
#endif

            if (dsa_builtin_paramgen2(dsa, L, N, md,
                                      tc->seed, tc->seedlen, tc->index, NULL,
                                      &counter2, &h2, NULL) < 0) {
                printf("Parameter Generation error\n");
                FIPS_dsa_free(dsa);
                return 1;
            }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            g2 = BN_dup(dsa->g);
#else
            DSA_get0_pqg(dsa, NULL, NULL, &tmp_g2);
            g2 = BN_dup(tmp_g2);
#endif

            if (BN_cmp(g2, g)) {
                r = 0;
            } else {
                r = 1;
            }

            FIPS_bn_free(p);
            FIPS_bn_free(q);
            FIPS_bn_free(g);
            FIPS_bn_free(g2);
            FIPS_dsa_free(dsa);
            tc->result = r;
            break;
        default:
            printf("DSA pqg mode not supported %d\n", tc->pqg);
            return 1;

            break;
        }
        break;

    case ACVP_DSA_MODE_SIGVER:
        switch (tc->sha) {
        case ACVP_SHA1:
            md = EVP_sha1();
            break;
        case ACVP_SHA224:
            md = EVP_sha224();
            break;
        case ACVP_SHA256:
            md = EVP_sha256();
            break;
        case ACVP_SHA384:
            md = EVP_sha384();
            break;
        case ACVP_SHA512:
            md = EVP_sha512();
            break;
#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
        case ACVP_SHA512_224:
            md = EVP_sha512_224();
            break;
        case ACVP_SHA512_256:
            md = EVP_sha512_256();
            break;
#else
        case ACVP_SHA512_224:
        case ACVP_SHA512_256:
#endif
        case ACVP_HASH_ALG_MAX:
        default:
            printf("DSA sha value not supported %d\n", tc->sha);
            return 1;

            break;
        }

        dsa = FIPS_dsa_new();
        if (!dsa) {
            printf("Failed to allocate DSA strcut\n");
            return 1;
        }
        sig = FIPS_dsa_sig_new();
        if (!sig) {
            printf("Failed to allocate SIG strcut\n");
            FIPS_dsa_free(dsa);
            return 1;
        }
        L = tc->l;
        N = tc->n;

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        dsa->p = BN_new();
        dsa->q = BN_new();
        dsa->g = BN_new();
        dsa->pub_key = BN_new();
        sig->r = BN_new();
        sig->s = BN_new();
        BN_bin2bn(tc->p, tc->p_len, dsa->p);
        BN_bin2bn(tc->q, tc->q_len, dsa->q);
        BN_bin2bn(tc->g, tc->g_len, dsa->g);
        BN_bin2bn(tc->y, tc->y_len, dsa->pub_key);
        BN_bin2bn(tc->r, tc->r_len, sig->r);
        BN_bin2bn(tc->s, tc->s_len, sig->s);
#else
        p = BN_new();
        q = BN_new();
        g = BN_new();
        pub_key = BN_new();
        sig_r = BN_new();
        sig_s = BN_new();

        BN_bin2bn(tc->p, tc->p_len, p);
        BN_bin2bn(tc->q, tc->q_len, q);
        BN_bin2bn(tc->g, tc->g_len, g);
        BN_bin2bn(tc->y, tc->y_len, pub_key);
        BN_bin2bn(tc->r, tc->r_len, sig_r);
        BN_bin2bn(tc->s, tc->s_len, sig_s);

        DSA_set0_pqg(dsa, p, q, g);
        DSA_set0_key(dsa, pub_key, NULL);
        DSA_SIG_set0(sig, sig_r, sig_s);


#endif

        n = tc->msglen;
        r = FIPS_dsa_verify(dsa, (const unsigned char *)tc->msg, n, md, sig);

        FIPS_dsa_free(dsa);
        FIPS_dsa_sig_free(sig);
        /* return result, 0 is failure, 1 is pass */
        tc->result = r;
        break;

    case ACVP_DSA_MODE_SIGGEN:
        switch (tc->sha) {
        case ACVP_SHA1:
            md = EVP_sha1();
            break;
        case ACVP_SHA224:
            md = EVP_sha224();
            break;
        case ACVP_SHA256:
            md = EVP_sha256();
            break;
        case ACVP_SHA384:
            md = EVP_sha384();
            break;
        case ACVP_SHA512:
            md = EVP_sha512();
            break;
#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
        case ACVP_SHA512_224:
            md = EVP_sha512_224();
            break;
        case ACVP_SHA512_256:
            md = EVP_sha512_256();
            break;
#else
        case ACVP_SHA512_224:
        case ACVP_SHA512_256:
#endif
        case ACVP_HASH_ALG_MAX:
        default:
            printf("DSA sha value not supported %d\n", tc->sha);
            return 1;

            break;
        }

        if (dsa_current_siggen_tg != tc->tg_id) {
            dsa_current_siggen_tg = tc->tg_id;

            /* Free the global "group" variables before re-allocating */
            app_dsa_cleanup(); 

            group_dsa = FIPS_dsa_new();
            if (!group_dsa) {
                printf("Failed to allocate DSA strcut\n");
                return 1;
            }
            L = tc->l;
            N = tc->n;

            if (dsa_builtin_paramgen2(group_dsa, L, N, md, NULL, 0, -1,
                                      NULL, NULL, NULL, NULL) <= 0) {
                printf("Parameter Generation error\n");
                return 1;
            }

            if (!DSA_generate_key(group_dsa)) {
                printf("\n DSA_generate_key failed");
                return 1;
            }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            group_p = BN_dup(group_dsa->p);
            group_q = BN_dup(group_dsa->q);
            group_g = BN_dup(group_dsa->g);
#else
            DSA_get0_pqg(group_dsa, &tmp_p1, &tmp_q1, &tmp_g1);
            group_p = BN_dup(tmp_p1);
            group_q = BN_dup(tmp_q1);
            group_g = BN_dup(tmp_g1);
#endif

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            group_pub_key = BN_dup(group_dsa->pub_key);
#else
            DSA_get0_key(group_dsa, &tmp_pub_key, NULL);
            group_pub_key = BN_dup(tmp_pub_key);
#endif
        }

        tc->p_len = BN_bn2bin(group_p, tc->p);
        tc->q_len = BN_bn2bin(group_q, tc->q);
        tc->g_len = BN_bn2bin(group_g, tc->g);
        tc->y_len = BN_bn2bin(group_pub_key, tc->y);

        sig = FIPS_dsa_sign(group_dsa, tc->msg, tc->msglen, md);

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        sig_r = sig->r;
        sig_s = sig->s;
#else
        DSA_SIG_get0(sig, &tmp_r, &tmp_s);
        sig_r = BN_dup(tmp_r);
        sig_s = BN_dup(tmp_s);
#endif

        tc->r_len = BN_bn2bin(sig_r, tc->r);
        tc->s_len = BN_bn2bin(sig_s, tc->s);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        if (tmp_r && tmp_s) {
            FIPS_bn_free(sig_r);
            FIPS_bn_free(sig_s);
        }
#endif
        FIPS_dsa_sig_free(sig);
        break;

    case ACVP_DSA_MODE_PQGGEN:
        switch (tc->sha) {
        case ACVP_SHA1:
            md = EVP_sha1();
            break;
        case ACVP_SHA224:
            md = EVP_sha224();
            break;
        case ACVP_SHA256:
            md = EVP_sha256();
            break;
        case ACVP_SHA384:
            md = EVP_sha384();
            break;
        case ACVP_SHA512:
            md = EVP_sha512();
            break;
#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
        case ACVP_SHA512_224:
            md = EVP_sha512_224();
            break;
        case ACVP_SHA512_256:
            md = EVP_sha512_256();
            break;
#else
        case ACVP_SHA512_224:
        case ACVP_SHA512_256:
#endif
        case ACVP_HASH_ALG_MAX:
        default:
            printf("DSA sha value not supported %d\n", tc->sha);
            return 1;

            break;
        }

        switch (tc->gen_pq) {
        case ACVP_DSA_UNVERIFIABLE:
            printf("DSA Parameter Generation2 error for %d, not supported\n", tc->gen_pq);
            return 1;

            break;
        case ACVP_DSA_CANONICAL:
            dsa = FIPS_dsa_new();

            p = FIPS_bn_new();
            q = FIPS_bn_new();
            g = FIPS_bn_new();
            BN_bin2bn(tc->p, tc->p_len, p);
            BN_bin2bn(tc->q, tc->q_len, q);

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            dsa->p = BN_dup(p);
            dsa->q = BN_dup(q);
#else
            tmp_p = BN_dup(p);
            tmp_q = BN_dup(q);
            tmp_g = BN_dup(g);
            DSA_set0_pqg(dsa, tmp_p, tmp_q, tmp_g);
#endif
            L = tc->l;
            N = tc->n;
            if (dsa_builtin_paramgen2(dsa, L, N, md,
                                      tc->seed, tc->seedlen, tc->index, NULL,
                                      NULL, NULL, NULL) <= 0) {
                printf("DSA Parameter Generation2 error for %d\n", tc->gen_pq);
                FIPS_dsa_free(dsa);
                return 1;
            }
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            tc->g_len = BN_bn2bin(dsa->g, tc->g);
#else
            DSA_get0_pqg(dsa, NULL, NULL, &tmp_g1);
            tc->g_len = BN_bn2bin(tmp_g1, tc->g);
#endif
            FIPS_bn_free(p);
            FIPS_bn_free(q);
            FIPS_bn_free(g);
            FIPS_dsa_free(dsa);
            break;

        case ACVP_DSA_PROBABLE:
        case ACVP_DSA_PROVABLE:
            dsa = FIPS_dsa_new();
            L = tc->l;
            N = tc->n;
            if (dsa_builtin_paramgen2(dsa, L, N, md,
                                      NULL, 0, -1, seed,
                                      &counter, &h, NULL) <= 0) {
                printf("DSA Parameter Generation 2 error for %d\n", tc->gen_pq);
                FIPS_dsa_free(dsa);
                return 1;
            }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            p = dsa->p;
            q = dsa->q;
            tc->p_len = BN_bn2bin(p, tc->p);
            tc->q_len = BN_bn2bin(q, tc->q);
#else
            DSA_get0_pqg(dsa, &p1, &q1, NULL);
            tc->p_len = BN_bn2bin(p1, tc->p);
            tc->q_len = BN_bn2bin(q1, tc->q);
#endif

            tc->counter = counter;
            tc->h = h;

#define DSA_MAX_SEED 3072
            memcpy_s(tc->seed, DSA_MAX_SEED, &seed, EVP_MD_size(md));
            tc->seedlen = EVP_MD_size(md);
            tc->counter = counter;
            FIPS_dsa_free(dsa);
            break;
        default:
            printf("Invalid DSA gen_pq %d\n", tc->gen_pq);
            return 1;

            break;
        }
        break;
    default:
        printf("Invalid DSA mode %d\n", tc->mode);
        return 1;

        break;
    }
    return 0;
}
#endif // OPENSSL_NO_DSA

#else
int app_dsa_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}
#endif // ACVP_NO_RUNTIME

