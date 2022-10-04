/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */



#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#endif

#include "app_lcl.h"
#include "safe_lib.h"

#if defined ACVP_NO_RUNTIME
#include "app_fips_lcl.h" /* All regular OpenSSL headers must come before here */
#endif

#ifndef OPENSSL_NO_DSA

#define DSA_MAX_SEED 1024

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/* Re-use these when possible to speed up test cases */
static EVP_PKEY_CTX *group_param_ctx = NULL;
static EVP_PKEY_CTX *group_pctx = NULL;
static EVP_PKEY *group_param_key = NULL;
static EVP_PKEY *group_pkey = NULL;
#elif defined ACVP_NO_RUNTIME
static DSA *group_dsa = NULL;
static BIGNUM *group_p = NULL;
static BIGNUM *group_q = NULL;
static BIGNUM *group_g = NULL;
static BIGNUM *group_pub_key = NULL;
#endif
static int dsa_current_siggen_tg = 0;
static int dsa_current_keygen_tg = 0;

void app_dsa_cleanup(void) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (group_param_ctx) EVP_PKEY_CTX_free(group_param_ctx);
    group_param_ctx = NULL;
    if (group_pctx) EVP_PKEY_CTX_free(group_pctx);
    group_pctx = NULL;
    if (group_param_key) EVP_PKEY_free(group_param_key);
    group_param_key = NULL;
    if (group_pkey) EVP_PKEY_free(group_pkey);
    group_pkey = NULL;
#elif defined ACVP_NO_RUNTIME
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
#endif
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

static int init_group_pkey_paramgen(int l, int n) {
    int rv = 1;
    group_param_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
    if (!group_param_ctx) {
        printf("Error initializing param CTX in DSA keygen\n");
        goto err;
    }
    if (EVP_PKEY_paramgen_init(group_param_ctx) != 1) {
        printf("Error initializing param CTX in DSA keygen\n");
        goto err;
    }

    if (EVP_PKEY_CTX_set_dsa_paramgen_bits(group_param_ctx, l) != 1 ||
            EVP_PKEY_CTX_set_dsa_paramgen_q_bits(group_param_ctx, n) != 1) {
        printf("Error setting keygen params in DSA\n");
        goto err;
    }
    if (EVP_PKEY_paramgen(group_param_ctx, &group_param_key) != 1) {
        printf("Error generating param key in DSA keygen\n");
        goto err;
    }
    group_pctx = EVP_PKEY_CTX_new_from_pkey(NULL, group_param_key, NULL);
    if (!group_pctx) {
        printf("Error creating group_pkey CTX in DSA keygen\n");
        goto err;
    }
    if (EVP_PKEY_keygen_init(group_pctx) != 1) {
        printf("Error initializing keygen in DSA keygen\n");
        goto err;
    }
    rv = 0;
err:
    return rv;
}

int app_dsa_handler(ACVP_TEST_CASE *test_case) {
    size_t seed_len = 0, sig_len = 0;
    const char *md = NULL;
    unsigned char *sig = NULL, *sig_iter = NULL;
    ACVP_DSA_TC *tc;
    BIGNUM *x = NULL, *y = NULL;
    BIGNUM *q = NULL, *p = NULL, *g = NULL, *r = NULL, *s = NULL, *pub_key = NULL;
    const BIGNUM *tmp_r = NULL, *tmp_s = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *param_ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *param_key = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *sig_ctx = NULL;
    DSA_SIG *sig_obj = NULL;

    tc = test_case->tc.dsa;
    switch (tc->mode) {
    case ACVP_DSA_MODE_KEYGEN:
        if (dsa_current_keygen_tg != tc->tg_id) {
            dsa_current_keygen_tg = tc->tg_id;
            app_dsa_cleanup();
            if (init_group_pkey_paramgen(tc->l, tc->n)) {
                printf("Error initiating group params in DSA keygen\n");
                goto err;
            }
        }

        if (EVP_PKEY_keygen(group_pctx, &pkey) != 1) {
            printf("Error generating group_pkey in DSA keygen\n");
            goto err;
        }

        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p) == 1) {
            tc->p_len = BN_bn2bin(p, tc->p);
        } else {
            printf("Error getting 'p' in DSA keygen\n");
            goto err;
        }
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_Q, &q) == 1) {
            tc->q_len = BN_bn2bin(q, tc->q);
        } else {
            printf("Error getting 'q' in DSA keygen\n");
            goto err;
        }
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &g) == 1) {
            tc->g_len = BN_bn2bin(g, tc->g);
        } else {
            printf("Error getting 'g' in DSA keygen\n");
            goto err;
        }
        if (EVP_PKEY_get_bn_param(pkey, "priv", &x) == 1) {
            tc->x_len = BN_bn2bin(x, tc->x);
        } else {
            printf("Error getting 'x' in DSA keygen\n");
            goto err;
        }
        if (EVP_PKEY_get_bn_param(pkey, "pub", &y) == 1) {
            tc->y_len = BN_bn2bin(y, tc->y);
        } else {
            printf("Error getting 'y' in DSA keygen\n");
            goto err;
        }
        break;
    case ACVP_DSA_MODE_PQGVER:
        md = get_md_string_for_hash_alg(tc->sha, NULL);
        if (!md) {
            printf("Invalid hash alg given for DSA pqgver\n");
            goto err;
        }

        p = BN_bin2bn(tc->p, tc->p_len, NULL);
        q = BN_bin2bn(tc->q, tc->q_len, NULL);
        g = BN_bin2bn(tc->g, tc->g_len, NULL);
        if (!p || !q || !g) {
            printf("Error converting P/Q/G to bignum in DSA pqgver\n");
            goto err;
        }

        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in DSA pqgver\n");
            goto err;
        }

        OSSL_PARAM_BLD_push_uint(pbld, OSSL_PKEY_PARAM_FFC_PBITS, tc->l);
        OSSL_PARAM_BLD_push_uint(pbld, OSSL_PKEY_PARAM_FFC_QBITS, tc->n);
        OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_FFC_P, p);
        OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_FFC_Q, q);
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_PKEY_PARAM_FFC_SEED, tc->seed, tc->seedlen);
        OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_PKEY_PARAM_FFC_DIGEST, md, 0);

        switch (tc->pqg) {
        case ACVP_DSA_PROBABLE:
            OSSL_PARAM_BLD_push_int(pbld, OSSL_PKEY_PARAM_FFC_VALIDATE_G, 0);
            OSSL_PARAM_BLD_push_int(pbld, OSSL_PKEY_PARAM_FFC_PCOUNTER, tc->c);
            break;
        case ACVP_DSA_CANONICAL:
            OSSL_PARAM_BLD_push_int(pbld, OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, 0);
            OSSL_PARAM_BLD_push_int(pbld, OSSL_PKEY_PARAM_FFC_GINDEX, tc->index);
            OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_FFC_G, g);
            break;
        case ACVP_DSA_UNVERIFIABLE:
            OSSL_PARAM_BLD_push_int(pbld, OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, 0);
            OSSL_PARAM_BLD_push_int(pbld, OSSL_PKEY_PARAM_FFC_H, tc->h);
            OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_FFC_G, g);
            break;
        case ACVP_DSA_PROVABLE:
        default:
            printf("Unsupported pqg mode for DSA pqgver\n");
            goto err;
        }

        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in DSA pqgver\n");
            goto err;
        }
        param_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
        if (!param_ctx) {
            printf("Error creating param CTX in DSA pqgver\n");
            goto err;
        }
        if (EVP_PKEY_fromdata_init(param_ctx) != 1) {
            printf("Error initializing parameter fromdata in DSA pqgver\n");
            goto err;
        }
        if (EVP_PKEY_fromdata(param_ctx, &param_key, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            printf("Error generating parameter pkey in DSA pqgver\n");
            goto err;
        }
        pctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
        if (!pctx) {
            printf("Error creating pkey CTX in DSA pqgver\n");
            goto err;
        }
        if (EVP_PKEY_param_check(pctx) == 1) {
            tc->result = 1;
        } else {
            tc->result = 0;
        }
        break;
    case ACVP_DSA_MODE_SIGVER:
        md = get_md_string_for_hash_alg(tc->sha, NULL);
        if (!md) {
            printf("Invalid hash alg given for DSA siggen\n");
            goto err;
        }

        p = BN_bin2bn(tc->p, tc->p_len, NULL);
        q = BN_bin2bn(tc->q, tc->q_len, NULL);
        g = BN_bin2bn(tc->g, tc->g_len, NULL);
        pub_key = BN_bin2bn(tc->y, tc->y_len, NULL);
        if (!p || !q || !g || !pub_key) {
            printf("Error converting P/Q/G/Y to bignum in DSA sigver\n");
            goto err;
        }

        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in DSA sigver\n");
            goto err;
        }
        OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_FFC_P, p);
        OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_FFC_Q, q);
        OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_FFC_G, g);
        OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_PUB_KEY, pub_key);
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating pkey params in DSA sigver\n");
            goto err;
        }

        pctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
        if (!pctx) {
            printf("Error creating CTX in DSA sigver\n");
            goto err;
        }
        if (EVP_PKEY_fromdata_init(pctx) != 1) {
            printf("Error initializing fromdata in DSA sigver\n");
            goto err;
        }
        if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            printf("Error performing fromdata in DSA sigver\n");
            goto err;
        }

        r = BN_bin2bn(tc->r, tc->r_len, NULL);
        s = BN_bin2bn(tc->s, tc->s_len, NULL);
        if (!r || !s) {
            printf("Error importing R or S in DSA sigver\n");
            goto err;
        }
        sig_obj = DSA_SIG_new();
        if (!sig_obj) {
            printf("Error creating signature object in DSA sigver\n");
            goto err;
        }
        if (DSA_SIG_set0(sig_obj, r, s) != 1) {
            printf("Error setting R and S values in DSA sigver\n");
            goto err;
        }
        sig_len = (size_t)i2d_DSA_SIG(sig_obj, &sig);

        sig_ctx = EVP_MD_CTX_new();
        if (!sig_ctx) {
            printf("Error initializing sig CTX for DSA sigver\n");
            goto err;
        }

        if (EVP_DigestVerifyInit_ex(sig_ctx, NULL, md, NULL, NULL, pkey, NULL) != 1) {
            printf("Error initializing verify for DSA sigver\n");
            goto err;
        }
        if (EVP_DigestVerify(sig_ctx, sig, sig_len, tc->msg, tc->msglen) == 1) {
            tc->result = 1;
        }
        break;
    case ACVP_DSA_MODE_SIGGEN:
        if (dsa_current_siggen_tg != tc->tg_id) {
            dsa_current_siggen_tg = tc->tg_id;
            app_dsa_cleanup();

            if (init_group_pkey_paramgen(tc->l, tc->n)) {
                printf("Error initiating group params in DSA siggen\n");
            }
            if (EVP_PKEY_keygen(group_pctx, &group_pkey) != 1) {
                printf("Error generating group_pkey in DSA siggen\n");
                goto err;
            }
        }

        if (EVP_PKEY_get_bn_param(group_pkey, OSSL_PKEY_PARAM_FFC_P, &p) == 1) {
            tc->p_len = BN_bn2bin(p, tc->p);
        } else {
            printf("Error getting 'p' in DSA siggen\n");
            goto err;
        }
        if (EVP_PKEY_get_bn_param(group_pkey, OSSL_PKEY_PARAM_FFC_Q, &q) == 1) {
            tc->q_len = BN_bn2bin(q, tc->q);
        } else {
            printf("Error getting 'q' in DSA siggen\n");
            goto err;
        }
        if (EVP_PKEY_get_bn_param(group_pkey, OSSL_PKEY_PARAM_FFC_G, &g) == 1) {
            tc->g_len = BN_bn2bin(g, tc->g);
        } else {
            printf("Error getting 'g' in DSA siggen\n");
            goto err;
        }
        if (EVP_PKEY_get_bn_param(group_pkey, OSSL_PKEY_PARAM_PUB_KEY, &pub_key) == 1) {
            tc->y_len = BN_bn2bin(pub_key, tc->y);
        } else {
            printf("Error getting 'y' in DSA siggen\n");
            goto err;
        }

        md = get_md_string_for_hash_alg(tc->sha, NULL);
        if (!md) {
            printf("Invalid hash alg given for DSA siggen\n");
            goto err;
        }
        sig_ctx = EVP_MD_CTX_new();
        if (!sig_ctx) {
            printf("Error initializing sign CTX for DSA siggen\n");
            goto err;
        }
        if (EVP_DigestSignInit_ex(sig_ctx, NULL, md, NULL, NULL, group_pkey, NULL) != 1) {
            printf("Error initializing signing for DSA siggen\n");
            goto err;
        }
        EVP_DigestSign(sig_ctx, NULL, &sig_len, tc->msg, tc->msglen);
        sig = calloc(sig_len, sizeof(char));
        if (!sig) {
            printf("Error allocating memory in DSA siggen\n");
            goto err;
        }
        if (EVP_DigestSign(sig_ctx, sig, &sig_len, tc->msg, tc->msglen) != 1) {
            printf("Error generating signature in ECDSA siggen\n");
            goto err;
        }

        /* Need to extract R and S from signature */
        sig_iter = sig; /* d2i functions alter pointer */
        sig_obj = d2i_DSA_SIG(NULL, (const unsigned char **)&sig_iter, (long)sig_len);
        if (!sig_obj) {
            printf("Error creating signature object neeed to retrieve output in ECDSA siggen\n");
            goto err;
        }
        DSA_SIG_get0(sig_obj, &tmp_r, &tmp_s);
        tc->r_len = BN_bn2bin(tmp_r, tc->r);
        tc->s_len = BN_bn2bin(tmp_s, tc->s);
        break;
    case ACVP_DSA_MODE_PQGGEN:
        md = get_md_string_for_hash_alg(tc->sha, NULL);
        if (!md) {
            printf("Invalid hash alg given for DSA pqggen\n");
            goto err;
        }

        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in DSA pqggen\n");
            goto err;
        }

        OSSL_PARAM_BLD_push_uint(pbld, OSSL_PKEY_PARAM_FFC_PBITS, tc->l);
        OSSL_PARAM_BLD_push_uint(pbld, OSSL_PKEY_PARAM_FFC_QBITS, tc->n);
        OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_PKEY_PARAM_FFC_DIGEST, md, 0);
        if (tc->pqg == ACVP_DSA_CANONICAL || tc->pqg == ACVP_DSA_UNVERIFIABLE) {
            p = BN_bin2bn(tc->p, tc->p_len, NULL);
            q = BN_bin2bn(tc->q, tc->q_len, NULL);
            if (!p || !q) {
                printf("Error converting P/Q to bignum in DSA pqggen\n");
                goto err;
            }
            OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_FFC_P, p);
            OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_FFC_Q, q);
        }
        if (tc->pqg == ACVP_DSA_UNVERIFIABLE) {
            OSSL_PARAM_BLD_push_int(pbld, OSSL_PKEY_PARAM_FFC_GINDEX, -1);
        }
        if (tc->pqg == ACVP_DSA_CANONICAL) {
            OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_PKEY_PARAM_FFC_SEED, tc->seed, tc->seedlen);
            OSSL_PARAM_BLD_push_int(pbld, OSSL_PKEY_PARAM_FFC_GINDEX, tc->index);
        }
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in DSA pqggen\n");
            goto err;
        }

        param_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
        if (!param_ctx) {
            printf("Error initializing param CTX in DSA pqggen\n");
            goto err;
        }
        if (tc->pqg == ACVP_DSA_UNVERIFIABLE) {
            if (EVP_PKEY_fromdata_init(param_ctx) != 1) {
                printf("Error initializing fromdata for params in DSA pqggen\n");
                goto err;
            }
            if (EVP_PKEY_fromdata(param_ctx, &param_key, EVP_PKEY_KEY_PARAMETERS, params) != 1) {
                printf("Error generating param pkey in DSA pqggen\n");
                goto err;
            }
            pctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
        } else {
            pctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
        }
        if (!pctx) {
            printf("Error creating paramgen CTX in DSA pqggen\n");
            goto err;
        }
        if (EVP_PKEY_paramgen_init(pctx) != 1) {
            printf("Error initializing paramgen in DSA pqggen\n");
            goto err;
        }
        if (tc->pqg != ACVP_DSA_UNVERIFIABLE) {
            EVP_PKEY_CTX_set_params(pctx, params);
        }

        if (EVP_PKEY_paramgen(pctx, &pkey) != 1) {
            printf("Error generating params in DSA pqggen\n");
            goto err;
        }

        switch (tc->pqg) {
        case ACVP_DSA_PROBABLE:
            if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p) == 1) {
                tc->p_len = BN_bn2bin(p, tc->p);
            } else {
                printf("Error getting 'p' in DSA pqggen\n");
                goto err;
            }
            if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_Q, &q) == 1) {
                tc->q_len = BN_bn2bin(q, tc->q);
            } else {
                printf("Error getting 'q' in DSA pqggen\n");
                goto err;
            }
            if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_FFC_SEED, tc->seed, DSA_MAX_SEED, &seed_len) == 1) {
                tc->seedlen = (int)seed_len;
            } else {
                printf("Error getting 'seed' in DSA pqggen\n");
                goto err;
            }
            if (EVP_PKEY_get_int_param(pkey, OSSL_PKEY_PARAM_FFC_PCOUNTER, &tc->counter) != 1) {
                printf("Error getting 'counter' in DSA pqggen\n");
                goto err;
            }
            break;
        case ACVP_DSA_CANONICAL:
        case ACVP_DSA_UNVERIFIABLE:
            if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &g) == 1) {
                tc->g_len = BN_bn2bin(g, tc->g);
            } else {
                printf("Error getting 'g' in DSA pqggen\n");
                goto err;
            }
            break;
        case ACVP_DSA_PROVABLE:
        default:
            printf("Unsupported pqg mode for DSA pqggen\n");
            goto err;
        }
        break;
    default:
        break;
    }
err:
    if (sig) free(sig);
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (q) BN_free(q);
    if (p) BN_free(p);
    if (g) BN_free(g);
    if (pub_key) BN_free(pub_key);
    if (sig_obj) DSA_SIG_free(sig_obj); /* Also frees R and S */
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (param_ctx) EVP_PKEY_CTX_free(param_ctx);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (param_key) EVP_PKEY_free(param_key);
    if (pkey) EVP_PKEY_free(pkey);
    if (sig_ctx) EVP_MD_CTX_free(sig_ctx);
    return 0;
}

#elif defined ACVP_NO_RUNTIME /* if OPENSSL_VERSION_NUMBER < 3 */

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
    BIGNUM              *tmp_q = NULL, *tmp_p = NULL, *tmp_g = NULL;
    const BIGNUM              *tmp_q1 = NULL, *tmp_p1 = NULL, *tmp_g1 = NULL;
    const BIGNUM              *tmp_q2 = NULL, *tmp_p2 = NULL, *tmp_g2 = NULL;
    const BIGNUM *tmp_r = NULL, *tmp_s = NULL;
    const BIGNUM *tmp_priv_key = NULL, *tmp_pub_key = NULL;
    const BIGNUM              *q1 = NULL, *p1 = NULL;
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

            DSA_get0_pqg(group_dsa, &tmp_p1,
                         &tmp_q1, &tmp_g1);
            group_p = BN_dup(tmp_p1);
            group_q = BN_dup(tmp_q1);
            group_g = BN_dup(tmp_g1);
        }

        tc->p_len = BN_bn2bin(group_p, tc->p);
        tc->q_len = BN_bn2bin(group_q, tc->q);
        tc->g_len = BN_bn2bin(group_g, tc->g);

        if (!DSA_generate_key(group_dsa)) {
            printf("\n DSA_generate_key failed");
            return 1;
        }

        DSA_get0_key(group_dsa, &tmp_pub_key, &tmp_priv_key);
        pub_key = BN_dup(tmp_pub_key);
        priv_key = BN_dup(tmp_priv_key);

        tc->x_len = BN_bn2bin(priv_key, tc->x);
        tc->y_len = BN_bn2bin(pub_key, tc->y);
        if (tmp_pub_key && tmp_priv_key) {
            FIPS_bn_free(pub_key);
            FIPS_bn_free(priv_key);
        }
        break;

    case ACVP_DSA_MODE_PQGVER:
        md = get_md_for_hash_alg(tc->sha);
        if (!md) {
            printf("DSA sha value not supported %d\n", tc->sha);
            return 1;
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

            DSA_get0_pqg(dsa, &tmp_p2, &tmp_q2, NULL);
            p2 = BN_dup(tmp_p2);
            q2 = BN_dup(tmp_q2);
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

            DSA_set0_pqg(dsa, BN_dup(p), BN_dup(q), BN_dup(g));

            if (dsa_builtin_paramgen2(dsa, L, N, md,
                                      tc->seed, tc->seedlen, tc->index, NULL,
                                      &counter2, &h2, NULL) < 0) {
                printf("Parameter Generation error\n");
                FIPS_dsa_free(dsa);
                return 1;
            }

            DSA_get0_pqg(dsa, NULL, NULL, &tmp_g2);
            g2 = BN_dup(tmp_g2);
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
        md = get_md_for_hash_alg(tc->sha);
        if (!md) {
            printf("DSA sha value not supported %d\n", tc->sha);
            return 1;
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

        n = tc->msglen;
        r = FIPS_dsa_verify(dsa, (const unsigned char *)tc->msg, n, md, sig);

        FIPS_dsa_free(dsa);
        FIPS_dsa_sig_free(sig);
        /* return result, 0 is failure, 1 is pass */
        tc->result = r;
        break;

    case ACVP_DSA_MODE_SIGGEN:
        md = get_md_for_hash_alg(tc->sha);
        if (!md) {
            printf("DSA sha value not supported %d\n", tc->sha);
            return 1;
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
            DSA_get0_pqg(group_dsa, &tmp_p1, &tmp_q1, &tmp_g1);
            group_p = BN_dup(tmp_p1);
            group_q = BN_dup(tmp_q1);
            group_g = BN_dup(tmp_g1);

            DSA_get0_key(group_dsa, &tmp_pub_key, NULL);
            group_pub_key = BN_dup(tmp_pub_key);
        }

        tc->p_len = BN_bn2bin(group_p, tc->p);
        tc->q_len = BN_bn2bin(group_q, tc->q);
        tc->g_len = BN_bn2bin(group_g, tc->g);
        tc->y_len = BN_bn2bin(group_pub_key, tc->y);

        sig = FIPS_dsa_sign(group_dsa, tc->msg, tc->msglen, md);

        DSA_SIG_get0(sig, &tmp_r, &tmp_s);
        sig_r = BN_dup(tmp_r);
        sig_s = BN_dup(tmp_s);

        tc->r_len = BN_bn2bin(sig_r, tc->r);
        tc->s_len = BN_bn2bin(sig_s, tc->s);
        if (tmp_r && tmp_s) {
            FIPS_bn_free(sig_r);
            FIPS_bn_free(sig_s);
        }
        FIPS_dsa_sig_free(sig);
        break;

    case ACVP_DSA_MODE_PQGGEN:
        md = get_md_for_hash_alg(tc->sha);
        if (!md) {
            printf("DSA sha value not supported %d\n", tc->sha);
            return 1;
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

            tmp_p = BN_dup(p);
            tmp_q = BN_dup(q);
            tmp_g = BN_dup(g);
            DSA_set0_pqg(dsa, tmp_p, tmp_q, tmp_g);
            L = tc->l;
            N = tc->n;
            if (dsa_builtin_paramgen2(dsa, L, N, md,
                                      tc->seed, tc->seedlen, tc->index, NULL,
                                      NULL, NULL, NULL) <= 0) {
                printf("DSA Parameter Generation2 error for %d\n", tc->gen_pq);
                FIPS_dsa_free(dsa);
                return 1;
            }
            DSA_get0_pqg(dsa, NULL, NULL, &tmp_g1);
            tc->g_len = BN_bn2bin(tmp_g1, tc->g);
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

            DSA_get0_pqg(dsa, &p1, &q1, NULL);
            tc->p_len = BN_bn2bin(p1, tc->p);
            tc->q_len = BN_bn2bin(q1, tc->q);

            tc->counter = counter;
            tc->h = h;

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
#else //OPENSSL_VERSION_NUMBER
int app_dsa_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}
#endif

#else //OPENSSL_NO_DSA

int app_dsa_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}
#endif
