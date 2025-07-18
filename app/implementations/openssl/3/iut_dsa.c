/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include "app_lcl.h"
#include "implementations/openssl/3/iut.h"
#include "safe_lib.h"

#if !defined OPENSSL_NO_DSA
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/err.h>

#define DSA_MAX_SEED 1024

/* Re-use these when possible to speed up test cases */
static EVP_PKEY_CTX *group_param_ctx = NULL;
static EVP_PKEY_CTX *group_pctx = NULL;
static EVP_PKEY *group_param_key = NULL;
static EVP_PKEY *group_pkey = NULL;
static int dsa_current_siggen_tg = 0;
static int dsa_current_keygen_tg = 0;

void app_dsa_cleanup(void) {
    if (group_param_ctx) EVP_PKEY_CTX_free(group_param_ctx);
    group_param_ctx = NULL;
    if (group_pctx) EVP_PKEY_CTX_free(group_pctx);
    group_pctx = NULL;
    if (group_param_key) EVP_PKEY_free(group_param_key);
    group_param_key = NULL;
    if (group_pkey) EVP_PKEY_free(group_pkey);
    group_pkey = NULL;
}

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
    if (rv != 0) ERR_print_errors_fp(stderr);
    return rv;
}

int app_dsa_handler(ACVP_TEST_CASE *test_case) {
    int rv = 1;
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
            printf("Error creating signature object needed to retrieve output in ECDSA siggen\n");
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
            if (EVP_PKEY_CTX_set_params(pctx, params) != 1) {
                printf("Error setting params in DSA pqggen\n");
            }
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

    rv = 0;
err:
    if (rv != 0) ERR_print_errors_fp(stderr);
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
    return rv;
}

#else

int app_dsa_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}
#endif

