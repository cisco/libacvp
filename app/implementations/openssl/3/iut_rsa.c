/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"
#include "implementations/openssl/3/iut.h"
#include "safe_lib.h"

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>

#define RSA_BUF_MAX 8192

int rsa_current_tg = 0;
BIGNUM *group_n = NULL;
EVP_PKEY *group_pkey = NULL;

void app_rsa_cleanup(void) {
    if (group_pkey) EVP_PKEY_free(group_pkey);
    group_pkey = NULL;
    if (group_n) BN_free(group_n);
    group_n = NULL;
}

int app_rsa_keygen_handler(ACVP_TEST_CASE *test_case) {
    ACVP_RSA_KEYGEN_TC *tc = NULL;
    int rv = 1;
    // storage for BN inputs
    BIGNUM *xp1 = NULL, *xp2 = NULL, *xp = NULL, *xq1 = NULL, *xq2 = NULL, *xq = NULL;
    // storage for output values before converting to binary
    BIGNUM *p = NULL, *q = NULL, *n = NULL, *d = NULL, *e = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    OSSL_PARAM *params = NULL;
    OSSL_PARAM_BLD *pkey_pbld = NULL;

    if (!test_case) {
        printf("Missing test_case\n");
        return 1;
    }

    tc = test_case->tc.rsa_keygen;
    e = BN_bin2bn(tc->e, tc->e_len, NULL);
    xp = BN_bin2bn(tc->xp, tc->xp_len, NULL);
    xp1 = BN_bin2bn(tc->xp1, tc->xp1_len, NULL);
    xp2 = BN_bin2bn(tc->xp2, tc->xp2_len, NULL);
    xq = BN_bin2bn(tc->xq, tc->xq_len, NULL);
    xq1 = BN_bin2bn(tc->xq1, tc->xq1_len, NULL);
    xq2 = BN_bin2bn(tc->xq2, tc->xq2_len, NULL);
    if (!e || !xp || !xp1 || !xp2 || !xq || !xq1 || !xq2) {
        printf("Error generating BN params from test case in RSA keygen\n");
        goto err;
    }

    pkey_pbld = OSSL_PARAM_BLD_new();
    if (!pkey_pbld) {
        printf("Error creating param_bld in RSA keygen\n");
        goto err;
    }
    OSSL_PARAM_BLD_push_BN(pkey_pbld, OSSL_PKEY_PARAM_RSA_E, e);
    OSSL_PARAM_BLD_push_uint(pkey_pbld, OSSL_PKEY_PARAM_RSA_BITS, tc->modulo);
    OSSL_PARAM_BLD_push_BN(pkey_pbld, OSSL_PKEY_PARAM_RSA_TEST_XP, xp);
    OSSL_PARAM_BLD_push_BN(pkey_pbld, OSSL_PKEY_PARAM_RSA_TEST_XP1, xp1);
    OSSL_PARAM_BLD_push_BN(pkey_pbld, OSSL_PKEY_PARAM_RSA_TEST_XP2, xp2);
    OSSL_PARAM_BLD_push_BN(pkey_pbld, OSSL_PKEY_PARAM_RSA_TEST_XQ, xq);
    OSSL_PARAM_BLD_push_BN(pkey_pbld, OSSL_PKEY_PARAM_RSA_TEST_XQ1, xq1);
    OSSL_PARAM_BLD_push_BN(pkey_pbld, OSSL_PKEY_PARAM_RSA_TEST_XQ2, xq2);
    params = OSSL_PARAM_BLD_to_param(pkey_pbld);
    if (!params) {
        printf("Error generating parameters for pkey generation in RSA keygen\n");
    }

    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!pkey_ctx) {
        printf("Error initializing pkey ctx for RSA keygen\n");
        goto err;
    }
    if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
        printf("Error initializing pkey in RSA ctx\n");
        goto err;
    }
    if (EVP_PKEY_CTX_set_params(pkey_ctx, params) != 1) {
        printf("Error setting params for pkey generation in RSA keygen\n");
        goto err;
    }
    EVP_PKEY_keygen(pkey_ctx, &pkey);
    if (!pkey) {
        printf("Error generating pkey in RSA keygen\n");
        goto err;
    }

    if (EVP_PKEY_get_bn_param(pkey, "rsa-factor1", &p) == 1) {
        tc->p_len = BN_bn2bin(p, tc->p);
    } else {
        printf("Error retrieving p from pkey in RSA keygen\n");
        goto err;
    }
    if (EVP_PKEY_get_bn_param(pkey, "rsa-factor2", &q) == 1) {
        tc->q_len = BN_bn2bin(q, tc->q);
    } else {
        printf("Error retrieving q from pkey in RSA keygen\n");
        goto err;
    }
    if (EVP_PKEY_get_bn_param(pkey, "n", &n) == 1) {
        tc->n_len = BN_bn2bin(n, tc->n);
    } else {
        printf("Error retrieving n from pkey in RSA keygen\n");
        goto err;
    }
    if (EVP_PKEY_get_bn_param(pkey, "d", &d) == 1) {
        tc->d_len = BN_bn2bin(d, tc->d);
    } else {
        printf("Error retrieving d from pkey in RSA keygen\n");
        goto err;
    }
    if (EVP_PKEY_get_bn_param(pkey, "e", &e) == 1) {
        tc->e_len = BN_bn2bin(e, tc->e);
    } else {
        printf("Error retrieving e from pkey in RSA keygen\n");
        goto err;
    }

    rv = 0;
err:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (p) BN_free(p);
    if (q) BN_free(q);
    if (n) BN_free(n);
    if (d) BN_free(d);
    if (e) BN_free(e);
    if (xp) BN_free(xp);
    if (xp1) BN_free(xp1);
    if (xp2) BN_free(xp2);
    if (xq) BN_free(xq);
    if (xq1) BN_free(xq1);
    if (xq2) BN_free(xq2);
    if (pkey) EVP_PKEY_free(pkey);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (params) OSSL_PARAM_free(params);
    if (pkey_pbld) OSSL_PARAM_BLD_free(pkey_pbld);
    return rv;
}

int app_rsa_sig_handler(ACVP_TEST_CASE *test_case) {
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    OSSL_PARAM_BLD *pkey_pbld = NULL, *sig_pbld = NULL;
    OSSL_PARAM *pkey_params = NULL, *sig_params = NULL;
    const char *padding = NULL, *md = NULL;
    int salt_len = -1;
    BIGNUM *bn_e = NULL, *e = NULL, *n = NULL;
    ACVP_RSA_SIG_TC *tc;

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

    bn_e = BN_new();
    if (!bn_e || !BN_set_word(bn_e, 0x10001)) {
        printf("\nError: Issue with exponent in RSA Sig\n");
        goto err;
    }

    if (!tc->modulo) {
        printf("\nError: Issue with modulo in RSA Sig\n");
        goto err;
    }

    // Set the padding mode and digest MD
    switch (tc->sig_type) {
    case ACVP_RSA_SIG_TYPE_X931:
        padding = "x931";
        break;
    case ACVP_RSA_SIG_TYPE_PKCS1PSS:
        salt_len = tc->salt_len;
        padding = "pss";
        break;
    case ACVP_RSA_SIG_TYPE_PKCS1V15:
        padding = "pkcs1";
        break;
    default:
        printf("\nError: sigType not supported\n");
        rv = ACVP_INVALID_ARG;
        goto err;
    }

    md = get_md_string_for_hash_alg(tc->hash_alg, NULL);
    if (!md) {
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

        pkey_pbld = OSSL_PARAM_BLD_new();
        if (!pkey_pbld) {
            printf("Error creating param_bld in RSA sigver\n");
            goto err;
        }
        OSSL_PARAM_BLD_push_BN(pkey_pbld, OSSL_PKEY_PARAM_RSA_N, n);
        OSSL_PARAM_BLD_push_BN(pkey_pbld, OSSL_PKEY_PARAM_RSA_E, e);
        pkey_params = OSSL_PARAM_BLD_to_param(pkey_pbld);
        if (!pkey_params) {
            printf("Error building pkey params in RSA sigver\n");
            goto err;
        }

        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey ctx for RSA sigver\n");
            goto err;
        }
        if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
            printf("Error initializing pkey in RSA ctx\n");
            goto err;
        }
        if (EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_KEYPAIR, pkey_params) != 1) {
            printf("Error generating pkey in RSA context\n");
            goto err;
        }

        // now we have the pkey, setup the digest ctx
        sig_pbld = OSSL_PARAM_BLD_new();
        if (!sig_pbld) {
            printf("Error creating param_bld in RSA sigver\n");
            goto err;
        }
        OSSL_PARAM_BLD_push_utf8_string(sig_pbld, OSSL_SIGNATURE_PARAM_PAD_MODE, padding, 0);
        OSSL_PARAM_BLD_push_utf8_string(sig_pbld, OSSL_SIGNATURE_PARAM_DIGEST, md, 0);
        sig_params = OSSL_PARAM_BLD_to_param(sig_pbld);
        if (!sig_params) {
            printf("Error building sig params in RSA sigver\n");
            goto err;
        }

        md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            printf("Error creating MD CTX in RSA sigver\n");
            goto err;
        }
        EVP_DigestVerifyInit_ex(md_ctx, NULL, md, NULL, NULL, pkey, sig_params);
        if (EVP_DigestVerify(md_ctx, tc->signature, tc->sig_len, tc->msg, tc->msg_len) == 1) {
            tc->ver_disposition = 1;
        }
    } else {
        if (rsa_current_tg != tc->tg_id) {
            rsa_current_tg = tc->tg_id;

            if (group_pkey) EVP_PKEY_free(group_pkey);
            group_pkey = NULL;
            if (group_n) BN_free(group_n);
            group_n = NULL;

            pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
            if (!pkey_ctx) {
                printf("Error initializing pkey ctx for RSA siggen\n");
                goto err;
            }
            if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
                printf("Error initializing pkey in RSA ctx\n");
                goto err;
            }
            EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, tc->modulo);

            if (EVP_PKEY_keygen(pkey_ctx, &group_pkey) != 1) {
                printf("Error generating pkey in RSA context\n");
                goto err;
            }
            if (EVP_PKEY_get_bn_param(group_pkey, "e", &e) != 1) {
                printf("Error retrieving e from generated pkey in RSA siggen\n");
                goto err;
            }
            if (EVP_PKEY_get_bn_param(group_pkey, "n", &n) != 1) {
                printf("Error retrieving n from generated pkey in RSA siggen\n");
                goto err;
            }
            group_n = BN_dup(n);
        } else {
            e = BN_dup(bn_e);
            n = BN_dup(group_n);
        }
        tc->e_len = BN_bn2bin(e, tc->e);
        tc->n_len = BN_bn2bin(n, tc->n);

        sig_pbld = OSSL_PARAM_BLD_new();
        if (!sig_pbld) {
            printf("Error creating param_bld in RSA siggen\n");
            goto err;
        }
        OSSL_PARAM_BLD_push_utf8_string(sig_pbld, OSSL_SIGNATURE_PARAM_PAD_MODE, padding, 0);
        OSSL_PARAM_BLD_push_utf8_string(sig_pbld, OSSL_SIGNATURE_PARAM_DIGEST, md, 0);
        if (tc->sig_type == ACVP_RSA_SIG_TYPE_PKCS1PSS) {
            OSSL_PARAM_BLD_push_int(sig_pbld, OSSL_SIGNATURE_PARAM_PSS_SALTLEN, salt_len);
        }
        sig_params = OSSL_PARAM_BLD_to_param(sig_pbld);
        if (!sig_params) {
            printf("Error building sig params in RSA siggen\n");
            goto err;
        }

        md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            printf("Error creating MD CTX in RSA sigver\n");
            goto err;
        }
        if (EVP_DigestSignInit_ex(md_ctx, NULL, md, NULL, NULL, group_pkey, sig_params) != 1) {
            printf("Error initializing sign ctx in RSA siggen\n");
            goto err;
        }
        if (EVP_DigestSign(md_ctx, tc->signature, (size_t *)&tc->sig_len, tc->msg, tc->msg_len) != 1) {
            printf("Error while performing signature generation\n");
            goto err;
        }
    }

    // Success
    rv = 0;

err:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (pkey_pbld) OSSL_PARAM_BLD_free(pkey_pbld);
    if (sig_pbld) OSSL_PARAM_BLD_free(sig_pbld);
    if (pkey_params) OSSL_PARAM_free(pkey_params);
    if (sig_params) OSSL_PARAM_free(sig_params);
    if (bn_e) BN_free(bn_e);
    if (e) BN_free(e);
    if (n) BN_free(n);

    return rv;
}

int app_rsa_sigprim_handler(ACVP_TEST_CASE *test_case) {
    BIGNUM *e = NULL, *n = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY_CTX *sign_ctx = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    BN_CTX *bctx = NULL;
    ACVP_RSA_PRIM_TC *tc;
    int rv = 1;

    tc = test_case->tc.rsa_prim;
    tc->disposition = 1;

    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("Error creating param_bld in RSA sigprim\n");
        goto err;
    }

    if (!tc->e || !tc->n) {
        printf("Missing arguments e|n\n");
        goto err;
    }
    e = BN_bin2bn(tc->e, tc->e_len, NULL);
    n = BN_bin2bn(tc->n, tc->n_len, NULL);
    if (!e || !n) {
        printf("Failed to convert e/n to bignum in RSA sigprim\n");
        goto err;
    }
    OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_N, n);
    OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_E, e);

    if (!tc->p || !tc->q) {
        printf("Missing TC key components\n");
        goto err;
    }
    p = BN_bin2bn(tc->p, tc->p_len, NULL);
    q = BN_bin2bn(tc->q, tc->q_len, NULL);
    if (!p || !q) {
        printf("Failed to convert key components to bignum in RSA sigprim\n");
        goto err;
    }
    OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
    OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_FACTOR2, q);

    switch (tc->key_format) {
    case ACVP_RSA_KEY_FORMAT_CRT:
        if (!tc->dmp1 || !tc->dmq1 || !tc->iqmp) {
            printf("Missing TC CRT key components\n");
            goto err;
        }
        dmp1 = BN_bin2bn(tc->dmp1, tc->dmp1_len, NULL);
        dmq1 = BN_bin2bn(tc->dmq1, tc->dmq1_len, NULL);
        iqmp = BN_bin2bn(tc->iqmp, tc->iqmp_len, NULL);
        if (!dmp1 || !dmq1 || !iqmp) {
            printf("Failed to convert CRT components to bignum in RSA sigprim\n");
            goto err;
        }
        // d should be provided as part of a CRT key, but it is not, so calculate ourselves
        bctx = BN_CTX_new();
        d = BN_dup(n);
        if (!bctx || !d) {
            printf("Error generating d in RSA sigprim\n");
            goto err;
        }
        BN_sub(d, d, p);
        BN_sub(d, d, q);
        BN_add_word(d, 1);
        BN_mod_inverse(d, e, d, bctx);
        OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1);
        OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1);
        OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp);
        break;
    case ACVP_RSA_KEY_FORMAT_STANDARD:
        if (!tc->d) {
            printf("Missing argument d\n");
            goto err;
        }
        d = BN_bin2bn(tc->d, tc->d_len, NULL);
        if (!d) {
            printf("Failed to convert d to bignum in RSA sigprim\n");
            goto err;
        }
        break;
    default:
        printf("Invalid key format in RSA sigprim\n");
        goto err;
    }

    OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_D, d);

    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error building params in RSA sigprim\n");
        goto err;
    }

    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!pkey_ctx) {
        printf("Error creating PKEY_CTX in RSA\n");
        goto err;
    }
    if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
        printf("Error initializing pkey in RSA ctx\n");
        goto err;
    }
    if (EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1) {
        printf("Error generating pkey in RSA context\n");
        goto err;
    }
    sign_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (!sign_ctx) {
        printf("Error generating signing CTX from pkey in RSA\n");
        goto err;
    }

    if (EVP_PKEY_sign_init(sign_ctx) != 1) {
        printf("Error initializing signing function in RSA\n");
        goto err;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(sign_ctx, RSA_NO_PADDING) != 1) {
        printf("Error setting padding in RSA context: %d\n", rv);
        goto err;
    }

    tc->sig_len = tc->modulo;
    if (EVP_PKEY_sign(sign_ctx, tc->signature, (size_t *)&tc->sig_len, tc->msg, tc->msg_len) != 1) {
        tc->disposition = 0;
    }

    rv = 0;

err:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (e) BN_free(e);
    if (n) BN_free(n);
    if (d) BN_free(d);
    if (p) BN_free(p);
    if (q) BN_free(q);
    if (dmp1) BN_free(dmp1);
    if (dmq1) BN_free(dmq1);
    if (iqmp) BN_free(iqmp);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (sign_ctx) EVP_PKEY_CTX_free(sign_ctx);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (bctx) BN_CTX_free(bctx);
    return rv;
}

int app_rsa_decprim_handler(ACVP_TEST_CASE *test_case) {
    BIGNUM *e = NULL, *n = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL, *dec_ctx = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    ACVP_RSA_PRIM_TC *tc;
    int rv = 1;

    tc = test_case->tc.rsa_prim;

    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("Error creating param_bld in RSA decprim\n");
        goto err;
    }

    // Handle common key components, then ones specific to CRT or standard key formats
    if (!tc->p || !tc->q || !tc->e || !tc->n || !tc->d) {
        printf("Missing TC key components for RSA decprim\n");
        goto err;
    }

    p = BN_bin2bn(tc->p, tc->p_len, NULL);
    q = BN_bin2bn(tc->q, tc->q_len, NULL);
    e = BN_bin2bn(tc->e, tc->e_len, NULL);
    n = BN_bin2bn(tc->n, tc->n_len, NULL);
    d = BN_bin2bn(tc->d, tc->d_len, NULL);
    if (!p || !q || !e || !n || !d) {
        printf("Failed to convert key components to bignum in RSA decprim\n");
        goto err;
    }
    OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_N, n);
    OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_E, e);
    OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
    OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
    OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_D, d);

    if (tc->key_format == ACVP_RSA_KEY_FORMAT_CRT) {
        if (!tc->dmp1 || !tc->dmq1 || !tc->iqmp) {
            printf("Missing TC CRT key components for RSA decprim\n");
            goto err;
        }
        dmp1 = BN_bin2bn(tc->dmp1, tc->dmp1_len, NULL);
        dmq1 = BN_bin2bn(tc->dmq1, tc->dmq1_len, NULL);
        iqmp = BN_bin2bn(tc->iqmp, tc->iqmp_len, NULL);
        if (!dmp1 || !dmq1 || !iqmp) {
            printf("Failed to convert CRT key components to bignum in RSA decprim\n");
            goto err;
        }
        OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1);
        OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1);
        OSSL_PARAM_BLD_push_BN(pbld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp);
    }

    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error building params in RSA decprim\n");
        goto err;
    }

    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
        printf("Error initializing pkey in RSA decprim ctx\n");
        goto err;
    }

    if (EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1) {
        printf("Error generating pkey in RSA decprim context\n");
        goto err;
    }

    dec_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (!dec_ctx) {
        printf("Error creating decrypt ctx in RSA decprim\n");
        goto err;
    }

    if (EVP_PKEY_decrypt_init(dec_ctx) != 1) {
        printf("Error initializing decrypt ctx in RSA decprim\n");
        goto err;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_NO_PADDING) != 1) {
        printf("Error setting padding in RSA decprim\n");
        goto err;
    }

    tc->pt_len = RSA_BUF_MAX;
    if (EVP_PKEY_decrypt(dec_ctx, tc->pt, (size_t *)&tc->pt_len, tc->cipher, tc->cipher_len) == 1) {
        tc->disposition = 1;
    } else {
        tc->disposition = 0;
    }

    rv = 0;
err:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (e) BN_free(e);
    if (n) BN_free(n);
    if (d) BN_free(d);
    if (p) BN_free(p);
    if (q) BN_free(q);
    if (dmp1) BN_free(dmp1);
    if (dmq1) BN_free(dmq1);
    if (iqmp) BN_free(iqmp);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (dec_ctx) EVP_PKEY_CTX_free(dec_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    return rv;
}
