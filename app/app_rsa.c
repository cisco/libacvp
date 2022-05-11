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
#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#endif

#include "app_lcl.h"
#include "safe_lib.h"
#if OPENSSL_VERSION_NUMBER >= 0x30000000L || defined ACVP_NO_RUNTIME
#ifdef ACVP_NO_RUNTIME
#include "app_fips_lcl.h" /* All regular OpenSSL headers must come before here */
#include <openssl/ossl_typ.h>
#endif

int rsa_current_tg = 0;
BIGNUM *group_n = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
EVP_PKEY *group_pkey = NULL;
#else
RSA *group_rsa = NULL;
#endif

void app_rsa_cleanup(void) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (group_pkey) EVP_PKEY_free(group_pkey);
    group_pkey = NULL;
#else
    if (group_rsa) RSA_free(group_rsa);
    group_rsa = NULL;
#endif
    if (group_n) BN_free(group_n);
    group_n = NULL;
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L && defined ACVP_NO_RUNTIME
int app_rsa_keygen_handler(ACVP_TEST_CASE *test_case) {
    ACVP_RSA_KEYGEN_TC *tc = NULL;
    int rv = 1;
    RSA *rsa = NULL;
    const BIGNUM *p1 = NULL, *q1 = NULL, *n1 = NULL, *d1 = NULL;
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

    RSA_get0_key(rsa, &n1, NULL, &d1);
    RSA_get0_factors(rsa, &p1, &q1);

    tc->p_len = BN_bn2bin(p1, tc->p);
    tc->q_len = BN_bn2bin(q1, tc->q);
    tc->n_len = BN_bn2bin(n1, tc->n);
    tc->d_len = BN_bn2bin(d1, tc->d);

    rv = 0;
err:
    if (rsa) FIPS_rsa_free(rsa);
    if (e) BN_free(e);
    return rv;
}
#else
int app_rsa_keygen_handler(ACVP_TEST_CASE *test_case) {
    ACVP_RSA_KEYGEN_TC *tc = NULL;
    int rv = 1;
    /** storage for BN inputs */
    BIGNUM *xp1 = NULL, *xp2 = NULL, *xp = NULL, *xq1 = NULL, *xq2 = NULL, *xq = NULL;
    /** storage for output values before converting to binary */
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
    OSSL_PARAM_BLD_push_BN(pkey_pbld, "e", e);
    OSSL_PARAM_BLD_push_uint(pkey_pbld, "bits", tc->modulo);
    OSSL_PARAM_BLD_push_BN(pkey_pbld, "xp", xp);
    OSSL_PARAM_BLD_push_BN(pkey_pbld, "xp1", xp1);
    OSSL_PARAM_BLD_push_BN(pkey_pbld, "xp2", xp2);
    OSSL_PARAM_BLD_push_BN(pkey_pbld, "xq", xq);
    OSSL_PARAM_BLD_push_BN(pkey_pbld, "xq1", xq1); 
    OSSL_PARAM_BLD_push_BN(pkey_pbld, "xq2", xq2);
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
        printf("Error retreiving p from pkey in RSA keygen\n");
        goto err;
    }
    if (EVP_PKEY_get_bn_param(pkey, "rsa-factor2", &q) == 1) {
        tc->q_len = BN_bn2bin(q, tc->q);
    } else {
        printf("Error retreiving q from pkey in RSA keygen\n");
        goto err;
    }
    if (EVP_PKEY_get_bn_param(pkey, "n", &n) == 1) {
        tc->n_len = BN_bn2bin(n, tc->n);
    } else {
        printf("Error retreiving n from pkey in RSA keygen\n");
        goto err;
    }
    if (EVP_PKEY_get_bn_param(pkey, "d", &d) == 1) {
        tc->d_len = BN_bn2bin(d, tc->d);
    } else {
        printf("Error retreiving d from pkey in RSA keygen\n");
        goto err;
    }
    if (EVP_PKEY_get_bn_param(pkey, "e", &e) == 1) {
        tc->e_len = BN_bn2bin(e, tc->e);
    } else {
        printf("Error retreiving e from pkey in RSA keygen\n");
        goto err;
    }

    rv = 0;
err:
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
#endif

int app_rsa_sig_handler(ACVP_TEST_CASE *test_case) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    OSSL_PARAM_BLD *pkey_pbld = NULL, *sig_pbld = NULL;
    OSSL_PARAM *pkey_params = NULL, *sig_params = NULL;
    const char *padding = NULL, *md = NULL;
#else
    const EVP_MD *tc_md = NULL;
    BIGNUM  *tmp_e = NULL, *tmp_n = NULL;
    const BIGNUM  *tmp_e1 = NULL, *tmp_n1 = NULL;
    RSA *rsa = NULL;
    int siglen = 0, pad_mode = 0;
#endif
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

/* Set the padding mode and digest MD */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
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

    switch (tc->hash_alg) {
    case ACVP_SHA1:
        md = "SHA-1";
        break;
    case ACVP_SHA224:
        md = "SHA2-224";
        break;
    case ACVP_SHA256:
        md = "SHA2-256";
        break;
    case ACVP_SHA384:
        md = "SHA2-384";
        break;
    case ACVP_SHA512:
        md = "SHA2-512";
        break;
    case ACVP_SHA512_224:
        md = "SHA2-512/224";
        break;
    case ACVP_SHA512_256:
        md = "SHA2-512/256";
        break;
    case ACVP_NO_SHA:
    case ACVP_SHA3_224:
    case ACVP_SHA3_256:
    case ACVP_SHA3_384:
    case ACVP_SHA3_512:
    case ACVP_HASH_ALG_MAX:
    default:
        printf("\nError: hashAlg not supported for RSA SigGen\n");
        goto err;
    }

#else

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

    switch (tc->hash_alg) {
    case ACVP_SHA1:
        tc_md = EVP_sha1();
        break;
    case ACVP_SHA224:
        tc_md = EVP_sha224();
        break;
    case ACVP_SHA256:
        tc_md = EVP_sha256();
        break;
    case ACVP_SHA384:
        tc_md = EVP_sha384();
        break;
    case ACVP_SHA512:
        tc_md = EVP_sha512();
        break;
    case ACVP_SHA512_224:
        tc_md = EVP_sha512_224();
        break;
    case ACVP_SHA512_256:
        tc_md = EVP_sha512_256();
        break;
    case ACVP_NO_SHA:
    case ACVP_SHA3_224:
    case ACVP_SHA3_256:
    case ACVP_SHA3_384:
    case ACVP_SHA3_512:
    case ACVP_HASH_ALG_MAX:
    default:
        printf("\nError: hashAlg not supported for RSA SigGen\n");
        goto err;
    }
#endif

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

        #if OPENSSL_VERSION_NUMBER >= 0x30000000L
            pkey_pbld = OSSL_PARAM_BLD_new();
            OSSL_PARAM_BLD_push_BN(pkey_pbld, "n", n);
            OSSL_PARAM_BLD_push_BN(pkey_pbld, "e", e);
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

            //now we have the pkey, setup the digest ctx
            sig_pbld = OSSL_PARAM_BLD_new();
            OSSL_PARAM_BLD_push_utf8_string(sig_pbld, "pad-mode", padding, 0);
            OSSL_PARAM_BLD_push_utf8_string(sig_pbld, "digest", md, 0);
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
        #else //if OPENSSL_VERSION_NUMBER is < 3
            rsa = FIPS_rsa_new();
            if (!rsa) {
                printf("\nError: Issue with RSA obj in RSA Sig\n");
                goto err;
            }
            tmp_e = BN_dup(e);
            tmp_n = BN_dup(n);
            RSA_set0_key(rsa, tmp_n, tmp_e, NULL);

            tc->ver_disposition = FIPS_rsa_verify(rsa, tc->msg, tc->msg_len, tc_md, 
                                                  pad_mode, salt_len, NULL, tc->signature, 
                                                  tc->sig_len);
        #endif
    } else {
        #if OPENSSL_VERSION_NUMBER >= 0x30000000L
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
            OSSL_PARAM_BLD_push_utf8_string(sig_pbld, "pad-mode", padding, 0);
            OSSL_PARAM_BLD_push_utf8_string(sig_pbld, "digest", md, 0);
            if (tc->sig_type == ACVP_RSA_SIG_TYPE_PKCS1PSS) {
                OSSL_PARAM_BLD_push_int(sig_pbld, "saltlen", salt_len);
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
            EVP_DigestSignInit_ex(md_ctx, NULL, md, NULL, NULL, group_pkey, sig_params);
            if (EVP_DigestSign(md_ctx, tc->signature, (size_t *)&tc->sig_len, tc->msg, tc->msg_len) != 1) {
                printf("Error while performing signature generation\n");
                goto err;
            }
        #else  //if OPENSSL_VERSION_NUMBER is < 3
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
                RSA_get0_key(group_rsa, &tmp_n1, &tmp_e1, NULL);
                e = BN_dup(tmp_e1);
                n = BN_dup(tmp_n1);
                group_n = BN_dup(n);
            } else {
                e = BN_dup(bn_e);
                n = BN_dup(group_n);
            }
            tc->e_len = BN_bn2bin(e, tc->e);
            tc->n_len = BN_bn2bin(n, tc->n);

            if (tc->msg && tc_md) {
                siglen = RSA_size(group_rsa);

                if (!FIPS_rsa_sign(group_rsa, tc->msg, tc->msg_len, tc_md, 
                                   pad_mode, salt_len, NULL,
                                   tc->signature, (unsigned int *)&siglen)) {
                    printf("\nError: RSA Signature Generation fail\n");
                    goto err;
                }

                tc->sig_len = siglen;
            }
        #endif
    }

    /* Success */
    rv = 0;

err:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (pkey_pbld) OSSL_PARAM_BLD_free(pkey_pbld);
    if (sig_pbld) OSSL_PARAM_BLD_free(sig_pbld);
    if (pkey_params) OSSL_PARAM_free(pkey_params);
    if (sig_params) OSSL_PARAM_free(sig_params);
#else
    if (rsa) FIPS_rsa_free(rsa);
#endif
    if (bn_e) BN_free(bn_e);
    if (e) BN_free(e);
    if (n) BN_free(n);

    return rv;
}

#if 0 //todo: when could this be used? or just remove since 3.0 supports runtime.

static const unsigned char sha1_bin[] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
  0x00, 0x04, 0x14
};

static const unsigned char sha224_bin[] = {
  0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c
};

static const unsigned char sha256_bin[] = {
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

static const unsigned char sha384_bin[] = {
  0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};

static const unsigned char sha512_bin[] = {
  0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

static const unsigned char sha1_nn_bin[] = {
  0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04,
  0x14
};

static const unsigned char sha224_nn_bin[] = {
  0x30, 0x2b, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x04, 0x04, 0x1c
};

static const unsigned char sha256_nn_bin[] = {
  0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x01, 0x04, 0x20
};

static const unsigned char sha384_nn_bin[] = {
  0x30, 0x3f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x02, 0x04, 0x30
};

static const unsigned char sha512_nn_bin[] = {
  0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x03, 0x04, 0x40
};


static const unsigned char *digestinfo_encoding(int nid, unsigned int *len)
	{
	switch (nid)
		{

		case NID_sha1:
		*len = sizeof(sha1_bin);
		return sha1_bin;

		case NID_sha224:
		*len = sizeof(sha224_bin);
		return sha224_bin;

		case NID_sha256:
		*len = sizeof(sha256_bin);
		return sha256_bin;

		case NID_sha384:
		*len = sizeof(sha384_bin);
		return sha384_bin;

		case NID_sha512:
		*len = sizeof(sha512_bin);
		return sha512_bin;

		default:
		return NULL;

		}
	}

static const unsigned char *digestinfo_nn_encoding(int nid, unsigned int *len)
	{
	switch (nid)
		{

		case NID_sha1:
		*len = sizeof(sha1_nn_bin);
		return sha1_nn_bin;

		case NID_sha224:
		*len = sizeof(sha224_nn_bin);
		return sha224_nn_bin;

		case NID_sha256:
		*len = sizeof(sha256_nn_bin);
		return sha256_nn_bin;

		case NID_sha384:
		*len = sizeof(sha384_nn_bin);
		return sha384_nn_bin;

		case NID_sha512:
		*len = sizeof(sha512_nn_bin);
		return sha512_nn_bin;

		default:
		return NULL;

		}
	}

int app_rsa_sig_handler(ACVP_TEST_CASE *test_case) {
    const EVP_MD *tc_md = NULL;
    int pad_mode;
    BIGNUM *bn_e = NULL, *e = NULL, *n = NULL;
    BIGNUM  *tmp_e = NULL, *tmp_n = NULL;
    ACVP_RSA_SIG_TC    *tc;
    RSA *rsa = NULL;
    unsigned int salt_len = -1, md_len = 0;
    int rv = 1, i;
    unsigned char *s = NULL, *mdhash = NULL;
    int md_type;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pk = NULL;

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

    rsa = RSA_new();
    if (!rsa) {
        printf("\nError: Issue with RSA obj in RSA Sig\n");
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

    /*
     * Set the pad mode and generate a key given the respective sigType
     */
    switch (tc->sig_type) {
    case ACVP_RSA_SIG_TYPE_X931:
        pad_mode = RSA_X931_PADDING;
        salt_len = tc->salt_len;
        break;
    case ACVP_RSA_SIG_TYPE_PKCS1PSS:
        pad_mode = RSA_PKCS1_PSS_PADDING;
        salt_len = tc->salt_len;
        break;
    case ACVP_RSA_SIG_TYPE_PKCS1V15:
        pad_mode = RSA_PKCS1_PADDING;
        salt_len = tc->salt_len;
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
        tc_md = EVP_sha1();
        break;
    case ACVP_SHA224:
        tc_md = EVP_sha224();
        break;
    case ACVP_SHA256:
        tc_md = EVP_sha256();
        break;
    case ACVP_SHA384:
        tc_md = EVP_sha384();
        break;
    case ACVP_SHA512:
        tc_md = EVP_sha512();
        break;
    case ACVP_SHA512_224:
        tc_md = EVP_sha512_224();
        break;
    case ACVP_SHA512_256:
        tc_md = EVP_sha512_256();
        break;
    case ACVP_HASH_ALG_MAX:
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

        tmp_e = BN_dup(e);
        tmp_n = BN_dup(n);
        RSA_set0_key(rsa, tmp_n, tmp_e, NULL);

        pk = EVP_PKEY_new();
        if (pk == NULL)
            goto err;

        EVP_PKEY_set1_RSA(pk, rsa);

        pctx = EVP_PKEY_CTX_new(pk, NULL);
	s= OPENSSL_malloc(tc->sig_len);
	if (s == NULL) {
            goto err;
        }
	mdhash = OPENSSL_malloc(EVP_MD_size(tc_md)+1);
	if (mdhash == NULL) {
            goto err;
        }
        EVP_Digest(tc->msg, tc->msg_len, mdhash, &md_len, tc_md, NULL);
        md_type = EVP_MD_nid(tc_md);
        if (pad_mode == RSA_X931_PADDING) {
            mdhash[md_len] = RSA_X931_hash_id(md_type);
            if (mdhash[md_len] == -1) {
                goto err;
            }
            md_len++;
        }
        EVP_PKEY_verify_init(pctx);
        EVP_PKEY_CTX_set_rsa_padding(pctx, pad_mode);
        if (pad_mode == RSA_PKCS1_PSS_PADDING) {
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt_len);
            EVP_PKEY_CTX_set_signature_md(pctx, tc_md);
        }
        if (pad_mode != RSA_PKCS1_PADDING) {
            i = EVP_PKEY_verify(pctx, tc->signature, tc->sig_len, mdhash, md_len); 
        } else {
                unsigned int dlen;
                const unsigned char *der = NULL;
                int diff1, diff2;

                i = RSA_public_decrypt(tc->sig_len, tc->signature, s,
                                       rsa, pad_mode);
                if (i <= 0) {
                    i = 0;
                    goto end;
                }
		der = digestinfo_encoding(md_type, &dlen);
		
		if (!der)
			{
			goto err;
			}

		/* Compare, DigestInfo length, DigestInfo header and finally
		 * digest value itself
		 */

		/* If length mismatch try alternate encoding */
		if (i != (int)(dlen + md_len))
			der = digestinfo_nn_encoding(md_type, &dlen);

                memcmp_s(der, dlen, s, dlen, &diff1);
                memcmp_s(s + dlen, md_len, mdhash, md_len, &diff2);
		if ((i != (int)(dlen + md_len)) || diff1
			|| diff2)
			{
                        i = 0;
			goto end;
			}
       }

        tc->ver_disposition = ACVP_TEST_DISPOSITION_PASS;
	if (i == 0) { 
            tc->ver_disposition = ACVP_TEST_DISPOSITION_FAIL;
        }

    } else {
        rv = 1;
        goto err;
    }
end:
    /* Success */
    rv = 0;

err:
    if (mdhash) free(mdhash);
    if (s) free(s);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (pk) EVP_PKEY_free(pk);
    if (bn_e) BN_free(bn_e);
    if (rsa) RSA_free(rsa);
    if (e) BN_free(e);
    if (n) BN_free(n);

    return rv;
}
#endif

int app_rsa_decprim_handler(ACVP_TEST_CASE *test_case) {
#ifdef OPENSSL_RSA_PRIMITIVE
    BIGNUM *e = NULL, *n1 = NULL, *ct = NULL;
    const BIGNUM *n = NULL;
    ACVP_RSA_PRIM_TC    *tc;
    RSA *rsa = NULL;
    int rv = 1, i;

    tc = test_case->tc.rsa_prim;

    rsa = RSA_new();
    e = BN_new();
    if (!e) {
        printf("Failed to allocate BN for e\n");
        goto err;
    }

    if (tc->modulo != 2048) {
        printf("Error, modulo not 2048\n");
        goto err;
    }

    if (!tc->cipher || !tc->cipher_len) {
        printf("Error, invlalid cipher information\n");
        goto err;
    }

    /* only support 0x10001 */
    if (!BN_set_word(e, RSA_F4)) {
        printf("Error converting e to BN\n");
        goto err;
    }

    tc->e_len = BN_bn2bin(e, tc->e);

    /* generate key pair, this can take a while to get one ct < pk-1 */
    if (!RSA_generate_key_ex(rsa, tc->modulo, e, NULL)) {
        printf("Error generating key\n");
        goto err;
    }
    RSA_get0_key(rsa, &n, NULL, NULL);
    tc->n_len = BN_bn2bin(n, tc->n);
    ct = BN_bin2bn(tc->cipher, tc->cipher_len, NULL);

/* get key and compare to cipherText, if 1 < ct < pk-1 is not true then fail. */

    n1 = BN_dup(n);
    BN_sub_word(n1, 1);
    i = BN_cmp(ct, n1);
    tc->disposition = 1;
    if (i < 0) {
        tc->pt_len = RSA_private_decrypt(tc->cipher_len, tc->cipher, tc->pt, rsa, RSA_NO_PADDING);
        if (tc->pt_len == -1) {
            printf("Error decrypting\n");
            goto err;
        }
        if (tc->pass) tc->pass--;
    } else {
        tc->disposition = 0;
        if (tc->fail) tc->fail--;
    }

    rv = 0;
err:
    if (e) BN_free(e);
    if (ct) BN_free(ct);
    if (n1) BN_free(n1);
    if (rsa) RSA_free(rsa);
    return rv;
#else
    return 1;
#endif
}

int app_rsa_sigprim_handler(ACVP_TEST_CASE *test_case) {
    BIGNUM *e = NULL, *n = NULL, *d = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY_CTX *sign_ctx = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
#else
    BIGNUM  *tmp_e = NULL, *tmp_n = NULL, *tmp_d = NULL;
    RSA *rsa = NULL;
#endif
    ACVP_RSA_PRIM_TC *tc;
    int rv = 1;

    tc = test_case->tc.rsa_prim;

    if (tc->key_format != ACVP_RSA_PRIM_KEYFORMAT_STANDARD) {
        printf("Key Format must be standard\n");
        goto err;
    }

    if (!tc->e || !tc->d || !tc->n) {
        printf("Missing arguments e|d|n\n");
        goto err;
    }

    tc->disposition = 1;

    e = BN_bin2bn(tc->e, tc->e_len, NULL);
    if (!e) {
        printf("Failed to allocate BN for e\n");
        goto err;
    }

    n = BN_bin2bn(tc->n, tc->n_len, NULL);
    if (!n) {
        printf("Failed to allocate BN for n\n");
        goto err;
    }
    d = BN_bin2bn(tc->d, tc->d_len, NULL);
    if (!d) {
        printf("Failed to allocate BN for d\n");
        goto err;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L

    tc->sig_len = tc->modulo;

    pbld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(pbld, "d", d);
    OSSL_PARAM_BLD_push_BN(pbld, "n", n);
    OSSL_PARAM_BLD_push_BN(pbld, "e", e);
    params = OSSL_PARAM_BLD_to_param(pbld);

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
    if (EVP_PKEY_sign(sign_ctx, tc->signature, (size_t *)&tc->sig_len, tc->msg, tc->msg_len) != 1) {
        tc->disposition = 0;
    }

#else
    rsa = RSA_new();
    tmp_d = BN_dup(d);
    tmp_n = BN_dup(n);
    tmp_e = BN_dup(e);
    RSA_set0_key(rsa, tmp_n, tmp_e, tmp_d);

    tc->sig_len = RSA_private_encrypt(tc->msg_len, tc->msg, tc->signature, rsa, RSA_NO_PADDING);
    if (tc->sig_len == -1) {
       tc->disposition = 0;
    }
#endif

    rv = 0;

err:
    if (e) BN_free(e);
    if (n) BN_free(n);
    if (d) BN_free(d);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (sign_ctx) EVP_PKEY_CTX_free(sign_ctx);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (pkey) EVP_PKEY_free(pkey);
#else
    if (rsa) RSA_free(rsa);
#endif

    return rv;
}

#else /* Runtime, SSL < 3.0 */
int app_rsa_keygen_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

int app_rsa_sig_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

int app_rsa_sigprim_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

#endif /* SSL >= 3 or ACVP_NO_RUNTIME */

