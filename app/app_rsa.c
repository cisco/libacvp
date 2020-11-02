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
#include <openssl/rsa.h>
#include "app_lcl.h"
#include "safe_lib.h"
#ifdef ACVP_NO_RUNTIME
#include "app_fips_lcl.h" /* All regular OpenSSL headers must come before here */
#include <openssl/ossl_typ.h>

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
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    BIGNUM *p = NULL, *q = NULL, *n = NULL, *d = NULL;
#else
    const BIGNUM *p1 = NULL, *q1 = NULL, *n1 = NULL, *d1 = NULL;
#endif
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

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    p = rsa->p;
    q = rsa->q;
    n = rsa->n;
    d = rsa->d;
    tc->p_len = BN_bn2bin(p, tc->p);
    tc->q_len = BN_bn2bin(q, tc->q);
    tc->n_len = BN_bn2bin(n, tc->n);
    tc->d_len = BN_bn2bin(d, tc->d);
#else
    RSA_get0_key(rsa, &n1, NULL, &d1);
    RSA_get0_factors(rsa, &p1, &q1);

    tc->p_len = BN_bn2bin(p1, tc->p);
    tc->q_len = BN_bn2bin(q1, tc->q);
    tc->n_len = BN_bn2bin(n1, tc->n);
    tc->d_len = BN_bn2bin(d1, tc->d);
#endif

    rv = 0;
err:
    if (rsa) FIPS_rsa_free(rsa);
    if (e) BN_free(e);
    return rv;
}


int app_rsa_sig_handler(ACVP_TEST_CASE *test_case) {
    const EVP_MD *tc_md = NULL;
    int siglen, pad_mode;
    BIGNUM *bn_e = NULL, *e = NULL, *n = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    BIGNUM  *tmp_e = NULL, *tmp_n = NULL;
    const BIGNUM  *tmp_e1 = NULL, *tmp_n1 = NULL;
#endif
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
 #if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
    case ACVP_SHA512_224:
        tc_md = EVP_sha512_224();
        break;
    case ACVP_SHA512_256:
        tc_md = EVP_sha512_256();
        break;
#else
    case ACVP_SHA512_224:
    case ACVP_SHA512_256:
#endif
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

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        rsa->e = BN_dup(e);
        rsa->n = BN_dup(n);
#else
        tmp_e = BN_dup(e);
        tmp_n = BN_dup(n);
        RSA_set0_key(rsa, tmp_n, tmp_e, NULL);
#endif

        tc->ver_disposition = FIPS_rsa_verify(rsa, tc->msg, tc->msg_len, tc_md, 
                                              pad_mode, salt_len, NULL, tc->signature, 
                                              tc->sig_len);
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
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
            e = BN_dup(group_rsa->e);
            n = BN_dup(group_rsa->n);
#else
            RSA_get0_key(group_rsa, &tmp_n1, &tmp_e1, NULL);
            e = BN_dup(tmp_e1);
            n = BN_dup(tmp_n1);
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

            if (!FIPS_rsa_sign(group_rsa, tc->msg, tc->msg_len, tc_md, 
                               pad_mode, salt_len, NULL,
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
#else
int app_rsa_keygen_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

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
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    BIGNUM  *tmp_e = NULL, *tmp_n = NULL;
#endif
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
 #if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
    case ACVP_SHA512_224:
        tc_md = EVP_sha512_224();
        break;
    case ACVP_SHA512_256:
        tc_md = EVP_sha512_256();
        break;
#else
    case ACVP_SHA512_224:
    case ACVP_SHA512_256:
#endif
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

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        rsa->e = BN_dup(e);
        rsa->n = BN_dup(n);
#else
        tmp_e = BN_dup(e);
        tmp_n = BN_dup(n);
        RSA_set0_key(rsa, tmp_n, tmp_e, NULL);
#endif

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
#endif // ACVP_NO_RUNTIME

int app_rsa_decprim_handler(ACVP_TEST_CASE *test_case) {
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
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    n = BN_dup(rsa->n);
#else
    RSA_get0_key(rsa, &n, NULL, NULL);
#endif
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
}

int app_rsa_sigprim_handler(ACVP_TEST_CASE *test_case) {
    BIGNUM *e = NULL, *n = NULL, *d = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    BIGNUM  *tmp_e = NULL, *tmp_n = NULL, *tmp_d = NULL;
#endif
    ACVP_RSA_PRIM_TC    *tc;
    RSA *rsa = NULL;
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

    rsa = RSA_new();
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

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    rsa->d = BN_dup(d);
    rsa->n = BN_dup(n);
    rsa->e = BN_dup(e);
#else
    tmp_d = BN_dup(d);
    tmp_n = BN_dup(n);
    tmp_e = BN_dup(e);
    RSA_set0_key(rsa, tmp_n, tmp_e, tmp_d);
#endif
    tc->disposition = 1;
    tc->sig_len = RSA_private_encrypt(tc->msg_len, tc->msg, tc->signature, rsa, RSA_NO_PADDING);
    if (tc->sig_len == -1) {
        tc->disposition = 0;
    }
    rv = 0;
err:
    if (e) BN_free(e);
    if (n) BN_free(n);
    if (d) BN_free(d);
    if (rsa) RSA_free(rsa);
    return rv;
}



