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
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include "app_lcl.h"
#ifdef ACVP_NO_RUNTIME
#include "app_fips_lcl.h" /* All regular OpenSSL headers must come before here */

static BIGNUM *ecdsa_group_Qx = NULL;
static BIGNUM *ecdsa_group_Qy = NULL;
static EC_KEY *ecdsa_group_key = NULL;
static int ecdsa_current_tg = 0;

void app_ecdsa_cleanup(void) {
    if (ecdsa_group_Qx) BN_free(ecdsa_group_Qx);
    ecdsa_group_Qx = NULL;
    if (ecdsa_group_Qy) BN_free(ecdsa_group_Qy);
    ecdsa_group_Qy = NULL;
    if (ecdsa_group_key) EC_KEY_free(ecdsa_group_key);
    ecdsa_group_key = NULL;
}

static int ec_get_pubkey(EC_KEY *key, BIGNUM *x, BIGNUM *y) {
    const EC_POINT *pt;
    const EC_GROUP *grp;
    const EC_METHOD *meth;
    int rv = 0;
    BN_CTX *ctx;

    ctx = BN_CTX_new();
    if (!ctx) return 0;

    grp = EC_KEY_get0_group(key);
    if (!grp) goto end;

    pt = EC_KEY_get0_public_key(key);
    if (!pt) goto end;

    meth = EC_GROUP_method_of(grp);
    if (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field) {
        rv = EC_POINT_get_affine_coordinates_GFp(grp, pt, x, y, ctx);
    } else {
        rv = EC_POINT_get_affine_coordinates_GF2m(grp, pt, x, y, ctx);
    }

end:
    if (ctx) BN_CTX_free(ctx);
    return rv;
}

int app_ecdsa_handler(ACVP_TEST_CASE *test_case) {
    ACVP_ECDSA_TC    *tc;
    int rv = 1;
    ACVP_CIPHER mode;
    const EVP_MD *md = NULL;
    ECDSA_SIG *sig = NULL;

    int nid = NID_undef, rc = 0, msg_len = 0;
    BIGNUM *Qx = NULL, *Qy = NULL;
    BIGNUM *r = NULL, *s = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
    const BIGNUM *a = NULL, *b = NULL;
#endif
    const BIGNUM *d = NULL;
    EC_KEY *key = NULL;


    if (!test_case) {
        printf("No test case found\n");
        return 1;
    }
    tc = test_case->tc.ecdsa;
    if (!tc) {
        printf("\nError: test case not found in ECDSA handler\n");
        return 1;
    }
    mode = tc->cipher;

    if (mode == ACVP_ECDSA_SIGGEN || mode == ACVP_ECDSA_SIGVER) {
        switch (tc->hash_alg) {
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
            printf("Unsupported hash alg in ECDSA\n");
            goto err;
        }
    }

    switch (tc->curve) {
    case ACVP_EC_CURVE_B233:
        nid = NID_sect233r1;
        break;
    case ACVP_EC_CURVE_B283:
        nid = NID_sect283r1;
        break;
    case ACVP_EC_CURVE_B409:
        nid = NID_sect409r1;
        break;
    case ACVP_EC_CURVE_B571:
        nid = NID_sect571r1;
        break;
    case ACVP_EC_CURVE_K233:
        nid = NID_sect233k1;
        break;
    case ACVP_EC_CURVE_K283:
        nid = NID_sect283k1;
        break;
    case ACVP_EC_CURVE_K409:
        nid = NID_sect409k1;
        break;
    case ACVP_EC_CURVE_K571:
        nid = NID_sect571k1;
        break;
    case ACVP_EC_CURVE_P224:
        nid = NID_secp224r1;
        break;
    case ACVP_EC_CURVE_P256:
        nid = NID_X9_62_prime256v1;
        break;
    case ACVP_EC_CURVE_P384:
        nid = NID_secp384r1;
        break;
    case ACVP_EC_CURVE_P521:
        nid = NID_secp521r1;
        break;
    default:
    case ACVP_EC_CURVE_P192:
    case ACVP_EC_CURVE_B163:
    case ACVP_EC_CURVE_K163:
    case ACVP_EC_CURVE_START:
    case ACVP_EC_CURVE_END:
        printf("Unsupported curve\n");
        goto err;
    }

    switch (mode) {
    case ACVP_ECDSA_KEYGEN:
        Qx = FIPS_bn_new();
        Qy = FIPS_bn_new();
        if (!Qx || !Qy) {
            printf("Error BIGNUM malloc\n");
            goto err;
        }

        key = EC_KEY_new_by_curve_name(nid);
        if (!key) {
            printf("Failed to instantiate ECDSA key\n");
            goto err;
        }

        if (!EC_KEY_generate_key(key)) {
            printf("Error generating ECDSA key\n");
            goto err;
        }

        if (!ec_get_pubkey(key, Qx, Qy)) {
            printf("Error getting ECDSA key attributes\n");
            goto err;
        }

        d = EC_KEY_get0_private_key(key);

        tc->qx_len = BN_bn2bin(Qx, tc->qx);
        tc->qy_len = BN_bn2bin(Qy, tc->qy);
        tc->d_len = BN_bn2bin(d, tc->d);
        break;
    case ACVP_ECDSA_KEYVER:
        Qx = FIPS_bn_new();
        Qy = FIPS_bn_new();
        if (!tc->qx || !tc->qy) {
            printf("missing qx or qy: ecdsa keyver\n");
            goto err;
        }
        BN_bin2bn(tc->qx, tc->qx_len, Qx);
        BN_bin2bn(tc->qy, tc->qy_len, Qy);
        if (!Qx || !Qy) {
            printf("Error BIGNUM conversion\n");
            goto err;
        }

        key = EC_KEY_new_by_curve_name(nid);
        if (!key) {
            printf("Failed to instantiate ECDSA key\n");
            goto err;
        }

        if (EC_KEY_set_public_key_affine_coordinates(key, Qx, Qy) == 1) {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_PASS;
        } else {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_FAIL;
        }
        break;
    case ACVP_ECDSA_SIGGEN:
        if (ecdsa_current_tg != tc->tg_id) {
            ecdsa_current_tg = tc->tg_id;

            /* Free the group objects before re-allocation */
            if (ecdsa_group_key) EC_KEY_free(ecdsa_group_key);
            ecdsa_group_key = NULL;
            if (ecdsa_group_Qx) BN_free(ecdsa_group_Qx);
            ecdsa_group_Qx = NULL;
            if (ecdsa_group_Qy) BN_free(ecdsa_group_Qy);
            ecdsa_group_Qy = NULL;

            ecdsa_group_Qx = FIPS_bn_new();
            ecdsa_group_Qy = FIPS_bn_new();
            if (!ecdsa_group_Qx || !ecdsa_group_Qy) {
                printf("Error BIGNUM malloc\n");
                goto err;
            }
            ecdsa_group_key = EC_KEY_new_by_curve_name(nid);
            if (!ecdsa_group_key) {
                printf("Failed to instantiate ECDSA key\n");
                goto err;
            }

            if (!EC_KEY_generate_key(ecdsa_group_key)) {
                printf("Error generating ECDSA key\n");
                goto err;
            }

            if (!ec_get_pubkey(ecdsa_group_key, ecdsa_group_Qx, ecdsa_group_Qy)) {
                printf("Error getting ECDSA key attributes\n");
                goto err;
            }
        }
        msg_len = tc->msg_len;
        if (!tc->message) {
            printf("ecdsa siggen missing msg\n");
            goto err;
        }
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        sig = FIPS_ecdsa_sign(ecdsa_group_key, tc->message, msg_len, md);
#else
        sig = FIPS_ecdsa_sign_md(ecdsa_group_key, tc->message, msg_len, md);
#endif

        if (!sig) {
            printf("Error signing message\n");
            goto err;
        }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        r = sig->r;
        s = sig->s;
#else
        ECDSA_SIG_get0(sig, &a, &b);
        r = BN_dup(a);
        s = BN_dup(b);
#endif

        tc->qx_len = BN_bn2bin(ecdsa_group_Qx, tc->qx);
        tc->qy_len = BN_bn2bin(ecdsa_group_Qy, tc->qy);
        tc->r_len = BN_bn2bin(r, tc->r);
        tc->s_len = BN_bn2bin(s, tc->s);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        BN_free(s);
        BN_free(r);
# endif
        break;
    case ACVP_ECDSA_SIGVER:
        if (!tc->message) {
            printf("missing sigver message - nothing to verify\n");
            goto err;
        }
        if (!tc->r) {
            printf("missing r ecdsa sigver\n");
            goto err;
        }
        if (!tc->s) {
            printf("missing s ecdsa sigver\n");
            goto err;
        }
        sig = ECDSA_SIG_new();
        if (!sig) {
            printf("Error generating ecdsa signature\n");
            goto err;
        }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        r = sig->r;
        s = sig->s;
#else
        r = FIPS_bn_new();
        s = FIPS_bn_new();
        ECDSA_SIG_set0(sig, r, s);
#endif

        Qx = FIPS_bn_new();
        Qy = FIPS_bn_new();

        if (!Qx || !Qy) {
            printf("Error BIGNUM conversion\n");
            goto err;
        }
        BN_bin2bn(tc->qx, tc->qx_len, Qx);
        BN_bin2bn(tc->qy, tc->qy_len, Qy);

        if (!r || !s) {
            printf("Error BIGNUM conversion\n");
            goto err;
        }
        BN_bin2bn(tc->r, tc->r_len, r);
        BN_bin2bn(tc->s, tc->s_len, s);

        key = EC_KEY_new_by_curve_name(nid);
        if (!key) {
            printf("Failed to instantiate ECDSA key\n");
            goto err;
        }

        rc = EC_KEY_set_public_key_affine_coordinates(key, Qx, Qy);
        if (rc != 1) {
            printf("Error setting ECDSA coordinates\n");
            goto points_err;
        }

        if (!tc->message) {
            printf("ecdsa siggen missing msg\n");
            goto err;
        }
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        if (FIPS_ecdsa_verify(key, tc->message, tc->msg_len, md, sig) == 1) {
#else
        if (FIPS_ecdsa_verify_md(key, tc->message, tc->msg_len, md, sig) == 1) {
#endif
            tc->ver_disposition = ACVP_TEST_DISPOSITION_PASS;
        } else {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_FAIL;
        }
points_err:
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
        printf("Unsupported ECDSA mode\n");
        break;
    }
    rv = 0;

err:
    if (sig) FIPS_ecdsa_sig_free(sig);
    if (Qx) FIPS_bn_free(Qx);
    if (Qy) FIPS_bn_free(Qy);
    if (key) EC_KEY_free(key);
    return rv;
}
#else
int app_ecdsa_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}
#endif // ACVP_NO_RUNTIME

