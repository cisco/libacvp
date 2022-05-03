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
#include <openssl/ec.h>
#include <openssl/param_build.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L && defined ACVP_NO_RUNTIME
#include "app_fips_lcl.h" /* All regular OpenSSL headers must come before here */
#endif
#include "app_lcl.h"
#include "safe_mem_lib.h"

#define KAS_ECC_Z_MAX 512

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
int app_kas_ecc_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KAS_ECC_TC *tc = NULL;
    int nid = NID_undef, s_key_size = 0, i_key_size = 0, rv = 1;
    size_t z_len = 0;
    OSSL_PARAM_BLD *serv_pbld = NULL, *iut_pbld = NULL;
    OSSL_PARAM *serv_params = NULL, *iut_params = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL, *der_ctx = NULL;
    EVP_PKEY *serv_pkey = NULL, *iut_pkey = NULL;
    char *s_pub_key = NULL, *i_pub_key = NULL;
    unsigned char *z = NULL;
    BIGNUM *ix = NULL, *iy = NULL, *ik = NULL;
    const char *curve = NULL;
    tc = test_case->tc.kas_ecc;
    nid = get_nid_for_curve(tc->curve);
    if (nid == NID_undef) {
        printf("Unable to get curve NID in KAS-ECC\n");
        goto err;
    }
    curve = OSSL_EC_curve_nid2name(nid);
    if (!curve) {
        printf("Unable to lookup curve name for ECDSA\n");
        goto err;
    }

    s_pub_key = ec_point_to_pub_key(tc->psx, tc->psxlen, tc->psy, tc->psylen, &s_key_size);
    if (!s_pub_key) {
        printf("Error generating server pub key in KAS-ECC\n");
        goto err;
    }

    /* Generate server pkey info */
    serv_pbld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(serv_pbld, "group", curve, 0);
    OSSL_PARAM_BLD_push_octet_string(serv_pbld, "pub", s_pub_key, s_key_size);
    OSSL_PARAM_BLD_push_int(serv_pbld, "use-cofactor-flag", 1);
    serv_params = OSSL_PARAM_BLD_to_param(serv_pbld);
    if (!serv_params) {
        printf("Error generating params in KAS-ECC\n");
        goto err;
    }
    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pkey_ctx) {
        printf("Error creating pkey ctx in KAS-ECC\n");
        goto err;
    }
    if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
        printf("Error initializing fromdata in KAS-ECC\n");
        goto err;
    }
    if (EVP_PKEY_fromdata(pkey_ctx, &serv_pkey, EVP_PKEY_PUBLIC_KEY, serv_params) != 1) {
        printf("Error performing fromdata in KAS-ECC\n");
        goto err;
    }

    /* generate our pkey info */
    iut_pbld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(iut_pbld, "group", curve, 0);
    OSSL_PARAM_BLD_push_int(iut_pbld, "use-cofactor-flag", 1);
    if (tc->test_type == ACVP_KAS_ECC_TT_VAL) {
        i_pub_key = ec_point_to_pub_key(tc->pix, tc->pixlen, tc->piy, tc->piylen, &i_key_size);
        if (!i_pub_key) {
            printf("Error generating IUT pub key in KAS-ECC\n");
            goto err;
        }
        OSSL_PARAM_BLD_push_octet_string(iut_pbld, "pub", i_pub_key, i_key_size);
        ik = BN_bin2bn(tc->d, tc->dlen, NULL);
        OSSL_PARAM_BLD_push_BN(iut_pbld, "priv", ik);
    }
    iut_params = OSSL_PARAM_BLD_to_param(iut_pbld);
    if (!iut_params) {
        printf("Error generating params in KAS-ECC\n");
        goto err;
    }

    if (tc->test_type == ACVP_KAS_ECC_TT_VAL) {
        if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
            printf("Error initializing fromdata in KAS-ECC\n");
            goto err;
        }
        if (EVP_PKEY_fromdata(pkey_ctx, &iut_pkey, EVP_PKEY_KEYPAIR, iut_params) != 1) {
            printf("Error performing fromdata in KAS-ECC\n");
            goto err;
        }
    } else {
        if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
            printf("Error initializing keygen in KAS-ECC\n");
            goto err;
        }
        if (EVP_PKEY_CTX_set_params(pkey_ctx, iut_params) != 1) {
            printf("Error setting params in KAS-ECC\n");
            goto err;
        }
        if (EVP_PKEY_keygen(pkey_ctx, &iut_pkey) != 1) {
            printf("Error performing keygen in KAS-ECC\n");
            goto err;
        }
    }

    if (tc->test_type == ACVP_KAS_ECC_TT_AFT) {
        /* get peer X and Y for test response */
        EVP_PKEY_get_bn_param(iut_pkey, "qx", &ix);
        EVP_PKEY_get_bn_param(iut_pkey, "qy", &iy);
        EVP_PKEY_get_bn_param(iut_pkey, "priv", &ik);
        if (!ix || !iy || !ik) {
            printf("Error getting key values from IUT pkey in KAS-ECC\n");
            goto err;
        }
        tc->pixlen = BN_bn2bin(ix, tc->pix);
        tc->piylen = BN_bn2bin(iy, tc->piy);
        tc->dlen = BN_bn2bin(ik, tc->d);
    }

    /* Finally, derive secret Z and add to test response */
    der_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, iut_pkey, NULL);
    if (!der_ctx) {
        printf("Error creating derive ctx in KAS-ECC\n");
        goto err;
    }
    if (EVP_PKEY_derive_init(der_ctx) != 1) {
        printf("Error initializing derive in KAS-ECC\n");
        goto err;
    }
    if (EVP_PKEY_derive_set_peer(der_ctx, serv_pkey) != 1) {
        printf("Error setting peer key in KAS-ECC\n");
        goto err;
    }
    EVP_PKEY_derive(der_ctx, NULL, &z_len);
    z = calloc(z_len, 1);
    if (!z) {
        printf("Error allocating memory for shared secret in KAS-ECC\\n");
        goto err;
    }
    if (EVP_PKEY_derive(der_ctx, z, &z_len) != 1) {
        printf("Error deriving secret in KAS-ECC\n");
        goto err;
    }
    if (tc->mode == ACVP_KAS_ECC_MODE_CDH) {
        tc->zlen = (int)z_len;
        memcpy_s(tc->z, KAS_ECC_Z_MAX, z, z_len);
    } else {
        tc->chashlen = (int)z_len;
        memcpy_s(tc->chash, KAS_ECC_Z_MAX, z, z_len);
    }
    rv = 0;
err:
    if (s_pub_key) free(s_pub_key);
    if (i_pub_key) free(i_pub_key);
    if (z) free (z);
    if (serv_pbld) OSSL_PARAM_BLD_free(serv_pbld);
    if (iut_pbld) OSSL_PARAM_BLD_free(iut_pbld);
    if (serv_params) OSSL_PARAM_free(serv_params);
    if (iut_params) OSSL_PARAM_free(iut_params);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (der_ctx) EVP_PKEY_CTX_free(der_ctx);
    if (serv_pkey) EVP_PKEY_free(serv_pkey);
    if (iut_pkey) EVP_PKEY_free(iut_pkey);
    if (ix) BN_free(ix);
    if (iy) BN_free(iy);
    if (ik) BN_free(ik);
    return rv;
}

int app_kas_ffc_handler(ACVP_TEST_CASE *test_case) {
    return 0;
}

int app_kas_ifc_handler(ACVP_TEST_CASE *test_case) {
    return 0;
}

int app_kts_ifc_handler(ACVP_TEST_CASE *test_case) {
    return 0;
}

int app_safe_primes_handler(ACVP_TEST_CASE *test_case) {
    return 0;
}

#elif defined ACVP_NO_RUNTIME
#  define get_rfc2409_prime_768 BN_get_rfc2409_prime_768
#  define get_rfc2409_prime_1024 BN_get_rfc2409_prime_1024
#  define get_rfc3526_prime_1536 BN_get_rfc3526_prime_1536
#  define get_rfc3526_prime_2048 BN_get_rfc3526_prime_2048
#  define get_rfc3526_prime_3072 BN_get_rfc3526_prime_3072
#  define get_rfc3526_prime_4096 BN_get_rfc3526_prime_4096
#  define get_rfc3526_prime_6144 BN_get_rfc3526_prime_6144
#  define get_rfc3526_prime_8192 BN_get_rfc3526_prime_8192

static EC_POINT *make_peer(EC_GROUP *group, BIGNUM *x, BIGNUM *y) {
    EC_POINT *peer = NULL;
    BN_CTX *c = NULL;
    int rv = 0;

    peer = EC_POINT_new(group);
    if (!peer) {
        printf("EC_POINT_new failed\n");
        return NULL;
    }
    c = BN_CTX_new();
    if (!c) {
        printf("BN_CTX_new failed\n");
        goto end;
    }
#if defined ACVP_NO_RUNTIME && FIPS_MODULE_VERSION_NUMBER >= 0x70000002L
    rv = EC_POINT_set_affine_coordinates(group, peer, x, y, c);
#else
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field) {
        rv = EC_POINT_set_affine_coordinates_GFp(group, peer, x, y, c);
    } else {
        rv = EC_POINT_set_affine_coordinates_GF2m(group, peer, x, y, c);
    }
#endif

end:
    if (rv == 0) {
        if (peer) EC_POINT_free(peer);
        peer = NULL;
    }
    if (c) BN_CTX_free(c);
    return peer;
}

static int ec_print_key(ACVP_KAS_ECC_TC *tc, EC_KEY *key) {
    const EC_POINT *pt;
    const EC_GROUP *grp;
    const EC_METHOD *meth;
    int rv = 0;
    BIGNUM *tx, *ty;
    const BIGNUM *d = NULL;
    BN_CTX *ctx;

    ctx = BN_CTX_new();
    if (!ctx) {
        printf("BN_CTX_new failed\n");
        return 0;
    }
    tx = BN_CTX_get(ctx);
    ty = BN_CTX_get(ctx);
    if (!tx || !ty) {
        BN_CTX_free(ctx);
        printf("BN_CTX_get failed\n");
        return 0;
    }
    grp = EC_KEY_get0_group(key);
    pt = EC_KEY_get0_public_key(key);
    d = EC_KEY_get0_private_key(key);
    meth = EC_GROUP_method_of(grp);
    if (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field) {
        rv = EC_POINT_get_affine_coordinates_GFp(grp, pt, tx, ty, ctx);
    } else {
        rv = EC_POINT_get_affine_coordinates_GF2m(grp, pt, tx, ty, ctx);
    }

    if (tc->test_type == ACVP_KAS_ECC_TT_AFT) {
        tc->pixlen = BN_bn2bin(tx, tc->pix);
        tc->piylen = BN_bn2bin(ty, tc->piy);
        if (tc->mode == ACVP_KAS_ECC_MODE_COMPONENT) {
            tc->dlen = BN_bn2bin(d, tc->d);
        }
    }
    BN_CTX_free(ctx);
    return rv;
}

int app_kas_ecc_handler(ACVP_TEST_CASE *test_case) {
    EC_GROUP *group = NULL;
    ACVP_KAS_ECC_TC         *tc;
    int nid = 0;
    EC_KEY *ec = NULL;
    EC_POINT *peerkey = NULL;
    unsigned char *Z = NULL;
    int Zlen = 0;
    BIGNUM *cx = NULL, *cy = NULL, *ix = NULL, *iy = NULL, *id = NULL;
    const EVP_MD *md = NULL;
    int rv = 1;

    tc = test_case->tc.kas_ecc;

    nid = get_nid_for_curve(tc->curve);
    if (nid == NID_undef) {
        printf("Unable to get curve NID in KAS-ECC\n");
        goto error;
    }

    if (tc->mode == ACVP_KAS_ECC_MODE_COMPONENT) {
        md = get_md_for_hash_alg(tc->md);
        if (!md) {
            printf("Unable to get MD in KAS-ECC\n");
            goto error;
        }
    }
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        printf("No group from curve name %d\n", nid);
        return rv;
    }

    ec = EC_KEY_new();
    if (ec == NULL) {
        printf("No EC_KEY_new\n");
        goto error;
    }
    EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH);
    if (!EC_KEY_set_group(ec, group)) {
        printf("No EC_KEY_set_group\n");
        goto error;
    }

    if (!tc->psx || !tc->psy) {
        printf("missing required psx or psy from kas ecc\n");
        goto error;
    }

    cx = FIPS_bn_new();
    cy = FIPS_bn_new();
    if (!cx || !cy) {
        printf("BN_new failed psx psy\n");
        goto error;
    }
    BN_bin2bn(tc->psx, tc->psxlen, cx);
    BN_bin2bn(tc->psy, tc->psylen, cy);

    peerkey = make_peer(group, cx, cy);
    if (peerkey == NULL) {
        printf("Peerkey failed\n");
        goto error;
    }
    if (tc->test_type == ACVP_KAS_ECC_TT_VAL) {
        if (!tc->pix || !tc->piy || !tc->d) {
            printf("missing required pix, piy, or d from kas ecc\n");
            goto error;
        }
        ix = FIPS_bn_new();
        iy = FIPS_bn_new();
        id = FIPS_bn_new();
        if (!ix || !iy || !id) {
            printf("BN_new failed pix piy d");
            goto error;
        }
        BN_bin2bn(tc->pix, tc->pixlen, ix);
        BN_bin2bn(tc->piy, tc->piylen, iy);
        BN_bin2bn(tc->d, tc->dlen, id);

        EC_KEY_set_public_key_affine_coordinates(ec, ix, iy);
        EC_KEY_set_private_key(ec, id);
    } else {
        if (!EC_KEY_generate_key(ec)) {
            printf("EC_KEY_generate_key failed\n");
            goto error;
        }
    }

    ec_print_key(tc, ec);
    Zlen = (EC_GROUP_get_degree(group) + 7) / 8;
    if (!Zlen) {
        printf("Zlen degree failure\n");
        goto error;
    }
    Z = OPENSSL_malloc(Zlen);
    if (!Z) {
        printf("Malloc failure\n");
        goto error;
    }
    if (!ECDH_compute_key(Z, Zlen, peerkey, ec, 0)) {
        printf("ECDH_compute_key failure\n");
        goto error;
    }

    if (tc->test_type == ACVP_KAS_ECC_TT_AFT) {
        memcpy_s(tc->z, KAS_ECC_Z_MAX, Z, Zlen);
        tc->zlen = Zlen;
    }
    if (tc->mode == ACVP_KAS_ECC_MODE_COMPONENT) {
        if (tc->md == ACVP_NO_SHA) {
            tc->chashlen = Zlen;
            memcpy_s(tc->chash, KAS_ECC_Z_MAX, Z, Zlen);
        } else {
            FIPS_digest(Z, Zlen, (unsigned char *)tc->chash, NULL, md);
            tc->chashlen = EVP_MD_size(md);
        }
    }
    rv = 0;

error:
    if (Z) {
        OPENSSL_cleanse(Z, Zlen);
        FIPS_free(Z);
    }
    if (ec) EC_KEY_free(ec);
    if (peerkey) EC_POINT_free(peerkey);
    if (group) EC_GROUP_free(group);
    if (cx) BN_free(cx);
    if (cy) BN_free(cy);
    if (ix) BN_free(ix);
    if (iy) BN_free(iy);
    if (id) BN_free(id);
    return rv;
}

#ifndef OPENSSL_NO_DSA

int app_kas_ffc_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KAS_FFC_TC         *tc;
    const EVP_MD *md = NULL;
    int rv = 1;
    unsigned char *Z = NULL;
    int Zlen = 0;
    DH *dh = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;
    BIGNUM *peerkey = NULL;
    BIGNUM *tmp_p = NULL, *tmp_q = NULL, *tmp_g = NULL;
    BIGNUM *tmp_pub_key = NULL, *tmp_priv_key = NULL;
    const BIGNUM *tmp_key = NULL;
    int is_modp = 0;

    tc = test_case->tc.kas_ffc;

    md = get_md_for_hash_alg(tc->md);
    if (!md) {
        printf("Unable to get MD in KAS-ECC\n");
        goto error;
    }

    p = BN_new();
    q = BN_new();
    g = BN_new();
    if (!p || !q || !g) {
        printf("BN_new failed p q g\n");
        goto error;
    }

    switch (tc->dgm)
    {
    case ACVP_KAS_FFC_FB:
    case ACVP_KAS_FFC_FC:
        dh = DH_new();
        if (!dh) {
            return rv;
        }

        if (!tc->p || !tc->q || !tc->g || !tc->eps ||
            !tc->plen || !tc->qlen || !tc->glen || !tc->epslen) {
            printf("Missing required p,q,g, or eps\n");
            goto error;
        }

        BN_bin2bn(tc->p, tc->plen, p);
        BN_bin2bn(tc->q, tc->qlen, q);
        BN_bin2bn(tc->g, tc->glen, g);
        tmp_p = BN_dup(p);
        tmp_q = BN_dup(q);
        tmp_g = BN_dup(g);
        DH_set0_pqg(dh, tmp_p, tmp_q, tmp_g);
        break;
   case ACVP_KAS_FFC_MODP2048:
        is_modp = 1;
        get_rfc3526_prime_2048(p);
        get_rfc3526_prime_2048(q);
        break;
    case ACVP_KAS_FFC_MODP3072:
        is_modp = 1;
        get_rfc3526_prime_3072(p);
        get_rfc3526_prime_3072(q);
        break;
    case ACVP_KAS_FFC_MODP4096:
        is_modp = 1;
        get_rfc3526_prime_4096(p);
        get_rfc3526_prime_4096(q);
        break;
    case ACVP_KAS_FFC_MODP6144:
        is_modp = 1;
        get_rfc3526_prime_6144(p);
        get_rfc3526_prime_6144(q);
        break;
    case ACVP_KAS_FFC_MODP8192:
        is_modp = 1;
        get_rfc3526_prime_8192(p);
        get_rfc3526_prime_8192(q);
        break;
    case ACVP_KAS_FFC_FFDHE2048:
        dh = DH_new_by_nid(NID_ffdhe2048);
        break;
    case ACVP_KAS_FFC_FFDHE3072:
        dh = DH_new_by_nid(NID_ffdhe3072);
        break;
    case ACVP_KAS_FFC_FFDHE4096:
        dh = DH_new_by_nid(NID_ffdhe4096);
        break;
    case ACVP_KAS_FFC_FFDHE6144:
        dh = DH_new_by_nid(NID_ffdhe6144);
        break;
    case ACVP_KAS_FFC_FFDHE8192:
        dh = DH_new_by_nid(NID_ffdhe8192);
        break;
    case ACVP_KAS_FFC_FUNCTION:
    case ACVP_KAS_FFC_CURVE:
    case ACVP_KAS_FFC_ROLE:
    case ACVP_KAS_FFC_HASH:
    case ACVP_KAS_FFC_GEN_METH:
    case ACVP_KAS_FFC_KDF:
    default:
        printf("\nInvalid dgm");
        goto error;
        break;
    }

   if (is_modp) {
        dh = DH_new();
        if (!dh) {
            goto error;
        }
        BN_sub_word(q, 1);
        BN_div_word(q, 2);
        BN_set_word(g, 2);

        tmp_p = BN_dup(p);
        tmp_q = BN_dup(q);
        tmp_g = BN_dup(g);
        DH_set0_pqg(dh, tmp_p, tmp_q, tmp_g);
    }

    peerkey = BN_new();
    if (!peerkey) {
        printf("BN_new failed peerkey\n");
        goto error;
    }
    BN_bin2bn(tc->eps, tc->epslen, peerkey);


    if (tc->test_type == ACVP_KAS_FFC_TT_VAL) {
        if (!tc->epri || !tc->epui || !tc->eprilen || !tc->epuilen) {
            printf("missing epri or epui\n");
            goto error;
        }
        pub_key = BN_new();
        priv_key = BN_new();
        if (!pub_key || !priv_key) {
            printf("BN_new failed epri epui\n");
            goto error;
        }

        BN_bin2bn(tc->epri, tc->eprilen, priv_key);
        BN_bin2bn(tc->epui, tc->epuilen, pub_key);

        tmp_pub_key = BN_dup(pub_key);
        tmp_priv_key = BN_dup(priv_key);
        DH_set0_key(dh, tmp_pub_key, tmp_priv_key);
    }

    if (tc->test_type == ACVP_KAS_FFC_TT_AFT) {
        if (!DH_generate_key(dh)) {
            printf("DH_generate_key failed\n");
            goto error;
        }
    }
#define KAS_FFC_Z_MAX 2048
    Z = OPENSSL_malloc(KAS_FFC_Z_MAX);
    if (!Z) {
        printf("Malloc failed for Z\n");
        goto error;
    }

    if (!tc->chash || !tc->piut) {
        printf("Unallocated buffers in kas ffc tc, no place to put answers\n");
        goto error;
    }

    Zlen = DH_compute_key_padded(Z, peerkey, dh);
    if (Zlen <= 0) {
        FIPS_free(Z);
        Z = NULL;
        printf("DH_compute_key_padded failed\n");
        goto error;
    }
    if (tc->md == ACVP_NO_SHA) {
        tc->chashlen = Zlen;
        memcpy_s(tc->chash, KAS_FFC_Z_MAX, Z, Zlen);
    } else {
        FIPS_digest(Z, Zlen, (unsigned char *)tc->chash, NULL, md);
        tc->chashlen = EVP_MD_size(md);
    }

    if (tc->test_type == ACVP_KAS_FFC_TT_AFT) {
        memcpy_s(tc->z, KAS_FFC_Z_MAX, Z, Zlen);
        tc->zlen = Zlen;
    }

    DH_get0_key(dh, &tmp_key, NULL);
    tc->piutlen = BN_bn2bin(tmp_key, tc->piut);

    rv = 0;

error:
    if (Z) {
        OPENSSL_cleanse(Z, Zlen);
        FIPS_free(Z);
    }
    if (peerkey) BN_clear_free(peerkey);
    if (dh) DH_free(dh);
    if (pub_key) BN_free(pub_key);
    if (priv_key) BN_free(priv_key);
    if (p) BN_free(p);
    if (q) BN_free(q);
    if (g) BN_free(g);
    return rv;
}
#endif // OPENSSL_NO_DSA

int app_kas_ifc_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KAS_IFC_TC *tc;
    int rv = 1;
    BIGNUM *e = NULL, *n = NULL, *p = NULL, *q = NULL, *d = NULL;
    BIGNUM *tmp_e = NULL, *tmp_n = NULL;
    RSA *rsa = NULL;
    const EVP_MD *md = NULL;

    tc = test_case->tc.kas_ifc;

    md = get_md_for_hash_alg(tc->md);
    if (!md) {
        printf("Unable to get MD in KAS-ECC\n");
        goto error;
    }

    rsa = RSA_new();
    e = BN_new();
    n = BN_new();
    if (!e || !n) {
        printf("Failed to allocate BN for e or n\n");
        goto err;
    }
    if (!tc->e || !tc->n) {
        printf("Missing e or n from library\n");
        goto err;
    }
    /* we only support e = 0x10001 */
    BN_bin2bn(tc->e, tc->elen, e);
    BN_bin2bn(tc->n, tc->nlen, n);

    if (tc->kas_role == ACVP_KAS_IFC_INITIATOR) {
        tmp_e = BN_dup(e);
        tmp_n = BN_dup(n);
        if (!tmp_n || !tmp_e) {
            printf("Error: Failed to dup tmp_n or tmp_e\n");
            goto err;
        }
        RSA_set0_key(rsa, tmp_n, tmp_e, d);
    } else {
        if (!tc->p || !tc->q || !tc->d) {
            printf("Failed p or q or d from library\n");
            goto err;
        }
        p = BN_new();
        q = BN_new();
        d = BN_new();
        if (!p || !q || !d) {
            printf("Failed to allocate BN for p or q or d\n");
            goto err;
        }
        BN_bin2bn(tc->p, tc->plen, p);
        BN_bin2bn(tc->q, tc->qlen, q);
        BN_bin2bn(tc->d, tc->dlen, d);
        tmp_e = BN_dup(e);
        tmp_n = BN_dup(n);
        if (!tmp_n || !tmp_e) {
            printf("Error: Failed to dup tmp_n or tmp_e\n");
            goto err;
        }
        RSA_set0_key(rsa, tmp_n, tmp_e, d);
        RSA_set0_factors(rsa, p, q);
    }

#define KAS_IFC_MAX 1024
    if (tc->test_type == ACVP_KAS_IFC_TT_AFT) {
        if (tc->kas_role == ACVP_KAS_IFC_INITIATOR) {
            if (!tc->chash) {
                printf("Missing chash from library\n");
                goto err;
            }
            /* 
             * Kludgy way to meet requirement for Z, could use RAND_bytes(), but that may
             * take several iterations to get a len == nlen and value < n.
             */
            tc->n[0] -= 8;
            tc->pt_len = RSA_public_encrypt(tc->nlen, tc->n, tc->pt, rsa, RSA_NO_PADDING);

        if (tc->md == ACVP_NO_SHA) {
            tc->chashlen = tc->nlen;
            memcpy_s(tc->chash, KAS_IFC_MAX, tc->n, tc->nlen);
        } else {
            FIPS_digest(tc->n, tc->nlen, (unsigned char *)tc->chash, NULL, md);
            tc->chashlen = EVP_MD_size(md);
        }

        } else {
            if (!tc->ct || !tc->pt || !tc->chash) {
                printf("Missing pt/ct/chash from library\n");
                goto err;
            }

            tc->pt_len = RSA_private_decrypt(tc->ct_len, tc->ct, tc->pt, rsa, RSA_NO_PADDING);
            if (tc->pt_len == -1) {
                printf("Error decrypting\n");
                goto err;
            }
            if (tc->md == ACVP_NO_SHA) {
                tc->chashlen = tc->pt_len;
                memcpy_s(tc->chash, KAS_IFC_MAX, tc->pt, tc->pt_len);
            } else {
                FIPS_digest(tc->pt, tc->pt_len, (unsigned char *)tc->chash, NULL, md);
                tc->chashlen = EVP_MD_size(md);
            }
        }
    } else {
        if (tc->kas_role == ACVP_KAS_IFC_INITIATOR) {
            if (!tc->chash || !tc->z) {
                printf("Missing chash or z from library\n");
                goto err;
            }
            tc->pt_len = RSA_public_encrypt(tc->zlen, tc->z, tc->pt, rsa, RSA_NO_PADDING);
            if (tc->md == ACVP_NO_SHA) {
                tc->chashlen = tc->zlen;
                memcpy_s(tc->chash, KAS_IFC_MAX, tc->z, tc->zlen);
            } else {
                FIPS_digest(tc->z, tc->zlen, (unsigned char *)tc->chash, NULL, md);
                tc->chashlen = EVP_MD_size(md);
            }
        } else {
            if (!tc->ct || !tc->pt || !tc->chash) {
                printf("Missing pt/ct/chash from library\n");
                goto err;
            }
            tc->pt_len = RSA_private_decrypt(tc->ct_len, tc->ct, tc->pt, rsa, RSA_NO_PADDING);
            if (tc->pt_len == -1) {
                printf("Error decrypting\n");
                goto err;
            }
            if (tc->md == ACVP_NO_SHA) {
                tc->chashlen = tc->pt_len;
                memcpy_s(tc->chash, KAS_IFC_MAX, tc->pt, tc->pt_len);
            } else {
                FIPS_digest(tc->pt, tc->pt_len, (unsigned char *)tc->chash, (unsigned int *)&tc->chashlen, md);
            }
        }
    }
    rv = 0;
err:
    if (e) BN_free(e);
    if (n) BN_free(n);
    if (rsa) RSA_free(rsa);
    return rv;
}


int app_kts_ifc_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    printf("No application support\n");
    return 1;
}




int app_safe_primes_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_SAFE_PRIMES_TC         *tc;
    int rv = 1;
    DH *dh = NULL;
    BIGNUM *pub_key_ver = NULL, *priv_key_ver = NULL;
    const BIGNUM *pver = NULL;
    BIGNUM *q = NULL, *p = NULL, *g = NULL, *q1 = NULL;
    BIGNUM *tmp_p = NULL, *tmp_q = NULL, *tmp_g = NULL;
    const BIGNUM *pub_key = NULL, *priv_key = NULL;
    BIGNUM *tmp_pub_key = NULL;
    BN_CTX *c = NULL;
    int is_modp = 0;
    int ret = 0;

    tc = test_case->tc.safe_primes;

    p = BN_new();
    q = BN_new();
    g = BN_new();
    if (!p || !q || !g) {
        printf("Failed to allocate BN for p or q or g\n");
        goto err;
    }
    switch (tc->dgm)
    { 
   case ACVP_SAFE_PRIMES_MODP2048:
        is_modp = 1;
        get_rfc3526_prime_2048(p);
        get_rfc3526_prime_2048(q);
        break;
    case ACVP_SAFE_PRIMES_MODP3072:
        is_modp = 1;
        get_rfc3526_prime_3072(p);
        get_rfc3526_prime_3072(q);
        break;
    case ACVP_SAFE_PRIMES_MODP4096:
        is_modp = 1;
        get_rfc3526_prime_4096(p);
        get_rfc3526_prime_4096(q);
        break;
    case ACVP_SAFE_PRIMES_MODP6144:
        is_modp = 1;
        get_rfc3526_prime_6144(p);
        get_rfc3526_prime_6144(q);
        break;
    case ACVP_SAFE_PRIMES_MODP8192:
        is_modp = 1;
        get_rfc3526_prime_8192(p);
        get_rfc3526_prime_8192(q);
        break;
    case ACVP_SAFE_PRIMES_FFDHE2048:
        dh = DH_new_by_nid(NID_ffdhe2048);
        break;
    case ACVP_SAFE_PRIMES_FFDHE3072:
        dh = DH_new_by_nid(NID_ffdhe3072);
        break;
    case ACVP_SAFE_PRIMES_FFDHE4096:
        dh = DH_new_by_nid(NID_ffdhe4096);
        break;
    case ACVP_SAFE_PRIMES_FFDHE6144:
        dh = DH_new_by_nid(NID_ffdhe6144);
        break;
    case ACVP_SAFE_PRIMES_FFDHE8192:
        dh = DH_new_by_nid(NID_ffdhe8192);
        break;
    default:
        printf("Invalid dgm\n");
        goto err;
        break;
    }

   if (is_modp) {
        dh = DH_new();
        if (!dh) {
            goto err;
        }
        BN_sub_word(q, 1);
        BN_div_word(q, 2);
        BN_set_word(g, 2);
        tmp_p = BN_dup(p);
        tmp_q = BN_dup(q);
        tmp_g = BN_dup(g);
        DH_set0_pqg(dh, tmp_p, tmp_q, tmp_g);
    }

    if (!tc->x || !tc->y) {
        printf("X or Y not allocated\n");
        goto err;
    }

    if (tc->cipher == ACVP_SAFE_PRIMES_KEYGEN) {
        if (!FIPS_dh_generate_key(dh)) {
            printf("DH_generate_key failed for dgm = %d\n", tc->dgm);
            goto err;
        }
        DH_get0_key(dh, &pub_key, &priv_key);
        tc->xlen = BN_bn2bin(priv_key, tc->x);
        tc->ylen = BN_bn2bin(pub_key, tc->y);
    }

    /* Validate 0 < x < q and y = g^x mod p */
    else if (tc->cipher == ACVP_SAFE_PRIMES_KEYVER) {

        DH_get0_pqg(dh, &pver, NULL, NULL);
        q1 = BN_dup(pver);
        BN_sub_word(q1, 1);
        BN_div_word(q1, 2);

        DH_set0_pqg(dh, NULL, q1, NULL);

        /* Build  the DH and perform the key verify */
        priv_key_ver = BN_new();
        pub_key_ver = BN_new();
        BN_bin2bn(tc->x, tc->xlen, priv_key_ver);
        BN_bin2bn(tc->y, tc->ylen, pub_key_ver);

        tmp_pub_key = BN_new();
        c = BN_CTX_new();
        if (!c) {
            printf("BN_CTX_new failed\n");
            goto end;
        }
        tc->result = 1;

        DH_set0_key(dh, pub_key_ver, priv_key_ver);
        rv = DH_check_pub_key(dh, pub_key_ver, &ret);
        if (!rv || ret) {
            tc->result = 0;
        }
    } else {
        printf("Invalid safe prime algorithm id\n");
        goto err;
    }
end:
    rv = 0;

err:
    if (p) BN_free(p);
    if (q) BN_free(q);
    if (g) BN_free(g);
    if (tmp_pub_key) BN_free(tmp_pub_key);
    if (c) BN_CTX_free(c);
    if (dh) DH_free(dh);
    return rv;
}



#else
int app_kas_ecc_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}
int app_kas_ffc_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}
int app_kas_ifc_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

int app_kts_ifc_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

int app_safe_primes_handler(ACVP_TEST_CASE *test_case)
{
    if (!test_case) {
        return -1;
    }
    return 1;
}

#endif // ACVP_NO_RUNTIME

