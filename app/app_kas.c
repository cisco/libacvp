/*****************************************************************************
* Copyright (c) 2019, Cisco Systems, Inc.
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

#ifdef ACVP_NO_RUNTIME

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "app_fips_lcl.h" /* All regular OpenSSL headers must come before here */
#include "app_lcl.h"
#include "safe_mem_lib.h"

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
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field) {
        rv = EC_POINT_set_affine_coordinates_GFp(group, peer, x, y, c);
    } else {
        rv = EC_POINT_set_affine_coordinates_GF2m(group, peer, x, y, c);
    }

end:
    if (rv == 0) {
        if (peer) EC_POINT_free(peer);
        peer = NULL;
    }
    if (c) BN_CTX_free(c);
    return peer;
}

static int ec_print_key(ACVP_KAS_ECC_TC *tc, EC_KEY *key, int add_e, int exout) {
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
    int nid = 0, exout = 0;
    EC_KEY *ec = NULL;
    EC_POINT *peerkey = NULL;
    unsigned char *Z = NULL;
    int Zlen = 0;
    BIGNUM *cx = NULL, *cy = NULL, *ix = NULL, *iy = NULL, *id = NULL;
    const EVP_MD *md = NULL;
    int rv = 1;

    tc = test_case->tc.kas_ecc;

    switch (tc->curve) {
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
    default:
        printf("Invalid curve %d\n", tc->curve);
        return rv;

        break;
    }

    if (tc->mode == ACVP_KAS_ECC_MODE_COMPONENT) {
        switch (tc->md) {
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
        default:
            printf("No valid hash name %d\n", tc->md);
            return rv;

            break;
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

    exout = md ? 1 : 0;
    ec_print_key(tc, ec, md ? 1 : 0, exout);
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

#define KAS_ECC_Z_MAX 512
    if (tc->test_type == ACVP_KAS_ECC_TT_AFT) {
        memcpy_s(tc->z, KAS_ECC_Z_MAX, Z, Zlen);
        tc->zlen = Zlen;
    }
    if (tc->mode == ACVP_KAS_ECC_MODE_COMPONENT) {
        FIPS_digest(Z, Zlen, (unsigned char *)tc->chash, NULL, md);
        tc->chashlen = EVP_MD_size(md);
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

    tc = test_case->tc.kas_ffc;

    switch (tc->md) {
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
    default:
        printf("No valid hash name %d\n", tc->md);
        return rv;

        break;
    }

    dh = FIPS_dh_new();
    if (!dh) {
        return rv;
    }

    if (!tc->p || !tc->q || !tc->g || !tc->eps ||
        !tc->plen || !tc->qlen || !tc->glen || !tc->epslen) {
        printf("Missing required p,q,g, or eps\n");
        goto error;
    }

    p = FIPS_bn_new();
    q = FIPS_bn_new();
    g = FIPS_bn_new();
    peerkey = FIPS_bn_new();
    if (!peerkey || !p || !q || !g) {
        printf("BN_new failed p q g eps\n");
        goto error;
    }

    BN_bin2bn(tc->p, tc->plen, p);
    BN_bin2bn(tc->q, tc->qlen, q);
    BN_bin2bn(tc->g, tc->glen, g);
    BN_bin2bn(tc->eps, tc->epslen, peerkey);

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    dh->p = BN_dup(p);
    dh->q = BN_dup(q);
    dh->g = BN_dup(g);
#else
    DH_set0_pqg(dh, p, q, g);
#endif

    if (tc->test_type == ACVP_KAS_FFC_TT_VAL) {
        if (!tc->epri || !tc->epui || !tc->eprilen || !tc->epuilen) {
            printf("missing epri or epui\n");
            goto error;
        }
        pub_key = FIPS_bn_new();
        priv_key = FIPS_bn_new();
        if (!pub_key || !priv_key) {
            printf("BN_new failed epri epui\n");
            goto error;
        }

        BN_bin2bn(tc->epri, tc->eprilen, priv_key);
        BN_bin2bn(tc->epui, tc->epuilen, pub_key);

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        dh->pub_key = BN_dup(pub_key);
        dh->priv_key = BN_dup(priv_key);
#else
        DH_set0_key(dh, pub_key, priv_key);
#endif
    }

    if (tc->test_type == ACVP_KAS_FFC_TT_AFT) {
        if (!DH_generate_key(dh)) {
            printf("DH_generate_key failed\n");
            goto error;
        }
    }
    Z = OPENSSL_malloc(BN_num_bytes(p));
    if (!Z) {
        printf("Malloc failed for Z\n");
        goto error;
    }

    if (!tc->chash || !tc->piut) {
        printf("Unallocated buffers in kas ffc tc, no place to put answers\n");
        goto error;
    }

    Zlen = DH_compute_key_padded(Z, peerkey, dh);
    FIPS_digest(Z, Zlen, (unsigned char *)tc->chash, NULL, md);
    tc->chashlen = EVP_MD_size(md);

#define KAS_FFC_Z_MAX 512
    if (tc->test_type == ACVP_KAS_FFC_TT_AFT) {
        memcpy_s(tc->z, KAS_FFC_Z_MAX, Z, Zlen);
        tc->zlen = Zlen;
    }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    tc->piutlen = BN_bn2bin(dh->pub_key, tc->piut);
#else
    tc->piutlen = BN_bn2bin(pub_key, tc->piut);
#endif

    rv = 0;

error:
    if (Z) {
        OPENSSL_cleanse(Z, Zlen);
        FIPS_free(Z);
    }
    if (peerkey) BN_clear_free(peerkey);
    if (dh) FIPS_dh_free(dh);
    if (pub_key) BN_free(pub_key);
    if (priv_key) BN_free(priv_key);
    if (p) BN_free(p);
    if (q) BN_free(q);
    if (g) BN_free(g);
    return rv;
}

#endif // ACVP_NO_RUNTIME

