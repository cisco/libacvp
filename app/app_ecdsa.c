/*
 * Copyright (c) 2023, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include "safe_lib.h"

static BIGNUM *ecdsa_group_Qx = NULL;
static BIGNUM *ecdsa_group_Qy = NULL;
static int ecdsa_current_tg = 0;

static EVP_PKEY *group_pkey = NULL;

void app_ecdsa_cleanup(void) {
    if (ecdsa_group_Qx) BN_free(ecdsa_group_Qx);
    ecdsa_group_Qx = NULL;
    if (ecdsa_group_Qy) BN_free(ecdsa_group_Qy);
    ecdsa_group_Qy = NULL;
    if (group_pkey) EVP_PKEY_free(group_pkey);
    group_pkey = NULL;
}

int app_ecdsa_handler(ACVP_TEST_CASE *test_case) {
    int rv = 1, nid = NID_undef, key_size = 0;
    size_t sig_len = 0;
    const char *curve = NULL, *md = NULL;
    char *pub_key = NULL;
    unsigned char *sig = NULL, *sig_iter = NULL;
    ACVP_CIPHER mode;
    ACVP_SUB_ECDSA alg;
    ACVP_ECDSA_TC *tc = NULL;
    EVP_MD_CTX *sig_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL, *comp_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM_BLD *pkey_pbld = NULL;
    OSSL_PARAM *params = NULL;
    ECDSA_SIG *sig_obj = NULL;
    BIGNUM *qx = NULL, *qy = NULL, *d = NULL;
    const BIGNUM *out_r = NULL, *out_s = NULL;
    BIGNUM *in_r = NULL, *in_s = NULL;
    if (!test_case) {
        printf("No test case found\n");
        return 1;
    }
    tc = test_case->tc.ecdsa;
    /* Todo: expand these checks and UTs */
    if (!tc || !tc->qx || !tc->qy) {
        printf("\nError: test case not found in ECDSA handler\n");
        return 1;
    }

    mode = tc->cipher;
    alg = acvp_get_ecdsa_alg(mode);
    if (alg == 0) {
        printf("Invalid cipher value");
        return 1;
    }

    nid = get_nid_for_curve(tc->curve);
    if (nid == NID_undef) {
        printf("Invalid curve provided for ECDSA\n");
        goto err;
    }
    curve = OSSL_EC_curve_nid2name(nid);
    if (!curve) {
        printf("Unable to lookup curve name for ECDSA\n");
        goto err;
    }

    if ((mode == ACVP_ECDSA_SIGGEN || mode == ACVP_ECDSA_SIGVER || mode == ACVP_DET_ECDSA_SIGGEN)) {
        md = get_md_string_for_hash_alg(tc->hash_alg, NULL);
        if (!md) {
            printf("Error getting hash alg from test case for ECDSA\n");
            goto err;
        }
    }

    switch (alg) {
    case ACVP_SUB_ECDSA_KEYGEN:
        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey CTX in ECDSA\n");
            goto err;
        }
        if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
            printf("Error initializing keygen in ECDSA keygen\n");
            goto err;
        }
        if (EVP_PKEY_CTX_set_group_name(pkey_ctx, curve) < 1) {
            printf("Error setting curve for ECDSA keygen\n");
            goto err;
        }
        EVP_PKEY_keygen(pkey_ctx, &pkey);
        if (!pkey) {
            printf("Error generating key in ECDSA keygen\n");
            goto err;
        }

        if (EVP_PKEY_get_bn_param(pkey, "priv", &d) == 1) {
            tc->d_len = BN_bn2bin(d, tc->d);
        } else {
            printf("Error getting 'd' in ECDSA keygen\n");
            goto err;
        }
        if (EVP_PKEY_get_bn_param(pkey, "qx", &qx) == 1) {
            tc->qx_len = BN_bn2bin(qx, tc->qx);
        } else {
            printf("Error getting 'qx' in ECDSA keygen\n");
            goto err;
        }
        if (EVP_PKEY_get_bn_param(pkey, "qy", &qy) == 1) {
            tc->qy_len = BN_bn2bin(qy, tc->qy);
        } else {
            printf("Error getting 'qy' in ECDSA keygen\n");
            goto err;
        }
        break;
    case ACVP_SUB_ECDSA_KEYVER:
        tc->ver_disposition = 0;

        pub_key = ec_point_to_pub_key(tc->qx, tc->qx_len, tc->qy, tc->qy_len, &key_size);
        if (!pub_key) {
            printf("Error generating pub key in ECDSA keyver\n");
            goto err;
        }

        pkey_pbld = OSSL_PARAM_BLD_new();
        if (!pkey_pbld) {
            printf("Error creating param_bld in ECDSA keyver\n");
            goto err;
        }
        OSSL_PARAM_BLD_push_utf8_string(pkey_pbld, OSSL_PKEY_PARAM_GROUP_NAME, curve, 0);
        OSSL_PARAM_BLD_push_octet_string(pkey_pbld, OSSL_PKEY_PARAM_PUB_KEY, pub_key, key_size);
        params = OSSL_PARAM_BLD_to_param(pkey_pbld);
        if (!params) {
            printf("Error generating parameters for pkey generation in ECDSA keygen\n");
        }

        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
            printf("Error initializing fromdata in ECDSA keyver\n");
            goto err;
        }
        if (EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1) {
            tc->ver_disposition = 1;
        }
        break;
    case ACVP_SUB_ECDSA_SIGGEN:
    case ACVP_SUB_DET_ECDSA_SIGGEN:
        if (ecdsa_current_tg != tc->tg_id) {
            ecdsa_current_tg = tc->tg_id;
            /* First, generate key for every test group */
            pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
            if (!pkey_ctx) {
                printf("Error creating pkey CTX in ECDSA siggen\n");
                goto err;
            }
            if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
                printf("Error initializing keygen in ECDSA siggen\n");
                goto err;
            }
            if (EVP_PKEY_CTX_set_group_name(pkey_ctx, curve) != 1) {
                printf("Error setting curve for ECDSA siggen\n");
                goto err;
            }
            if (EVP_PKEY_generate(pkey_ctx, &group_pkey) != 1) {
                printf("Error generating pkey in ECDSA siggen\n");
                goto err;
            }
            EVP_PKEY_get_bn_param(group_pkey, "qx", &ecdsa_group_Qx);
            EVP_PKEY_get_bn_param(group_pkey, "qy", &ecdsa_group_Qy);
            if (!ecdsa_group_Qx || !ecdsa_group_Qy) {
                printf("Error retrieving params from pkey in ECDSA siggen\n");
                goto err;
            }
        }

        /* Then, for each test case, generate a signature */
        if (!tc->is_component) {
            sig_ctx = EVP_MD_CTX_new();
            if (!sig_ctx) {
                printf("Error initializing sign CTX for ECDSA siggen\n");
                goto err;
            }
            if (EVP_DigestSignInit_ex(sig_ctx, NULL, md, NULL, NULL, group_pkey, NULL) != 1) {
                printf("Error initializing signing for ECDSA siggen\n");
                goto err;
            }

            if (alg == ACVP_SUB_DET_ECDSA_SIGGEN) {
                if (pkey_pbld) OSSL_PARAM_BLD_free(pkey_pbld);
                if (params) OSSL_PARAM_free(params);
                pkey_pbld = NULL;
                params = NULL;

                pkey_pbld = OSSL_PARAM_BLD_new();
                if (!pkey_pbld) {
                    printf("Error creating param_bld in ECDSA keyver\n");
                    goto err;
                }

                OSSL_PARAM_BLD_push_uint(pkey_pbld, OSSL_SIGNATURE_PARAM_NONCE_TYPE, 1);
                params = OSSL_PARAM_BLD_to_param(pkey_pbld);
                if (!params) {
                    printf("Error generating parameters for pkey generation in DetECDSA siggen\n");
                }

                if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
                pkey_ctx = NULL;
                if (EVP_DigestSignInit_ex(sig_ctx, &pkey_ctx, md, NULL, NULL, group_pkey, NULL) != 1) {
                    printf("Error initializing signing for DetECDSA siggen\n");
                    goto err;
                }

                if (!EVP_PKEY_CTX_set_params(pkey_ctx, params)) {
                    printf("Error setting params for DetECDSA\n");
                    goto err;
                }

                pkey_ctx = NULL; //freed with md ctx
            } else {
                if (EVP_DigestSignInit_ex(sig_ctx, NULL, md, NULL, NULL, group_pkey, NULL) != 1) {
                    printf("Error initializing signing for ECDSA siggen\n");
                    goto err;
                }
            }

            EVP_DigestSign(sig_ctx, NULL, &sig_len, tc->message, tc->msg_len);
            sig = calloc(sig_len, sizeof(char));
            if (!sig) {
                printf("Error allocating memory in ECDSA siggen\n");
                goto err;
            }
            sig_iter = sig; /* since d2i_ECDSA_SIG alters the pointer, we need to keep the original one for freeing */
            if (EVP_DigestSign(sig_ctx, sig, &sig_len, tc->message, tc->msg_len) != 1) {
                printf("Error generating signature in ECDSA siggen\n");
                goto err;
            }
        } else {
            comp_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, group_pkey, NULL);
            if (!comp_ctx) {
                printf("Error initializing sign CTX for ECDSA component siggen\n");
                goto err;
            }
            if (EVP_PKEY_sign_init(comp_ctx) != 1) {
                printf("Error initializing signing for ECDSA component siggen\n");
                goto err;
            }
            EVP_PKEY_sign(comp_ctx, NULL, &sig_len, tc->message, tc->msg_len);
            sig = calloc(sig_len, sizeof(char));
            if (!sig) {
                printf("Error allocating memory in ECDSA component siggen\n");
                goto err;
            }
            sig_iter = sig; /* since d2i_ECDSA_SIG alters the pointer, we need to keep the original one for freeing */
            if (EVP_PKEY_sign(comp_ctx, sig, &sig_len, tc->message, tc->msg_len) != 1) {
                printf("Error generating signature in ECDSA component siggen\n");
                goto err;
            }
        }
        /* Finally, extract R and S from signature */
        sig_obj = d2i_ECDSA_SIG(NULL, (const unsigned char **)&sig_iter, (long)sig_len);
        if (!sig_obj) {
            printf("Error creating signature object neeed to retrieve output in ECDSA siggen\n");
            goto err;
        }
        out_r = ECDSA_SIG_get0_r(sig_obj);
        out_s = ECDSA_SIG_get0_s(sig_obj);
        if (!out_r || !out_s) {
            printf("Error retrieving output values in ECDSA siggen\n");
            goto err;
        }
        /* and copy our values to the TC response */
        tc->r_len = BN_bn2bin(out_r, tc->r);
        tc->s_len = BN_bn2bin(out_s, tc->s);
        tc->qx_len = BN_bn2bin(ecdsa_group_Qx, tc->qx);
        tc->qy_len = BN_bn2bin(ecdsa_group_Qy, tc->qy);
        break;
    case ACVP_SUB_ECDSA_SIGVER:
        tc->ver_disposition = 0;

        pub_key = ec_point_to_pub_key(tc->qx, tc->qx_len, tc->qy, tc->qy_len, &key_size);
        if (!pub_key) {
            printf("Error generating pub key in ECDSA sigver\n");
            goto err;
        }

        pkey_pbld = OSSL_PARAM_BLD_new();
        if (!pkey_pbld) {
            printf("Error creating param_bld in ECDSA sigver\n");
            goto err;
        }
        OSSL_PARAM_BLD_push_utf8_string(pkey_pbld, OSSL_PKEY_PARAM_GROUP_NAME, curve, 0);
        OSSL_PARAM_BLD_push_octet_string(pkey_pbld, OSSL_PKEY_PARAM_PUB_KEY, pub_key, key_size);
        params = OSSL_PARAM_BLD_to_param(pkey_pbld);
        if (!params) {
            printf("Error generating parameters for pkey generation in RSA sigver\n");
        }

        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (!pkey_ctx) {
            printf("Error creating pkey ctx in ECDSA sigver\n");
            goto err;
        }
        if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
            printf("Error initializing fromdata in ECDSA keyver\n");
            goto err;
        }
        if (EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            printf("Error generating pkey from public key data in ECDSA sigver\n");
            goto err;
        }

        in_r = BN_bin2bn(tc->r, tc->r_len, NULL);
        in_s = BN_bin2bn(tc->s, tc->s_len, NULL);
        if (!in_r || !in_s) {
            printf("Error importing R or S in ECDSA sigver\n");
            goto err;
        }
        sig_obj = ECDSA_SIG_new();
        if (!sig_obj) {
            printf("Error creating signature object in ECDSA sigver\n");
            goto err;
        }
        if (ECDSA_SIG_set0(sig_obj, in_r, in_s) != 1) {
            printf("Error setting R and S values in ECDSA sigver\n");
            goto err;
        }

        sig_len = (size_t)i2d_ECDSA_SIG(sig_obj, &sig);

        if (!tc->is_component) {
            sig_ctx = EVP_MD_CTX_new();
            if (!sig_ctx) {
                printf("Error initializing sign CTX for ECDSA sigver\n");
                goto err;
            }

            if (EVP_DigestVerifyInit_ex(sig_ctx, NULL, md, NULL, NULL, pkey, NULL) != 1) {
                printf("Error initializing signing for ECDSA sigver\n");
                goto err;
            }
            if (EVP_DigestVerify(sig_ctx, sig, sig_len, tc->message, tc->msg_len) == 1) {
                tc->ver_disposition = 1;
            }
        } else {
            comp_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
            if (!comp_ctx) {
                printf("Error initializing sign CTX for ECDSA component sigver\n");
                goto err;
            }
            if (EVP_PKEY_verify_init(comp_ctx) != 1) {
                printf("Error initializing signing for ECDSA component sigver\n");
                goto err;
            }
            if (EVP_PKEY_verify(comp_ctx, sig, sig_len, tc->message, tc->msg_len) == 1) {
                tc->ver_disposition = 1;
            }
        }
        break;
    default:
        printf("Invalid ECDSA alg in test case\n");
        goto err;
    }
    rv = 0;
err:
    if (qx) BN_free(qx);
    if (qy) BN_free(qy);
    if (d) BN_free(d);
    if (pub_key) free(pub_key);
    if (sig) free(sig);
    if (pkey_pbld) OSSL_PARAM_BLD_free(pkey_pbld);
    if (params) OSSL_PARAM_free(params);
    if (sig_obj) ECDSA_SIG_free(sig_obj);
    if (pkey) EVP_PKEY_free(pkey);
    if (sig_ctx) EVP_MD_CTX_free(sig_ctx);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (comp_ctx) EVP_PKEY_CTX_free(comp_ctx);
    return rv;
}

#else

int app_ecdsa_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}
#endif

