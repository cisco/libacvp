/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"
#include "safe_lib.h"
#include "implementations/openssl/3/iut.h"

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

static unsigned char *eddsa_group_q = NULL;
static size_t group_q_len = 0;
static EVP_PKEY *group_pkey = NULL;
static int eddsa_current_tg = 0;

void app_eddsa_cleanup(void) {
    if (eddsa_group_q) free(eddsa_group_q);
    eddsa_group_q = NULL;
    if (group_pkey) EVP_PKEY_free(group_pkey);
    group_pkey = NULL;
}

int app_eddsa_handler(ACVP_TEST_CASE *test_case) {
    int rv = 1;
    size_t sig_len = 0, d_len = 0, q_len = 0;
    const char *curve = NULL, *instance = NULL;
    char *pub_key = NULL;
    unsigned char *sig = NULL, *d = NULL, *q = NULL;
    ACVP_CIPHER mode;
    ACVP_SUB_EDDSA alg;
    ACVP_EDDSA_TC *tc = NULL;
    EVP_MD_CTX *sig_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM_BLD *pkey_pbld = NULL;
    OSSL_PARAM *params = NULL;

    if (!test_case) {
        printf("No test case found\n");
        return 1;
    }
    tc = test_case->tc.eddsa;
    /* Todo: expand these checks and UTs */
    if (!tc || !tc->q) {
        printf("Error: test case not found in EDDSA handler\n");
        return 1;
    }

    mode = tc->cipher;
    alg = acvp_get_eddsa_alg(mode);
    if (alg == 0) {
        printf("Invalid cipher value\n");
        return 1;
    }

    /* Key operations and signature operations for OpenSSL EDDSA use different string identifiers */
    instance = get_ed_instance_param(tc->curve, tc->use_prehash, tc->context ? 1 : 0);
    if (!instance) {
        printf("Error getting instance param for EDDSA\n");
        return 1;
    }
    curve = get_ed_curve_string(tc->curve);
    if (!curve) {
        printf("Unable to lookup curve name for EDDSA\n");
        goto err;
    }

    switch (alg) {
    case ACVP_SUB_EDDSA_KEYGEN:
        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, curve, NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey CTX in EDDSA\n");
            goto err;
        }
        if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
            printf("Error initializing keygen in EDDSA keygen\n");
            goto err;
        }
        EVP_PKEY_keygen(pkey_ctx, &pkey);
        if (!pkey) {
            printf("Error generating key in EDDSA keygen\n");
            goto err;
        }
        if (EVP_PKEY_get_octet_string_param(pkey, "priv", NULL, 0, &d_len) == 1) {
            d = calloc(d_len, sizeof(char));
            if (!d) {
                printf("Error allocating memory for 'd' in EDDSA keygen\n");
                goto err;
            }
            if (EVP_PKEY_get_octet_string_param(pkey, "priv", d, d_len, &d_len) != 1) {
                printf("Error getting 'd' in EDDSA keygen\n");
                goto err;
            }
            tc->d_len = (int)d_len;
            memcpy_s(tc->d, 8192, d, d_len);
        } else {
            printf("Error getting 'd' in EDDSA keygen\n");
            goto err;
        }

        if (EVP_PKEY_get_octet_string_param(pkey, "pub", NULL, 0, &q_len) == 1) {
            q = calloc(q_len, sizeof(char));
            if (!q) {
                printf("Error allocating memory for 'q' in EDDSA keygen\n");
                goto err;
            }
            if (EVP_PKEY_get_octet_string_param(pkey, "pub", q, q_len, &q_len) != 1) {
                printf("Error getting 'q' in EDDSA keygen\n");
                goto err;
            }
            tc->q_len = (int)q_len;
            memcpy_s(tc->q, 8192, q, q_len);
        } else {
            printf("Error getting 'q' in EDDSA keygen\n");
            goto err;
        }

        break;
    case ACVP_SUB_EDDSA_KEYVER:
        tc->ver_disposition = 0;

        pkey_pbld = OSSL_PARAM_BLD_new();
        if (!pkey_pbld) {
            printf("Error creating param_bld in EDDSA keyver\n");
            goto err;
        }

        OSSL_PARAM_BLD_push_octet_string(pkey_pbld, OSSL_PKEY_PARAM_PUB_KEY, tc->q, tc->q_len);
        params = OSSL_PARAM_BLD_to_param(pkey_pbld);
        if (!params) {
            printf("Error generating parameters for pkey generation in EDDSA keyver\n");
            goto err;
        }

        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, curve, NULL);
        if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
            printf("Error initializing fromdata in EDDSA keyver\n");
            goto err;
        }
        if (EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            printf("Error generating pkey from public key data in EDDSA keyver\n");
            goto err;
        }

        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (EVP_PKEY_public_check(pkey_ctx) == 1) {
            tc->ver_disposition = 1;
        }
        break;
    case ACVP_SUB_EDDSA_SIGGEN:
        if (eddsa_current_tg != tc->tg_id) {
            eddsa_current_tg = tc->tg_id;
            /* First, generate key for every test group */
            pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, curve, NULL);
            if (!pkey_ctx) {
                printf("Error creating pkey CTX in EDDSA siggen\n");
                goto err;
            }
            if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
                printf("Error initializing keygen in EDDSA siggen\n");
                goto err;
            }
            if (EVP_PKEY_generate(pkey_ctx, &group_pkey) != 1) {
                printf("Error generating pkey in EDDSA siggen\n");
                goto err;
            }
            if (EVP_PKEY_get_octet_string_param(group_pkey, "pub", NULL, 0, &group_q_len) == 1) {
                if (eddsa_group_q) free(eddsa_group_q);
                eddsa_group_q = calloc(group_q_len, sizeof(char));
                if (!eddsa_group_q) {
                    printf("Error allocating memory for 'q' in EDDSA keygen\n");
                    goto err;
                }
                if (EVP_PKEY_get_octet_string_param(group_pkey, "pub", eddsa_group_q, group_q_len, &group_q_len) != 1) {
                    printf("Error getting 'q' in EDDSA keygen\n");
                    goto err;
                }
            } else {
                printf("Error getting 'q' in EDDSA siggen\n");
                goto err;
            }
        }

        /* Then, for each test case, generate a signature */
        sig_ctx = EVP_MD_CTX_new();
        if (!sig_ctx) {
            printf("Error initializing sign CTX for EDDSA siggen\n");
            goto err;
        }

        pkey_pbld = OSSL_PARAM_BLD_new();
        if (!pkey_pbld) {
            printf("Error creating param_bld in EDDSA siggen\n");
            goto err;
        }
        OSSL_PARAM_BLD_push_utf8_string(pkey_pbld, OSSL_SIGNATURE_PARAM_INSTANCE, instance, 0);
        if (tc->context) {
            OSSL_PARAM_BLD_push_octet_string(pkey_pbld, OSSL_SIGNATURE_PARAM_CONTEXT_STRING, tc->context, tc->context_len);
        }
        params = OSSL_PARAM_BLD_to_param(pkey_pbld);
        if (!params) {
            printf("Error generating parameters for pkey generation in EDDSA siggen\n");
            goto err;
        }
        if (EVP_DigestSignInit_ex(sig_ctx, NULL, NULL, NULL, NULL, group_pkey, params) != 1) {
            printf("Error initializing signing for EDDSA siggen\n");
            goto err;
        }

        EVP_DigestSign(sig_ctx, NULL, &sig_len, tc->message, tc->msg_len);
        sig = calloc(sig_len, sizeof(char));
        if (!sig) {
            printf("Error allocating memory in EDDSA siggen\n");
            goto err;
        }
        if (EVP_DigestSign(sig_ctx, sig, &sig_len, tc->message, tc->msg_len) != 1) {
            printf("Error generating signature in EDDSA siggen\n");
            goto err;
        }
   
        /* and copy our values to the TC response */
        tc->q_len = (int)group_q_len;
        memcpy_s(tc->q, 8192, eddsa_group_q, group_q_len);
        tc->signature_len = (int)sig_len;
        memcpy_s(tc->signature, 8192, sig, sig_len);
        break;
    case ACVP_SUB_EDDSA_SIGVER:
        tc->ver_disposition = 0;

        pkey_pbld = OSSL_PARAM_BLD_new();
        if (!pkey_pbld) {
            printf("Error creating param_bld in EDDSA sigver\n");
            goto err;
        }
        OSSL_PARAM_BLD_push_octet_string(pkey_pbld, OSSL_PKEY_PARAM_PUB_KEY, tc->q, tc->q_len);
        params = OSSL_PARAM_BLD_to_param(pkey_pbld);
        if (!params) {
            printf("Error generating parameters for pkey generation in EDDSA sigver\n");
            goto err;
        }

        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, curve, NULL);
        if (!pkey_ctx) {
            printf("Error creating pkey ctx in EDDSA sigver\n");
            goto err;
        }
        if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
            printf("Error initializing fromdata in EDDSA keyver\n");
            goto err;
        }
        if (EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            printf("Error generating pkey from public key data in EDDSA sigver\n");
            goto err;
        }

        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(pkey_pbld);

        pkey_pbld = OSSL_PARAM_BLD_new();
        if (!pkey_pbld) {
            printf("Error creating param_bld in EDDSA sigver\n");
            goto err;
        }
        OSSL_PARAM_BLD_push_utf8_string(pkey_pbld, OSSL_SIGNATURE_PARAM_INSTANCE, instance, 0);
        if (tc->context) {
            OSSL_PARAM_BLD_push_octet_string(pkey_pbld, OSSL_SIGNATURE_PARAM_CONTEXT_STRING, tc->context, tc->context_len);
        }
        params = OSSL_PARAM_BLD_to_param(pkey_pbld);
        if (!params) {
            printf("Error generating parameters for pkey generation in EDDSA sigver\n");
            goto err;
        }

        sig_ctx = EVP_MD_CTX_new();
        if (!sig_ctx) {
            printf("Error initializing sign CTX for EDDSA sigver\n");
            goto err;
        }

        if (EVP_DigestVerifyInit_ex(sig_ctx, NULL, NULL, NULL, NULL, pkey, params) != 1) {
            printf("Error initializing signing for EDDSA sigver\n");
            goto err;
        }
        if (EVP_DigestVerify(sig_ctx, tc->signature, tc->signature_len, tc->message, tc->msg_len) == 1) {
            tc->ver_disposition = 1;
        }

        break;
    default:
        printf("Invalid EDDSA alg in test case\n");
        goto err;
    }

    rv = 0;
err:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (q) free(q);
    if (d) free(d);
    if (pub_key) free(pub_key);
    if (sig) free(sig);
    if (pkey_pbld) OSSL_PARAM_BLD_free(pkey_pbld);
    if (params) OSSL_PARAM_free(params);
    if (pkey) EVP_PKEY_free(pkey);
    if (sig_ctx) EVP_MD_CTX_free(sig_ctx);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    return rv;
}
