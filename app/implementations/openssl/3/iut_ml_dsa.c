/*
 * Copyright (c) 2025, Cisco Systems, Inc.
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

#define ML_DSA_MAX_BUF_SIZE 8192
/* Stubs for new functions to allow old versions of OpenSSL to compile */
#if OPENSSL_VERSION_NUMBER < 0x30400000L
int EVP_PKEY_verify_message_init(EVP_PKEY_CTX *ctx, EVP_SIGNATURE *algo, const OSSL_PARAM params[]) {
    if (!ctx || !algo || !params) {
        return -1;
    }
    return 0;
}
int EVP_PKEY_sign_message_init(EVP_PKEY_CTX *ctx, EVP_SIGNATURE *algo, const OSSL_PARAM params[]) {
    if (!ctx || !algo || !params) {
        return -1;
    }
    return 0;
}
#endif

int app_ml_dsa_handler(ACVP_TEST_CASE *test_case) {
    ACVP_ML_DSA_TC *tc = NULL;
    ACVP_SUB_ML_DSA alg = 0;
    int rv = 1;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig = NULL;
    size_t sk_len = 0, pk_len = 0, sig_len = 0, msg_len = 0;
    const char *param_set = NULL;
    unsigned char *sig_buf = NULL, *msg_ptr = NULL;

    if (!test_case) {
        printf("Missing ML-DSA test case\n");
        return -1;
    }

    tc = test_case->tc.ml_dsa;
    if (!tc) return rv;

    alg = acvp_get_ml_dsa_alg(tc->cipher);
    if (!alg) return rv;

    if (alg == ACVP_SUB_ML_DSA_SIGGEN || alg == ACVP_SUB_ML_DSA_SIGVER) {
        if (tc->mu_len > 0 && tc->msg_len > 0) {
            printf("Test case incorrectly has both mu and msg data for ML-DSA\n");
            return -1;
        } else if (tc->mu_len + tc->msg_len == 0) {
            printf("Test case is missing message or mu data for ML-DSA\n");
            return -1;
        }
    }

    switch (tc->param_set) {
    case ACVP_ML_DSA_PARAM_SET_ML_DSA_44:
        param_set = "ML-DSA-44";
        break;
    case ACVP_ML_DSA_PARAM_SET_ML_DSA_65:
        param_set = "ML-DSA-65";
        break;
    case ACVP_ML_DSA_PARAM_SET_ML_DSA_87:
        param_set = "ML-DSA-87";
        break;
    case ACVP_ML_DSA_PARAM_SET_NONE:
    case ACVP_ML_DSA_PARAM_SET_MAX:
    default:
        printf("Invalid param set in ML-DSA handler\n");
        goto end;
    }

    switch (alg) {
    case ACVP_SUB_ML_DSA_KEYGEN:
        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in ML-DSA\n");
            goto end;
        }
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_PKEY_PARAM_ML_DSA_SEED, tc->seed, tc->seed_len);
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in ML-DSA keygen\n");
            goto end;
        }
        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, param_set, NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey CTX in ML-DSA keygen\n");
            goto end;
        }
        if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
            printf("Error initializing keygen in ML-DSA keygen\n");
            goto end;
        }
        if (EVP_PKEY_CTX_set_params(pkey_ctx, params) != 1) {
            printf("Error setting params in ML-DSA keygen\n");
            goto end;
        }
        EVP_PKEY_keygen(pkey_ctx, &pkey);
        if (!pkey) {
            printf("Error generating key in ML-DSA keygen\n");
            goto end;
        }
        EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, tc->secret_key, ML_DSA_MAX_BUF_SIZE, &sk_len);
        EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, tc->pub_key, ML_DSA_MAX_BUF_SIZE, &pk_len);
        tc->secret_key_len = (int)sk_len;
        tc->pub_key_len = (int)pk_len;
        break;
    case ACVP_SUB_ML_DSA_SIGGEN:
        /* First, create the pkey containing the sk we are given */
        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, param_set, NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey CTX in ML-DSA siggen\n");
            goto end;
        }
        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in ML-DSA siggen\n");
            goto end;
        }
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_PKEY_PARAM_PRIV_KEY, tc->secret_key, tc->secret_key_len);
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in ML-DSA siggen\n");
            goto end;
        }
        if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
            printf("Error initializing fromdata in ML-DSA siggen\n");
            goto end;
        }
        if (EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PRIVATE_KEY, params) != 1) {
            printf("Error generating pkey from private key data in ML-DSA siggen\n");
            goto end;
        }

        /* Then, create the signature object */
        sig = EVP_SIGNATURE_fetch(NULL, param_set, NULL);
        if (!sig) {
            printf("Error fetching signature in ML-DSA siggen\n");
            goto end;
        }
        /* Then, use that pkey to sign. Start generating new params */
        if (pbld) OSSL_PARAM_BLD_free(pbld);
        if (params) OSSL_PARAM_free(params);

        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in ML-DSA siggen\n");
            goto end;
        }
        OSSL_PARAM_BLD_push_int(pbld, OSSL_SIGNATURE_PARAM_DETERMINISTIC, tc->is_deterministic);
        if (tc->rnd_len) {
            OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_SIGNATURE_PARAM_TEST_ENTROPY, tc->rnd, tc->rnd_len);
        }

        /* Determine if we have mu or message; if MU, set correct flag */
        if (tc->mu_len) {
            msg_ptr = tc->mu;
            msg_len = (size_t)tc->mu_len;
            OSSL_PARAM_BLD_push_int(pbld, OSSL_SIGNATURE_PARAM_MU, 1);
        } else {
            msg_ptr = tc->msg;
            msg_len = (size_t)tc->msg_len;
        }
        if (tc->context) {
            OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_SIGNATURE_PARAM_CONTEXT_STRING, tc->context, tc->context_len);

        }
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in ML-DSA siggen\n");
            goto end;
        }

        /* Initialize and perform sig operation */
        if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey ctx from pkey in ML-DSA siggen\n");
            goto end;
        }
        if (EVP_PKEY_sign_message_init(pkey_ctx, sig, params) != 1) {
            printf("Error initializing sign operation in ML-DSA siggen\n");
            goto end;
        }
        EVP_PKEY_sign(pkey_ctx, NULL, &sig_len, msg_ptr, msg_len);
        sig_buf = calloc(sig_len, sizeof(char));
        if (!sig_buf) {
            printf("Error allocating memory in ML-DSA siggen\n");
            goto end;
        }
        if (EVP_PKEY_sign(pkey_ctx, sig_buf, &sig_len, msg_ptr, msg_len) != 1) {
            printf("Error generating signature in ML-DSA siggen\n");
            goto end;
        }

        /* Copy results back into test case */
        memcpy_s(tc->sig, ML_DSA_MAX_BUF_SIZE, sig_buf, sig_len);
        tc->sig_len = (int)sig_len;

        break;
    case ACVP_SUB_ML_DSA_SIGVER:
        tc->ver_disposition = 0;

        /* First, create the pkey containing the pk we are given */
        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, param_set, NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey CTX in ML-DSA sigver\n");
            goto end;
        }
        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in ML-DSA sigver\n");
            goto end;
        }
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_PKEY_PARAM_PUB_KEY, tc->pub_key, tc->pub_key_len);
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in ML-DSA sigver\n");
            goto end;
        }
        if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
            printf("Error initializing fromdata in ML-DSA sigver\n");
            goto end;
        }
        if (EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            printf("Error generating pkey from private key data in ML-DSA sigver\n");
            goto end;
        }

        /* Set up params */
        if (pbld) OSSL_PARAM_BLD_free(pbld);
        if (params) OSSL_PARAM_free(params);
        if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);

        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in ML-DSA sigver\n");
            goto end;
        }
        /* Determine if we have mu or message; if MU, set correct flag */
        if (tc->mu_len) {
            msg_ptr = tc->mu;
            msg_len = (size_t)tc->mu_len;
            OSSL_PARAM_BLD_push_int(pbld, OSSL_SIGNATURE_PARAM_MU, 1);
        } else {
            msg_ptr = tc->msg;
            msg_len = (size_t)tc->msg_len;
        }
        if (tc->context) {
            OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_SIGNATURE_PARAM_CONTEXT_STRING, tc->context, tc->context_len);

        }
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in ML-DSA sigver\n");
            goto end;
        }

        /* Set up the CTX's and run the verify */
        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey ctx from pkey in ML-DSA sigver\n");
            goto end;
        }

        sig = EVP_SIGNATURE_fetch(NULL, param_set, NULL);
        if (!sig) {
            printf("Error fetching signature in ML-DSA sigver\n");
            goto end;
        }
        if (EVP_PKEY_verify_message_init(pkey_ctx, sig, params) != 1) {
            printf("Error initializing verify in ML-DSA sigver\n");
            goto end;
        }
        if (EVP_PKEY_verify(pkey_ctx, tc->sig, tc->sig_len, msg_ptr, msg_len) == 1) {
            tc->ver_disposition = 1;
        }

        break;
    default:
        printf("Invalid algorithm provided in ML-DSA handler\n");
        goto end;
    }

    rv = 0;
end:
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (sig) EVP_SIGNATURE_free(sig);
    if (sig_buf) free(sig_buf);
    return rv;
}
