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

#define SLH_DSA_MAX_BUF_SIZE 50000

int app_slh_dsa_handler(ACVP_TEST_CASE *test_case) {
    ACVP_SLH_DSA_TC *tc = NULL;
    ACVP_SUB_SLH_DSA alg = 0;
    int rv = 1;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig = NULL;
    size_t sk_len = 0, pk_len = 0, sig_len = 0, seed_len = 0;
    const char *param_set = NULL;
    unsigned char *sig_buf = NULL,  *seed = NULL;
    if (!test_case) {
        printf("Missing SLH-DSA test case\n");
        return -1;
    }

    tc = test_case->tc.slh_dsa;
    if (!tc) return rv;

    alg = acvp_get_slh_dsa_alg(tc->cipher);
    if (!alg) return rv;

    switch (tc->param_set) {
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHA2_128S:
        param_set = "SLH-DSA-SHA2-128s";
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHA2_128F:
        param_set = "SLH-DSA-SHA2-128f";
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHA2_192S:
        param_set = "SLH-DSA-SHA2-192s";
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHA2_192F:
        param_set = "SLH-DSA-SHA2-192f";
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHA2_256S:
        param_set = "SLH-DSA-SHA2-256s";
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHA2_256F:
        param_set = "SLH-DSA-SHA2-256f";
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHAKE_128S:
        param_set = "SLH-DSA-SHAKE-128s";
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHAKE_128F:
        param_set = "SLH-DSA-SHAKE-128f";
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHAKE_192S:
        param_set = "SLH-DSA-SHAKE-192s";
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHAKE_192F:
        param_set = "SLH-DSA-SHAKE-192f";
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHAKE_256S:
        param_set = "SLH-DSA-SHAKE-256s";
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHAKE_256F:
        param_set = "SLH-DSA-SHAKE-256f";
        break;
    case ACVP_SLH_DSA_PARAM_SET_NONE:
    case ACVP_SLH_DSA_PARAM_SET_MAX:
    default:
        printf("Invalid param set in SLH-DSA handler\n");
        return -1;
    }

    switch (alg) {
    case ACVP_SUB_SLH_DSA_KEYGEN:
        /* concatenate secret_seed, secret_prf, and pub_seed */
        seed_len = tc->secret_seed_len + tc->secret_prf_len + tc->pub_seed_len;
        seed = calloc(seed_len, sizeof(char));
        if (!seed) {
            printf("Error allocating memory in SLH-DSA keygen\n");
            goto end;
        }
        memcpy_s(seed, seed_len,  tc->secret_seed, tc->secret_seed_len);
        memcpy_s(seed + tc->secret_seed_len, seed_len - tc->secret_seed_len, tc->secret_prf, tc->secret_prf_len);
        memcpy_s(seed + tc->secret_seed_len + tc->secret_prf_len, seed_len - tc->secret_seed_len - tc->secret_prf_len, tc->pub_seed, tc->pub_seed_len);

        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in SLH-DSA\n");
            goto end;
        }
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_PKEY_PARAM_SLH_DSA_SEED, seed, seed_len);
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in SLH-DSA keygen\n");
            goto end;
        }
        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, param_set, NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey CTX in SLH-DSA keygen\n");
            goto end;
        }
        if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
            printf("Error initializing keygen in SLH-DSA keygen\n");
            goto end;
        }
        if (EVP_PKEY_CTX_set_params(pkey_ctx, params) != 1) {
            printf("Error setting params in SLH-DSA keygen\n");
            goto end;
        }
        EVP_PKEY_keygen(pkey_ctx, &pkey);
        if (!pkey) {
            printf("Error generating key in SLH-DSA keygen\n");
            goto end;
        }
        EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, tc->secret_key, SLH_DSA_MAX_BUF_SIZE, &sk_len);
        EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, tc->pub_key, SLH_DSA_MAX_BUF_SIZE, &pk_len);
        tc->secret_key_len = (int)sk_len;
        tc->pub_key_len = (int)pk_len;
        break;
    case ACVP_SUB_SLH_DSA_SIGGEN:
        /* First, create the pkey containing the sk we are given */
        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, param_set, NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey CTX in SLH-DSA siggen\n");
            goto end;
        }
        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in SLH-DSA siggen\n");
            goto end;
        }
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_PKEY_PARAM_PRIV_KEY, tc->secret_key, tc->secret_key_len);
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in SLH-DSA siggen\n");
            goto end;
        }
        if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
            printf("Error initializing fromdata in SLH-DSA siggen\n");
            goto end;
        }
        if (EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PRIVATE_KEY, params) != 1) {
            printf("Error generating pkey from private key data in SLH-DSA siggen\n");
            goto end;
        }

        /* Then, create the signature object */
        sig = EVP_SIGNATURE_fetch(NULL, param_set, NULL);
        if (!sig) {
            printf("Error fetching signature in SLH-DSA siggen\n");
            goto end;
        }
        /* Then, use that pkey to sign. Start generating new params */
        if (pbld) OSSL_PARAM_BLD_free(pbld);
        if (params) OSSL_PARAM_free(params);

        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in SLH-DSA siggen\n");
            goto end;
        }
        OSSL_PARAM_BLD_push_int(pbld, OSSL_SIGNATURE_PARAM_DETERMINISTIC, tc->is_deterministic);
        if (tc->rnd_len) {
            OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_SIGNATURE_PARAM_TEST_ENTROPY, tc->rnd, tc->rnd_len);
        }

        if (tc->sig_interface == ACVP_SIG_INTERFACE_EXTERNAL) {
            OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_SIGNATURE_PARAM_CONTEXT_STRING, tc->context, tc->context_len);
        } else {
            OSSL_PARAM_BLD_push_int(pbld, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, 0);
        }
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in SLH-DSA siggen\n");
            goto end;
        }

        /* Initialize and perform sig operation */
        if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey ctx from pkey in SLH-DSA siggen\n");
            goto end;
        }
        if (EVP_PKEY_sign_message_init(pkey_ctx, sig, params) != 1) {
            printf("Error initializing sign operation in SLH-DSA siggen\n");
            goto end;
        }
        EVP_PKEY_sign(pkey_ctx, NULL, &sig_len, tc->msg, (size_t)tc->msg_len);
        sig_buf = calloc(sig_len, sizeof(char));
        if (!sig_buf) {
            printf("Error allocating memory in SLH-DSA siggen\n");
            goto end;
        }
        if (EVP_PKEY_sign(pkey_ctx, sig_buf, &sig_len, tc->msg, (size_t)tc->msg_len) != 1) {
            printf("Error generating signature in SLH-DSA siggen\n");
            goto end;
        }

        /* Copy results back into test case */
        memcpy_s(tc->sig, SLH_DSA_MAX_BUF_SIZE, sig_buf, sig_len);
        tc->sig_len = (int)sig_len;

        break;
    case ACVP_SUB_SLH_DSA_SIGVER:
        tc->ver_disposition = 0;

        /* First, create the pkey containing the pk we are given */
        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, param_set, NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey CTX in SLH-DSA sigver\n");
            goto end;
        }
        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in SLH-DSA sigver\n");
            goto end;
        }
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_PKEY_PARAM_PUB_KEY, tc->pub_key, tc->pub_key_len);
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in SLH-DSA sigver\n");
            goto end;
        }
        if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
            printf("Error initializing fromdata in SLH-DSA sigver\n");
            goto end;
        }
        if (EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            printf("Error generating pkey from private key data in SLH-DSA sigver\n");
            goto end;
        }

        /* Set up params */
        if (pbld) OSSL_PARAM_BLD_free(pbld);
        if (params) OSSL_PARAM_free(params);
        if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);

        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in SLH-DSA sigver\n");
            goto end;
        }

        if (tc->sig_interface == ACVP_SIG_INTERFACE_EXTERNAL) {
            OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_SIGNATURE_PARAM_CONTEXT_STRING, tc->context, tc->context_len);
        } else {
            OSSL_PARAM_BLD_push_int(pbld, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, 0);
        }
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in SLH-DSA sigver\n");
            goto end;
        }

        /* Set up the CTX's and run the verify */
        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey ctx from pkey in SLH-DSA sigver\n");
            goto end;
        }

        sig = EVP_SIGNATURE_fetch(NULL, param_set, NULL);
        if (!sig) {
            printf("Error fetching signature in SLH-DSA sigver\n");
            goto end;
        }
        if (EVP_PKEY_verify_message_init(pkey_ctx, sig, params) != 1) {
            printf("Error initializing verify in SLH-DSA sigver\n");
            goto end;
        }
        if (EVP_PKEY_verify(pkey_ctx, tc->sig, tc->sig_len, tc->msg, (size_t)tc->msg_len) == 1) {
            tc->ver_disposition = 1;
        }

        break;
    default:
        printf("Invalid algorithm provided in SLH-DSA handler\n");
        goto end;
    }

    rv = 0;
end:
    ERR_print_errors_fp(stderr);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (sig) EVP_SIGNATURE_free(sig);
    if (sig_buf) free(sig_buf);
    if (seed) free(seed);
    return rv;
}
