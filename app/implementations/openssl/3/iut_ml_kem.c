/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"
#include "acvp/acvp.h"
#include "safe_lib.h"
#include "implementations/openssl/3/iut.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>


#define ML_KEM_MAX_BUF_SIZE 8192

unsigned char *seed_concatenation(unsigned char *d, int d_len, unsigned char *z, int z_len, int *output_len) {
    unsigned char *out = NULL;
    int out_len = 0;

    out_len = d_len + z_len;
    out = calloc(out_len, sizeof(unsigned char));
    if (!out) {
        printf("Error allocating memory in seed concatenation for ML-KEM\n");
        return NULL;
    }

    memcpy_s(out, out_len, d, d_len);
    memcpy_s(out + d_len, out_len - d_len, z, z_len);

    *output_len = out_len;
    return out;
}

int app_ml_kem_handler(ACVP_TEST_CASE *test_case) {
    ACVP_ML_KEM_TC *tc = NULL;
    ACVP_SUB_ML_KEM alg = 0;
    int rv = 1, seed_len = 0, ossl_ret = 0;
    size_t out_len = 0, out_len_2 = 0;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    const char *param_set = NULL;
    unsigned char *seed = NULL, *out = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;

    if (!test_case) {
        printf("Missing ML-KEM test case\n");
        return -1;
    }

    tc = test_case->tc.ml_kem;
    if (!tc) return rv;

    alg = acvp_get_ml_kem_alg(tc->cipher);
    if (!alg) return rv;

    switch (tc->param_set) {
    case ACVP_ML_KEM_PARAM_SET_ML_KEM_512:
        param_set = "ML-KEM-512";
        break;
    case ACVP_ML_KEM_PARAM_SET_ML_KEM_768:
        param_set = "ML-KEM-768";
        break;
    case ACVP_ML_KEM_PARAM_SET_ML_KEM_1024:
        param_set = "ML-KEM-1024";
        break;
    case ACVP_ML_KEM_PARAM_SET_NONE:
    case ACVP_ML_KEM_PARAM_SET_MAX:
    default:
        printf("Invalid param set in ML-KEM handler\n");
        goto end;
    }

    if (tc->cipher == ACVP_ML_KEM_KEYGEN) {
        seed = seed_concatenation(tc->d, tc->d_len, tc->z, tc->z_len, &seed_len);
        if (!seed) {
            printf("Error building seed variable in ML-KEM keygen\n");
            goto end;
        }

        pbld = OSSL_PARAM_BLD_new();
        if (!pbld) {
            printf("Error creating param_bld in ML-KEM keygen\n");
            goto end;
        }
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_PKEY_PARAM_ML_KEM_SEED, seed, seed_len);
        params = OSSL_PARAM_BLD_to_param(pbld);
        if (!params) {
            printf("Error generating params in ML-KEM keygen\n");
            goto end;
        }

        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, param_set, NULL);
        if (!pkey_ctx) {
            printf("Error initializing pkey CTX in ML-KEM keygen\n");
            goto end;
        }
        if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
            printf("Error initializing keygen in ML-KEM keygen\n");
            goto end;
        }
        if (EVP_PKEY_CTX_set_params(pkey_ctx, params) != 1) {
            printf("Error setting params in ML-KEM keygen\n");
            goto end;
        }
        if (EVP_PKEY_keygen(pkey_ctx, &pkey) != 1) {
            printf("Error generating key in ML-KEM keygen\n");
            goto end;
        }

        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &out_len) == 1) {
            out = calloc(out_len, sizeof(char));
            if (!out) {
                printf("Error allocating memory for ek in ML-KEM keygen\n");
                goto end;
            }
            if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, out, out_len, &out_len) != 1) {
                printf("Error getting ek in ML-KEM keygen\n");
                goto end;
            }
            tc->ek_len = (int)out_len;
            memcpy_s(tc->ek, ML_KEM_MAX_BUF_SIZE, out, out_len);
            free(out);
            out = NULL;
        } else {
            printf("Error getting ek in ML-KEM keygen\n");
            goto end;
        }

        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, &out_len) == 1) {
            out = calloc(out_len, sizeof(char));
            if (!out) {
                printf("Error allocating memory for dk in ML-KEM keygen\n");
                goto end;
            }
            if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, out, out_len, &out_len) != 1) {
                printf("Error getting dk in ML-KEM keygen\n");
                goto end;
            }
            tc->dk_len = (int)out_len;
            memcpy_s(tc->dk, ML_KEM_MAX_BUF_SIZE, out, out_len);
            free(out);
            out = NULL;
        } else {
            printf("Error getting dk in ML-KEM keygen\n");
            goto end;
        }
    } else if (tc->cipher == ACVP_ML_KEM_XCAP) {
        if (tc->function == ACVP_ML_KEM_FUNCTION_ENCAPSULATE || tc->function == ACVP_ML_KEM_FUNCTION_ENC_KEYCHECK) {
            /* First, create the pkey containing the sk we are given */
            pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, param_set, NULL);
            if (!pkey_ctx) {
                printf("Error initializing pkey CTX in ML-KEM encap\n");
                goto end;
            }
            pbld = OSSL_PARAM_BLD_new();
            if (!pbld) {
                printf("Error creating param_bld in ML-KEM encap\n");
                goto end;
            }
            OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_PKEY_PARAM_PUB_KEY, tc->ek, tc->ek_len);
            params = OSSL_PARAM_BLD_to_param(pbld);
            if (!params) {
                printf("Error generating params in ML-KEM encap\n");
                goto end;
            }
            if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
                printf("Error initializing fromdata in ML-KEM encap\n");
                goto end;
            }

            ossl_ret = EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
            if (ossl_ret != 1 && tc->function != ACVP_ML_KEM_FUNCTION_ENC_KEYCHECK) {
                printf("Error generating pkey from private key data in ML-KEM encap\n");
                goto end;
            }

            if (tc->function == ACVP_ML_KEM_FUNCTION_ENC_KEYCHECK) {
                /* if fromdata returns 1, the check was successful, otherwise fail */
                tc->keycheck_disposition = ossl_ret == 1 ? ACVP_TEST_DISPOSITION_PASS : ACVP_TEST_DISPOSITION_FAIL;
                rv = 0;
                goto end;
            }

            if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
            if (pbld) OSSL_PARAM_BLD_free(pbld);
            if (params) OSSL_PARAM_free(params);
            pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
            if (!pkey_ctx) {
                printf("Error initializing pkey ctx from pkey in ML-KEM encap\n");
                goto end;
            }
            pbld = OSSL_PARAM_BLD_new();
            if (!pbld) {
                printf("Error creating param_bld in ML-KEM encap\n");
                goto end;
            }
            OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KEM_PARAM_IKME, tc->m, tc->m_len);
            params = OSSL_PARAM_BLD_to_param(pbld);
            if (!params) {
                printf("Error generating params in ML-KEM encap\n");
                goto end;
            }
            if (EVP_PKEY_encapsulate_init(pkey_ctx, params) != 1) {
                printf("Error initializing encapsulate in ML-KEM encap\n");
                goto end;
            }
            if (EVP_PKEY_encapsulate(pkey_ctx, NULL, &out_len, tc->k, &out_len_2) != 1) {
                printf("Error determining buffer len in ML-KEM encap\n");
                goto end;
            }
            out = calloc(out_len, sizeof(unsigned char));
            if (!out) {
                printf("Error allocating memory in ML-KEM encap\n");
                goto end;
            }
            if (EVP_PKEY_encapsulate(pkey_ctx, out, &out_len, tc->k, &out_len_2) != 1) {
                printf("Error encapsulating in ML-KEM encap\n");
                goto end;
            }
            memcpy_s(tc->c, ML_KEM_MAX_BUF_SIZE, out, out_len);
            tc->c_len = (int)out_len;
            tc->k_len = (int)out_len_2;
        } else if (tc->function == ACVP_ML_KEM_FUNCTION_DECAPSULATE || tc->function == ACVP_ML_KEM_FUNCTION_DEC_KEYCHECK) {
            pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, param_set, NULL);
            if (!pkey_ctx) {
                printf("Error initializing pkey CTX in ML-KEM decap\n");
                goto end;
            }
            pbld = OSSL_PARAM_BLD_new();
            if (!pbld) {
                printf("Error creating param_bld in ML-KEM decap\n");
                goto end;
            }
            OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_PKEY_PARAM_PRIV_KEY, tc->dk, tc->dk_len);
            params = OSSL_PARAM_BLD_to_param(pbld);
            if (!params) {
                printf("Error generating params in ML-KEM decap\n");
                goto end;
            }
            if (EVP_PKEY_fromdata_init(pkey_ctx) != 1) {
                printf("Error initializing fromdata in ML-KEM decap\n");
                goto end;
            }

            ossl_ret = EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PRIVATE_KEY, params);
            if (ossl_ret != 1 && tc->function != ACVP_ML_KEM_FUNCTION_DEC_KEYCHECK) {
                printf("Error generating pkey from private key data in ML-KEM decap\n");
                goto end;
            }

            if (tc->function == ACVP_ML_KEM_FUNCTION_DEC_KEYCHECK) {
                /* if fromdata returns 1, the check was successful, otherwise fail */
                tc->keycheck_disposition = ossl_ret == 1 ? ACVP_TEST_DISPOSITION_PASS : ACVP_TEST_DISPOSITION_FAIL;
                rv = 0;
                goto end;
            }


            if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
            pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
            if (!pkey_ctx) {
                printf("Error initializing pkey ctx from pkey in ML-KEM decap\n");
                goto end;
            }
            if (EVP_PKEY_decapsulate_init(pkey_ctx, params) != 1) {
                printf("Error initializing decapsulate in ML-KEM decap\n");
                goto end;
            }
            if (EVP_PKEY_decapsulate(pkey_ctx, NULL, &out_len, tc->dk, tc->dk_len) != 1) {
                printf("Error determining buffer size in ML-KEM decap\n");
                goto end;
            }
            out = calloc(out_len, sizeof(unsigned char));
            if (!out) {
                printf("Error allocating memory in ML-KEM decap\n");
                goto end;
            }
            if (EVP_PKEY_decapsulate(pkey_ctx, out, &out_len, tc->c, tc->c_len) != 1) {
                printf("Error decapsulating in ML-KEM decap\n");
                goto end;
            }
            memcpy_s(tc->k, ML_KEM_MAX_BUF_SIZE, out, out_len);
            tc->k_len = (int)out_len;
        }
    } else {
        printf("Invalid algorithm provided in ML-KEM handler\n");
        goto end;
    }

    rv = 0;
end:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (seed) free(seed);
    if (out) free(out);
    return rv;
}
