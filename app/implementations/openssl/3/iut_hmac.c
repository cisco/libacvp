/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "acvp/acvp.h"
#include "app_lcl.h"
#include "safe_lib.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>

int app_hmac_handler(ACVP_TEST_CASE *test_case) {
    ACVP_HMAC_TC    *tc;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *hmac_ctx = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    const char *md_name = NULL;
    int msg_len;
    int rv = 1;
    ACVP_SUB_HMAC alg;

    if (!test_case) {
        return rv;
    }

    tc = test_case->tc.hmac;
    if (!tc) return rv;

    alg = acvp_get_hmac_alg(tc->cipher);
    if (alg == 0) {
        printf("Invalid cipher value");
        return 1;
    }

    msg_len = tc->msg_len;

    switch (alg) {
    case ACVP_SUB_HMAC_SHA1:
        md_name = ACVP_STR_SHA_1;
        break;
    case ACVP_SUB_HMAC_SHA2_224:
        md_name = ACVP_STR_SHA2_224;
        break;
    case ACVP_SUB_HMAC_SHA2_256:
        md_name = ACVP_STR_SHA2_256;
        break;
    case ACVP_SUB_HMAC_SHA2_384:
        md_name = ACVP_STR_SHA2_384;
        break;
    case ACVP_SUB_HMAC_SHA2_512:
        md_name = ACVP_STR_SHA2_512;
        break;
    case ACVP_SUB_HMAC_SHA2_512_224:
        md_name = ACVP_STR_SHA2_512_224;
        break;
    case ACVP_SUB_HMAC_SHA2_512_256:
        md_name = ACVP_STR_SHA2_512_256;
        break;
    case ACVP_SUB_HMAC_SHA3_224:
        md_name = ACVP_STR_SHA3_224;
        break;
    case ACVP_SUB_HMAC_SHA3_256:
        md_name = ACVP_STR_SHA3_256;
        break;
    case ACVP_SUB_HMAC_SHA3_384:
        md_name = ACVP_STR_SHA3_384;
        break;
    case ACVP_SUB_HMAC_SHA3_512:
        md_name = ACVP_STR_SHA3_512;
        break;
    default:
        printf("Error: Unsupported hash algorithm requested by ACVP server\n");
        return rv;

        break;
    }

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        printf("Error: unable to fetch HMAC");
        goto end;
    }
    hmac_ctx = EVP_MAC_CTX_new(mac);
    if (!hmac_ctx) {
        printf("Error: unable to create HMAC CTX");
        goto end;
    }

    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("Error creating param_bld in HMAC\n");
        goto end;
    }
    OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_MAC_PARAM_DIGEST, md_name, 0);
    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params in HMAC\n");
        goto end;
    }

#define HMAC_BUF_MAX 128

    if (!EVP_MAC_init(hmac_ctx, tc->key, tc->key_len, params)) {
        printf("\nCrypto module error, EVP_MAC_init failed\n");
        goto end;
    }

    if (!EVP_MAC_update(hmac_ctx, tc->msg, msg_len)) {
        printf("\nCrypto module error, EVP_MAC_update failed\n");
        goto end;
    }

    if (!EVP_MAC_final(hmac_ctx, tc->mac, (long unsigned int *)&tc->mac_len, HMAC_BUF_MAX)) {
        printf("\nCrypto module error, EVP_MAC_final failed\n");
        goto end;
    }

    rv = 0;

end:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (hmac_ctx) EVP_MAC_CTX_free(hmac_ctx);
    if (mac) EVP_MAC_free(mac);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    return rv;
}

