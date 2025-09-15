/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "acvp/acvp.h"
#include "app_lcl.h"
#include "safe_lib.h"
#include "implementations/openssl/3/iut.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>

int app_cshake_handler(ACVP_TEST_CASE *test_case) {
    ACVP_CSHAKE_TC *tc = NULL;
    EVP_MD *md = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    const char *alg_name = NULL;
    int rv = 1;
    ACVP_SUB_CSHAKE alg = 0;

    if (!test_case) {
        printf("Missing CSHAKE test case from library\n");
        return rv;
    }

    tc = test_case->tc.cshake;
    if (!tc) {
        printf("Missing CSHAKE test case from library\n");
        return rv;
    }

    if ( !tc->msg) {
        printf("Missing key/msg/md/maclen in CSHAKE test case\n");
        return rv;
    }

    if (tc->custom_len && !(tc->custom || tc->custom_hex)) {
        printf("Missing customization buffer in CSHAKE test case\n");
        return rv;
    }


    alg = acvp_get_cshake_alg(tc->cipher);
    if (alg == 0) {
        printf("Invalid cipher value in CSHAKE");
        return 1;
    }

    switch (alg) {
    case ACVP_SUB_CSHAKE_128:
        alg_name = "CSHAKE-128";
        break;
    case ACVP_SUB_CSHAKE_256:
        alg_name = "CSHAKE-256";
        break;
    default:
        printf("Error: Unsupported CSHAKE algorithm requested by ACVP server\n");
        return rv;
    }

    md = EVP_MD_fetch(NULL, alg_name, NULL);
    if (!md) {
        printf("Error: unable to fetch CSHAKE");
        goto end;
    }
    md_ctx = EVP_MD_CTX_create();
    if (!md_ctx) {
        printf("Error: unable to create CSHAKE CTX");
        goto end;
    }

    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("error creating param_bld in CSHAKE\n");
        goto end;
    }

    OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_DIGEST_PARAM_N, tc->function_name, tc->function_name_len);
    OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_DIGEST_PARAM_S, tc->custom, tc->custom_len);
    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params for cSHAKE\n");
        goto end;
    }

    if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
        printf("Crypto module error, EVP_DigestInit_ex failed\n");
        goto end;
    }

    if (EVP_MD_CTX_set_params(md_ctx, params) != 1) {
        printf("Error setting cSHAKE params\n");
        goto end;
    }

    if (!EVP_DigestUpdate(md_ctx, tc->msg, tc->msg_len)) {
        printf("Crypto module error, EVP_DigestUpdate failed\n");
        goto end;
    }

    if (!EVP_DigestFinalXOF(md_ctx, tc->md, tc->md_len)) {
        printf("Crypto module error, EVP_DigestFinalXOF failed\n");
        goto end;
    }

    rv = 0;

end:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (md) EVP_MD_free(md);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    return rv;
}
