/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "safe_lib.h"

int app_kmac_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KMAC_TC *tc;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *kmac_ctx = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    const char *alg_name = NULL;
    unsigned char *mac_compare = NULL;
    int rv = 1, diff = 1;
    size_t mac_out_len;
    ACVP_SUB_KMAC alg;

    if (!test_case) {
        printf("Missing KMAC test case from library\n");
        return rv;
    }

    tc = test_case->tc.kmac;
    if (!tc) {
        printf("Missing KMAC test case from library\n");
        return rv;
    }

    if (!tc->key || !tc->msg || !tc->mac || !tc->mac_len) {
        printf("Missing key/msg/mac/maclen in KMAC test case\n");
        return rv;
    }

    if (tc->custom_len && !(tc->custom || tc->custom_hex)) {
        printf("Missing customization buffer in KMAC test case\n");
        return rv;
    }


    alg = acvp_get_kmac_alg(tc->cipher);
    if (alg == 0) {
        printf("Invalid cipher value in KMAC");
        return 1;
    }

    switch (alg) {
    case ACVP_SUB_KMAC_128:
        alg_name = "KMAC-128";
        break;
    case ACVP_SUB_KMAC_256:
        alg_name = "KMAC-256";
        break;
    default:
        printf("Error: Unsupported KMAC algorithm requested by ACVP server\n");
        return rv;
    }

    mac = EVP_MAC_fetch(NULL, alg_name, NULL);
    if (!mac) {
        printf("Error: unable to fetch KMAC");
        goto end;
    }
    kmac_ctx = EVP_MAC_CTX_new(mac);
    if (!kmac_ctx) {
        printf("Error: unable to create KMAC CTX");
        goto end;
    }

    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("error creating param_bld in KMAC\n");
        goto end;
    }
    OSSL_PARAM_BLD_push_int(pbld, OSSL_MAC_PARAM_XOF, tc->xof);
    OSSL_PARAM_BLD_push_uint(pbld, OSSL_MAC_PARAM_SIZE, (unsigned int)tc->mac_len);
    if (tc->hex_customization) {
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_MAC_PARAM_CUSTOM, tc->custom_hex, tc->custom_len);
    } else {
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_MAC_PARAM_CUSTOM, tc->custom, tc->custom_len);
    }
    params = OSSL_PARAM_BLD_to_param(pbld);
#define KMAC_BUF_MAX 8192

    if (!EVP_MAC_init(kmac_ctx, tc->key, tc->key_len, params)) {
        printf("Crypto module error, EVP_MAC_init failed\n");
        goto end;
    }

    if (!EVP_MAC_update(kmac_ctx, tc->msg, tc->msg_len)) {
        printf("Crypto module error, EVP_MAC_update failed\n");
        goto end;
    }
    /* Get output size */
    if (!EVP_MAC_final(kmac_ctx, NULL, &mac_out_len, 0)) {
        printf("Crypto module error, EVP_MAC_final failed\n");
        goto end;
    }
        
    if (tc->test_type == ACVP_KMAC_TEST_TYPE_MVT) {
        mac_compare = calloc(mac_out_len, sizeof(unsigned char));
        if (!mac_compare) {
            printf("Error allocating memory in KMAC verify\n");
            goto end;
        }

        if (!EVP_MAC_final(kmac_ctx, mac_compare, &mac_out_len, mac_out_len)) {
            printf("\nCrypto module error, EVP_MAC_final failed\n");
            goto end;
        }

        memcmp_s(tc->mac, tc->mac_len, mac_compare, mac_out_len, &diff);
        if (!diff) {
            tc->disposition = ACVP_TEST_DISPOSITION_PASS;
        } else {
            tc->disposition = ACVP_TEST_DISPOSITION_FAIL;
        }
    } else {
        if ((int)mac_out_len != tc->mac_len) {
            printf("Error: output KMAC not the correct length\n");
            goto end;
        }

        if (!EVP_MAC_final(kmac_ctx, tc->mac, &mac_out_len, KMAC_BUF_MAX)) {
            printf("\nCrypto module error, EVP_MAC_final failed\n");
            goto end;
        }
    }

    rv = 0;

end:
    if (kmac_ctx) EVP_MAC_CTX_free(kmac_ctx);
    if (mac) EVP_MAC_free(mac);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (mac_compare) free(mac_compare);
    return rv;
}
