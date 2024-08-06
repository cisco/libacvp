/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include <openssl/evp.h>
#include <openssl/cmac.h>
#include "acvp/acvp.h"
#include "app_lcl.h"
#include "safe_lib.h"
#include <openssl/param_build.h>
#include <openssl/core_names.h>


int app_cmac_handler(ACVP_TEST_CASE *test_case) {
    ACVP_CMAC_TC *tc;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *cmac_ctx = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    const char *alg_name = NULL;
    int rv = 1;
    int key_len, i;
    unsigned char mac_compare[16] = { 0 };
    char full_key[33] = { 0 };
    size_t mac_cmp_len;
    ACVP_SUB_CMAC alg;

    if (!test_case) {
        return rv;
    }

    tc = test_case->tc.cmac;
    if (!tc) return rv;
    if (!tc->key) return rv;
    if (!tc->mac) return rv;
    if (!tc->msg) return rv;

    alg = acvp_get_cmac_alg(tc->cipher);
    if (alg == 0) {
        printf("Invalid cipher value");
        return 1;
    }

 switch (alg) {
    case ACVP_SUB_CMAC_AES:
        switch (tc->key_len * 8) {
        case 128:
            alg_name = "aes-128-cbc";
            break;
        case 192:
            alg_name = "aes-192-cbc";
            break;
        case 256:
            alg_name = "aes-256-cbc";
            break;
        default:
            break;
        }
        key_len = (tc->key_len);
        for (i = 0; i < key_len; i++) {
            full_key[i] = tc->key[i];
        }
        break;
    case ACVP_SUB_CMAC_TDES:
        alg_name = "des-ede3-cbc";
        for (i = 0; i < 8; i++) {
            full_key[i] = tc->key[i];
        }
        for (; i < 16; i++) {
            full_key[i] = tc->key2[i % 8];
        }
        for (; i < 24; i++) {
            full_key[i] = tc->key3[i % 8];
        }
        key_len = 24;
        break;
    default:
        printf("Error: Unsupported CMAC algorithm requested by ACVP server\n");
        return rv;
    }

    full_key[key_len] = '\0';

    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac) {
        printf("Error: unable to fetch CMAC");
        goto end;
    }
    cmac_ctx = EVP_MAC_CTX_new(mac);
    if (!cmac_ctx) {
        printf("Error: unable to create CMAC CTX");
        goto end;
    }
    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("Error creating param_bld in CMAC\n");
        goto end;
    }
    OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_MAC_PARAM_CIPHER, alg_name, 0);
    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params){
        printf("Error generating params in CMAC\n");
        goto end;
    }

#define CMAC_BUF_MAX 128

    if (!EVP_MAC_init(cmac_ctx, (unsigned char *)full_key, key_len, params)) {
        printf("\nCrypto module error, EVP_MAC_init failed\n");
        goto end;
    }

    if (!EVP_MAC_update(cmac_ctx, tc->msg, tc->msg_len)) {
        printf("\nCrypto module error, EVP_MAC_update failed\n");
        goto end;
    }

    if (tc->verify) {
        int diff = 0;

        if (!EVP_MAC_final(cmac_ctx, mac_compare, &mac_cmp_len, 16)) {
            printf("\nCrypto module error, EVP_MAC_final failed\n");
            goto end;
        }

        memcmp_s(tc->mac, tc->mac_len, mac_compare, mac_cmp_len, &diff);
        if (!diff) {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_PASS;
        } else {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_FAIL;
        }
    } else {
        if (!EVP_MAC_final(cmac_ctx, tc->mac, &mac_cmp_len, CMAC_BUF_MAX)) {
            printf("\nCrypto module error, EVP_MAC_final failed\n");
            goto end;
        }
        tc->mac_len = (int)mac_cmp_len;
    }

    rv = 0;

end:
    if (cmac_ctx) EVP_MAC_CTX_free(cmac_ctx);
    if (mac) EVP_MAC_free(mac);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    return rv;
}

