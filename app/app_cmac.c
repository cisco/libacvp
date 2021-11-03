/*
 * Copyright (c) 2021, Cisco Systems, Inc.
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

#ifdef ACVP_NO_RUNTIME
# include "app_fips_lcl.h"
#endif

int app_cmac_handler(ACVP_TEST_CASE *test_case) {
    ACVP_CMAC_TC    *tc;
    int rv = 1;
    const EVP_CIPHER    *c = NULL;
    CMAC_CTX       *cmac_ctx = NULL;
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

    alg = acvp_get_cmac_alg(tc->cipher);
    if (alg == 0) {
        printf("Invalid cipher value");
        return 1;
    }

    switch (alg) {
    case ACVP_SUB_CMAC_AES:
        switch (tc->key_len * 8) {
        case 128:
            c = EVP_aes_128_cbc();
            break;
        case 192:
            c = EVP_aes_192_cbc();
            break;
        case 256:
            c = EVP_aes_256_cbc();
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
        c = EVP_des_ede3_cbc();
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

    cmac_ctx = CMAC_CTX_new();

    if (!CMAC_Init(cmac_ctx, full_key, key_len, c, NULL)) {
        printf("\nCrypto module error, CMAC_Init_ex failed\n");
        goto cleanup;
    }

    if (!CMAC_Update(cmac_ctx, tc->msg, tc->msg_len)) {
        printf("\nCrypto module error, CMAC_Update failed\n");
        goto cleanup;
    }

    if (tc->verify) {
        int diff = 0;

        if (!CMAC_Final(cmac_ctx, mac_compare, &mac_cmp_len)) {
            printf("\nCrypto module error, CMAC_Final failed\n");
            goto cleanup;
        }

        memcmp_s(tc->mac, tc->mac_len, mac_compare, mac_cmp_len, &diff);
        if (!diff) {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_PASS;
        } else {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_FAIL;
        }
    } else {
        if (!CMAC_Final(cmac_ctx, tc->mac, &mac_cmp_len)) {
            printf("\nCrypto module error, CMAC_Final failed\n");
            goto cleanup;
        }
        tc->mac_len = (int)mac_cmp_len;
    }
    rv = 0;

cleanup:
    if (cmac_ctx) CMAC_CTX_free(cmac_ctx);

    return rv;
}

