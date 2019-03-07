/*****************************************************************************
* Copyright (c) 2019, Cisco Systems, Inc.
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

#include <openssl/evp.h>
#include <openssl/cmac.h>
#include "acvp/acvp.h"
#include "app_lcl.h"
#include "safe_lib.h"

int app_cmac_handler(ACVP_TEST_CASE *test_case) {
    ACVP_CMAC_TC    *tc;
    int rv = 1;
    const EVP_CIPHER    *c = NULL;
    CMAC_CTX       *cmac_ctx = NULL;
    int key_len, i;
    unsigned char mac_compare[16] = { 0 };
    char full_key[32] = { 0 };
    int mac_cmp_len;

    if (!test_case) {
        return rv;
    }

    tc = test_case->tc.cmac;
    if (!tc) return rv;
    if (!tc->key) return rv;

    switch (tc->cipher) {
    case ACVP_CMAC_AES:
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
    case ACVP_CMAC_TDES:
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

        if (!CMAC_Final(cmac_ctx, mac_compare, (size_t *)&mac_cmp_len)) {
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
        if (!CMAC_Final(cmac_ctx, tc->mac, (size_t *)&tc->mac_len)) {
            printf("\nCrypto module error, CMAC_Final failed\n");
            goto cleanup;
        }
    }
    rv = 0;

cleanup:
    if (cmac_ctx) CMAC_CTX_free(cmac_ctx);

    return rv;
}

