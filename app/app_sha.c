/*****************************************************************************
* Copyright (c) 2019, Cisco Systems, Inc.
* All rights reserved.

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

#include "acvp/acvp.h"
#include "app_lcl.h"

int app_sha_handler(ACVP_TEST_CASE *test_case) {
    ACVP_HASH_TC    *tc;
    const EVP_MD    *md;
    EVP_MD_CTX *md_ctx = NULL;
    /* assume fail */
    int rc = 1;

    if (!test_case) {
        return 1;
    }

    tc = test_case->tc.hash;
    if (!tc) return rc;

    switch (tc->cipher) {
    case ACVP_HASH_SHA1:
        md = EVP_sha1();
        break;
    case ACVP_HASH_SHA224:
        md = EVP_sha224();
        break;
    case ACVP_HASH_SHA256:
        md = EVP_sha256();
        break;
    case ACVP_HASH_SHA384:
        md = EVP_sha384();
        break;
    case ACVP_HASH_SHA512:
        md = EVP_sha512();
        break;
    default:
        printf("Error: Unsupported hash algorithm requested by ACVP server\n");
        return ACVP_NO_CAP;

        break;
    }

    if (!tc->md) {
        printf("\nCrypto module error, md memory not allocated by library\n");
        goto end;
    }
    md_ctx = EVP_MD_CTX_create();

    /* If Monte Carlo we need to be able to init and then update
     * one thousand times before we complete each iteration.
     */
    if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT) {
        if (!tc->m1 || !tc->m2 || !tc->m3) {
            printf("\nCrypto module error, m1, m2, or m3 missing in sha mct test case\n");
            goto end;
        }
        if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
            printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
            goto end;
        }
        if (!EVP_DigestUpdate(md_ctx, tc->m1, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestUpdate(md_ctx, tc->m2, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestUpdate(md_ctx, tc->m3, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestFinal(md_ctx, tc->md, &tc->md_len)) {
            printf("\nCrypto module error, EVP_DigestFinal failed\n");
            goto end;
        }
    } else {
        if (!tc->msg) {
            printf("\nCrypto module error, msg missing in sha test case\n");
            goto end;
        }
        if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
            printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
            goto end;
        }

        if (!EVP_DigestUpdate(md_ctx, tc->msg, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestFinal(md_ctx, tc->md, &tc->md_len)) {
            printf("\nCrypto module error, EVP_DigestFinal failed\n");
            goto end;
        }
    }

    rc = 0;

end:
    if (md_ctx) EVP_MD_CTX_destroy(md_ctx);

    return rc;
}

