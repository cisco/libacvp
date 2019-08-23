/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "acvp/acvp.h"
#include "app_lcl.h"

int app_hmac_handler(ACVP_TEST_CASE *test_case) {
    ACVP_HMAC_TC    *tc;
    const EVP_MD    *md;
    HMAC_CTX *hmac_ctx = NULL;
    int msg_len;
    int rc = 1;

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    HMAC_CTX static_ctx;
#endif

    if (!test_case) {
        return rc;
    }

    tc = test_case->tc.hmac;
    if (!tc) return rc;

    switch (tc->cipher) {
    case ACVP_HMAC_SHA1:
        md = EVP_sha1();
        break;
    case ACVP_HMAC_SHA2_224:
        md = EVP_sha224();
        break;
    case ACVP_HMAC_SHA2_256:
        md = EVP_sha256();
        break;
    case ACVP_HMAC_SHA2_384:
        md = EVP_sha384();
        break;
    case ACVP_HMAC_SHA2_512:
        md = EVP_sha512();
        break;
    case ACVP_HMAC_SHA2_512_224:
        md = EVP_sha512_224();
        break;
    case ACVP_HMAC_SHA2_512_256:
        md = EVP_sha512_256();
        break;
    default:
        printf("Error: Unsupported hash algorithm requested by ACVP server\n");
        return rc;

        break;
    }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    hmac_ctx = &static_ctx;
    HMAC_CTX_init(hmac_ctx);
#else
    hmac_ctx = HMAC_CTX_new();
#endif
    msg_len = tc->msg_len;

    if (!HMAC_Init_ex(hmac_ctx, tc->key, tc->key_len, md, NULL)) {
        printf("\nCrypto module error, HMAC_Init_ex failed\n");
        goto end;
    }

    if (!HMAC_Update(hmac_ctx, tc->msg, msg_len)) {
        printf("\nCrypto module error, HMAC_Update failed\n");
        goto end;
    }

    if (!HMAC_Final(hmac_ctx, tc->mac, &tc->mac_len)) {
        printf("\nCrypto module error, HMAC_Final failed\n");
        goto end;
    }

    rc = 0;

end:
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    HMAC_CTX_cleanup(hmac_ctx);
#else
    if (hmac_ctx) HMAC_CTX_free(hmac_ctx);
#endif

    return rc;
}

