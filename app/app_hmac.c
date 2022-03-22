/*
 * Copyright (c) 2021, Cisco Systems, Inc.
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
#if defined ACVP_NO_RUNTIME && OPENSSL_VERSION_NUMBER < 0x30000000L
#include "app_fips_lcl.h"
#endif

int app_hmac_handler(ACVP_TEST_CASE *test_case) {
    ACVP_HMAC_TC    *tc;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined ACV_LEGACY_HMAC
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *hmac_ctx = NULL;
    OSSL_PARAM params[2];
    const char *md_name;
#else
    const EVP_MD *md = NULL;
    HMAC_CTX *hmac_ctx = NULL;
#endif
    int msg_len;
    int rc = 1;
    ACVP_SUB_HMAC alg;

    if (!test_case) {
        return rc;
    }

    tc = test_case->tc.hmac;
    if (!tc) return rc;

    alg = acvp_get_hmac_alg(tc->cipher);
    if (alg == 0) {
        printf("Invalid cipher value");
        return 1;
    }

    msg_len = tc->msg_len;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined ACV_LEGACY_HMAC
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
        return rc;

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

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*)md_name, 0);
    params[1] = OSSL_PARAM_construct_end();

#define HMAC_BUF_MAX 512

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

    rc = 0;

#else

    switch (alg) {
    case ACVP_SUB_HMAC_SHA1:
        md = EVP_sha1();
        break;
    case ACVP_SUB_HMAC_SHA2_224:
        md = EVP_sha224();
        break;
    case ACVP_SUB_HMAC_SHA2_256:
        md = EVP_sha256();
        break;
    case ACVP_SUB_HMAC_SHA2_384:
        md = EVP_sha384();
        break;
    case ACVP_SUB_HMAC_SHA2_512:
        md = EVP_sha512();
        break;
    case ACVP_SUB_HMAC_SHA2_512_224:
        md = EVP_sha512_224();
        break;
    case ACVP_SUB_HMAC_SHA2_512_256:
        md = EVP_sha512_256();
        break;
    case ACVP_SUB_HMAC_SHA3_224:
        md = EVP_sha3_224();
        break;
    case ACVP_SUB_HMAC_SHA3_256:
        md = EVP_sha3_256();
        break;
    case ACVP_SUB_HMAC_SHA3_384:
        md = EVP_sha3_384();
        break;
    case ACVP_SUB_HMAC_SHA3_512:
        md = EVP_sha3_512();
        break;
    default:
        printf("Error: Unsupported hash algorithm requested by ACVP server\n");
        return rc;

        break;
    }

    hmac_ctx = HMAC_CTX_new();

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
#endif

end:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined ACV_LEGACY_HMAC
    if (hmac_ctx) EVP_MAC_CTX_free(hmac_ctx);
    if (mac) EVP_MAC_free(mac);
#else
    if (hmac_ctx) HMAC_CTX_free(hmac_ctx);
#endif
    return rc;
}

