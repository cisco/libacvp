/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"
#include "safe_mem_lib.h"

#include <openssl/evp.h>
#include <openssl/err.h>

int app_sha_ldt_handler(ACVP_HASH_TC *tc, const EVP_MD *md);

int app_sha_handler(ACVP_TEST_CASE *test_case) {
    ACVP_HASH_TC    *tc;
    const EVP_MD    *md;
    EVP_MD_CTX *md_ctx = NULL;
    // assume fail
    int rv = 1;
    int sha3 = 0, shake = 0;
    ACVP_SUB_HASH alg;
    unsigned char *mct_msg = NULL;
    size_t mct_msg_len = 0;

    if (!test_case) {
        return 1;
    }

    tc = test_case->tc.hash;
    if (!tc) return rv;

    alg = acvp_get_hash_alg(tc->cipher);
    if (alg == 0) {
        printf("Invalid cipher value");
        return 1;
    }

    switch (alg) {
    case ACVP_SUB_HASH_SHA1:
        md = EVP_sha1();
        break;
    case ACVP_SUB_HASH_SHA2_224:
        md = EVP_sha224();
        break;
    case ACVP_SUB_HASH_SHA2_256:
        md = EVP_sha256();
        break;
    case ACVP_SUB_HASH_SHA2_384:
        md = EVP_sha384();
        break;
    case ACVP_SUB_HASH_SHA2_512:
        md = EVP_sha512();
        break;
    case ACVP_SUB_HASH_SHA2_512_224:
        md = EVP_sha512_224();
        break;
    case ACVP_SUB_HASH_SHA2_512_256:
        md = EVP_sha512_256();
        break;
    case ACVP_SUB_HASH_SHA3_224:
        md = EVP_sha3_224();
        sha3 = 1;
        break;
    case ACVP_SUB_HASH_SHA3_256:
        md = EVP_sha3_256();
        sha3 = 1;
        break;
    case ACVP_SUB_HASH_SHA3_384:
        md = EVP_sha3_384();
        sha3 = 1;
        break;
    case ACVP_SUB_HASH_SHA3_512:
        md = EVP_sha3_512();
        sha3 = 1;
        break;
    case ACVP_SUB_HASH_SHAKE_128:
        md = EVP_shake128();
        shake = 1;
        break;
    case ACVP_SUB_HASH_SHAKE_256:
        md = EVP_shake256();
        shake = 1;
        break;
    default:
        printf("Error: Unsupported hash algorithm requested by ACVP server\n");
        return ACVP_NO_CAP;
    }

    if (!tc->md) {
        printf("\nCrypto module error, md memory not allocated by library\n");
        goto end;
    }
    md_ctx = EVP_MD_CTX_create();
    if (tc->test_type == ACVP_HASH_TEST_TYPE_LDT) {
        rv = app_sha_ldt_handler(tc, md);
        goto end;
    } else if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT && !sha3 && !shake) {
        /* If Monte Carlo we need to be able to init and then update
         * one thousand times before we complete each iteration.
         * This style doesn't apply to sha3 MCT.
         */
        if (!tc->m1 || !tc->m2 || !tc->m3) {
            printf("\nCrypto module error, m1, m2, or m3 missing in sha mct test case\n");
            goto end;
        }
        if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
            printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
        }

        // We can either use this helper function, or concatenate m1/m2/m3 ourselves
        mct_msg = acvp_hash_create_mct_msg(tc, &mct_msg_len);
        if (!mct_msg) {
            printf("Library failed to generate mct message for test when asked\n");
            goto end;
        }
        if (!EVP_DigestUpdate(md_ctx, mct_msg, mct_msg_len)) {
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

        if (shake) {
            if (!EVP_DigestFinalXOF(md_ctx, tc->md, tc->xof_len)) {
                printf("\nCrypto module error, EVP_DigestFinalXOF failed\n");
                goto end;
            }
            tc->md_len = tc->xof_len;
        } else if (!EVP_DigestFinal(md_ctx, tc->md, &tc->md_len)) {
            printf("\nCrypto module error, EVP_DigestFinal failed\n");
            goto end;
        }
    }

    rv = 0;

end:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (md_ctx) EVP_MD_CTX_destroy(md_ctx);
    if (mct_msg) free(mct_msg);
    return rv;
}

/**
 * 1) malloc buffer, concat full message, process with a single call;
 * 2) oneshot function or a single call to update; never multiple calls to update
 * 3) allowed for all SHA, not SHAKE
 */
int app_sha_ldt_handler(ACVP_HASH_TC *tc, const EVP_MD *md) {
    unsigned char *large_data = NULL, *iter = NULL;
    int numcopies = 0, i = 0, rv = 1;
    EVP_MD_CTX *md_ctx = NULL;

    printf("Performing hash large data test (This may take time...)\n");

    large_data = calloc(tc->exp_len, sizeof(unsigned char));
    if (!large_data) {
        printf("Error: Unable to allocate memory for large data test (Needed %llu bytes)\n", tc->exp_len);
        return 1;
    }

    // We have to copy the message into the buffer many times. Assume concatenation as it is the only mode currently
    numcopies = tc->exp_len / tc->msg_len;
    iter = large_data;
    for (i = 0; i < numcopies; i++) {
        memcpy_s(iter, tc->exp_len - (i * tc->msg_len), tc->msg, tc->msg_len);
        iter += tc->msg_len;
    }

    md_ctx = EVP_MD_CTX_create();

    if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
        printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
        goto end;
    }

    // Update MUST only be called once
    if (!EVP_DigestUpdate(md_ctx, large_data, tc->exp_len)) {
        printf("\nCrypto module error, EVP_DigestUpdate failed\n");
        goto end;
    }
    if (!EVP_DigestFinal(md_ctx, tc->md, &tc->md_len)) {
        printf("\nCrypto module error, EVP_DigestFinal failed\n");
        goto end;
    }

    rv = 0;
end:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (large_data) free(large_data);
    if (md_ctx) EVP_MD_CTX_destroy(md_ctx);
    return rv;
}
