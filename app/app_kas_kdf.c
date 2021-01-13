/*
 * Copyright (c) 2020, Cisco Systems, Inc.
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
#include "safe_lib.h"

int app_kas_hkdf_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KAS_HKDF_TC *stc = NULL;
    const EVP_MD *md = NULL;
    int rc = 1, i = 0, fixedInfoLen = 0, tmp = 0, reps = 0,
        resultLen = 0, lBits = 0, resultIterator = 0;
    unsigned int h_output_len = 0, count = 0;
    unsigned char *fixedInfo = NULL;
    unsigned char *h_output = NULL;
    unsigned char *result = NULL;
    unsigned char counter[4] = {0};
    HMAC_CTX *hmac_ctx = NULL;

    if (!test_case) {
        printf("Missing HKDF test case\n");
        return -1;
    }
    stc = test_case->tc.kas_hkdf;
    if (!stc) {
        printf("Missing HKDF test case\n");
        return -1;
    }

    #if OPENSSL_VERSION_NUMBER <= 0x10100000L
    HMAC_CTX static_ctx;
    hmac_ctx = &static_ctx;
    HMAC_CTX_init(hmac_ctx);
#else
    hmac_ctx = HMAC_CTX_new();
#endif


    switch (stc->encoding) {
    case ACVP_KAS_KDF_ENCODING_CONCAT:
        //calculate the size of the buffer we need for fixed info, +4 incase L is included
        fixedInfoLen = stc->literalLen + stc->uPartyIdLen + stc->uEphemeralLen + stc->vPartyIdLen
                     + stc->vEphemeralLen + stc->algIdLen + stc->labelLen + stc->contextLen;
        //add 4 bytes for the int of lengths is used
        for(i = 0; i < ACVP_KAS_KDF_PATTERN_MAX; i++) {
            if (stc->fixedInfoPattern[i] == ACVP_KAS_KDF_PATTERN_L) {
                fixedInfoLen += 4;
                break;
            }
        }

        fixedInfo = calloc(fixedInfoLen, sizeof(unsigned char));
        for (i = 0; i < ACVP_KAS_KDF_PATTERN_MAX; i++) {
            if (stc->fixedInfoPattern[i] == 0) {
                break;
            }
            switch(stc->fixedInfoPattern[i]) {
            case ACVP_KAS_KDF_PATTERN_LITERAL:
                if (!stc->literalCandidate) {
                    printf("Test case missing literal pattern data\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->literalCandidate, stc->literalLen);
                tmp += stc->literalLen;
                break;
            case ACVP_KAS_KDF_PATTERN_UPARTYINFO:
                if (!stc->uPartyId) {
                    printf("Test case missing uPartyId\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->uPartyId, stc->uPartyIdLen);
                tmp += stc->uPartyIdLen;
                if (stc->uEphemeralData) {
                    memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->uEphemeralData, stc->uEphemeralLen);
                    tmp += stc->uEphemeralLen;
                }
                break;
            case ACVP_KAS_KDF_PATTERN_VPARTYINFO:
                if (!stc->vPartyId) {
                    printf("Test case missing vPartyId\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->vPartyId, stc->vPartyIdLen);
                tmp += stc->vPartyIdLen;
                if (stc->vEphemeralData) {
                    memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->vEphemeralData, stc->vEphemeralLen);
                    tmp += stc->vEphemeralLen;
                }
                break;
            case ACVP_KAS_KDF_PATTERN_ALGID:
                if (!stc->algorithmId) {
                    printf("Test case missing algorithmId\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->algorithmId, stc->algIdLen);
                tmp += stc->algIdLen;
                break;
            case ACVP_KAS_KDF_PATTERN_LABEL:
                if (!stc->label) {
                    printf("Test case missing label\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->label, stc->labelLen);
                tmp += stc->labelLen;
                break;
            case ACVP_KAS_KDF_PATTERN_CONTEXT:
                if (!stc->context) {
                    printf("Test case missing context\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->context, stc->contextLen);
                tmp += stc->contextLen;
                break;
            case ACVP_KAS_KDF_PATTERN_L:
                lBits = stc->l * 8;
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, &lBits, 4);
                tmp += 4;
                break;
            default:
                printf("Invalid fixedInfoPattern candidate value");
                goto end;
            }
        }
        break;
    default:
        printf("Invalid encoding for fixed info provided in test case");
        goto end;
    }

    switch (stc->hmacAlg) {
    case ACVP_SHA224:
        md = EVP_sha224();
        h_output_len = 224;
        break;
    case ACVP_SHA256:
        md = EVP_sha256();
        h_output_len = 256;
        break;
    case ACVP_SHA384:
        md = EVP_sha384();
        h_output_len = 384;
        break;
    case ACVP_SHA512:
        md = EVP_sha512();
        h_output_len = 512;
        break;
#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
    case ACVP_SHA512_224:
        md = EVP_sha512_224();
        h_output_len = 224;
        break;
    case ACVP_SHA512_256:
        md = EVP_sha512_256();
        h_output_len = 256;
        break;
    case ACVP_SHA3_224:
        md = EVP_sha3_224();
        h_output_len = 224;
        break;
    case ACVP_SHA3_256:
        md = EVP_sha3_256();
        h_output_len = 256;
        break;
    case ACVP_SHA3_384:
        md = EVP_sha3_384();
        h_output_len = 384;
        break;
    case ACVP_SHA3_512:
        md = EVP_sha3_512();
        h_output_len = 512;
        break;
#else
    case ACVP_SHA512_224:
    case ACVP_SHA512_256:
    case ACVP_SHA3_224:
    case ACVP_SHA3_256:
    case ACVP_SHA3_384:
    case ACVP_SHA3_512:
#endif
    default:
        printf("Invalid hmac algorithm provided in test case\n");
        goto end;
        break;
    }

    //convert h_output_len to bytes for use with functions
    h_output_len /= 8;

    //the number of repetitions as defined by SP800-56Cr1 (always round up)
    reps = (stc->l * 8) / (h_output_len * 8);
    if ((stc->l * 8) % (h_output_len * 8) != 0) {
        reps++;
    }

    //buffer for H function output
    h_output = calloc(h_output_len, sizeof(unsigned char));
    if (!h_output) {
        printf("Failed to allocate memory for test case\n");
        goto end;
    }

    //the spec calls us to concatenate the previous loops result to the new one.
    //this might be a big buffer.
    resultLen = h_output_len * reps;
    result = calloc(resultLen, sizeof(unsigned char));
    if (!result) {
        printf("Failed to allocate memory for test case\n");
        goto end;
    }

    //onestep/hkdf as per NIST calls to concatenate counter || Z || FixedInfo every iteration
    for (i = 1; i <= reps; i++) {
        count++;
        memcpy_s(&counter, sizeof(int), &count, sizeof(int)); //dodge some compiler warnings
        if (!HMAC_Init_ex(hmac_ctx, stc->salt, stc->saltLen, md, NULL)) {
            printf("\nCrypto module error, HMAC_Init_ex failed\n");
            goto end;
        }

        if (!HMAC_Update(hmac_ctx, &counter[0], sizeof(int))) {
            printf("\nCrypto module error, HMAC_Update failed\n");
            goto end;
        }

        if (!HMAC_Update(hmac_ctx, stc->z, stc->zLen)) {
            printf("\nCrypto module error, HMAC_Update failed\n");
            goto end;
        }
        if (!HMAC_Update(hmac_ctx, fixedInfo, fixedInfoLen)) {
            printf("\nCrypto module error, HMAC_Update failed\n");
            goto end;
        }

        if (!HMAC_Final(hmac_ctx, h_output, &h_output_len)) {
            printf("\nCrypto module error, HMAC_Final failed\n");
            goto end;
        }
        //concatenate to previous result
        memcpy_s(result + resultIterator, resultLen - resultIterator, h_output, h_output_len);
        resultIterator += h_output_len;

        //zero out our buffers for re-use just in case
        memzero_s(h_output, h_output_len);
    }
    
    memcpy_s(stc->outputDkm, stc->l, result, stc->l);
    rc = 0;
end:
    if (fixedInfo) free(fixedInfo);
    if (h_output) free(h_output);
    if (result) free(result);
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    HMAC_CTX_cleanup(hmac_ctx);
#else
    if (hmac_ctx) HMAC_CTX_free(hmac_ctx);
#endif
    return rc;
}


int app_kas_kdf_onestep_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KAS_KDF_ONESTEP_TC *stc = NULL;
    const EVP_MD *md = NULL;
    int rc = 1, i = 0, fixedInfoLen = 0, tmp = 0, reps = 0,
        resultLen = 0, lBits = 0, resultIterator = 0, isSha = 0;
    unsigned int h_output_len = 0, count = 0;
    unsigned char *fixedInfo = NULL;
    unsigned char *h_output = NULL;
    unsigned char *result = NULL;
    unsigned char counter[4] = {0};
    HMAC_CTX *hmac_ctx = NULL;
    EVP_MD_CTX *sha_ctx = NULL;

    if (!test_case) {
        printf("Missing KDF onestep test case\n");
        return -1;
    }
    stc = test_case->tc.kas_kdf_onestep;
    if (!stc) {
        printf("Missing KDF onestep test case\n");
        return -1;
    }

    //if the test case has a salt, we are using HMAC, otherwise, SHA
    if (stc->salt) {
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        HMAC_CTX static_ctx;
        hmac_ctx = &static_ctx;
        HMAC_CTX_init(hmac_ctx);
#else
        hmac_ctx = HMAC_CTX_new();
#endif
    } else {
        sha_ctx = EVP_MD_CTX_create();
        isSha = 1;
    }


    switch (stc->encoding) {
    case ACVP_KAS_KDF_ENCODING_CONCAT:
        //calculate the size of the buffer we need for fixed info, +4 incase L is included
        fixedInfoLen = stc->literalLen + stc->uPartyIdLen + stc->uEphemeralLen + stc->vPartyIdLen
                     + stc->vEphemeralLen + stc->algIdLen + stc->labelLen + stc->contextLen;
        //add 4 bytes for the int of lengths is used
        for(i = 0; i < ACVP_KAS_KDF_PATTERN_MAX; i++) {
            if (stc->fixedInfoPattern[i] == ACVP_KAS_KDF_PATTERN_L) {
                fixedInfoLen += 4;
                break;
            }
        }

        fixedInfo = calloc(fixedInfoLen, sizeof(unsigned char));
        for (i = 0; i < ACVP_KAS_KDF_PATTERN_MAX; i++) {
            if (stc->fixedInfoPattern[i] == 0) {
                break;
            }
            switch(stc->fixedInfoPattern[i]) {
            case ACVP_KAS_KDF_PATTERN_LITERAL:
                if (!stc->literalCandidate) {
                    printf("Test case missing literal pattern data\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->literalCandidate, stc->literalLen);
                tmp += stc->literalLen;
                break;
            case ACVP_KAS_KDF_PATTERN_UPARTYINFO:
                if (!stc->uPartyId) {
                    printf("Test case missing uPartyId\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->uPartyId, stc->uPartyIdLen);
                tmp += stc->uPartyIdLen;
                if (stc->uEphemeralData) {
                    memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->uEphemeralData, stc->uEphemeralLen);
                    tmp += stc->uEphemeralLen;
                }
                break;
            case ACVP_KAS_KDF_PATTERN_VPARTYINFO:
                if (!stc->vPartyId) {
                    printf("Test case missing vPartyId\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->vPartyId, stc->vPartyIdLen);
                tmp += stc->vPartyIdLen;
                if (stc->vEphemeralData) {
                    memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->vEphemeralData, stc->vEphemeralLen);
                    tmp += stc->vEphemeralLen;
                }
                break;
            case ACVP_KAS_KDF_PATTERN_ALGID:
                if (!stc->algorithmId) {
                    printf("Test case missing algorithmId\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->algorithmId, stc->algIdLen);
                tmp += stc->algIdLen;
                break;
            case ACVP_KAS_KDF_PATTERN_LABEL:
                if (!stc->label) {
                    printf("Test case missing label\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->label, stc->labelLen);
                tmp += stc->labelLen;
                break;
            case ACVP_KAS_KDF_PATTERN_CONTEXT:
                if (!stc->context) {
                    printf("Test case missing context\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->context, stc->contextLen);
                tmp += stc->contextLen;
                break;
            case ACVP_KAS_KDF_PATTERN_L:
                lBits = stc->l * 8;
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, &lBits, 4);
                tmp += 4;
                break;
            default:
                printf("Invalid fixedInfoPattern candidate value");
                goto end;
            }
        }
        break;
    default:
        printf("Invalid encoding for fixed info provided in test case");
        goto end;
    }

    switch (stc->aux_function) {
    case ACVP_HASH_SHA224:
    case ACVP_HMAC_SHA2_224:
        md = EVP_sha224();
        h_output_len = 224;
        break;
    case ACVP_HASH_SHA256:
    case ACVP_HMAC_SHA2_256:
        md = EVP_sha256();
        h_output_len = 256;
        break;
    case ACVP_HASH_SHA384:
    case ACVP_HMAC_SHA2_384:
        md = EVP_sha384();
        h_output_len = 384;
        break;
    case ACVP_HASH_SHA512:
    case ACVP_HMAC_SHA2_512:
        md = EVP_sha512();
        h_output_len = 512;
        break;
#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
    case ACVP_HASH_SHA512_224:
    case ACVP_HMAC_SHA2_512_224:
        md = EVP_sha512_224();
        h_output_len = 224;
        break;
    case ACVP_HASH_SHA512_256:
    case ACVP_HMAC_SHA2_512_256:
        md = EVP_sha512_256();
        h_output_len = 256;
        break;
    case ACVP_HASH_SHA3_224:
    case ACVP_HMAC_SHA3_224:
        md = EVP_sha3_224();
        h_output_len = 224;
        break;
    case ACVP_HASH_SHA3_256:
    case ACVP_HMAC_SHA3_256:
        md = EVP_sha3_256();
        h_output_len = 256;
        break;
    case ACVP_HASH_SHA3_384:
    case ACVP_HMAC_SHA3_384:
        md = EVP_sha3_384();
        h_output_len = 384;
        break;
    case ACVP_HASH_SHA3_512:
    case ACVP_HMAC_SHA3_512:
        md = EVP_sha3_512();
        h_output_len = 512;
        break;
#else
    case ACVP_HASH_SHA512_224:
    case ACVP_HMAC_SHA2_512_224:
    case ACVP_HASH_SHA512_256:
    case ACVP_HMAC_SHA2_512_256:
    case ACVP_HASH_SHA3_224:
    case ACVP_HMAC_SHA3_224:
    case ACVP_HASH_SHA3_256:
    case ACVP_HMAC_SHA3_256:
    case ACVP_HASH_SHA3_384:
    case ACVP_HMAC_SHA3_384:
    case ACVP_HASH_SHA3_512:
    case ACVP_HMAC_SHA3_512:
#endif
    default:
        printf("Invalid aux function provided in test case\n");
        goto end;
        break;
    }

    //convert h_output_len to bytes for use with functions
    h_output_len /= 8;

    //the number of repetitions as defined by SP800-56Cr1 (always round up)
    reps = (stc->l * 8) / (h_output_len * 8);
    if ((stc->l * 8) % (h_output_len * 8) != 0) {
        reps++;
    }

    //buffer for H function output
    h_output = calloc(h_output_len, sizeof(unsigned char));
    if (!h_output) {
        printf("Failed to allocate memory for test case\n");
        goto end;
    }

    //the spec calls us to concatenate the previous loops result to the new one.
    //this might be a big buffer.
    resultLen = h_output_len * reps;
    result = calloc(resultLen, sizeof(unsigned char));
    if (!result) {
        printf("Failed to allocate memory for test case\n");
        goto end;
    }
    //onestep/hkdf as per NIST calls to concatenate counter || Z || FixedInfo every iteration
    for (i = 1; i <= reps; i++) {
        count++;
        memcpy_s(&counter, sizeof(int), &count, sizeof(int)); //dodge some compiler warnings

        if (isSha) {
            if (!EVP_DigestInit_ex(sha_ctx, md, NULL)) {
                printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
                goto end;
            }

            if (!EVP_DigestUpdate(sha_ctx, &counter[0], sizeof(int))) {
                printf("\nCrypto module error, EVP_DigestUpdate failed\n");
                goto end;
            }

            if (!EVP_DigestUpdate(sha_ctx, stc->z, stc->zLen)) {
                printf("\nCrypto module error, EVP_DigestUpdate failed\n");
                goto end;
            }

            if (!EVP_DigestUpdate(sha_ctx, fixedInfo, fixedInfoLen)) {
                printf("\nCrypto module error, EVP_DigestUpdate failed\n");
                goto end;
            }

            if (!EVP_DigestFinal(sha_ctx, h_output, &h_output_len)) {
                printf("\nCrypto module error, EVP_DigestFinal failed\n");
                goto end;
            }
        } else {
            if (!HMAC_Init_ex(hmac_ctx, stc->salt, stc->saltLen, md, NULL)) {
                printf("\nCrypto module error, HMAC_Init_ex failed\n");
                goto end;
            }

            if (!HMAC_Update(hmac_ctx, &counter[0], sizeof(int))) {
                printf("\nCrypto module error, HMAC_Update failed\n");
                goto end;
            }

            if (!HMAC_Update(hmac_ctx, stc->z, stc->zLen)) {
                printf("\nCrypto module error, HMAC_Update failed\n");
                goto end;
            }
            if (!HMAC_Update(hmac_ctx, fixedInfo, fixedInfoLen)) {
                printf("\nCrypto module error, HMAC_Update failed\n");
                goto end;
            }

            if (!HMAC_Final(hmac_ctx, h_output, &h_output_len)) {
                printf("\nCrypto module error, HMAC_Final failed\n");
                goto end;
            }
        }
        //concatenate to previous result
        memcpy_s(result + resultIterator, resultLen - resultIterator, h_output, h_output_len);
        resultIterator += h_output_len;

        //zero out our buffers for re-use just in case
        memzero_s(h_output, h_output_len);
    }
    
    memcpy_s(stc->outputDkm, stc->l, result, stc->l);
    rc = 0;
end:
    if (fixedInfo) free(fixedInfo);
    if (h_output) free(h_output);
    if (result) free(result);
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    HMAC_CTX_cleanup(hmac_ctx);
#else
    if (hmac_ctx) HMAC_CTX_free(hmac_ctx);
#endif
    if (sha_ctx) EVP_MD_CTX_destroy(sha_ctx);
    return rc;
}
