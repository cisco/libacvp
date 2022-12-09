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
#include "safe_lib.h"

#ifdef ACVP_NO_RUNTIME
#include "app_fips_lcl.h" /* All regular OpenSSL headers must come before here */
#endif

int app_kda_hkdf_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDA_HKDF_TC *stc = NULL;
    const EVP_MD *md = NULL;
    int rc = 1, i = 0, fixedInfoLen = 0, tmp = 0, reps = 0, resultLen = 0, resultIterator = 0;
    unsigned int h_output_len = 0, lBits = 0;
    unsigned char *fixedInfo = NULL;
    unsigned char *extract_output = NULL, *expand_output = NULL;
    unsigned char *result = NULL;
    HMAC_CTX *hmac_ctx = NULL;

    if (!test_case) {
        printf("Missing HKDF test case\n");
        return -1;
    }
    stc = test_case->tc.kda_hkdf;
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
    case ACVP_KDA_ENCODING_CONCAT:
        //calculate the size of the buffer we need for fixed info, +4 incase L is included
        fixedInfoLen = stc->literalLen + stc->uPartyIdLen + stc->uEphemeralLen + stc->vPartyIdLen
                     + stc->vEphemeralLen + stc->algIdLen + stc->labelLen + stc->contextLen;
        //add 4 bytes for the int of lengths is used
        for (i = 0; i < ACVP_KDA_PATTERN_MAX; i++) {
            if (stc->fixedInfoPattern[i] == ACVP_KDA_PATTERN_L) {
                fixedInfoLen += 4;
                break;
            }
        }

        fixedInfo = calloc(fixedInfoLen, sizeof(unsigned char));
        for (i = 0; i < ACVP_KDA_PATTERN_MAX; i++) {
            if (stc->fixedInfoPattern[i] == 0) {
                break;
            }
            switch(stc->fixedInfoPattern[i]) {
            case ACVP_KDA_PATTERN_LITERAL:
                if (!stc->literalCandidate) {
                    printf("Test case missing literal pattern data\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->literalCandidate, stc->literalLen);
                tmp += stc->literalLen;
                break;
            case ACVP_KDA_PATTERN_UPARTYINFO:
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
            case ACVP_KDA_PATTERN_VPARTYINFO:
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
            case ACVP_KDA_PATTERN_ALGID:
                if (!stc->algorithmId) {
                    printf("Test case missing algorithmId\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->algorithmId, stc->algIdLen);
                tmp += stc->algIdLen;
                break;
            case ACVP_KDA_PATTERN_LABEL:
                if (!stc->label) {
                    printf("Test case missing label\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->label, stc->labelLen);
                tmp += stc->labelLen;
                break;
            case ACVP_KDA_PATTERN_CONTEXT:
                if (!stc->context) {
                    printf("Test case missing context\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->context, stc->contextLen);
                tmp += stc->contextLen;
                break;
            case ACVP_KDA_PATTERN_L:
                lBits = stc->l * 8;
                if (check_is_little_endian()) { lBits = swap_uint_endian(lBits); }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, (char *)&lBits, 4);
                tmp += 4;
                break;
            case ACVP_KDA_PATTERN_T:
            case ACVP_KDA_PATTERN_NONE:
            case ACVP_KDA_PATTERN_MAX:
            default:
                printf("Invalid fixedInfoPattern candidate value\n");
                goto end;
            }
        }
        break;
    case ACVP_KDA_ENCODING_NONE:
    case ACVP_KDA_ENCODING_MAX:
    default:
        printf("Invalid encoding for fixed info provided in test case\n");
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
    case ACVP_SHA1:
    case ACVP_NO_SHA:
    case ACVP_HASH_ALG_MAX:
    default:
        printf("Invalid hmac algorithm provided in test case\n");
        goto end;
        break;
    }

    //convert h_output_len to bytes for use with functions
    h_output_len /= 8;

    //buffer for first step, extract, output
    extract_output = calloc(h_output_len, sizeof(unsigned char));
    if (!extract_output) {
        printf("Failed to allocate memory for test case\n");
        goto end;
    }

    //extract the pseudorandom key to be used in the creation of keying material in the second step
    if (!HMAC_Init_ex(hmac_ctx, stc->salt, stc->saltLen, md, NULL)) {
        printf("\nCrypto module error, HMAC_Init_ex failed\n");
        goto end;
    }

    if (!HMAC_Update(hmac_ctx, stc->z, stc->zLen)) {
        printf("\nCrypto module error, HMAC_Update failed\n");
        goto end;
    }
    
    if (!HMAC_Final(hmac_ctx, extract_output, &h_output_len)) {
        printf("\nCrypto module error, HMAC_Final failed\n");
        goto end;
    }

    //the number of repetitions in step 2 (always round up)
    //technically, this operation is defined to be done with bits, but using common denominators
    reps = stc->l / h_output_len;
    if (stc->l % h_output_len) {
        reps++;
    }

    //buffer for second step, expand, output
    expand_output = calloc(h_output_len, sizeof(unsigned char));
    if (!expand_output) {
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

    //hkdf as per RFC5869 calls to concatenate extract_output || fixedInfo || counter every iteration
    for (i = 1; i <= reps; i++) {
        unsigned int counter = i;
        if (!check_is_little_endian()) { counter = swap_uint_endian(counter); }
        if (i == 1) {
            if (!HMAC_Init_ex(hmac_ctx, extract_output, h_output_len, md, NULL)) {
                printf("\nCrypto module error, HMAC_Init_ex failed\n");
                goto end;
            }
        } else {
            if (!HMAC_Init_ex(hmac_ctx, NULL, 0, NULL, NULL)) {
                printf("\nCrypto module error, HMAC_Init_ex failed\n");
                goto end;
            }

            if (!HMAC_Update(hmac_ctx, expand_output, h_output_len)) {
                printf("\nCrypto module error, HMAC_Update failed\n");
                goto end;
            }
        }
        if (!HMAC_Update(hmac_ctx, fixedInfo, fixedInfoLen)) {
            printf("\nCrypto module error, HMAC_Update failed\n");
            goto end;
        }
        if (!HMAC_Update(hmac_ctx, (unsigned char *)&counter, 1)) { //1 byte for hkdf, not 4
            printf("\nCrypto module error, HMAC_Update failed\n");
            goto end;
        }

        if (!HMAC_Final(hmac_ctx, expand_output, &h_output_len)) {
            printf("\nCrypto module error, HMAC_Final failed\n");
            goto end;
        }
        //concatenate to previous result
        memcpy_s(result + resultIterator, resultLen - resultIterator, expand_output, h_output_len);
        resultIterator += h_output_len;
        if (resultIterator >= stc->l) {
            break;
        }
    }
    
    memcpy_s(stc->outputDkm, stc->l, result, stc->l);
    rc = 0;
end:
    if (fixedInfo) free(fixedInfo);
    if (extract_output) free(extract_output);
    if (expand_output) free(expand_output);
    if (result) free(result);
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    if (hmac_ctx) HMAC_CTX_cleanup(hmac_ctx);
#else
    if (hmac_ctx) HMAC_CTX_free(hmac_ctx);
#endif
    return rc;
}


int app_kda_onestep_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDA_ONESTEP_TC *stc = NULL;
    const EVP_MD *md = NULL;
    int rc = 1, i = 0, fixedInfoLen = 0, tmp = 0, reps = 0, resultLen = 0, resultIterator = 0, isSha = 0;
    unsigned int h_output_len = 0, lBits = 0;
    unsigned char *fixedInfo = NULL;
    unsigned char *h_output = NULL;
    unsigned char *result = NULL;
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    HMAC_CTX static_ctx;
#endif
    HMAC_CTX *hmac_ctx = NULL;
    EVP_MD_CTX *sha_ctx = NULL;
    ACVP_SUB_HASH hashalg;
    ACVP_SUB_HMAC hmacalg;

    if (!test_case) {
        printf("Missing KDF onestep test case\n");
        return -1;
    }
    stc = test_case->tc.kda_onestep;
    if (!stc) {
        printf("Missing KDF onestep test case\n");
        return -1;
    }

    //if the test case has a salt, we are using HMAC, otherwise, SHA
    if (stc->salt) {
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
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
    case ACVP_KDA_ENCODING_CONCAT:
        //calculate the size of the buffer we need for fixed info, +4 incase L is included
        fixedInfoLen = stc->literalLen + stc->uPartyIdLen + stc->uEphemeralLen + stc->vPartyIdLen
                     + stc->vEphemeralLen + stc->algIdLen + stc->labelLen + stc->contextLen;
        //add 4 bytes for the int of lengths is used
        for (i = 0; i < ACVP_KDA_PATTERN_MAX; i++) {
            if (stc->fixedInfoPattern[i] == ACVP_KDA_PATTERN_L) {
                fixedInfoLen += 4;
                break;
            }
        }

        fixedInfo = calloc(fixedInfoLen, sizeof(unsigned char));
        for (i = 0; i < ACVP_KDA_PATTERN_MAX; i++) {
            if (stc->fixedInfoPattern[i] == 0) {
                break;
            }
            switch(stc->fixedInfoPattern[i]) {
            case ACVP_KDA_PATTERN_LITERAL:
                if (!stc->literalCandidate) {
                    printf("Test case missing literal pattern data\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->literalCandidate, stc->literalLen);
                tmp += stc->literalLen;
                break;
            case ACVP_KDA_PATTERN_UPARTYINFO:
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
            case ACVP_KDA_PATTERN_VPARTYINFO:
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
            case ACVP_KDA_PATTERN_ALGID:
                if (!stc->algorithmId) {
                    printf("Test case missing algorithmId\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->algorithmId, stc->algIdLen);
                tmp += stc->algIdLen;
                break;
            case ACVP_KDA_PATTERN_LABEL:
                if (!stc->label) {
                    printf("Test case missing label\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->label, stc->labelLen);
                tmp += stc->labelLen;
                break;
            case ACVP_KDA_PATTERN_CONTEXT:
                if (!stc->context) {
                    printf("Test case missing context\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->context, stc->contextLen);
                tmp += stc->contextLen;
                break;
            case ACVP_KDA_PATTERN_L:
                lBits = stc->l * 8;
                if (check_is_little_endian()) { lBits = swap_uint_endian(lBits); }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, (char *)&lBits, 4);
                tmp += 4;
                break;
            case ACVP_KDA_PATTERN_NONE:
            case ACVP_KDA_PATTERN_MAX:
            default:
                printf("Invalid fixedInfoPattern candidate value\n");
                goto end;
            }
        }
        break;
    case ACVP_KDA_ENCODING_NONE:
    case ACVP_KDA_ENCODING_MAX:
    default:
        printf("Invalid encoding for fixed info provided in test case\n");
        goto end;
    }

  if (isSha) {
    hashalg = acvp_get_hash_alg(stc->aux_function);
    if (hashalg == 0) {
        printf("Invalid cipher value");
        goto end;
    }

    switch (hashalg) {
    case ACVP_SUB_HASH_SHA2_224:
        md = EVP_sha224();
        h_output_len = 224;
        break;
    case ACVP_SUB_HASH_SHA2_256:
        md = EVP_sha256();
        h_output_len = 256;
        break;
    case ACVP_SUB_HASH_SHA2_384:
        md = EVP_sha384();
        h_output_len = 384;
        break;
    case ACVP_SUB_HASH_SHA2_512:
        md = EVP_sha512();
        h_output_len = 512;
        break;
#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
    case ACVP_SUB_HASH_SHA2_512_224:
        md = EVP_sha512_224();
        h_output_len = 224;
        break;
    case ACVP_SUB_HASH_SHA2_512_256:
        md = EVP_sha512_256();
        h_output_len = 256;
        break;
    case ACVP_SUB_HASH_SHA3_224:
        md = EVP_sha3_224();
        h_output_len = 224;
        break;
    case ACVP_SUB_HASH_SHA3_256:
        md = EVP_sha3_256();
        h_output_len = 256;
        break;
    case ACVP_SUB_HASH_SHA3_384:
        md = EVP_sha3_384();
        h_output_len = 384;
        break;
    case ACVP_SUB_HASH_SHA3_512:
        md = EVP_sha3_512();
        h_output_len = 512;
        break;
#else
    case ACVP_SUB_HASH_SHA2_512_224:
    case ACVP_SUB_HASH_SHA2_512_256:
    case ACVP_SUB_HASH_SHA3_224:
    case ACVP_SUB_HASH_SHA3_256:
    case ACVP_SUB_HASH_SHA3_384:
    case ACVP_SUB_HASH_SHA3_512:
#endif
    case ACVP_SUB_HASH_SHA1:
    case ACVP_SUB_HASH_SHAKE_128:
    case ACVP_SUB_HASH_SHAKE_256:
    default:
        printf("Invalid aux function provided in test case\n");
        goto end;
        break;
    }

  } else {
    hmacalg = acvp_get_hmac_alg(stc->aux_function);
    if (hmacalg == 0) {
        printf("Invalid cipher value");
        goto end;
    }

    switch (hmacalg) {
    case ACVP_SUB_HMAC_SHA2_224:
        md = EVP_sha224();
        h_output_len = 224;
        break;
    case ACVP_SUB_HMAC_SHA2_256:
        md = EVP_sha256();
        h_output_len = 256;
        break;
    case ACVP_SUB_HMAC_SHA2_384:
        md = EVP_sha384();
        h_output_len = 384;
        break;
    case ACVP_SUB_HMAC_SHA2_512:
        md = EVP_sha512();
        h_output_len = 512;
        break;
#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
    case ACVP_SUB_HMAC_SHA2_512_224:
        md = EVP_sha512_224();
        h_output_len = 224;
        break;
    case ACVP_SUB_HMAC_SHA2_512_256:
        md = EVP_sha512_256();
        h_output_len = 256;
        break;
    case ACVP_SUB_HMAC_SHA3_224:
        md = EVP_sha3_224();
        h_output_len = 224;
        break;
    case ACVP_SUB_HMAC_SHA3_256:
        md = EVP_sha3_256();
        h_output_len = 256;
        break;
    case ACVP_SUB_HMAC_SHA3_384:
        md = EVP_sha3_384();
        h_output_len = 384;
        break;
    case ACVP_SUB_HMAC_SHA3_512:
        md = EVP_sha3_512();
        h_output_len = 512;
        break;
#else
    case ACVP_SUB_HMAC_SHA2_512_224:
    case ACVP_SUB_HMAC_SHA2_512_256:
    case ACVP_SUB_HMAC_SHA3_224:
    case ACVP_SUB_HMAC_SHA3_256:
    case ACVP_SUB_HMAC_SHA3_384:
    case ACVP_SUB_HMAC_SHA3_512:
#endif
    case ACVP_SUB_HMAC_SHA1:
    default:
        printf("Invalid aux function provided in test case\n");
        goto end;
        break;
    }
  }
    //convert h_output_len to bytes for use with functions
    h_output_len /= 8;

    //the number of repetitions as defined by SP800-56Cr1 (always round up)
    //technically, this operation is defined to be done with bits, but using common denominators
    reps = stc->l * h_output_len;
    if (stc->l % h_output_len) {
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
    //onestep as per NIST calls to concatenate counter || Z || FixedInfo every iteration
    for (i = 1; i <= reps; i++) {
        unsigned int counter = i;
        if (check_is_little_endian()) { counter = swap_uint_endian(counter); } //nist doc specifically wants big endian byte string
        if (isSha) {
            if (!EVP_DigestInit_ex(sha_ctx, md, NULL)) {
                printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
                goto end;
            }

            if (!EVP_DigestUpdate(sha_ctx, (unsigned char *)&counter, sizeof(int))) {
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

            if (!HMAC_Update(hmac_ctx, (unsigned char *)&counter, sizeof(int))) {
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

        memzero_s(h_output, h_output_len);
        if (resultIterator >= stc->l) {
            break;
        }
    }
    
    memcpy_s(stc->outputDkm, stc->l, result, stc->l);
    rc = 0;
end:
    if (fixedInfo) free(fixedInfo);
    if (h_output) free(h_output);
    if (result) free(result);
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    if (hmac_ctx) HMAC_CTX_cleanup(hmac_ctx);
#else
    if (hmac_ctx) HMAC_CTX_free(hmac_ctx);
#endif
    if (sha_ctx) EVP_MD_CTX_destroy(sha_ctx);
    return rc;
}
