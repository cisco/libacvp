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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#endif
#include "acvp/acvp.h"
#include "app_lcl.h"
#include "safe_lib.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
int app_kda_hkdf_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDA_HKDF_TC *stc = NULL;
    int rc = 1, i = 0, tmp = 0, fixedInfoLen = 0, lBits = 0;
    unsigned char *fixedInfo = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    const char *md = NULL;

    if (!test_case) {
        printf("Missing HKDF test case\n");
        return -1;
    }
    stc = test_case->tc.kda_hkdf;
    if (!stc) {
        printf("Missing HKDF test case\n");
        return -1;
    }

    switch (stc->encoding) {
    case ACVP_KDA_ENCODING_CONCAT:
        //calculate the size of the buffer we need for fixed info, +4 incase L is included
        fixedInfoLen = stc->literalLen + stc->uPartyIdLen + stc->uEphemeralLen + stc->vPartyIdLen
                     + stc->vEphemeralLen + stc->algIdLen + stc->labelLen + stc->contextLen + stc->tLen;
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
                if (!stc->t) {
                    printf("Test case missing t\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->t, stc->tLen);
                tmp += stc->tLen;
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

    md = get_md_string_for_hash_alg(stc->hmacAlg);
    if (!md) {
        printf("Invalid hmac alg in KDA-HKDF\n");
        goto end;
    }
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        printf("Error creating KDF CTX in HKDF\n");
        goto end;
    }
    pbld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(pbld, "digest", md, 0);
    OSSL_PARAM_BLD_push_octet_string(pbld, "key", stc->z, (size_t)stc->zLen);
    OSSL_PARAM_BLD_push_octet_string(pbld, "info", fixedInfo, (size_t)fixedInfoLen);
    OSSL_PARAM_BLD_push_octet_string(pbld, "salt", stc->salt, (size_t)stc->saltLen);
    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params in HKDF\n");
        goto end;
    }
    if (EVP_KDF_derive(kctx, stc->outputDkm, stc->l, params) != 1) {
        printf("Failure deriving key material in KDA-HKDF\n");
        goto end;
    }
    rc = 0;
end:
    OSSL_PARAM_BLD_free(pbld);
    OSSL_PARAM_free(params);
    if (fixedInfo) free(fixedInfo);
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    return rc;
}


int app_kda_onestep_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDA_ONESTEP_TC *stc = NULL;
    int rc = 1, i = 0, tmp = 0, fixedInfoLen = 0, lBits = 0;
    unsigned char *fixedInfo = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    const char *md = NULL, *mac = NULL;
    ACVP_SUB_HASH hashalg;
    ACVP_SUB_HMAC hmacalg;

    if (!test_case) {
        printf("Missing OneStep test case\n");
        return -1;
    }
    stc = test_case->tc.kda_onestep;
    if (!stc) {
        printf("Missing OneStep test case\n");
        return -1;
    }

    switch (stc->encoding) {
    case ACVP_KDA_ENCODING_CONCAT:
        //calculate the size of the buffer we need for fixed info, +4 incase L is included
        fixedInfoLen = stc->literalLen + stc->uPartyIdLen + stc->uEphemeralLen + stc->vPartyIdLen
                     + stc->vEphemeralLen + stc->algIdLen + stc->labelLen + stc->contextLen + stc->tLen;
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
                if (!stc->t) {
                    printf("Test case missing t\n");
                    goto end;
                }
                memcpy_s(fixedInfo + tmp, fixedInfoLen - tmp, stc->t, stc->tLen);
                tmp += stc->tLen;
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

    if (!stc->salt) {
        hashalg = acvp_get_hash_alg(stc->aux_function);
        if (hashalg == 0) {
            printf("Invalid cipher value");
            goto end;
        }
        switch (hashalg) {
        case ACVP_SUB_HASH_SHA1:
            md = "SHA-1";
            break;
        case ACVP_SUB_HASH_SHA2_224:
            md = "SHA2-224";
            break;
        case ACVP_SUB_HASH_SHA2_256:
            md = "SHA2-256";
            break;
        case ACVP_SUB_HASH_SHA2_384:
            md = "SHA2-384";
            break;
        case ACVP_SUB_HASH_SHA2_512:
            md = "SHA2-512";
            break;
        case ACVP_SUB_HASH_SHA2_512_224:
            md = "SHA2-512/224";
            break;
        case ACVP_SUB_HASH_SHA2_512_256:
            md = "SHA2-512/256";
            break;
        case ACVP_SUB_HASH_SHA3_224:
            md = "SHA3-224";
            break;
        case ACVP_SUB_HASH_SHA3_256:
            md = "SHA3-256";
            break;
        case ACVP_SUB_HASH_SHA3_384:
            md = "SHA3-384";
            break;
        case ACVP_SUB_HASH_SHA3_512:
            md = "SHA3-512";
            break;
        case ACVP_SUB_HASH_SHAKE_128:
        case ACVP_SUB_HASH_SHAKE_256:
        default:
            printf("Invalid aux function provided in test case\n");
            goto end;
        }
    } else {
        hmacalg = acvp_get_hmac_alg(stc->aux_function);
        if (hmacalg == 0) {
            printf("Invalid cipher value");
            goto end;
        }
        mac = "HMAC";
        switch (hmacalg) {
        case ACVP_SUB_HMAC_SHA1:
            md = "SHA-1";
            break;
        case ACVP_SUB_HMAC_SHA2_224:
            md = "SHA2-224";
            break;
        case ACVP_SUB_HMAC_SHA2_256:
            md = "SHA2-256";
            break;
        case ACVP_SUB_HMAC_SHA2_384:
            md = "SHA2-384";
            break;
        case ACVP_SUB_HMAC_SHA2_512:
            md = "SHA2-512";
            break;
        case ACVP_SUB_HMAC_SHA2_512_224:
            md = "SHA2-512/224";
            break;
        case ACVP_SUB_HMAC_SHA2_512_256:
            md = "SHA2-512/256";
            break;
        case ACVP_SUB_HMAC_SHA3_224:
            md = "SHA3-224";
            break;
        case ACVP_SUB_HMAC_SHA3_256:
            md = "SHA3-256";
            break;
        case ACVP_SUB_HMAC_SHA3_384:
            md = "SHA3-384";
            break;
        case ACVP_SUB_HMAC_SHA3_512:
            md = "SHA3-512";
            break;
        default:
            printf("Invalid aux function provided in test case\n");
            goto end;
        }
    }
    if (!md) {
        printf("Invalid hmac alg in KDA-OneStep\n");
        goto end;
    }

    kdf = EVP_KDF_fetch(NULL, "SSKDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        printf("Error creating KDF CTX in KDA Onestep\n");
        goto end;
    }
    pbld = OSSL_PARAM_BLD_new();
    if (stc->salt) {
        OSSL_PARAM_BLD_push_utf8_string(pbld, "mac", mac, 0);
        OSSL_PARAM_BLD_push_octet_string(pbld, "salt", stc->salt, (size_t)stc->saltLen);
    }
    OSSL_PARAM_BLD_push_utf8_string(pbld, "digest", md, 0);
    OSSL_PARAM_BLD_push_octet_string(pbld, "key", stc->z, (size_t)stc->zLen);
    OSSL_PARAM_BLD_push_octet_string(pbld, "info", fixedInfo, (size_t)fixedInfoLen);
    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params in KDA Onestep\n");
        goto end;
    }
    if (EVP_KDF_derive(kctx, stc->outputDkm, stc->l, params) != 1) {
        printf("Failure deriving key material in KDA-OneStep\n");
        goto end;
    }
    rc = 0;
end:
    OSSL_PARAM_BLD_free(pbld);
    OSSL_PARAM_free(params);
    if (fixedInfo) free(fixedInfo);
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    return rc;
}

#else //SSL < 3.0

int app_kda_hkdf_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    printf("No application support\n");
    return 1;
}

int app_kda_onestep_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    printf("No application support\n");
    return 1;
}

#endif