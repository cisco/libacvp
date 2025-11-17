/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"
#include "acvp/acvp.h"
#include "safe_lib.h"
#include "implementations/openssl/3/iut.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>

static unsigned char *fixed_info_gen_concat(ACVP_KDA_PATTERN_CANDIDATE *fixedInfoPattern,
                                            unsigned char *literalCandidate,
                                            unsigned char *uPartyId,
                                            unsigned char *uEphemeralData,
                                            unsigned char *vPartyId,
                                            unsigned char *vEphemeralData,
                                            unsigned char *algId,
                                            unsigned char *label,
                                            unsigned char *context,
                                            unsigned char *t,
                                            int literalLen,
                                            int uPartyIdLen,
                                            int uEphemeralLen,
                                            int vPartyIdLen,
                                            int vEphemeralLen,
                                            int algIdLen,
                                            int labelLen,
                                            int contextLen,
                                            int tLen,
                                            int l,
                                            int *fixedInfoLen) {
    unsigned char *fixedInfo = NULL;
    int totalLen = 0, i = 0, tmp = 0, lBits = 0, rv = 1;

    // calculate the size of the buffer we need for fixed info, +4 incase L is included
    totalLen = literalLen + uPartyIdLen + uEphemeralLen + vPartyIdLen
                    + vEphemeralLen + algIdLen + labelLen + contextLen + tLen;
    // add 4 bytes for the int of lengths is used
    for (i = 0; i < ACVP_KDA_PATTERN_MAX; i++) {
        if (fixedInfoPattern[i] == ACVP_KDA_PATTERN_L) {
            totalLen += 4;
            break;
        }
    }

    fixedInfo = calloc(totalLen, sizeof(unsigned char));
    if (!fixedInfo) {
        printf("Error allocating memory for fixedInfo\n");
        goto end;
    }
    for (i = 0; i < ACVP_KDA_PATTERN_MAX; i++) {
        if (fixedInfoPattern[i] == 0) {
            break;
        }
        switch(fixedInfoPattern[i]) {
        case ACVP_KDA_PATTERN_LITERAL:
            if (!literalCandidate) {
                printf("Test case missing literal pattern data\n");
                goto end;
            }
            memcpy_s(fixedInfo + tmp, totalLen - tmp, literalCandidate, literalLen);
            tmp += literalLen;
            break;
        case ACVP_KDA_PATTERN_UPARTYINFO:
            if (!uPartyId) {
                printf("Test case missing uPartyId\n");
                goto end;
            }
            memcpy_s(fixedInfo + tmp, totalLen - tmp, uPartyId, uPartyIdLen);
            tmp += uPartyIdLen;
            if (uEphemeralData) {
                memcpy_s(fixedInfo + tmp, totalLen - tmp, uEphemeralData, uEphemeralLen);
                tmp += uEphemeralLen;
            }
            break;
        case ACVP_KDA_PATTERN_VPARTYINFO:
            if (!vPartyId) {
                printf("Test case missing vPartyId\n");
                goto end;
            }
            memcpy_s(fixedInfo + tmp, totalLen - tmp, vPartyId, vPartyIdLen);
            tmp += vPartyIdLen;
            if (vEphemeralData) {
                memcpy_s(fixedInfo + tmp, totalLen - tmp, vEphemeralData, vEphemeralLen);
                tmp += vEphemeralLen;
            }
            break;
        case ACVP_KDA_PATTERN_ALGID:
            if (!algId) {
                printf("Test case missing algorithmId\n");
                goto end;
            }
            memcpy_s(fixedInfo + tmp, totalLen - tmp, algId, algIdLen);
            tmp += algIdLen;
            break;
        case ACVP_KDA_PATTERN_LABEL:
            if (!label) {
                printf("Test case missing label\n");
                goto end;
            }
            memcpy_s(fixedInfo + tmp, totalLen - tmp, label, labelLen);
            tmp += labelLen;
            break;
        case ACVP_KDA_PATTERN_CONTEXT:
            if (!context) {
                printf("Test case missing context\n");
                goto end;
            }
            memcpy_s(fixedInfo + tmp, totalLen - tmp, context, contextLen);
            tmp += contextLen;
            break;
        case ACVP_KDA_PATTERN_L:
            lBits = l * 8;
            if (check_is_little_endian()) { lBits = swap_uint_endian(lBits); }
            memcpy_s(fixedInfo + tmp, totalLen - tmp, (char *)&lBits, 4);
            tmp += 4;
            break;
        case ACVP_KDA_PATTERN_T:
            if (!t) {
                printf("Test case missing t\n");
                goto end;
            }
            memcpy_s(fixedInfo + tmp, totalLen - tmp, t, tLen);
            tmp += tLen;
            break;
        case ACVP_KDA_PATTERN_NONE:
        case ACVP_KDA_PATTERN_MAX:
        default:
            printf("Invalid fixedInfoPattern candidate value\n");
            goto end;
        }
    }

    rv = 0;
end:
    if (rv) {
        if (fixedInfo) free(fixedInfo);
        fixedInfo = NULL;
    } else {
        *fixedInfoLen = totalLen;
    }
    return fixedInfo;
}

int app_kda_hkdf_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDA_HKDF_TC *stc = NULL;
    int rv = 1, fixedInfoLen = 0;
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
    if (stc->encoding != ACVP_KDA_ENCODING_CONCAT) {
        printf("Unsupported encoding provided for KDA HKDF\n");
        goto end;
    }

    fixedInfo = fixed_info_gen_concat(stc->fixedInfoPattern, stc->literalCandidate, stc->uPartyId,
                                      stc->uEphemeralData, stc->vPartyId, stc->vEphemeralData,
                                      stc->algorithmId, stc->label, stc->context, stc->t,
                                      stc->literalLen, stc->uPartyIdLen, stc->uEphemeralLen,
                                      stc->vPartyIdLen, stc->vEphemeralLen, stc->algIdLen,
                                      stc->labelLen, stc->contextLen, stc->tLen, stc->l, &fixedInfoLen);
    if (!fixedInfo) {
        printf("Error creating fixed info\n");
        goto end;
    }

    md = get_md_string_for_hash_alg(stc->hmacAlg, NULL);
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
    if (!pbld) {
        printf("Error creating param_bld in HKDF\n");
        goto end;
    }
    OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_DIGEST, md, 0);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_KEY, stc->z, (size_t)stc->zLen);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_INFO, fixedInfo, (size_t)fixedInfoLen);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_SALT, stc->salt, (size_t)stc->saltLen);
    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params in HKDF\n");
        goto end;
    }
    if (EVP_KDF_derive(kctx, stc->outputDkm, stc->l, params) != 1) {
        printf("Failure deriving key material in KDA-HKDF\n");
        goto end;
    }
    rv = 0;
end:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (fixedInfo) free(fixedInfo);
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    return rv;
}


int app_kda_onestep_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDA_ONESTEP_TC *stc = NULL;
    int rv = 1, fixedInfoLen = 0;
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
    if (stc->encoding != ACVP_KDA_ENCODING_CONCAT) {
        printf("Unsupported encoding provided for KDA onestep\n");
        goto end;
    }

    fixedInfo = fixed_info_gen_concat(stc->fixedInfoPattern, stc->literalCandidate, stc->uPartyId,
                                      stc->uEphemeralData, stc->vPartyId, stc->vEphemeralData,
                                      stc->algorithmId, stc->label, stc->context, stc->t,
                                      stc->literalLen, stc->uPartyIdLen, stc->uEphemeralLen,
                                      stc->vPartyIdLen, stc->vEphemeralLen, stc->algIdLen,
                                      stc->labelLen, stc->contextLen, stc->tLen, stc->l, &fixedInfoLen);
    if (!fixedInfo) {
        printf("Error creating fixed info\n");
        goto end;
    }

    if (stc->aux_function == ACVP_KMAC_128) {
        mac = "KMAC128";
    } else if (stc->aux_function == ACVP_KMAC_256) {
        mac = "KMAC256";
    } else if (!stc->salt) {
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

    kdf = EVP_KDF_fetch(NULL, "SSKDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        printf("Error creating KDF CTX in KDA Onestep\n");
        goto end;
    }
    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("Error creating param_bld in KDA Onestep\n");
        goto end;
    }
    if (stc->salt) {
        OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_MAC, mac, 0);
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_SALT, stc->salt, (size_t)stc->saltLen);
    }
    if (md) {
        OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_DIGEST, md, 0);
    }
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_KEY, stc->z, (size_t)stc->zLen);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_INFO, fixedInfo, (size_t)fixedInfoLen);
    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params in KDA Onestep\n");
        goto end;
    }
    if (EVP_KDF_derive(kctx, stc->outputDkm, stc->l, params) != 1) {
        printf("Failure deriving key material in KDA-OneStep\n");
        goto end;
    }
    rv = 0;
end:
    if (rv != 0) ERR_print_errors_fp(stderr);
    OSSL_PARAM_BLD_free(pbld);
    OSSL_PARAM_free(params);
    if (fixedInfo) free(fixedInfo);
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    return rv;
}

int app_kda_twostep_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDA_TWOSTEP_TC *stc = NULL;
    int rv = 1, fixedInfoLen = 0;
    unsigned char *fixedInfo = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    const char *alg = NULL;
    if (!test_case) {
        printf("Missing TwoStep test case\n");
        return -1;
    }
    stc = test_case->tc.kda_twostep;
    if (!stc) {
        printf("Missing TwoStep test case\n");
        return -1;
    }
    if (stc->encoding != ACVP_KDA_ENCODING_CONCAT) {
        printf("Unsupported encoding provided for KDA twostep\n");
        goto end;
    }

    fixedInfo = fixed_info_gen_concat(stc->fixedInfoPattern, stc->literalCandidate, stc->uPartyId,
                                      stc->uEphemeralData, stc->vPartyId, stc->vEphemeralData,
                                      stc->algorithmId, stc->label, stc->context, stc->t,
                                      stc->literalLen, stc->uPartyIdLen, stc->uEphemeralLen,
                                      stc->vPartyIdLen, stc->vEphemeralLen, stc->algIdLen,
                                      stc->labelLen, stc->contextLen, stc->tLen, stc->l, &fixedInfoLen);
    if (!fixedInfo) {
        printf("Error creating fixed info\n");
        goto end;
    }

    switch (stc->macFunction) {
    case ACVP_KDF108_MAC_MODE_HMAC_SHA1:
        alg = "SHA-1";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA224:
        alg = "SHA2-224";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA256:
        alg = "SHA2-256";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA384:
        alg = "SHA2-384";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA512:
        alg = "SHA2-512";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA512_224:
        alg = "SHA2-512/224";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA512_256:
        alg = "SHA2-512/256";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA3_224:
        alg = "SHA3-224";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA3_256:
        alg = "SHA3-256";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA3_384:
        alg = "SHA3-384";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA3_512:
        alg = "SHA3-512";
        break;
    case ACVP_KDF108_MAC_MODE_KMAC_128:
    case ACVP_KDF108_MAC_MODE_KMAC_256:
    case ACVP_KDF108_MAC_MODE_CMAC_AES128:
    case ACVP_KDF108_MAC_MODE_CMAC_AES192:
    case ACVP_KDF108_MAC_MODE_CMAC_AES256:
    case ACVP_KDF108_MAC_MODE_MIN:
    case ACVP_KDF108_MAC_MODE_CMAC_TDES:
    case ACVP_KDF108_MAC_MODE_MAX:
    default:
        printf("app_kda_twostep_handler error: Unsupported mac algorithm\n");
        goto end;
    }

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        printf("Error creating KDF CTX in KDA twostep\n");
        goto end;
    }
    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("Error creating param_bld in KDA twostep\n");
        goto end;
    }
    OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_DIGEST, alg, 0);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_KEY, stc->z, (size_t)stc->zLen);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_INFO, fixedInfo, (size_t)fixedInfoLen);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_SALT, stc->salt, (size_t)stc->saltLen);
    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params in KDA twostep\n");
        goto end;
    }
    if (EVP_KDF_derive(kctx, stc->outputDkm, stc->l, params) != 1) {
        printf("Failure deriving key material in KDA twostep\n");
        goto end;
    }
    rv = 0;
end:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (fixedInfo) free(fixedInfo);
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    return rv;
}
