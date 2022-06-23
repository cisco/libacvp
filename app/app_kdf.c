/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#ifdef OPENSSL_KDF_SUPPORT
#include <openssl/evp.h>
#include <openssl/bn.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/rand.h>
#include <openssl/param_build.h>
#include <openssl/kdf.h>
#include "safe_lib.h"
#endif
#include "app_lcl.h"
#include "app_fips_lcl.h"

#define TLS_MD_MASTER_SECRET_CONST              "master secret"
#define TLS_MD_MASTER_SECRET_CONST_SIZE         13
#define TLS_MD_EXTENDED_MASTER_SECRET_CONST     "extended master secret"
#define TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE 22
#define TLS_MD_KEY_EXPANSION_CONST              "key expansion"
#define TLS_MD_KEY_EXPANSION_CONST_SIZE         13

int app_kdf135_srtp_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

int app_kdf135_ikev2_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

int app_kdf135_ikev1_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

int app_kdf135_x963_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

int app_kdf108_handler(ACVP_TEST_CASE *test_case) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    ACVP_KDF108_TC *stc = NULL;
    int rc = 1, isHmac = 1, fixed_len = 64;
    char *aname = NULL;
    unsigned char *fixed = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    const char *alg = NULL, *mac = NULL;

    if (!test_case) {
        printf("Missing kdf108 test case\n");
        return -1;
    }
    stc = test_case->tc.kdf108;
    if (!stc) {
        printf("Missing kdf108 test case\n");
        return -1;
    }

    switch (stc->mac_mode) {
    case ACVP_KDF108_MAC_MODE_HMAC_SHA1:
        alg = "SHA-1";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA224:
        alg = "SHA2-224";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA256:
        alg = "SHA2-256";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA384:
        alg = "SHA2-384";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA512:
        alg = "SHA2-512";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA512_224:
        alg = "SHA2-512/224";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA512_256:
        alg = "SHA2-512/256";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA3_224:
        alg = "SHA3-224";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA3_256:
        alg = "SHA3-256";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA3_384:
        alg = "SHA3-384";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA3_512:
        alg = "SHA3-512";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_CMAC_AES128:
        alg = "AES128";
        mac = "CMAC";
        isHmac = 0;
        break;
    case ACVP_KDF108_MAC_MODE_CMAC_AES192:
        alg = "AES192";
        mac = "CMAC";
        isHmac = 0;
        break;
    case ACVP_KDF108_MAC_MODE_CMAC_AES256:
        alg = "AES256";
        mac = "CMAC";
        isHmac = 0;
        break;
    case ACVP_KDF108_MAC_MODE_MIN:
    case ACVP_KDF108_MAC_MODE_CMAC_TDES:
    case ACVP_KDF108_MAC_MODE_MAX:
    default:
        printf("app_kda_kdf108_handler error: Unsupported mac algorithm\n");
        return 1;
    }

    aname = calloc(256, sizeof(char)); //avoid const removal warnings
    if (!aname) {
        printf("Error allocating memory for KDF 108\n");
        goto end;
    }
    strcpy_s(aname, 256, alg);

    fixed = calloc(fixed_len, sizeof(char)); //arbitrary length fixed info
    if (!fixed) {
        printf("Error allocating memory for KDF 108\n");
        goto end;
    }
    RAND_bytes(fixed, fixed_len);
    memcpy_s(stc->fixed_data, ACVP_KDF108_FIXED_DATA_MAX, fixed, fixed_len);
    stc->fixed_data_len = fixed_len;

    kdf = EVP_KDF_fetch(NULL, "KBKDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        printf("Error creating KDF CTX in kdf108\n");
        goto end;
    }
    pbld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(pbld, "mac", mac, 0);
    OSSL_PARAM_BLD_push_octet_string(pbld, "key", stc->key_in, stc->key_in_len);
    OSSL_PARAM_BLD_push_octet_string(pbld, "seed", stc->iv, stc->iv_len);
    OSSL_PARAM_BLD_push_octet_string(pbld, "info", fixed, fixed_len);
    OSSL_PARAM_BLD_push_int(pbld, "use-separator", 0);
    OSSL_PARAM_BLD_push_int(pbld, "use-l", 0);

    if (isHmac) {
        OSSL_PARAM_BLD_push_utf8_string(pbld, "digest", aname, 0);
    } else {
        OSSL_PARAM_BLD_push_utf8_string(pbld, "cipher", aname, 0);
    }

    if (stc->mode == ACVP_KDF108_MODE_COUNTER) {
        OSSL_PARAM_BLD_push_utf8_string(pbld, "mode", "COUNTER", 0);
    } else if (stc->mode == ACVP_KDF108_MODE_FEEDBACK) {
        OSSL_PARAM_BLD_push_utf8_string(pbld, "mode", "FEEDBACK", 0);
    } else {
        printf("Unsupported KDF108 mode given for kdf108\n");
        goto end;
    }

    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params in kdf108\n");
        goto end;
    }

    if (EVP_KDF_derive(kctx, stc->key_out, stc->key_out_len, params) != 1) {
        printf("Failure deriving key material in kdf108");
    }
    rc = 0;
end:
    ERR_print_errors_fp(stdout);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    return rc;
#else
    if (!test_case) {
        return -1;
    }
    return 1;
#endif
}

int app_kdf135_snmp_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

int app_kdf135_ssh_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

int app_pbkdf_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

int app_kdf_tls12_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

int app_kdf_tls13_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    }
    return 1;
}

#endif // OPENSSL_KDF_SUPPORT
