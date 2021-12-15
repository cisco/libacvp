/** @file */
/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "ut_common.h"
#include "app_common.h"
#include "acvp/acvp_lcl.h"

ACVP_CTX *ctx;
ACVP_TEST_CASE *test_case;
ACVP_KDA_HKDF_TC *kda_hkdf_tc;
ACVP_KDA_ONESTEP_TC *kda_onestep_tc;
ACVP_RESULT rv;

void free_kda_hkdf_tc(ACVP_KDA_HKDF_TC *stc) {
    if (stc->salt) free(stc->salt);
    if (stc->z) free(stc->z);
    if (stc->literalCandidate) free(stc->literalCandidate);
    if (stc->algorithmId) free(stc->algorithmId);
    if (stc->label) free(stc->label);
    if (stc->context) free(stc->context);
    if (stc->uPartyId) free(stc->uPartyId);
    if (stc->vPartyId) free(stc->vPartyId);
    if (stc->uEphemeralData) free(stc->uEphemeralData);
    if (stc->vEphemeralData) free(stc->vEphemeralData);
    if (stc->providedDkm) free(stc->providedDkm);
    if (stc->outputDkm) free(stc->outputDkm);
    free(stc);
}

void free_kda_onestep_tc(ACVP_KDA_ONESTEP_TC *stc) {
    if (stc->salt) free(stc->salt);
    if (stc->z) free(stc->z);
    if (stc->literalCandidate) free(stc->literalCandidate);
    if (stc->algorithmId) free(stc->algorithmId);
    if (stc->label) free(stc->label);
    if (stc->context) free(stc->context);
    if (stc->uPartyId) free(stc->uPartyId);
    if (stc->vPartyId) free(stc->vPartyId);
    if (stc->uEphemeralData) free(stc->uEphemeralData);
    if (stc->vEphemeralData) free(stc->vEphemeralData);
    if (stc->providedDkm) free(stc->providedDkm);
    if (stc->outputDkm) free(stc->outputDkm);
    free(stc);
}

int initialize_kda_hkdf_tc(ACVP_KDA_HKDF_TC *stc,
                            ACVP_HASH_ALG hmac_alg,
                            const char *salt,
                            const char *z,
                            const char *uparty,
                            const char *uephemeral,
                            const char *vparty,
                            const char *vephemeral,
                            const char *algid,
                            const char *context,
                            const char *label,
                            const char *providedDkm,
                            const int l,
                            const int saltLen,
                            ACVP_KDA_MAC_SALT_METHOD saltMethod,
                            ACVP_KDA_ENCODING encoding,
                            ACVP_KDA_PATTERN_CANDIDATE *fixedArr,
                            ACVP_KDA_TEST_TYPE test_type) {
    
    ACVP_RESULT rv;
    stc->type = test_type;
    stc->hmacAlg = hmac_alg;
    stc->l = l / 8;
    stc->encoding = encoding;
    stc->saltMethod = saltMethod;

    if (fixedArr && memcpy_s(stc->fixedInfoPattern, ACVP_KDA_PATTERN_MAX * sizeof(int), fixedArr, ACVP_KDA_PATTERN_MAX * sizeof(int))) {
        printf("Error copying array of fixedInfoPattern candidates into test case structure\n");
        rv = ACVP_MALLOC_FAIL;
        goto err;
    }

    if (salt) {
        stc->salt = calloc(1, ACVP_KDA_SALT_BYTE_MAX);
        if (!stc->salt) { goto err; }
        rv = acvp_hexstr_to_bin(salt, stc->salt, ACVP_KDA_SALT_BYTE_MAX, &(stc->saltLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (salt)\n");
            goto err;
        }
    }

    if (z) {
        stc->z = calloc(1, ACVP_KDA_Z_BYTE_MAX);
        if (!stc->z) { goto err; }
        rv = acvp_hexstr_to_bin(z, stc->z, ACVP_KDA_Z_BYTE_MAX, &(stc->zLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (z)\n");
            goto err;
        }
    }

    if (uparty) {
        stc->uPartyId = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->uPartyId) { goto err; }
        rv = acvp_hexstr_to_bin(uparty, stc->uPartyId, ACVP_KDA_FIXED_BYTE_MAX, &(stc->uPartyIdLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (uPartyId)\n");
            goto err;
        }
    }
    if (uephemeral) {
        stc->uEphemeralData = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->uEphemeralData) { goto err; }
        rv = acvp_hexstr_to_bin(uephemeral, stc->uEphemeralData, ACVP_KDA_FIXED_BYTE_MAX, &(stc->uEphemeralLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (uEphemeral)\n");
            goto err;
        }
    }

    if (vparty) {
        stc->vPartyId = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->vPartyId) { goto err; }
        rv = acvp_hexstr_to_bin(vparty, stc->vPartyId, ACVP_KDA_FIXED_BYTE_MAX, &(stc->vPartyIdLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (vPartyid)\n");
            goto err;
        }
    }

    if (vephemeral) {
        stc->vEphemeralData = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->vEphemeralData) { goto err; }
        rv = acvp_hexstr_to_bin(vephemeral, stc->vEphemeralData, ACVP_KDA_FIXED_BYTE_MAX, &(stc->vEphemeralLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (vEphemeral)\n");
            goto err;
        }
    }

    if (algid) {
        stc->algorithmId = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->algorithmId) { goto err; }
        rv = acvp_hexstr_to_bin(algid, stc->algorithmId, ACVP_KDA_FIXED_BYTE_MAX, &(stc->algIdLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (algorithmId)\n");
            goto err;
        }
    }

    if (label) {
        stc->label = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->label) { goto err; }
        rv = acvp_hexstr_to_bin(label, stc->label, ACVP_KDA_FIXED_BYTE_MAX, &(stc->labelLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (label)\n");
            goto err;
        }
    }

    if (context) {
        stc->context = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->context) { goto err; }
        rv = acvp_hexstr_to_bin(context, stc->context, ACVP_KDA_FIXED_BYTE_MAX, &(stc->contextLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (algorithmId)\n");
            goto err;
        }
    }

    stc->outputDkm = calloc(ACVP_KDA_DKM_BYTE_MAX, 1);
    if (!stc->outputDkm) { 
        printf("Failed to allocate outputDkm initializing test case\n");
        goto err;
    }

    if (providedDkm) {
        stc->providedDkm = calloc(ACVP_KDA_DKM_BYTE_MAX, 1);
        if (!stc->providedDkm) { goto err; }
        rv = acvp_hexstr_to_bin(providedDkm, stc->providedDkm, ACVP_KDA_DKM_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (dkm)\n");
            goto err;
        }
    }

    return 1;

err:
    free_kda_hkdf_tc(stc);
    return 0;
}

int initialize_kda_onestep_tc(ACVP_KDA_ONESTEP_TC *stc,
                                    ACVP_CIPHER aux_function,
                                    const char *salt,
                                    const char *z,
                                    const char *uparty,
                                    const char *uephemeral,
                                    const char *vparty,
                                    const char *vephemeral,
                                    const char *algid,
                                    const char *context,
                                    const char *label,
                                    const char *providedDkm,
                                    const int l,
                                    const int saltLen,
                                    ACVP_KDA_MAC_SALT_METHOD saltMethod,
                                    ACVP_KDA_ENCODING encoding,
                                    ACVP_KDA_PATTERN_CANDIDATE *fixedArr,
                                    ACVP_KDA_TEST_TYPE test_type) {
    ACVP_RESULT rv;

    stc->type = test_type;
    stc->aux_function = aux_function;
    stc->l = l / 8;
    stc->encoding = encoding;
    stc->saltMethod = saltMethod;

    if (fixedArr && memcpy_s(stc->fixedInfoPattern, ACVP_KDA_PATTERN_MAX * sizeof(int), fixedArr, ACVP_KDA_PATTERN_MAX * sizeof(int))) {
        printf("Error copying array of fixedInfoPattern candidates into test case structure\n");
        rv = ACVP_MALLOC_FAIL;
        goto err;
    } 
    if (salt) {
        stc->salt = calloc(1, ACVP_KDA_SALT_BYTE_MAX);
        if (!stc->salt) { goto err; }
        rv = acvp_hexstr_to_bin(salt, stc->salt, ACVP_KDA_SALT_BYTE_MAX, &(stc->saltLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (salt)\n");
            goto err;
        }
    }
    if (z) {
        stc->z = calloc(1, ACVP_KDA_Z_BYTE_MAX);
        if (!stc->z) { goto err; }
        rv = acvp_hexstr_to_bin(z, stc->z, ACVP_KDA_Z_BYTE_MAX, &(stc->zLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (z)\n");
            goto err;
        }
    }

    if (uparty) {
        stc->uPartyId = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->uPartyId) { goto err; }
        rv = acvp_hexstr_to_bin(uparty, stc->uPartyId, ACVP_KDA_FIXED_BYTE_MAX, &(stc->uPartyIdLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (uPartyId)\n");
            goto err;
        }
    }
    if (uephemeral) {
        stc->uEphemeralData = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->uEphemeralData) { goto err; }
        rv = acvp_hexstr_to_bin(uephemeral, stc->uEphemeralData, ACVP_KDA_FIXED_BYTE_MAX, &(stc->uEphemeralLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (uEphemeral)\n");
            goto err;
        }
    }

    if (vparty) {
        stc->vPartyId = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->vPartyId) { goto err; }
        rv = acvp_hexstr_to_bin(vparty, stc->vPartyId, ACVP_KDA_FIXED_BYTE_MAX, &(stc->vPartyIdLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (vPartyid)\n");
            goto err;
        }
    }
    if (vephemeral) {
        stc->vEphemeralData = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->vEphemeralData) { goto err; }
        rv = acvp_hexstr_to_bin(vephemeral, stc->vEphemeralData, ACVP_KDA_FIXED_BYTE_MAX, &(stc->vEphemeralLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (vEphemeral)\n");
            goto err;
        }
    }

    if (algid) {
        stc->algorithmId = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->algorithmId) { goto err; }
        rv = acvp_hexstr_to_bin(algid, stc->algorithmId, ACVP_KDA_FIXED_BYTE_MAX, &(stc->algIdLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (algorithmId)\n");
            goto err;
        }
    }

    if (label) {
        stc->label = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->label) { goto err; }
        rv = acvp_hexstr_to_bin(label, stc->label, ACVP_KDA_FIXED_BYTE_MAX, &(stc->labelLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (label)\n");
            goto err;
        }
    }

    if (context) {
        stc->context = calloc(1, ACVP_KDA_FIXED_BYTE_MAX);
        if (!stc->context) { goto err; }
        rv = acvp_hexstr_to_bin(context, stc->context, ACVP_KDA_FIXED_BYTE_MAX, &(stc->contextLen));
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (algorithmId)\n");
            goto err;
        }
    }

    stc->outputDkm = calloc(ACVP_KDA_DKM_BYTE_MAX, 1);
    if (!stc->outputDkm) { 
        printf("Failed to allocate outputDkm initializing test case\n");
        goto err;
    }

    if (providedDkm) {
        stc->providedDkm = calloc(ACVP_KDA_DKM_BYTE_MAX, 1);
        if (!stc->providedDkm) { goto err; }
        rv = acvp_hexstr_to_bin(providedDkm, stc->providedDkm, ACVP_KDA_DKM_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            printf("Hex conversion failure (dkm)\n");
            goto err;
        }
    }

    return 1;

err:
    free_kda_onestep_tc(stc);
    return 0;
}

Test(APP_KDA_HKDF_HANDLER, invalid_encoding) {
    char *salt = "aa";
    char *z = "aa";
    char *uPartyId = "aa";
    char *vPartyId = "aa";
    ACVP_KDA_PATTERN_CANDIDATE pat[ACVP_KDA_PATTERN_MAX] = { ACVP_KDA_PATTERN_VPARTYINFO, ACVP_KDA_PATTERN_UPARTYINFO };

    kda_hkdf_tc = calloc(1, sizeof(ACVP_KDA_HKDF_TC));

    if (!initialize_kda_hkdf_tc(kda_hkdf_tc, ACVP_SHA256, salt, z, uPartyId, NULL, vPartyId,
                                NULL, NULL, NULL, NULL, NULL, 1024, 256, 
                                ACVP_KDA_MAC_SALT_METHOD_DEFAULT, 0,
                                pat, ACVP_KDA_TT_AFT)) {
        cr_assert_fail("kda hkdf init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kda_hkdf = kda_hkdf_tc;

    rv = app_kda_hkdf_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kda_hkdf_tc(kda_hkdf_tc);
    free(test_case);
}

Test(APP_KDA_HKDF_HANDLER, invalid_pattern) {
    char *salt = "aa";
    char *z = "aa";
    char *uPartyId = "aa";
    char *vPartyId = "aa";
    ACVP_KDA_PATTERN_CANDIDATE pat[ACVP_KDA_PATTERN_MAX] = { ACVP_KDA_PATTERN_VPARTYINFO, ACVP_KDA_PATTERN_MAX };

    kda_hkdf_tc = calloc(1, sizeof(ACVP_KDA_HKDF_TC));

    if (!initialize_kda_hkdf_tc(kda_hkdf_tc, ACVP_SHA256, salt, z, uPartyId, NULL, vPartyId,
                                NULL, NULL, NULL, NULL, NULL, 1024, 256, 
                                ACVP_KDA_MAC_SALT_METHOD_DEFAULT, ACVP_KDA_ENCODING_CONCAT,
                                pat, ACVP_KDA_TT_AFT)) {
        cr_assert_fail("kda hkdf init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kda_hkdf = kda_hkdf_tc;

    rv = app_kda_hkdf_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kda_hkdf_tc(kda_hkdf_tc);
    free(test_case);
}

Test(APP_KDA_HKDF_HANDLER, invalid_alg) {
    char *salt = "aaaa";
    char *z = "aaaa";
    char *uPartyId = "aaaa";
    char *vPartyId = "aaaa";
    ACVP_KDA_PATTERN_CANDIDATE pat[ACVP_KDA_PATTERN_MAX] = { ACVP_KDA_PATTERN_VPARTYINFO, ACVP_KDA_PATTERN_UPARTYINFO, ACVP_KDA_PATTERN_ALGID };

    kda_hkdf_tc = calloc(1, sizeof(ACVP_KDA_HKDF_TC));

    if (!initialize_kda_hkdf_tc(kda_hkdf_tc, ACVP_HASH_ALG_MAX, salt, z, uPartyId, NULL, vPartyId,
                                NULL, NULL, NULL, NULL, NULL, 1024, 256, 
                                ACVP_KDA_MAC_SALT_METHOD_DEFAULT, ACVP_KDA_ENCODING_CONCAT,
                                pat, ACVP_KDA_TT_AFT)) {
        cr_assert_fail("kda hkdf init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kda_hkdf = kda_hkdf_tc;

    rv = app_kda_hkdf_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kda_hkdf_tc(kda_hkdf_tc);
    free(test_case);
}

//onestep

Test(APP_KDA_ONESTEP_HANDLER, invalid_encoding) {
    char *z = "aa";
    char *uPartyId = "aa";
    char *vPartyId = "aa";
    ACVP_KDA_PATTERN_CANDIDATE pat[ACVP_KDA_PATTERN_MAX] = { ACVP_KDA_PATTERN_VPARTYINFO, ACVP_KDA_PATTERN_UPARTYINFO };

    kda_onestep_tc = calloc(1, sizeof(ACVP_KDA_ONESTEP_TC));

    if (!initialize_kda_onestep_tc(kda_onestep_tc, ACVP_HASH_SHA256, NULL, z, uPartyId, NULL, vPartyId,
                                NULL, NULL, NULL, NULL, NULL, 1024, 256, 
                                ACVP_KDA_MAC_SALT_METHOD_DEFAULT, 0,
                                pat, ACVP_KDA_TT_AFT)) {
        cr_assert_fail("kda onestep init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kda_onestep = kda_onestep_tc;

    rv = app_kda_onestep_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kda_onestep_tc(kda_onestep_tc);
    free(test_case);
}

Test(APP_KDA_ONESTEP_HANDLER, invalid_pattern) {
    char *salt = "aa";
    char *z = "aa";
    char *uPartyId = "aa";
    char *vPartyId = "aa";
    ACVP_KDA_PATTERN_CANDIDATE pat[ACVP_KDA_PATTERN_MAX] = { ACVP_KDA_PATTERN_VPARTYINFO, ACVP_KDA_PATTERN_MAX };

    kda_onestep_tc = calloc(1, sizeof(ACVP_KDA_ONESTEP_TC));

    if (!initialize_kda_onestep_tc(kda_onestep_tc, ACVP_HMAC_SHA2_256, salt, z, uPartyId, NULL, vPartyId,
                                NULL, NULL, NULL, NULL, NULL, 1024, 256, 
                                ACVP_KDA_MAC_SALT_METHOD_DEFAULT, ACVP_KDA_ENCODING_CONCAT,
                                pat, ACVP_KDA_TT_AFT)) {
        cr_assert_fail("kda onestep init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kda_onestep = kda_onestep_tc;

    rv = app_kda_onestep_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kda_onestep_tc(kda_onestep_tc);
    free(test_case);
}

Test(APP_KDA_ONESTEP_HANDLER, invalid_alg) {
    char *salt = "aaaa";
    char *z = "aaaa";
    char *uPartyId = "aaaa";
    char *vPartyId = "aaaa";
    ACVP_KDA_PATTERN_CANDIDATE pat[ACVP_KDA_PATTERN_MAX] = { ACVP_KDA_PATTERN_VPARTYINFO, ACVP_KDA_PATTERN_UPARTYINFO, ACVP_KDA_PATTERN_CONTEXT };

    kda_onestep_tc = calloc(1, sizeof(ACVP_KDA_ONESTEP_TC));

    if (!initialize_kda_onestep_tc(kda_onestep_tc, ACVP_CIPHER_END, salt, z, uPartyId, NULL, vPartyId,
                                NULL, NULL, NULL, NULL, NULL, 1024, 256, 
                                ACVP_KDA_MAC_SALT_METHOD_DEFAULT, ACVP_KDA_ENCODING_CONCAT,
                                pat, ACVP_KDA_TT_AFT)) {
        cr_assert_fail("kda_onestep init tc failure");
    }

    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.kda_onestep = kda_onestep_tc;

    rv = app_kda_onestep_handler(test_case);
    cr_assert_neq(rv, 0);

    free_kda_onestep_tc(kda_onestep_tc);
    free(test_case);
}
