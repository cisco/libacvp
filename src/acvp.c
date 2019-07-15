/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef WIN32
#include <io.h>
#include <Windows.h>
#else
#include <unistd.h>
#endif
#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"
#include "safe_lib.h"

/*
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_login(ACVP_CTX *ctx, int refresh);

static ACVP_RESULT acvp_validate_test_session(ACVP_CTX *ctx);

static ACVP_RESULT fips_metadata_ready(ACVP_CTX *ctx);

static ACVP_RESULT acvp_append_vsid_url(ACVP_CTX *ctx, char *vsid_url);

static ACVP_RESULT acvp_parse_login(ACVP_CTX *ctx);

static ACVP_RESULT acvp_parse_test_session_register(ACVP_CTX *ctx);

static ACVP_RESULT acvp_process_vsid(ACVP_CTX *ctx, char *vsid_url, int count);

static ACVP_RESULT acvp_process_vector_set(ACVP_CTX *ctx, JSON_Object *obj);

static ACVP_RESULT acvp_dispatch_vector_set(ACVP_CTX *ctx, JSON_Object *obj);

static void acvp_cap_free_sl(ACVP_SL_LIST *list);

static void acvp_cap_free_nl(ACVP_NAME_LIST *list);

static void acvp_cap_free_hash_pairs(ACVP_RSA_HASH_PAIR_LIST *list);

static ACVP_RESULT acvp_get_result_test_session(ACVP_CTX *ctx, char *session_url);

/*
 * This table maps ACVP operations to handlers within libacvp.
 * Each ACVP operation may have unique parameters.  For instance,
 * the parameters to test RSA are different than AES.  Therefore,
 * we allow for a unique handler to be registered for each
 * ACVP operation.
 *
 * WARNING:
 * This table is not sparse, it must contain ACVP_OP_MAX entries.
 */
ACVP_ALG_HANDLER alg_tbl[ACVP_ALG_MAX] = {
    { ACVP_AES_GCM,           &acvp_aes_kat_handler,          ACVP_ALG_AES_GCM,           NULL, ACVP_REV_AES_GCM},
    { ACVP_AES_CCM,           &acvp_aes_kat_handler,          ACVP_ALG_AES_CCM,           NULL, ACVP_REV_AES_CCM},
    { ACVP_AES_ECB,           &acvp_aes_kat_handler,          ACVP_ALG_AES_ECB,           NULL, ACVP_REV_AES_ECB},
    { ACVP_AES_CBC,           &acvp_aes_kat_handler,          ACVP_ALG_AES_CBC,           NULL, ACVP_REV_AES_CBC},
    { ACVP_AES_CFB1,          &acvp_aes_kat_handler,          ACVP_ALG_AES_CFB1,          NULL, ACVP_REV_AES_CFB1},
    { ACVP_AES_CFB8,          &acvp_aes_kat_handler,          ACVP_ALG_AES_CFB8,          NULL, ACVP_REV_AES_CFB8},
    { ACVP_AES_CFB128,        &acvp_aes_kat_handler,          ACVP_ALG_AES_CFB128,        NULL, ACVP_REV_AES_CFB128},
    { ACVP_AES_OFB,           &acvp_aes_kat_handler,          ACVP_ALG_AES_OFB,           NULL, ACVP_REV_AES_OFB},
    { ACVP_AES_CTR,           &acvp_aes_kat_handler,          ACVP_ALG_AES_CTR,           NULL, ACVP_REV_AES_CTR},
    { ACVP_AES_XTS,           &acvp_aes_kat_handler,          ACVP_ALG_AES_XTS,           NULL, ACVP_REV_AES_XTS},
    { ACVP_AES_KW,            &acvp_aes_kat_handler,          ACVP_ALG_AES_KW,            NULL, ACVP_REV_AES_KW},
    { ACVP_AES_KWP,           &acvp_aes_kat_handler,          ACVP_ALG_AES_KWP,           NULL, ACVP_REV_AES_KWP},
    { ACVP_TDES_ECB,          &acvp_des_kat_handler,          ACVP_ALG_TDES_ECB,          NULL, ACVP_REV_TDES_ECB},
    { ACVP_TDES_CBC,          &acvp_des_kat_handler,          ACVP_ALG_TDES_CBC,          NULL, ACVP_REV_TDES_CBC},
    { ACVP_TDES_CBCI,         &acvp_des_kat_handler,          ACVP_ALG_TDES_CBCI,         NULL, ACVP_REV_TDES_CBCI},
    { ACVP_TDES_OFB,          &acvp_des_kat_handler,          ACVP_ALG_TDES_OFB,          NULL, ACVP_REV_TDES_OFB},
    { ACVP_TDES_OFBI,         &acvp_des_kat_handler,          ACVP_ALG_TDES_OFBI,         NULL, ACVP_REV_TDES_OFBI},
    { ACVP_TDES_CFB1,         &acvp_des_kat_handler,          ACVP_ALG_TDES_CFB1,         NULL, ACVP_REV_TDES_CFB1},
    { ACVP_TDES_CFB8,         &acvp_des_kat_handler,          ACVP_ALG_TDES_CFB8,         NULL, ACVP_REV_TDES_CFB8},
    { ACVP_TDES_CFB64,        &acvp_des_kat_handler,          ACVP_ALG_TDES_CFB64,        NULL, ACVP_REV_TDES_CFB64},
    { ACVP_TDES_CFBP1,        &acvp_des_kat_handler,          ACVP_ALG_TDES_CFBP1,        NULL, ACVP_REV_TDES_CFBP1},
    { ACVP_TDES_CFBP8,        &acvp_des_kat_handler,          ACVP_ALG_TDES_CFBP8,        NULL, ACVP_REV_TDES_CFBP8},
    { ACVP_TDES_CFBP64,       &acvp_des_kat_handler,          ACVP_ALG_TDES_CFBP64,       NULL, ACVP_REV_TDES_CFBP64},
    { ACVP_TDES_CTR,          &acvp_des_kat_handler,          ACVP_ALG_TDES_CTR,          NULL, ACVP_REV_TDES_CTR},
    { ACVP_TDES_KW,           &acvp_des_kat_handler,          ACVP_ALG_TDES_KW,           NULL, ACVP_REV_TDES_KW},
    { ACVP_HASH_SHA1,         &acvp_hash_kat_handler,         ACVP_ALG_SHA1,              NULL, ACVP_REV_HASH_SHA1},
    { ACVP_HASH_SHA224,       &acvp_hash_kat_handler,         ACVP_ALG_SHA224,            NULL, ACVP_REV_HASH_SHA224},
    { ACVP_HASH_SHA256,       &acvp_hash_kat_handler,         ACVP_ALG_SHA256,            NULL, ACVP_REV_HASH_SHA256},
    { ACVP_HASH_SHA384,       &acvp_hash_kat_handler,         ACVP_ALG_SHA384,            NULL, ACVP_REV_HASH_SHA384},
    { ACVP_HASH_SHA512,       &acvp_hash_kat_handler,         ACVP_ALG_SHA512,            NULL, ACVP_REV_HASH_SHA512},
    { ACVP_HASH_SHA3_224,     &acvp_hash_kat_handler,         ACVP_ALG_SHA3_224,          NULL, ACVP_REV_HASH_SHA3_224},
    { ACVP_HASH_SHA3_256,     &acvp_hash_kat_handler,         ACVP_ALG_SHA3_256,          NULL, ACVP_REV_HASH_SHA3_256},
    { ACVP_HASH_SHA3_384,     &acvp_hash_kat_handler,         ACVP_ALG_SHA3_384,          NULL, ACVP_REV_HASH_SHA3_384},
    { ACVP_HASH_SHA3_512,     &acvp_hash_kat_handler,         ACVP_ALG_SHA3_512,          NULL, ACVP_REV_HASH_SHA3_512},
    { ACVP_HASH_SHAKE_128,    &acvp_hash_kat_handler,         ACVP_ALG_SHAKE_128,         NULL, ACVP_REV_HASH_SHAKE_128},
    { ACVP_HASH_SHAKE_256,    &acvp_hash_kat_handler,         ACVP_ALG_SHAKE_256,         NULL, ACVP_REV_HASH_SHAKE_256},
    { ACVP_HASHDRBG,          &acvp_drbg_kat_handler,         ACVP_ALG_HASHDRBG,          NULL, ACVP_REV_HASHDRBG},
    { ACVP_HMACDRBG,          &acvp_drbg_kat_handler,         ACVP_ALG_HMACDRBG,          NULL, ACVP_REV_HMACDRBG},
    { ACVP_CTRDRBG,           &acvp_drbg_kat_handler,         ACVP_ALG_CTRDRBG,           NULL, ACVP_REV_CTRDRBG},
    { ACVP_HMAC_SHA1,         &acvp_hmac_kat_handler,         ACVP_ALG_HMAC_SHA1,         NULL, ACVP_REV_HMAC_SHA1},
    { ACVP_HMAC_SHA2_224,     &acvp_hmac_kat_handler,         ACVP_ALG_HMAC_SHA2_224,     NULL, ACVP_REV_HMAC_SHA2_224},
    { ACVP_HMAC_SHA2_256,     &acvp_hmac_kat_handler,         ACVP_ALG_HMAC_SHA2_256,     NULL, ACVP_REV_HMAC_SHA2_256},
    { ACVP_HMAC_SHA2_384,     &acvp_hmac_kat_handler,         ACVP_ALG_HMAC_SHA2_384,     NULL, ACVP_REV_HMAC_SHA2_384},
    { ACVP_HMAC_SHA2_512,     &acvp_hmac_kat_handler,         ACVP_ALG_HMAC_SHA2_512,     NULL, ACVP_REV_HMAC_SHA2_512},
    { ACVP_HMAC_SHA2_512_224, &acvp_hmac_kat_handler,         ACVP_ALG_HMAC_SHA2_512_224, NULL, ACVP_REV_HMAC_SHA2_512_224},
    { ACVP_HMAC_SHA2_512_256, &acvp_hmac_kat_handler,         ACVP_ALG_HMAC_SHA2_512_256, NULL, ACVP_REV_HMAC_SHA2_512_256},
    { ACVP_HMAC_SHA3_224,     &acvp_hmac_kat_handler,         ACVP_ALG_HMAC_SHA3_224,     NULL, ACVP_REV_HMAC_SHA3_224},
    { ACVP_HMAC_SHA3_256,     &acvp_hmac_kat_handler,         ACVP_ALG_HMAC_SHA3_256,     NULL, ACVP_REV_HMAC_SHA3_256},
    { ACVP_HMAC_SHA3_384,     &acvp_hmac_kat_handler,         ACVP_ALG_HMAC_SHA3_384,     NULL, ACVP_REV_HMAC_SHA3_384},
    { ACVP_HMAC_SHA3_512,     &acvp_hmac_kat_handler,         ACVP_ALG_HMAC_SHA3_512,     NULL, ACVP_REV_HMAC_SHA3_512},
    { ACVP_CMAC_AES,          &acvp_cmac_kat_handler,         ACVP_ALG_CMAC_AES,          NULL, ACVP_REV_CMAC_AES},
    { ACVP_CMAC_TDES,         &acvp_cmac_kat_handler,         ACVP_ALG_CMAC_TDES,         NULL, ACVP_REV_CMAC_TDES},
    { ACVP_DSA_KEYGEN,        &acvp_dsa_kat_handler,          ACVP_ALG_DSA,               ACVP_ALG_DSA_KEYGEN, ACVP_REV_DSA},
    { ACVP_DSA_PQGGEN,        &acvp_dsa_kat_handler,          ACVP_ALG_DSA,               ACVP_ALG_DSA_PQGGEN, ACVP_REV_DSA},
    { ACVP_DSA_PQGVER,        &acvp_dsa_kat_handler,          ACVP_ALG_DSA,               ACVP_ALG_DSA_PQGVER, ACVP_REV_DSA},
    { ACVP_DSA_SIGGEN,        &acvp_dsa_kat_handler,          ACVP_ALG_DSA,               ACVP_ALG_DSA_SIGGEN, ACVP_REV_DSA},
    { ACVP_DSA_SIGVER,        &acvp_dsa_kat_handler,          ACVP_ALG_DSA,               ACVP_ALG_DSA_SIGVER, ACVP_REV_DSA},
    { ACVP_RSA_KEYGEN,        &acvp_rsa_keygen_kat_handler,   ACVP_ALG_RSA,               ACVP_MODE_KEYGEN, ACVP_REV_RSA},
    { ACVP_RSA_SIGGEN,        &acvp_rsa_siggen_kat_handler,   ACVP_ALG_RSA,               ACVP_MODE_SIGGEN, ACVP_REV_RSA},
    { ACVP_RSA_SIGVER,        &acvp_rsa_sigver_kat_handler,   ACVP_ALG_RSA,               ACVP_MODE_SIGVER, ACVP_REV_RSA},
    { ACVP_ECDSA_KEYGEN,      &acvp_ecdsa_keygen_kat_handler, ACVP_ALG_ECDSA,             ACVP_MODE_KEYGEN, ACVP_REV_RSA},
    { ACVP_ECDSA_KEYVER,      &acvp_ecdsa_keyver_kat_handler, ACVP_ALG_ECDSA,             ACVP_MODE_KEYVER, ACVP_REV_RSA},
    { ACVP_ECDSA_SIGGEN,      &acvp_ecdsa_siggen_kat_handler, ACVP_ALG_ECDSA,             ACVP_MODE_SIGGEN, ACVP_REV_RSA},
    { ACVP_ECDSA_SIGVER,      &acvp_ecdsa_sigver_kat_handler, ACVP_ALG_ECDSA,             ACVP_MODE_SIGVER, ACVP_REV_RSA},
    { ACVP_KDF135_TLS,        &acvp_kdf135_tls_kat_handler,   ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_TLS, ACVP_REV_KDF135_TLS},
    { ACVP_KDF135_SNMP,       &acvp_kdf135_snmp_kat_handler,  ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_SNMP, ACVP_REV_KDF135_SNMP},
    { ACVP_KDF135_SSH,        &acvp_kdf135_ssh_kat_handler,   ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_SSH, ACVP_REV_KDF135_SSH},
    { ACVP_KDF135_SRTP,       &acvp_kdf135_srtp_kat_handler,  ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_SRTP, ACVP_REV_KDF135_SRTP},
    { ACVP_KDF135_IKEV2,      &acvp_kdf135_ikev2_kat_handler, ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_IKEV2, ACVP_REV_KDF135_IKEV2},
    { ACVP_KDF135_IKEV1,      &acvp_kdf135_ikev1_kat_handler, ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_IKEV1, ACVP_REV_KDF135_IKEV1},
    { ACVP_KDF135_X963,       &acvp_kdf135_x963_kat_handler,  ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_X963, ACVP_REV_KDF135_X963},
    { ACVP_KDF108,            &acvp_kdf108_kat_handler,       ACVP_ALG_KDF108,            NULL, ACVP_REV_KDF108},
    { ACVP_KAS_ECC_CDH,       &acvp_kas_ecc_kat_handler,      ACVP_ALG_KAS_ECC,           ACVP_ALG_KAS_ECC_CDH, ACVP_REV_KAS_ECC},
    { ACVP_KAS_ECC_COMP,      &acvp_kas_ecc_kat_handler,      ACVP_ALG_KAS_ECC,           ACVP_ALG_KAS_ECC_COMP, ACVP_REV_KAS_ECC},
    { ACVP_KAS_ECC_NOCOMP,    &acvp_kas_ecc_kat_handler,      ACVP_ALG_KAS_ECC,           ACVP_ALG_KAS_ECC_NOCOMP, ACVP_REV_KAS_ECC},
    { ACVP_KAS_FFC_COMP,      &acvp_kas_ffc_kat_handler,      ACVP_ALG_KAS_FFC,           ACVP_ALG_KAS_FFC_COMP, ACVP_REV_KAS_FFC},
    { ACVP_KAS_FFC_NOCOMP,    &acvp_kas_ffc_kat_handler,      ACVP_ALG_KAS_FFC,           ACVP_ALG_KAS_FFC_NOCOMP, ACVP_REV_KAS_FFC}
};

/*
 * This is the first function the user should invoke to allocate
 * a new context to be used for the test session.
 */
ACVP_RESULT acvp_create_test_session(ACVP_CTX **ctx,
                                     ACVP_RESULT (*progress_cb)(char *msg),
                                     ACVP_LOG_LVL level) {
    if (!ctx) {
        return ACVP_INVALID_ARG;
    }
    if (*ctx) {
        printf("ERROR: Cannot initialize non-null ctx; clear ctx & set to NULL first\n");
        return ACVP_DUPLICATE_CTX;
    }
    *ctx = calloc(1, sizeof(ACVP_CTX));
    if (!*ctx) {
        return ACVP_MALLOC_FAIL;
    }

    if (progress_cb) {
        (*ctx)->test_progress_cb = progress_cb;
    }

    (*ctx)->debug = level;

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_set_2fa_callback(ACVP_CTX *ctx, ACVP_RESULT (*totp_cb)(char **token, int token_max)) {
    if (totp_cb == NULL) {
        return ACVP_MISSING_ARG;
    }
    if (ctx == NULL) {
        return ACVP_NO_CTX;
    }
    ctx->totp_cb = totp_cb;
    return ACVP_SUCCESS;
}

static void acvp_free_prereqs(ACVP_CAPS_LIST *cap_list) {
    while (cap_list->prereq_vals) {
        ACVP_PREREQ_LIST *temp_ptr;
        temp_ptr = cap_list->prereq_vals;
        cap_list->prereq_vals = cap_list->prereq_vals->next;
        free(temp_ptr);
    }
}

/*
 * Free Internal memory for DSA operations. Since it supports
 * multiple modes, we have to free the whole list
 */
static void acvp_cap_free_dsa_attrs(ACVP_CAPS_LIST *cap_entry) {
    ACVP_DSA_ATTRS *attrs = NULL, *next = NULL;
    ACVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    int i;

    for (i = 0; i <= ACVP_DSA_MAX_MODES - 1; i++) {
        dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[i];
        if (dsa_cap_mode->defined) {
            next = dsa_cap_mode->dsa_attrs;
            while (next) {
                attrs = next;
                next = attrs->next;
                free(attrs);
            }
        }
    }
    dsa_cap_mode = cap_entry->cap.dsa_cap->dsa_cap_mode;
    free(dsa_cap_mode);
}

/*
 * Free Internal memory for keygen struct. Since it supports
 * multiple modes, we have to free the whole list
 */
static void acvp_cap_free_rsa_keygen_list(ACVP_CAPS_LIST *cap_list) {
    ACVP_RSA_KEYGEN_CAP *keygen_cap = cap_list->cap.rsa_keygen_cap;
    ACVP_RSA_KEYGEN_CAP *temp_keygen_cap;

    acvp_free_prereqs(cap_list);

    while (keygen_cap) {
        if (keygen_cap->fixed_pub_exp) {
            free(keygen_cap->fixed_pub_exp);
        }

        ACVP_RSA_MODE_CAPS_LIST *mode_list = keygen_cap->mode_capabilities;
        ACVP_RSA_MODE_CAPS_LIST *temp_mode_list;

        while (mode_list) {
            acvp_cap_free_nl(mode_list->hash_algs);
            acvp_cap_free_nl(mode_list->prime_tests);

            temp_mode_list = mode_list;
            mode_list = mode_list->next;
            free(temp_mode_list);
            temp_mode_list = NULL;
        }

        temp_keygen_cap = keygen_cap;
        keygen_cap = keygen_cap->next;
        free(temp_keygen_cap);
        temp_keygen_cap = NULL;
    }
}

/*
 * Free Internal memory for keygen struct. Since it supports
 * multiple modes, we have to free the whole list
 */
static void acvp_cap_free_rsa_sig_list(ACVP_CAPS_LIST *cap_list) {
    ACVP_RSA_SIG_CAP *sig_cap = NULL, *temp_sig_cap = NULL;

    if (cap_list->cipher == ACVP_RSA_SIGGEN) {
        sig_cap = cap_list->cap.rsa_siggen_cap;
    } else if (cap_list->cipher == ACVP_RSA_SIGVER) {
        sig_cap = cap_list->cap.rsa_sigver_cap;
    } else {
        return;
    }

    acvp_free_prereqs(cap_list);

    while (sig_cap) {
        ACVP_RSA_MODE_CAPS_LIST *mode_list = sig_cap->mode_capabilities;
        ACVP_RSA_MODE_CAPS_LIST *temp_mode_list;

        if (sig_cap->fixed_pub_exp) {
            free(sig_cap->fixed_pub_exp);
        }
        while (mode_list) {
            acvp_cap_free_hash_pairs(mode_list->hash_pair);

            temp_mode_list = mode_list;
            mode_list = mode_list->next;
            free(temp_mode_list);
            temp_mode_list = NULL;
        }

        temp_sig_cap = sig_cap;
        sig_cap = sig_cap->next;
        free(temp_sig_cap);
        temp_sig_cap = NULL;
    }
}

/*
 * Free Internal memory for KAS-ECC Data struct
 */
static void acvp_cap_free_kas_ecc_mode(ACVP_CAPS_LIST *cap_list) {
    ACVP_KAS_ECC_CAP *kas_ecc_cap = cap_list->cap.kas_ecc_cap;
    ACVP_KAS_ECC_CAP_MODE *mode;
    int i;

    if (kas_ecc_cap) {
        ACVP_PREREQ_LIST *current_pre_req_vals;
        ACVP_PREREQ_LIST *next_pre_req_vals;
        ACVP_PARAM_LIST *current_func;
        ACVP_PARAM_LIST *next_func;
        ACVP_PARAM_LIST *current_curve;
        ACVP_PARAM_LIST *next_curve;
        ACVP_PARAM_LIST *current_hash;
        ACVP_PARAM_LIST *next_hash;
        ACVP_PARAM_LIST *current_role;
        ACVP_PARAM_LIST *next_role;
        ACVP_KAS_ECC_PSET *current_pset;
        ACVP_KAS_ECC_PSET *next_pset;
        ACVP_KAS_ECC_SCHEME *current_scheme;
        ACVP_KAS_ECC_SCHEME *next_scheme;

        if (kas_ecc_cap->kas_ecc_mode) {
            for (i = 0; i < ACVP_KAS_ECC_MAX_MODES; i++) {
                mode = &kas_ecc_cap->kas_ecc_mode[i];
                current_pre_req_vals = mode->prereq_vals;
                /*
                 * Delete all pre_req
                 */
                if (current_pre_req_vals) {
                    do {
                        next_pre_req_vals = current_pre_req_vals->next;
                        free(current_pre_req_vals);
                        current_pre_req_vals = next_pre_req_vals;
                    } while (current_pre_req_vals);
                }
                /*
                 * Delete all function name lists
                 */
                current_func = mode->function;
                if (current_func) {
                    do {
                        next_func = current_func->next;
                        free(current_func);
                        current_func = next_func;
                    } while (current_func);
                }
                /*
                 * Delete all curve name lists
                 */
                current_curve = mode->curve;
                if (current_curve) {
                    do {
                        next_curve = current_curve->next;
                        free(current_curve);
                        current_curve = next_curve;
                    } while (current_curve);
                }
                /*
                 * Delete all schemes, psets and their param lists
                 */
                current_scheme = mode->scheme;
                if (current_scheme) {
                    do {
                        current_role = current_scheme->role;
                        if (current_role) {
                            do {
                                next_role = current_role->next;
                                free(current_role);
                                current_role = next_role;
                            } while (current_role);
                        }
                        current_pset = current_scheme->pset;
                        if (current_pset) {
                            do {
                                current_hash = current_pset->sha;
                                if (current_hash) {
                                    do {
                                        next_hash = current_hash->next;
                                        free(current_hash);
                                        current_hash = next_hash;
                                    } while (current_hash);
                                }
                                next_pset = current_pset->next;
                                free(current_pset);
                                current_pset = next_pset;
                            } while (current_pset);
                        }
                        next_scheme = current_scheme->next;
                        free(current_scheme);
                        current_scheme = next_scheme;
                    } while (current_scheme);
                }
            }
        }
    }
    free(cap_list->cap.kas_ecc_cap->kas_ecc_mode);
    free(cap_list->cap.kas_ecc_cap);
}

/*
 * Free Internal memory for KAS-FFC Data struct
 */
static void acvp_cap_free_kas_ffc_mode(ACVP_CAPS_LIST *cap_list) {
    ACVP_KAS_FFC_CAP *kas_ffc_cap = cap_list->cap.kas_ffc_cap;
    ACVP_KAS_FFC_CAP_MODE *mode;
    int i;

    if (kas_ffc_cap) {
        ACVP_PREREQ_LIST *current_pre_req_vals;
        ACVP_PREREQ_LIST *next_pre_req_vals;
        ACVP_PARAM_LIST *current_func;
        ACVP_PARAM_LIST *next_func;
        ACVP_PARAM_LIST *current_hash;
        ACVP_PARAM_LIST *next_hash;
        ACVP_PARAM_LIST *current_role;
        ACVP_PARAM_LIST *next_role;
        ACVP_KAS_FFC_PSET *current_pset;
        ACVP_KAS_FFC_PSET *next_pset;
        ACVP_KAS_FFC_SCHEME *current_scheme;
        ACVP_KAS_FFC_SCHEME *next_scheme;

        if (kas_ffc_cap->kas_ffc_mode) {
            for (i = 0; i < ACVP_KAS_FFC_MAX_MODES; i++) {
                mode = &kas_ffc_cap->kas_ffc_mode[i];
                current_pre_req_vals = mode->prereq_vals;
                /*
                 * Delete all pre_req
                 */
                if (current_pre_req_vals) {
                    do {
                        next_pre_req_vals = current_pre_req_vals->next;
                        free(current_pre_req_vals);
                        current_pre_req_vals = next_pre_req_vals;
                    } while (current_pre_req_vals);
                }
                /*
                 * Delete all function name lists
                 */
                current_func = mode->function;
                if (current_func) {
                    do {
                        next_func = current_func->next;
                        free(current_func);
                        current_func = next_func;
                    } while (current_func);
                }
                /*
                 * Delete all schemes, psets and their param lists
                 */
                current_scheme = mode->scheme;
                if (current_scheme) {
                    do {
                        current_role = current_scheme->role;
                        if (current_role) {
                            do {
                                next_role = current_role->next;
                                free(current_role);
                                current_role = next_role;
                            } while (current_role);
                        }
                        current_pset = current_scheme->pset;
                        if (current_pset) {
                            do {
                                current_hash = current_pset->sha;
                                if (current_hash) {
                                    do {
                                        next_hash = current_hash->next;
                                        free(current_hash);
                                        current_hash = next_hash;
                                    } while (current_hash);
                                }
                                next_pset = current_pset->next;
                                free(current_pset);
                                current_pset = next_pset;
                            } while (current_pset);
                        }
                        next_scheme = current_scheme->next;
                        free(current_scheme);
                        current_scheme = next_scheme;
                    } while (current_scheme);
                }
            }
        }
    }
    free(cap_list->cap.kas_ffc_cap->kas_ffc_mode);
    free(cap_list->cap.kas_ffc_cap);
}

/*
 * Free Internal memory for DRBG Data struct
 */
static void acvp_free_drbg_struct(ACVP_CAPS_LIST *cap_list) {
    ACVP_DRBG_CAP *drbg_cap = cap_list->cap.drbg_cap;

    if (drbg_cap) {
        ACVP_DRBG_CAP_MODE_LIST *mode_list = drbg_cap->drbg_cap_mode_list;
        ACVP_DRBG_CAP_MODE_LIST *next_mode_list;
        ACVP_PREREQ_LIST *current_pre_req_vals;
        ACVP_PREREQ_LIST *next_pre_req_vals;

        if (mode_list) {
            do {
                //Top of list
                current_pre_req_vals = mode_list->cap_mode.prereq_vals;
                /*
                 * Delete all pre_req
                 */
                if (current_pre_req_vals) {
                    do {
                        next_pre_req_vals = current_pre_req_vals->next;
                        free(current_pre_req_vals);
                        current_pre_req_vals = next_pre_req_vals;
                    } while (current_pre_req_vals);
                }
                next_mode_list = mode_list->next;
                free(mode_list);
                mode_list = next_mode_list;
            } while (mode_list);
        }
        free(drbg_cap);
        drbg_cap = NULL;
        cap_list->cap.drbg_cap = NULL;
    }
}

/*
 * Free Internal memory for KDF108 Cap struct
 */
static void acvp_cap_free_kdf108(ACVP_CAPS_LIST *cap_list) {
    ACVP_KDF108_CAP *cap = cap_list->cap.kdf108_cap;
    ACVP_KDF108_MODE_PARAMS *mode_obj = NULL;

    if (cap) {
        if (cap->counter_mode.kdf_mode) {
            mode_obj = &cap->counter_mode;
            if (mode_obj->mac_mode) {
                acvp_cap_free_nl(mode_obj->mac_mode);
            }
            if (mode_obj->data_order) {
                acvp_cap_free_nl(mode_obj->data_order);
            }
            if (mode_obj->counter_lens) {
                acvp_cap_free_sl(mode_obj->counter_lens);
            }
        }

        if (cap->feedback_mode.kdf_mode) {
            mode_obj = &cap->feedback_mode;
            if (mode_obj->mac_mode) {
                acvp_cap_free_nl(mode_obj->mac_mode);
            }
            if (mode_obj->data_order) {
                acvp_cap_free_nl(mode_obj->data_order);
            }
            if (mode_obj->counter_lens) {
                acvp_cap_free_sl(mode_obj->counter_lens);
            }
        }

        if (cap->dpi_mode.kdf_mode) {
            mode_obj = &cap->dpi_mode;
            if (mode_obj->mac_mode) {
                acvp_cap_free_nl(mode_obj->mac_mode);
            }
            if (mode_obj->data_order) {
                acvp_cap_free_nl(mode_obj->data_order);
            }
            if (mode_obj->counter_lens) {
                acvp_cap_free_sl(mode_obj->counter_lens);
            }
        }

        free(cap);
        cap = NULL;
        cap_list->cap.kdf108_cap = NULL;
    }
}

/*
 * The application will invoke this to free the ACVP context
 * when the test session is finished.
 */
ACVP_RESULT acvp_free_test_session(ACVP_CTX *ctx) {
    ACVP_VS_LIST *vs_entry, *vs_e2;
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    if (!ctx) {
        ACVP_LOG_STATUS("No ctx to free");
        return ACVP_SUCCESS;
    }

    if (ctx->kat_resp) { json_value_free(ctx->kat_resp); }
    if (ctx->curl_buf) { free(ctx->curl_buf); }
    if (ctx->server_name) { free(ctx->server_name); }
    if (ctx->path_segment) { free(ctx->path_segment); }
    if (ctx->api_context) { free(ctx->api_context); }
    if (ctx->cacerts_file) { free(ctx->cacerts_file); }
    if (ctx->tls_cert) { free(ctx->tls_cert); }
    if (ctx->tls_key) { free(ctx->tls_key); }
    if (ctx->json_filename) { free(ctx->json_filename); }
    if (ctx->session_url) { free(ctx->session_url); }
    if (ctx->vector_req_file) { free(ctx->vector_req_file); }
    if (ctx->get_string) { free(ctx->get_string); }
    if (ctx->post_filename) { free(ctx->post_filename); }
    if (ctx->jwt_token) { free(ctx->jwt_token); }
    if (ctx->tmp_jwt) { free(ctx->tmp_jwt); }
    if (ctx->vs_list) {
        vs_entry = ctx->vs_list;
        while (vs_entry) {
            vs_e2 = vs_entry->next;
            free(vs_entry);
            vs_entry = vs_e2;
        }
    }
    if (ctx->vsid_url_list) {
        acvp_free_str_list(&ctx->vsid_url_list);
    }
    if (ctx->caps_list) {
        cap_entry = ctx->caps_list;
        while (cap_entry) {
            cap_e2 = cap_entry->next;
            if (cap_entry->prereq_vals) {
                acvp_free_prereqs(cap_entry);
            }
            switch (cap_entry->cap_type) {
            case ACVP_SYM_TYPE:
                acvp_cap_free_sl(cap_entry->cap.sym_cap->keylen);
                acvp_cap_free_sl(cap_entry->cap.sym_cap->ptlen);
                acvp_cap_free_sl(cap_entry->cap.sym_cap->ivlen);
                acvp_cap_free_sl(cap_entry->cap.sym_cap->aadlen);
                acvp_cap_free_sl(cap_entry->cap.sym_cap->taglen);
                acvp_cap_free_sl(cap_entry->cap.sym_cap->tweak);
                free(cap_entry->cap.sym_cap);
                break;
            case ACVP_HASH_TYPE:
                free(cap_entry->cap.hash_cap);
                break;
            case ACVP_DRBG_TYPE:
                acvp_free_drbg_struct(cap_entry);
                break;
            case ACVP_HMAC_TYPE:
                free(cap_entry->cap.hmac_cap);
                break;
            case ACVP_CMAC_TYPE:
                acvp_cap_free_sl(cap_entry->cap.cmac_cap->key_len);
                acvp_cap_free_sl(cap_entry->cap.cmac_cap->keying_option);
                free(cap_entry->cap.cmac_cap);
                break;
            case ACVP_DSA_TYPE:
                acvp_cap_free_dsa_attrs(cap_entry);
                free(cap_entry->cap.dsa_cap);
                break;
            case ACVP_KAS_ECC_CDH_TYPE:
            case ACVP_KAS_ECC_COMP_TYPE:
            case ACVP_KAS_ECC_NOCOMP_TYPE:
                acvp_cap_free_kas_ecc_mode(cap_entry);
                break;
            case ACVP_KAS_FFC_COMP_TYPE:
            case ACVP_KAS_FFC_NOCOMP_TYPE:
                acvp_cap_free_kas_ffc_mode(cap_entry);
                break;
            case ACVP_RSA_KEYGEN_TYPE:
                acvp_cap_free_rsa_keygen_list(cap_entry);
                break;
            case ACVP_RSA_SIGGEN_TYPE:
                acvp_cap_free_rsa_sig_list(cap_entry);
                break;
            case ACVP_RSA_SIGVER_TYPE:
                acvp_cap_free_rsa_sig_list(cap_entry);
                break;
            case ACVP_ECDSA_KEYGEN_TYPE:
                acvp_cap_free_nl(cap_entry->cap.ecdsa_keygen_cap->curves);
                acvp_cap_free_nl(cap_entry->cap.ecdsa_keygen_cap->secret_gen_modes);
                free(cap_entry->cap.ecdsa_keygen_cap);
                break;
            case ACVP_ECDSA_KEYVER_TYPE:
                acvp_cap_free_nl(cap_entry->cap.ecdsa_keyver_cap->curves);
                acvp_cap_free_nl(cap_entry->cap.ecdsa_keyver_cap->secret_gen_modes);
                free(cap_entry->cap.ecdsa_keyver_cap);
                break;
            case ACVP_ECDSA_SIGGEN_TYPE:
                acvp_cap_free_nl(cap_entry->cap.ecdsa_siggen_cap->curves);
                acvp_cap_free_nl(cap_entry->cap.ecdsa_siggen_cap->hash_algs);
                free(cap_entry->cap.ecdsa_siggen_cap);
                break;
            case ACVP_ECDSA_SIGVER_TYPE:
                acvp_cap_free_nl(cap_entry->cap.ecdsa_sigver_cap->curves);
                acvp_cap_free_nl(cap_entry->cap.ecdsa_sigver_cap->hash_algs);
                free(cap_entry->cap.ecdsa_sigver_cap);
                break;
            case ACVP_KDF135_SRTP_TYPE:
                acvp_cap_free_sl(cap_entry->cap.kdf135_srtp_cap->aes_keylens);
                free(cap_entry->cap.kdf135_srtp_cap);
                break;
            case ACVP_KDF135_TLS_TYPE:
                free(cap_entry->cap.kdf135_tls_cap);
                break;
            case ACVP_KDF108_TYPE:
                acvp_cap_free_kdf108(cap_entry);
                break;
            case ACVP_KDF135_SNMP_TYPE:
                acvp_cap_free_sl(cap_entry->cap.kdf135_snmp_cap->pass_lens);
                acvp_cap_free_nl(cap_entry->cap.kdf135_snmp_cap->eng_ids);
                free(cap_entry->cap.kdf135_snmp_cap);
                break;
            case ACVP_KDF135_SSH_TYPE:
                free(cap_entry->cap.kdf135_ssh_cap);
                break;
            case ACVP_KDF135_IKEV2_TYPE:
                acvp_cap_free_nl(cap_entry->cap.kdf135_ikev2_cap->hash_algs);
                free(cap_entry->cap.kdf135_ikev2_cap);
                break;
            case ACVP_KDF135_IKEV1_TYPE:
                acvp_cap_free_nl(cap_entry->cap.kdf135_ikev1_cap->hash_algs);
                free(cap_entry->cap.kdf135_ikev1_cap);
                break;
            case ACVP_KDF135_X963_TYPE:
                acvp_cap_free_nl(cap_entry->cap.kdf135_x963_cap->hash_algs);
                acvp_cap_free_sl(cap_entry->cap.kdf135_x963_cap->shared_info_lengths);
                acvp_cap_free_sl(cap_entry->cap.kdf135_x963_cap->field_sizes);
                acvp_cap_free_sl(cap_entry->cap.kdf135_x963_cap->key_data_lengths);
                free(cap_entry->cap.kdf135_x963_cap);
                break;
            case ACVP_KDF135_TPM_TYPE:
            default:
                return ACVP_INVALID_ARG;
            }
            free(cap_entry);
            cap_entry = cap_e2;
        }
    }

    /*
     * Free everything in the Operating Environment structs
     */
    acvp_oe_free_operating_env(ctx);

    /* Free the ACVP_CTX struct */
    free(ctx);

    return ACVP_SUCCESS;
}

/*
 * Simple utility function to free a supported length
 * list from the capabilities structure.
 */
static void acvp_cap_free_sl(ACVP_SL_LIST *list) {
    ACVP_SL_LIST *top = list;
    ACVP_SL_LIST *tmp;

    while (top) {
        tmp = top;
        top = top->next;
        free(tmp);
    }
}

/*
 * Simple utility function to free a name
 * list from the capabilities structure.
 */
static void acvp_cap_free_nl(ACVP_NAME_LIST *list) {
    ACVP_NAME_LIST *top = list;
    ACVP_NAME_LIST *tmp;

    while (top) {
        tmp = top;
        top = top->next;
        free(tmp);
    }
}

static void acvp_cap_free_hash_pairs(ACVP_RSA_HASH_PAIR_LIST *list) {
    ACVP_RSA_HASH_PAIR_LIST *top = list;
    ACVP_RSA_HASH_PAIR_LIST *tmp;

    while (top) {
        tmp = top;

        top = top->next;
        free(tmp);
    }
}

/*
 * Allows application to load JSON kat vector file within context
 * to be read in and used for vector testing
 */
ACVP_RESULT acvp_load_kat_filename(ACVP_CTX *ctx, const char *kat_filename) {
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Array *reg_array;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!kat_filename) {
        ACVP_LOG_ERR("Must provide value for JSON filename");
        return ACVP_MISSING_ARG;
    }

    if (strnlen_s(kat_filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided kat_filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    val = json_parse_file(kat_filename);

    reg_array = json_value_get_array(val);
    obj = json_array_get_object(reg_array, 1);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        json_value_free(val);
        return ACVP_INVALID_ARG;
    }

    /* Process the kat vector(s) */
    rv  = acvp_dispatch_vector_set(ctx, obj);
    json_value_free(val);
    return rv;
}

/*
 * Allows application to load JSON vector file(req_filename) within context
 * to be read in and used for vector testing. The results are
 * then saved in a response file(rsp_filename).
 */
ACVP_RESULT acvp_run_vectors_from_file(ACVP_CTX *ctx, const char *req_filename, const char *rsp_filename) {
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;
    JSON_Array *reg_array;
    JSON_Value *file_val = NULL;
    JSON_Value *kat_val = NULL;
    JSON_Array *kat_array;
    JSON_Value *rsp_val = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;
    int n, i;
    ACVP_STRING_LIST *vs_entry;
    JSON_Array *vect_sets = NULL;
    const char *test_session_url = NULL;
    int vs_cnt = 0;
    const char *jwt = NULL;
    char *json_result = NULL;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!req_filename) {
        ACVP_LOG_ERR("Must provide value for JSON filename");
        return ACVP_MISSING_ARG;
    }

    if (strnlen_s(req_filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided req_filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    val = json_parse_file(req_filename);

    n = 0;
    reg_array = json_value_get_array(val);
    obj = json_array_get_object(reg_array, n);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    /*
     * This is the identifiers provided by the server
     * for this specific test session!
     */
    test_session_url = json_object_get_string(obj, "url");
    if (test_session_url) {
        ctx->session_url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
        strcpy_s(ctx->session_url, ACVP_ATTR_URL_MAX + 1, test_session_url);
    } else {
        ACVP_LOG_WARN("Missing session URL, results will not be POSTed to server");
        goto end;
    }

    jwt = json_object_get_string(obj, "jwt");
    if (jwt) {
        ctx->jwt_token = calloc(ACVP_JWT_TOKEN_MAX + 1, sizeof(char));
        strcpy_s(ctx->jwt_token, ACVP_JWT_TOKEN_MAX + 1, jwt);
    } else {
        ACVP_LOG_WARN("Missing JWT, results will not be POSTed to server");
        goto end;
    }

    vect_sets = json_object_get_array(obj, "vectorSetUrls");
    vs_cnt = json_array_get_count(vect_sets);
    for (i = 0; i < vs_cnt; i++) {
        char *vsid_url = (char*)json_array_get_string(vect_sets, i);

        if (!vsid_url) {
            ACVP_LOG_WARN("No vsId URL, results will not be POSTed to server");
            goto end;
        }

        rv = acvp_append_vsid_url(ctx, vsid_url);
        if (rv != ACVP_SUCCESS) goto end;
        ACVP_LOG_INFO("Received vsid_url=%s", vsid_url);
    }

    n++;        /* bump past the version or url, jwt, url sets */
    obj = json_array_get_object(reg_array, n);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    vs_entry = ctx->vsid_url_list;
    if (!vs_entry) {
        goto end;
    }

    while (obj) {
        if (!vs_entry) {
            goto end;
        }
        /* Process the kat vector(s) */
        rv  = acvp_dispatch_vector_set(ctx, obj);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("KAT dispatch error");
            goto end;
        }
        ACVP_LOG_STATUS("Write vector set response vsId: %d", ctx->vs_id);

        /* 
         * Convert the JSON from a fully qualified to a value that can be 
         * added to the file. Kind of klumsy, but it works.
         */
        kat_array = json_value_get_array(ctx->kat_resp);
        kat_val = json_array_get_value(kat_array, 1);
        if (!kat_val) {
            ACVP_LOG_ERR("JSON val parse error");
            goto end;
        }
        json_result = json_serialize_to_string_pretty(kat_val, NULL);
        file_val = json_parse_string(json_result);
        json_free_serialized_string(json_result);

        /* track first vector set with file count */
        if (n == 1) {

            rsp_val = json_array_get_value(reg_array, 0);
            /* start the file with the '[' and identifiers array */
            acvp_json_serialize_to_file_pretty_w(rsp_val, rsp_filename);
        } 
        /* append vector sets */
        rv = acvp_json_serialize_to_file_pretty_a(file_val, rsp_filename);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("File write error");
            json_value_free(file_val);
            goto end;
        }

        json_value_free(file_val);
        n++;
        obj = json_array_get_object(reg_array, n);
        vs_entry = vs_entry->next;
    }
    /* append the final ']' to make the JSON work */ 
    rv = acvp_json_serialize_to_file_pretty_a(NULL, rsp_filename);
end:
    json_value_free(val);
    return rv;
}

/*
 * Allows application to read JSON vector responses from a file(rsp_filename)
 * and upload them to the server for verification.
 */
ACVP_RESULT acvp_upload_vectors_from_file(ACVP_CTX *ctx, const char *rsp_filename, int fips_validation) {
    JSON_Object *obj = NULL;
    JSON_Object *rsp_obj = NULL;
    JSON_Object *ver_obj = NULL;
    JSON_Value *vs_val = NULL;
    JSON_Value *new_val = NULL;
    JSON_Value *ver_val = NULL;
    JSON_Value *val = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Array *reg_array;
    int n, i;
    ACVP_STRING_LIST *vs_entry;
    JSON_Array *vect_sets = NULL;
    const char *test_session_url = NULL;
    int vs_cnt = 0;
    const char *jwt = NULL;
    char *json_result = NULL;
    JSON_Array *vec_array = NULL;
    JSON_Value *vec_array_val = NULL;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!rsp_filename) {
        ACVP_LOG_ERR("Must provide value for JSON filename");
        return ACVP_MISSING_ARG;
    }

    if (strnlen_s(rsp_filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided rsp_filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    val = json_parse_file(rsp_filename);
    if (!val) {
        ACVP_LOG_ERR("JSON val parse error");
        return ACVP_MALFORMED_JSON;
    }
    reg_array = json_value_get_array(val);
    obj = json_array_get_object(reg_array, 0);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        rv = ACVP_MALFORMED_JSON;
        goto end;
    }

    /*
     * This is the identifiers provided by the server
     * for this specific test session!
     */
    test_session_url = json_object_get_string(obj, "url");
    if (!test_session_url) {
        ACVP_LOG_ERR("Missing session URL");
        rv = ACVP_MALFORMED_JSON;
        goto end;
    }

    ctx->session_url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!ctx->session_url) {
        rv = ACVP_MALLOC_FAIL;
        goto end;
    }
    strcpy_s(ctx->session_url, ACVP_ATTR_URL_MAX + 1, test_session_url);

    jwt = json_object_get_string(obj, "jwt");
    if (!jwt) {
        rv = ACVP_MALFORMED_JSON;
        goto end;
    }
    ctx->jwt_token = calloc(ACVP_JWT_TOKEN_MAX + 1, sizeof(char));
    if (!ctx->jwt_token) {
        rv = ACVP_MALLOC_FAIL;
        goto end;
    }
    strcpy_s(ctx->jwt_token, ACVP_JWT_TOKEN_MAX + 1, jwt);

    vect_sets = json_object_get_array(obj, "vectorSetUrls");
    vs_cnt = json_array_get_count(vect_sets);
    for (i = 0; i < vs_cnt; i++) {
        char *vsid_url = (char*)json_array_get_string(vect_sets, i);

        if (!vsid_url) {
            ACVP_LOG_ERR("No vsId URL, results will not be POSTed to server");
            rv = ACVP_MALFORMED_JSON;
            goto end;
        }

        rv = acvp_append_vsid_url(ctx, vsid_url);
        if (rv != ACVP_SUCCESS) goto end;
        ACVP_LOG_INFO("Received vsid_url=%s", vsid_url);
    }

    vs_entry = ctx->vsid_url_list;
    if (!vs_entry) {
        goto end;
    }

    if (fips_validation) {
        rv = fips_metadata_ready(ctx);
        if (ACVP_SUCCESS != rv) {
            ACVP_LOG_ERR("Validation metadata not ready");
            goto end;
        }

        ctx->fips.do_validation = 1; /* Enable */
    } else {
        ctx->fips.do_validation = 0; /* Disable */
    }

    n = 1;    /* start with second array index */
    reg_array = json_value_get_array(val);
    vs_val = json_array_get_value(reg_array, n);

    while (vs_entry) {

        /* check vsId compared to vs URL */
        rsp_obj = json_array_get_object(reg_array, n);
        ctx->vs_id = json_object_get_number(rsp_obj, "vsId");

        vec_array_val = json_value_init_array();
        vec_array = json_array((const JSON_Value *)vec_array_val);

        ver_val = json_value_init_object();
        ver_obj = json_value_get_object(ver_val);

        json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
        json_array_append_value(vec_array, ver_val);

        json_result = json_serialize_to_string_pretty(vs_val, NULL);
        new_val = json_parse_string(json_result);
        json_free_serialized_string(json_result);

        json_array_append_value(vec_array, new_val);

        ctx->kat_resp = vec_array_val;

        json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
        if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
            printf("\n\n%s\n\n", json_result);
        } else {
            ACVP_LOG_INFO("\n\n%s\n\n", json_result);
        }
        json_free_serialized_string(json_result);

        rv = acvp_submit_vector_responses(ctx, vs_entry->string);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to submit test results");
            goto end;
        }

        n++;
        vs_val = json_array_get_value(reg_array, n);
        vs_entry = vs_entry->next;
    }

    /*
     * Check the test results.
     */
    ACVP_LOG_STATUS("Tests complete, checking results...");
    rv = acvp_check_test_results(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to retrieve test results");
    }

    if (fips_validation) {
        /*
         * Tell the server to provision a FIPS certificate for this testSession.
         */
        rv = acvp_validate_test_session(ctx);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to perform Validation of testSession");
            goto end;
        }
    }
end:
    json_value_free(val);

    return rv;
}

/*
 * Allows application to set JSON filename within context
 * to be read in during registration
 */
ACVP_RESULT acvp_set_json_filename(ACVP_CTX *ctx, const char *json_filename) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!json_filename) {
        ACVP_LOG_ERR("Must provide value for JSON filename");
        return ACVP_MISSING_ARG;
    }
    if (ctx->json_filename) { free(ctx->json_filename); }

    if (strnlen_s(json_filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided json_filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    ctx->json_filename = calloc(ACVP_JSON_FILENAME_MAX + 1, sizeof(char));
    if (!ctx->json_filename) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->json_filename, ACVP_JSON_FILENAME_MAX + 1, json_filename);

    ctx->use_json = 1;

    return ACVP_SUCCESS;
}

/*
 * This function is used by the application to specify the
 * ACVP server address and TCP port#.
 */
ACVP_RESULT acvp_set_server(ACVP_CTX *ctx, char *server_name, int port) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!server_name || port < 1) {
        return ACVP_INVALID_ARG;
    }
    if (strnlen_s(server_name, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
        ACVP_LOG_ERR("Server name string(s) too long");
        return ACVP_INVALID_ARG;
    }
    if (ctx->server_name) {
        free(ctx->server_name);
    }
    ctx->server_name = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->server_name) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->server_name, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, server_name);

    ctx->server_port = port;

    return ACVP_SUCCESS;
}

/*
 * This function is used by the application to specify the
 * ACVP server URI path segment prefix.
 */
ACVP_RESULT acvp_set_path_segment(ACVP_CTX *ctx, char *path_segment) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!path_segment) {
        return ACVP_INVALID_ARG;
    }
    if (strnlen_s(path_segment, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
        ACVP_LOG_ERR("Path segment string(s) too long");
        return ACVP_INVALID_ARG;
    }
    if (ctx->path_segment) { free(ctx->path_segment); }
    ctx->path_segment = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->path_segment) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->path_segment, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, path_segment);

    return ACVP_SUCCESS;
}

/*
 * This function is used by the application to specify the
 * ACVP server URI path segment prefix.
 */
ACVP_RESULT acvp_set_api_context(ACVP_CTX *ctx, char *api_context) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!api_context) {
        return ACVP_INVALID_ARG;
    }
    if (strnlen_s(api_context, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
        ACVP_LOG_ERR("API context string(s) too long");
        return ACVP_INVALID_ARG;
    }
    if (ctx->api_context) { free(ctx->api_context); }
    ctx->api_context = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->api_context) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->api_context, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, api_context);

    return ACVP_SUCCESS;
}

/*
 * This function allows the client to specify the location of the
 * PEM encoded CA certificates that will be used by Curl to verify
 * the ACVP server during the TLS handshake.  If this function is
 * not called by the application, then peer verification is not
 * enabled, which is not recommended (but provided as an operational
 * mode for testing).
 */
ACVP_RESULT acvp_set_cacerts(ACVP_CTX *ctx, char *ca_file) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!ca_file) {
        return ACVP_MISSING_ARG;
    }

    if (strnlen_s(ca_file, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
        ACVP_LOG_ERR("CA filename is suspiciously long...");
        return ACVP_INVALID_ARG;
    }

    if (ctx->cacerts_file) { free(ctx->cacerts_file); }
    ctx->cacerts_file = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->cacerts_file) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->cacerts_file, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, ca_file);

    return ACVP_SUCCESS;
}

/*
 * This function is used to set the X509 certificate and private
 * key that will be used by libacvp during the TLS handshake to
 * identify itself to the server.  Some servers require TLS client
 * authentication, others do not.  This function is optional and
 * should only be used when the ACVP server supports TLS client
 * authentication.
 */
ACVP_RESULT acvp_set_certkey(ACVP_CTX *ctx, char *cert_file, char *key_file) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!cert_file || !key_file) {
        return ACVP_MISSING_ARG;
    }
    if (strnlen_s(cert_file, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX ||
        strnlen_s(key_file, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
        ACVP_LOG_ERR("CA filename is suspiciously long...");
        return ACVP_INVALID_ARG;
    }
    if (ctx->tls_cert) { free(ctx->tls_cert); }
    ctx->tls_cert = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->tls_cert) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->tls_cert, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, cert_file);

    if (ctx->tls_key) { free(ctx->tls_key); }
    ctx->tls_key = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->tls_key) {
        free(ctx->tls_cert);
        ctx->tls_cert = NULL;
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->tls_key, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, key_file);

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_mark_as_sample(ACVP_CTX *ctx) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    ctx->is_sample = 1;
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_mark_as_request_only(ACVP_CTX *ctx, char *filename) {
    if (!ctx) {
        return ACVP_NO_CTX;
    } 
    if (!filename) {
        return ACVP_MISSING_ARG;
    }
    if (strnlen_s(filename, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
         ACVP_LOG_ERR("Vector filename is suspiciously long...");
        return ACVP_INVALID_ARG;
    }

    if (ctx->vector_req_file) { free(ctx->vector_req_file); }
    ctx->vector_req_file = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->vector_req_file) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->vector_req_file, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, filename);
    ctx->vector_req = 1;
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_mark_as_get_only(ACVP_CTX *ctx, char *string) {

    if (!ctx) {
        return ACVP_NO_CTX;
    } 
    if (!string) {
        return ACVP_MISSING_ARG;
    }
    if (strnlen_s(string, ACVP_REQUEST_STR_LEN_MAX + 1) > ACVP_REQUEST_STR_LEN_MAX) {
         ACVP_LOG_ERR("Request string is suspiciously long...");
        return ACVP_INVALID_ARG;
    }

    if (ctx->get_string) { free(ctx->get_string); }
    ctx->get_string = calloc(ACVP_REQUEST_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->get_string) {
        return ACVP_MALLOC_FAIL;
    }

    strcpy_s(ctx->get_string, ACVP_REQUEST_STR_LEN_MAX + 1, string);
    ctx->get = 1;
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_mark_as_post_only(ACVP_CTX *ctx, char *filename) {

    if (!ctx) {
        return ACVP_NO_CTX;
    } 
    if (!filename) {
        return ACVP_MISSING_ARG;
    }
    if (strnlen_s(filename, ACVP_REQUEST_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
         ACVP_LOG_ERR("Request filename is suspiciously long...");
        return ACVP_INVALID_ARG;
    }

    if (ctx->post_filename) { free(ctx->post_filename); }
    ctx->post_filename = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->post_filename) {
        return ACVP_MALLOC_FAIL;
    }

    strcpy_s(ctx->post_filename, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, filename);
    ctx->post = 1;
    return ACVP_SUCCESS;
}

/*
 * This function builds the JSON login message that
 * will be sent to the ACVP server. If enabled,
 * it will perform the second of the two-factor
 * authentications using a TOTP.
 */
static ACVP_RESULT acvp_build_login(ACVP_CTX *ctx, char **login, int *login_len, int refresh) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *reg_arry_val = NULL;
    JSON_Value *ver_val = NULL;
    JSON_Object *ver_obj = NULL;
    JSON_Value *pw_val = NULL;
    JSON_Object *pw_obj = NULL;
    JSON_Array *reg_arry = NULL;
    char *token = NULL;

    if (!login_len) return ACVP_INVALID_ARG;

    /*
     * Start the login array
     */
    reg_arry_val = json_value_init_array();
    reg_arry = json_array((const JSON_Value *)reg_arry_val);

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
    json_array_append_value(reg_arry, ver_val);

    if (ctx->totp_cb || refresh) {
        pw_val = json_value_init_object();
        pw_obj = json_value_get_object(pw_val);
    }

    if (ctx->totp_cb) {
        token = calloc(ACVP_TOTP_TOKEN_MAX, sizeof(char));
        if (!token) return ACVP_MALLOC_FAIL;

        ctx->totp_cb(&token, ACVP_TOTP_TOKEN_MAX);
        if (strnlen_s(token, ACVP_TOTP_TOKEN_MAX + 1) > ACVP_TOTP_TOKEN_MAX) {
            ACVP_LOG_ERR("totp cb generated a token that is too long");
            json_value_free(pw_val);
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        json_object_set_string(pw_obj, "password", token);
    }

    if (refresh) {
        json_object_set_string(pw_obj, "accessToken", ctx->jwt_token);
    }
    if (pw_val) json_array_append_value(reg_arry, pw_val);

err:
    *login = json_serialize_to_string(reg_arry_val, login_len);
    if (token) free(token);
    json_value_free(reg_arry_val);
    return rv;
}

/*
 * This function is used to register the DUT with the server.
 * Registration allows the DUT to advertise it's capabilities to
 * the server.  The server will respond with a set of vector set
 * identifiers that the client will need to process.
 */
static ACVP_RESULT acvp_register(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *reg = NULL;
    int reg_len = 0;
    JSON_Value *tmp_json_from_file;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (ctx->use_json) {
        tmp_json_from_file = json_parse_file(ctx->json_filename);
        reg = json_serialize_to_string_pretty(tmp_json_from_file, NULL);
        json_value_free(tmp_json_from_file);

        goto end;
    }

    /*
     * Send the capabilities to the ACVP server and get the response,
     * which should be a list of vector set ID urls
     */
    rv = acvp_build_test_session(ctx, &reg, &reg_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to build register message");
        goto end;
    }
    ACVP_LOG_STATUS("Sending registration... %s", reg);
    rv = acvp_send_test_session_registration(ctx, reg, reg_len);
    if (rv == ACVP_SUCCESS) {
        rv = acvp_parse_test_session_register(ctx);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to parse test session response");
            goto end;
        }
    } else {
        ACVP_LOG_ERR("Failed to send registration");
    }

end:
    if (reg) json_free_serialized_string(reg);
    return rv;
}

/*
 * Append a VS identifier to the list of VS identifiers
 * that will need to be downloaded and processed later.
 */
static ACVP_RESULT acvp_append_vsid_url(ACVP_CTX *ctx, char *vsid_url) {
    ACVP_STRING_LIST *vs_entry, *vs_e2;

    vs_entry = calloc(1, sizeof(ACVP_STRING_LIST));
    if (!vs_entry) {
        return ACVP_MALLOC_FAIL;
    }
    vs_entry->string = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!vs_entry->string) {
        free(vs_entry);
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(vs_entry->string, ACVP_ATTR_URL_MAX + 1, vsid_url);

    if (!ctx->vsid_url_list) {
        ctx->vsid_url_list = vs_entry;
    } else {
        vs_e2 = ctx->vsid_url_list;
        while (vs_e2->next) {
            vs_e2 = vs_e2->next;
        }
        vs_e2->next = vs_entry;
    }
    return ACVP_SUCCESS;
}

/*
 * This routine performs the JSON parsing of the login response
 * from the ACVP server.  The response should contain an initial
 * jwt which will be used once during registration.
 */
static ACVP_RESULT acvp_parse_login(ACVP_CTX *ctx) {
    JSON_Value *val;
    JSON_Object *obj = NULL;
    char *json_buf = ctx->curl_buf;
    const char *jwt;
    int large_required = 0;
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Parse the JSON
     */
    val = json_parse_string(json_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }

    obj = acvp_get_obj_from_rsp(ctx, val);

    large_required = json_object_get_boolean(obj, "largeEndpointRequired");

    if (large_required) {
        /* Grab the large submission sizeConstraint */
        ctx->post_size_constraint = (unsigned int)json_object_get_number(obj, "sizeConstraint");
    }

    /*
     * Get the JWT assigned to this session by the server.  This will need
     * to be included when sending the vector responses back to the server
     * later.
     */
    jwt = json_object_get_string(obj, "accessToken");
    if (!jwt) {
        ACVP_LOG_ERR("No access_token provided in registration response");
        rv = ACVP_NO_TOKEN;
        goto end;
    } else {
        if (strnlen_s(jwt, ACVP_JWT_TOKEN_MAX + 1) > ACVP_JWT_TOKEN_MAX) {
            ACVP_LOG_ERR("access_token too large");
            rv = ACVP_NO_TOKEN;
            goto end;
        }

        ctx->jwt_token = calloc(ACVP_JWT_TOKEN_MAX + 1, sizeof(char));
        strcpy_s(ctx->jwt_token, ACVP_JWT_TOKEN_MAX + 1, jwt);

        ACVP_LOG_STATUS("JWT: %s", ctx->jwt_token);
    }
end:
    json_value_free(val);
    return rv;
}

static ACVP_RESULT acvp_parse_validation(ACVP_CTX *ctx) {
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    const char *url = NULL, *status = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Parse the JSON
     */
    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }

    obj = acvp_get_obj_from_rsp(ctx, val);

    /*
     * Get the url of the 'request' status sent by server.
     */
    url = json_object_get_string(obj, "url");
    if (!url) {
        ACVP_LOG_ERR("Validation response JSON missing 'url'");
        rv = ACVP_JSON_ERR;
        goto end;
    }

    status = json_object_get_string(obj, "status");
    if (!status) {
        ACVP_LOG_ERR("Validation response JSON missing 'status'");
        rv = ACVP_JSON_ERR;
        goto end;
    }

    /* Print the request info to screen */
    ACVP_LOG_STATUS("Validation requested -- status %s -- url: %s", status, url);

end:
    if (val) json_value_free(val);
    return rv;
}

ACVP_RESULT acvp_notify_large(ACVP_CTX *ctx,
                              const char *url,
                              char *large_url,
                              unsigned int data_len) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *arr_val = NULL, *val = NULL,
               *ver_val = NULL, *server_val = NULL;
    JSON_Object *obj = NULL, *ver_obj = NULL, *server_obj = NULL;
    JSON_Array *arr = NULL;
    char *substr = NULL;
    char snipped_url[ACVP_ATTR_URL_MAX + 1] = {0} ;
    char *large_notify = NULL;
    const char *jwt = NULL;
    int notify_len = 0;
    const char *large_url_str = NULL;

    if (!url) return ACVP_MISSING_ARG;
    if (!large_url) return ACVP_MISSING_ARG;
    if (!(data_len > ctx->post_size_constraint)) return ACVP_INVALID_ARG;

    arr_val = json_value_init_array();
    arr = json_array((const JSON_Value *)arr_val);

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
    json_array_append_value(arr, ver_val);

    /*
     * Start the large/ array
     */
    val = json_value_init_object();
    obj = json_value_get_object(val);

    /* 
     * Cut off the https://name:port/ prefix and /results suffix
     */
    strstr_s((char *)url, ACVP_ATTR_URL_MAX, "/acvp/v1", 8, &substr);
    strcpy_s(snipped_url, ACVP_ATTR_URL_MAX, substr);
    strstr_s(snipped_url, ACVP_ATTR_URL_MAX, "/results", 8, &substr);
    if (!substr) {
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    *substr = '\0';

    json_object_set_string(obj, "vectorSetUrl", snipped_url);
    json_object_set_number(obj, "submissionSize", data_len);
    
    json_array_append_value(arr, val);

    large_notify = json_serialize_to_string(arr_val, &notify_len);

    ACVP_LOG_ERR("Notifying /large endpoint for this submission... %s", large_notify);
    rv = acvp_transport_post(ctx, "large", large_notify, notify_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to notify /large endpoint");
        goto err;
    }

    server_val = json_parse_string(ctx->curl_buf);
    if (!server_val) {
        ACVP_LOG_ERR("JSON parse error");
        rv = ACVP_JSON_ERR;
        goto err;
    }
    server_obj = acvp_get_obj_from_rsp(ctx, server_val);

    if (!server_obj) {
        ACVP_LOG_ERR("JSON parse error no server object");
        rv = ACVP_JSON_ERR;
        goto err;
    }

    /* Grab the full large/ endpoint URL */
    large_url_str = json_object_get_string(server_obj, "url");
    if (!large_url_str) {
        ACVP_LOG_ERR("JSON parse error no large URL object");
        rv = ACVP_JSON_ERR;
        goto err;
    }

    strcpy_s(large_url, ACVP_ATTR_URL_MAX, large_url_str);

    jwt = json_object_get_string(server_obj, "accessToken");
    if (jwt) {
        /*
         * A single-use JWT was given.
         */
        if (strnlen_s(jwt, ACVP_JWT_TOKEN_MAX + 1) > ACVP_JWT_TOKEN_MAX) {
            ACVP_LOG_ERR("access_token too large");
            rv = ACVP_NO_TOKEN;
            goto err;
        }

        if (ctx->tmp_jwt) {
            memzero_s(ctx->tmp_jwt, ACVP_JWT_TOKEN_MAX);
        } else {
            ctx->tmp_jwt = calloc(ACVP_JWT_TOKEN_MAX + 1, sizeof(char));
        }
        strcpy_s(ctx->tmp_jwt, ACVP_JWT_TOKEN_MAX + 1, jwt);

        ctx->use_tmp_jwt = 1;
    }

err:
    if (arr_val) json_value_free(arr_val);
    if (server_val) json_value_free(server_val);
    if (large_notify) json_free_serialized_string(large_notify);
    return rv;
}

/*
 * This routine performs the JSON parsing of the test session registration
 * from the server. It should contain a list of URLs for vector sets that
 * can be queried to get the test parameters.
 */
static ACVP_RESULT acvp_parse_test_session_register(ACVP_CTX *ctx) {
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    JSON_Array *vect_sets = NULL;
    const char *test_session_url = NULL, *access_token = NULL;
    int i = 0, vs_cnt = 0;
    ACVP_RESULT rv = 0;

    /*
     * Parse the JSON
     */
    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }
    obj = acvp_get_obj_from_rsp(ctx, val);

    /*
     * This is the identifiers provided by the server
     * for this specific test session!
     */
    test_session_url = json_object_get_string(obj, "url");
    if (!test_session_url) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }

    ctx->session_url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
    strcpy_s(ctx->session_url, ACVP_ATTR_URL_MAX + 1, test_session_url);

    /*
     * The accessToken needed for this specific test session.
     */
    access_token = json_object_get_string(obj, "accessToken");
    if (!access_token) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }
    memzero_s(ctx->jwt_token, ACVP_JWT_TOKEN_MAX + 1);
    strcpy_s(ctx->jwt_token, ACVP_JWT_TOKEN_MAX + 1, access_token);

    /*
     * Identify the VS identifiers provided by the server, save them for
     * processing later.
     */
    vect_sets = json_object_get_array(obj, "vectorSetUrls");
    vs_cnt = json_array_get_count(vect_sets);
    for (i = 0; i < vs_cnt; i++) {
        char *vsid_url = (char*)json_array_get_string(vect_sets, i);

        if (!vsid_url) {
            ACVP_LOG_ERR("No vsid_url");
            goto end;
        }

        rv = acvp_append_vsid_url(ctx, vsid_url);
        if (rv != ACVP_SUCCESS) goto end;
        ACVP_LOG_INFO("Received vsid_url=%s", vsid_url);
    }

end:
    if (val) json_value_free(val);
    return rv;
}

/*
 * This function is used by the application after registration
 * to commence the testing.  All the testing will be handled
 * by libacvp.  This function will block the caller.  Therefore,
 * it should be run on a separate thread if needed.
 */
ACVP_RESULT acvp_process_tests(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_STRING_LIST *vs_entry = NULL;
    int count = 0;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Iterate through the VS identifiers the server sent to us
     * in the test session register response.  Process each vector set and
     * return the results to the server.
     */
    vs_entry = ctx->vsid_url_list;
    if (!vs_entry) {
        return ACVP_MISSING_ARG;
    }
    while (vs_entry) {
        rv = acvp_process_vsid(ctx, vs_entry->string, count);
        vs_entry = vs_entry->next;
        count++;
    }
    /* Need to add the ending ']' here */
    if (ctx->vector_req) {
        rv = acvp_json_serialize_to_file_pretty_a(NULL, ctx->vector_req_file);
    }
    return rv;
}

/*
 * This is a minimal retry handler, which pauses for a specific time.
 * This allows the server time to generate the vectors on behalf of
 * the client.
 */
static ACVP_RESULT acvp_retry_handler(ACVP_CTX *ctx, unsigned int retry_period) {
    ACVP_LOG_STATUS("200 OK KAT values not ready, server requests we wait %u seconds and try again...", retry_period);
    if (retry_period <= 0 || retry_period > ACVP_RETRY_TIME_MAX) {
        retry_period = ACVP_RETRY_TIME_MAX;
        ACVP_LOG_WARN("retry_period not found, using max retry period!");
    }
    #ifdef WIN32
    Sleep(retry_period);
    #else
    sleep(retry_period);
    #endif

    return ACVP_KAT_DOWNLOAD_RETRY;
}

/*
 * This routine will iterate through all the vector sets, requesting
 * the test result from the server for each set.
 */
ACVP_RESULT acvp_check_test_results(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    rv = acvp_get_result_test_session(ctx, ctx->session_url);
    return rv;
}

/***************************************************************************************************************
* Begin vector processing logic.  This code should probably go into another module.
***************************************************************************************************************/

static ACVP_RESULT acvp_login(ACVP_CTX *ctx, int refresh) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *login = NULL;
    int login_len = 0;

    rv = acvp_build_login(ctx, &login, &login_len, refresh);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to build login message");
        goto end;
    }

    /*
     * Send the login to the ACVP server and get the response,
     */
    rv = acvp_send_login(ctx, login, login_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_STATUS("Login Send Failed");
        goto end;
    }

    rv = acvp_parse_login(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_STATUS("Login Response Failed, %d", rv);
    }

end:
    if (login) free(login);
    return rv;
}

ACVP_RESULT acvp_refresh(ACVP_CTX *ctx) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    return acvp_login(ctx, 1);
}


/*
 * This function will process a single KAT vector set.  Each KAT
 * vector set has an identifier associated with it, called
 * the vs_id.  During registration, libacvp will receive the
 * list of vs_id's that need to be processed during the test
 * session.  This routine will execute the test flow for a single
 * vs_id.  The flow is:
 *	a) Download the KAT vector set from the server using the vs_id
 *	b) Parse the KAT vectors
 *	c) Process each test case in the KAT vector set
 *	d) Generate the response data
 *	e) Send the response data back to the ACVP server
 */
static ACVP_RESULT acvp_process_vsid(ACVP_CTX *ctx, char *vsid_url, int count) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *val = NULL;
    JSON_Value *alg_val = NULL;
    JSON_Array *alg_array = NULL;
    JSON_Array *url_arr = NULL;
    JSON_Value *ts_val = NULL;
    JSON_Object *ts_obj = NULL;
    JSON_Object *obj = NULL;
    ACVP_STRING_LIST *vs_entry = NULL;
    unsigned int retry_period = 0;
    int retry = 1;

    //TODO: do we want to limit the number of retries?
    while (retry) {
        /*
         * Get the KAT vector set
         */
        rv = acvp_retrieve_vector_set(ctx, vsid_url);
        if (rv != ACVP_SUCCESS) goto end;

        val = json_parse_string(ctx->curl_buf);
        if (!val) {
            ACVP_LOG_ERR("JSON parse error");
            rv = ACVP_JSON_ERR;
            goto end;
        }
        obj = acvp_get_obj_from_rsp(ctx, val);

        /*
         * Check if we received a retry response
         */
        retry_period = (unsigned int)json_object_get_number(obj, "retry");
        if (retry_period) {
            /*
             * Wait and try again to retrieve the VectorSet
             */
            acvp_retry_handler(ctx, retry_period);
            retry = 1;
        } else {

            /*
             * Save the KAT VectorSet to file
             */
            if (ctx->vector_req) {
                alg_array = json_value_get_array(val);
                alg_val = json_array_get_value(alg_array, 1);

                /* track first vector set with file count */
                if (count == 0) {
                    ts_val = json_value_init_object();
                    ts_obj = json_value_get_object(ts_val);

                    json_object_set_string(ts_obj, "jwt", ctx->jwt_token);
                    json_object_set_string(ts_obj, "url", ctx->session_url);

                    json_object_set_value(ts_obj, "vectorSetUrls", json_value_init_array());
                    url_arr = json_object_get_array(ts_obj, "vectorSetUrls");

                    vs_entry = ctx->vsid_url_list;
                    while (vs_entry) {
                        json_array_append_string(url_arr, vs_entry->string);
                        vs_entry = vs_entry->next;
                    }
                    /* Start with identifiers */
                    rv = acvp_json_serialize_to_file_pretty_w(ts_val, ctx->vector_req_file);
                    if (rv != ACVP_SUCCESS) {
                        ACVP_LOG_ERR("File write error");
                        json_value_free(ts_val);
                        goto end;
                    }
                } 
                /* append vector set */
                rv = acvp_json_serialize_to_file_pretty_a(alg_val, ctx->vector_req_file);
                json_value_free(ts_val);
                goto end;
            }
            /*
             * Process the KAT VectorSet
             */
            rv = acvp_process_vector_set(ctx, obj);
            json_value_free(ts_val);
            retry = 0;
        }

        if (rv != ACVP_SUCCESS) goto end;
        json_value_free(val);
        val = NULL;
    }

    /*
     * Send the responses to the ACVP server
     */
    ACVP_LOG_STATUS("POST vector set response vsId: %d", ctx->vs_id);
    rv = acvp_submit_vector_responses(ctx, vsid_url);

end:
    if (val) json_value_free(val);
    return rv;
}

/*
 * This function is used to invoke the appropriate handler function
 * for a given ACV operation.  The operation is specified in the
 * KAT vector set that was previously downloaded.  The handler function
 * is looked up in the alg_tbl[] and invoked here.
 */
static ACVP_RESULT acvp_dispatch_vector_set(ACVP_CTX *ctx, JSON_Object *obj) {
    int i;
    const char *alg = json_object_get_string(obj, "algorithm");
    const char *mode = json_object_get_string(obj, "mode");
    int vs_id = json_object_get_number(obj, "vsId");
    int diff = 1;

    ctx->vs_id = vs_id;
    ACVP_RESULT rv;

    if (!alg) {
        ACVP_LOG_ERR("JSON parse error: ACV algorithm not found");
        return ACVP_JSON_ERR;
    }

    ACVP_LOG_STATUS("vs: %d", vs_id);
    ACVP_LOG_STATUS("ACV Operation: %s", alg);

    for (i = 0; i < ACVP_ALG_MAX; i++) {
        strcmp_s(alg_tbl[i].name,
                 ACVP_ALG_NAME_MAX,
                 alg, &diff);
        if (!diff) {
            if (mode == NULL) {
                rv = (alg_tbl[i].handler)(ctx, obj);
                return rv;
            }

            if (alg_tbl[i].mode != NULL) {
                strcmp_s(alg_tbl[i].mode,
                        ACVP_ALG_MODE_MAX,
                        mode, &diff);
                if (!diff) {
                    rv = (alg_tbl[i].handler)(ctx, obj);
                    return rv;
                }
            }
        }
    }
    return ACVP_UNSUPPORTED_OP;
}

/*
 * This function is used to process the test cases for
 * a given KAT vector set.  This is invoked after the
 * KAT vector set has been downloaded from the server.  The
 * vectors are stored on the ACVP_CTX in one of the
 * transitory fields.  Therefore, the vs_id isn't needed
 * here to know which vectors need to be processed.
 *
 * The processing logic is:
 *	a) JSON parse the data
 *	b) Identify the ACVP operation to be performed (e.g. AES encrypt)
 *	c) Dispatch the vectors to the handler for the
 *	   specified ACVP operation.
 */
static ACVP_RESULT acvp_process_vector_set(ACVP_CTX *ctx, JSON_Object *obj) {
    ACVP_RESULT rv;

    rv = acvp_dispatch_vector_set(ctx, obj);
    if (rv != ACVP_SUCCESS) {
        return rv;
    }

    ACVP_LOG_STATUS("Successfully processed KAT vector set");
    return ACVP_SUCCESS;
}

/*
 * This function will get the test results for a single KAT vector set.
 */
static ACVP_RESULT acvp_get_result_test_session(ACVP_CTX *ctx, char *session_url) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    int count = 0, i = 0, passed = 0;
    JSON_Array *results = NULL;
    JSON_Object *current = NULL;
    const char *status = NULL;

    while (1) {
        /*
         * Get the KAT vector set
         */
        rv = acvp_retrieve_vector_set_result(ctx, session_url);
        if (rv != ACVP_SUCCESS) {
            goto end;
        }

        val = json_parse_string(ctx->curl_buf);
        if (!val) {
            ACVP_LOG_ERR("JSON parse error");
            return ACVP_JSON_ERR;
        }
        obj = acvp_get_obj_from_rsp(ctx, val);

        results = json_object_get_array(obj, "results");
        count = (int)json_array_get_count(results);

        passed = json_object_get_boolean(obj, "passed");
        if (passed == -1) {
            /*
             * Retry
             */
            ACVP_LOG_STATUS("TestSession results incomplete...");
            acvp_retry_handler(ctx, 30);
            if (val) json_value_free(val);
            continue;
        } else if (passed == 1) {
            /*
             * Pass, exit loop
             */
            ACVP_LOG_STATUS("Passed all vectors in testSession");
            ctx->session_passed = 1;
            goto end;
        } else {
            /*
             * Fail, fall through
             */
            ACVP_LOG_STATUS("Failed testSession");
        }

        for (i = 0; i < count; i++) {
            /*
             * Get the sample results if the user had requestd them.
             */
            int diff = 1;
            current = json_array_get_object(results, i);

            status = json_object_get_string(current, "status");
            if (!status) {
                goto end;
            }
            strcmp_s("fail", 4, status, &diff);
            if (!diff) {
                char *vs_url = (char *)json_object_get_string(current, "vectorSetUrl");
                if (!vs_url) {
                    ACVP_LOG_ERR("No vector set URL");
                    goto end;
                }

                ACVP_LOG_STATUS("Getting details for failed Vector Set...");
                rv = acvp_retrieve_vector_set_result(ctx, vs_url);
                if (rv != ACVP_SUCCESS) goto end;

                if (ctx->is_sample) {
                    ACVP_LOG_STATUS("Getting expected results for failed Vector Set...");
                    rv = acvp_retrieve_expected_result(ctx, vs_url);
                    if (rv != ACVP_SUCCESS) goto end;
                }
            }
        }

        /* If we got here, the testSession failed, exit loop*/
        break;
    }

end:
    if (val) json_value_free(val);
    return rv;
}

static ACVP_RESULT fips_metadata_ready(ACVP_CTX *ctx) {
    ACVP_RESULT rv = 0;

    if (ctx == NULL) return ACVP_NO_CTX;

    if (ctx->fips.module == NULL) {
        ACVP_LOG_ERR("Need to specify 'Module' via acvp_oe_set_fips_validation_metadata()");
        return ACVP_UNSUPPORTED_OP;
    }

    if (ctx->fips.oe == NULL) {
        ACVP_LOG_ERR("Need to specify 'Operating Environment' via acvp_oe_set_fips_validation_metadata()");
        return ACVP_UNSUPPORTED_OP;
    }

    /*
     * Verify that the selected FIPS metadata is sane.
     * A.k.a. check that the resources exist on the server DB, if required.
     */
    rv = acvp_oe_verify_fips_operating_env(ctx);
    if (ACVP_SUCCESS != rv) {
        ACVP_LOG_ERR("Failed to verify the FIPS metadata with server");
        return rv;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_validate_test_session(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *validation = NULL;
    int validation_len = 0;

    if (ctx == NULL) return ACVP_NO_CTX;

    if (ctx->session_passed != 1) {
        ACVP_LOG_ERR("This testSession cannot be certified. Required disposition == 'pass'.");
        return ACVP_SUCCESS; // Technically no error occurred
    }

    rv = acvp_build_validation(ctx, &validation, &validation_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to build Validation message");
        goto end;
    }

    /*
     * PUT the validation with the ACVP server and get the response,
     */
    rv = acvp_transport_put_validation(ctx, validation, validation_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_STATUS("Validation send failed");
        goto end;
    }

    rv = acvp_parse_validation(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_STATUS("Failed to parse Validation response");
    }

end:
    if (validation) free(validation);

    return rv;
}


static
ACVP_RESULT acvp_post_data(ACVP_CTX *ctx, char *filename) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Array *data_array = NULL;
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;
    JSON_Value *post_val = NULL;
    JSON_Value *raw_val = NULL;
    const char *path = NULL;
    char *json_result = NULL;
    int len;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!filename) {
        ACVP_LOG_ERR("Must provide value for JSON filename");
        return ACVP_MISSING_ARG;
    }

    if (strnlen_s(filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    val = json_parse_file(filename);
    if (!val) {
        ACVP_LOG_ERR("JSON val parse error");
        return ACVP_MALFORMED_JSON;
    }

    data_array = json_value_get_array(val);
    obj = json_array_get_object(data_array, 0);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    path = json_object_get_string(obj, "url");
    if (!path) {
        ACVP_LOG_WARN("Missing path, POST aborted");
        goto end;
    }

    raw_val = json_array_get_value(data_array, 1);
    json_result = json_serialize_to_string_pretty(raw_val, NULL);
    post_val = json_parse_string(json_result);
    json_free_serialized_string(json_result);

    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    json_array_append_value(reg_arry, post_val);

    json_result = json_serialize_to_string_pretty(reg_arry_val, &len);
    if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
        printf("\nPOST Data: %s\n\n", json_result);
    } else {
        ACVP_LOG_INFO("\n\n%s\n\n", json_result);
    }
    json_value_free(reg_arry_val);

    rv = acvp_login(ctx, 0);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to login with ACVP server");
        json_free_serialized_string(json_result);
        goto end;
    }

    rv = acvp_transport_post(ctx, path, json_result, len);
    json_free_serialized_string(json_result);

end:
    json_value_free(val);
    return rv;

}

ACVP_RESULT acvp_run(ACVP_CTX *ctx, int fips_validation) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (ctx == NULL) return ACVP_NO_CTX;

    rv = acvp_login(ctx, 0);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to login with ACVP server");
        goto end;
    }


    if (ctx->get) { 
        rv = acvp_transport_get(ctx, ctx->get_string, NULL);
        if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
            printf("\nGET Response: %s\n\n", ctx->curl_buf);
        }
        goto end;
    }

    if (ctx->post) { 
        rv = acvp_post_data(ctx, ctx->post_filename);
        goto end;
    }

    if (fips_validation) {
        rv = fips_metadata_ready(ctx);
        if (ACVP_SUCCESS != rv) {
            ACVP_LOG_ERR("Validation metadata not ready");
            return ACVP_UNSUPPORTED_OP;
        }

        ctx->fips.do_validation = 1; /* Enable */
    } else {
        ctx->fips.do_validation = 0; /* Disable */
    }

    /*
     * Register with the server to advertise our capabilities and receive
     * the vector sets identifiers.
     */
    rv = acvp_register(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to register with ACVP server");
        goto end;
    }

    /*
     * Now we process the test cases given to us during
     * registration earlier.
     */
    rv = acvp_process_tests(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to process vectors");
        goto end;
    }
    if (ctx->vector_req) {
        return ACVP_SUCCESS;
    }

    /*
     * Check the test results.
     */
    ACVP_LOG_STATUS("Tests complete, checking results...");
    rv = acvp_check_test_results(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to retrieve test results");
        goto end;
    }

    if (fips_validation) {
        /*
         * Tell the server to provision a FIPS certificate for this testSession.
         */
        rv = acvp_validate_test_session(ctx);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to perform Validation of testSession");
            goto end;
        }
    }

end:
    return rv;
}

char *acvp_version(void) {
    return ACVP_LIBRARY_VERSION;
}

char *acvp_protocol_version(void) {
    return ACVP_VERSION;
}
