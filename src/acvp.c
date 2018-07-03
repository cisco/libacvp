/** @file */
/*****************************************************************************
* Copyright (c) 2016-2017, Cisco Systems, Inc.
* All rights reserved.

* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"


/*
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_parse_register (ACVP_CTX *ctx);

static ACVP_RESULT acvp_parse_login (ACVP_CTX *ctx);

static ACVP_RESULT acvp_process_vsid (ACVP_CTX *ctx, int vs_id);

static ACVP_RESULT acvp_process_vector_set (ACVP_CTX *ctx, JSON_Object *obj);

static ACVP_RESULT acvp_dispatch_vector_set (ACVP_CTX *ctx, JSON_Object *obj);

static void acvp_cap_free_sl (ACVP_SL_LIST *list);

static void acvp_cap_free_nl (ACVP_NAME_LIST *list);

static void acvp_cap_free_hash_pairs (ACVP_RSA_HASH_PAIR_LIST *list);

static ACVP_RESULT acvp_get_result_vsid (ACVP_CTX *ctx, int vs_id);


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
        {ACVP_AES_GCM,           &acvp_aes_kat_handler,             ACVP_ALG_AES_GCM,           NULL},
        {ACVP_AES_CCM,           &acvp_aes_kat_handler,             ACVP_ALG_AES_CCM,           NULL},
        {ACVP_AES_ECB,           &acvp_aes_kat_handler,             ACVP_ALG_AES_ECB,           NULL},
        {ACVP_AES_CBC,           &acvp_aes_kat_handler,             ACVP_ALG_AES_CBC,           NULL},
        {ACVP_AES_CFB1,          &acvp_aes_kat_handler,             ACVP_ALG_AES_CFB1,          NULL},
        {ACVP_AES_CFB8,          &acvp_aes_kat_handler,             ACVP_ALG_AES_CFB8,          NULL},
        {ACVP_AES_CFB128,        &acvp_aes_kat_handler,             ACVP_ALG_AES_CFB128,        NULL},
        {ACVP_AES_OFB,           &acvp_aes_kat_handler,             ACVP_ALG_AES_OFB,           NULL},
        {ACVP_AES_CTR,           &acvp_aes_kat_handler,             ACVP_ALG_AES_CTR,           NULL},
        {ACVP_AES_XTS,           &acvp_aes_kat_handler,             ACVP_ALG_AES_XTS,           NULL},
        {ACVP_AES_KW,            &acvp_aes_kat_handler,             ACVP_ALG_AES_KW,            NULL},
        {ACVP_AES_KWP,           &acvp_aes_kat_handler,             ACVP_ALG_AES_KWP,           NULL},
        {ACVP_TDES_ECB,          &acvp_des_kat_handler,             ACVP_ALG_TDES_ECB,          NULL},
        {ACVP_TDES_CBC,          &acvp_des_kat_handler,             ACVP_ALG_TDES_CBC,          NULL},
        {ACVP_TDES_CBCI,         &acvp_des_kat_handler,             ACVP_ALG_TDES_CBCI,         NULL},
        {ACVP_TDES_OFB,          &acvp_des_kat_handler,             ACVP_ALG_TDES_OFB,          NULL},
        {ACVP_TDES_OFBI,         &acvp_des_kat_handler,             ACVP_ALG_TDES_OFBI,         NULL},
        {ACVP_TDES_CFB1,         &acvp_des_kat_handler,             ACVP_ALG_TDES_CFB1,         NULL},
        {ACVP_TDES_CFB8,         &acvp_des_kat_handler,             ACVP_ALG_TDES_CFB8,         NULL},
        {ACVP_TDES_CFB64,        &acvp_des_kat_handler,             ACVP_ALG_TDES_CFB64,        NULL},
        {ACVP_TDES_CFBP1,        &acvp_des_kat_handler,             ACVP_ALG_TDES_CFBP1,        NULL},
        {ACVP_TDES_CFBP8,        &acvp_des_kat_handler,             ACVP_ALG_TDES_CFBP8,        NULL},
        {ACVP_TDES_CFBP64,       &acvp_des_kat_handler,             ACVP_ALG_TDES_CFBP64,       NULL},
        {ACVP_TDES_CTR,          &acvp_des_kat_handler,             ACVP_ALG_TDES_CTR,          NULL},
        {ACVP_TDES_KW,           &acvp_des_kat_handler,             ACVP_ALG_TDES_KW,           NULL},
        {ACVP_SHA1,              &acvp_hash_kat_handler,            ACVP_ALG_SHA1,              NULL},
        {ACVP_SHA224,            &acvp_hash_kat_handler,            ACVP_ALG_SHA224,            NULL},
        {ACVP_SHA256,            &acvp_hash_kat_handler,            ACVP_ALG_SHA256,            NULL},
        {ACVP_SHA384,            &acvp_hash_kat_handler,            ACVP_ALG_SHA384,            NULL},
        {ACVP_SHA512,            &acvp_hash_kat_handler,            ACVP_ALG_SHA512,            NULL},
        {ACVP_HASHDRBG,          &acvp_drbg_kat_handler,            ACVP_ALG_HASHDRBG,          NULL},
        {ACVP_HMACDRBG,          &acvp_drbg_kat_handler,            ACVP_ALG_HMACDRBG,          NULL},
        {ACVP_CTRDRBG,           &acvp_drbg_kat_handler,            ACVP_ALG_CTRDRBG,           NULL},
        {ACVP_HMAC_SHA1,         &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA1,         NULL},
        {ACVP_HMAC_SHA2_224,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA2_224,     NULL},
        {ACVP_HMAC_SHA2_256,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA2_256,     NULL},
        {ACVP_HMAC_SHA2_384,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA2_384,     NULL},
        {ACVP_HMAC_SHA2_512,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA2_512,     NULL},
        {ACVP_HMAC_SHA2_512_224, &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA2_512_224, NULL},
        {ACVP_HMAC_SHA2_512_256, &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA2_512_256, NULL},
        {ACVP_HMAC_SHA3_224,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA3_224,     NULL},
        {ACVP_HMAC_SHA3_256,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA3_256,     NULL},
        {ACVP_HMAC_SHA3_384,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA3_384,     NULL},
        {ACVP_HMAC_SHA3_512,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA3_512,     NULL},
        {ACVP_CMAC_AES,          &acvp_cmac_kat_handler,            ACVP_ALG_CMAC_AES,          NULL},
        {ACVP_CMAC_TDES,         &acvp_cmac_kat_handler,            ACVP_ALG_CMAC_TDES,         NULL},
        {ACVP_DSA_KEYGEN,        &acvp_dsa_kat_handler,             ACVP_ALG_DSA,               ACVP_ALG_DSA_KEYGEN},
        {ACVP_DSA_PQGGEN,        &acvp_dsa_kat_handler,             ACVP_ALG_DSA,               ACVP_ALG_DSA_PQGGEN},
        {ACVP_DSA_PQGVER,        &acvp_dsa_kat_handler,             ACVP_ALG_DSA,               ACVP_ALG_DSA_PQGVER},
        {ACVP_DSA_SIGGEN,        &acvp_dsa_kat_handler,             ACVP_ALG_DSA,               ACVP_ALG_DSA_SIGGEN},
        {ACVP_DSA_SIGVER,        &acvp_dsa_kat_handler,             ACVP_ALG_DSA,               ACVP_ALG_DSA_SIGVER},
        {ACVP_RSA_KEYGEN,        &acvp_rsa_keygen_kat_handler,      ACVP_ALG_RSA,               ACVP_MODE_KEYGEN},
        {ACVP_RSA_SIGGEN,        &acvp_rsa_siggen_kat_handler,      ACVP_ALG_RSA,               ACVP_MODE_SIGGEN},
        {ACVP_RSA_SIGVER,        &acvp_rsa_sigver_kat_handler,      ACVP_ALG_RSA,               ACVP_MODE_SIGVER},
        {ACVP_ECDSA_KEYGEN,      &acvp_ecdsa_keygen_kat_handler,    ACVP_ALG_ECDSA,             ACVP_MODE_KEYGEN},
        {ACVP_ECDSA_KEYVER,      &acvp_ecdsa_keyver_kat_handler,    ACVP_ALG_ECDSA,             ACVP_MODE_KEYVER},
        {ACVP_ECDSA_SIGGEN,      &acvp_ecdsa_siggen_kat_handler,    ACVP_ALG_ECDSA,             ACVP_MODE_SIGGEN},
        {ACVP_ECDSA_SIGVER,      &acvp_ecdsa_sigver_kat_handler,    ACVP_ALG_ECDSA,             ACVP_MODE_SIGVER},
        {ACVP_KDF135_TLS,        &acvp_kdf135_tls_kat_handler,      ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_TLS},
        {ACVP_KDF135_SNMP,       &acvp_kdf135_snmp_kat_handler,     ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_SNMP},
        {ACVP_KDF135_SSH,        &acvp_kdf135_ssh_kat_handler,      ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_SSH},
        {ACVP_KDF135_SRTP,       &acvp_kdf135_srtp_kat_handler,     ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_SRTP},
        {ACVP_KDF135_IKEV2,      &acvp_kdf135_ikev2_kat_handler,    ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_IKEV2},
        {ACVP_KDF135_IKEV1,      &acvp_kdf135_ikev1_kat_handler,    ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_IKEV1},
        {ACVP_KDF135_X963,       &acvp_kdf135_x963_kat_handler,     ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_X963},
        {ACVP_KDF135_TPM,        &acvp_kdf135_tpm_kat_handler,      ACVP_ALG_KDF135_TPM,        NULL},
        {ACVP_KDF108,            &acvp_kdf108_kat_handler,          ACVP_ALG_KDF108,            NULL},
        {ACVP_KAS_ECC_CDH,       &acvp_kas_ecc_kat_handler,         ACVP_ALG_KAS_ECC,           ACVP_ALG_KAS_ECC_CDH},
        {ACVP_KAS_ECC_COMP,      &acvp_kas_ecc_kat_handler,         ACVP_ALG_KAS_ECC,           ACVP_ALG_KAS_ECC_COMP},
        {ACVP_KAS_ECC_NOCOMP,    &acvp_kas_ecc_kat_handler,         ACVP_ALG_KAS_ECC,           ACVP_ALG_KAS_ECC_NOCOMP},
        {ACVP_KAS_FFC_COMP,      &acvp_kas_ffc_kat_handler,         ACVP_ALG_KAS_FFC,           ACVP_ALG_KAS_FFC_COMP},
        {ACVP_KAS_FFC_NOCOMP,    &acvp_kas_ffc_kat_handler,         ACVP_ALG_KAS_FFC,           ACVP_ALG_KAS_FFC_NOCOMP}
};

/*
 * This is the first function the user should invoke to allocate
 * a new context to be used for the test session.
 */
ACVP_RESULT acvp_create_test_session (ACVP_CTX **ctx,
                                      ACVP_RESULT (*progress_cb) (char *msg),
                                      ACVP_LOG_LVL level) {
    if (!ctx) {
        return ACVP_INVALID_ARG;
    }
    *ctx = calloc(1, sizeof(ACVP_CTX));
    if (!*ctx) {
        return ACVP_MALLOC_FAIL;
    }
    (*ctx)->path_segment = strdup(ACVP_PATH_SEGMENT_DEFAULT);

    if (progress_cb) {
        (*ctx)->test_progress_cb = progress_cb;
    }

    (*ctx)->debug = level;

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_set_2fa_callback (ACVP_CTX *ctx, ACVP_RESULT (*totp_cb) (char **token))
{
    ctx->totp_cb = totp_cb;
    return ACVP_SUCCESS;
}

static void acvp_free_prereqs (ACVP_CAPS_LIST *cap_list) {
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
static void acvp_cap_free_dsa_attrs (ACVP_CAPS_LIST *cap_entry) {
    ACVP_DSA_ATTRS *attrs = NULL, *next = NULL;
    ACVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    int i;

    for (i=0; i<=ACVP_DSA_MAX_MODES; i++) {
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
    dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[0];
    free(dsa_cap_mode);
}

/*
 * Free Internal memory for keygen struct. Since it supports
 * multiple modes, we have to free the whole list
 */
static void acvp_cap_free_rsa_keygen_list (ACVP_CAPS_LIST *cap_list) {
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
static void acvp_cap_free_rsa_sig_list (ACVP_CAPS_LIST *cap_list) {
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
static void acvp_cap_free_kas_ecc_mode (ACVP_CAPS_LIST *cap_list) {
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
            for (i=0; i< ACVP_KAS_ECC_MAX_MODES; i++) {
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
static void acvp_cap_free_kas_ffc_mode (ACVP_CAPS_LIST *cap_list) {
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
            for (i=0; i< ACVP_KAS_FFC_MAX_MODES; i++) {
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
static void acvp_free_drbg_struct (ACVP_CAPS_LIST *cap_list) {
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
static void acvp_cap_free_kdf108 (ACVP_CAPS_LIST *cap_list) {
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
ACVP_RESULT acvp_free_test_session (ACVP_CTX *ctx) {
    ACVP_VS_LIST *vs_entry, *vs_e2;
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    if (ctx) {
        if (ctx->reg_buf) { free(ctx->reg_buf); }
        if (ctx->kat_buf) { free(ctx->kat_buf); }
        if (ctx->upld_buf) { free(ctx->upld_buf); }
        if (ctx->kat_resp) { json_value_free(ctx->kat_resp); }
        if (ctx->server_name) { free(ctx->server_name); }
        if (ctx->vendor_name) { free(ctx->vendor_name); }
        if (ctx->vendor_url) { free(ctx->vendor_url); }
        if (ctx->contact_name) { free(ctx->contact_name); }
        if (ctx->contact_email) { free(ctx->contact_email); }
        if (ctx->module_name) { free(ctx->module_name); }
        if (ctx->module_version) { free(ctx->module_version); }
        if (ctx->module_type) { free(ctx->module_type); }
        if (ctx->module_desc) { free(ctx->module_desc); }
        if (ctx->path_segment) { free(ctx->path_segment); }
        if (ctx->cacerts_file) { free(ctx->cacerts_file); }
        if (ctx->tls_cert) { free(ctx->tls_cert); }
        if (ctx->tls_key) { free(ctx->tls_key); }
        if (ctx->vs_list) {
            vs_entry = ctx->vs_list;
            while (vs_entry) {
                vs_e2 = vs_entry->next;
                free(vs_entry);
                vs_entry = vs_e2;
            }
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
                    free(cap_entry->cap.sym_cap);
                    break;
                case ACVP_HASH_TYPE:
                    free(cap_entry->cap.hash_cap);
                    break;
                case ACVP_DRBG_TYPE:
                    acvp_free_drbg_struct(cap_entry);
                    break;
                case ACVP_HMAC_TYPE:
                    acvp_cap_free_sl(cap_entry->cap.hmac_cap->mac_len);
                    free(cap_entry->cap.hmac_cap);
                    break;
                case ACVP_CMAC_TYPE:
                    acvp_cap_free_sl(cap_entry->cap.cmac_cap->mac_len);
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
                    break;
                case ACVP_ECDSA_KEYVER_TYPE:
                    acvp_cap_free_nl(cap_entry->cap.ecdsa_keyver_cap->curves);
                    acvp_cap_free_nl(cap_entry->cap.ecdsa_keyver_cap->secret_gen_modes);
                    break;
                case ACVP_ECDSA_SIGGEN_TYPE:
                    acvp_cap_free_nl(cap_entry->cap.ecdsa_siggen_cap->curves);
                    acvp_cap_free_nl(cap_entry->cap.ecdsa_siggen_cap->hash_algs);
                    break;
                case ACVP_ECDSA_SIGVER_TYPE:
                    acvp_cap_free_nl(cap_entry->cap.ecdsa_sigver_cap->curves);
                    acvp_cap_free_nl(cap_entry->cap.ecdsa_sigver_cap->hash_algs);
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
                    break;
                case ACVP_KDF135_SSH_TYPE:
                    break;
                case ACVP_KDF135_IKEV2_TYPE:
                    acvp_cap_free_nl(cap_entry->cap.kdf135_ikev2_cap->hash_algs);
                    break;
                case ACVP_KDF135_IKEV1_TYPE:
                    acvp_cap_free_nl(cap_entry->cap.kdf135_ikev1_cap->hash_algs);
                    break;
                case ACVP_KDF135_X963_TYPE:
                    acvp_cap_free_nl(cap_entry->cap.kdf135_x963_cap->hash_algs);
                    acvp_cap_free_sl(cap_entry->cap.kdf135_x963_cap->shared_info_lengths);
                    acvp_cap_free_sl(cap_entry->cap.kdf135_x963_cap->field_sizes);
                    acvp_cap_free_sl(cap_entry->cap.kdf135_x963_cap->key_data_lengths);
                    break;
                case ACVP_KDF135_TPM_TYPE:
                default:
                    return ACVP_INVALID_ARG;
                }
                free(cap_entry);
                cap_entry = cap_e2;
            }
        }
        if (ctx->jwt_token) { free(ctx->jwt_token); }
        free(ctx);
    }
    return ACVP_SUCCESS;
}

/*
 * Simple utility function to free a supported length
 * list from the capabilities structure.
 */
static void acvp_cap_free_sl (ACVP_SL_LIST *list) {
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
static void acvp_cap_free_nl (ACVP_NAME_LIST *list) {
    ACVP_NAME_LIST *top = list;
    ACVP_NAME_LIST *tmp;

    while (top) {
        tmp = top;
        top = top->next;
        free(tmp);
    }
}

static void acvp_cap_free_hash_pairs (ACVP_RSA_HASH_PAIR_LIST *list) {
    ACVP_RSA_HASH_PAIR_LIST *top = list;
    ACVP_RSA_HASH_PAIR_LIST *tmp;

    while (top) {
        tmp = top;

        top = top->next;
        free(tmp);
    }
}

/*
 * Allows application to set JSON filename within context
 * to be read in during registration
 */
ACVP_RESULT acvp_set_json_filename (ACVP_CTX *ctx, const char *json_filename) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!json_filename) {
        ACVP_LOG_ERR("Must provide value for JSON filename");
        return ACVP_INVALID_ARG;
    }
    if (ctx->json_filename) { free(ctx->json_filename); }
    ctx->json_filename = strdup(json_filename);
    ctx->use_json = 1;

    return ACVP_SUCCESS;
}

/*
 * Allows application to specify the vendor attributes for
 * the test session.
 */
ACVP_RESULT acvp_set_vendor_info (ACVP_CTX *ctx,
                                  const char *vendor_name,
                                  const char *vendor_url,
                                  const char *contact_name,
                                  const char *contact_email) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!vendor_name || !vendor_url ||
        !contact_name || !contact_email) {
        ACVP_LOG_ERR("Must provide values for vendor info");
        return ACVP_INVALID_ARG;
    }

    if (ctx->vendor_name) { free(ctx->vendor_name); }
    if (ctx->vendor_url) { free(ctx->vendor_url); }
    if (ctx->contact_name) { free(ctx->contact_name); }
    if (ctx->contact_email) { free(ctx->contact_email); }

    ctx->vendor_name = strdup(vendor_name);
    ctx->vendor_url = strdup(vendor_url);
    ctx->contact_name = strdup(contact_name);
    ctx->contact_email = strdup(contact_email);

    return ACVP_SUCCESS;
}

/*
 * Allows application to specify the crypto module attributes for
 * the test session.
 */
ACVP_RESULT acvp_set_module_info (ACVP_CTX *ctx,
                                  const char *module_name,
                                  const char *module_type,
                                  const char *module_version,
                                  const char *module_description) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (ctx->module_name) { free(ctx->module_name); }
    if (ctx->module_type) { free(ctx->module_type); }
    if (ctx->module_version) { free(ctx->module_version); }
    if (ctx->module_desc) { free(ctx->module_desc); }

    ctx->module_name = strdup(module_name);
    ctx->module_type = strdup(module_type);
    ctx->module_version = strdup(module_version);
    ctx->module_desc = strdup(module_description);

    return ACVP_SUCCESS;
}

/*
 * This function is used by the application to specify the
 * ACVP server address and TCP port#.
 */
ACVP_RESULT acvp_set_server (ACVP_CTX *ctx, char *server_name, int port) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!server_name || !port) {
        return ACVP_INVALID_ARG;
    }
    if (ctx->server_name) {
        free(ctx->server_name);
    }
    ctx->server_name = strdup(server_name);
    ctx->server_port = port;

    return ACVP_SUCCESS;
}

/*
 * This function is used by the application to specify the
 * ACVP server URI path segment prefix.
 */
ACVP_RESULT acvp_set_path_segment (ACVP_CTX *ctx, char *path_segment) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!path_segment) {
        return ACVP_INVALID_ARG;
    }
    if (ctx->path_segment) { free(ctx->path_segment); }
    ctx->path_segment = strdup(path_segment);

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
ACVP_RESULT acvp_set_cacerts (ACVP_CTX *ctx, char *ca_file) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (ctx->cacerts_file) { free(ctx->cacerts_file); }
    ctx->cacerts_file = strdup(ca_file);

    /*
     * Enable peer verification when CA certs are provided.
     */
    ctx->verify_peer = 1;

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
ACVP_RESULT acvp_set_certkey (ACVP_CTX *ctx, char *cert_file, char *key_file) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (ctx->tls_cert) { free(ctx->tls_cert); }
    ctx->tls_cert = strdup(cert_file);
    if (ctx->tls_key) { free(ctx->tls_key); }
    ctx->tls_key = strdup(key_file);

    return ACVP_SUCCESS;
}


void acvp_mark_as_sample (ACVP_CTX *ctx) {
    ctx->is_sample = 1;
}

/*
 * This function builds the JSON login message that
 * will be sent to the ACVP server to perform the
 * second of the two-factor authentications using
 * a TOTP.
 */
static ACVP_RESULT acvp_build_login (ACVP_CTX *ctx, char **login, int refresh) {

    JSON_Value *reg_arry_val = NULL;
    JSON_Value *ver_val = NULL;
    JSON_Object *ver_obj = NULL;
    JSON_Value *pw_val = NULL;
    JSON_Object *pw_obj = NULL;
    JSON_Array *reg_arry = NULL;
    char *token = malloc(ACVP_TOTP_TOKEN_MAX);
    memset(token, 0, ACVP_TOTP_TOKEN_MAX);

    /*
     * Start the login array
     */
    reg_arry_val = json_value_init_array();
    reg_arry = json_array((const JSON_Value *) reg_arry_val);

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
    json_array_append_value(reg_arry, ver_val);

    pw_val = json_value_init_object();
    pw_obj = json_value_get_object(pw_val);

    ctx->totp_cb(&token);

    json_object_set_string(pw_obj, "password", token);

    if (refresh) {
        json_object_set_string(pw_obj, "accessToken", ctx->jwt_token);
    }
    json_array_append_value(reg_arry, pw_val);


    *login = json_serialize_to_string_pretty(reg_arry_val);
    free(token);
    json_value_free(reg_arry_val);
    return ACVP_SUCCESS;
}

/*
 * This function is used to regitser the DUT with the server.
 * Registration allows the DUT to advertise it's capabilities to
 * the server.  The server will respond with a set of vector set
 * identifiers that the client will need to process.
 */
ACVP_RESULT acvp_register (ACVP_CTX *ctx) {
    ACVP_RESULT rv;
    char *reg;
    char *login;
    JSON_Value *tmp_json_from_file;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Construct the login message
     */
    if (ctx->totp_cb) {
        rv = acvp_build_login(ctx, &login, 0);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to build login message");
            return rv;
        }

        if (ctx->debug >= ACVP_LOG_LVL_STATUS) {
            printf("\nPOST %s\n", login);
        } else {
            ACVP_LOG_INFO("POST %s", login);
        }

        /*
         * Send the login to the ACVP server and get the response,
         */
        rv = acvp_send_login(ctx, login);
        if (rv == ACVP_SUCCESS) {
            ACVP_LOG_STATUS("200 OK %s", ctx->reg_buf);
            rv = acvp_parse_login(ctx);
        } else {
            ACVP_LOG_STATUS("Login Response Failed %s", ctx->reg_buf);
        }
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_STATUS("Login Send Failed");
            return rv;
        }
    }

    if (ctx->use_json != 1) {
        /*
         * Construct the registration message based on the capabilities
         * the user has enabled.
         */
        rv = acvp_build_register(ctx, &reg);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to build register message");
            return rv;
        }
    } else {
        tmp_json_from_file = json_parse_file(ctx->json_filename);
        reg = json_serialize_to_string_pretty(tmp_json_from_file);
        json_value_free(tmp_json_from_file);
    }

    if (ctx->debug >= ACVP_LOG_LVL_STATUS) {
        printf("\nPOST %s\n", reg);
    } else {
        ACVP_LOG_INFO("POST %s", reg);
    }
    /*
     * Send the capabilities to the ACVP server and get the response,
     * which should be a list of VS identifiers that will need
     * to be downloaded and processed.
     */
    rv = acvp_send_register(ctx, reg);
    if (rv == ACVP_SUCCESS) {
        ACVP_LOG_STATUS("200 OK %s", ctx->reg_buf);
        rv = acvp_parse_register(ctx);
    }

    json_free_serialized_string(reg);

    return (rv);
}

/*
 * Append a VS identifier to the list of VS identifiers
 * that will need to be downloaded and processed later.
 */
static ACVP_RESULT acvp_append_vs_entry (ACVP_CTX *ctx, int vs_id) {
    ACVP_VS_LIST *vs_entry, *vs_e2;

    vs_entry = calloc(1, sizeof(ACVP_VS_LIST));
    if (!vs_entry) {
        return ACVP_MALLOC_FAIL;
    }
    vs_entry->vs_id = vs_id;

    if (!ctx->vs_list) {
        ctx->vs_list = vs_entry;
    } else {
        vs_e2 = ctx->vs_list;
        while (vs_e2->next) {
            vs_e2 = vs_e2->next;
        }
        vs_e2->next = vs_entry;
    }
    return (ACVP_SUCCESS);
}

/*
 * get version from response
 */
static char *acvp_get_version_from_rsp (JSON_Value *arry_val) {
    char *version = NULL;
    JSON_Object *ver_obj = NULL;

    JSON_Array *reg_array;

    reg_array = json_value_get_array(arry_val);
    ver_obj = json_array_get_object(reg_array, 0);
    version = (char *) json_object_get_string(ver_obj, "acvVersion");
    if (version == NULL) {
        return NULL;
    }

    return (version);
}

/*
 * get JASON Object from response
 */
static JSON_Object *acvp_get_obj_from_rsp (JSON_Value *arry_val) {
    JSON_Object *obj = NULL;
    JSON_Array *reg_array;
    char *ver = NULL;

    reg_array = json_value_get_array(arry_val);
    ver = acvp_get_version_from_rsp(arry_val);
    if (ver == NULL) {
        return NULL;
    }

    obj = json_array_get_object(reg_array, 1);
    return (obj);
}

/*
 * This routine performs the JSON parsing of the login response
 * from the ACVP server.  The response should contain an initial
 * jwt which will be used once during registration.
 */
static ACVP_RESULT acvp_parse_login (ACVP_CTX *ctx) {
    JSON_Value *val;
    JSON_Object *obj = NULL;
    char *json_buf = ctx->reg_buf;
    int i;
    const char *jwt;

    /*
     * Parse the JSON
     */
    val = json_parse_string_with_comments(json_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }

    obj = acvp_get_obj_from_rsp(val);

    /*
     * Get the JWT assigned to this session by the server.  This will need
     * to be included when sending the vector responses back to the server
     * later.
     */
    jwt = json_object_get_string(obj, "accessToken");
    if (!jwt) {
        json_value_free(val);
        ACVP_LOG_ERR("No access_token provided in registration response");
        return ACVP_NO_TOKEN;
    } else {
        i = strnlen(jwt, ACVP_JWT_TOKEN_MAX + 1);
        if (i > ACVP_JWT_TOKEN_MAX) {
            json_value_free(val);
            ACVP_LOG_ERR("access_token too large");
            return ACVP_NO_TOKEN;
        }
        ctx->jwt_token = calloc(1, i + 1);
        strncpy(ctx->jwt_token, jwt, i);
        ctx->jwt_token[i] = 0;
        ACVP_LOG_STATUS("JWT: %s", ctx->jwt_token);
    }
    json_value_free(val);
    return ACVP_SUCCESS;
}

/*
 * This routine performs the JSON parsing of the registration response
 * from the ACVP server.  The response should contain a list of vector
 * set (VS) identifiers that will need to be downloaded and processed
 * by the DUT.
 */
static ACVP_RESULT acvp_parse_register (ACVP_CTX *ctx) {
    JSON_Value *val;
    JSON_Object *obj = NULL;
    JSON_Object *cap_obj = NULL;
    ACVP_RESULT rv;
    char *json_buf = ctx->reg_buf;
    JSON_Array *vect_sets;
    JSON_Value *vs_val;
    JSON_Object *vs_obj;
    int i, vs_cnt;
    int vs_id;
    const char *jwt;

    /*
     * Parse the JSON
     */
    val = json_parse_string_with_comments(json_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }

    obj = acvp_get_obj_from_rsp(val);

    /*
     * Get the JWT assigned to this session by the server.  This will need
     * to be included when sending the vector responses back to the server
     * later.
     */
    jwt = json_object_get_string(obj, "accessToken");
    if (!jwt) {
        json_value_free(val);
        ACVP_LOG_ERR("No access_token provided in registration response");
        return ACVP_NO_TOKEN;
    } else {
        i = strnlen(jwt, ACVP_JWT_TOKEN_MAX + 1);
        if (i > ACVP_JWT_TOKEN_MAX) {
            json_value_free(val);
            ACVP_LOG_ERR("access_token too large");
            return ACVP_NO_TOKEN;
        }
        /* free it if it was used for login */
        if (ctx->jwt_token) {
            free(ctx->jwt_token);
        }
        ctx->jwt_token = calloc(1, i + 1);
        strncpy(ctx->jwt_token, jwt, i);
        ctx->jwt_token[i] = 0;
        ACVP_LOG_STATUS("JWT: %s", ctx->jwt_token);
    }

    /*
     * Identify the VS identifiers provided by the server, save them for
     * processing later.
     */
    cap_obj = json_object_get_object(obj, "capabilityResponse");
    vect_sets = json_object_get_array(cap_obj, "vectorSets");
    vs_cnt = json_array_get_count(vect_sets);
    for (i = 0; i < vs_cnt; i++) {
        vs_val = json_array_get_value(vect_sets, i);
        vs_obj = json_value_get_object(vs_val);
        vs_id = json_object_get_number(vs_obj, "vsId");

        rv = acvp_append_vs_entry(ctx, vs_id);
        if (rv != ACVP_SUCCESS) {
            json_value_free(val);
            return rv;
        }
        ACVP_LOG_INFO("Received vs_id=%d", vs_id);
    }

    json_value_free(val);

    ACVP_LOG_INFO("Successfully processed registration response from server");

    return ACVP_SUCCESS;

}

/*
 * This function is used by the application after registration
 * to commence the testing.  All the testing will be handled
 * by libacvp.  This function will block the caller.  Therefore,
 * it should be run on a separate thread if needed.
 */
ACVP_RESULT acvp_process_tests (ACVP_CTX *ctx) {
    ACVP_RESULT rv;
    ACVP_VS_LIST *vs_entry;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Iterate through the VS identifiers the server sent to us
     * in the regisration response.  Process each vector set and
     * return the results to the server.
     */
    vs_entry = ctx->vs_list;
    while (vs_entry) {
        rv = acvp_process_vsid(ctx, vs_entry->vs_id);
        vs_entry = vs_entry->next;
    }

    return (rv);
}

/*
 * This is a minimal retry handler, which pauses for a specific time.
 * This allows the server time to generate the vectors on behalf of
 * the client.
 */
ACVP_RESULT acvp_retry_handler (ACVP_CTX *ctx, unsigned int retry_period) {
    ACVP_LOG_STATUS("200 OK KAT values not ready, server requests we wait and try again...");
    if (retry_period <= 0 || retry_period > ACVP_RETRY_TIME_MAX) {
        retry_period = ACVP_RETRY_TIME_MAX;
        ACVP_LOG_WARN("retry_period not found, using max retry period!");
    }
    sleep(retry_period);

    return ACVP_KAT_DOWNLOAD_RETRY;
}


/*
 * This routine will iterate through all the vector sets, requesting
 * the test result from the server for each set.
 */
ACVP_RESULT acvp_check_test_results (ACVP_CTX *ctx) {
    ACVP_RESULT rv;
    ACVP_VS_LIST *vs_entry;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Iterate through the VS identifiers the server sent to us
     * in the regisration response.  Attempt to download the result
     * for each vector set.
     */
    vs_entry = ctx->vs_list;
    while (vs_entry) {
        rv = acvp_get_result_vsid(ctx, vs_entry->vs_id);
        if (ctx->is_sample) {
            rv = acvp_retrieve_sample_answers(ctx, vs_entry->vs_id);
        }
        vs_entry = vs_entry->next;
    }

    return (rv);
}



/***************************************************************************************************************
* Begin vector processing logic.  This code should probably go into another module.
***************************************************************************************************************/

ACVP_RESULT acvp_refresh (ACVP_CTX *ctx)
{
    char *login = NULL;
    ACVP_RESULT rv;

    if (ctx->totp_cb) {
        rv = acvp_build_login(ctx, &login, 1);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to build login message");
            return rv;
        }

        if (ctx->debug >= ACVP_LOG_LVL_STATUS) {
            printf("\nPOST %s\n", login);
        } else {
            ACVP_LOG_INFO("POST %s", login);
        }

        /*
         * Send the login to the ACVP server and get the response,
         */
        rv = acvp_send_login(ctx, login);
        if (rv == ACVP_SUCCESS) {
            ACVP_LOG_STATUS("200 OK %s", ctx->reg_buf);
            rv = acvp_parse_login(ctx);
        } else {
            ACVP_LOG_STATUS("Login Response Failed %s", ctx->reg_buf);
        }
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_STATUS("Login Send Failed");
            return rv;
        }
    }
    return ACVP_SUCCESS;
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
static ACVP_RESULT acvp_process_vsid (ACVP_CTX *ctx, int vs_id) {
    ACVP_RESULT rv;
    JSON_Value *val;
    JSON_Object *obj = NULL;
    char *json_buf;
    int retry = 1;

    //TODO: do we want to limit the number of retries?
    while (retry) {
        /*
         * Get the KAT vector set
         */
        rv = acvp_retrieve_vector_set(ctx, vs_id);
        if (rv != ACVP_SUCCESS) {
            return (rv);
        }
        json_buf = ctx->kat_buf;
        if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
            printf("\n200 OK %s\n", ctx->kat_buf);
        } else {
            ACVP_LOG_STATUS("200 OK %s\n", ctx->kat_buf);
        }
        val = json_parse_string_with_comments(json_buf);
        if (!val) {
            ACVP_LOG_ERR("JSON parse error");
            return ACVP_JSON_ERR;
        }
        obj = acvp_get_obj_from_rsp(val);
        ctx->vs_id = vs_id;

        /*
         * Check if we received a retry response
         */
        unsigned int retry_period = json_object_get_number(obj, "retry");
        if (retry_period) {
            rv = acvp_retry_handler(ctx, retry_period);
        } else {
            /*
             * Process the KAT vectors
             */
            rv = acvp_process_vector_set(ctx, obj);
        }
        json_value_free(val);

        /*
         * Check if we need to retry the download because
         * the KAT values were not ready
         */
        if (ACVP_KAT_DOWNLOAD_RETRY == rv) {
            retry = 1;
        } else if (rv != ACVP_SUCCESS) {
            return (rv);
        } else {
            retry = 0;
        }
    }

    /*
     * Send the responses to the ACVP server
     */
    ACVP_LOG_STATUS("POST vector set response vsId: %d", vs_id);
    rv = acvp_submit_vector_responses(ctx);
    if (rv != ACVP_SUCCESS) {
        return (rv);
    }

    return ACVP_SUCCESS;
}

/*
 * This function is used to invoke the appropriate handler function
 * for a given ACV operation.  The operation is specified in the
 * KAT vector set that was previously downloaded.  The handler function
 * is looked up in the alg_tbl[] and invoked here.
 */
static ACVP_RESULT acvp_dispatch_vector_set (ACVP_CTX *ctx, JSON_Object *obj) {
    int i;
    const char *alg = json_object_get_string(obj, "algorithm");
    const char *mode = json_object_get_string(obj, "mode");
    const char *dir = json_object_get_string(obj, "direction");
    int vs_id = json_object_get_number(obj, "vsId");
    ACVP_RESULT rv;
    
    if (!alg) {
        ACVP_LOG_ERR("JSON parse error: ACV algorithm not found");
        return ACVP_JSON_ERR;
    }
    
    ACVP_LOG_STATUS("vsId: %d", vs_id);
    ACVP_LOG_STATUS("ACV Operation: %s", alg);
    // TODO: make sure this is included where relevant only
    ACVP_LOG_INFO("ACV Direction: %s", dir);
    
    ACVP_LOG_INFO("ACV version: %s", json_object_get_string(obj, "acvVersion"));
    
    for (i = 0; i < ACVP_ALG_MAX; i++) {
        if (!strncmp(alg, alg_tbl[i].name, strlen(alg_tbl[i].name))) {
            if (alg_tbl[i].mode != NULL) {
                if (mode != NULL) {
                    if (!strncmp(mode, alg_tbl[i].mode, strlen(alg_tbl[i].mode))) {
                        rv = (alg_tbl[i].handler)(ctx, obj);
                        return rv;
                    }
                }
            } else {
                rv = (alg_tbl[i].handler)(ctx, obj);
                return rv;
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
static ACVP_RESULT acvp_process_vector_set (ACVP_CTX *ctx, JSON_Object *obj) {
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
static ACVP_RESULT acvp_get_result_vsid (ACVP_CTX *ctx, int vs_id) {
    ACVP_RESULT rv;
    JSON_Value *val;
    JSON_Object *obj = NULL;
    char *json_buf;
    int retry = 1;

    while (retry) {
        /*
         * Get the KAT vector set
         */
        rv = acvp_retrieve_vector_set_result(ctx, vs_id);
        if (rv != ACVP_SUCCESS) {
            return (rv);
        }
        json_buf = ctx->kat_buf;

        if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
            printf("\n%s\n", ctx->kat_buf);
        } else {
            ACVP_LOG_ERR("%s", ctx->kat_buf);
        }
        val = json_parse_string_with_comments(json_buf);
        if (!val) {
            ACVP_LOG_ERR("JSON parse error");
            return ACVP_JSON_ERR;
        }
        obj = acvp_get_obj_from_rsp(val);
        ctx->vs_id = vs_id;

        /*
         * Check if we received a retry response
         */
        unsigned int retry_period = json_object_get_number(obj, "retry");
        if (retry_period) {
            rv = acvp_retry_handler(ctx, retry_period);
        } else {
            /*
             * Parse the JSON response from the server, if the vector set failed,
             * then pull out the reason code and log it.
             */
            //TODO
        }
        json_value_free(val);

        /*
         * Check if we need to retry the download because
         * the KAT values were not ready
         */
        if (ACVP_KAT_DOWNLOAD_RETRY == rv) {
            retry = 1;
        } else if (rv != ACVP_SUCCESS) {
            return (rv);
        } else {
            retry = 0;
        }
    }

    return ACVP_SUCCESS;
}

