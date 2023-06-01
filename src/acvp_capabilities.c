/** @file */
/*
 * Copyright (c) 2023, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"
#include "safe_str_lib.h"

static ACVP_RESULT validate_domain_range(int min, int max, int inc) {
    if (min > max || min < 0 || max < 0 || inc < 0 || (max - min) % inc != 0) {
        return ACVP_INVALID_ARG;
    }
    return ACVP_SUCCESS;
}

static ACVP_DSA_CAP *allocate_dsa_cap(void) {
    ACVP_DSA_CAP *cap = NULL;
    ACVP_DSA_CAP_MODE *modes = NULL;
    int i = 0;

    // Allocate the capability object
    cap = calloc(1, sizeof(ACVP_DSA_CAP));
    if (!cap) return NULL;

    // Allocate the array of dsa_mode
    modes = calloc(ACVP_DSA_MAX_MODES, sizeof(ACVP_DSA_CAP_MODE));
    if (!modes) {
        free(cap);
        return NULL;
    }
    cap->dsa_cap_mode = modes;

    /*
     * Set the cap_mode types
     */
    for (i = 0; i < ACVP_DSA_MAX_MODES; i++) {
        // The ACVP_DSA_MODE enum starts at 1
        cap->dsa_cap_mode[i].cap_mode = (ACVP_DSA_MODE)(i + 1);
    }

    return cap;
}

static ACVP_KAS_ECC_CAP *allocate_kas_ecc_cap(void) {
    ACVP_KAS_ECC_CAP *cap = NULL;
    ACVP_KAS_ECC_CAP_MODE *modes = NULL;
    int i = 0;

    cap = calloc(1, sizeof(ACVP_KAS_ECC_CAP));
    if (!cap) {
        return NULL;
    }

    modes = calloc(ACVP_KAS_ECC_MAX_MODES, sizeof(ACVP_KAS_ECC_CAP_MODE));
    if (!modes) {
        free(cap);
        return NULL;
    }
    cap->kas_ecc_mode = (ACVP_KAS_ECC_CAP_MODE *)modes;

    for (i = 0; i < ACVP_KAS_ECC_MAX_MODES; i++) {
        cap->kas_ecc_mode[i].cap_mode = (ACVP_KAS_ECC_MODE)(i + 1);
    }

    return cap;
}

static ACVP_KAS_FFC_CAP *allocate_kas_ffc_cap(void) {
    ACVP_KAS_FFC_CAP *cap = NULL;
    ACVP_KAS_FFC_MODE *modes = NULL;
    int i = 0;

    cap = calloc(1, sizeof(ACVP_KAS_FFC_CAP));
    if (!cap) {
        return NULL;
    }

    modes = calloc(ACVP_KAS_FFC_MAX_MODES, sizeof(ACVP_KAS_FFC_CAP_MODE));
    if (!modes) {
        free(cap);
        return NULL;
    }

    cap->kas_ffc_mode = (ACVP_KAS_FFC_CAP_MODE *)modes;
    for (i = 0; i < ACVP_KAS_FFC_MAX_MODES; i++) {
        cap->kas_ffc_mode[i].cap_mode = (ACVP_KAS_FFC_MODE)(i + 1);
    }

    return cap;
}

static ACVP_KAS_IFC_CAP *allocate_kas_ifc_cap(void) {
    ACVP_KAS_IFC_CAP *cap = NULL;

    cap = calloc(1, sizeof(ACVP_KAS_IFC_CAP));
    if (!cap) {
        return NULL;
    }

    return cap;
}

static ACVP_KTS_IFC_CAP *allocate_kts_ifc_cap(void) {
    ACVP_KTS_IFC_CAP *cap = NULL;

    cap = calloc(1, sizeof(ACVP_KTS_IFC_CAP));
    if (!cap) {
        return NULL;
    }

    return cap;
}

static ACVP_SAFE_PRIMES_CAP *allocate_safe_primes_cap(void) {
    ACVP_SAFE_PRIMES_CAP *cap = NULL;

    cap = calloc(1, sizeof(ACVP_SAFE_PRIMES_CAP));
    if (!cap) {
        return NULL;
    }

    return cap;
}

/*!
 * @brief Create and append an ACVP_CAPS_LIST object
 *        to the current list.
 *
 * This function is designed to handle all of the
 * ACVP_CIPHER and ACVP_CAP_TYPE permutations.
 *
 * @param[in] ctx Pointer to ACVP_CTX whose cap_list will be appended to.
 * @param[in] type ACVP_CAP_TYPE enum value.
 * @param[in] cipher ACVP_CIPHER enum value.
 * @param[in] crypto_handler The function pointer for crypto module callback.
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT acvp_cap_list_append(ACVP_CTX *ctx,
                                        ACVP_CAP_TYPE type,
                                        ACVP_CIPHER cipher,
                                        int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Check for duplicate entry
     */
    if (acvp_locate_cap_entry(ctx, cipher)) {
        return ACVP_DUP_CIPHER;
    }

    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }

    switch (type) {
    case ACVP_CMAC_TYPE:
        cap_entry->cap.cmac_cap = calloc(1, sizeof(ACVP_CMAC_CAP));
        if (!cap_entry->cap.cmac_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KMAC_TYPE:
        cap_entry->cap.kmac_cap = calloc(1, sizeof(ACVP_KMAC_CAP));
        if (!cap_entry->cap.kmac_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_DRBG_TYPE:
        cap_entry->cap.drbg_cap = calloc(1, sizeof(ACVP_DRBG_CAP));
        if (!cap_entry->cap.drbg_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_DSA_TYPE:
        cap_entry->cap.dsa_cap = allocate_dsa_cap();
        if (!cap_entry->cap.dsa_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_ECDSA_KEYGEN_TYPE:
        if (cipher != ACVP_ECDSA_KEYGEN) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.ecdsa_keygen_cap = calloc(1, sizeof(ACVP_ECDSA_CAP));
        if (!cap_entry->cap.ecdsa_keygen_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_ECDSA_KEYVER_TYPE:
        if (cipher != ACVP_ECDSA_KEYVER) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.ecdsa_keyver_cap = calloc(1, sizeof(ACVP_ECDSA_CAP));
        if (!cap_entry->cap.ecdsa_keyver_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_ECDSA_SIGGEN_TYPE:
        if (cipher != ACVP_ECDSA_SIGGEN) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.ecdsa_siggen_cap = calloc(1, sizeof(ACVP_ECDSA_CAP));
        if (!cap_entry->cap.ecdsa_siggen_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_ECDSA_SIGVER_TYPE:
        if (cipher != ACVP_ECDSA_SIGVER) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.ecdsa_sigver_cap = calloc(1, sizeof(ACVP_ECDSA_CAP));
        if (!cap_entry->cap.ecdsa_sigver_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_HASH_TYPE:
        cap_entry->cap.hash_cap = calloc(1, sizeof(ACVP_HASH_CAP));
        if (!cap_entry->cap.hash_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_HMAC_TYPE:
        cap_entry->cap.hmac_cap = calloc(1, sizeof(ACVP_HMAC_CAP));
        if (!cap_entry->cap.hmac_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KAS_ECC_CDH_TYPE:
        if (cipher != ACVP_KAS_ECC_CDH) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ecc_cap = allocate_kas_ecc_cap();
        if (!cap_entry->cap.kas_ecc_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KAS_ECC_COMP_TYPE:
        if (cipher != ACVP_KAS_ECC_COMP) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ecc_cap = allocate_kas_ecc_cap();
        if (!cap_entry->cap.kas_ecc_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KAS_ECC_NOCOMP_TYPE:
        if (cipher != ACVP_KAS_ECC_NOCOMP) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ecc_cap = allocate_kas_ecc_cap();
        if (!cap_entry->cap.kas_ecc_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KAS_ECC_SSC_TYPE:
        if (cipher != ACVP_KAS_ECC_SSC) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ecc_cap = allocate_kas_ecc_cap();
        if (!cap_entry->cap.kas_ecc_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KAS_FFC_SSC_TYPE:
        if (cipher != ACVP_KAS_FFC_SSC) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ffc_cap = allocate_kas_ffc_cap();
        if (!cap_entry->cap.kas_ffc_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;
    case ACVP_KAS_FFC_COMP_TYPE:
        if (cipher != ACVP_KAS_FFC_COMP) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ffc_cap = allocate_kas_ffc_cap();
        if (!cap_entry->cap.kas_ffc_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KAS_FFC_NOCOMP_TYPE:
        if (cipher != ACVP_KAS_FFC_NOCOMP) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ffc_cap = allocate_kas_ffc_cap();
        if (!cap_entry->cap.kas_ffc_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KDA_HKDF_TYPE:
        if (cipher != ACVP_KDA_HKDF) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kda_hkdf_cap = calloc(1, sizeof(ACVP_KDA_HKDF_CAP));
        if (!cap_entry->cap.kda_hkdf_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KDA_ONESTEP_TYPE:
        if (cipher != ACVP_KDA_ONESTEP) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kda_onestep_cap = calloc(1, sizeof(ACVP_KDA_ONESTEP_CAP));
        if (!cap_entry->cap.kda_onestep_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KDA_TWOSTEP_TYPE:
        if (cipher != ACVP_KDA_TWOSTEP) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kda_twostep_cap = calloc(1, sizeof(ACVP_KDA_TWOSTEP_CAP));
        if (!cap_entry->cap.kda_twostep_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KAS_IFC_TYPE:
        if (cipher != ACVP_KAS_IFC_SSC) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ifc_cap = allocate_kas_ifc_cap();
        if (!cap_entry->cap.kas_ifc_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KTS_IFC_TYPE:
        if (cipher != ACVP_KTS_IFC) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kts_ifc_cap = allocate_kts_ifc_cap();
        if (!cap_entry->cap.kts_ifc_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KDF108_TYPE:
        if (cipher != ACVP_KDF108) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf108_cap = calloc(1, sizeof(ACVP_KDF108_CAP));
        if (!cap_entry->cap.kdf108_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KDF135_IKEV1_TYPE:
        if (cipher != ACVP_KDF135_IKEV1) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_ikev1_cap = calloc(1, sizeof(ACVP_KDF135_IKEV1_CAP));
        if (!cap_entry->cap.kdf135_ikev1_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KDF135_IKEV2_TYPE:
        if (cipher != ACVP_KDF135_IKEV2) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_ikev2_cap = calloc(1, sizeof(ACVP_KDF135_IKEV2_CAP));
        if (!cap_entry->cap.kdf135_ikev2_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KDF135_SNMP_TYPE:
        if (cipher != ACVP_KDF135_SNMP) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_snmp_cap = calloc(1, sizeof(ACVP_KDF135_SNMP_CAP));
        if (!cap_entry->cap.kdf135_snmp_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KDF135_SRTP_TYPE:
        if (cipher != ACVP_KDF135_SRTP) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_srtp_cap = calloc(1, sizeof(ACVP_KDF135_SRTP_CAP));
        if (!cap_entry->cap.kdf135_srtp_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KDF135_SSH_TYPE:
        if (cipher != ACVP_KDF135_SSH) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_ssh_cap = calloc(1, sizeof(ACVP_KDF135_SSH_CAP));
        if (!cap_entry->cap.kdf135_ssh_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KDF135_X942_TYPE:
        if (cipher != ACVP_KDF135_X942) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_x942_cap = calloc(1, sizeof(ACVP_KDF135_X942_CAP));
        if (!cap_entry->cap.kdf135_x942_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KDF135_X963_TYPE:
        if (cipher != ACVP_KDF135_X963) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_x963_cap = calloc(1, sizeof(ACVP_KDF135_X963_CAP));
        if (!cap_entry->cap.kdf135_x963_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_PBKDF_TYPE:
        if (cipher != ACVP_PBKDF) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.pbkdf_cap = calloc(1, sizeof(ACVP_PBKDF_CAP));
        if (!cap_entry->cap.pbkdf_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

        case ACVP_KDF_TLS12_TYPE:
        if (cipher != ACVP_KDF_TLS12) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf_tls12_cap = calloc(1, sizeof(ACVP_KDF_TLS12_CAP));
        if (!cap_entry->cap.kdf_tls12_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KDF_TLS13_TYPE:
        if (cipher != ACVP_KDF_TLS13) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf_tls13_cap = calloc(1, sizeof(ACVP_KDF_TLS13_CAP));
        if (!cap_entry->cap.kdf_tls13_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_RSA_KEYGEN_TYPE:
        if (cipher != ACVP_RSA_KEYGEN) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.rsa_keygen_cap = calloc(1, sizeof(ACVP_RSA_KEYGEN_CAP));
        if (!cap_entry->cap.rsa_keygen_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_RSA_SIGGEN_TYPE:
        if (cipher != ACVP_RSA_SIGGEN) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.rsa_siggen_cap = calloc(1, sizeof(ACVP_RSA_SIG_CAP));
        if (!cap_entry->cap.rsa_siggen_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;
    case ACVP_RSA_SIGVER_TYPE:
        if (cipher != ACVP_RSA_SIGVER) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.rsa_sigver_cap = calloc(1, sizeof(ACVP_RSA_SIG_CAP));
        if (!cap_entry->cap.rsa_sigver_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;
    case ACVP_RSA_PRIM_TYPE:
        if ((cipher != ACVP_RSA_SIGPRIM) && (cipher != ACVP_RSA_DECPRIM)) {
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.rsa_prim_cap = calloc(1, sizeof(ACVP_RSA_PRIM_CAP));
        if (!cap_entry->cap.rsa_prim_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;
    case ACVP_SYM_TYPE:
        cap_entry->cap.sym_cap = calloc(1, sizeof(ACVP_SYM_CIPHER_CAP));
        if (!cap_entry->cap.sym_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        cap_entry->cap.sym_cap->perform_ctr_tests = 1; //true by default
        cap_entry->cap.sym_cap->dulen_matches_paylen = 1; //true by default
        break;

    case ACVP_SAFE_PRIMES_KEYGEN_TYPE:
        cap_entry->cap.safe_primes_keygen_cap = allocate_safe_primes_cap();
        if (!cap_entry->cap.safe_primes_keygen_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_SAFE_PRIMES_KEYVER_TYPE:
        cap_entry->cap.safe_primes_keyver_cap = allocate_safe_primes_cap();
        if (!cap_entry->cap.safe_primes_keyver_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_LMS_KEYGEN_TYPE:
        cap_entry->cap.lms_keygen_cap = calloc(1, sizeof(ACVP_LMS_CAP));
        if (!cap_entry->cap.lms_keygen_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_LMS_SIGGEN_TYPE:
        cap_entry->cap.lms_siggen_cap = calloc(1, sizeof(ACVP_LMS_CAP));
        if (!cap_entry->cap.lms_siggen_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_LMS_SIGVER_TYPE:
        cap_entry->cap.lms_sigver_cap = calloc(1, sizeof(ACVP_LMS_CAP));
        if (!cap_entry->cap.lms_sigver_cap) {
            rv = ACVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case ACVP_KDF135_TPM_TYPE:
    default:
        ACVP_LOG_ERR("Invalid parameter 'type'");
        rv = ACVP_INVALID_ARG;
        goto err;
    }

    // Set the other necessary fields
    cap_entry->cipher = cipher;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = type;

    // Append to list
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }

    /* Assume here one cap = one vector set; for special cases we will handle those as the parameter is set */
    ctx->vs_count++;
    return ACVP_SUCCESS;

err:
    if (cap_entry) free(cap_entry);

    return rv;
}

static ACVP_RESULT acvp_validate_kdf135_ssh_param_value(ACVP_KDF135_SSH_METHOD method, ACVP_HASH_ALG param) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;

    if ((method < ACVP_SSH_METH_MAX) && (method > 0)) {
        if ((param & ACVP_SHA3_224) ||
            (param & ACVP_SHA3_256) ||
            (param & ACVP_SHA3_384) ||
            (param & ACVP_SHA3_512)) {
            retval = ACVP_INVALID_ARG;
            
        } else if ((param & ACVP_SHA1) ||
                   (param & ACVP_SHA224) ||
                   (param & ACVP_SHA256) ||
                   (param & ACVP_SHA384) ||
                   (param & ACVP_SHA512)) {
            retval = ACVP_SUCCESS;
        }
    }
    return retval;
}

static ACVP_RESULT acvp_validate_kdf135_srtp_param_value(ACVP_KDF135_SRTP_PARAM param, int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;

    switch (param) {
    case ACVP_SRTP_AES_KEYLEN:
        if (value == 128 ||
            value == 192 ||
            value == 256) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_SRTP_SUPPORT_ZERO_KDR:
        retval = is_valid_tf_param(value);
        break;
    case ACVP_SRTP_KDF_EXPONENT:
        if (value >= 1 && value <= 24) {
            retval = ACVP_SUCCESS;
        }
        break;
    default:
        // Invalid
        break;
    }
    return retval;
}

static ACVP_RESULT acvp_validate_kdf135_x942_domain_value(ACVP_KDF135_X942_PARM param, int min, int max, int inc) {
    switch (param) {
    case ACVP_KDF_X942_KEY_LEN:
    case ACVP_KDF_X942_ZZ_LEN:
        if (min >= 1 && max <= 4096 && inc % 8 == 0) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF_X942_OTHER_INFO_LEN:
    case ACVP_KDF_X942_SUPP_INFO_LEN:
        if (min >= 0 && max <= 4096 && inc % 8 == 0) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF_X942_KDF_TYPE:
    case ACVP_KDF_X942_OID:
    case ACVP_KDF_X942_HASH_ALG:
    default:
        break;
    }

    return ACVP_INVALID_ARG;
}

static ACVP_RESULT acvp_validate_kdf108_param_value(ACVP_CTX *ctx, ACVP_KDF108_PARM param, int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;

    switch (param) {
    case ACVP_KDF108_KDF_MODE:
        ACVP_LOG_ERR("No need to explicity enable mode string. It is set implicity as params are added to a mode.");
        break;
    case ACVP_KDF108_MAC_MODE:
        if (value > ACVP_KDF108_MAC_MODE_MIN && value < ACVP_KDF108_MAC_MODE_MAX) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF108_FIXED_DATA_ORDER:
        if (value > ACVP_KDF108_FIXED_DATA_ORDER_MIN && value < ACVP_KDF108_FIXED_DATA_ORDER_MAX) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF108_COUNTER_LEN:
        if (value <= 32 && value % 8 == 0) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF108_SUPPORTS_EMPTY_IV:
    case ACVP_KDF108_REQUIRES_EMPTY_IV:
        retval = is_valid_tf_param(value);
        break;
    case ACVP_KDF108_PARAM_MIN:
    case ACVP_KDF108_PARAM_MAX:
    case ACVP_KDF108_SUPPORTED_LEN:
        if (value >= 1 && value <= ACVP_KDF108_KEYIN_BIT_MAX) {
            retval = ACVP_SUCCESS;
        }
        break;
    default:
        break;
    }
    return retval;
}

static ACVP_RESULT acvp_dsa_set_modulo(ACVP_DSA_CAP_MODE *dsa_cap_mode,
                                       ACVP_DSA_PARM param,
                                       ACVP_HASH_ALG value) {
    ACVP_DSA_ATTRS *attrs;

    if (!dsa_cap_mode) {
        return ACVP_NO_CTX;
    }

    attrs = dsa_cap_mode->dsa_attrs;
    if (!attrs) {
        attrs = calloc(1, sizeof(ACVP_DSA_ATTRS));
        if (!attrs) {
            return ACVP_MALLOC_FAIL;
        }
        dsa_cap_mode->dsa_attrs = attrs;
        attrs->modulo = param;
        attrs->next = NULL;
    }
    while (1) {
        if (attrs->modulo == param) {
            attrs->sha |= value;
            return ACVP_SUCCESS;
        }
        if (attrs->next == NULL) {
            break;
        }
        attrs = attrs->next;
    }
    attrs->next = calloc(1, sizeof(ACVP_DSA_ATTRS));
    if (!attrs->next) {
        return ACVP_MALLOC_FAIL;
    }
    attrs = attrs->next;
    attrs->modulo = param;
    attrs->sha |= value;
    attrs->next = NULL;
    return ACVP_SUCCESS;
}

/*
 * Add DSA per modulo parameters
 */
static ACVP_RESULT acvp_add_dsa_mode_parm(ACVP_CTX *ctx,
                                          ACVP_DSA_CAP_MODE *dsa_cap_mode,
                                          ACVP_DSA_PARM param,
                                          ACVP_HASH_ALG value) {
    ACVP_RESULT rv;

    /*
     * Validate input
     */
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!dsa_cap_mode) {
        return ACVP_NO_CTX;
    }

    rv = acvp_dsa_set_modulo(dsa_cap_mode, param, value);
    if (rv != ACVP_SUCCESS) {
        return rv;
    }

    return ACVP_SUCCESS;
}

/*
 * Add top level DSA pqggen parameters
 */
static ACVP_RESULT acvp_add_dsa_pqggen_parm(ACVP_CTX *ctx,
                                            ACVP_DSA_CAP_MODE *dsa_cap_mode,
                                            ACVP_DSA_PARM param,
                                            int value) {
    switch (param) {
    case ACVP_DSA_GENPQ:
        switch (value) {
        case ACVP_DSA_PROVABLE:
            dsa_cap_mode->gen_pq_prov = 1;
            break;
        case ACVP_DSA_PROBABLE:
            dsa_cap_mode->gen_pq_prob = 1;
            break;
        default:
            return ACVP_INVALID_ARG;

            break;
        }
        break;
    case ACVP_DSA_GENG:
        switch (value) {
        case ACVP_DSA_CANONICAL:
            dsa_cap_mode->gen_g_can = 1;
            break;
        case ACVP_DSA_UNVERIFIABLE:
            dsa_cap_mode->gen_g_unv = 1;
            break;
        default:
            return ACVP_INVALID_ARG;

            break;
        }
        break;
    case ACVP_DSA_LN1024_160:
        /* allow for verify only */
        if (dsa_cap_mode->cap_mode == ACVP_DSA_MODE_SIGVER || dsa_cap_mode->cap_mode == ACVP_DSA_MODE_PQGVER) {
            return acvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value);
        } else {
            return ACVP_INVALID_ARG;
        }
    case ACVP_DSA_LN2048_224:
    case ACVP_DSA_LN2048_256:
    case ACVP_DSA_LN3072_256:
        return acvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value);
        break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }

    return ACVP_SUCCESS;
}

/*
 * Add top level DSA pqggen parameters
 */
static ACVP_RESULT acvp_add_dsa_keygen_parm(ACVP_CTX *ctx,
                                            ACVP_DSA_CAP_MODE *dsa_cap_mode,
                                            ACVP_DSA_PARM param,
                                            int value) {
    switch (param) {
    case ACVP_DSA_LN2048_224:
    case ACVP_DSA_LN2048_256:
    case ACVP_DSA_LN3072_256:
        return acvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value);
        break;
    case ACVP_DSA_LN1024_160:
    case ACVP_DSA_GENPQ:
    case ACVP_DSA_GENG:
    default:
        return ACVP_INVALID_ARG;

        break;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_validate_sym_cipher_parm_value(ACVP_CIPHER cipher, ACVP_SYM_CIPH_PARM parm, int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;

    switch (parm) {
    case ACVP_SYM_CIPH_KEYLEN:
        switch (cipher) {
        case ACVP_AES_GCM:
        case ACVP_AES_GCM_SIV:
        case ACVP_AES_CCM:
        case ACVP_AES_ECB:
        case ACVP_AES_CBC:
        case ACVP_AES_CBC_CS1:
        case ACVP_AES_CBC_CS2:
        case ACVP_AES_CBC_CS3:
        case ACVP_AES_CFB1:
        case ACVP_AES_CFB8:
        case ACVP_AES_CFB128:
        case ACVP_AES_OFB:
        case ACVP_AES_CTR:
        case ACVP_AES_XTS:
        case ACVP_AES_KW:
        case ACVP_AES_KWP:
        case ACVP_AES_GMAC:
        case ACVP_AES_XPN:
            if (value == 128 || value == 192 || value == 256) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_TDES_ECB:
        case ACVP_TDES_CBC:
        case ACVP_TDES_CBCI:
        case ACVP_TDES_OFB:
        case ACVP_TDES_OFBI:
        case ACVP_TDES_CFB1:
        case ACVP_TDES_CFB8:
        case ACVP_TDES_CFB64:
        case ACVP_TDES_CFBP1:
        case ACVP_TDES_CFBP8:
        case ACVP_TDES_CFBP64:
        case ACVP_TDES_CTR:
        case ACVP_TDES_KW:
            if (value == 192) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_CIPHER_START:
        case ACVP_HASH_SHA1:
        case ACVP_HASH_SHA224:
        case ACVP_HASH_SHA256:
        case ACVP_HASH_SHA384:
        case ACVP_HASH_SHA512:
        case ACVP_HASH_SHA512_224:
        case ACVP_HASH_SHA512_256:
        case ACVP_HASH_SHA3_224:
        case ACVP_HASH_SHA3_256:
        case ACVP_HASH_SHA3_384:
        case ACVP_HASH_SHA3_512:
        case ACVP_HASH_SHAKE_128:
        case ACVP_HASH_SHAKE_256:
        case ACVP_HASHDRBG:
        case ACVP_HMACDRBG:
        case ACVP_CTRDRBG:
        case ACVP_HMAC_SHA1:
        case ACVP_HMAC_SHA2_224:
        case ACVP_HMAC_SHA2_256:
        case ACVP_HMAC_SHA2_384:
        case ACVP_HMAC_SHA2_512:
        case ACVP_HMAC_SHA2_512_224:
        case ACVP_HMAC_SHA2_512_256:
        case ACVP_HMAC_SHA3_224:
        case ACVP_HMAC_SHA3_256:
        case ACVP_HMAC_SHA3_384:
        case ACVP_HMAC_SHA3_512:
        case ACVP_CMAC_AES:
        case ACVP_CMAC_TDES:
        case ACVP_KMAC_128:
        case ACVP_KMAC_256:
        case ACVP_DSA_KEYGEN:
        case ACVP_DSA_PQGGEN:
        case ACVP_DSA_PQGVER:
        case ACVP_DSA_SIGGEN:
        case ACVP_DSA_SIGVER:
        case ACVP_RSA_KEYGEN:
        case ACVP_RSA_SIGGEN:
        case ACVP_RSA_SIGVER:
        case ACVP_RSA_SIGPRIM:
        case ACVP_RSA_DECPRIM:
        case ACVP_ECDSA_KEYGEN:
        case ACVP_ECDSA_KEYVER:
        case ACVP_ECDSA_SIGGEN:
        case ACVP_ECDSA_SIGVER:
        case ACVP_KDF135_SNMP:
        case ACVP_KDF135_SSH:
        case ACVP_KDF135_SRTP:
        case ACVP_KDF135_IKEV2:
        case ACVP_KDF135_IKEV1:
        case ACVP_KDF135_X942:
        case ACVP_KDF135_X963:
        case ACVP_KDF108:
        case ACVP_PBKDF:
        case ACVP_KDF_TLS12:
        case ACVP_KDF_TLS13:
        case ACVP_KAS_ECC_CDH:
        case ACVP_KAS_ECC_COMP:
        case ACVP_KAS_ECC_NOCOMP:
        case ACVP_KAS_ECC_SSC:
        case ACVP_KAS_FFC_COMP:
        case ACVP_KAS_FFC_NOCOMP:
        case ACVP_KDA_ONESTEP:
        case ACVP_KDA_TWOSTEP:
        case ACVP_KDA_HKDF:
        case ACVP_KAS_FFC_SSC:
        case ACVP_KAS_IFC_SSC:
        case ACVP_KTS_IFC:
        case ACVP_SAFE_PRIMES_KEYGEN:
        case ACVP_SAFE_PRIMES_KEYVER:
        case ACVP_LMS_SIGGEN:
        case ACVP_LMS_SIGVER:
        case ACVP_LMS_KEYGEN:
        case ACVP_CIPHER_END:
        default:
            break;
        }
        break;
    case ACVP_SYM_CIPH_TAGLEN:
        switch (cipher) {
        case ACVP_AES_GCM:
        case ACVP_AES_GMAC:
        case ACVP_AES_CCM:
        case ACVP_AES_XPN:
            if (value > 0 && value % 8 == 0 && value <= 128) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_CIPHER_START:
        case ACVP_AES_GCM_SIV:
        case ACVP_AES_ECB:
        case ACVP_AES_CBC:
        case ACVP_AES_CBC_CS1:
        case ACVP_AES_CBC_CS2:
        case ACVP_AES_CBC_CS3:
        case ACVP_AES_CFB1:
        case ACVP_AES_CFB8:
        case ACVP_AES_CFB128:
        case ACVP_AES_OFB:
        case ACVP_AES_CTR:
        case ACVP_AES_XTS:
        case ACVP_AES_KW:
        case ACVP_AES_KWP:
        case ACVP_TDES_ECB:
        case ACVP_TDES_CBC:
        case ACVP_TDES_CBCI:
        case ACVP_TDES_OFB:
        case ACVP_TDES_OFBI:
        case ACVP_TDES_CFB1:
        case ACVP_TDES_CFB8:
        case ACVP_TDES_CFB64:
        case ACVP_TDES_CFBP1:
        case ACVP_TDES_CFBP8:
        case ACVP_TDES_CFBP64:
        case ACVP_TDES_CTR:
        case ACVP_TDES_KW:
        case ACVP_HASH_SHA1:
        case ACVP_HASH_SHA224:
        case ACVP_HASH_SHA256:
        case ACVP_HASH_SHA384:
        case ACVP_HASH_SHA512:
        case ACVP_HASH_SHA512_224:
        case ACVP_HASH_SHA512_256:
        case ACVP_HASH_SHA3_224:
        case ACVP_HASH_SHA3_256:
        case ACVP_HASH_SHA3_384:
        case ACVP_HASH_SHA3_512:
        case ACVP_HASH_SHAKE_128:
        case ACVP_HASH_SHAKE_256:
        case ACVP_HASHDRBG:
        case ACVP_HMACDRBG:
        case ACVP_CTRDRBG:
        case ACVP_HMAC_SHA1:
        case ACVP_HMAC_SHA2_224:
        case ACVP_HMAC_SHA2_256:
        case ACVP_HMAC_SHA2_384:
        case ACVP_HMAC_SHA2_512:
        case ACVP_HMAC_SHA2_512_224:
        case ACVP_HMAC_SHA2_512_256:
        case ACVP_HMAC_SHA3_224:
        case ACVP_HMAC_SHA3_256:
        case ACVP_HMAC_SHA3_384:
        case ACVP_HMAC_SHA3_512:
        case ACVP_CMAC_AES:
        case ACVP_CMAC_TDES:
        case ACVP_KMAC_128:
        case ACVP_KMAC_256:
        case ACVP_DSA_KEYGEN:
        case ACVP_DSA_PQGGEN:
        case ACVP_DSA_PQGVER:
        case ACVP_DSA_SIGGEN:
        case ACVP_DSA_SIGVER:
        case ACVP_RSA_KEYGEN:
        case ACVP_RSA_SIGGEN:
        case ACVP_RSA_SIGVER:
        case ACVP_RSA_SIGPRIM:
        case ACVP_RSA_DECPRIM:
        case ACVP_ECDSA_KEYGEN:
        case ACVP_ECDSA_KEYVER:
        case ACVP_ECDSA_SIGGEN:
        case ACVP_ECDSA_SIGVER:
        case ACVP_KDF135_SNMP:
        case ACVP_KDF135_SSH:
        case ACVP_KDF135_SRTP:
        case ACVP_KDF135_IKEV2:
        case ACVP_KDF135_IKEV1:
        case ACVP_KDF135_X942:
        case ACVP_KDF135_X963:
        case ACVP_KDF108:
        case ACVP_PBKDF:
        case ACVP_KDF_TLS12:
        case ACVP_KDF_TLS13:
        case ACVP_KAS_ECC_CDH:
        case ACVP_KAS_ECC_COMP:
        case ACVP_KAS_ECC_NOCOMP:
        case ACVP_KAS_ECC_SSC:
        case ACVP_KAS_FFC_COMP:
        case ACVP_KAS_FFC_NOCOMP:
        case ACVP_KDA_ONESTEP:
        case ACVP_KDA_TWOSTEP:
        case ACVP_KDA_HKDF:
        case ACVP_KAS_FFC_SSC:
        case ACVP_KAS_IFC_SSC:
        case ACVP_KTS_IFC:
        case ACVP_SAFE_PRIMES_KEYGEN:
        case ACVP_SAFE_PRIMES_KEYVER:
        case ACVP_LMS_SIGGEN:
        case ACVP_LMS_SIGVER:
        case ACVP_LMS_KEYGEN:
        case ACVP_CIPHER_END:
        default:
            break;
        }
        break;
    case ACVP_SYM_CIPH_IVLEN:
        switch (cipher) {
        case ACVP_AES_GCM:
        case ACVP_AES_GCM_SIV:
        case ACVP_AES_CCM:
        case ACVP_AES_GMAC:
        case ACVP_TDES_CBC:
        case ACVP_AES_OFB:
        case ACVP_TDES_CFB1:
        case ACVP_TDES_OFB:
        case ACVP_TDES_CFB8:
        case ACVP_TDES_CFB64:
            if (value >= 8 && value <= 1024) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_CIPHER_START:
        case ACVP_AES_ECB:
        case ACVP_AES_CBC:
        case ACVP_AES_CBC_CS1:
        case ACVP_AES_CBC_CS2:
        case ACVP_AES_CBC_CS3:
        case ACVP_AES_CFB1:
        case ACVP_AES_CFB8:
        case ACVP_AES_CFB128:
        case ACVP_AES_CTR:
        case ACVP_AES_XTS:
        case ACVP_AES_KW:
        case ACVP_AES_KWP:
        case ACVP_AES_XPN:
        case ACVP_TDES_ECB:
        case ACVP_TDES_CBCI:
        case ACVP_TDES_OFBI:
        case ACVP_TDES_CFBP1:
        case ACVP_TDES_CFBP8:
        case ACVP_TDES_CFBP64:
        case ACVP_TDES_CTR:
        case ACVP_TDES_KW:
        case ACVP_HASH_SHA1:
        case ACVP_HASH_SHA224:
        case ACVP_HASH_SHA256:
        case ACVP_HASH_SHA384:
        case ACVP_HASH_SHA512:
        case ACVP_HASH_SHA512_224:
        case ACVP_HASH_SHA512_256:
        case ACVP_HASH_SHA3_224:
        case ACVP_HASH_SHA3_256:
        case ACVP_HASH_SHA3_384:
        case ACVP_HASH_SHA3_512:
        case ACVP_HASH_SHAKE_128:
        case ACVP_HASH_SHAKE_256:
        case ACVP_HASHDRBG:
        case ACVP_HMACDRBG:
        case ACVP_CTRDRBG:
        case ACVP_HMAC_SHA1:
        case ACVP_HMAC_SHA2_224:
        case ACVP_HMAC_SHA2_256:
        case ACVP_HMAC_SHA2_384:
        case ACVP_HMAC_SHA2_512:
        case ACVP_HMAC_SHA2_512_224:
        case ACVP_HMAC_SHA2_512_256:
        case ACVP_HMAC_SHA3_224:
        case ACVP_HMAC_SHA3_256:
        case ACVP_HMAC_SHA3_384:
        case ACVP_HMAC_SHA3_512:
        case ACVP_CMAC_AES:
        case ACVP_CMAC_TDES:
        case ACVP_KMAC_128:
        case ACVP_KMAC_256:
        case ACVP_DSA_KEYGEN:
        case ACVP_DSA_PQGGEN:
        case ACVP_DSA_PQGVER:
        case ACVP_DSA_SIGGEN:
        case ACVP_DSA_SIGVER:
        case ACVP_RSA_KEYGEN:
        case ACVP_RSA_SIGGEN:
        case ACVP_RSA_SIGVER:
        case ACVP_RSA_SIGPRIM:
        case ACVP_RSA_DECPRIM:
        case ACVP_ECDSA_KEYGEN:
        case ACVP_ECDSA_KEYVER:
        case ACVP_ECDSA_SIGGEN:
        case ACVP_ECDSA_SIGVER:
        case ACVP_KDF135_SNMP:
        case ACVP_KDF135_SSH:
        case ACVP_KDF135_SRTP:
        case ACVP_KDF135_IKEV2:
        case ACVP_KDF135_IKEV1:
        case ACVP_KDF135_X942:
        case ACVP_KDF135_X963:
        case ACVP_KDF108:
        case ACVP_PBKDF:
        case ACVP_KDF_TLS12:
        case ACVP_KDF_TLS13:
        case ACVP_KAS_ECC_CDH:
        case ACVP_KAS_ECC_COMP:
        case ACVP_KAS_ECC_NOCOMP:
        case ACVP_KAS_ECC_SSC:
        case ACVP_KAS_FFC_COMP:
        case ACVP_KAS_FFC_NOCOMP:
        case ACVP_KDA_ONESTEP:
        case ACVP_KDA_TWOSTEP:
        case ACVP_KDA_HKDF:
        case ACVP_KAS_FFC_SSC:
        case ACVP_KAS_IFC_SSC:
        case ACVP_KTS_IFC:
        case ACVP_SAFE_PRIMES_KEYGEN:
        case ACVP_SAFE_PRIMES_KEYVER:
        case ACVP_LMS_SIGGEN:
        case ACVP_LMS_SIGVER:
        case ACVP_LMS_KEYGEN:
        case ACVP_CIPHER_END:
        default:
            break;
        }
        break;
    case ACVP_SYM_CIPH_TWEAK:
        if (cipher == ACVP_AES_XTS && value >= ACVP_SYM_CIPH_TWEAK_HEX &&
            value < ACVP_SYM_CIPH_TWEAK_NONE) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_SYM_CIPH_AADLEN:
        switch (cipher) {
        case ACVP_AES_GCM:
        case ACVP_AES_GCM_SIV:
        case ACVP_AES_CCM:
        case ACVP_AES_ECB:
        case ACVP_AES_CBC:
        case ACVP_AES_CFB1:
        case ACVP_AES_CFB8:
        case ACVP_AES_CFB128:
        case ACVP_AES_OFB:
        case ACVP_AES_CTR:
        case ACVP_AES_GMAC:
        case ACVP_AES_XPN:
            if (value >= 0 && value <= 65536) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_CIPHER_START:
        case ACVP_AES_CBC_CS1:
        case ACVP_AES_CBC_CS2:
        case ACVP_AES_CBC_CS3:
        case ACVP_AES_XTS:
        case ACVP_AES_KW:
        case ACVP_AES_KWP:
        case ACVP_TDES_ECB:
        case ACVP_TDES_CBC:
        case ACVP_TDES_CBCI:
        case ACVP_TDES_OFB:
        case ACVP_TDES_OFBI:
        case ACVP_TDES_CFB1:
        case ACVP_TDES_CFB8:
        case ACVP_TDES_CFB64:
        case ACVP_TDES_CFBP1:
        case ACVP_TDES_CFBP8:
        case ACVP_TDES_CFBP64:
        case ACVP_TDES_CTR:
        case ACVP_TDES_KW:
        case ACVP_HASH_SHA1:
        case ACVP_HASH_SHA224:
        case ACVP_HASH_SHA256:
        case ACVP_HASH_SHA384:
        case ACVP_HASH_SHA512:
        case ACVP_HASH_SHA512_224:
        case ACVP_HASH_SHA512_256:
        case ACVP_HASH_SHA3_224:
        case ACVP_HASH_SHA3_256:
        case ACVP_HASH_SHA3_384:
        case ACVP_HASH_SHA3_512:
        case ACVP_HASH_SHAKE_128:
        case ACVP_HASH_SHAKE_256:
        case ACVP_HASHDRBG:
        case ACVP_HMACDRBG:
        case ACVP_CTRDRBG:
        case ACVP_HMAC_SHA1:
        case ACVP_HMAC_SHA2_224:
        case ACVP_HMAC_SHA2_256:
        case ACVP_HMAC_SHA2_384:
        case ACVP_HMAC_SHA2_512:
        case ACVP_HMAC_SHA2_512_224:
        case ACVP_HMAC_SHA2_512_256:
        case ACVP_HMAC_SHA3_224:
        case ACVP_HMAC_SHA3_256:
        case ACVP_HMAC_SHA3_384:
        case ACVP_HMAC_SHA3_512:
        case ACVP_CMAC_AES:
        case ACVP_CMAC_TDES:
        case ACVP_KMAC_128:
        case ACVP_KMAC_256:
        case ACVP_DSA_KEYGEN:
        case ACVP_DSA_PQGGEN:
        case ACVP_DSA_PQGVER:
        case ACVP_DSA_SIGGEN:
        case ACVP_DSA_SIGVER:
        case ACVP_RSA_KEYGEN:
        case ACVP_RSA_SIGGEN:
        case ACVP_RSA_SIGVER:
        case ACVP_RSA_SIGPRIM:
        case ACVP_RSA_DECPRIM:
        case ACVP_ECDSA_KEYGEN:
        case ACVP_ECDSA_KEYVER:
        case ACVP_ECDSA_SIGGEN:
        case ACVP_ECDSA_SIGVER:
        case ACVP_KDF135_SNMP:
        case ACVP_KDF135_SSH:
        case ACVP_KDF135_SRTP:
        case ACVP_KDF135_IKEV2:
        case ACVP_KDF135_IKEV1:
        case ACVP_KDF135_X942:
        case ACVP_KDF135_X963:
        case ACVP_KDF108:
        case ACVP_PBKDF:
        case ACVP_KDF_TLS12:
        case ACVP_KDF_TLS13:
        case ACVP_KAS_ECC_CDH:
        case ACVP_KAS_ECC_COMP:
        case ACVP_KAS_ECC_NOCOMP:
        case ACVP_KAS_ECC_SSC:
        case ACVP_KAS_FFC_COMP:
        case ACVP_KAS_FFC_NOCOMP:
        case ACVP_KDA_ONESTEP:
        case ACVP_KDA_TWOSTEP:
        case ACVP_KDA_HKDF:
        case ACVP_KAS_FFC_SSC:
        case ACVP_KAS_IFC_SSC:
        case ACVP_KTS_IFC:
        case ACVP_SAFE_PRIMES_KEYGEN:
        case ACVP_SAFE_PRIMES_KEYVER:
        case ACVP_LMS_SIGGEN:
        case ACVP_LMS_SIGVER:
        case ACVP_LMS_KEYGEN:
        case ACVP_CIPHER_END:
        default:
            break;
        }
        break;
    case ACVP_SYM_CIPH_PTLEN:
        switch(cipher) {
        case ACVP_AES_GMAC:
            break;
        case ACVP_CIPHER_START:
        case ACVP_AES_GCM:
        case ACVP_AES_GCM_SIV:
        case ACVP_AES_CCM:
        case ACVP_AES_ECB:
        case ACVP_AES_CBC:
        case ACVP_AES_CBC_CS1:
        case ACVP_AES_CBC_CS2:
        case ACVP_AES_CBC_CS3:
        case ACVP_AES_CFB1:
        case ACVP_AES_CFB8:
        case ACVP_AES_CFB128:
        case ACVP_AES_OFB:
        case ACVP_AES_CTR:
        case ACVP_AES_XTS:
        case ACVP_AES_KW:
        case ACVP_AES_KWP:
        case ACVP_AES_XPN:
        case ACVP_TDES_ECB:
        case ACVP_TDES_CBC:
        case ACVP_TDES_CBCI:
        case ACVP_TDES_OFB:
        case ACVP_TDES_OFBI:
        case ACVP_TDES_CFB1:
        case ACVP_TDES_CFB8:
        case ACVP_TDES_CFB64:
        case ACVP_TDES_CFBP1:
        case ACVP_TDES_CFBP8:
        case ACVP_TDES_CFBP64:
        case ACVP_TDES_CTR:
        case ACVP_TDES_KW:
        case ACVP_HASH_SHA1:
        case ACVP_HASH_SHA224:
        case ACVP_HASH_SHA256:
        case ACVP_HASH_SHA384:
        case ACVP_HASH_SHA512:
        case ACVP_HASH_SHA512_224:
        case ACVP_HASH_SHA512_256:
        case ACVP_HASH_SHA3_224:
        case ACVP_HASH_SHA3_256:
        case ACVP_HASH_SHA3_384:
        case ACVP_HASH_SHA3_512:
        case ACVP_HASH_SHAKE_128:
        case ACVP_HASH_SHAKE_256:
        case ACVP_HASHDRBG:
        case ACVP_HMACDRBG:
        case ACVP_CTRDRBG:
        case ACVP_HMAC_SHA1:
        case ACVP_HMAC_SHA2_224:
        case ACVP_HMAC_SHA2_256:
        case ACVP_HMAC_SHA2_384:
        case ACVP_HMAC_SHA2_512:
        case ACVP_HMAC_SHA2_512_224:
        case ACVP_HMAC_SHA2_512_256:
        case ACVP_HMAC_SHA3_224:
        case ACVP_HMAC_SHA3_256:
        case ACVP_HMAC_SHA3_384:
        case ACVP_HMAC_SHA3_512:
        case ACVP_CMAC_AES:
        case ACVP_CMAC_TDES:
        case ACVP_KMAC_128:
        case ACVP_KMAC_256:
        case ACVP_DSA_KEYGEN:
        case ACVP_DSA_PQGGEN:
        case ACVP_DSA_PQGVER:
        case ACVP_DSA_SIGGEN:
        case ACVP_DSA_SIGVER:
        case ACVP_RSA_KEYGEN:
        case ACVP_RSA_SIGGEN:
        case ACVP_RSA_SIGVER:
        case ACVP_RSA_SIGPRIM:
        case ACVP_RSA_DECPRIM:
        case ACVP_ECDSA_KEYGEN:
        case ACVP_ECDSA_KEYVER:
        case ACVP_ECDSA_SIGGEN:
        case ACVP_ECDSA_SIGVER:
        case ACVP_KDF135_SNMP:
        case ACVP_KDF135_SSH:
        case ACVP_KDF135_SRTP:
        case ACVP_KDF135_IKEV2:
        case ACVP_KDF135_IKEV1:
        case ACVP_KDF135_X942:
        case ACVP_KDF135_X963:
        case ACVP_KDF108:
        case ACVP_PBKDF:
        case ACVP_KDF_TLS12:
        case ACVP_KDF_TLS13:
        case ACVP_KAS_ECC_CDH:
        case ACVP_KAS_ECC_COMP:
        case ACVP_KAS_ECC_NOCOMP:
        case ACVP_KAS_ECC_SSC:
        case ACVP_KAS_FFC_COMP:
        case ACVP_KAS_FFC_NOCOMP:
        case ACVP_KDA_ONESTEP:
        case ACVP_KDA_TWOSTEP:
        case ACVP_KDA_HKDF:
        case ACVP_KAS_FFC_SSC:
        case ACVP_KAS_IFC_SSC:
        case ACVP_KTS_IFC:
        case ACVP_SAFE_PRIMES_KEYGEN:
        case ACVP_SAFE_PRIMES_KEYVER:
        case ACVP_LMS_SIGGEN:
        case ACVP_LMS_SIGVER:
        case ACVP_LMS_KEYGEN:
        case ACVP_CIPHER_END:
        default:
            if (value >= 0 && value <= 65536) {
                retval = ACVP_SUCCESS;
            }
            break;
         }
        break;
    case ACVP_SYM_CIPH_KW_MODE:
    case ACVP_SYM_CIPH_PARM_DIR:
    case ACVP_SYM_CIPH_PARM_KO:
    case ACVP_SYM_CIPH_PARM_PERFORM_CTR:
    case ACVP_SYM_CIPH_PARM_CTR_INCR:
    case ACVP_SYM_CIPH_PARM_CTR_OVRFLW:
    case ACVP_SYM_CIPH_PARM_IVGEN_MODE:
    case ACVP_SYM_CIPH_PARM_IVGEN_SRC:
    case ACVP_SYM_CIPH_PARM_SALT_SRC:
    case ACVP_SYM_CIPH_PARM_CONFORMANCE:
    case ACVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN:
    default:
        break;
    }

    return retval;
}

static ACVP_RESULT acvp_validate_sym_cipher_domain_value(ACVP_CIPHER cipher, ACVP_SYM_CIPH_DOMAIN_PARM parm,
                                                       int min, int max, int increment) {

    ACVP_RESULT retval = ACVP_INVALID_ARG;
    int diff = 0;

    if (min > max || min < 0 || increment <= 0) {
        return retval;
    }

    diff = max - min;
    if (diff % increment != 0) {
        return retval;
    }

    switch (cipher) {
    case ACVP_AES_GCM:
        switch (parm) {
        case ACVP_SYM_CIPH_DOMAIN_IVLEN:
            if (min >= 0 && max <= 1024) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 0 && max <= 65536) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_AADLEN:
            if (min >= 0 && max <= 65536) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case ACVP_AES_GCM_SIV:
        switch (parm) {
        case ACVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 0 && max <= 65536 && increment == 8) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_AADLEN:
            if (min >= 0 && max <= 65536 && increment == 8) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_IVLEN:
        case ACVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case ACVP_AES_CCM:
        switch (parm) {
        case ACVP_SYM_CIPH_DOMAIN_IVLEN:
            if (min >= 56 && max <= 104 && increment == 8) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 0 && max <= 256 && increment == 8) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_AADLEN:
            if (min >= 0 && max <= 524288) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case ACVP_AES_CBC_CS1:
    case ACVP_AES_CBC_CS2:
    case ACVP_AES_CBC_CS3:
        switch (parm) {
        case ACVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 128 && max <= 65536) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_IVLEN:
        case ACVP_SYM_CIPH_DOMAIN_AADLEN:
        case ACVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case ACVP_AES_CTR:
        switch (parm) {
        case ACVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 1 && max <= 128) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_IVLEN:
        case ACVP_SYM_CIPH_DOMAIN_AADLEN:
        case ACVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case ACVP_AES_XTS:
        switch (parm) {
        case ACVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 128 && max <= 65536) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_DULEN:
            if (min >= 128 && max <= 65536 && increment % 8 == 0) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_IVLEN:
        case ACVP_SYM_CIPH_DOMAIN_AADLEN:
        default:
            break;
        }
        break;
    case ACVP_AES_KW:
        switch (parm) {
        case ACVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 128 && max <= 524288 && increment % 8 == 0) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_IVLEN:
        case ACVP_SYM_CIPH_DOMAIN_AADLEN:
        case ACVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case ACVP_AES_KWP:
        switch (parm) {
        case ACVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 0 && max <= 524288) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_IVLEN:
        case ACVP_SYM_CIPH_DOMAIN_AADLEN:
        case ACVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case ACVP_AES_GMAC:
        switch (parm) {
        case ACVP_SYM_CIPH_DOMAIN_IVLEN:
            if (min >= 8 && max <= 1024 && increment % 8 == 0) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_AADLEN:
            if (min >= 0 && max <= 65536 && increment % 8 == 0) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_PTLEN:
        case ACVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case ACVP_AES_XPN:
        switch (parm) {
        case ACVP_SYM_CIPH_DOMAIN_IVLEN:
            if (min >= 8 && max <= 1024) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 0 && max <= 65536) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_AADLEN:
            if (min >= 0 && max <= 65536) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case ACVP_TDES_CTR:
    case ACVP_TDES_KW:
        switch (parm) {
        case ACVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 0 && max <= 65536) {
                retval = ACVP_SUCCESS;
            }
            break;
        case ACVP_SYM_CIPH_DOMAIN_IVLEN:
        case ACVP_SYM_CIPH_DOMAIN_AADLEN:
        case ACVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case ACVP_CIPHER_START:
    case ACVP_AES_ECB:
    case ACVP_AES_CBC:
    case ACVP_AES_CFB1:
    case ACVP_AES_CFB8:
    case ACVP_AES_CFB128:
    case ACVP_AES_OFB:
    case ACVP_TDES_ECB:
    case ACVP_TDES_CBC:
    case ACVP_TDES_CBCI:
    case ACVP_TDES_OFB:
    case ACVP_TDES_OFBI:
    case ACVP_TDES_CFB1:
    case ACVP_TDES_CFB8:
    case ACVP_TDES_CFB64:
    case ACVP_TDES_CFBP1:
    case ACVP_TDES_CFBP8:
    case ACVP_TDES_CFBP64:
    case ACVP_HASH_SHA1:
    case ACVP_HASH_SHA224:
    case ACVP_HASH_SHA256:
    case ACVP_HASH_SHA384:
    case ACVP_HASH_SHA512:
    case ACVP_HASH_SHA512_224:
    case ACVP_HASH_SHA512_256:
    case ACVP_HASH_SHA3_224:
    case ACVP_HASH_SHA3_256:
    case ACVP_HASH_SHA3_384:
    case ACVP_HASH_SHA3_512:
    case ACVP_HASH_SHAKE_128:
    case ACVP_HASH_SHAKE_256:
    case ACVP_HASHDRBG:
    case ACVP_HMACDRBG:
    case ACVP_CTRDRBG:
    case ACVP_HMAC_SHA1:
    case ACVP_HMAC_SHA2_224:
    case ACVP_HMAC_SHA2_256:
    case ACVP_HMAC_SHA2_384:
    case ACVP_HMAC_SHA2_512:
    case ACVP_HMAC_SHA2_512_224:
    case ACVP_HMAC_SHA2_512_256:
    case ACVP_HMAC_SHA3_224:
    case ACVP_HMAC_SHA3_256:
    case ACVP_HMAC_SHA3_384:
    case ACVP_HMAC_SHA3_512:
    case ACVP_CMAC_AES:
    case ACVP_CMAC_TDES:
    case ACVP_KMAC_128:
    case ACVP_KMAC_256:
    case ACVP_DSA_KEYGEN:
    case ACVP_DSA_PQGGEN:
    case ACVP_DSA_PQGVER:
    case ACVP_DSA_SIGGEN:
    case ACVP_DSA_SIGVER:
    case ACVP_RSA_KEYGEN:
    case ACVP_RSA_SIGGEN:
    case ACVP_RSA_SIGVER:
    case ACVP_RSA_SIGPRIM:
    case ACVP_RSA_DECPRIM:
    case ACVP_ECDSA_KEYGEN:
    case ACVP_ECDSA_KEYVER:
    case ACVP_ECDSA_SIGGEN:
    case ACVP_ECDSA_SIGVER:
    case ACVP_KDF135_SNMP:
    case ACVP_KDF135_SSH:
    case ACVP_KDF135_SRTP:
    case ACVP_KDF135_IKEV2:
    case ACVP_KDF135_IKEV1:
    case ACVP_KDF135_X942:
    case ACVP_KDF135_X963:
    case ACVP_KDF108:
    case ACVP_PBKDF:
    case ACVP_KDF_TLS12:
    case ACVP_KDF_TLS13:
    case ACVP_KAS_ECC_CDH:
    case ACVP_KAS_ECC_COMP:
    case ACVP_KAS_ECC_NOCOMP:
    case ACVP_KAS_ECC_SSC:
    case ACVP_KAS_FFC_COMP:
    case ACVP_KAS_FFC_NOCOMP:
    case ACVP_KDA_ONESTEP:
    case ACVP_KDA_TWOSTEP:
    case ACVP_KDA_HKDF:
    case ACVP_KAS_FFC_SSC:
    case ACVP_KAS_IFC_SSC:
    case ACVP_KTS_IFC:
    case ACVP_SAFE_PRIMES_KEYGEN:
    case ACVP_SAFE_PRIMES_KEYVER:
    case ACVP_LMS_SIGGEN:
    case ACVP_LMS_SIGVER:
    case ACVP_LMS_KEYGEN:
    case ACVP_CIPHER_END:
    default:
        break;
    }

    return retval;
}

static ACVP_RESULT acvp_validate_prereq_val(ACVP_CIPHER cipher, ACVP_PREREQ_ALG pre_req) {
    switch (cipher) {
    case ACVP_AES_GCM:
    case ACVP_AES_GCM_SIV:
    case ACVP_AES_CCM:
    case ACVP_AES_ECB:
    case ACVP_AES_CFB1:
    case ACVP_AES_CFB8:
    case ACVP_AES_CFB128:
    case ACVP_AES_CTR:
    case ACVP_AES_OFB:
    case ACVP_AES_CBC:
    case ACVP_AES_CBC_CS1:
    case ACVP_AES_CBC_CS2:
    case ACVP_AES_CBC_CS3:
    case ACVP_AES_KW:
    case ACVP_AES_KWP:
    case ACVP_AES_XTS:
    case ACVP_AES_GMAC:
    case ACVP_AES_XPN:
        if (pre_req == ACVP_PREREQ_AES ||
            pre_req == ACVP_PREREQ_DRBG) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_TDES_ECB:
    case ACVP_TDES_CBC:
    case ACVP_TDES_OFB:
    case ACVP_TDES_CFB64:
    case ACVP_TDES_CFB8:
    case ACVP_TDES_CFB1:
    case ACVP_TDES_KW:
        if (pre_req == ACVP_PREREQ_TDES) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_HASH_SHA1:
    case ACVP_HASH_SHA224:
    case ACVP_HASH_SHA256:
    case ACVP_HASH_SHA384:
    case ACVP_HASH_SHA512:
    case ACVP_HASH_SHA512_224:
    case ACVP_HASH_SHA512_256:
    case ACVP_HASH_SHA3_224:
    case ACVP_HASH_SHA3_256:
    case ACVP_HASH_SHA3_384:
    case ACVP_HASH_SHA3_512:
    case ACVP_HASH_SHAKE_128:
    case ACVP_HASH_SHAKE_256:
        return ACVP_INVALID_ARG;

        break;
    case ACVP_HASHDRBG:
        if (pre_req == ACVP_PREREQ_SHA) {
            return ACVP_SUCCESS;
        }
        break;
     case ACVP_HMACDRBG:
        if (pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_HMAC) {
                return ACVP_SUCCESS;
        }
        break;
     case ACVP_CTRDRBG:
         if (pre_req == ACVP_PREREQ_AES ||
             pre_req == ACVP_PREREQ_TDES) {
             return ACVP_SUCCESS;
         }
         break;
    case ACVP_HMAC_SHA1:
    case ACVP_HMAC_SHA2_224:
    case ACVP_HMAC_SHA2_256:
    case ACVP_HMAC_SHA2_384:
    case ACVP_HMAC_SHA2_512:
    case ACVP_HMAC_SHA2_512_224:
    case ACVP_HMAC_SHA2_512_256:
    case ACVP_HMAC_SHA3_224:
    case ACVP_HMAC_SHA3_256:
    case ACVP_HMAC_SHA3_384:
    case ACVP_HMAC_SHA3_512:
        if (pre_req == ACVP_PREREQ_SHA) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_CMAC_AES:
    case ACVP_CMAC_TDES:
        if (pre_req == ACVP_PREREQ_AES ||
            pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_TDES) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KMAC_128:
    case ACVP_KMAC_256:
        break;
    case ACVP_DSA_KEYGEN:
    case ACVP_DSA_PQGGEN:
    case ACVP_DSA_PQGVER:
    case ACVP_DSA_SIGGEN:
    case ACVP_DSA_SIGVER:
        if (pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_DRBG) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_RSA_KEYGEN:
    case ACVP_RSA_SIGGEN:
    case ACVP_RSA_SIGVER:
    case ACVP_RSA_SIGPRIM:
    case ACVP_RSA_DECPRIM:
    case ACVP_ECDSA_KEYGEN:
    case ACVP_ECDSA_KEYVER:
    case ACVP_ECDSA_SIGGEN:
    case ACVP_ECDSA_SIGVER:
        if (pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_DRBG) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF135_SNMP:
    case ACVP_KDF135_SSH:
        if (pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_HMAC ||
            pre_req == ACVP_PREREQ_TDES ||
            pre_req == ACVP_PREREQ_AES) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF135_SRTP:
        if (pre_req == ACVP_PREREQ_AES) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF135_IKEV2:
    case ACVP_KDF135_IKEV1:
        if (pre_req == ACVP_PREREQ_DRBG ||
            pre_req == ACVP_PREREQ_SHA) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF108:
        if (pre_req == ACVP_PREREQ_DRBG ||
            pre_req == ACVP_PREREQ_HMAC ||
            pre_req == ACVP_PREREQ_CMAC ||
            pre_req == ACVP_PREREQ_KAS) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_PBKDF:
        if (pre_req == ACVP_PREREQ_HMAC) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF_TLS12:
        if (pre_req == ACVP_PREREQ_HMAC ||
            pre_req == ACVP_PREREQ_SHA) {
                return ACVP_SUCCESS;
            }
        break;
    case ACVP_KDF_TLS13:
        if (pre_req == ACVP_PREREQ_HMAC) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KAS_ECC_COMP:
    case ACVP_KAS_ECC_SSC:
    case ACVP_KAS_ECC_NOCOMP:
        if (pre_req == ACVP_PREREQ_DRBG ||
            pre_req == ACVP_PREREQ_HMAC ||
            pre_req == ACVP_PREREQ_CMAC ||
            pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_CCM ||
            pre_req == ACVP_PREREQ_ECDSA) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KAS_ECC_CDH:
        if (pre_req == ACVP_PREREQ_ECDSA) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KAS_FFC_COMP:
    case ACVP_KAS_FFC_NOCOMP:
    case ACVP_KAS_FFC_SSC:
        if (pre_req == ACVP_PREREQ_DRBG ||
            pre_req == ACVP_PREREQ_HMAC ||
            pre_req == ACVP_PREREQ_CMAC ||
            pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_SAFE_PRIMES ||
            pre_req == ACVP_PREREQ_CCM ||
            pre_req == ACVP_PREREQ_DSA) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KTS_IFC:
        if (pre_req == ACVP_PREREQ_DRBG || /* will need to add macs if/when supported */
            pre_req == ACVP_PREREQ_HMAC ||
            pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_RSA ||
            pre_req == ACVP_PREREQ_RSADP) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KAS_IFC_SSC:
        if (pre_req == ACVP_PREREQ_DRBG ||
            pre_req == ACVP_PREREQ_HMAC ||
            pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_RSA ||
            pre_req == ACVP_PREREQ_RSADP) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDA_ONESTEP:
        if (pre_req == ACVP_PREREQ_DRBG ||
            pre_req == ACVP_PREREQ_HMAC ||
            pre_req == ACVP_PREREQ_KMAC ||
            pre_req == ACVP_PREREQ_SHA) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDA_TWOSTEP:
        if (pre_req == ACVP_PREREQ_DRBG ||
            pre_req == ACVP_PREREQ_HMAC ||
            pre_req == ACVP_PREREQ_SHA) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDA_HKDF:
        if (pre_req == ACVP_PREREQ_DRBG ||
            pre_req == ACVP_PREREQ_HMAC ||
            pre_req == ACVP_PREREQ_SHA) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF135_X942:
        if (pre_req == ACVP_PREREQ_SHA) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF135_X963:
        if (pre_req == ACVP_PREREQ_SHA) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_SAFE_PRIMES_KEYGEN:
    case ACVP_SAFE_PRIMES_KEYVER:
        if (pre_req == ACVP_PREREQ_DRBG ||
            pre_req == ACVP_PREREQ_SHA) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_LMS_SIGGEN:
    case ACVP_LMS_SIGVER:
    case ACVP_LMS_KEYGEN:
        if (pre_req == ACVP_PREREQ_SHA) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_CIPHER_START:
    case ACVP_TDES_CBCI:
    case ACVP_TDES_OFBI:
    case ACVP_TDES_CFBP1:
    case ACVP_TDES_CFBP8:
    case ACVP_TDES_CFBP64:
    case ACVP_TDES_CTR:
    case ACVP_CIPHER_END:
    default:
        break;
    }

    return ACVP_INVALID_ARG;
}

/*
 * Append a pre req val to the list of prereqs
 */
static ACVP_RESULT acvp_add_prereq_val(ACVP_CIPHER cipher,
                                       ACVP_CAPS_LIST *cap_list,
                                       ACVP_PREREQ_ALG pre_req,
                                       char *value) {
    ACVP_PREREQ_LIST *prereq_entry, *prereq_entry_2;
    ACVP_RESULT result;

    prereq_entry = calloc(1, sizeof(ACVP_PREREQ_LIST));
    if (!prereq_entry) {
        return ACVP_MALLOC_FAIL;
    }
    prereq_entry->prereq_alg_val.alg = pre_req;
    prereq_entry->prereq_alg_val.val = value;

    result = acvp_validate_prereq_val(cipher, pre_req);
    if (result != ACVP_SUCCESS) {
        free(prereq_entry);
        return result;
    }
    /*
     * 1st entry
     */
    if (!cap_list->prereq_vals) {
        cap_list->prereq_vals = prereq_entry;
    } else {
        /*
         * append to the last in the list
         */
        prereq_entry_2 = cap_list->prereq_vals;
        while (prereq_entry_2->next) {
            prereq_entry_2 = prereq_entry_2->next;
        }
        prereq_entry_2->next = prereq_entry;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_set_prereq(ACVP_CTX *ctx,
                                ACVP_CIPHER cipher,
                                ACVP_PREREQ_ALG pre_req_cap,
                                char *value) {
    ACVP_CAPS_LIST *cap_list;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!value || strnlen_s(value, 12) == 0) {
        return ACVP_INVALID_ARG;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    cap_list->has_prereq = 1;     /* make sure this is set */
    /*
     * Add the value to the cap
     */
    return acvp_add_prereq_val(cipher, cap_list, pre_req_cap, value);
}

/*
 * The user should call this after invoking acvp_enable_sym_cipher_cap()
 * to specify the supported key lengths, PT lengths, AAD lengths, IV
 * lengths, and tag lengths. This is called multiple times, for different parms
 * 
 * NOTE: Sym ciphers originally used range values instead of domain. Range values
 * will be phsed out slowly where applicable. For now, allow either set domain OR 
 * set parm to be called for a param, but not both.
 */
ACVP_RESULT acvp_cap_sym_cipher_set_domain(ACVP_CTX *ctx,
                                           ACVP_CIPHER cipher,
                                           ACVP_SYM_CIPH_DOMAIN_PARM parm,
                                           int min,
                                           int max,
                                           int increment) {
    ACVP_CAPS_LIST *cap = NULL;
    ACVP_SYM_CIPHER_CAP *symcap = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    switch (cipher) {
    case ACVP_AES_GCM:
    case ACVP_AES_GCM_SIV:
    case ACVP_AES_CCM:
    case ACVP_AES_ECB:
    case ACVP_AES_CBC:
    case ACVP_AES_CBC_CS1:
    case ACVP_AES_CBC_CS2:
    case ACVP_AES_CBC_CS3:
    case ACVP_AES_CFB1:
    case ACVP_AES_CFB8:
    case ACVP_AES_CFB128:
    case ACVP_AES_OFB:
    case ACVP_AES_CTR:
    case ACVP_AES_XTS:
    case ACVP_AES_KW:
    case ACVP_AES_KWP:
    case ACVP_AES_GMAC:
    case ACVP_AES_XPN:
    case ACVP_TDES_ECB:
    case ACVP_TDES_CBC:
    case ACVP_TDES_CBCI:
    case ACVP_TDES_OFB:
    case ACVP_TDES_OFBI:
    case ACVP_TDES_CFB1:
    case ACVP_TDES_CFB8:
    case ACVP_TDES_CFB64:
    case ACVP_TDES_CFBP1:
    case ACVP_TDES_CFBP8:
    case ACVP_TDES_CFBP64:
    case ACVP_TDES_CTR:
    case ACVP_TDES_KW:
        break;
    case ACVP_CIPHER_START:
    case ACVP_HASH_SHA1:
    case ACVP_HASH_SHA224:
    case ACVP_HASH_SHA256:
    case ACVP_HASH_SHA384:
    case ACVP_HASH_SHA512:
    case ACVP_HASH_SHA512_224:
    case ACVP_HASH_SHA512_256:
    case ACVP_HASH_SHA3_224:
    case ACVP_HASH_SHA3_256:
    case ACVP_HASH_SHA3_384:
    case ACVP_HASH_SHA3_512:
    case ACVP_HASH_SHAKE_128:
    case ACVP_HASH_SHAKE_256:
    case ACVP_HASHDRBG:
    case ACVP_HMACDRBG:
    case ACVP_CTRDRBG:
    case ACVP_HMAC_SHA1:
    case ACVP_HMAC_SHA2_224:
    case ACVP_HMAC_SHA2_256:
    case ACVP_HMAC_SHA2_384:
    case ACVP_HMAC_SHA2_512:
    case ACVP_HMAC_SHA2_512_224:
    case ACVP_HMAC_SHA2_512_256:
    case ACVP_HMAC_SHA3_224:
    case ACVP_HMAC_SHA3_256:
    case ACVP_HMAC_SHA3_384:
    case ACVP_HMAC_SHA3_512:
    case ACVP_CMAC_AES:
    case ACVP_CMAC_TDES:
    case ACVP_KMAC_128:
    case ACVP_KMAC_256:
    case ACVP_DSA_KEYGEN:
    case ACVP_DSA_PQGGEN:
    case ACVP_DSA_PQGVER:
    case ACVP_DSA_SIGGEN:
    case ACVP_DSA_SIGVER:
    case ACVP_RSA_KEYGEN:
    case ACVP_RSA_SIGGEN:
    case ACVP_RSA_SIGVER:
    case ACVP_RSA_SIGPRIM:
    case ACVP_RSA_DECPRIM:
    case ACVP_ECDSA_KEYGEN:
    case ACVP_ECDSA_KEYVER:
    case ACVP_ECDSA_SIGGEN:
    case ACVP_ECDSA_SIGVER:
    case ACVP_KDF135_SNMP:
    case ACVP_KDF135_SSH:
    case ACVP_KDF135_SRTP:
    case ACVP_KDF135_IKEV2:
    case ACVP_KDF135_IKEV1:
    case ACVP_KDF135_X942:
    case ACVP_KDF135_X963:
    case ACVP_KDF108:
    case ACVP_PBKDF:
    case ACVP_KDF_TLS12:
    case ACVP_KDF_TLS13:
    case ACVP_KAS_ECC_CDH:
    case ACVP_KAS_ECC_COMP:
    case ACVP_KAS_ECC_NOCOMP:
    case ACVP_KAS_ECC_SSC:
    case ACVP_KAS_FFC_COMP:
    case ACVP_KAS_FFC_NOCOMP:
    case ACVP_KDA_ONESTEP:
    case ACVP_KDA_TWOSTEP:
    case ACVP_KDA_HKDF:
    case ACVP_KAS_FFC_SSC:
    case ACVP_KAS_IFC_SSC:
    case ACVP_KTS_IFC:
    case ACVP_SAFE_PRIMES_KEYGEN:
    case ACVP_SAFE_PRIMES_KEYVER:
    case ACVP_LMS_SIGGEN:
    case ACVP_LMS_SIGVER:
    case ACVP_LMS_KEYGEN:
    case ACVP_CIPHER_END:
    default:
        return ACVP_INVALID_ARG;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        ACVP_LOG_ERR("Cap entry not found, use acvp_enable_sym_cipher_cap() first.");
        return ACVP_NO_CAP;
    }
    symcap = cap->cap.sym_cap;
    if (!symcap) {
        ACVP_LOG_ERR("Error retrieving sym cipher capabilities object");
        return ACVP_NO_CAP;
    }

    switch (parm) {
    case ACVP_SYM_CIPH_DOMAIN_IVLEN:
        if (symcap->ivlen) {
            ACVP_LOG_ERR("ivLen already defined using acvp_sym_cipher_set_parm. Please set ivLen using only one function "
                         "(Using set_parm for ivLen will eventually be depreciated).");
            return ACVP_INVALID_ARG;
        }
        rv = acvp_validate_sym_cipher_domain_value(cipher, parm, min, max, increment);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to validate given domain value (cipher=%d, param=%d)", cipher, parm);
            return ACVP_INVALID_ARG;
        }
        symcap->iv_len.min = min;
        symcap->iv_len.max = max;
        symcap->iv_len.increment = increment;
        break;
    case ACVP_SYM_CIPH_DOMAIN_PTLEN:
        if (symcap->ptlen) {
            ACVP_LOG_ERR("ptLen already defined using acvp_sym_cipher_set_parm. Please set ptLen using only one function "
                         "(Using set_parm for ptLen will eventually be depreciated).");
            return ACVP_INVALID_ARG;
        }
        rv = acvp_validate_sym_cipher_domain_value(cipher, parm, min, max, increment);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to validate given domain value (cipher=%d, param=%d)", cipher, parm);
            return ACVP_INVALID_ARG;
        }
        symcap->payload_len.min = min;
        symcap->payload_len.max = max;
        symcap->payload_len.increment = increment;
        break;
    case ACVP_SYM_CIPH_DOMAIN_AADLEN:
        if (symcap->aadlen) {
            ACVP_LOG_ERR("aadLen already defined using acvp_sym_cipher_set_parm. Please set aadLen using only one function "
                         "(Using set_parm for aadLen will eventually be depreciated).");
            return ACVP_INVALID_ARG;
        }
        rv = acvp_validate_sym_cipher_domain_value(cipher, parm, min, max, increment);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to validate given domain value (cipher=%d, param=%d)", cipher, parm);
            return ACVP_INVALID_ARG;
        }
        symcap->aad_len.min = min;
        symcap->aad_len.max = max;
        symcap->aad_len.increment = increment;
        break;
    case ACVP_SYM_CIPH_DOMAIN_DULEN:
        if (symcap->dulen_matches_paylen) {
            ACVP_LOG_ERR("ACVP_SYM_CIPH_DOMAIN_DULEN can only be set if "
                         "ACVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN is already set to 0 (false)");
            return ACVP_INVALID_ARG;
        }
        if (cipher != ACVP_AES_XTS) {
            ACVP_LOG_ERR("Data Unit Length may only be set for AES-XTS.");
            return ACVP_INVALID_ARG;
        }
        rv = acvp_validate_sym_cipher_domain_value(cipher, parm, min, max, increment);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to validate given domain value (cipher=%d, param=%d)", cipher, parm);
            return ACVP_INVALID_ARG;
        }
        symcap->du_len.min = min;
        symcap->du_len.max = max;
        symcap->du_len.increment = increment;
        break;
    default:
        ACVP_LOG_ERR("Invalid parameter for symmetric cipher");
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_sym_cipher_cap()
 * to specify the supported key lengths, direction, etc. This is called by the 
 * user multiple times, for different parms.
 */
ACVP_RESULT acvp_cap_sym_cipher_set_parm(ACVP_CTX *ctx,
                                         ACVP_CIPHER cipher,
                                         ACVP_SYM_CIPH_PARM parm,
                                         int value) {
    ACVP_CAPS_LIST *cap = NULL;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    switch (cipher) {
    case ACVP_AES_GCM:
    case ACVP_AES_GCM_SIV:
    case ACVP_AES_CCM:
    case ACVP_AES_ECB:
    case ACVP_AES_CBC:
    case ACVP_AES_CBC_CS1:
    case ACVP_AES_CBC_CS2:
    case ACVP_AES_CBC_CS3:
    case ACVP_AES_CFB1:
    case ACVP_AES_CFB8:
    case ACVP_AES_CFB128:
    case ACVP_AES_OFB:
    case ACVP_AES_CTR:
    case ACVP_AES_XTS:
    case ACVP_AES_KW:
    case ACVP_AES_KWP:
    case ACVP_AES_GMAC:
    case ACVP_AES_XPN:
    case ACVP_TDES_ECB:
    case ACVP_TDES_CBC:
    case ACVP_TDES_CBCI:
    case ACVP_TDES_OFB:
    case ACVP_TDES_OFBI:
    case ACVP_TDES_CFB1:
    case ACVP_TDES_CFB8:
    case ACVP_TDES_CFB64:
    case ACVP_TDES_CFBP1:
    case ACVP_TDES_CFBP8:
    case ACVP_TDES_CFBP64:
    case ACVP_TDES_CTR:
    case ACVP_TDES_KW:
        break;
    case ACVP_CIPHER_START:
    case ACVP_HASH_SHA1:
    case ACVP_HASH_SHA224:
    case ACVP_HASH_SHA256:
    case ACVP_HASH_SHA384:
    case ACVP_HASH_SHA512:
    case ACVP_HASH_SHA512_224:
    case ACVP_HASH_SHA512_256:
    case ACVP_HASH_SHA3_224:
    case ACVP_HASH_SHA3_256:
    case ACVP_HASH_SHA3_384:
    case ACVP_HASH_SHA3_512:
    case ACVP_HASH_SHAKE_128:
    case ACVP_HASH_SHAKE_256:
    case ACVP_HASHDRBG:
    case ACVP_HMACDRBG:
    case ACVP_CTRDRBG:
    case ACVP_HMAC_SHA1:
    case ACVP_HMAC_SHA2_224:
    case ACVP_HMAC_SHA2_256:
    case ACVP_HMAC_SHA2_384:
    case ACVP_HMAC_SHA2_512:
    case ACVP_HMAC_SHA2_512_224:
    case ACVP_HMAC_SHA2_512_256:
    case ACVP_HMAC_SHA3_224:
    case ACVP_HMAC_SHA3_256:
    case ACVP_HMAC_SHA3_384:
    case ACVP_HMAC_SHA3_512:
    case ACVP_CMAC_AES:
    case ACVP_CMAC_TDES:
    case ACVP_KMAC_128:
    case ACVP_KMAC_256:
    case ACVP_DSA_KEYGEN:
    case ACVP_DSA_PQGGEN:
    case ACVP_DSA_PQGVER:
    case ACVP_DSA_SIGGEN:
    case ACVP_DSA_SIGVER:
    case ACVP_RSA_KEYGEN:
    case ACVP_RSA_SIGGEN:
    case ACVP_RSA_SIGVER:
    case ACVP_RSA_SIGPRIM:
    case ACVP_RSA_DECPRIM:
    case ACVP_ECDSA_KEYGEN:
    case ACVP_ECDSA_KEYVER:
    case ACVP_ECDSA_SIGGEN:
    case ACVP_ECDSA_SIGVER:
    case ACVP_KDF135_SNMP:
    case ACVP_KDF135_SSH:
    case ACVP_KDF135_SRTP:
    case ACVP_KDF135_IKEV2:
    case ACVP_KDF135_IKEV1:
    case ACVP_KDF135_X942:
    case ACVP_KDF135_X963:
    case ACVP_KDF108:
    case ACVP_PBKDF:
    case ACVP_KDF_TLS12:
    case ACVP_KDF_TLS13:
    case ACVP_KAS_ECC_CDH:
    case ACVP_KAS_ECC_COMP:
    case ACVP_KAS_ECC_NOCOMP:
    case ACVP_KAS_ECC_SSC:
    case ACVP_KAS_FFC_COMP:
    case ACVP_KAS_FFC_NOCOMP:
    case ACVP_KDA_ONESTEP:
    case ACVP_KDA_TWOSTEP:
    case ACVP_KDA_HKDF:
    case ACVP_KAS_FFC_SSC:
    case ACVP_KAS_IFC_SSC:
    case ACVP_KTS_IFC:
    case ACVP_SAFE_PRIMES_KEYGEN:
    case ACVP_SAFE_PRIMES_KEYVER:
    case ACVP_LMS_SIGGEN:
    case ACVP_LMS_SIGVER:
    case ACVP_LMS_KEYGEN:
    case ACVP_CIPHER_END:
    default:
        return ACVP_INVALID_ARG;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        ACVP_LOG_ERR("Cap entry not found, use acvp_cap_sym_cipher_enable() first.");
        return ACVP_NO_CAP;
    }

    /*
     * Check is this is a non-length related value.
     */
    switch (parm) {
    case ACVP_SYM_CIPH_KW_MODE:
        if (value < ACVP_SYM_KW_MAX) {
            cap->cap.sym_cap->kw_mode |= value;
            return ACVP_SUCCESS;
        } else {
            ACVP_LOG_ERR("Invalid parameter 'value' for param ACVP_SYM_CIPH_KW_MODE");
            return ACVP_INVALID_ARG;
        }

    case ACVP_SYM_CIPH_PARM_DIR:
        if (value > 0 && value < ACVP_SYM_CIPH_DIR_MAX) {
            cap->cap.sym_cap->direction = value;
            return ACVP_SUCCESS;
        } else {
            ACVP_LOG_ERR("Invalid parameter 'value' for param ACVP_SYM_CIPH_PARM_DIR");
            return ACVP_INVALID_ARG;
        }

    case ACVP_SYM_CIPH_PARM_KO:
        if (value >= ACVP_SYM_CIPH_KO_NA && value < ACVP_SYM_CIPH_KO_MAX) {
            cap->cap.sym_cap->keying_option = value;
            return ACVP_SUCCESS;
        } else {
            ACVP_LOG_ERR("Invalid parameter 'value' for param ACVP_SYM_CIPH_PARM_KO");
            return ACVP_INVALID_ARG;
        }

    case ACVP_SYM_CIPH_PARM_PERFORM_CTR:
        if (value == 0 || value == 1) {
            if (value == 0 && (cap->cap.sym_cap->ctr_incr || cap->cap.sym_cap->ctr_ovrflw)) {
                ACVP_LOG_WARN("Perform counter test set to false, but value for ctr increment or ctr overflow already set. Server will ignore other values. Continuing...");
            }
            cap->cap.sym_cap->perform_ctr_tests = value;
            return ACVP_SUCCESS;
        } else {
            ACVP_LOG_ERR("Invalid parameter 'value' for param ACVP_SYM_CIPH_PARM_PERFORM_CTR");
            return ACVP_INVALID_ARG;
        }

    case ACVP_SYM_CIPH_PARM_CTR_INCR:
        if (cap->cap.sym_cap->perform_ctr_tests == 0) {
            ACVP_LOG_WARN("Perform counter test set to false, but value for ctr increment being set; server will ignore this. Continuing...");
        }
        if (value == 0 || value == 1) {
            cap->cap.sym_cap->ctr_incr = value;
            return ACVP_SUCCESS;
        } else {
            ACVP_LOG_ERR("Invalid parameter 'value' for param ACVP_SYM_CIPH_PARM_CTR_INCR");
            return ACVP_INVALID_ARG;
        }

    case ACVP_SYM_CIPH_PARM_CTR_OVRFLW:
        if (cap->cap.sym_cap->perform_ctr_tests == 0) {
            ACVP_LOG_WARN("Perform counter test set to false, but value for ctr overflow being set; server will ignore this. Continuing...");
        }
        if (value == 0 || value == 1) {
            cap->cap.sym_cap->ctr_ovrflw = value;
            return ACVP_SUCCESS;
        } else {
            ACVP_LOG_ERR("Invalid parameter 'value' for param ACVP_SYM_CIPH_PARM_CTR_OVRFLW");
            return ACVP_INVALID_ARG;
        }

    case ACVP_SYM_CIPH_PARM_IVGEN_SRC:
        if (value > 0 && value < ACVP_SYM_CIPH_IVGEN_SRC_MAX) {
            if (value == ACVP_SYM_CIPH_IVGEN_SRC_EITHER) {
                /* This will generate two vector sets, one for internal ivgen and one for external */
                ctx->vs_count++;
            }
            cap->cap.sym_cap->ivgen_source = value;
            return ACVP_SUCCESS;
        } else {
            ACVP_LOG_ERR("Invalid parameter 'value' for param ACVP_SYM_CIPH_PARM_IVGEN_SRC");
            return ACVP_INVALID_ARG;
        }

    case ACVP_SYM_CIPH_PARM_IVGEN_MODE:
        if (value > 0 && value < ACVP_SYM_CIPH_IVGEN_MODE_MAX) {
            cap->cap.sym_cap->ivgen_mode = value;
            return ACVP_SUCCESS;
        } else {
            ACVP_LOG_ERR("Invalid parameter 'value' for param ACVP_SYM_CIPH_PARM_IVGEN_MODE");
            return ACVP_INVALID_ARG;
        }
    case ACVP_SYM_CIPH_PARM_SALT_SRC:
        if  (cipher == ACVP_AES_XPN && value > 0 && value < ACVP_SYM_CIPH_SALT_SRC_MAX) {
            cap->cap.sym_cap->salt_source = value;
            return ACVP_SUCCESS;
        } else {
            ACVP_LOG_ERR("Invalid parameter 'value' for parm ACVP_SYM_CIPH_PARM_SALT_SRC");
            return ACVP_INVALID_ARG;
        }
    case ACVP_SYM_CIPH_PARM_CONFORMANCE:
        if (cipher == ACVP_AES_CTR && value == ACVP_CONFORMANCE_RFC3686) {
            cap->cap.sym_cap->conformance = ACVP_CONFORMANCE_RFC3686;
            return ACVP_SUCCESS;
        } else {
            ACVP_LOG_ERR("Invalid parameter 'value' for parm ACVP_SYM_CIPH_PARM_CONFORMANCE");
            return ACVP_INVALID_ARG;
        }
    case ACVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN:
        if (cipher != ACVP_AES_XTS) {
            ACVP_LOG_ERR("ACVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN can only be set for AES-XTS");
            return ACVP_INVALID_ARG;
        }
        if ((cap->cap.sym_cap->du_len.max != 0 || cap->cap.sym_cap->du_len.increment != 0)) {
            ACVP_LOG_ERR("ACVP_SYM_CIPH_DULEN_MATCHES_PAYLOADLEN cannot be changed after setting "
                         "ACVP_SYM_CIPH_DOMAIN_DULEN");
            return ACVP_INVALID_ARG;
        } else if (value == 0 || value == 1) {
            cap->cap.sym_cap->dulen_matches_paylen = value;
            return ACVP_SUCCESS;
        } else {
            ACVP_LOG_ERR("Invalid parameter 'value' for parm ACVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN");
            return ACVP_INVALID_ARG;
        }
    case ACVP_SYM_CIPH_KEYLEN:
    case ACVP_SYM_CIPH_TAGLEN:
    case ACVP_SYM_CIPH_IVLEN:
    case ACVP_SYM_CIPH_PTLEN:
    case ACVP_SYM_CIPH_TWEAK:
    case ACVP_SYM_CIPH_AADLEN:
    default:
        break;
    }

    if (acvp_validate_sym_cipher_parm_value(cipher, parm, value) != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to validate given parameter (cipher=%d, value=%d)", cipher, value);
        return ACVP_INVALID_ARG;
    }

    switch (parm) {
    case ACVP_SYM_CIPH_KEYLEN:
        acvp_append_sl_list(&cap->cap.sym_cap->keylen, value);
        break;
    case ACVP_SYM_CIPH_TAGLEN:
        acvp_append_sl_list(&cap->cap.sym_cap->taglen, value);
        break;
    case ACVP_SYM_CIPH_IVLEN:
        if (acvp_is_domain_already_set(&cap->cap.sym_cap->iv_len)) {
            ACVP_LOG_ERR("ivLen already defined using acvp_sym_cipher_set_domain. Please set ivLen using only one function "
                        "(Using set_parm for ivLen will eventually be depreciated).");
            return ACVP_INVALID_ARG;
        }
        acvp_append_sl_list(&cap->cap.sym_cap->ivlen, value);
        break;
    case ACVP_SYM_CIPH_PTLEN:
        if (acvp_is_domain_already_set(&cap->cap.sym_cap->payload_len)) {
            ACVP_LOG_ERR("payloadLen already defined using acvp_sym_cipher_set_domain. Please set payloadLen using only one function "
                         "(Using set_parm for payloadLen will eventually be depreciated).");
            return ACVP_INVALID_ARG;
        }
        acvp_append_sl_list(&cap->cap.sym_cap->ptlen, value);
        break;
    case ACVP_SYM_CIPH_TWEAK:
        acvp_append_sl_list(&cap->cap.sym_cap->tweak, value);
        break;
    case ACVP_SYM_CIPH_AADLEN:
        if (acvp_is_domain_already_set(&cap->cap.sym_cap->aad_len)) {
            ACVP_LOG_ERR("aadLen already defined using acvp_sym_cipher_set_domain. Please set aadLen using only one function "
                         "(Using set_parm for aadLen will eventually be depreciated).");
            return ACVP_INVALID_ARG;
        }
        acvp_append_sl_list(&cap->cap.sym_cap->aadlen, value);
        break;
    case ACVP_SYM_CIPH_KW_MODE:
    case ACVP_SYM_CIPH_PARM_DIR:
    case ACVP_SYM_CIPH_PARM_KO:
    case ACVP_SYM_CIPH_PARM_PERFORM_CTR:
    case ACVP_SYM_CIPH_PARM_CTR_INCR:
    case ACVP_SYM_CIPH_PARM_CTR_OVRFLW:
    case ACVP_SYM_CIPH_PARM_IVGEN_MODE:
    case ACVP_SYM_CIPH_PARM_IVGEN_SRC:
    case ACVP_SYM_CIPH_PARM_CONFORMANCE:
    case ACVP_SYM_CIPH_PARM_SALT_SRC:
    case ACVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN:
    default:
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}

/*
 * This function is called by the application to register a crypto
 * capability for symmetric ciphers, along with a handler that the
 * application implements when that particular crypto operation is
 * needed by libacvp.
 *
 * This function should be called one or more times for each crypto
 * capability supported by the crypto module being validated.  This
 * needs to be called after acvp_create_test_session() and prior to
 * calling acvp_register().
 *
 */
ACVP_RESULT acvp_cap_sym_cipher_enable(ACVP_CTX *ctx,
                                       ACVP_CIPHER cipher,
                                       int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    switch (cipher) {
    case ACVP_AES_GCM:
    case ACVP_AES_GCM_SIV:
    case ACVP_AES_CCM:
    case ACVP_AES_ECB:
    case ACVP_AES_CBC:
    case ACVP_AES_CBC_CS1:
    case ACVP_AES_CBC_CS2:
    case ACVP_AES_CBC_CS3:
    case ACVP_AES_CFB1:
    case ACVP_AES_CFB8:
    case ACVP_AES_CFB128:
    case ACVP_AES_OFB:
    case ACVP_AES_CTR:
    case ACVP_AES_XTS:
    case ACVP_AES_KW:
    case ACVP_AES_KWP:
    case ACVP_AES_GMAC:
    case ACVP_AES_XPN:
    case ACVP_TDES_ECB:
    case ACVP_TDES_CBC:
    case ACVP_TDES_CBCI:
    case ACVP_TDES_OFB:
    case ACVP_TDES_OFBI:
    case ACVP_TDES_CFB1:
    case ACVP_TDES_CFB8:
    case ACVP_TDES_CFB64:
    case ACVP_TDES_CFBP1:
    case ACVP_TDES_CFBP8:
    case ACVP_TDES_CFBP64:
    case ACVP_TDES_CTR:
    case ACVP_TDES_KW:
        break;
    case ACVP_CIPHER_START:
    case ACVP_HASH_SHA1:
    case ACVP_HASH_SHA224:
    case ACVP_HASH_SHA256:
    case ACVP_HASH_SHA384:
    case ACVP_HASH_SHA512:
    case ACVP_HASH_SHA512_224:
    case ACVP_HASH_SHA512_256:
    case ACVP_HASH_SHA3_224:
    case ACVP_HASH_SHA3_256:
    case ACVP_HASH_SHA3_384:
    case ACVP_HASH_SHA3_512:
    case ACVP_HASH_SHAKE_128:
    case ACVP_HASH_SHAKE_256:
    case ACVP_HASHDRBG:
    case ACVP_HMACDRBG:
    case ACVP_CTRDRBG:
    case ACVP_HMAC_SHA1:
    case ACVP_HMAC_SHA2_224:
    case ACVP_HMAC_SHA2_256:
    case ACVP_HMAC_SHA2_384:
    case ACVP_HMAC_SHA2_512:
    case ACVP_HMAC_SHA2_512_224:
    case ACVP_HMAC_SHA2_512_256:
    case ACVP_HMAC_SHA3_224:
    case ACVP_HMAC_SHA3_256:
    case ACVP_HMAC_SHA3_384:
    case ACVP_HMAC_SHA3_512:
    case ACVP_CMAC_AES:
    case ACVP_CMAC_TDES:
    case ACVP_KMAC_128:
    case ACVP_KMAC_256:
    case ACVP_DSA_KEYGEN:
    case ACVP_DSA_PQGGEN:
    case ACVP_DSA_PQGVER:
    case ACVP_DSA_SIGGEN:
    case ACVP_DSA_SIGVER:
    case ACVP_RSA_KEYGEN:
    case ACVP_RSA_SIGGEN:
    case ACVP_RSA_SIGVER:
    case ACVP_RSA_SIGPRIM:
    case ACVP_RSA_DECPRIM:
    case ACVP_ECDSA_KEYGEN:
    case ACVP_ECDSA_KEYVER:
    case ACVP_ECDSA_SIGGEN:
    case ACVP_ECDSA_SIGVER:
    case ACVP_KDF135_SNMP:
    case ACVP_KDF135_SSH:
    case ACVP_KDF135_SRTP:
    case ACVP_KDF135_IKEV2:
    case ACVP_KDF135_IKEV1:
    case ACVP_KDF135_X942:
    case ACVP_KDF135_X963:
    case ACVP_KDF108:
    case ACVP_PBKDF:
    case ACVP_KDF_TLS12:
    case ACVP_KDF_TLS13:
    case ACVP_KAS_ECC_CDH:
    case ACVP_KAS_ECC_COMP:
    case ACVP_KAS_ECC_NOCOMP:
    case ACVP_KAS_ECC_SSC:
    case ACVP_KAS_FFC_COMP:
    case ACVP_KAS_FFC_NOCOMP:
    case ACVP_KDA_ONESTEP:
    case ACVP_KDA_TWOSTEP:
    case ACVP_KDA_HKDF:
    case ACVP_KAS_FFC_SSC:
    case ACVP_KAS_IFC_SSC:
    case ACVP_KTS_IFC:
    case ACVP_SAFE_PRIMES_KEYGEN:
    case ACVP_SAFE_PRIMES_KEYVER:
    case ACVP_LMS_SIGGEN:
    case ACVP_LMS_SIGVER:
    case ACVP_LMS_KEYGEN:
    case ACVP_CIPHER_END:
    default:
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_SYM_TYPE, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_hash_enable(ACVP_CTX *ctx,
                                 ACVP_CIPHER cipher,
                                 int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_SUB_HASH alg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    alg = acvp_get_hash_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }

    switch (alg) {
    case ACVP_SUB_HASH_SHA1:
    case ACVP_SUB_HASH_SHA2_224:
    case ACVP_SUB_HASH_SHA2_256:
    case ACVP_SUB_HASH_SHA2_384:
    case ACVP_SUB_HASH_SHA2_512:
    case ACVP_SUB_HASH_SHA2_512_224:
    case ACVP_SUB_HASH_SHA2_512_256:
    case ACVP_SUB_HASH_SHA3_224:
    case ACVP_SUB_HASH_SHA3_256:
    case ACVP_SUB_HASH_SHA3_384:
    case ACVP_SUB_HASH_SHA3_512:
    case ACVP_SUB_HASH_SHAKE_128:
    case ACVP_SUB_HASH_SHAKE_256:
        break;
    default:
        ACVP_LOG_ERR("Invalid parameter 'cipher'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_HASH_TYPE, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

static ACVP_RESULT acvp_validate_hash_parm_value(ACVP_HASH_PARM parm, int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;

    switch (parm) {
    case ACVP_HASH_IN_BIT:
    case ACVP_HASH_IN_EMPTY:
    case ACVP_HASH_OUT_BIT:
        retval = is_valid_tf_param(value);
        break;
    case ACVP_HASH_OUT_LENGTH:
    case ACVP_HASH_MESSAGE_LEN:
    default:
        break;
    }

    return retval;
}

ACVP_RESULT acvp_cap_hash_set_parm(ACVP_CTX *ctx,
                                   ACVP_CIPHER cipher,
                                   ACVP_HASH_PARM param,
                                   int value) {
    ACVP_CAPS_LIST *cap;
    ACVP_HASH_CAP *hash_cap;
    ACVP_SUB_HASH alg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    alg = acvp_get_hash_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }

    switch (alg) {
    case ACVP_SUB_HASH_SHA3_224:
    case ACVP_SUB_HASH_SHA3_256:
    case ACVP_SUB_HASH_SHA3_384:
    case ACVP_SUB_HASH_SHA3_512:
    case ACVP_SUB_HASH_SHAKE_128:
    case ACVP_SUB_HASH_SHAKE_256:
        break;
    case ACVP_SUB_HASH_SHA1:
    case ACVP_SUB_HASH_SHA2_224:
    case ACVP_SUB_HASH_SHA2_256:
    case ACVP_SUB_HASH_SHA2_384:
    case ACVP_SUB_HASH_SHA2_512:
    case ACVP_SUB_HASH_SHA2_512_224:
    case ACVP_SUB_HASH_SHA2_512_256:
    default:
        return ACVP_INVALID_ARG;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    hash_cap = cap->cap.hash_cap;
    if (!hash_cap) {
        return ACVP_NO_CAP;
    }

    if (acvp_validate_hash_parm_value(param, value) != ACVP_SUCCESS) {
        return ACVP_INVALID_ARG;
    }

    switch (param) {
    case ACVP_HASH_IN_BIT:
        hash_cap->in_bit = value;
        break;
    case ACVP_HASH_IN_EMPTY:
        hash_cap->in_empty = value;
        break;
    case ACVP_HASH_OUT_BIT:
        switch (alg) {
        case ACVP_SUB_HASH_SHAKE_128:
        case ACVP_SUB_HASH_SHAKE_256:
            break;
        case ACVP_SUB_HASH_SHA3_224:
        case ACVP_SUB_HASH_SHA3_256:
        case ACVP_SUB_HASH_SHA3_384:
        case ACVP_SUB_HASH_SHA3_512:
        case ACVP_SUB_HASH_SHA1:
        case ACVP_SUB_HASH_SHA2_224:
        case ACVP_SUB_HASH_SHA2_256:
        case ACVP_SUB_HASH_SHA2_384:
        case ACVP_SUB_HASH_SHA2_512:
        case ACVP_SUB_HASH_SHA2_512_224:
        case ACVP_SUB_HASH_SHA2_512_256:
        default:
            ACVP_LOG_ERR("parm 'ACVP_HASH_OUT_BIT' only allowed for ACVP_HASH_SHAKE_* ");
            return ACVP_INVALID_ARG;
        }

        hash_cap->out_bit = value;
        break;
    case ACVP_HASH_OUT_LENGTH:
    case ACVP_HASH_MESSAGE_LEN:
    default:
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}

/*
 * Add HASH(SHA) parameters
 */
ACVP_RESULT acvp_cap_hash_set_domain(ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     ACVP_HASH_PARM parm,
                                     int min,
                                     int max,
                                     int increment) {
    ACVP_CAPS_LIST *cap;
    ACVP_HASH_CAP *hash_cap;
    ACVP_JSON_DOMAIN_OBJ *domain;
    ACVP_SUB_HASH alg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    alg = acvp_get_hash_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }

    switch (alg) {
    case ACVP_SUB_HASH_SHA3_224:
    case ACVP_SUB_HASH_SHA3_256:
    case ACVP_SUB_HASH_SHA3_384:
    case ACVP_SUB_HASH_SHA3_512:
    case ACVP_SUB_HASH_SHAKE_128:
    case ACVP_SUB_HASH_SHAKE_256:
    case ACVP_SUB_HASH_SHA1:
    case ACVP_SUB_HASH_SHA2_224:
    case ACVP_SUB_HASH_SHA2_256:
    case ACVP_SUB_HASH_SHA2_384:
    case ACVP_SUB_HASH_SHA2_512:
    case ACVP_SUB_HASH_SHA2_512_224:
    case ACVP_SUB_HASH_SHA2_512_256:
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    hash_cap = cap->cap.hash_cap;
    if (!hash_cap) {
        return ACVP_NO_CAP;
    }

    switch (parm) {
    case ACVP_HASH_MESSAGE_LEN:
        if (cipher == ACVP_HASH_SHAKE_128 || cipher == ACVP_HASH_SHAKE_256) {
            ACVP_LOG_ERR("ACVP_HASH_MSG_LEN cannot be set for SHAKE ciphers");
            return ACVP_INVALID_ARG;
        }
        if (min < ACVP_HASH_MSG_BIT_MIN ||  max > ACVP_HASH_MSG_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &hash_cap->msg_length;
        break;
    case ACVP_HASH_OUT_LENGTH:
        if (cipher != ACVP_HASH_SHAKE_128 && cipher != ACVP_HASH_SHAKE_256) {
            ACVP_LOG_ERR("Only SHAKE_128 or SHAKE_256 allowed for ACVP_HASH_OUT_LENGTH");
            return ACVP_INVALID_ARG;
        }
        if (min < ACVP_HASH_XOF_MD_BIT_MIN ||  max > ACVP_HASH_XOF_MD_BIT_MAX) {
            ACVP_LOG_ERR("'ACVP_HASH_OUT_LENGTH' min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        if (increment + min > ACVP_HASH_XOF_MD_BIT_MAX) {
            ACVP_LOG_ERR("'ACVP_HASH_OUT_LENGTH' increment(%d) + min(%d) > max(%d)",
                         increment, min, ACVP_HASH_XOF_MD_BIT_MAX);
            return ACVP_INVALID_ARG;
        }
        domain = &hash_cap->out_len;
        break;
    case ACVP_HASH_IN_BIT:
    case ACVP_HASH_IN_EMPTY:
    case ACVP_HASH_OUT_BIT:
    default:
        ACVP_LOG_ERR("Invalid 'parm'");
        return ACVP_INVALID_ARG;
    }
    
    if (increment <= 0) {
        ACVP_LOG_ERR("Invalid increment (%d) for hash set domain", increment);
        return ACVP_INVALID_ARG;
    }

    if (min % increment != 0) {
        ACVP_LOG_ERR("min(%d) MODULO increment(%d) must equal 0", min, increment);
        return ACVP_INVALID_ARG;
    }
    if (max % increment != 0) {
        ACVP_LOG_ERR("max(%d) MODULO increment(%d) must equal 0", max, increment);
        return ACVP_INVALID_ARG;
    }

    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_validate_hmac_parm_value(ACVP_CIPHER cipher,
                                                 ACVP_HMAC_PARM parm,
                                                 int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;
    int max_val = 0;
    ACVP_SUB_HMAC alg;

    switch (parm) {
    case ACVP_HMAC_KEYLEN:
        if (value >= ACVP_HMAC_KEY_BIT_MIN &&
            value <= ACVP_HMAC_KEY_BIT_MAX &&
            value % 8 == 0) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_HMAC_MACLEN:
        alg = acvp_get_hmac_alg(cipher);
        if (alg == 0) {
            return ACVP_INVALID_ARG;
        }

        switch (alg) {
        case ACVP_SUB_HMAC_SHA1:
            max_val = 160;
            break;
        case ACVP_SUB_HMAC_SHA2_224:
        case ACVP_SUB_HMAC_SHA2_512_224:
        case ACVP_SUB_HMAC_SHA3_224:
            max_val = 224;
            break;
        case ACVP_SUB_HMAC_SHA2_256:
        case ACVP_SUB_HMAC_SHA2_512_256:
        case ACVP_SUB_HMAC_SHA3_256:
            max_val = 256;
            break;
        case ACVP_SUB_HMAC_SHA2_384:
        case ACVP_SUB_HMAC_SHA3_384:
            max_val = 384;
            break;
        case ACVP_SUB_HMAC_SHA2_512:
        case ACVP_SUB_HMAC_SHA3_512:
            max_val = 512;
            break;
        default:
            break;
        }
        if (value >= ACVP_HMAC_MAC_BIT_MIN &&
            value <= max_val &&
            value % 8 == 0) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_HMAC_KEYBLOCK:
    default:
        break;
    }

    return retval;
}

ACVP_RESULT acvp_cap_hmac_enable(ACVP_CTX *ctx,
                                 ACVP_CIPHER cipher,
                                 int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_SUB_HMAC alg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    alg = acvp_get_hmac_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_HMAC_SHA1:
    case ACVP_SUB_HMAC_SHA2_224:
    case ACVP_SUB_HMAC_SHA2_256:
    case ACVP_SUB_HMAC_SHA2_384:
    case ACVP_SUB_HMAC_SHA2_512:
    case ACVP_SUB_HMAC_SHA2_512_224:
    case ACVP_SUB_HMAC_SHA2_512_256:
    case ACVP_SUB_HMAC_SHA3_224:
    case ACVP_SUB_HMAC_SHA3_256:
    case ACVP_SUB_HMAC_SHA3_384:
    case ACVP_SUB_HMAC_SHA3_512:
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_HMAC_TYPE, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_hmac_set_domain(ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     ACVP_HMAC_PARM parm,
                                     int min,
                                     int max,
                                     int increment) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_JSON_DOMAIN_OBJ *domain;
    ACVP_HMAC_CAP *current_hmac_cap;

    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    current_hmac_cap = cap_list->cap.hmac_cap;

    switch (parm) {
    case ACVP_HMAC_KEYLEN:
        if (min < ACVP_HMAC_KEY_BIT_MIN ||
            max > ACVP_HMAC_KEY_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &current_hmac_cap->key_len;
        break;
    case ACVP_HMAC_MACLEN:
        if (min < ACVP_HMAC_MAC_BIT_MIN ||
            max > ACVP_HMAC_MAC_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &current_hmac_cap->mac_len;
        break;
    case ACVP_HMAC_KEYBLOCK:
    default:
        return ACVP_INVALID_ARG;
    }

    if (increment % 8 != 0) {
        ACVP_LOG_ERR("increment must be mod 8");
        return ACVP_INVALID_ARG;
    }

    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_hmac_cap()
 * to specify the supported key ranges, keyblock value, and
 * suuported mac lengths. This is called by the user multiple times,
 * once for each length supported.
 */
ACVP_RESULT acvp_cap_hmac_set_parm(ACVP_CTX *ctx,
                                   ACVP_CIPHER cipher,
                                   ACVP_HMAC_PARM parm,
                                   int value) {
    ACVP_CAPS_LIST *cap;

    /*
     * Locate this cipher in the caps array
     */
    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        ACVP_LOG_ERR("Cap entry not found, use acvp_enable_hmac_cipher_cap() first.");
        return ACVP_NO_CAP;
    }

    if (acvp_validate_hmac_parm_value(cipher, parm, value) != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Invalid parm or value");
        return ACVP_INVALID_ARG;
    }

    switch (parm) {
    case ACVP_HMAC_KEYLEN:
        if (acvp_append_sl_list(&cap->cap.hmac_cap->key_len.values, value) != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Error adding HMAC key length to list");
            return ACVP_MALLOC_FAIL;
        }
        break;
    case ACVP_HMAC_MACLEN:
        if (acvp_append_sl_list(&cap->cap.hmac_cap->mac_len.values, value) != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Error adding HMAC mac length to list");
            return ACVP_MALLOC_FAIL;
        }
        break;
    case ACVP_HMAC_KEYBLOCK:
    default:
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_validate_cmac_parm_value(ACVP_CMAC_PARM parm, int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;

    switch (parm) {
    case ACVP_CMAC_MACLEN:
        if (value >= ACVP_CMAC_MACLEN_MIN &&
            value <= ACVP_CMAC_MACLEN_MAX &&
            value % 8 == 0) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_CMAC_MSGLEN:
        if (value >= ACVP_CMAC_MSGLEN_MIN &&
            value <= ACVP_CMAC_MSGLEN_MAX &&
            value % 8 == 0) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_CMAC_KEYLEN:
        if (value == ACVP_CMAC_KEYLEN_128 ||
            value == ACVP_CMAC_KEYLEN_192 ||
            value == ACVP_CMAC_KEYLEN_256) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_CMAC_KEYING_OPTION:
        if (value == ACVP_CMAC_KEYING_OPTION_1 || value == ACVP_CMAC_KEYING_OPTION_2) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_CMAC_DIRECTION_GEN:
    case ACVP_CMAC_DIRECTION_VER:
        return is_valid_tf_param(value);

    default:
        break;
    }

    return retval;
}

ACVP_RESULT acvp_cap_cmac_enable(ACVP_CTX *ctx,
                                 ACVP_CIPHER cipher,
                                 int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_SUB_CMAC alg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    alg = acvp_get_cmac_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_CMAC_AES:
    case ACVP_SUB_CMAC_TDES:
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_CMAC_TYPE, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_cmac_set_domain(ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     ACVP_CMAC_PARM parm,
                                     int min,
                                     int max,
                                     int increment) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_JSON_DOMAIN_OBJ *domain;
    ACVP_CMAC_CAP *current_cmac_cap;

    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    current_cmac_cap = cap_list->cap.cmac_cap;

    switch (parm) {
    case ACVP_CMAC_MSGLEN:
        if (min < ACVP_CMAC_MSGLEN_MIN ||
            max > ACVP_CMAC_MSGLEN_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &current_cmac_cap->msg_len;
        break;
    case ACVP_CMAC_MACLEN:
        if (min < ACVP_CMAC_MACLEN_MIN ||
            max > ACVP_CMAC_MACLEN_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &current_cmac_cap->mac_len;
        break;
    case ACVP_CMAC_KEYLEN:
    case ACVP_CMAC_KEYING_OPTION:
    case ACVP_CMAC_DIRECTION_GEN:
    case ACVP_CMAC_DIRECTION_VER:
    default:
        return ACVP_INVALID_ARG;
    }
    if (increment % 8 != 0) {
        ACVP_LOG_ERR("increment must be mod 8");
        return ACVP_INVALID_ARG;
    }

    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_cmac_cap()
 * to specify the supported msg lengths and mac lengths.
 * This is called by the user multiple times,
 * once for each length supported.
 */
ACVP_RESULT acvp_cap_cmac_set_parm(ACVP_CTX *ctx,
                                   ACVP_CIPHER cipher,
                                   ACVP_CMAC_PARM parm,
                                   int value) {
    ACVP_CAPS_LIST *cap;
    ACVP_CMAC_CAP *current_cmac_cap;

    /*
     * Locate this cipher in the caps array
     */
    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        ACVP_LOG_ERR("Cap entry not found, use acvp_enable_cmac_cipher_cap() first.");
        return ACVP_NO_CAP;
    }
    current_cmac_cap = cap->cap.cmac_cap;
    if (acvp_validate_cmac_parm_value(parm, value) != ACVP_SUCCESS) {
        return ACVP_INVALID_ARG;
    }

    switch (parm) {
    case ACVP_CMAC_MSGLEN:
        if (acvp_append_sl_list(&current_cmac_cap->msg_len.values, value) != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Error adding CMAC msg len to list");
            return ACVP_MALLOC_FAIL;
        }
        break;
    case ACVP_CMAC_MACLEN:
        if (acvp_append_sl_list(&current_cmac_cap->mac_len.values, value) != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Error adding CMAC mac len to list");
            return ACVP_MALLOC_FAIL;
        }
        break;
    case ACVP_CMAC_DIRECTION_GEN:
        cap->cap.cmac_cap->direction_gen = value;
        break;
    case ACVP_CMAC_DIRECTION_VER:
        cap->cap.cmac_cap->direction_ver = value;
        break;
    case ACVP_CMAC_KEYLEN:
        acvp_append_sl_list(&cap->cap.cmac_cap->key_len, value);
        break;
    case ACVP_CMAC_KEYING_OPTION:
        if (cipher == ACVP_CMAC_TDES) {
            acvp_append_sl_list(&cap->cap.cmac_cap->keying_option, value);
            break;
        }
        return ACVP_INVALID_ARG;
    default:
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_kmac_enable(ACVP_CTX *ctx,
                                 ACVP_CIPHER cipher,
                                 int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_SUB_KMAC alg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    alg = acvp_get_kmac_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_KMAC_128:
    case ACVP_SUB_KMAC_256:
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_KMAC_TYPE, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_kmac_set_parm(ACVP_CTX *ctx,
                                   ACVP_CIPHER cipher,
                                   ACVP_KMAC_PARM parm,
                                   int value) {
    ACVP_CAPS_LIST *cap;
    ACVP_KMAC_CAP *kmac_cap;

    /*
     * Locate this cipher in the caps array
     */
    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        ACVP_LOG_ERR("Cap entry not found, use acvp_enable_kmac_cipher_cap() first.");
        return ACVP_NO_CAP;
    }
    kmac_cap = cap->cap.kmac_cap;

    switch (parm) {
    case ACVP_KMAC_XOF_SUPPORT:
        switch (value) {
        case ACVP_XOF_SUPPORT_FALSE:
        case ACVP_XOF_SUPPORT_TRUE:
        case ACVP_XOF_SUPPORT_BOTH:
            kmac_cap->xof = value;
            break;
        default:
            ACVP_LOG_ERR("Invalid value for KMAC XOF support");
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_KMAC_HEX_CUSTOM_SUPPORT:
        if (is_valid_tf_param(value) == ACVP_SUCCESS) {
            kmac_cap->hex_customization = value;
        } else {
            ACVP_LOG_ERR("Invalid boolean for KMAC hex customization support");
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_KMAC_MACLEN:
    case ACVP_KMAC_MSGLEN:
    case ACVP_KMAC_KEYLEN:
    default:
        ACVP_LOG_ERR("Invalid KMAC parameter given");
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;

}

ACVP_RESULT acvp_cap_kmac_set_domain(ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     ACVP_KMAC_PARM parm,
                                     int min,
                                     int max,
                                     int increment) {
    ACVP_CAPS_LIST *cap;
    ACVP_KMAC_CAP *kmac_cap;

    /*
     * Locate this cipher in the caps array
     */
    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        ACVP_LOG_ERR("Cap entry not found, use acvp_enable_kmac_cipher_cap() first.");
        return ACVP_NO_CAP;
    }
    kmac_cap = cap->cap.kmac_cap;

    if (validate_domain_range(min, max, increment) != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Invalid domain given for KMAC");
        return ACVP_INVALID_ARG;
    }

    switch (parm) {
    case ACVP_KMAC_MACLEN:
        if (max > 65536 || min < 32 || increment != 8) {
            ACVP_LOG_ERR("Out of bounds maclen given for KMAC");
            return ACVP_INVALID_ARG;
        }
        kmac_cap->mac_len.min = min;
        kmac_cap->mac_len.max = max;
        kmac_cap->mac_len.increment = increment;
        break;
    case ACVP_KMAC_MSGLEN:
        if (max > 65536) {
            ACVP_LOG_ERR("Out of bounds msglen given for KMAC");
            return ACVP_INVALID_ARG;
        }
        kmac_cap->msg_len.min = min;
        kmac_cap->msg_len.max = max;
        kmac_cap->msg_len.increment = increment;
        break;
    case ACVP_KMAC_KEYLEN:
        if (max > 524288 || min < 128 || increment != 8) {
            ACVP_LOG_ERR("Out of bounds keylen given for KMAC");
            return ACVP_INVALID_ARG;
        }
        kmac_cap->key_len.min = min;
        kmac_cap->key_len.max = max;
        kmac_cap->key_len.increment = increment;
        break;
    case ACVP_KMAC_XOF_SUPPORT:
    case ACVP_KMAC_HEX_CUSTOM_SUPPORT:
    default:
        ACVP_LOG_ERR("Invalid KMAC parameter given");
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;

}

/*
 * Add DRBG Length Range
 */
static ACVP_RESULT acvp_add_drbg_length_range(ACVP_DRBG_CAP_GROUP *cap_group,
                                              ACVP_DRBG_PARM param,
                                              int min,
                                              int step,
                                              int max) {
    if (!cap_group) {
        return ACVP_INVALID_ARG;
    }

    switch (param) {
    case ACVP_DRBG_ENTROPY_LEN:
        cap_group->entropy_len_min = min;
        cap_group->entropy_len_step = step;
        cap_group->entropy_len_max = max;
        break;
    case ACVP_DRBG_NONCE_LEN:
        cap_group->nonce_len_min = min;
        cap_group->nonce_len_step = step;
        cap_group->nonce_len_max = max;
        break;
    case ACVP_DRBG_PERSO_LEN:
        cap_group->perso_len_min = min;
        cap_group->perso_len_step = step;
        cap_group->perso_len_max = max;
        break;
    case ACVP_DRBG_ADD_IN_LEN:
        cap_group->additional_in_len_min = min;
        cap_group->additional_in_len_step = step;
        cap_group->additional_in_len_max = max;
        break;
    case ACVP_DRBG_RET_BITS_LEN:
    case ACVP_DRBG_PRE_REQ_VALS:
    case ACVP_DRBG_DER_FUNC_ENABLED:
    case ACVP_DRBG_PRED_RESIST_ENABLED:
    case ACVP_DRBG_RESEED_ENABLED:
    default:
        return ACVP_INVALID_ARG;

        break;
    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_drbg_set_length(ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     ACVP_DRBG_MODE mode,
                                     int group,
                                     ACVP_DRBG_PARM param,
                                     int min,
                                     int step,
                                     int max) {
    ACVP_DRBG_MODE_LIST *drbg_cap_mode = NULL;
    ACVP_DRBG_CAP_GROUP *grp = NULL;
    ACVP_CAPS_LIST *cap_list = NULL;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     * if the mode does not exist yet then create it.
     */
    drbg_cap_mode  = acvp_locate_drbg_mode_entry(cap_list, mode);
    if (!drbg_cap_mode) {
        drbg_cap_mode = acvp_create_drbg_mode_entry(cap_list, mode);
        if (!drbg_cap_mode) {
            ACVP_LOG_ERR("Malloc Failed.");
            return ACVP_MALLOC_FAIL;
        }
    }

    grp = acvp_locate_drbg_group_entry(drbg_cap_mode, group);
    if (!grp) {
        grp = acvp_create_drbg_group(drbg_cap_mode, group);
        if (!grp) {
            ACVP_LOG_ERR("Error creating group for DRBG capabilities");
            return ACVP_MALLOC_FAIL;
        }
    }

    switch (param) {
    case ACVP_DRBG_ENTROPY_LEN:
        if (max > ACVP_DRBG_ENTPY_IN_BIT_MAX) {
            ACVP_LOG_ERR("Parameter 'max'(%d) > ACVP_DRBG_ENTPY_IN_BIT_MAX(%d). "
                         "Please reduce the integer.",
                         max, ACVP_DRBG_ENTPY_IN_BIT_MAX);
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_DRBG_NONCE_LEN:
        if (max > ACVP_DRBG_NONCE_BIT_MAX) {
            ACVP_LOG_ERR("Parameter 'max'(%d) > ACVP_DRBG_NONCE_BIT_MAX(%d). "
                         "Please reduce the integer.",
                         max, ACVP_DRBG_NONCE_BIT_MAX);
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_DRBG_PERSO_LEN:
        if (max > ACVP_DRBG_PER_SO_BIT_MAX) {
            ACVP_LOG_ERR("Parameter 'max'(%d) > ACVP_DRBG_PER_SO_BIT_MAX(%d). "
                         "Please reduce the integer.",
                         max, ACVP_DRBG_PER_SO_BIT_MAX);
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_DRBG_ADD_IN_LEN:
        if (max > ACVP_DRBG_ADDI_IN_BIT_MAX) {
            ACVP_LOG_ERR("Parameter 'max'(%d) > ACVP_DRBG_ADDI_IN_BIT_MAX(%d). "
                         "Please reduce the integer.",
                         max, ACVP_DRBG_ADDI_IN_BIT_MAX);
            return ACVP_INVALID_ARG;
        }
    case ACVP_DRBG_DER_FUNC_ENABLED:
    case ACVP_DRBG_PRED_RESIST_ENABLED:
    case ACVP_DRBG_RESEED_ENABLED:
    case ACVP_DRBG_RET_BITS_LEN:
    case ACVP_DRBG_PRE_REQ_VALS:
    default:
        break;
    }

    /*
     * Add the length range to the cap
     */
    return acvp_add_drbg_length_range(grp, param, min, step, max);
}

static ACVP_RESULT acvp_validate_drbg_parm_value(ACVP_DRBG_PARM parm, int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;

    switch (parm) {
    case ACVP_DRBG_DER_FUNC_ENABLED:
    case ACVP_DRBG_PRED_RESIST_ENABLED:
    case ACVP_DRBG_RESEED_ENABLED:
        retval = is_valid_tf_param(value);
        break;
    case ACVP_DRBG_ENTROPY_LEN:
        if (value >= ACVP_DRBG_ENTPY_IN_BIT_MIN &&
            value <= ACVP_DRBG_ENTPY_IN_BIT_MAX) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_DRBG_NONCE_LEN:
        if (value >= ACVP_DRBG_NONCE_BIT_MIN &&
            value <= ACVP_DRBG_NONCE_BIT_MAX) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_DRBG_PERSO_LEN:
        if (value <= ACVP_DRBG_PER_SO_BIT_MAX) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_DRBG_ADD_IN_LEN:
        if (value <= ACVP_DRBG_ADDI_IN_BIT_MAX) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_DRBG_RET_BITS_LEN:
        if (value <= ACVP_DRB_BIT_MAX) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_DRBG_PRE_REQ_VALS:
        retval = ACVP_SUCCESS;
        break;
    default:
        break;
    }

    return retval;
}

/* The user should call this after invoking acvp_enable_drbg_cap_parm(). */
ACVP_RESULT acvp_cap_drbg_set_parm(ACVP_CTX *ctx,
                                   ACVP_CIPHER cipher,
                                   ACVP_DRBG_MODE mode,
                                   int group,
                                   ACVP_DRBG_PARM param,
                                   int value) {
    ACVP_DRBG_MODE_LIST *cap_mode = NULL;
    ACVP_DRBG_CAP_GROUP *grp = NULL;
    ACVP_CAPS_LIST *cap_list = NULL;
    ACVP_SUB_DRBG alg;

    /*
     * Validate input
     */
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     * if the mode does not exist yet then create it.
     */
    if (!cap_list->cap.drbg_cap) {
        ACVP_LOG_ERR("DRBG Cap entry not found.");
        return ACVP_NO_CAP;
    }

    cap_mode = acvp_locate_drbg_mode_entry(cap_list, mode);
    if (!cap_mode) {
        cap_mode = acvp_create_drbg_mode_entry(cap_list, mode);
        if (!cap_mode) {
            ACVP_LOG_ERR("Malloc Failed.");
            return ACVP_MALLOC_FAIL;
        }
    }

    grp = acvp_locate_drbg_group_entry(cap_mode, group);
    if (!grp) {
        grp = acvp_create_drbg_group(cap_mode, group);
        if (!grp) {
            ACVP_LOG_ERR("Error creating group for DRBG capabilities");
            return ACVP_MALLOC_FAIL;
        }
    }

    /*
     * Add the value to the cap
     */
    alg = acvp_get_drbg_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }

    if (acvp_validate_drbg_parm_value(param, value) != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Error validating DRBG paramater value (param = %d, value = %d", param, value);
        return ACVP_INVALID_ARG;
    }

    switch (param) {
    case ACVP_DRBG_DER_FUNC_ENABLED:
        grp->der_func_enabled = value;
        break;
    case ACVP_DRBG_PRED_RESIST_ENABLED:
        cap_list->cap.drbg_cap->pred_resist_enabled = value;
        break;
    case ACVP_DRBG_RESEED_ENABLED:
        cap_list->cap.drbg_cap->reseed_implemented = value;
        break;
    case ACVP_DRBG_ENTROPY_LEN:
        grp->entropy_input_len = value;
        break;
    case ACVP_DRBG_NONCE_LEN:
        grp->nonce_len = value;
        break;
    case ACVP_DRBG_PERSO_LEN:
        grp->perso_string_len = value;
        break;
    case ACVP_DRBG_ADD_IN_LEN:
        grp->additional_input_len = value;
        break;
    case ACVP_DRBG_RET_BITS_LEN:
        grp->returned_bits_len = value;
        break;
    case ACVP_DRBG_PRE_REQ_VALS:
    default:
        ACVP_LOG_ERR("Invalid DRBG param supplied");
        return ACVP_INVALID_ARG;
        break;
    }


    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_drbg_enable(ACVP_CTX *ctx,
                                 ACVP_CIPHER cipher,
                                 int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_DRBG_TYPE, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

/*
 * The user should call this after invoking acvp_enable_rsa_keygen_cap().
 */
ACVP_RESULT acvp_cap_rsa_keygen_set_mode(ACVP_CTX *ctx,
                                         ACVP_RSA_KEYGEN_MODE value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_RSA_KEYGEN_CAP *keygen_cap;
    ACVP_RESULT result = ACVP_SUCCESS;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_KEYGEN);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    if (!cap_list->cap.rsa_keygen_cap) {
        cap_list->cap.rsa_keygen_cap = calloc(1, sizeof(ACVP_RSA_KEYGEN_CAP));
    }
    keygen_cap = cap_list->cap.rsa_keygen_cap;

    while (keygen_cap) {
        if (keygen_cap->rand_pq != ACVP_RSA_KEYGEN_B32 &&
            keygen_cap->rand_pq != ACVP_RSA_KEYGEN_B33 &&
            keygen_cap->rand_pq != ACVP_RSA_KEYGEN_B34 &&
            keygen_cap->rand_pq != ACVP_RSA_KEYGEN_B35 &&
            keygen_cap->rand_pq != ACVP_RSA_KEYGEN_B36) {
            break;
        }
        if (keygen_cap->rand_pq == value) {
            return ACVP_DUP_CIPHER;
        }
        if (!keygen_cap->next) {
            keygen_cap->next = calloc(1, sizeof(ACVP_RSA_KEYGEN_CAP));
            keygen_cap = keygen_cap->next;
            break;
        }
        keygen_cap = keygen_cap->next;
    }

    keygen_cap->rand_pq = value;
    switch (value) {
    case ACVP_RSA_KEYGEN_B32:
        keygen_cap->rand_pq_str = ACVP_RSA_RANDPQ32_STR;
        break;
    case ACVP_RSA_KEYGEN_B33:
        keygen_cap->rand_pq_str = ACVP_RSA_RANDPQ33_STR;
        break;
    case ACVP_RSA_KEYGEN_B34:
        keygen_cap->rand_pq_str = ACVP_RSA_RANDPQ34_STR;
        break;
    case ACVP_RSA_KEYGEN_B35:
        keygen_cap->rand_pq_str = ACVP_RSA_RANDPQ35_STR;
        break;
    case ACVP_RSA_KEYGEN_B36:
        keygen_cap->rand_pq_str = ACVP_RSA_RANDPQ36_STR;
        break;
    default:
        break;
    }

    return result;
}

/*
 * The user should call this after invoking acvp_enable_rsa_keygen_cap().
 */
ACVP_RESULT acvp_cap_rsa_keygen_set_parm(ACVP_CTX *ctx,
                                         ACVP_RSA_PARM param,
                                         int value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_RESULT rv = ACVP_SUCCESS;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_KEYGEN);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    switch (param) {
    case ACVP_RSA_PARM_PUB_EXP_MODE:
        cap_list->cap.rsa_keygen_cap->pub_exp_mode = value;
        break;
    case ACVP_RSA_PARM_INFO_GEN_BY_SERVER:
        rv = is_valid_tf_param(value);
        if (rv != ACVP_SUCCESS) {
            break;
        }
        cap_list->cap.rsa_keygen_cap->info_gen_by_server = value;
        break;
    case ACVP_RSA_PARM_KEY_FORMAT_CRT:
        rv = is_valid_tf_param(value);
        if (rv != ACVP_SUCCESS) {
            break;
        }
        cap_list->cap.rsa_keygen_cap->key_format_crt = value;
        break;
    case ACVP_RSA_PARM_RAND_PQ:
    case ACVP_RSA_PARM_FIXED_PUB_EXP_VAL:
        rv = ACVP_INVALID_ARG;
        ACVP_LOG_ERR("Use acvp_enable_rsa_keygen_mode() or acvp_enable_rsa_keygen_exp_parm() API to enable a new randPQ or exponent.");
        break;
    default:
        rv = ACVP_INVALID_ARG;
        break;
    }
    return rv;
}

ACVP_RESULT acvp_cap_rsa_keygen_enable(ACVP_CTX *ctx,
                                       ACVP_CIPHER cipher,
                                       int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    if (cipher != ACVP_RSA_KEYGEN) {
        ACVP_LOG_ERR("Invalid parameter 'cipher'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_RSA_KEYGEN_TYPE, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

/*
 * The user should call this after invoking acvp_enable_rsa_sigver_cap().
 */
ACVP_RESULT acvp_cap_rsa_sigver_set_parm(ACVP_CTX *ctx,
                                         ACVP_RSA_PARM param,
                                         int value) {
    ACVP_CAPS_LIST *cap_list;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_SIGVER);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    switch (param) {
    case ACVP_RSA_PARM_PUB_EXP_MODE:
        cap_list->cap.rsa_sigver_cap->pub_exp_mode = value;
        break;
    case ACVP_RSA_PARM_FIXED_PUB_EXP_VAL:
    case ACVP_RSA_PARM_KEY_FORMAT_CRT:
    case ACVP_RSA_PARM_RAND_PQ:
    case ACVP_RSA_PARM_INFO_GEN_BY_SERVER:
    default:
        return ACVP_INVALID_ARG;

        break;
    }
    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_rsa_sigver_cap().
 */
ACVP_RESULT acvp_cap_rsa_sigver_set_type(ACVP_CTX *ctx,
                                         ACVP_RSA_SIG_TYPE value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_RSA_SIG_CAP *sigver_cap;
    ACVP_RESULT result = ACVP_SUCCESS;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_SIGVER);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    if (!cap_list->cap.rsa_sigver_cap) {
        cap_list->cap.rsa_sigver_cap = calloc(1, sizeof(ACVP_RSA_SIG_CAP));
    }
    sigver_cap = cap_list->cap.rsa_sigver_cap;

    while (sigver_cap) {
        if (!sigver_cap->sig_type) {
            break;
        }
        if (sigver_cap->sig_type == value) {
            return ACVP_DUP_CIPHER;
        }
        if (!sigver_cap->next) {
            sigver_cap->next = calloc(1, sizeof(ACVP_RSA_SIG_CAP));
            sigver_cap = sigver_cap->next;
            break;
        }
        sigver_cap = sigver_cap->next;
    }

    sigver_cap->sig_type = value;
    switch (value) {
    case ACVP_RSA_SIG_TYPE_X931:
        sigver_cap->sig_type_str = ACVP_RSA_SIG_TYPE_X931_STR;
        break;
    case ACVP_RSA_SIG_TYPE_PKCS1V15:
        sigver_cap->sig_type_str = ACVP_RSA_SIG_TYPE_PKCS1V15_STR;
        break;
    case ACVP_RSA_SIG_TYPE_PKCS1PSS:
        sigver_cap->sig_type_str = ACVP_RSA_SIG_TYPE_PKCS1PSS_STR;
        break;
    default:
        break;
    }

    return result;
}

/*
 * The user should call this after invoking acvp_enable_rsa_siggen_cap().
 */
ACVP_RESULT acvp_cap_rsa_siggen_set_type(ACVP_CTX *ctx,
                                         ACVP_RSA_SIG_TYPE value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_RSA_SIG_CAP *siggen_cap;
    ACVP_RESULT result = ACVP_SUCCESS;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_SIGGEN);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    if (!cap_list->cap.rsa_siggen_cap) {
        cap_list->cap.rsa_siggen_cap = calloc(1, sizeof(ACVP_RSA_SIG_CAP));
    }
    siggen_cap = cap_list->cap.rsa_siggen_cap;

    while (siggen_cap) {
        if (!siggen_cap->sig_type) {
            break;
        }
        if (siggen_cap->sig_type == value) {
            return ACVP_DUP_CIPHER;
        }
        if (!siggen_cap->next) {
            siggen_cap->next = calloc(1, sizeof(ACVP_RSA_SIG_CAP));
            siggen_cap = siggen_cap->next;
            break;
        }
        siggen_cap = siggen_cap->next;
    }

    siggen_cap->sig_type = value;
    switch (value) {
    case ACVP_RSA_SIG_TYPE_X931:
        siggen_cap->sig_type_str = ACVP_RSA_SIG_TYPE_X931_STR;
        break;
    case ACVP_RSA_SIG_TYPE_PKCS1V15:
        siggen_cap->sig_type_str = ACVP_RSA_SIG_TYPE_PKCS1V15_STR;
        break;
    case ACVP_RSA_SIG_TYPE_PKCS1PSS:
        siggen_cap->sig_type_str = ACVP_RSA_SIG_TYPE_PKCS1PSS_STR;
        break;
    default:
        break;
    }

    return result;
}

/*
 * The user should call this after invoking acvp_enable_rsa_keygen_cap_parm().
 */
ACVP_RESULT acvp_cap_rsa_keygen_set_exponent(ACVP_CTX *ctx,
                                             ACVP_RSA_PARM param,
                                             char *value) {
    ACVP_CAPS_LIST *cap_list = NULL;
    ACVP_RSA_KEYGEN_CAP *cap = NULL;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_KEYGEN);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    /* Get pointer to rsa keygen cap */
    cap = cap_list->cap.rsa_keygen_cap;

    /*
     * Add the value to the cap
     */
    switch (param) {
    case ACVP_RSA_PARM_FIXED_PUB_EXP_VAL:
        if (cap->pub_exp_mode == ACVP_RSA_PUB_EXP_MODE_FIXED) {
            if (cap->fixed_pub_exp == NULL) {
                unsigned int len = strnlen_s(value, ACVP_CAPABILITY_STR_MAX + 1);

                if (len > ACVP_CAPABILITY_STR_MAX) {
                    ACVP_LOG_ERR("Parameter 'value' string is too long. "
                                 "max allowed is (%d) characters.",
                                 ACVP_CAPABILITY_STR_MAX);
                    return ACVP_INVALID_ARG;
                }

                cap->fixed_pub_exp = calloc(len + 1, sizeof(char));
                strcpy_s(cap->fixed_pub_exp, len + 1, value);
            } else {
                ACVP_LOG_ERR("ACVP_FIXED_PUB_EXP_VAL has already been set.");
                return ACVP_UNSUPPORTED_OP;
            }
        }
        break;
    case ACVP_RSA_PARM_PUB_EXP_MODE:
    case ACVP_RSA_PARM_KEY_FORMAT_CRT:
    case ACVP_RSA_PARM_RAND_PQ:
    case ACVP_RSA_PARM_INFO_GEN_BY_SERVER:
    default:
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_rsa_sigver_cap_parm().
 */
ACVP_RESULT acvp_cap_rsa_sigver_set_exponent(ACVP_CTX *ctx,
                                             ACVP_RSA_PARM param,
                                             char *value) {
    ACVP_CAPS_LIST *cap_list = NULL;
    ACVP_RSA_SIG_CAP *cap = NULL;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_SIGVER);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    /* Get pointer to rsa keygen cap */
    cap = cap_list->cap.rsa_sigver_cap;

    /*
     * Add the value to the cap
     */
    switch (param) {
    case ACVP_RSA_PARM_FIXED_PUB_EXP_VAL:
        if (cap->pub_exp_mode == ACVP_RSA_PUB_EXP_MODE_FIXED) {
            if (cap->fixed_pub_exp == NULL) {
                unsigned int len = strnlen_s(value, ACVP_CAPABILITY_STR_MAX + 1);

                if (len > ACVP_CAPABILITY_STR_MAX) {
                    ACVP_LOG_ERR("Parameter 'value' string is too long. "
                                 "max allowed is (%d) characters.",
                                 ACVP_CAPABILITY_STR_MAX);
                    return ACVP_INVALID_ARG;
                }

                cap->fixed_pub_exp = calloc(len + 1, sizeof(char));
                strcpy_s(cap->fixed_pub_exp, len + 1, value);
            } else {
                ACVP_LOG_ERR("ACVP_FIXED_PUB_EXP_VAL has already been set.");
                return ACVP_UNSUPPORTED_OP;
            }
        }
        break;
    case ACVP_RSA_PARM_PUB_EXP_MODE:
    case ACVP_RSA_PARM_KEY_FORMAT_CRT:
    case ACVP_RSA_PARM_RAND_PQ:
    case ACVP_RSA_PARM_INFO_GEN_BY_SERVER:
    default:
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_rsa_cap_parm()
 * and setting the randPQ value.
 */
ACVP_RESULT acvp_cap_rsa_keygen_set_primes(ACVP_CTX *ctx,
                                           ACVP_RSA_KEYGEN_MODE mode,
                                           unsigned int mod,
                                           ACVP_RSA_PRIME_PARAM param,
                                           int value) {
    ACVP_RSA_KEYGEN_CAP *keygen_cap;
    ACVP_CAPS_LIST *cap_list;
    ACVP_RSA_MODE_CAPS_LIST *current_prime = NULL;
    ACVP_RESULT result = ACVP_SUCCESS;
    int found = 0;
    const char *string = NULL;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_KEYGEN);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    if (!cap_list->cap.rsa_keygen_cap) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    keygen_cap = cap_list->cap.rsa_keygen_cap;
    while (keygen_cap) {
        if (keygen_cap->rand_pq == mode) {
            break;
        } else {
            keygen_cap = keygen_cap->next;
        }
    }

    if (!keygen_cap) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    if (!keygen_cap->mode_capabilities) {
        keygen_cap->mode_capabilities = calloc(1, sizeof(ACVP_RSA_MODE_CAPS_LIST));
        if (!keygen_cap->mode_capabilities) {
            ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return ACVP_MALLOC_FAIL;
        }
        keygen_cap->mode_capabilities->modulo = mod;
        current_prime = keygen_cap->mode_capabilities;
    } else {
        current_prime = keygen_cap->mode_capabilities;

        found = 0;
        do {
            if (current_prime->modulo != mod) {
                if (current_prime->next == NULL) {
                    current_prime->next = calloc(1, sizeof(ACVP_RSA_MODE_CAPS_LIST));
                    if (!current_prime->next) {
                        ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                        return ACVP_MALLOC_FAIL;
                    }
                    current_prime = current_prime->next;
                    current_prime->modulo = mod;
                    found = 1;
                } else {
                    current_prime = current_prime->next;
                }
            } else {
                found = 1;
            }
        } while (!found);
    }

    if (param == ACVP_RSA_PRIME_HASH_ALG) {
        string = acvp_lookup_hash_alg_name(value);
        if (!string) {
            ACVP_LOG_ERR("Invalid 'value' for ACVP_RSA_HASH_ALG");
            return ACVP_INVALID_ARG;
        }
        result = acvp_append_name_list(&current_prime->hash_algs, string);
    } else if (param == ACVP_RSA_PRIME_TEST) {
        string = acvp_lookup_rsa_prime_test_name(value);
        if (!string) {
            ACVP_LOG_ERR("Invalid 'value' for ACVP_RSA_PRIME_TEST");
            return ACVP_INVALID_ARG;
        }
        result = acvp_append_name_list(&current_prime->prime_tests, string);
    } else {
        ACVP_LOG_ERR("Invalid parameter 'param'");
        return ACVP_INVALID_ARG;
    }

    return result;
}

/*
 * The user should call this after invoking acvp_enable_rsa_sigver_cap()
 * and setting the randPQ value.
 *
 * Set parameters for a specific modulo value.
 */
ACVP_RESULT acvp_cap_rsa_sigver_set_mod_parm(ACVP_CTX *ctx,
                                             ACVP_RSA_SIG_TYPE sig_type,
                                             unsigned int mod,
                                             int hash_alg,
                                             int salt_len) {
    ACVP_RSA_SIG_CAP *sigver_cap;
    ACVP_CAPS_LIST *cap_list;
    ACVP_RSA_MODE_CAPS_LIST *current_cap = NULL;
    ACVP_RSA_HASH_PAIR_LIST *current_hash = NULL;
    const char *string = NULL;
    int found = 0;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!hash_alg || !mod) {
        ACVP_LOG_ERR("Must specify mod and hash_alg");
        return ACVP_INVALID_ARG;
    }

    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_SIGVER);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    sigver_cap = cap_list->cap.rsa_sigver_cap;
    while (sigver_cap) {
        if (sigver_cap->sig_type != sig_type) {
            sigver_cap = sigver_cap->next;
        } else {
            break;
        }
    }
    if (!sigver_cap) {
        return ACVP_NO_CAP;
    }

    if (!sigver_cap->mode_capabilities) {
        sigver_cap->mode_capabilities = calloc(1, sizeof(ACVP_RSA_MODE_CAPS_LIST));
        if (!sigver_cap->mode_capabilities) {
            ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return ACVP_MALLOC_FAIL;
        }
        sigver_cap->mode_capabilities->modulo = mod;
        current_cap = sigver_cap->mode_capabilities;
    } else {
        current_cap = sigver_cap->mode_capabilities;

        found = 0;
        do {
            if (current_cap->modulo != mod) {
                if (current_cap->next == NULL) {
                    current_cap->next = calloc(1, sizeof(ACVP_RSA_MODE_CAPS_LIST));
                    if (!current_cap->next) {
                        ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                        return ACVP_MALLOC_FAIL;
                    }
                    current_cap = current_cap->next;
                    current_cap->modulo = mod;
                    found = 1;
                } else {
                    current_cap = current_cap->next;
                }
            } else {
                found = 1;
            }
        } while (!found);
    }

    string = acvp_lookup_hash_alg_name(hash_alg);
    if (!string) {
        ACVP_LOG_ERR("Invalid parameter 'hash_alg'");
    }

    if (!current_cap->hash_pair) {
        current_cap->hash_pair = calloc(1, sizeof(ACVP_RSA_HASH_PAIR_LIST));
        if (!current_cap->hash_pair) {
            ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return ACVP_MALLOC_FAIL;
        }
        current_cap->hash_pair->name = string;
        if (salt_len) {
            current_cap->hash_pair->salt = salt_len;
        }
    } else {
        current_hash = current_cap->hash_pair;
        while (current_hash->next != NULL) {
            current_hash = current_hash->next;
        }
        current_hash->next = calloc(1, sizeof(ACVP_RSA_HASH_PAIR_LIST));
        if (!current_hash->next) {
            ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return ACVP_MALLOC_FAIL;
        }
        current_hash->next->name = string;
        if (salt_len) {
            current_hash->next->salt = salt_len;
        }
    }

    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_rsa_siggen_cap()
 * and setting the randPQ value.
 */
ACVP_RESULT acvp_cap_rsa_siggen_set_mod_parm(ACVP_CTX *ctx,
                                             ACVP_RSA_SIG_TYPE sig_type,
                                             unsigned int mod,
                                             int hash_alg,
                                             int salt_len) {
    ACVP_RSA_SIG_CAP *siggen_cap;
    ACVP_CAPS_LIST *cap_list;
    ACVP_RSA_MODE_CAPS_LIST *current_cap = NULL;
    ACVP_RSA_HASH_PAIR_LIST *current_hash = NULL;
    const char *string = NULL;
    int found = 0;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!hash_alg || !mod) {
        ACVP_LOG_ERR("Must specify mod and hash_alg");
        return ACVP_INVALID_ARG;
    }

    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_SIGGEN);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    siggen_cap = cap_list->cap.rsa_siggen_cap;
    while (siggen_cap) {
        if (siggen_cap->sig_type != sig_type) {
            siggen_cap = siggen_cap->next;
        } else {
            break;
        }
    }
    if (!siggen_cap) {
        return ACVP_NO_CAP;
    }

    if (!siggen_cap->mode_capabilities) {
        siggen_cap->mode_capabilities = calloc(1, sizeof(ACVP_RSA_MODE_CAPS_LIST));
        if (!siggen_cap->mode_capabilities) {
            ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return ACVP_MALLOC_FAIL;
        }
        siggen_cap->mode_capabilities->modulo = mod;
        current_cap = siggen_cap->mode_capabilities;
    } else {
        current_cap = siggen_cap->mode_capabilities;

        found = 0;
        do {
            if (current_cap->modulo != mod) {
                if (current_cap->next == NULL) {
                    current_cap->next = calloc(1, sizeof(ACVP_RSA_MODE_CAPS_LIST));
                    if (!current_cap->next) {
                        ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                        return ACVP_MALLOC_FAIL;
                    }
                    current_cap = current_cap->next;
                    current_cap->modulo = mod;
                    found = 1;
                } else {
                    current_cap = current_cap->next;
                }
            } else {
                found = 1;
            }
        } while (!found);
    }

    string = acvp_lookup_hash_alg_name(hash_alg);
    if (!string) {
        ACVP_LOG_ERR("Invalid parameter 'hash_alg'");
    }

    if (!current_cap->hash_pair) {
        current_cap->hash_pair = calloc(1, sizeof(ACVP_RSA_HASH_PAIR_LIST));
        if (!current_cap->hash_pair) {
            ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return ACVP_MALLOC_FAIL;
        }
        current_cap->hash_pair->name = string;
        if (salt_len) {
            current_cap->hash_pair->salt = salt_len;
        }
    } else {
        current_hash = current_cap->hash_pair;
        while (current_hash->next != NULL) {
            current_hash = current_hash->next;
        }
        current_hash->next = calloc(1, sizeof(ACVP_RSA_HASH_PAIR_LIST));
        if (!current_hash->next) {
            ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return ACVP_MALLOC_FAIL;
        }
        current_hash->next->name = string;
        if (salt_len) {
            current_hash->next->salt = salt_len;
        }
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT internal_cap_rsa_sig_enable(ACVP_CTX *ctx,
                                               ACVP_CIPHER cipher,
                                               int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_CAP_TYPE type = 0;
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_SUB_RSA alg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }

    alg = acvp_get_rsa_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_RSA_SIGGEN:
        type = ACVP_RSA_SIGGEN_TYPE;
        break;
    case ACVP_SUB_RSA_SIGVER:
        type = ACVP_RSA_SIGVER_TYPE;
        break;
    case ACVP_SUB_RSA_SIGPRIM:
    case ACVP_SUB_RSA_DECPRIM:
        type = ACVP_RSA_PRIM_TYPE;
        break;
    case ACVP_SUB_RSA_KEYGEN:
    default:
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, type, cipher, crypto_handler);

    return result;
}

ACVP_RESULT acvp_cap_rsa_sig_enable(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;
    const char *cap_message_str = NULL;
    ACVP_SUB_RSA alg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    alg = acvp_get_rsa_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_RSA_SIGGEN:
        cap_message_str = "ACVP_RSA_SIGGEN";
        break;
    case ACVP_SUB_RSA_SIGVER:
        cap_message_str = "ACVP_RSA_SIGVER";
        break;
    case ACVP_SUB_RSA_KEYGEN:
    case ACVP_SUB_RSA_DECPRIM:
    case ACVP_SUB_RSA_SIGPRIM:
    default:
        ACVP_LOG_ERR("Invalid parameter 'cipher'");
        return ACVP_INVALID_ARG;
    }

    result = internal_cap_rsa_sig_enable(ctx, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability (%s) previously enabled. Duplicate not allowed.",
                     cap_message_str);
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate (%s) capability object",
                     cap_message_str);
    }

    return result;
}
ACVP_RESULT acvp_cap_rsa_prim_enable(ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    if ((cipher != ACVP_RSA_SIGPRIM) && (cipher != ACVP_RSA_DECPRIM)) {
        ACVP_LOG_ERR("Invalid parameter 'cipher'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_RSA_PRIM_TYPE, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

/*
 * The user should call this after invoking acvp_enable_rsa_prim_cap().
 */
ACVP_RESULT acvp_cap_rsa_prim_set_parm(ACVP_CTX *ctx,
                                       ACVP_RSA_PARM param,
                                       int value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_RESULT rv = ACVP_SUCCESS;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_SIGPRIM);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    switch (param) {
    case ACVP_RSA_PARM_PUB_EXP_MODE:
        cap_list->cap.rsa_prim_cap->pub_exp_mode = value;
        break;
    case ACVP_RSA_PARM_KEY_FORMAT_CRT:
        rv = is_valid_tf_param(value);
        if (rv != ACVP_SUCCESS) {
            break;
        }
        cap_list->cap.rsa_prim_cap->key_format_crt = value;
        break;
    case ACVP_RSA_PARM_FIXED_PUB_EXP_VAL:
    case ACVP_RSA_PARM_RAND_PQ:
    case ACVP_RSA_PARM_INFO_GEN_BY_SERVER:
    default:
        rv = ACVP_INVALID_ARG;
        break;
    }
    return rv;
}

/*
 * The user should call this after invoking acvp_enable_rsa_prim_cap_parm().
 */
ACVP_RESULT acvp_cap_rsa_prim_set_exponent(ACVP_CTX *ctx,
                                             ACVP_RSA_PARM param,
                                             char *value) {
    ACVP_CAPS_LIST *cap_list = NULL;
    ACVP_RSA_PRIM_CAP *cap = NULL;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_SIGPRIM);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    /* Get pointer to rsa prim cap */
    cap = cap_list->cap.rsa_prim_cap;

    /*
     * Add the value to the cap
     */
    switch (param) {
    case ACVP_RSA_PARM_FIXED_PUB_EXP_VAL:
        if (cap->pub_exp_mode == ACVP_RSA_PUB_EXP_MODE_FIXED) {
            if (cap->fixed_pub_exp == NULL) {
                unsigned int len = strnlen_s(value, ACVP_CAPABILITY_STR_MAX + 1);

                if (len > ACVP_CAPABILITY_STR_MAX) {
                    ACVP_LOG_ERR("Parameter 'value' string is too long. "
                                 "max allowed is (%d) characters.",
                                 ACVP_CAPABILITY_STR_MAX);
                    return ACVP_INVALID_ARG;
                }

                cap->fixed_pub_exp = calloc(len + 1, sizeof(char));
                strcpy_s(cap->fixed_pub_exp, len + 1, value);
            } else {
                ACVP_LOG_ERR("ACVP_FIXED_PUB_EXP_VAL has already been set.");
                return ACVP_UNSUPPORTED_OP;
            }
        }
        break;
    case ACVP_RSA_PARM_PUB_EXP_MODE:
    case ACVP_RSA_PARM_KEY_FORMAT_CRT:
    case ACVP_RSA_PARM_RAND_PQ:
    case ACVP_RSA_PARM_INFO_GEN_BY_SERVER:
    default:
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}


/*
 * The user should call this after invoking acvp_enable_ecdsa_cap().
 */
ACVP_RESULT acvp_cap_ecdsa_set_parm(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    ACVP_ECDSA_PARM param,
                                    int value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_CURVE_ALG_COMPAT_LIST *current_curve;
    ACVP_ECDSA_CAP *cap;
    const char *string = NULL;
    ACVP_SUB_ECDSA alg;
    ACVP_RESULT result = ACVP_SUCCESS;

    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    alg = acvp_get_ecdsa_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_ECDSA_KEYGEN:
        cap = cap_list->cap.ecdsa_keygen_cap;
        break;
    case ACVP_SUB_ECDSA_KEYVER:
        cap = cap_list->cap.ecdsa_keyver_cap;
        break;
    case ACVP_SUB_ECDSA_SIGGEN:
        cap = cap_list->cap.ecdsa_siggen_cap;
        break;
    case ACVP_SUB_ECDSA_SIGVER:
        cap = cap_list->cap.ecdsa_sigver_cap;
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    if (!value) {
        return ACVP_MISSING_ARG;
    }

    switch (param) {
    case ACVP_ECDSA_CURVE:
        if (value <= ACVP_EC_CURVE_START || value >= ACVP_EC_CURVE_END) {
            ACVP_LOG_ERR("Invalid 'value' for ACVP_ECDSA_CURVE");
            return ACVP_INVALID_ARG;
        }

        current_curve = cap->curves;
        if (current_curve) {
            while (current_curve->next) {
                current_curve = current_curve->next;
            }
            current_curve->next = calloc(1, sizeof(ACVP_CURVE_ALG_COMPAT_LIST));
            current_curve->next->curve = value;
        } else {
            cap->curves = calloc(1, sizeof(ACVP_CURVE_ALG_COMPAT_LIST));
            cap->curves->curve = value;
        }
        break;
    case ACVP_ECDSA_SECRET_GEN:
        if (cipher != ACVP_ECDSA_KEYGEN) {
            return ACVP_INVALID_ARG;
        }

        switch (value) {
        case ACVP_ECDSA_SECRET_GEN_EXTRA_BITS:
            string = ACVP_ECDSA_EXTRA_BITS_STR;
            break;
        case ACVP_ECDSA_SECRET_GEN_TEST_CAND:
            string = ACVP_ECDSA_TESTING_CANDIDATES_STR;
            break;
        default:
            ACVP_LOG_ERR("Invalid 'value' for ACVP_ECDSA_SECRET_GEN");
            return ACVP_INVALID_ARG;
        }

        result = acvp_append_name_list(&cap->secret_gen_modes, string);
        break;
    case ACVP_ECDSA_HASH_ALG:
        if (cipher != ACVP_ECDSA_SIGGEN && cipher != ACVP_ECDSA_SIGVER) {
            return ACVP_INVALID_ARG;
        }

        if (value <= ACVP_NO_SHA || value >= ACVP_HASH_ALG_MAX || (value & (value - 1)) != 0) {
            ACVP_LOG_ERR("Invalid 'value' for ACVP_ECDSA_HASH_ALG");
            return ACVP_INVALID_ARG;
        }

        cap->hash_algs[value] = 1;
        break;
    case ACVP_ECDSA_COMPONENT_TEST:
        if (cipher == ACVP_ECDSA_SIGGEN || cipher == ACVP_ECDSA_SIGVER) {
            if (value >= ACVP_ECDSA_COMPONENT_MODE_NO && value <= ACVP_ECDSA_COMPONENT_MODE_BOTH) {
                if (value == ACVP_ECDSA_COMPONENT_MODE_BOTH) {
                    /* This will generate two vector sets, one for and one not for component mode */
                    ctx->vs_count++;
                }
                cap->component = value;
            } else {
                ACVP_LOG_ERR("Invalid value given for ECDSA component test mode");
                return ACVP_INVALID_ARG;
            }
        } else {
            ACVP_LOG_ERR("ECDSA Component Tests only apply to siggen and sigver");
            return ACVP_INVALID_ARG;
        }
        break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }

    return result;
}

ACVP_RESULT acvp_cap_ecdsa_set_curve_hash_alg(ACVP_CTX *ctx, ACVP_CIPHER cipher, ACVP_EC_CURVE curve, ACVP_HASH_ALG alg) {
    ACVP_CAPS_LIST *cap;
    ACVP_ECDSA_CAP *ecdsa_cap;
    ACVP_CURVE_ALG_COMPAT_LIST *list;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (curve <= ACVP_EC_CURVE_START || curve >= ACVP_EC_CURVE_END) {
        ACVP_LOG_ERR("Invalid 'curve' argument for acvp_cap_ecdsa_set_curve_hash_alg");
        return ACVP_INVALID_ARG;
    }

    if (alg <= ACVP_NO_SHA || alg >= ACVP_HASH_ALG_MAX || (alg & (alg - 1)) != 0) {
        ACVP_LOG_ERR("Invalid 'alg' argument for acvp_cap_ecdsa_set_curve_hash_alg");
        return ACVP_INVALID_ARG;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    if (cipher == ACVP_ECDSA_SIGGEN) {
        ecdsa_cap = cap->cap.ecdsa_siggen_cap;
    } else if (cipher == ACVP_ECDSA_SIGVER) {
        ecdsa_cap = cap->cap.ecdsa_sigver_cap;
    } else {
        ACVP_LOG_ERR("Invalid 'cipher' argument for acvp_cap_ecdsa_set_curve_hash_alg");
        return ACVP_INVALID_ARG;
    }

    list = ecdsa_cap->curves;

    while (list) {
        if (curve == list->curve) {
            list->algs[alg] = 1;
            return ACVP_SUCCESS;
        }
        list = list->next;
    }

    ACVP_LOG_ERR("Curve not yet enabled. Please enable the given curve before setting its hash algs");
    return ACVP_UNSUPPORTED_OP;
}

ACVP_RESULT acvp_cap_ecdsa_enable(ACVP_CTX *ctx,
                                  ACVP_CIPHER cipher,
                                  int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_CAP_TYPE type = 0;
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_SUB_ECDSA alg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    alg = acvp_get_ecdsa_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_ECDSA_KEYGEN:
        type = ACVP_ECDSA_KEYGEN_TYPE;
        break;
    case ACVP_SUB_ECDSA_KEYVER:
        type = ACVP_ECDSA_KEYVER_TYPE;
        break;
    case ACVP_SUB_ECDSA_SIGGEN:
        type = ACVP_ECDSA_SIGGEN_TYPE;
        break;
    case ACVP_SUB_ECDSA_SIGVER:
        type = ACVP_ECDSA_SIGVER_TYPE;
        break;
    default:
        ACVP_LOG_ERR("Invalid parameter 'cipher'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, type, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

/*
 * The user should call this after invoking acvp_enable_dsa_cap().
 */
ACVP_RESULT acvp_cap_dsa_set_parm(ACVP_CTX *ctx,
                                  ACVP_CIPHER cipher,
                                  ACVP_DSA_MODE mode,
                                  ACVP_DSA_PARM param,
                                  int value) {
    ACVP_DSA_CAP_MODE *dsa_cap_mode;
    ACVP_DSA_CAP *dsa_cap;
    ACVP_CAPS_LIST *cap_list;
    ACVP_RESULT result;


    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    dsa_cap = cap_list->cap.dsa_cap;

    /* range check mode */
    dsa_cap_mode = &dsa_cap->dsa_cap_mode[mode - 1];
    dsa_cap_mode->defined = 1;

    /*
     * Add the value to the cap
     */
    switch (mode) {
    case ACVP_DSA_MODE_PQGGEN:
        result = acvp_add_dsa_pqggen_parm(ctx, dsa_cap_mode, param, value);
        if (result != ACVP_SUCCESS)
            ACVP_LOG_ERR("Invalid param to enable_dsa_cap_parm.");
        break;
    case ACVP_DSA_MODE_PQGVER:
        result = acvp_add_dsa_pqggen_parm(ctx, dsa_cap_mode, param, value);
        if (result != ACVP_SUCCESS)
            ACVP_LOG_ERR("Invalid param to enable_dsa_cap_parm.");
        break;
    case ACVP_DSA_MODE_KEYGEN:
        result = acvp_add_dsa_keygen_parm(ctx, dsa_cap_mode, param, value);
        if (result != ACVP_SUCCESS)
            ACVP_LOG_ERR("Invalid param to enable_dsa_cap_parm.");
        break;
    case ACVP_DSA_MODE_SIGGEN:
        result = acvp_add_dsa_pqggen_parm(ctx, dsa_cap_mode, param, value);
        if (result != ACVP_SUCCESS)
            ACVP_LOG_ERR("Invalid param to enable_dsa_cap_parm.");
        break;
    case ACVP_DSA_MODE_SIGVER:
        result = acvp_add_dsa_pqggen_parm(ctx, dsa_cap_mode, param, value);
        if (result != ACVP_SUCCESS)
            ACVP_LOG_ERR("Invalid param to enable_dsa_cap_parm.");
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    return result;
}

/*
 * The user should call this after invoking acvp_enable_kdf135_snmp_cap()
 * to specify kdf parameters
 */
ACVP_RESULT acvp_cap_kdf135_snmp_set_parm(ACVP_CTX *ctx,
                                          ACVP_CIPHER kcap,
                                          ACVP_KDF135_SNMP_PARAM param,
                                          int value) {
    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_SNMP_CAP *kdf135_snmp_cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (param != ACVP_KDF135_SNMP_PASS_LEN) {
        return ACVP_INVALID_ARG;
    }

    if (value < ACVP_KDF135_SNMP_PASS_LEN_MIN ||
        value > ACVP_KDF135_SNMP_PASS_LEN_MAX) {
        ACVP_LOG_ERR("Invalid pass len");
        return ACVP_INVALID_ARG;
    }

    cap = acvp_locate_cap_entry(ctx, kcap);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kdf135_snmp_cap = cap->cap.kdf135_snmp_cap;
    if (!kdf135_snmp_cap) {
        return ACVP_NO_CAP;
    }

    acvp_append_sl_list(&kdf135_snmp_cap->pass_lens, value);

    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_kdf135_snmp_cap()
 * to specify the hex string engine id. acvp_enable_kdf135_snmp_cap_parm()
 * should be used to specify password length
 */
ACVP_RESULT acvp_cap_kdf135_snmp_set_engid(ACVP_CTX *ctx,
                                           ACVP_CIPHER kcap,
                                           const char *engid) {
    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_SNMP_CAP *kdf135_snmp_cap;
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!engid) {
        return ACVP_INVALID_ARG;
    }
    if (strnlen_s(engid, ACVP_KDF135_SNMP_ENGID_MAX_STR + 1) > ACVP_KDF135_SNMP_ENGID_MAX_STR) {
        ACVP_LOG_ERR("engid too long");
        return ACVP_INVALID_ARG;
    }

    cap = acvp_locate_cap_entry(ctx, kcap);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kdf135_snmp_cap = cap->cap.kdf135_snmp_cap;
    if (!kdf135_snmp_cap) {
        return ACVP_NO_CAP;
    }

    result = acvp_append_name_list(&kdf135_snmp_cap->eng_ids, engid);

    return result;
}

ACVP_RESULT acvp_cap_kdf135_srtp_enable(ACVP_CTX *ctx,
                                        int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_KDF135_SRTP_TYPE, ACVP_KDF135_SRTP, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_kdf135_ikev2_enable(ACVP_CTX *ctx,
                                         int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_KDF135_IKEV2_TYPE, ACVP_KDF135_IKEV2, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}


ACVP_RESULT acvp_cap_kdf135_x942_enable(ACVP_CTX *ctx,
                                        int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_KDF135_X942_TYPE, ACVP_KDF135_X942, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}


ACVP_RESULT acvp_cap_kdf135_x963_enable(ACVP_CTX *ctx,
                                        int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_KDF135_X963_TYPE, ACVP_KDF135_X963, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_kdf135_ikev1_enable(ACVP_CTX *ctx,
                                         int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_KDF135_IKEV1_TYPE, ACVP_KDF135_IKEV1, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_kdf108_enable(ACVP_CTX *ctx,
                                   int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_KDF108_TYPE, ACVP_KDF108, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_kdf135_snmp_enable(ACVP_CTX *ctx,
                                        int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_KDF135_SNMP_TYPE, ACVP_KDF135_SNMP, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_kdf135_ssh_enable(ACVP_CTX *ctx,
                                       int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_KDF135_SSH_TYPE, ACVP_KDF135_SSH, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_pbkdf_enable(ACVP_CTX *ctx,
                                  int (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_PBKDF_TYPE, ACVP_PBKDF, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_pbkdf_set_domain(ACVP_CTX *ctx,
                                      ACVP_PBKDF_PARM param,
                                      int min, int max, 
                                      int increment) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_JSON_DOMAIN_OBJ *domain;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_PBKDF);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    } else if (max < min || increment < 1) {
        ACVP_LOG_ERR("Invalid domain values given");
        return ACVP_INVALID_ARG;
    }

    switch (param) {
    case ACVP_PBKDF_ITERATION_COUNT:
        if (min < ACVP_PBKDF_ITERATION_MIN ||
            max > ACVP_PBKDF_ITERATION_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap_list->cap.pbkdf_cap->iteration_count_domain;
        break;
    case ACVP_PBKDF_KEY_LEN:
        if (min < ACVP_PBKDF_KEY_BIT_MIN ||
            max > ACVP_PBKDF_KEY_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap_list->cap.pbkdf_cap->key_len_domain;
        break;
    case ACVP_PBKDF_PASSWORD_LEN:
        if (min < ACVP_PBKDF_PASS_LEN_MIN ||
            max > ACVP_PBKDF_PASS_LEN_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap_list->cap.pbkdf_cap->password_len_domain;
        break;
    case ACVP_PBKDF_SALT_LEN:
        if (min < ACVP_PBKDF_SALT_LEN_BIT_MIN ||
            max > ACVP_PBKDF_SALT_LEN_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap_list->cap.pbkdf_cap->salt_len_domain;
        break;
    case ACVP_PBKDF_PARAM_MIN:
    case ACVP_PBKDF_HMAC_ALG:
    default:
        return ACVP_INVALID_ARG;
    }

    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return ACVP_SUCCESS;

}

ACVP_RESULT acvp_cap_pbkdf_set_parm(ACVP_CTX *ctx,
                                    ACVP_PBKDF_PARM param,
                                    int value) {
    ACVP_CAPS_LIST *cap_list = NULL;
    ACVP_PBKDF_CAP *cap = NULL;
    const char *alg_str = NULL;
    ACVP_RESULT result = ACVP_SUCCESS;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_PBKDF);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found. You must enable algorithm before setting parameters.");
        return ACVP_NO_CAP;
    }
    cap = cap_list->cap.pbkdf_cap;

    if (param != ACVP_PBKDF_HMAC_ALG) {
        ACVP_LOG_ERR("Invalid param.");
        return ACVP_INVALID_ARG;
    }

    alg_str = acvp_lookup_hash_alg_name(value);
    if (!alg_str) {
        ACVP_LOG_ERR("Invalid value specified for PBKDF hmac alg.");
        return ACVP_INVALID_ARG;
    }
    if (acvp_is_in_name_list(cap->hmac_algs, alg_str)) {
        ACVP_LOG_WARN("Attempting to register an hmac alg with PBKDF that has already been registered, skipping.");
    } else {
        result = acvp_append_name_list(&cap->hmac_algs, alg_str);
    }
    return result;
}

/*
 * The user should call this after invoking acvp_enable_kdf135_ssh_cap()
 * to specify the kdf parameters.
 */
ACVP_RESULT acvp_cap_kdf135_ssh_set_parm(ACVP_CTX *ctx,
                                         ACVP_CIPHER kcap,
                                         ACVP_KDF135_SSH_METHOD method,
                                         ACVP_HASH_ALG param) {
    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_SSH_CAP *kdf135_ssh_cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, kcap);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kdf135_ssh_cap = cap->cap.kdf135_ssh_cap;
    if (!kdf135_ssh_cap) {
        return ACVP_NO_CAP;
    }

    if (acvp_validate_kdf135_ssh_param_value(method, param) != ACVP_SUCCESS) {
        return ACVP_INVALID_ARG;
    }

    /* only support two method types so just use whichever is available */
    switch (method) {
    case ACVP_SSH_METH_TDES_CBC:
        kdf135_ssh_cap->method[0] = ACVP_SSH_METH_TDES_CBC;
        break;
    case ACVP_SSH_METH_AES_128_CBC:
        kdf135_ssh_cap->method[1] = ACVP_SSH_METH_AES_128_CBC;
        break;
    case ACVP_SSH_METH_AES_192_CBC:
        kdf135_ssh_cap->method[2] = ACVP_SSH_METH_AES_192_CBC;
        break;
    case ACVP_SSH_METH_AES_256_CBC:
        kdf135_ssh_cap->method[3] = ACVP_SSH_METH_AES_256_CBC;
        break;
    case ACVP_SSH_METH_MAX:
    default:
        return ACVP_INVALID_ARG;
    }

    kdf135_ssh_cap->sha = kdf135_ssh_cap->sha | param;

    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_kdf108_cap()
 * to specify the kdf parameters.
 */
ACVP_RESULT acvp_cap_kdf108_set_parm(ACVP_CTX *ctx,
                                     ACVP_KDF108_MODE mode,
                                     ACVP_KDF108_PARM param,
                                     int value) {
    ACVP_CAPS_LIST *cap;
    ACVP_KDF108_CAP *kdf108_cap;
    ACVP_KDF108_MODE_PARAMS *mode_obj;
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, ACVP_KDF108);

    if (!cap) {
        return ACVP_NO_CAP;
    }

    kdf108_cap = cap->cap.kdf108_cap;
    if (!kdf108_cap) {
        return ACVP_NO_CAP;
    }

    if (acvp_validate_kdf108_param_value(ctx, param, value) != ACVP_SUCCESS) {
        return ACVP_INVALID_ARG;
    }

    switch (mode) {
    case ACVP_KDF108_MODE_COUNTER:
        mode_obj = &cap->cap.kdf108_cap->counter_mode;
        if (!mode_obj->kdf_mode) {
            mode_obj->kdf_mode = ACVP_MODE_COUNTER;
        }
        break;
    case ACVP_KDF108_MODE_FEEDBACK:
        mode_obj = &cap->cap.kdf108_cap->feedback_mode;
        if (!mode_obj->kdf_mode) {
            mode_obj->kdf_mode = ACVP_MODE_FEEDBACK;
        }
        break;
    case ACVP_KDF108_MODE_DPI:
        mode_obj = &cap->cap.kdf108_cap->dpi_mode;
        if (!mode_obj->kdf_mode) {
            mode_obj->kdf_mode = ACVP_MODE_DPI;
        }
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    /* only support two method types so just use whichever is available */
    switch (param) {
    case ACVP_KDF108_MAC_MODE:
        switch (value) {
        case ACVP_KDF108_MAC_MODE_CMAC_AES128:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_CMAC_AES_128);
            break;
        case ACVP_KDF108_MAC_MODE_CMAC_AES192:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_CMAC_AES_192);
            break;
        case ACVP_KDF108_MAC_MODE_CMAC_AES256:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_CMAC_AES_256);
            break;
        case ACVP_KDF108_MAC_MODE_CMAC_TDES:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_CMAC_TDES);
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA1:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA1);
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA224:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA2_224);
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA256:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA2_256);
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA384:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA2_384);
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA512:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA2_512);
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA512_224:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA2_512_224);
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA512_256:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA2_512_256);
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA3_224:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA3_224);
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA3_256:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA3_256);
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA3_384:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA3_384);
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA3_512:
            result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA3_512);
            break;
        default:
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_KDF108_COUNTER_LEN:
        acvp_append_sl_list(&mode_obj->counter_lens, value);
        break;
    case ACVP_KDF108_FIXED_DATA_ORDER:
        switch (value) {
        case ACVP_KDF108_FIXED_DATA_ORDER_AFTER:
            result = acvp_append_name_list(&mode_obj->data_order, ACVP_FIXED_DATA_ORDER_AFTER_STR);
            break;
        case ACVP_KDF108_FIXED_DATA_ORDER_BEFORE:
            result = acvp_append_name_list(&mode_obj->data_order, ACVP_FIXED_DATA_ORDER_BEFORE_STR);
            break;
        case ACVP_KDF108_FIXED_DATA_ORDER_MIDDLE:
            result = acvp_append_name_list(&mode_obj->data_order, ACVP_FIXED_DATA_ORDER_MIDDLE_STR);
            break;
        case ACVP_KDF108_FIXED_DATA_ORDER_NONE:
            result = acvp_append_name_list(&mode_obj->data_order, ACVP_FIXED_DATA_ORDER_NONE_STR);
            break;
        case ACVP_KDF108_FIXED_DATA_ORDER_BEFORE_ITERATOR:
            result = acvp_append_name_list(&mode_obj->data_order, ACVP_FIXED_DATA_ORDER_BEFORE_ITERATOR_STR);
            break;
        default:
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_KDF108_SUPPORTS_EMPTY_IV:
        mode_obj->empty_iv_support = value;
        break;
    case ACVP_KDF108_REQUIRES_EMPTY_IV:
       if (mode_obj->empty_iv_support == 0) {
           ACVP_LOG_ERR("REQUIRES_EMPTY_IV for KDF108 can only be set if SUPPORTS_EMPTY_IV is true");
           return ACVP_INVALID_ARG;
       } else {
            mode_obj->requires_empty_iv = value;
       }
       break;
    case ACVP_KDF108_SUPPORTED_LEN:
        if (acvp_append_sl_list(&mode_obj->supported_lens.values, value) != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Error adding supported length for KDF108 to list");
            return ACVP_MALLOC_FAIL;
        }
        break;
    case ACVP_KDF108_PARAM_MIN:
    case ACVP_KDF108_PARAM_MAX:
    case ACVP_KDF108_KDF_MODE:
    default:
        return ACVP_INVALID_ARG;
    }

    return result;
}

/*
 * The user should call this after invoking acvp_enable_kdf135_ssh_cap()
 * to specify the kdf parameters.
 */
ACVP_RESULT acvp_cap_kdf135_srtp_set_parm(ACVP_CTX *ctx,
                                          ACVP_CIPHER cipher,
                                          ACVP_KDF135_SRTP_PARAM param,
                                          int value) {
    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_SRTP_CAP *kdf135_srtp_cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (cipher != ACVP_KDF135_SRTP) {
        return ACVP_INVALID_ARG;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kdf135_srtp_cap = cap->cap.kdf135_srtp_cap;
    if (!kdf135_srtp_cap) {
        return ACVP_NO_CAP;
    }

    if (acvp_validate_kdf135_srtp_param_value(param, value) != ACVP_SUCCESS) {
        return ACVP_INVALID_ARG;
    }

    /* only support two method types so just use whichever is available */
    switch (param) {
    case ACVP_SRTP_AES_KEYLEN:
        if (value != 128 && value != 192 && value != 256) {
            ACVP_LOG_ERR("invalid aes keylen");
            return ACVP_INVALID_ARG;
        }
        acvp_append_sl_list(&kdf135_srtp_cap->aes_keylens, value);
        break;
    case ACVP_SRTP_SUPPORT_ZERO_KDR:
        if (is_valid_tf_param(value) != ACVP_SUCCESS) {
            ACVP_LOG_ERR("invalid boolean for zero kdr support");
            return ACVP_INVALID_ARG;
        }
        kdf135_srtp_cap->supports_zero_kdr = value;
        break;
    case ACVP_SRTP_KDF_EXPONENT:
        if (!value || value > ACVP_KDF135_SRTP_KDR_MAX) {
            ACVP_LOG_ERR("invalid srtp exponent");
            return ACVP_INVALID_ARG;
        }
        kdf135_srtp_cap->kdr_exp[value - 1] = 1;
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_dsa_enable(ACVP_CTX *ctx,
                                ACVP_CIPHER cipher,
                                int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_DSA_TYPE, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_kdf135_ikev2_set_parm(ACVP_CTX *ctx,
                                           ACVP_KDF135_IKEV2_PARM param,
                                           int value) {
    ACVP_CAPS_LIST *cap_list = NULL;
    ACVP_KDF135_IKEV2_CAP *cap = NULL;
    ACVP_RESULT result = ACVP_SUCCESS;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF135_IKEV2);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_ikev2_cap;

    if (param != ACVP_KDF_HASH_ALG) {
        ACVP_LOG_ERR("Invalid param.");
        return ACVP_INVALID_ARG;
    }

    switch (value) {
    case ACVP_SHA1:
        result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA_1);
        break;
    case ACVP_SHA224:
        result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA2_224);
        break;
    case ACVP_SHA256:
        result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA2_256);
        break;
    case ACVP_SHA384:
        result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA2_384);
        break;
    case ACVP_SHA512:
        result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA2_512);
        break;
    default:
        ACVP_LOG_ERR("Invalid hash algorithm.");
        return ACVP_INVALID_ARG;
    }

    return result;
}

ACVP_RESULT acvp_cap_kdf135_ikev2_set_length(ACVP_CTX *ctx,
                                             ACVP_KDF135_IKEV2_PARM param,
                                             int value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_KDF135_IKEV2_CAP *cap;
    ACVP_JSON_DOMAIN_OBJ *domain;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF135_IKEV2);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_ikev2_cap;

    switch (param) {
    case ACVP_INIT_NONCE_LEN:
        if (value < ACVP_KDF135_IKEV2_INIT_NONCE_BIT_MIN ||
            value > ACVP_KDF135_IKEV2_INIT_NONCE_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap->init_nonce_len_domain;
        break;
    case ACVP_RESPOND_NONCE_LEN:
        if (value < ACVP_KDF135_IKEV2_RESP_NONCE_BIT_MIN ||
            value > ACVP_KDF135_IKEV2_RESP_NONCE_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap->respond_nonce_len_domain;
        break;
    case ACVP_DH_SECRET_LEN:
        if (value < ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MIN ||
            value > ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap->dh_secret_len;
        break;
    case ACVP_KEY_MATERIAL_LEN:
        if (value < ACVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MIN ||
            value > ACVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap->key_material_len;
        break;
    case ACVP_KDF_HASH_ALG:
    default:
        return ACVP_INVALID_ARG;
    }

    if (acvp_append_sl_list(&domain->values, value) != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Error adding provided length to list for IKEV2");
        return ACVP_MALLOC_FAIL;
    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_kdf135_ikev1_set_parm(ACVP_CTX *ctx,
                                           ACVP_KDF135_IKEV1_PARM param,
                                           int value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_KDF135_IKEV1_CAP *cap;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF135_IKEV1);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_ikev1_cap;

    if (param == ACVP_KDF_IKEv1_HASH_ALG) {
        switch (value) {
        case ACVP_SHA1:
            result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA_1);
            break;
        case ACVP_SHA224:
            result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA2_224);
            break;
        case ACVP_SHA256:
            result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA2_256);
            break;
        case ACVP_SHA384:
            result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA2_384);
            break;
        case ACVP_SHA512:
            result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA2_512);
            break;
        default:
            ACVP_LOG_ERR("Invalid hash algorithm.");
            return ACVP_INVALID_ARG;
        }
    } else if (param == ACVP_KDF_IKEv1_AUTH_METHOD) {
        switch (value) {
        case ACVP_KDF135_IKEV1_AMETH_DSA:
            strcpy_s(cap->auth_method, ACVP_AUTH_METHOD_STR_MAX_PLUS,
                     ACVP_AUTH_METHOD_DSA_STR);
            break;
        case ACVP_KDF135_IKEV1_AMETH_PSK:
            strcpy_s(cap->auth_method, ACVP_AUTH_METHOD_STR_MAX_PLUS,
                     ACVP_AUTH_METHOD_PSK_STR);
            break;
        case ACVP_KDF135_IKEV1_AMETH_PKE:
            strcpy_s(cap->auth_method, ACVP_AUTH_METHOD_STR_MAX_PLUS,
                     ACVP_AUTH_METHOD_PKE_STR);
            break;
        default:
            ACVP_LOG_ERR("Invalid authentication method.");
            return ACVP_INVALID_ARG;
        }
    } else {
        ACVP_LOG_ERR("Invalid param.");
        return ACVP_INVALID_ARG;
    }

    return result;
}

ACVP_RESULT acvp_cap_kdf135_x942_set_domain(ACVP_CTX *ctx,
                                             ACVP_KDF135_X942_PARM param,
                                             int min,
                                             int max,
                                             int increment) {
    ACVP_CAPS_LIST *cap_list = NULL;
    ACVP_KDF135_X942_CAP *cap = NULL;
    ACVP_JSON_DOMAIN_OBJ *domain = NULL;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF135_X942);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_x942_cap;

    if (acvp_validate_kdf135_x942_domain_value(param, min, max, increment) != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Invalid domain range provided for param %d in kdf135-x942", param);
        return ACVP_INVALID_ARG;
    }

    switch (param) {
    case ACVP_KDF_X942_KEY_LEN:
        domain = &cap->key_len;
        break;
    case ACVP_KDF_X942_OTHER_INFO_LEN:
        domain = &cap->other_len;
        break;
    case ACVP_KDF_X942_SUPP_INFO_LEN:
        domain = &cap->supp_len;
        break;
    case ACVP_KDF_X942_ZZ_LEN:
        domain = &cap->zz_len;
        break;
    case ACVP_KDF_X942_KDF_TYPE:
    case ACVP_KDF_X942_OID:
    case ACVP_KDF_X942_HASH_ALG:
    default:
        ACVP_LOG_ERR("Invalid domain parameter provided for kdf135-x942");
        return ACVP_INVALID_ARG;
    }

    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_kdf135_x942_set_parm(ACVP_CTX *ctx,
                                          ACVP_KDF135_X942_PARM param,
                                          int value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_KDF135_X942_CAP *cap;
    const char *alg = NULL;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF135_X942);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_x942_cap;

    switch (param) {
    case ACVP_KDF_X942_KDF_TYPE:
        if (value == ACVP_KDF_X942_KDF_TYPE_DER || value == ACVP_KDF_X942_KDF_TYPE_CONCAT) {
            cap->type = value;
        } else {
            ACVP_LOG_ERR("Invalid KDF type provided for kdf135-x942");
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_KDF_X942_HASH_ALG:
        alg = acvp_lookup_hash_alg_name(value);
        if (!alg) {
            ACVP_LOG_ERR("Invalid hash alg provided for kdf135-x942");
            return ACVP_INVALID_ARG;
        }
        acvp_append_name_list(&cap->hash_algs, alg);
        break;
    case ACVP_KDF_X942_OID:
        switch (value) {
        case ACVP_KDF_X942_OID_TDES:
            acvp_append_name_list(&cap->oids, "TDES");
            break;
        case ACVP_KDF_X942_OID_AES128KW:
            acvp_append_name_list(&cap->oids, "AES-128-KW");
            break;
        case ACVP_KDF_X942_OID_AES192KW:
            acvp_append_name_list(&cap->oids, "AES-192-KW");
            break;
        case ACVP_KDF_X942_OID_AES256KW:
            acvp_append_name_list(&cap->oids, "AES-256-KW");
            break;
        default:
            ACVP_LOG_ERR("Invalid OID provided for kdf135-x942");
            return ACVP_INVALID_ARG;
        break;
        }
        break;
    case ACVP_KDF_X942_KEY_LEN:
    case ACVP_KDF_X942_OTHER_INFO_LEN:
    case ACVP_KDF_X942_SUPP_INFO_LEN:
    case ACVP_KDF_X942_ZZ_LEN:
    default:
        ACVP_LOG_ERR("Invalid parameter provided for kdf135-x942");
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_kdf135_x963_set_parm(ACVP_CTX *ctx,
                                          ACVP_KDF135_X963_PARM param,
                                          int value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_KDF135_X963_CAP *cap;
    ACVP_RESULT result = ACVP_SUCCESS;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF135_X963);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_x963_cap;

    if (param == ACVP_KDF_X963_HASH_ALG) {
        switch (value) {
        case ACVP_SHA224:
            result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA2_224);
            break;
        case ACVP_SHA256:
            result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA2_256);
            break;
        case ACVP_SHA384:
            result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA2_384);
            break;
        case ACVP_SHA512:
            result = acvp_append_name_list(&cap->hash_algs, ACVP_STR_SHA2_512);
            break;
        default:
            ACVP_LOG_ERR("Invalid hash alg");
            return ACVP_INVALID_ARG;
        }
    } else {
        switch (param) {
        case ACVP_KDF_X963_KEY_DATA_LEN:
            if (value < ACVP_KDF135_X963_KEYDATA_MIN_BITS ||
                value > ACVP_KDF135_X963_KEYDATA_MAX_BITS) {
                ACVP_LOG_ERR("invalid key len value");
                return ACVP_INVALID_ARG;
            }
            acvp_append_sl_list(&cap->key_data_lengths, value);
            break;
        case ACVP_KDF_X963_FIELD_SIZE:
            if (value != ACVP_KDF135_X963_FIELD_SIZE_224 &&
                value != ACVP_KDF135_X963_FIELD_SIZE_233 &&
                value != ACVP_KDF135_X963_FIELD_SIZE_256 &&
                value != ACVP_KDF135_X963_FIELD_SIZE_283 &&
                value != ACVP_KDF135_X963_FIELD_SIZE_384 &&
                value != ACVP_KDF135_X963_FIELD_SIZE_409 &&
                value != ACVP_KDF135_X963_FIELD_SIZE_521 &&
                value != ACVP_KDF135_X963_FIELD_SIZE_571) {
                ACVP_LOG_ERR("invalid field size value");
                return ACVP_INVALID_ARG;
            }
            acvp_append_sl_list(&cap->field_sizes, value);
            break;
        case ACVP_KDF_X963_SHARED_INFO_LEN:
            if (value < ACVP_KDF135_X963_SHARED_INFO_LEN_MIN ||
                value > ACVP_KDF135_X963_SHARED_INFO_LEN_MAX) {
                ACVP_LOG_ERR("invalid shared info len value");
                return ACVP_INVALID_ARG;
            }
            acvp_append_sl_list(&cap->shared_info_lengths, value);
            break;
        case ACVP_KDF_X963_HASH_ALG:
        default:
            return ACVP_INVALID_ARG;
        }
    }

    return result;
}

ACVP_RESULT acvp_cap_kdf135_ikev2_set_domain(ACVP_CTX *ctx,
                                             ACVP_KDF135_IKEV2_PARM param,
                                             int min,
                                             int max,
                                             int increment) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_JSON_DOMAIN_OBJ *domain;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF135_IKEV2);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    switch (param) {
    case ACVP_INIT_NONCE_LEN:
        if (min < ACVP_KDF135_IKEV2_INIT_NONCE_BIT_MIN ||
            max > ACVP_KDF135_IKEV2_INIT_NONCE_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev2_cap->init_nonce_len_domain;
        break;
    case ACVP_RESPOND_NONCE_LEN:
        if (min < ACVP_KDF135_IKEV2_RESP_NONCE_BIT_MIN ||
            max > ACVP_KDF135_IKEV2_RESP_NONCE_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev2_cap->respond_nonce_len_domain;
        break;
    case ACVP_DH_SECRET_LEN:
        if (min < ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MIN ||
            max > ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev2_cap->dh_secret_len;
        break;
    case ACVP_KEY_MATERIAL_LEN:
        if (min < ACVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MIN ||
            max > ACVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev2_cap->key_material_len;
        break;
    case ACVP_KDF_HASH_ALG:
    default:
        return ACVP_INVALID_ARG;
    }

    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_kdf135_ikev1_set_domain(ACVP_CTX *ctx,
                                             ACVP_KDF135_IKEV1_PARM param,
                                             int min,
                                             int max,
                                             int increment) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_JSON_DOMAIN_OBJ *domain;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF135_IKEV1);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    switch (param) {
    case ACVP_KDF_IKEv1_INIT_NONCE_LEN:
        if (min < ACVP_KDF135_IKEV1_INIT_NONCE_BIT_MIN ||
            max > ACVP_KDF135_IKEV1_INIT_NONCE_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev1_cap->init_nonce_len_domain;
        break;
    case ACVP_KDF_IKEv1_RESPOND_NONCE_LEN:
        if (min < ACVP_KDF135_IKEV1_RESP_NONCE_BIT_MIN ||
            max > ACVP_KDF135_IKEV1_RESP_NONCE_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev1_cap->respond_nonce_len_domain;
        break;
    case ACVP_KDF_IKEv1_DH_SECRET_LEN:
        if (min < ACVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MIN ||
            max > ACVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev1_cap->dh_secret_len;
        break;
    case ACVP_KDF_IKEv1_PSK_LEN:
        if (min < ACVP_KDF135_IKEV1_PSK_BIT_MIN ||
            max > ACVP_KDF135_IKEV1_PSK_BIT_MAX) {
            ACVP_LOG_ERR("min or max outside of acceptable range");
            return ACVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev1_cap->psk_len;
        break;
    case ACVP_KDF_IKEv1_HASH_ALG:
    case ACVP_KDF_IKEv1_AUTH_METHOD:
    default:
        return ACVP_INVALID_ARG;
    }
    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_kdf108_set_domain(ACVP_CTX *ctx,
                                       ACVP_KDF108_MODE mode,
                                       ACVP_KDF108_PARM param,
                                       int min,
                                       int max,
                                       int increment) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_JSON_DOMAIN_OBJ *domain;
    ACVP_KDF108_MODE_PARAMS *mode_obj;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF108);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    if (!min || max > ACVP_KDF108_KEYIN_BIT_MAX) {
        ACVP_LOG_ERR("min and/or max outside acceptable range");
        return ACVP_INVALID_ARG;
    }

    switch (mode) {
    case ACVP_KDF108_MODE_COUNTER:
        mode_obj = &cap_list->cap.kdf108_cap->counter_mode;
        break;
    case ACVP_KDF108_MODE_FEEDBACK:
        mode_obj = &cap_list->cap.kdf108_cap->feedback_mode;
        break;
    case ACVP_KDF108_MODE_DPI:
        mode_obj = &cap_list->cap.kdf108_cap->dpi_mode;
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    switch (param) {
    case ACVP_KDF108_SUPPORTED_LEN:
        domain = &mode_obj->supported_lens;
        break;
    case ACVP_KDF108_KDF_MODE:
    case ACVP_KDF108_MAC_MODE:
    case ACVP_KDF108_FIXED_DATA_ORDER:
    case ACVP_KDF108_COUNTER_LEN:
    case ACVP_KDF108_SUPPORTS_EMPTY_IV:
    case ACVP_KDF108_REQUIRES_EMPTY_IV:
    case ACVP_KDF108_PARAM_MIN:
    case ACVP_KDF108_PARAM_MAX:
    default:
        return ACVP_INVALID_ARG;
    }
    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_kdf_tls12_enable(ACVP_CTX *ctx,
                                       int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
    }

    result = acvp_cap_list_append(ctx, ACVP_KDF_TLS12_TYPE, ACVP_KDF_TLS12, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

/*
 * The user should call this after invoking acvp_cap_kdf_tls12_enable()
 * to specify the kdf parameters.
 */
ACVP_RESULT acvp_cap_kdf_tls12_set_parm(ACVP_CTX *ctx,
                                         ACVP_KDF_TLS12_PARM param,
                                         int value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_KDF_TLS12_CAP *cap;
    ACVP_RESULT result = ACVP_SUCCESS;
    const char *alg_str = NULL;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF_TLS12);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found. You must enable algorithm before setting parameters.");
        return ACVP_NO_CAP;
    }

    cap = cap_list->cap.kdf_tls12_cap;
    if (!cap) {
        return ACVP_NO_CAP;
    }    

    switch(param) {
    case ACVP_KDF_TLS12_HASH_ALG:
        alg_str = acvp_lookup_hash_alg_name(value);
        if ((value != ACVP_SHA256 && value != ACVP_SHA384 && value != ACVP_SHA512) || !alg_str) {
            ACVP_LOG_ERR("Invalid value specified for TLS 1.2 alg.");
            return ACVP_INVALID_ARG;
        }
        if (acvp_is_in_name_list(cap->hash_algs, alg_str)) {
            ACVP_LOG_WARN("Attempting to register a hash alg with TLS 1.2 KDF that has already been registered, skipping.");
            return ACVP_SUCCESS;
        } else {
            result = acvp_append_name_list(&cap->hash_algs, alg_str);
        }
        break;
    case ACVP_KDF_TLS12_PARAM_MIN:
    default:
        return ACVP_INVALID_ARG;
    }

    return result;
}



ACVP_RESULT acvp_cap_kdf_tls13_enable(ACVP_CTX *ctx,
                                      int (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, ACVP_KDF_TLS13_TYPE, ACVP_KDF_TLS13, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_kdf_tls13_set_parm(ACVP_CTX *ctx,
                                        ACVP_KDF_TLS13_PARM param,
                                        int value) {
    ACVP_CAPS_LIST *cap_list = NULL;
    ACVP_KDF_TLS13_CAP *cap = NULL;
    ACVP_RESULT result = ACVP_SUCCESS;
    const char *alg_str = NULL;

    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF_TLS13);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found. You must enable algorithm before setting parameters.");
        return ACVP_NO_CAP;
    }
    cap = cap_list->cap.kdf_tls13_cap;

    switch(param) {
    case ACVP_KDF_TLS13_HMAC_ALG:
        alg_str = acvp_lookup_hash_alg_name(value);
        if ((value != ACVP_SHA256 && value != ACVP_SHA384) || !alg_str) {
            ACVP_LOG_ERR("Invalid value specified for TLS 1.3 hmac alg.");
            return ACVP_INVALID_ARG;
        }
        if (acvp_is_in_name_list(cap->hmac_algs, alg_str)) {
            ACVP_LOG_WARN("Attempting to register an hmac alg with TLS 1.3 KDF that has already been registered, skipping.");
            return ACVP_SUCCESS;
        } else {
            result = acvp_append_name_list(&cap->hmac_algs, alg_str);
        }
        break;
    case ACVP_KDF_TLS13_RUNNING_MODE:
        if (value <= ACVP_KDF_TLS13_RUN_MODE_MIN || value >= ACVP_KDF_TLS13_RUN_MODE_MAX) {
            ACVP_LOG_ERR("Invalid TLS 1.3 KDF running mode provided");
            return ACVP_INVALID_ARG;
        }
        result = acvp_append_param_list(&cap->running_mode, value);
        break;
    case ACVP_KDF_TLS13_PARAM_MIN:
    default:
        return ACVP_INVALID_ARG;
    }

    return result;

}
/*
 * Append a KAS-ECC pre req val to the capabilities
 */
static ACVP_RESULT acvp_add_kas_ecc_prereq_val(ACVP_CTX *ctx, ACVP_KAS_ECC_CAP_MODE *kas_ecc_mode,
                                               ACVP_KAS_ECC_MODE mode,
                                               ACVP_PREREQ_ALG pre_req,
                                               char *value) {
    ACVP_PREREQ_LIST *prereq_entry, *prereq_entry_2;

    ACVP_LOG_INFO("KAS-ECC mode %d", mode);
    prereq_entry = calloc(1, sizeof(ACVP_PREREQ_LIST));
    if (!prereq_entry) {
        return ACVP_MALLOC_FAIL;
    }
    prereq_entry->prereq_alg_val.alg = pre_req;
    prereq_entry->prereq_alg_val.val = value;

    /*
     * 1st entry
     */
    if (!kas_ecc_mode->prereq_vals) {
        kas_ecc_mode->prereq_vals = prereq_entry;
    } else {
        /*
         * append to the last in the list
         */
        prereq_entry_2 = kas_ecc_mode->prereq_vals;
        while (prereq_entry_2->next) {
            prereq_entry_2 = prereq_entry_2->next;
        }
        prereq_entry_2->next = prereq_entry;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_kas_ecc_set_prereq(ACVP_CTX *ctx,
                                        ACVP_CIPHER cipher,
                                        ACVP_KAS_ECC_MODE mode,
                                        ACVP_PREREQ_ALG pre_req,
                                        char *value) {
    ACVP_KAS_ECC_CAP_MODE *kas_ecc_mode;
    ACVP_KAS_ECC_CAP *kas_ecc_cap;
    ACVP_CAPS_LIST *cap_list;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    switch (pre_req) {
    case ACVP_PREREQ_CCM:
    case ACVP_PREREQ_CMAC:
    case ACVP_PREREQ_DRBG:
    case ACVP_PREREQ_ECDSA:
    case ACVP_PREREQ_HMAC:
    case ACVP_PREREQ_SHA:
        break;
    case ACVP_PREREQ_AES:
    case ACVP_PREREQ_DSA:
    case ACVP_PREREQ_KAS:
    case ACVP_PREREQ_SAFE_PRIMES:
    case ACVP_PREREQ_TDES:
    case ACVP_PREREQ_RSADP:
    case ACVP_PREREQ_RSA:
    case ACVP_PREREQ_KMAC:
    default:
        ACVP_LOG_ERR("\nUnsupported KAS-ECC prereq %d", pre_req);
        return ACVP_INVALID_ARG;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     */
    kas_ecc_cap = cap_list->cap.kas_ecc_cap;
    kas_ecc_mode = &kas_ecc_cap->kas_ecc_mode[mode - 1];

    /*
     * Add the value to the cap
     */
    return acvp_add_kas_ecc_prereq_val(ctx, kas_ecc_mode, mode, pre_req, value);
}

ACVP_RESULT acvp_cap_kas_ecc_enable(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_CAP_TYPE type = 0;
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_SUB_KAS alg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    alg = acvp_get_kas_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_KAS_ECC_CDH:
        type = ACVP_KAS_ECC_CDH_TYPE;
        break;
    case ACVP_SUB_KAS_ECC_COMP:
        type = ACVP_KAS_ECC_COMP_TYPE;
        break;
    case ACVP_SUB_KAS_ECC_NOCOMP:
        type = ACVP_KAS_ECC_NOCOMP_TYPE;
        break;
    case ACVP_SUB_KAS_ECC_SSC:
        type = ACVP_KAS_ECC_SSC_TYPE;
        break;
    case ACVP_SUB_KAS_FFC_COMP:
    case ACVP_SUB_KAS_FFC_NOCOMP:
    case ACVP_SUB_KAS_FFC_SSC: 
    case ACVP_SUB_KAS_IFC_SSC: 
    case ACVP_SUB_KTS_IFC: 
    case ACVP_SUB_KDA_ONESTEP:
    case ACVP_SUB_KDA_TWOSTEP:
    case ACVP_SUB_KDA_HKDF:
    case ACVP_SUB_SAFE_PRIMES_KEYGEN:
    case ACVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        ACVP_LOG_ERR("Invalid parameter 'cipher'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, type, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_kas_ecc_set_parm(ACVP_CTX *ctx,
                                      ACVP_CIPHER cipher,
                                      ACVP_KAS_ECC_MODE mode,
                                      ACVP_KAS_ECC_PARAM param,
                                      int value) {
    ACVP_CAPS_LIST *cap;
    ACVP_KAS_ECC_CAP *kas_ecc_cap;
    ACVP_KAS_ECC_CAP_MODE *kas_ecc_cap_mode;
    ACVP_SUB_KAS alg;
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    alg = acvp_get_kas_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_KAS_ECC_CDH:
    case ACVP_SUB_KAS_ECC_COMP:
    case ACVP_SUB_KAS_ECC_NOCOMP:
    case ACVP_SUB_KAS_ECC_SSC:
        break;
    case ACVP_SUB_KAS_FFC_COMP:
    case ACVP_SUB_KAS_FFC_NOCOMP:
    case ACVP_SUB_KAS_FFC_SSC: 
    case ACVP_SUB_KAS_IFC_SSC: 
    case ACVP_SUB_KTS_IFC: 
    case ACVP_SUB_KDA_ONESTEP:
    case ACVP_SUB_KDA_TWOSTEP:
    case ACVP_SUB_KDA_HKDF:
    case ACVP_SUB_SAFE_PRIMES_KEYGEN:
    case ACVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        ACVP_LOG_ERR("Invalid cipher");
        return ACVP_INVALID_ARG;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kas_ecc_cap = cap->cap.kas_ecc_cap;
    if (!kas_ecc_cap) {
        return ACVP_NO_CAP;
    }
    kas_ecc_cap_mode = &kas_ecc_cap->kas_ecc_mode[mode - 1];
    switch (mode) {
    case ACVP_KAS_ECC_MODE_CDH:
    case ACVP_KAS_ECC_MODE_NONE:
        switch (param) {
        case ACVP_KAS_ECC_FUNCTION:
            if (!value || value > ACVP_KAS_ECC_MAX_FUNCS) {
                ACVP_LOG_ERR("invalid kas ecc function");
                return ACVP_INVALID_ARG;
            }
            result = acvp_append_param_list(&kas_ecc_cap_mode->function, value);
            break;
        case ACVP_KAS_ECC_REVISION:
            if (cipher == ACVP_KAS_ECC_CDH) {
                if (value == ACVP_REVISION_SP800_56AR3) {
                    kas_ecc_cap_mode->revision = value;
                } else {
                    ACVP_LOG_ERR("Invalid revision value for KAS-ECC-CDH");
                    return ACVP_INVALID_ARG;
                }
            } else {
                ACVP_LOG_ERR("Unsupported KAS-ECC param %d", param);
                return ACVP_INVALID_ARG;
            }
            break;
        case ACVP_KAS_ECC_HASH:
            if ((value < ACVP_NO_SHA || value >= ACVP_HASH_ALG_MAX) && !(value & (value - 1))) {
                ACVP_LOG_ERR("Invalid hash alg value for KAS-ECC hash Z function");
                return ACVP_INVALID_ARG;
            }
            kas_ecc_cap_mode->hash = value;
            break;
        case ACVP_KAS_ECC_CURVE:
            if (value <= ACVP_EC_CURVE_START || value >= ACVP_EC_CURVE_END) {
                ACVP_LOG_ERR("invalid kas ecc curve attr");
                return ACVP_INVALID_ARG;
            }
            result = acvp_append_param_list(&kas_ecc_cap_mode->curve, value);
            break;
        case ACVP_KAS_ECC_NONE:
            if (cipher == ACVP_KAS_ECC_SSC) {
                break;
            } else {
                ACVP_LOG_ERR("\nUnsupported KAS-ECC param %d", param);
                return ACVP_INVALID_ARG;
            }
        case ACVP_KAS_ECC_ROLE:
        case ACVP_KAS_ECC_KDF:
        case ACVP_KAS_ECC_EB:
        case ACVP_KAS_ECC_EC:
        case ACVP_KAS_ECC_ED:
        case ACVP_KAS_ECC_EE:
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-ECC param %d", param);
            return ACVP_INVALID_ARG;

            break;
        }
        break;
    case ACVP_KAS_ECC_MODE_COMPONENT:
        switch (param) {
        case ACVP_KAS_ECC_FUNCTION:
            if (!value || value > ACVP_KAS_ECC_MAX_FUNCS) {
                ACVP_LOG_ERR("invalid kas ecc function");
                return ACVP_INVALID_ARG;
            }
            result = acvp_append_param_list(&kas_ecc_cap_mode->function, value);
            break;
        case ACVP_KAS_ECC_REVISION:
        case ACVP_KAS_ECC_CURVE:
        case ACVP_KAS_ECC_ROLE:
        case ACVP_KAS_ECC_KDF:
        case ACVP_KAS_ECC_EB:
        case ACVP_KAS_ECC_EC:
        case ACVP_KAS_ECC_ED:
        case ACVP_KAS_ECC_EE:
        case ACVP_KAS_ECC_NONE:
        case ACVP_KAS_ECC_HASH:
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-ECC param %d", param);
            return ACVP_INVALID_ARG;

            break;
        }
        break;
    case ACVP_KAS_ECC_MODE_NOCOMP:
    case ACVP_KAS_ECC_MAX_MODES:
    default:
        ACVP_LOG_ERR("\nUnsupported KAS-ECC mode %d", mode);
        return ACVP_INVALID_ARG;

        break;
    }
    return result;
}

ACVP_RESULT acvp_cap_kas_ecc_set_scheme(ACVP_CTX *ctx,
                                        ACVP_CIPHER cipher,
                                        ACVP_KAS_ECC_MODE mode,
                                        ACVP_KAS_ECC_SCHEMES scheme,
                                        ACVP_KAS_ECC_PARAM param,
                                        int option,
                                        int value) {
    ACVP_CAPS_LIST *cap;
    ACVP_KAS_ECC_CAP *kas_ecc_cap;
    ACVP_KAS_ECC_CAP_MODE *kas_ecc_cap_mode;
    ACVP_KAS_ECC_SCHEME *current_scheme;
    ACVP_KAS_ECC_PSET *current_pset;
    ACVP_KAS_ECC_PSET *last_pset = NULL;
    ACVP_SUB_KAS alg;
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    alg = acvp_get_kas_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_KAS_ECC_CDH:
    case ACVP_SUB_KAS_ECC_COMP:
    case ACVP_SUB_KAS_ECC_NOCOMP:
    case ACVP_SUB_KAS_ECC_SSC:
        break;
    case ACVP_SUB_KAS_FFC_COMP:
    case ACVP_SUB_KAS_FFC_NOCOMP:
    case ACVP_SUB_KAS_FFC_SSC:
    case ACVP_SUB_KAS_IFC_SSC: 
    case ACVP_SUB_KTS_IFC: 
    case ACVP_SUB_KDA_ONESTEP:
    case ACVP_SUB_KDA_TWOSTEP:
    case ACVP_SUB_KDA_HKDF:
    case ACVP_SUB_SAFE_PRIMES_KEYGEN:
    case ACVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        ACVP_LOG_ERR("Invalid cipher");
        return ACVP_INVALID_ARG;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kas_ecc_cap = cap->cap.kas_ecc_cap;
    if (!kas_ecc_cap) {
        return ACVP_NO_CAP;
    }
    kas_ecc_cap_mode = &kas_ecc_cap->kas_ecc_mode[mode - 1];
    switch (mode) {
    case ACVP_KAS_ECC_MODE_COMPONENT:
    case ACVP_KAS_ECC_MODE_NOCOMP:
    case ACVP_KAS_ECC_MODE_NONE:
        if (!scheme || scheme >= ACVP_KAS_ECC_SCHEMES_MAX) {
            ACVP_LOG_ERR("Invalid ecc scheme");
            return ACVP_INVALID_ARG;
        }
        current_scheme = kas_ecc_cap_mode->scheme;
        while (current_scheme) {
            if (current_scheme->scheme == scheme) {
                break;
            } else {
                current_scheme = current_scheme->next;
            }
        }
        /* if there are none or didn't find the one we're looking for... */
        if (current_scheme == NULL) {
            kas_ecc_cap_mode->scheme = calloc(1, sizeof(ACVP_KAS_ECC_SCHEME));
            kas_ecc_cap_mode->scheme->scheme = scheme;
            current_scheme = kas_ecc_cap_mode->scheme;
        }
        switch (param) {
        case ACVP_KAS_ECC_KDF:
            if (!value || value > ACVP_KAS_ECC_PARMSET) {
                return ACVP_INVALID_ARG;
            }
            current_scheme->kdf = (ACVP_KAS_ECC_SET)value;
            break;
        case ACVP_KAS_ECC_ROLE:
            if (value != ACVP_KAS_ECC_ROLE_INITIATOR &&
                value != ACVP_KAS_ECC_ROLE_RESPONDER) {
                return ACVP_INVALID_ARG;
            }
            result = acvp_append_param_list(&current_scheme->role, value);
            break;
        case ACVP_KAS_ECC_EB:
        case ACVP_KAS_ECC_EC:
        case ACVP_KAS_ECC_ED:
        case ACVP_KAS_ECC_EE:
            current_pset = current_scheme->pset;
            while (current_pset) {
                if (current_pset->set == param) {
                    break;
                } else {
                    last_pset = current_pset;
                    current_pset = current_pset->next;
                }
            }
            if (!current_pset) {
                current_pset = calloc(1, sizeof(ACVP_KAS_ECC_PSET));
                if (current_scheme->pset == NULL) {
                    current_scheme->pset = current_pset;
                } else {
                    last_pset->next = current_pset;
                }
                current_pset->set = param;
                current_pset->curve = option;
            }
            //then set sha in a param list
            result = acvp_append_param_list(&current_pset->sha, value);
            break;
        case ACVP_KAS_ECC_NONE:
            break;
        case ACVP_KAS_ECC_REVISION:
        case ACVP_KAS_ECC_CURVE:
        case ACVP_KAS_ECC_FUNCTION:
        case ACVP_KAS_ECC_HASH:
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-ECC param %d", param);
            return ACVP_INVALID_ARG;

            break;
        }
        break;
    case ACVP_KAS_ECC_MODE_CDH:
    case ACVP_KAS_ECC_MAX_MODES:
    default:
        ACVP_LOG_ERR("Scheme parameter sets not supported for this mode %d\n", mode);
        return ACVP_INVALID_ARG;

        break;
    }
    return result;
}

/*
 * Append a KAS-FFC pre req val to the capabilities
 */
static ACVP_RESULT acvp_add_kas_ffc_prereq_val(ACVP_CTX *ctx, ACVP_KAS_FFC_CAP_MODE *kas_ffc_mode,
                                               ACVP_KAS_FFC_MODE mode,
                                               ACVP_PREREQ_ALG pre_req,
                                               char *value) {
    ACVP_PREREQ_LIST *prereq_entry, *prereq_entry_2;

    ACVP_LOG_INFO("KAS-FFC mode %d", mode);
    prereq_entry = calloc(1, sizeof(ACVP_PREREQ_LIST));
    if (!prereq_entry) {
        return ACVP_MALLOC_FAIL;
    }
    prereq_entry->prereq_alg_val.alg = pre_req;
    prereq_entry->prereq_alg_val.val = value;

    /*
     * 1st entry
     */
    if (!kas_ffc_mode->prereq_vals) {
        kas_ffc_mode->prereq_vals = prereq_entry;
    } else {
        /*
         * append to the last in the list
         */
        prereq_entry_2 = kas_ffc_mode->prereq_vals;
        while (prereq_entry_2->next) {
            prereq_entry_2 = prereq_entry_2->next;
        }
        prereq_entry_2->next = prereq_entry;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_kas_ffc_set_prereq(ACVP_CTX *ctx,
                                        ACVP_CIPHER cipher,
                                        ACVP_KAS_FFC_MODE mode,
                                        ACVP_PREREQ_ALG pre_req,
                                        char *value) {
    ACVP_KAS_FFC_CAP_MODE *kas_ffc_mode;
    ACVP_KAS_FFC_CAP *kas_ffc_cap;
    ACVP_CAPS_LIST *cap_list;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    switch (pre_req) {
    case ACVP_PREREQ_CCM:
    case ACVP_PREREQ_CMAC:
    case ACVP_PREREQ_DRBG:
    case ACVP_PREREQ_DSA:
    case ACVP_PREREQ_HMAC:
    case ACVP_PREREQ_SHA:
    case ACVP_PREREQ_SAFE_PRIMES:
        break;
    case ACVP_PREREQ_AES:
    case ACVP_PREREQ_ECDSA:
    case ACVP_PREREQ_KAS:
    case ACVP_PREREQ_TDES:
    case ACVP_PREREQ_RSADP:
    case ACVP_PREREQ_RSA:
    case ACVP_PREREQ_KMAC:
    default:
        ACVP_LOG_ERR("\nUnsupported KAS-FFC prereq %d", pre_req);
        return ACVP_INVALID_ARG;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     */
    kas_ffc_cap = cap_list->cap.kas_ffc_cap;
    kas_ffc_mode = &kas_ffc_cap->kas_ffc_mode[mode - 1];

    /*
     * Add the value to the cap
     */
    return acvp_add_kas_ffc_prereq_val(ctx, kas_ffc_mode, mode, pre_req, value);
}

ACVP_RESULT acvp_cap_kas_ffc_enable(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_CAP_TYPE type = 0;
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_SUB_KAS alg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    alg = acvp_get_kas_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_KAS_FFC_SSC:
        type = ACVP_KAS_FFC_SSC_TYPE;
        break;
    case ACVP_SUB_KAS_FFC_COMP:
        type = ACVP_KAS_FFC_COMP_TYPE;
        break;
    case ACVP_SUB_KAS_FFC_NOCOMP:
        type = ACVP_KAS_FFC_NOCOMP_TYPE;
        break;
    case ACVP_SUB_KAS_ECC_CDH:
    case ACVP_SUB_KAS_ECC_COMP:
    case ACVP_SUB_KAS_ECC_NOCOMP:
    case ACVP_SUB_KAS_ECC_SSC:
    case ACVP_SUB_KAS_IFC_SSC: 
    case ACVP_SUB_KTS_IFC: 
    case ACVP_SUB_SAFE_PRIMES_KEYGEN:
    case ACVP_SUB_SAFE_PRIMES_KEYVER:
    case ACVP_SUB_KDA_ONESTEP:
    case ACVP_SUB_KDA_TWOSTEP:
    case ACVP_SUB_KDA_HKDF:
    default:
        ACVP_LOG_ERR("Invalid parameter 'cipher'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, type, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_kas_ffc_set_parm(ACVP_CTX *ctx,
                                      ACVP_CIPHER cipher,
                                      ACVP_KAS_FFC_MODE mode,
                                      ACVP_KAS_FFC_PARAM param,
                                      int value) {
    ACVP_CAPS_LIST *cap;
    ACVP_KAS_FFC_CAP *kas_ffc_cap;
    ACVP_KAS_FFC_CAP_MODE *kas_ffc_cap_mode;
    ACVP_SUB_KAS alg;
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    alg = acvp_get_kas_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_KAS_FFC_COMP:
    case ACVP_SUB_KAS_FFC_NOCOMP:
    case ACVP_SUB_KAS_FFC_SSC:
        break;
    case ACVP_SUB_KAS_ECC_CDH:
    case ACVP_SUB_KAS_ECC_COMP:
    case ACVP_SUB_KAS_ECC_NOCOMP:
    case ACVP_SUB_KAS_ECC_SSC: 
    case ACVP_SUB_KAS_IFC_SSC: 
    case ACVP_SUB_KTS_IFC: 
    case ACVP_SUB_KDA_ONESTEP:
    case ACVP_SUB_KDA_TWOSTEP:
    case ACVP_SUB_KDA_HKDF:
    case ACVP_SUB_SAFE_PRIMES_KEYGEN:
    case ACVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        ACVP_LOG_ERR("Invalid cipher");
        return ACVP_INVALID_ARG;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kas_ffc_cap = cap->cap.kas_ffc_cap;
    if (!kas_ffc_cap) {
        return ACVP_NO_CAP;
    }
    kas_ffc_cap_mode = &kas_ffc_cap->kas_ffc_mode[mode - 1];
    switch (mode) {
    case ACVP_KAS_FFC_MODE_COMPONENT:
        switch (param) {
        case ACVP_KAS_FFC_FUNCTION:
            if (!value || value > ACVP_KAS_FFC_MAX_FUNCS) {
                ACVP_LOG_ERR("invalid kas ffc function");
                return ACVP_INVALID_ARG;
            }
            result = acvp_append_param_list(&kas_ffc_cap_mode->function, value);
            break;
        case ACVP_KAS_FFC_CURVE:
        case ACVP_KAS_FFC_ROLE:
        case ACVP_KAS_FFC_KDF:
        case ACVP_KAS_FFC_FB:
        case ACVP_KAS_FFC_FC:
        case ACVP_KAS_FFC_MODP2048:
        case ACVP_KAS_FFC_MODP3072:
        case ACVP_KAS_FFC_MODP4096:
        case ACVP_KAS_FFC_MODP6144:
        case ACVP_KAS_FFC_MODP8192:
        case ACVP_KAS_FFC_FFDHE2048:
        case ACVP_KAS_FFC_FFDHE3072:
        case ACVP_KAS_FFC_FFDHE4096:
        case ACVP_KAS_FFC_FFDHE6144:
        case ACVP_KAS_FFC_FFDHE8192:
        case ACVP_KAS_FFC_HASH:
        case ACVP_KAS_FFC_GEN_METH:
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-FFC param %d", param);
            return ACVP_INVALID_ARG;

            break;
        }
        break;
    case ACVP_KAS_FFC_MODE_NONE:
        switch (param) {
        case ACVP_KAS_FFC_GEN_METH:
            result = acvp_append_param_list(&kas_ffc_cap_mode->genmeth, value);
            break;
        case ACVP_KAS_FFC_HASH:
            if ((value < ACVP_NO_SHA || value >= ACVP_HASH_ALG_MAX) && !(value & (value - 1))) {
                ACVP_LOG_ERR("Invalid hash alg value for KAS-FFC hash Z function");
                return ACVP_INVALID_ARG;
            }
            kas_ffc_cap_mode->hash = value;
            break;
        case ACVP_KAS_FFC_FUNCTION:
        case ACVP_KAS_FFC_CURVE:
        case ACVP_KAS_FFC_ROLE:
        case ACVP_KAS_FFC_KDF:
        case ACVP_KAS_FFC_FB:
        case ACVP_KAS_FFC_FC:
        case ACVP_KAS_FFC_MODP2048:
        case ACVP_KAS_FFC_MODP3072:
        case ACVP_KAS_FFC_MODP4096:
        case ACVP_KAS_FFC_MODP6144:
        case ACVP_KAS_FFC_MODP8192:
        case ACVP_KAS_FFC_FFDHE2048:
        case ACVP_KAS_FFC_FFDHE3072:
        case ACVP_KAS_FFC_FFDHE4096:
        case ACVP_KAS_FFC_FFDHE6144:
        case ACVP_KAS_FFC_FFDHE8192:
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-FFC param %d", param);
            return ACVP_INVALID_ARG;

            break;
        }
        break;
    case ACVP_KAS_FFC_MODE_NOCOMP:
    case ACVP_KAS_FFC_MAX_MODES:
    default:
        ACVP_LOG_ERR("\nUnsupported KAS-FFC mode %d", mode);
        return ACVP_INVALID_ARG;

        break;
    }
    return result;
}

ACVP_RESULT acvp_cap_kas_ffc_set_scheme(ACVP_CTX *ctx,
                                        ACVP_CIPHER cipher,
                                        ACVP_KAS_FFC_MODE mode,
                                        ACVP_KAS_FFC_SCHEMES scheme,
                                        ACVP_KAS_FFC_PARAM param,
                                        int value) {
    ACVP_CAPS_LIST *cap;
    ACVP_KAS_FFC_CAP *kas_ffc_cap;
    ACVP_KAS_FFC_CAP_MODE *kas_ffc_cap_mode;
    ACVP_KAS_FFC_SCHEME *current_scheme;
    ACVP_KAS_FFC_PSET *current_pset;
    ACVP_KAS_FFC_PSET *last_pset = NULL;
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kas_ffc_cap = cap->cap.kas_ffc_cap;
    if (!kas_ffc_cap) {
        return ACVP_NO_CAP;
    }
    kas_ffc_cap_mode = &kas_ffc_cap->kas_ffc_mode[mode - 1];
    switch (mode) {
    case ACVP_KAS_FFC_MODE_COMPONENT:
    case ACVP_KAS_FFC_MODE_NOCOMP:
    case ACVP_KAS_FFC_MODE_NONE:
        if (!scheme || scheme >= ACVP_KAS_FFC_MAX_SCHEMES) {
            ACVP_LOG_ERR("Invalid kas ffc scheme");
            return ACVP_INVALID_ARG;
        }
        current_scheme = kas_ffc_cap_mode->scheme;
        while (current_scheme) {
            if (current_scheme->scheme == scheme) {
                break;
            } else {
                current_scheme = current_scheme->next;
            }
        }
        /* if there are none or didn't find the one we're looking for... */
        if (current_scheme == NULL) {
            kas_ffc_cap_mode->scheme = calloc(1, sizeof(ACVP_KAS_FFC_SCHEME));
            kas_ffc_cap_mode->scheme->scheme = scheme;
            current_scheme = kas_ffc_cap_mode->scheme;
        }
        switch (param) {
        case ACVP_KAS_FFC_KDF:
            if (!value || value > ACVP_KAS_FFC_PARMSET) {
                return ACVP_INVALID_ARG;
            }
            current_scheme->kdf = (ACVP_KAS_FFC_SET)value;
            break;
        case ACVP_KAS_FFC_ROLE:
            if (value != ACVP_KAS_FFC_ROLE_INITIATOR &&
                value != ACVP_KAS_FFC_ROLE_RESPONDER) {
                return ACVP_INVALID_ARG;
            }
            result = acvp_append_param_list(&current_scheme->role, value);
            break;
        case ACVP_KAS_FFC_FB:
        case ACVP_KAS_FFC_FC:
        case ACVP_KAS_FFC_MODP2048:
        case ACVP_KAS_FFC_MODP3072:
        case ACVP_KAS_FFC_MODP4096:
        case ACVP_KAS_FFC_MODP6144:
        case ACVP_KAS_FFC_MODP8192:
        case ACVP_KAS_FFC_FFDHE2048:
        case ACVP_KAS_FFC_FFDHE3072:
        case ACVP_KAS_FFC_FFDHE4096:
        case ACVP_KAS_FFC_FFDHE6144:
        case ACVP_KAS_FFC_FFDHE8192:
            current_pset = current_scheme->pset;
            while (current_pset) {
                if (current_pset->set == param) {
                    break;
                } else {
                    last_pset = current_pset;
                    current_pset = current_pset->next;
                }
            }
            if (!current_pset) {
                current_pset = calloc(1, sizeof(ACVP_KAS_FFC_PSET));
                if (current_scheme->pset == NULL) {
                    current_scheme->pset = current_pset;
                } else {
                    last_pset->next = current_pset;
                }
                current_pset->set = param;
            }
            //then set sha in a param list
            result = acvp_append_param_list(&current_pset->sha, value);
            break;
        case ACVP_KAS_FFC_FUNCTION:
        case ACVP_KAS_FFC_CURVE:
        case ACVP_KAS_FFC_HASH:
        case ACVP_KAS_FFC_GEN_METH:
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-FFC param %d", param);
            return ACVP_INVALID_ARG;

            break;
        }
        break;
    case ACVP_KAS_FFC_MAX_MODES:
    default:
        ACVP_LOG_ERR("Scheme parameter sets not supported for this mode %d\n", mode);
        return ACVP_INVALID_ARG;

        break;
    }
    return result;
}

ACVP_RESULT acvp_cap_kas_ifc_enable(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_CAP_TYPE type = 0;
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }
    type = ACVP_KAS_IFC_TYPE;
    result = acvp_cap_list_append(ctx, type, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_kas_ifc_set_parm(ACVP_CTX *ctx,
                                      ACVP_CIPHER cipher,
                                      ACVP_KAS_IFC_PARAM param,
                                      int value) {

    ACVP_KAS_IFC_CAP *kas_ifc_cap = NULL;
    ACVP_CAPS_LIST *cap;
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kas_ifc_cap = cap->cap.kas_ifc_cap;
    if (!kas_ifc_cap) {
        return ACVP_NO_CAP;
    }

    switch (param)
    {
    case ACVP_KAS_IFC_KAS1:
        result = acvp_append_param_list(&kas_ifc_cap->kas1_roles, value);
        break;
    case ACVP_KAS_IFC_KAS2:
        result = acvp_append_param_list(&kas_ifc_cap->kas2_roles, value);
        break;
    case ACVP_KAS_IFC_KEYGEN_METHOD:
        result = acvp_append_param_list(&kas_ifc_cap->keygen_method, value);
        break;
    case ACVP_KAS_IFC_MODULO:
        acvp_append_sl_list(&kas_ifc_cap->modulo, value);
        break;
    case ACVP_KAS_IFC_HASH:
        if ((value < ACVP_NO_SHA || value >= ACVP_HASH_ALG_MAX) && !(value & (value - 1))) {
            ACVP_LOG_ERR("Invalid hash alg value for KAS-IFC hash Z function");
            return ACVP_INVALID_ARG;
        }
        kas_ifc_cap->hash = value;        
        break;
    case ACVP_KAS_IFC_FIXEDPUBEXP:
    default:
        ACVP_LOG_ERR("Invalid param");
        return ACVP_INVALID_ARG;
        break;
    }
    return result;
}

ACVP_RESULT acvp_cap_kas_ifc_set_exponent(ACVP_CTX *ctx,
                                          ACVP_CIPHER cipher,
                                          ACVP_KAS_IFC_PARAM param,
                                          char *value) {
    unsigned int len = strnlen_s(value, ACVP_CAPABILITY_STR_MAX + 1);
    ACVP_KAS_IFC_CAP *kas_ifc_cap = NULL;
    ACVP_CAPS_LIST *cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kas_ifc_cap = cap->cap.kas_ifc_cap;
    if (!kas_ifc_cap) {
        return ACVP_NO_CAP;
    }

    if (len > ACVP_CAPABILITY_STR_MAX) {
        ACVP_LOG_ERR("Parameter 'value' string is too long. "
                     "max allowed is (%d) characters.",
                      ACVP_CAPABILITY_STR_MAX);
        return ACVP_INVALID_ARG;
    }

    if (param != ACVP_KAS_IFC_FIXEDPUBEXP) {
        return ACVP_INVALID_ARG;
    }        
    kas_ifc_cap->fixed_pub_exp = calloc(len + 1, sizeof(char));
    strcpy_s(kas_ifc_cap->fixed_pub_exp, len + 1, value);
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_kda_enable(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_CAP_TYPE type = 0;
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_SUB_KAS alg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    alg = acvp_get_kas_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_KDA_ONESTEP:
        type = ACVP_KDA_ONESTEP_TYPE;
        break;
    case ACVP_SUB_KDA_TWOSTEP:
        type = ACVP_KDA_TWOSTEP_TYPE;
        break;
    case ACVP_SUB_KDA_HKDF:
        type = ACVP_KDA_HKDF_TYPE;
        break;
    case ACVP_SUB_KAS_ECC_CDH:
    case ACVP_SUB_KAS_ECC_COMP:
    case ACVP_SUB_KAS_ECC_NOCOMP:
    case ACVP_SUB_KAS_ECC_SSC:
    case ACVP_SUB_KAS_FFC_COMP:
    case ACVP_SUB_KAS_FFC_NOCOMP:
    case ACVP_SUB_KAS_FFC_SSC:
    case ACVP_SUB_KAS_IFC_SSC:
    case ACVP_SUB_KTS_IFC:
    case ACVP_SUB_SAFE_PRIMES_KEYGEN:
    case ACVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        ACVP_LOG_ERR("Invalid parameter 'cipher'");
        return ACVP_INVALID_ARG;
    }

    result = acvp_cap_list_append(ctx, type, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_kda_set_parm(ACVP_CTX *ctx, ACVP_CIPHER cipher, ACVP_KDA_PARM param,
                                      int value, const char* string) {
    ACVP_CAPS_LIST *cap_list = NULL;
    ACVP_RESULT result = ACVP_SUCCESS;
    const char* tmp = NULL;
    ACVP_SUB_KAS alg;
    ACVP_KDA_HKDF_CAP *hkdf_cap = NULL;
    ACVP_KDA_ONESTEP_CAP *os_cap = NULL;

    /*
     * Validate input
     */
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (param == ACVP_KDA_PATTERN && value == ACVP_KDA_PATTERN_LITERAL && !string) {
        ACVP_LOG_ERR("string must not be null when setting literal pattern for KDA algorithms.");
        return ACVP_INVALID_ARG;
    } 
    if (string && (param != ACVP_KDA_PATTERN || value != ACVP_KDA_PATTERN_LITERAL)) {
        ACVP_LOG_WARN("String parameter should only be used when setting literal pattern. Ignoring value...");
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    alg = acvp_get_kas_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return 1;
    }

    switch (alg) {
    case ACVP_SUB_KDA_ONESTEP:
        os_cap = cap_list->cap.kda_onestep_cap;
        if (!os_cap) {
            ACVP_LOG_ERR("KDA onestep cap entry not found.");
            return ACVP_NO_CAP;
        }
        switch (param) {
        case ACVP_KDA_PATTERN:
            if (value == ACVP_KDA_PATTERN_LITERAL && os_cap->literal_pattern_candidate) {
                ACVP_LOG_WARN("Literal pattern candidate was already previously set. Replacing...");
                free(os_cap->literal_pattern_candidate);
                os_cap->literal_pattern_candidate = NULL;
            }
            if (value == ACVP_KDA_PATTERN_LITERAL) {
                int len = strnlen_s(string, ACVP_KDA_PATTERN_LITERAL_STR_LEN_MAX + 1);
                if (len > ACVP_KDA_PATTERN_LITERAL_STR_LEN_MAX) {
                    ACVP_LOG_ERR("Provided literal string too long");
                    return ACVP_INVALID_ARG;
                } else if (len < 1) {
                    ACVP_LOG_ERR("Provided literal string empty");
                    return ACVP_INVALID_ARG;
                }
                os_cap->literal_pattern_candidate = calloc(ACVP_KDA_PATTERN_LITERAL_STR_LEN_MAX + 1, sizeof(char));
                if (!os_cap->literal_pattern_candidate) {
                    ACVP_LOG_ERR("Unable to allocate memory for literal pattern candidate");
                    return ACVP_MALLOC_FAIL;
                }
                strncpy_s(os_cap->literal_pattern_candidate, 
                          ACVP_KDA_PATTERN_LITERAL_STR_LEN_MAX, string, len);
            }
            if (value > ACVP_KDA_PATTERN_NONE && value < ACVP_KDA_PATTERN_MAX) {
                result = acvp_append_param_list(&os_cap->patterns, value);
            } else {
                ACVP_LOG_ERR("Invalid pattern type specified when setting param for KDA onestep.");
                return ACVP_INVALID_ARG;
            }
            break;
        case ACVP_KDA_REVISION:
            if (value != ACVP_REVISION_SP800_56CR1) {
                ACVP_LOG_ERR("Invalid revision for KDA specified.");
                return ACVP_INVALID_ARG;
            }
            os_cap->revision = value;
            break;
        case ACVP_KDA_ENCODING_TYPE:
            if (value > ACVP_KDA_ENCODING_NONE && value < ACVP_KDA_ENCODING_MAX) {
                result = acvp_append_param_list(&os_cap->encodings, value);
            } else {
                ACVP_LOG_ERR("Invalid encoding type specified when setting param for KDA onestep.");
                return ACVP_INVALID_ARG;
            }
            break;
        case ACVP_KDA_L:
            if (value <= 0) {
                ACVP_LOG_ERR("Valid for l must be > 0");
                return ACVP_INVALID_ARG;
            } else  if (value % 8 != 0) {
                ACVP_LOG_ERR("Value for l for KDA onestep must be convertable to exact bytes (mod 8)");
                return ACVP_INVALID_ARG;
            } else {
                os_cap->l = value;
            }
            break;
        case ACVP_KDA_MAC_SALT:
            if (value == ACVP_KDA_MAC_SALT_METHOD_DEFAULT) {
                result = acvp_append_name_list(&os_cap->mac_salt_methods,
                                               ACVP_KDA_MAC_SALT_METHOD_DEFAULT_STR);
            } else if (value == ACVP_KDA_MAC_SALT_METHOD_RANDOM) {
                result = acvp_append_name_list(&os_cap->mac_salt_methods,
                                               ACVP_KDA_MAC_SALT_METHOD_RANDOM_STR);
            } else {
                ACVP_LOG_ERR("Invalid value for ACVK_KDA_MAC_SALT");
                return ACVP_INVALID_ARG;
            }
            break;
        case ACVP_KDA_ONESTEP_AUX_FUNCTION:
            tmp = acvp_lookup_aux_function_alg_str(value);
            if (!tmp) {
                ACVP_LOG_ERR("Invalid aux function cipher provided");
                return ACVP_INVALID_ARG;
            }
            result = acvp_append_name_list(&os_cap->aux_functions, tmp);
            break;
        case ACVP_KDA_Z:
        case ACVP_KDA_USE_HYBRID_SECRET:
        case ACVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
        case ACVP_KDA_MAC_ALG:
        case ACVP_KDA_TWOSTEP_SUPPORTED_LEN:
        case ACVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
        case ACVP_KDA_TWOSTEP_COUNTER_LEN:
        case ACVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
        case ACVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
        default:
            ACVP_LOG_ERR("Invalid parameter specified");
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_SUB_KDA_HKDF:
        hkdf_cap = cap_list->cap.kda_hkdf_cap;
        if (!hkdf_cap) {
            ACVP_LOG_ERR("KDA-HKDF entry not found.");
            return ACVP_NO_CAP;
        }
        switch (param) {
        case ACVP_KDA_PATTERN:
            if (value == ACVP_KDA_PATTERN_LITERAL && hkdf_cap->literal_pattern_candidate) {
                ACVP_LOG_WARN("Literal pattern candidate was already previously set. Replacing...");
                free(hkdf_cap->literal_pattern_candidate);
                hkdf_cap->literal_pattern_candidate = NULL;
            }
            if (value == ACVP_KDA_PATTERN_LITERAL) {
                int len = strnlen_s(string, ACVP_KDA_PATTERN_LITERAL_STR_LEN_MAX + 1);
                if (len > ACVP_KDA_PATTERN_LITERAL_STR_LEN_MAX) {
                    ACVP_LOG_ERR("Provided literal string too long");
                    return ACVP_INVALID_ARG;
                } else if (len < 1) {
                    ACVP_LOG_ERR("Provided literal string empty");
                    return ACVP_INVALID_ARG;
                }
                hkdf_cap->literal_pattern_candidate = calloc(ACVP_KDA_PATTERN_LITERAL_STR_LEN_MAX + 1, sizeof(char));
                if (!hkdf_cap->literal_pattern_candidate) {
                    ACVP_LOG_ERR("Unable to allocate memory for literal pattern candidate");
                    return ACVP_MALLOC_FAIL;
                }
                strncpy_s(hkdf_cap->literal_pattern_candidate, 
                          ACVP_KDA_PATTERN_LITERAL_STR_LEN_MAX, string, len);
            }
            if (value == ACVP_KDA_PATTERN_T) {
                ACVP_LOG_ERR("T is only a valid pattern for KDA onestep");
                return ACVP_INVALID_ARG;
            }
            if (value > ACVP_KDA_PATTERN_NONE && value < ACVP_KDA_PATTERN_MAX) {
                result = acvp_append_param_list(&hkdf_cap->patterns, value);
            } else {
                ACVP_LOG_ERR("Invalid pattern type specified when setting param for KDA-HKDF.");
                return ACVP_INVALID_ARG;
            }
            break;
        case ACVP_KDA_REVISION:
            if (value != ACVP_REVISION_SP800_56CR1) {
                ACVP_LOG_ERR("Invalid revision for KDA specified.");
                return ACVP_INVALID_ARG;
            }
            hkdf_cap->revision = value;
            break;
        case ACVP_KDA_ENCODING_TYPE:
            if (value > ACVP_KDA_ENCODING_NONE && value < ACVP_KDA_ENCODING_MAX) {
                result = acvp_append_param_list(&hkdf_cap->encodings, value);
            } else {
                ACVP_LOG_ERR("Invalid encoding type specified when setting param for KDA-HKDF.");
                return ACVP_INVALID_ARG;
            }
            break;
        case ACVP_KDA_L:
            if (value <= 0) {
                ACVP_LOG_ERR("Valid for l must be > 0");
                return ACVP_INVALID_ARG;
            } else  if (value % 8 != 0) {
                ACVP_LOG_ERR("Value for l for KDA-HKDF must be convertable to exact bytes (mod 8)");
                return ACVP_INVALID_ARG;
            } else {
                hkdf_cap->l = value;
            }
            break;
        case ACVP_KDA_MAC_SALT:
            if (value == ACVP_KDA_MAC_SALT_METHOD_DEFAULT) {
                result = acvp_append_name_list(&hkdf_cap->mac_salt_methods,
                                               ACVP_KDA_MAC_SALT_METHOD_DEFAULT_STR);
            } else if (value == ACVP_KDA_MAC_SALT_METHOD_RANDOM) {
                result = acvp_append_name_list(&hkdf_cap->mac_salt_methods,
                                               ACVP_KDA_MAC_SALT_METHOD_RANDOM_STR);
            } else {
                ACVP_LOG_ERR("Invalid value for ACVK_KDA_MAC_SALT");
                return ACVP_INVALID_ARG;
            }
            break;
        case ACVP_KDA_MAC_ALG:
            tmp = acvp_lookup_hash_alg_name(value);
            if (!tmp) {
                ACVP_LOG_ERR("Invalid value for hmac alg for KDA-HKDF");
                return ACVP_INVALID_ARG;
            }
            result = acvp_append_name_list(&hkdf_cap->hmac_algs, tmp);
            break;
        case ACVP_KDA_USE_HYBRID_SECRET:
            /* revision is only set for non-default revisions */
            if (cap_list->cap.kda_hkdf_cap->revision) {
                ACVP_LOG_ERR("Hybrid secrets for HKDF can only be set for revision SP800-56Cr2");
                return ACVP_INVALID_ARG;
            }
            result = acvp_append_sl_list(&cap_list->cap.kda_hkdf_cap->aux_secret_len.values, value);
            if (result == ACVP_SUCCESS) {
                cap_list->cap.kda_hkdf_cap->use_hybrid_shared_secret = 1;
            }
            break;
        case ACVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
            if (value > 0) {
                hkdf_cap->perform_multi_expansion_tests = 1;
            } else {
                hkdf_cap->perform_multi_expansion_tests = 0;
            }
            break;
        case ACVP_KDA_Z:
        case ACVP_KDA_ONESTEP_AUX_FUNCTION:
        case ACVP_KDA_TWOSTEP_SUPPORTED_LEN:
        case ACVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
        case ACVP_KDA_TWOSTEP_COUNTER_LEN:
        case ACVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
        case ACVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
        default:
            ACVP_LOG_ERR("Invalid parameter specified");
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_SUB_KDA_TWOSTEP:
    case ACVP_SUB_KAS_ECC_CDH:
    case ACVP_SUB_KAS_ECC_COMP:
    case ACVP_SUB_KAS_ECC_NOCOMP:
    case ACVP_SUB_KAS_ECC_SSC:
    case ACVP_SUB_KAS_FFC_COMP:
    case ACVP_SUB_KAS_FFC_NOCOMP:
    case ACVP_SUB_KAS_FFC_SSC:
    case ACVP_SUB_KAS_IFC_SSC:
    case ACVP_SUB_KTS_IFC:
    case ACVP_SUB_SAFE_PRIMES_KEYGEN:
    case ACVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        ACVP_LOG_ERR("Invalid cipher specified");
        return ACVP_INVALID_ARG;
    }
    return result;
}

ACVP_RESULT acvp_cap_kda_twostep_set_parm(ACVP_CTX *ctx, ACVP_KDA_PARM param,
                                      int value, int kdf_mode, const char* string) {
    ACVP_CAPS_LIST *cap_list = NULL;
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_KDA_TWOSTEP_CAP *cap = NULL;
    ACVP_KDF108_MODE_PARAMS *mode_obj = NULL;

    /* Validate input */
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDA_TWOSTEP);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found. You must enable algorithm before setting parameters.");
        return ACVP_NO_CAP;
    }

    cap = cap_list->cap.kda_twostep_cap;
    if (!cap) {
        return ACVP_NO_CAP;
    }

    /* check if a valid KDF108 mode has been provided if needed */
    switch (param) {
    case ACVP_KDA_TWOSTEP_SUPPORTED_LEN:
    case ACVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
    case ACVP_KDA_TWOSTEP_COUNTER_LEN:
    case ACVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
    case ACVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
    case ACVP_KDA_MAC_ALG: 
        switch (kdf_mode) {
        case ACVP_KDF108_MODE_COUNTER:
            mode_obj = &cap->kdf_params.counter_mode;
            if (!mode_obj->kdf_mode) {
                mode_obj->kdf_mode = ACVP_MODE_COUNTER;
            }
            break;
        case ACVP_KDF108_MODE_DPI:
            mode_obj = &cap->kdf_params.dpi_mode;
            if (!mode_obj->kdf_mode) {
                mode_obj->kdf_mode = ACVP_MODE_DPI;
            }
            break;
        case ACVP_KDF108_MODE_FEEDBACK:
            mode_obj = &cap->kdf_params.feedback_mode;
            if (!mode_obj->kdf_mode) {
                mode_obj->kdf_mode = ACVP_MODE_FEEDBACK;
            }
            break;
        default:
            ACVP_LOG_ERR("Must use a valid KDF108 mode when setting certain parameters in KDA twostep");
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_KDA_PATTERN:
    case ACVP_KDA_ENCODING_TYPE:
    case ACVP_KDA_MAC_SALT:
    case ACVP_KDA_REVISION:
    case ACVP_KDA_L:
    case ACVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
    case ACVP_KDA_USE_HYBRID_SECRET:
    case ACVP_KDA_Z:
    case ACVP_KDA_ONESTEP_AUX_FUNCTION:
    default:
        break;
    }

    if (param == ACVP_KDA_PATTERN && value == ACVP_KDA_PATTERN_LITERAL && !string) {
        ACVP_LOG_ERR("string must not be null when setting literal pattern for KDA algorithms.");
        return ACVP_INVALID_ARG;
    } 
    if (string && (param != ACVP_KDA_PATTERN || value != ACVP_KDA_PATTERN_LITERAL)) {
        ACVP_LOG_WARN("String parameter should only be used when setting literal pattern. Ignoring value...");
    }

    switch (param) {
    case ACVP_KDA_PATTERN:
        if (value == ACVP_KDA_PATTERN_LITERAL && cap->literal_pattern_candidate) {
            ACVP_LOG_WARN("Literal pattern candidate was already previously set. Replacing...");
            free(cap->literal_pattern_candidate);
            cap->literal_pattern_candidate = NULL;
        }
        if (value == ACVP_KDA_PATTERN_LITERAL) {
            int len = strnlen_s(string, ACVP_KDA_PATTERN_LITERAL_STR_LEN_MAX + 1);
            if (len > ACVP_KDA_PATTERN_LITERAL_STR_LEN_MAX) {
                ACVP_LOG_ERR("Provided literal string too long");
                return ACVP_INVALID_ARG;
            } else if (len < 1) {
                ACVP_LOG_ERR("Provided literal string empty");
                return ACVP_INVALID_ARG;
            }
            cap->literal_pattern_candidate = calloc(ACVP_KDA_PATTERN_LITERAL_STR_LEN_MAX + 1, sizeof(char));
            if (!cap->literal_pattern_candidate) {
                ACVP_LOG_ERR("Unable to allocate memory for literal pattern candidate");
                return ACVP_MALLOC_FAIL;
            }
            strncpy_s(cap->literal_pattern_candidate, 
                        ACVP_KDA_PATTERN_LITERAL_STR_LEN_MAX, string, len);
        }
        if (value > ACVP_KDA_PATTERN_NONE && value < ACVP_KDA_PATTERN_MAX) {
            result = acvp_append_param_list(&cap->patterns, value);
        } else {
            ACVP_LOG_ERR("Invalid pattern type specified when setting param for KDA twostep.");
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_KDA_REVISION:
        if (value != ACVP_REVISION_SP800_56CR1) {
            ACVP_LOG_ERR("Invalid revision for KDA specified.");
            return ACVP_INVALID_ARG;
        }
        cap->revision = value;
        break;
    case ACVP_KDA_ENCODING_TYPE:
        if (value > ACVP_KDA_ENCODING_NONE && value < ACVP_KDA_ENCODING_MAX) {
            result = acvp_append_param_list(&cap->encodings, value);
        } else {
            ACVP_LOG_ERR("Invalid encoding type specified when setting param for KDA twostep.");
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_KDA_L:
        if (value <= 0) {
            ACVP_LOG_ERR("Valid for l must be > 0");
            return ACVP_INVALID_ARG;
        } else  if (value % 8 != 0) {
            ACVP_LOG_ERR("Value for l for KDA twostep must be convertable to exact bytes (mod 8)");
            return ACVP_INVALID_ARG;
        } else {
            cap->l = value;
        }
        break;
    case ACVP_KDA_MAC_SALT:
        if (value == ACVP_KDA_MAC_SALT_METHOD_DEFAULT) {
            result = acvp_append_name_list(&cap->mac_salt_methods,
                                            ACVP_KDA_MAC_SALT_METHOD_DEFAULT_STR);
        } else if (value == ACVP_KDA_MAC_SALT_METHOD_RANDOM) {
            result = acvp_append_name_list(&cap->mac_salt_methods,
                                            ACVP_KDA_MAC_SALT_METHOD_RANDOM_STR);
        } else {
            ACVP_LOG_ERR("Invalid value for ACVK_KDA_MAC_SALT");
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_KDA_MAC_ALG:
        switch (value) {
            case ACVP_KDF108_MAC_MODE_CMAC_AES128:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_CMAC_AES_128);
                break;
            case ACVP_KDF108_MAC_MODE_CMAC_AES192:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_CMAC_AES_192);
                break;
            case ACVP_KDF108_MAC_MODE_CMAC_AES256:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_CMAC_AES_256);
                break;
            case ACVP_KDF108_MAC_MODE_HMAC_SHA1:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA1);
                break;
            case ACVP_KDF108_MAC_MODE_HMAC_SHA224:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA2_224);
                break;
            case ACVP_KDF108_MAC_MODE_HMAC_SHA256:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA2_256);
                break;
            case ACVP_KDF108_MAC_MODE_HMAC_SHA384:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA2_384);
                break;
            case ACVP_KDF108_MAC_MODE_HMAC_SHA512:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA2_512);
                break;
            case ACVP_KDF108_MAC_MODE_HMAC_SHA512_224:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA2_512_224);
                break;
            case ACVP_KDF108_MAC_MODE_HMAC_SHA512_256:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA2_512_256);
                break;
            case ACVP_KDF108_MAC_MODE_HMAC_SHA3_224:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA3_224);
                break;
            case ACVP_KDF108_MAC_MODE_HMAC_SHA3_256:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA3_256);
                break;
            case ACVP_KDF108_MAC_MODE_HMAC_SHA3_384:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA3_384);
                break;
            case ACVP_KDF108_MAC_MODE_HMAC_SHA3_512:
                result = acvp_append_name_list(&mode_obj->mac_mode, ACVP_ALG_HMAC_SHA3_512);
                break;
            case ACVP_KDF108_MAC_MODE_CMAC_TDES:
            default:
                ACVP_LOG_ERR("Given MAC mode not supported for KDA Twostep");
                return ACVP_INVALID_ARG;
            }
        break;
    case ACVP_KDA_USE_HYBRID_SECRET:
        if (cap_list->cap.kda_twostep_cap->revision) {
            ACVP_LOG_ERR("Hybrid secrets for twostep can only be set for revision SP800-56Cr2");
            return ACVP_INVALID_ARG;
        }
        acvp_append_sl_list(&cap_list->cap.kda_twostep_cap->aux_secret_len.values, value);
        cap_list->cap.kda_twostep_cap->use_hybrid_shared_secret = 1;
        break;
    case ACVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
        if (value > 0) {
            cap->perform_multi_expansion_tests = 1;
        } else {
            cap->perform_multi_expansion_tests = 0;
        }
        break;
    /* For these, a KDF108 mode must be provided */
    case ACVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
        switch (value) {
        case ACVP_KDF108_FIXED_DATA_ORDER_AFTER:
            result = acvp_append_name_list(&mode_obj->data_order, ACVP_FIXED_DATA_ORDER_AFTER_STR);
            break;
        case ACVP_KDF108_FIXED_DATA_ORDER_BEFORE:
            result = acvp_append_name_list(&mode_obj->data_order, ACVP_FIXED_DATA_ORDER_BEFORE_STR);
            break;
        case ACVP_KDF108_FIXED_DATA_ORDER_MIDDLE:
            result = acvp_append_name_list(&mode_obj->data_order, ACVP_FIXED_DATA_ORDER_MIDDLE_STR);
            break;
        case ACVP_KDF108_FIXED_DATA_ORDER_NONE:
            result = acvp_append_name_list(&mode_obj->data_order, ACVP_FIXED_DATA_ORDER_NONE_STR);
            break;
        case ACVP_KDF108_FIXED_DATA_ORDER_BEFORE_ITERATOR:
            result = acvp_append_name_list(&mode_obj->data_order, ACVP_FIXED_DATA_ORDER_BEFORE_ITERATOR_STR);
            break;
        default:
            ACVP_LOG_ERR("Invalid fixed data order provided for KDA Twostep");
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_KDA_TWOSTEP_COUNTER_LEN:
        if (value < 1 || value > ACVP_KDF108_KEYIN_BIT_MAX) {
            printf("Invalid value provided for KDA twostep supported length");
            return ACVP_INVALID_ARG;
        }
        acvp_append_sl_list(&mode_obj->counter_lens, value);
        break;
    case ACVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
        mode_obj->empty_iv_support = value;
        break;
    case ACVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
        if (mode_obj->empty_iv_support == 0) {
            ACVP_LOG_ERR("REQUIRES_EMPTY_IV for twostep modes can only be set if SUPPORTS_EMPTY_IV is true");
            return ACVP_INVALID_ARG;
        } else {
            mode_obj->requires_empty_iv = value;
        }
        break;
    case ACVP_KDA_TWOSTEP_SUPPORTED_LEN:
        result = acvp_append_sl_list(&mode_obj->supported_lens.values, value);
        break;
    case ACVP_KDA_Z:
    case ACVP_KDA_ONESTEP_AUX_FUNCTION:
    default:
        ACVP_LOG_ERR("Invalid parameter specified %d", param);
        return ACVP_INVALID_ARG;
    }

    return result;
}

ACVP_RESULT acvp_cap_kda_twostep_set_domain(ACVP_CTX *ctx, ACVP_KDA_PARM param,
                                      int min, int max, int increment, int kdf_mode) {
    ACVP_CAPS_LIST *cap_list = NULL;
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_KDA_TWOSTEP_CAP *cap = NULL;
    ACVP_KDF108_MODE_PARAMS *mode_obj = NULL;

    /* Validate input */
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDA_TWOSTEP);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found. You must enable algorithm before setting parameters.");
        return ACVP_NO_CAP;
    }

    cap = cap_list->cap.kda_twostep_cap;
    if (!cap) {
        return ACVP_NO_CAP;
    }

    switch (param) {
    case ACVP_KDA_TWOSTEP_SUPPORTED_LEN:
        switch (kdf_mode) {
        case ACVP_KDF108_MODE_COUNTER:
            mode_obj = &cap->kdf_params.counter_mode;
            if (!mode_obj->kdf_mode) {
                mode_obj->kdf_mode = ACVP_MODE_COUNTER;
            }
            break;
        case ACVP_KDF108_MODE_DPI:
            mode_obj = &cap->kdf_params.dpi_mode;
            if (!mode_obj->kdf_mode) {
                mode_obj->kdf_mode = ACVP_MODE_DPI;
            }
            break;
        case ACVP_KDF108_MODE_FEEDBACK:
            mode_obj = &cap->kdf_params.feedback_mode;
            if (!mode_obj->kdf_mode) {
                mode_obj->kdf_mode = ACVP_MODE_FEEDBACK;
            }
            break;
        default:
            ACVP_LOG_ERR("Must use a valid KDF108 mode when setting certain parameters in KDA twostep");
            return ACVP_INVALID_ARG;
        }
        if (!increment) {
            ACVP_LOG_ERR("Invalid domain provided for KDA twostep supported len");
            return ACVP_INVALID_ARG;
        }
        mode_obj->supported_lens.min = min;
        mode_obj->supported_lens.max = max;
        mode_obj->supported_lens.increment = increment;
        break;
    case ACVP_KDA_Z:
        if (min < 224 || max > 65536 || increment % 8 != 0) {
            ACVP_LOG_ERR("Invalid Z domain provided for KDA twostep");
            return ACVP_INVALID_ARG;
        }
        cap->z.min = min;
        cap->z.max = max;
        cap->z.increment = increment;
        break;
    case ACVP_KDA_USE_HYBRID_SECRET:
        if (cap_list->cap.kda_twostep_cap->revision) {
            ACVP_LOG_ERR("Hybrid secrets for twostep can only be set for revision SP800-56Cr2");
            return ACVP_INVALID_ARG;
        }
        if (min < 112 || max > 65536 || increment % 8 != 0) {
            ACVP_LOG_ERR("Invalid aux secret len domain provided for twostep");
            return ACVP_INVALID_ARG;
        }
        cap->aux_secret_len.min = min;
        cap->aux_secret_len.max = max;
        cap->aux_secret_len.increment = increment;
        cap->use_hybrid_shared_secret = 1;
        break;
    case ACVP_KDA_PATTERN:
    case ACVP_KDA_REVISION:
    case ACVP_KDA_ENCODING_TYPE:
    case ACVP_KDA_L:
    case ACVP_KDA_MAC_SALT:
    case ACVP_KDA_MAC_ALG:
    case ACVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
    case ACVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
    case ACVP_KDA_TWOSTEP_COUNTER_LEN:
    case ACVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
    case ACVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
    case ACVP_KDA_ONESTEP_AUX_FUNCTION:
    default:
        ACVP_LOG_ERR("Invalid parameter specified %d", param);
        return ACVP_INVALID_ARG;
    }

    return result;
}

ACVP_RESULT acvp_cap_kda_set_domain(ACVP_CTX *ctx, ACVP_CIPHER cipher, ACVP_KDA_PARM param,
                                        int min, int max, int increment) {
    ACVP_CAPS_LIST *cap_list = NULL;
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_SUB_KAS alg;
    /*
     * Validate input
     */  
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    if (min < 0 || max < min || max - min < 8) {
        ACVP_LOG_ERR("Invalid domain given");
    }

    alg = acvp_get_kas_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return 1;
    }

    switch (alg) {
    case ACVP_SUB_KDA_ONESTEP:
        if (!cap_list->cap.kda_onestep_cap) {
            ACVP_LOG_ERR("KDA onestep cap entry not found.");
            return ACVP_NO_CAP;
        }

        switch(param) {
        case ACVP_KDA_Z:
            if (min < 224 || max > 65536 || increment % 8 != 0) {
                ACVP_LOG_ERR("Invalid Z domain provided for KDA onestep");
                return ACVP_INVALID_ARG;
            }
            cap_list->cap.kda_onestep_cap->z.min = min;
            cap_list->cap.kda_onestep_cap->z.max = max;
            cap_list->cap.kda_onestep_cap->z.increment = increment;
            break;
        case ACVP_KDA_USE_HYBRID_SECRET:
            ACVP_LOG_ERR("Hybrid secret only applies to HKDF and twostep, not onestep");
            return ACVP_INVALID_ARG;
        case ACVP_KDA_PATTERN:
        case ACVP_KDA_REVISION:
        case ACVP_KDA_ENCODING_TYPE:
        case ACVP_KDA_L:
        case ACVP_KDA_MAC_SALT:
        case ACVP_KDA_MAC_ALG:
        case ACVP_KDA_ONESTEP_AUX_FUNCTION:
        case ACVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
        case ACVP_KDA_TWOSTEP_SUPPORTED_LEN:
        case ACVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
        case ACVP_KDA_TWOSTEP_COUNTER_LEN:
        case ACVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
        case ACVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
        default:
            ACVP_LOG_ERR("Invalid domain param provided for KDA");
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_SUB_KDA_HKDF:
        if (!cap_list->cap.kda_hkdf_cap) {
            ACVP_LOG_ERR("KDA-HKDF entry not found.");
            return ACVP_NO_CAP;
        }

        switch(param) {
        case ACVP_KDA_Z:
            if (min < 224 || max > 65536 || increment % 8 != 0) {
                ACVP_LOG_ERR("Invalid Z domain provided for HKDF");
                return ACVP_INVALID_ARG;
            }
            cap_list->cap.kda_hkdf_cap->z.min = min;
            cap_list->cap.kda_hkdf_cap->z.max = max;
            cap_list->cap.kda_hkdf_cap->z.increment = increment;
            break;
        case ACVP_KDA_USE_HYBRID_SECRET:
            if (cap_list->cap.kda_hkdf_cap->revision) {
                ACVP_LOG_ERR("Hybrid secrets for HKDF can only be set for revision SP800-56Cr2");
                return ACVP_INVALID_ARG;
            }
            if (min < 112 || max > 65536 || increment % 8 != 0) {
                ACVP_LOG_ERR("Invalid aux secret len domain provided for HKDF");
                return ACVP_INVALID_ARG;
            }
            cap_list->cap.kda_hkdf_cap->aux_secret_len.min = min;
            cap_list->cap.kda_hkdf_cap->aux_secret_len.max = max;
            cap_list->cap.kda_hkdf_cap->aux_secret_len.increment = increment;
            cap_list->cap.kda_hkdf_cap->use_hybrid_shared_secret = 1;
            break;
        case ACVP_KDA_PATTERN:
        case ACVP_KDA_REVISION:
        case ACVP_KDA_ENCODING_TYPE:
        case ACVP_KDA_L:
        case ACVP_KDA_MAC_SALT:
        case ACVP_KDA_MAC_ALG:
        case ACVP_KDA_ONESTEP_AUX_FUNCTION:
        case ACVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
        case ACVP_KDA_TWOSTEP_SUPPORTED_LEN:
        case ACVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
        case ACVP_KDA_TWOSTEP_COUNTER_LEN:
        case ACVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
        case ACVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
        default:
            ACVP_LOG_ERR("Invalid domain param provided for KDA");
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_SUB_KDA_TWOSTEP:
    case ACVP_SUB_KAS_ECC_CDH:
    case ACVP_SUB_KAS_ECC_COMP:
    case ACVP_SUB_KAS_ECC_NOCOMP:
    case ACVP_SUB_KAS_ECC_SSC:
    case ACVP_SUB_KAS_FFC_COMP:
    case ACVP_SUB_KAS_FFC_NOCOMP:
    case ACVP_SUB_KAS_FFC_SSC:
    case ACVP_SUB_KAS_IFC_SSC:
    case ACVP_SUB_KTS_IFC:
    case ACVP_SUB_SAFE_PRIMES_KEYGEN:
    case ACVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        ACVP_LOG_ERR("Invalid cipher specified");
        return ACVP_INVALID_ARG;
    }
    return result;
}

ACVP_RESULT acvp_cap_kts_ifc_enable(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_CAP_TYPE type = 0;
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    type = ACVP_KTS_IFC_TYPE;

    result = acvp_cap_list_append(ctx, type, cipher, crypto_handler);

    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

ACVP_RESULT acvp_cap_kts_ifc_set_parm(ACVP_CTX *ctx,
                                      ACVP_CIPHER cipher,
                                      ACVP_KTS_IFC_PARAM param,
                                      int value) {

    ACVP_KTS_IFC_CAP *kts_ifc_cap = NULL;
    ACVP_CAPS_LIST *cap;
    ACVP_KTS_IFC_SCHEMES *current_scheme;
    ACVP_RESULT result = ACVP_SUCCESS;
    if (!ctx) {
        return ACVP_NO_CTX;
    }

      cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kts_ifc_cap = cap->cap.kts_ifc_cap;
    if (!kts_ifc_cap) {
        return ACVP_NO_CAP;
    }

    switch (param)
    {
    case ACVP_KTS_IFC_KEYGEN_METHOD:
        result = acvp_append_param_list(&kts_ifc_cap->keygen_method, value);
        break;
    case ACVP_KTS_IFC_FUNCTION:
        result = acvp_append_param_list(&kts_ifc_cap->functions, value);
        break;
    case ACVP_KTS_IFC_MODULO:
        acvp_append_sl_list(&kts_ifc_cap->modulo, value);
        break;
    case ACVP_KTS_IFC_SCHEME:
        current_scheme = kts_ifc_cap->schemes;
        if (current_scheme) {
            while (current_scheme->next) {
                current_scheme = current_scheme->next;
            }
            current_scheme->next = calloc(1, sizeof(ACVP_KTS_IFC_SCHEMES));
            current_scheme->next->scheme = value;
        } else {
            kts_ifc_cap->schemes = calloc(1, sizeof(ACVP_KTS_IFC_SCHEMES));
            kts_ifc_cap->schemes->scheme = value;
        }
        break;
    case ACVP_KTS_IFC_IUT_ID:
    case ACVP_KTS_IFC_FIXEDPUBEXP:
    case ACVP_KTS_IFC_KEYPAIR_GEN:
    case ACVP_KTS_IFC_PARTIAL_VAL:
    default:
        ACVP_LOG_ERR("Invalid param");
        return ACVP_INVALID_ARG;
        break;
    }
    return result;
}

ACVP_RESULT acvp_cap_kts_ifc_set_scheme_parm(ACVP_CTX *ctx,
                                             ACVP_CIPHER cipher,
                                             ACVP_KTS_IFC_SCHEME_TYPE scheme,
                                             ACVP_KTS_IFC_SCHEME_PARAM param,
                                             int value) {

    ACVP_KTS_IFC_CAP *kts_ifc_cap = NULL;
    ACVP_CAPS_LIST *cap;
    ACVP_KTS_IFC_SCHEMES *current_scheme;
    ACVP_RESULT result = ACVP_SUCCESS;
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kts_ifc_cap = cap->cap.kts_ifc_cap;
    if (!kts_ifc_cap) {
        return ACVP_NO_CAP;
    }

    current_scheme = kts_ifc_cap->schemes;
    if (!current_scheme) {
        return ACVP_NO_CAP;
    }

    while (current_scheme) {
        if (current_scheme->scheme != scheme) {
            current_scheme = current_scheme->next;
        }
        break;
    }
    if (!current_scheme) {
        return ACVP_NO_CAP;
    }

    switch (param)
    {
    case ACVP_KTS_IFC_NULL_ASSOC_DATA:
        current_scheme->null_assoc_data = value;
        break;
    case ACVP_KTS_IFC_L:
        current_scheme->l = value;
        break;
    case ACVP_KTS_IFC_ROLE:
        result = acvp_append_param_list(&current_scheme->roles, value);
        break;
    case ACVP_KTS_IFC_HASH:
        result = acvp_append_param_list(&current_scheme->hash, value);
        break;
    case ACVP_KTS_IFC_AD_PATTERN:
    case ACVP_KTS_IFC_ENCODING:
    case ACVP_KTS_IFC_MAC_METHODS:
    default:
        ACVP_LOG_ERR("Invalid param");
        return ACVP_INVALID_ARG;
        break;
    }
    return result;
}

ACVP_RESULT acvp_cap_kts_ifc_set_param_string(ACVP_CTX *ctx,
                                              ACVP_CIPHER cipher,
                                              ACVP_KTS_IFC_PARAM param,
                                              char *value) {
    unsigned int len = strnlen_s(value, ACVP_CAPABILITY_STR_MAX + 1);
    ACVP_KTS_IFC_CAP *kts_ifc_cap = NULL;
    ACVP_CAPS_LIST *cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kts_ifc_cap = cap->cap.kts_ifc_cap;
    if (!kts_ifc_cap) {
        return ACVP_NO_CAP;
    }

    if (len > ACVP_CAPABILITY_STR_MAX) {
        ACVP_LOG_ERR("Parameter 'value' string is too long. "
                     "max allowed is (%d) characters.",
                      ACVP_CAPABILITY_STR_MAX);
        return ACVP_INVALID_ARG;
    }
    switch (param)
    {
    case ACVP_KTS_IFC_FIXEDPUBEXP:
        kts_ifc_cap->fixed_pub_exp = calloc(len + 1, sizeof(char));
        strcpy_s(kts_ifc_cap->fixed_pub_exp, len + 1, value);
        break;
    case ACVP_KTS_IFC_IUT_ID:
        kts_ifc_cap->iut_id = calloc(len + 1, sizeof(char));
        strcpy_s(kts_ifc_cap->iut_id, len + 1, value);
        break;
    case ACVP_KTS_IFC_KEYGEN_METHOD:
    case ACVP_KTS_IFC_SCHEME:
    case ACVP_KTS_IFC_FUNCTION:
    case ACVP_KTS_IFC_MODULO:
    case ACVP_KTS_IFC_KEYPAIR_GEN:
    case ACVP_KTS_IFC_PARTIAL_VAL:
    default:
        ACVP_LOG_ERR("Invalid param");
        return ACVP_INVALID_ARG;
        break;
    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_kts_ifc_set_scheme_string(ACVP_CTX *ctx,
                                               ACVP_CIPHER cipher,
                                               ACVP_KTS_IFC_SCHEME_TYPE scheme,
                                               ACVP_KTS_IFC_PARAM param,
                                               char *value) {
    unsigned int len = strnlen_s(value, ACVP_CAPABILITY_STR_MAX + 1);
    ACVP_KTS_IFC_CAP *kts_ifc_cap = NULL;
    ACVP_CAPS_LIST *cap;
    ACVP_KTS_IFC_SCHEMES *current_scheme;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kts_ifc_cap = cap->cap.kts_ifc_cap;
    if (!kts_ifc_cap) {
        return ACVP_NO_CAP;
    }

    if (len > ACVP_CAPABILITY_STR_MAX) {
        ACVP_LOG_ERR("Parameter 'value' string is too long. "
                     "max allowed is (%d) characters.",
                      ACVP_CAPABILITY_STR_MAX);
        return ACVP_INVALID_ARG;
    }

    current_scheme = kts_ifc_cap->schemes;
    if (!current_scheme) {
        return ACVP_NO_CAP;
    }

    while (current_scheme) {
        if (current_scheme->scheme != scheme) {
            current_scheme = current_scheme->next;
        }
        break;
    }
    if (!current_scheme) {
        return ACVP_NO_CAP;
    }


    switch (param)
    {
    case ACVP_KTS_IFC_AD_PATTERN:
        current_scheme->assoc_data_pattern = calloc(len + 1, sizeof(char));
        strcpy_s(current_scheme->assoc_data_pattern, len + 1, value);
        break;
    case ACVP_KTS_IFC_ENCODING:
        current_scheme->encodings = calloc(len + 1, sizeof(char));
        strcpy_s(current_scheme->encodings, len + 1, value);
        break;
    case ACVP_KTS_IFC_NULL_ASSOC_DATA:
    case ACVP_KTS_IFC_HASH:
    case ACVP_KTS_IFC_ROLE:
    case ACVP_KTS_IFC_L:
    case ACVP_KTS_IFC_MAC_METHODS:
    case ACVP_KTS_IFC_FIXEDPUBEXP:
    default:
        ACVP_LOG_ERR("Invalid param");
        return ACVP_INVALID_ARG;
        break;
    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_safe_primes_enable(ACVP_CTX *ctx,
                                        ACVP_CIPHER cipher,
                                        int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_NO_CAP;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    if (cipher == ACVP_SAFE_PRIMES_KEYGEN) {
        result = acvp_cap_list_append(ctx, ACVP_SAFE_PRIMES_KEYGEN_TYPE, cipher, crypto_handler);
    } else if (cipher == ACVP_SAFE_PRIMES_KEYVER) {
        result = acvp_cap_list_append(ctx, ACVP_SAFE_PRIMES_KEYVER_TYPE, cipher, crypto_handler);
    } 
    if (result == ACVP_DUP_CIPHER) {
        ACVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == ACVP_MALLOC_FAIL) {
        ACVP_LOG_ERR("Failed to allocate capability object");
    } else if (result == ACVP_NO_CAP) {
        ACVP_LOG_ERR("Invalid capability");
        return ACVP_NO_CAP;
    }

    return result;
}

ACVP_RESULT acvp_cap_safe_primes_set_parm(ACVP_CTX *ctx,
                                          ACVP_CIPHER cipher,
                                          ACVP_SAFE_PRIMES_PARAM param,
                                          ACVP_SAFE_PRIMES_MODE mode) {
    ACVP_CAPS_LIST *cap;
    ACVP_SAFE_PRIMES_CAP *safe_primes_cap;
    ACVP_SAFE_PRIMES_CAP_MODE *safe_primes_cap_mode;
    ACVP_SUB_KAS alg;
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    if (cipher == ACVP_SAFE_PRIMES_KEYGEN) {
        safe_primes_cap = cap->cap.safe_primes_keygen_cap;
    } else if (cipher == ACVP_SAFE_PRIMES_KEYVER) {
        safe_primes_cap = cap->cap.safe_primes_keyver_cap;
    } else {
        ACVP_LOG_ERR("Invalid capability");
        return ACVP_NO_CAP;
    }

    if (!safe_primes_cap) {
        return ACVP_NO_CAP;
    }
    if (!safe_primes_cap->mode) {
        safe_primes_cap->mode = calloc(1, sizeof(ACVP_SAFE_PRIMES_CAP_MODE));
    }

    safe_primes_cap_mode = safe_primes_cap->mode;
    if (!safe_primes_cap_mode) {
        return ACVP_NO_CAP;
    }
    alg = acvp_get_kas_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    
    switch (alg) {
    case ACVP_SUB_SAFE_PRIMES_KEYVER:
        switch (param) {
        case ACVP_SAFE_PRIMES_GENMETH:
            result = acvp_append_param_list(&safe_primes_cap_mode->genmeth, mode);
            break;
        default:
            break;
        }
        break;
    case ACVP_SUB_SAFE_PRIMES_KEYGEN:
        switch (param) {
        case ACVP_SAFE_PRIMES_GENMETH:
            result = acvp_append_param_list(&safe_primes_cap_mode->genmeth, mode);
            break;
        default:
            break;
        }
        break;
    case ACVP_SUB_KAS_ECC_CDH:
    case ACVP_SUB_KAS_ECC_COMP:
    case ACVP_SUB_KAS_ECC_NOCOMP:
    case ACVP_SUB_KAS_ECC_SSC:
    case ACVP_SUB_KAS_FFC_SSC:
    case ACVP_SUB_KAS_FFC_COMP:
    case ACVP_SUB_KAS_FFC_NOCOMP:
    case ACVP_SUB_KAS_IFC_SSC:
    case ACVP_SUB_KTS_IFC:
    case ACVP_SUB_KDA_ONESTEP:
    case ACVP_SUB_KDA_TWOSTEP:
    case ACVP_SUB_KDA_HKDF:
    default:
        break;
    }
    return result;
}

ACVP_RESULT acvp_cap_lms_enable(ACVP_CTX *ctx,
                                ACVP_CIPHER cipher,
                                int (*crypto_handler)(ACVP_TEST_CASE *test_case)) {
    ACVP_RESULT result = ACVP_NO_CAP;
    ACVP_SUB_LMS alg;
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        ACVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return ACVP_INVALID_ARG;
    }

    alg = acvp_get_lms_alg(cipher);
    if (alg == 0) {
        ACVP_LOG_ERR("Invalid cipher value");
        return ACVP_INVALID_ARG;
    }
    switch (alg) {
    case ACVP_SUB_LMS_KEYGEN:
        result = acvp_cap_list_append(ctx, ACVP_LMS_KEYGEN_TYPE, cipher, crypto_handler);
        break;
    case ACVP_SUB_LMS_SIGGEN:
        result = acvp_cap_list_append(ctx, ACVP_LMS_SIGGEN_TYPE, cipher, crypto_handler);
        break;
    case ACVP_SUB_LMS_SIGVER:
        result = acvp_cap_list_append(ctx, ACVP_LMS_SIGVER_TYPE, cipher, crypto_handler);
        break;
    default:
        ACVP_LOG_ERR("Invalid cipher provided to acvp_cap_lms_enable()");
        break;
    }

    if (result != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Error occured while enabling LMS algorithm. rv: %d", result);
    }

    return result;
}

ACVP_RESULT acvp_cap_lms_set_parm(ACVP_CTX *ctx,
                                  ACVP_CIPHER cipher,
                                  ACVP_LMS_PARAM param, int value) {
    ACVP_CAPS_LIST *cap;
    ACVP_LMS_CAP *lms_cap;
    ACVP_SUB_LMS alg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }
    alg = acvp_get_lms_alg(cipher);
    switch (alg) {
    case ACVP_SUB_LMS_KEYGEN:
        lms_cap = cap->cap.lms_keygen_cap;
        break;
    case ACVP_SUB_LMS_SIGGEN:
        lms_cap = cap->cap.lms_siggen_cap;
        break;
    case ACVP_SUB_LMS_SIGVER:
        lms_cap = cap->cap.lms_sigver_cap;
        break;
    default:
        ACVP_LOG_ERR("Invalid cipher provided for setting LMS paramater");
        return ACVP_INVALID_ARG;
    }

    switch (param) {
    case ACVP_LMS_PARAM_LMS_MODE:
        if (value <= ACVP_LMS_MODE_NONE || value >= ACVP_LMS_MODE_MAX) {
            ACVP_LOG_ERR("Invalid LMS mode provided");
            return ACVP_INVALID_ARG;
        }
        return acvp_append_param_list(&lms_cap->lms_modes, value);
        break;
    case ACVP_LMS_PARAM_LMOTS_MODE:
        if (value <= ACVP_LMOTS_MODE_NONE || value >= ACVP_LMOTS_MODE_MAX) {
            ACVP_LOG_ERR("Invalid LMOTS mode provided");
            return ACVP_INVALID_ARG;
        }
        return acvp_append_param_list(&lms_cap->lmots_modes, value);
        break;
    default:
        break;
    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_cap_lms_set_mode_compatability_pair(ACVP_CTX *ctx,
                                                     ACVP_CIPHER cipher,
                                                     ACVP_LMS_MODE lms_mode,
                                                     ACVP_LMOTS_MODE lmots_mode) {
    ACVP_CAPS_LIST *cap;
    ACVP_LMS_CAP *lms_cap;
    ACVP_SUB_LMS alg;
    ACVP_LMS_SPECIFIC_LIST *list = NULL;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }
    alg = acvp_get_lms_alg(cipher);
    switch (alg) {
    case ACVP_SUB_LMS_KEYGEN:
        lms_cap = cap->cap.lms_keygen_cap;
        break;
    case ACVP_SUB_LMS_SIGGEN:
        lms_cap = cap->cap.lms_siggen_cap;
        break;
    case ACVP_SUB_LMS_SIGVER:
        lms_cap = cap->cap.lms_sigver_cap;
        break;
    default:
        ACVP_LOG_ERR("Invalid cipher provided for setting LMS mode pair");
        return ACVP_INVALID_ARG;
    }

    if (lms_mode <= ACVP_LMS_MODE_NONE || lms_mode >= ACVP_LMS_MODE_MAX) {
        ACVP_LOG_ERR("Invalid LMS mode provided");
        return ACVP_INVALID_ARG;
    }

    if (lmots_mode <= ACVP_LMOTS_MODE_NONE || lmots_mode >= ACVP_LMOTS_MODE_MAX) {
        ACVP_LOG_ERR("Invalid LMOTS mode provided");
        return ACVP_INVALID_ARG;
    }

    list = lms_cap->specific_list;
    if (!list) {
        lms_cap->specific_list = calloc(1, sizeof(ACVP_LMS_SPECIFIC_LIST));
        if (!lms_cap->specific_list) {
            return ACVP_MALLOC_FAIL;
        }
        lms_cap->specific_list->lms_mode = lms_mode;
        lms_cap->specific_list->lmots_mode = lmots_mode;
    } else {
        while (list->next) {
            list = list->next;
        }
        list->next = calloc(1, sizeof(ACVP_LMS_SPECIFIC_LIST));
        if (!list->next) {
            return ACVP_MALLOC_FAIL;
        }
        list->next->lms_mode = lms_mode;
        list->next->lmots_mode = lmots_mode;
    }

    return ACVP_SUCCESS;
}
