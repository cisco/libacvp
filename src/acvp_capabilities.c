/** @file */
/*****************************************************************************
* Copyright (c) 2018, Cisco Systems, Inc.
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
 * Adds the length provided to the linked list of
 * supported lengths.
 */
static ACVP_RESULT acvp_cap_add_length (ACVP_SL_LIST **list, int len) {
    ACVP_SL_LIST *l = *list;
    ACVP_SL_LIST *new_sl;
    
    /*
     * Allocate some space for the new entry
     */
    new_sl = calloc(1, sizeof(ACVP_SL_LIST));
    if (!new_sl) {
        return ACVP_MALLOC_FAIL;
    }
    new_sl->length = len;
    
    /*
     * See if we need to create the list first
     */
    if (!l) {
        *list = new_sl;
    } else {
        /*
         * Find the end of the list and add the new entry there
         */
        while (l->next) {
            l = l->next;
        }
        l->next = new_sl;
    }
    return ACVP_SUCCESS;
}

/*
 * Append a symmetric cipher capabilitiy to the
 * capabilities list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_sym_cipher_caps_entry (
        ACVP_CTX *ctx,
        ACVP_SYM_CIPHER_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.sym_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_SYM_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

/*
 * Append a hash capabilitiy to the
 * capabilities list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_hash_caps_entry (
        ACVP_CTX *ctx,
        ACVP_HASH_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.hash_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_HASH_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}


/*
 * Append a DRBG capability to the
 * capabilities list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_drbg_caps_entry (
        ACVP_CTX *ctx,
        ACVP_DRBG_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.drbg_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_DRBG_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

/*
 * Append an RSA capability to the
 * capabilities list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_rsa_keygen_caps_entry (
        ACVP_CTX *ctx,
        ACVP_RSA_KEYGEN_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.rsa_keygen_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_RSA_KEYGEN_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

/*
 * Append an ECDSA capability to the
 * capabilities list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_ecdsa_caps_entry (
        ACVP_CTX *ctx,
        ACVP_ECDSA_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->crypto_handler = crypto_handler;
    
    switch (cipher) {
    case ACVP_ECDSA_KEYGEN:
        cap_entry->cap.ecdsa_keygen_cap = cap;
        cap_entry->cap_type = ACVP_ECDSA_KEYGEN_TYPE;
        break;
    case ACVP_ECDSA_KEYVER:
        cap_entry->cap.ecdsa_keyver_cap = cap;
        cap_entry->cap_type = ACVP_ECDSA_KEYVER_TYPE;
        break;
    case ACVP_ECDSA_SIGGEN:
        cap_entry->cap.ecdsa_siggen_cap = cap;
        cap_entry->cap_type = ACVP_ECDSA_SIGGEN_TYPE;
        break;
    case ACVP_ECDSA_SIGVER:
        cap_entry->cap.ecdsa_sigver_cap = cap;
        cap_entry->cap_type = ACVP_ECDSA_SIGVER_TYPE;
        break;
    default:
        free(cap_entry);
        return ACVP_INVALID_ARG;
    }
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

/*
 * Append an RSA capability to the
 * capabilities list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_rsa_sig_caps_entry (
        ACVP_CTX *ctx,
        ACVP_RSA_SIG_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    if (cipher == ACVP_RSA_SIGGEN) {
        cap_entry->cap.rsa_siggen_cap = cap;
        cap_entry->cap_type = ACVP_RSA_SIGGEN_TYPE;
    } else if (cipher == ACVP_RSA_SIGVER) {
        cap_entry->cap.rsa_sigver_cap = cap;
        cap_entry->cap_type = ACVP_RSA_SIGVER_TYPE;
    }
    cap_entry->crypto_handler = crypto_handler;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

/*
 * Append hmac capability to the capabilities
 * list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_hmac_caps_entry (
        ACVP_CTX *ctx,
        ACVP_HMAC_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.hmac_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_HMAC_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

/*
 * Append cmac capability to the capabilities
 * list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_cmac_caps_entry (
        ACVP_CTX *ctx,
        ACVP_CMAC_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.cmac_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_CMAC_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

static ACVP_RESULT acvp_append_kdf135_tls_caps_entry (
        ACVP_CTX *ctx,
        ACVP_KDF135_TLS_CAP *cap,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = ACVP_KDF135_TLS;
    cap_entry->cap.kdf135_tls_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_KDF135_TLS_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_validate_kdf135_tls_param_value (ACVP_KDF135_TLS_METHOD method, ACVP_KDF135_TLS_CAP_PARM param) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;
    
    switch (method) {
    
    case ACVP_KDF135_TLS12:
        if ((param < ACVP_KDF135_TLS_CAP_MAX) && (param > 0)) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF135_TLS10_TLS11:
        if (param == 0) {
            retval = ACVP_SUCCESS;
        }
        break;
    default:
        break;
    }
    
    return retval;
}

static ACVP_RESULT acvp_append_kdf135_srtp_caps_entry (
        ACVP_CTX *ctx,
        ACVP_KDF135_SRTP_CAP *cap,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cap.kdf135_srtp_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cipher = ACVP_KDF135_SRTP;
    cap_entry->cap_type = ACVP_KDF135_SRTP_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_append_kdf135_ikev2_caps_entry (
        ACVP_CTX *ctx,
        ACVP_KDF135_IKEV2_CAP *cap,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cap.kdf135_ikev2_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cipher = ACVP_KDF135_IKEV2;
    cap_entry->cap_type = ACVP_KDF135_IKEV2_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_append_kdf135_x963_caps_entry (
        ACVP_CTX *ctx,
        ACVP_KDF135_X963_CAP *cap,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cap.kdf135_x963_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cipher = ACVP_KDF135_X963;
    cap_entry->cap_type = ACVP_KDF135_X963_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_append_kdf135_ikev1_caps_entry (
        ACVP_CTX *ctx,
        ACVP_KDF135_IKEV1_CAP *cap,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cap.kdf135_ikev1_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cipher = ACVP_KDF135_IKEV1;
    cap_entry->cap_type = ACVP_KDF135_IKEV1_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return ACVP_SUCCESS;
}


static ACVP_RESULT acvp_append_kdf108_caps_entry (
        ACVP_CTX *ctx,
        ACVP_KDF108_CAP *cap,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cap.kdf108_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cipher = ACVP_KDF108;
    cap_entry->cap_type = ACVP_KDF108_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_append_kdf135_snmp_caps_entry (
        ACVP_CTX *ctx,
        ACVP_KDF135_SNMP_CAP *cap,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cap.kdf135_snmp_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cipher = ACVP_KDF135_SNMP;
    cap_entry->cap_type = ACVP_KDF135_SNMP_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_append_kdf135_ssh_caps_entry (
        ACVP_CTX *ctx,
        ACVP_KDF135_SSH_CAP *cap,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = ACVP_KDF135_SSH;
    cap_entry->cap.kdf135_ssh_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_KDF135_SSH_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_validate_kdf135_ssh_param_value (ACVP_KDF135_SSH_METHOD method, ACVP_KDF135_SSH_CAP_PARM param) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;
    
    if ((method < ACVP_SSH_METH_MAX) && (method > 0)) {
        if ((param & ACVP_KDF135_SSH_CAP_SHA1) ||
            (param & ACVP_KDF135_SSH_CAP_SHA224) ||
            (param & ACVP_KDF135_SSH_CAP_SHA256) ||
            (param & ACVP_KDF135_SSH_CAP_SHA384) ||
            (param & ACVP_KDF135_SSH_CAP_SHA512)) {
            retval = ACVP_SUCCESS;
        }
    }
    return retval;
}

static ACVP_RESULT acvp_validate_kdf135_srtp_param_value (ACVP_KDF135_SRTP_PARAM param, int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;
    
    if ((param > ACVP_SRTP_PARAM_MIN) && (param < ACVP_SRTP_PARAM_MAX)) {
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
            break;
        }
    }
    return retval;
}

static ACVP_RESULT acvp_validate_kdf108_param_value (ACVP_KDF108_PARM param, int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;
    
    if ((param > ACVP_KDF108_PARAM_MIN) && (param < ACVP_KDF108_PARAM_MAX)) {
        switch (param) {
        case ACVP_KDF108_KDF_MODE:
            printf("No need to explicity enable mode string. It is set implicity as params are added to a mode.");
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
            retval = is_valid_tf_param(value);
            break;
        default:
            break;
        }
    }
    return retval;
}

/*
 * Append an DSA capability to the
 * capabilities list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_dsa_caps_entry (
        ACVP_CTX *ctx,
        ACVP_DSA_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.dsa_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_DSA_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

static ACVP_RESULT acvp_dsa_set_modulo (ACVP_DSA_CAP_MODE *dsa_cap_mode,
                                        ACVP_DSA_PARM param,
                                        ACVP_DSA_SHA value) {
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
    /* TODO check range of modulo and value */
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
static ACVP_RESULT acvp_add_dsa_mode_parm (ACVP_CTX *ctx,
                                           ACVP_DSA_CAP_MODE *dsa_cap_mode,
                                           ACVP_DSA_PARM param,
                                           ACVP_DSA_SHA value) {
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
static ACVP_RESULT acvp_add_dsa_pqggen_parm (ACVP_CTX *ctx,
                                             ACVP_DSA_CAP_MODE *dsa_cap_mode,
                                             ACVP_DSA_PARM param,
                                             int value
) {
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
    case ACVP_DSA_LN2048_224:
        return (acvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value));
        break;
    case ACVP_DSA_LN2048_256:
        return (acvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value));
        break;
    case ACVP_DSA_LN3072_256:
        return (acvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value));
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
static ACVP_RESULT acvp_add_dsa_keygen_parm (ACVP_CTX *ctx,
                                             ACVP_DSA_CAP_MODE *dsa_cap_mode,
                                             ACVP_DSA_PARM param,
                                             int value) {
    switch (param) {
    case ACVP_DSA_LN2048_224:
        return (acvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value));
        break;
    case ACVP_DSA_LN2048_256:
        return (acvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value));
        break;
    case ACVP_DSA_LN3072_256:
        return (acvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value));
        break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_append_kdf135_tpm_caps_entry (
        ACVP_CTX *ctx,
        ACVP_KDF135_TPM_CAP *cap,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = ACVP_KDF135_TPM;
    cap_entry->cap.kdf135_tpm_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_KDF135_TPM_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_validate_sym_cipher_parm_value (ACVP_CIPHER cipher, ACVP_SYM_CIPH_PARM parm, int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;
    
    switch (parm) {
    case ACVP_SYM_CIPH_KEYLEN:
        if (value == 128 || value == 168 || value == 192 || value == 256) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_SYM_CIPH_TAGLEN:
        switch (cipher) {
        case ACVP_AES_GCM:
        case ACVP_AES_CCM:
        case ACVP_AES_ECB:
        case ACVP_AES_CBC:
        case ACVP_AES_CFB1:
        case ACVP_AES_CFB8:
        case ACVP_AES_CFB128:
        case ACVP_AES_OFB:
        case ACVP_AES_CTR:
            if (value >= 4 && value <= 128) {
                retval = ACVP_SUCCESS;
            }
            break;
        default:
            break;
        }
        break;
    case ACVP_SYM_CIPH_IVLEN:
        if (value >= 8 && value <= 1024) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_SYM_CIPH_TWEAK:
        if (value >= ACVP_SYM_CIPH_TWEAK_HEX &&
            value < ACVP_SYM_CIPH_TWEAK_NONE) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_SYM_CIPH_AADLEN:
        switch (cipher) {
        case ACVP_AES_GCM:
        case ACVP_AES_CCM:
        case ACVP_AES_ECB:
        case ACVP_AES_CBC:
        case ACVP_AES_CFB1:
        case ACVP_AES_CFB8:
        case ACVP_AES_CFB128:
        case ACVP_AES_OFB:
        case ACVP_AES_CTR:
            if (value >= 0 && value <= 65536) {
                retval = ACVP_SUCCESS;
            }
            break;
        default:
            break;
        }
        break;
    case ACVP_SYM_CIPH_PTLEN:
        if (value >= 0 && value <= 65536) {
            retval = ACVP_SUCCESS;
        }
        break;
    default:
        break;
    }
    
    return retval;
}

static ACVP_RESULT acvp_validate_prereq_val (ACVP_CIPHER cipher, ACVP_PREREQ_ALG pre_req) {
    switch (cipher) {
    case ACVP_AES_GCM:
    case ACVP_AES_CCM:
    case ACVP_AES_ECB:
    case ACVP_AES_CFB1:
    case ACVP_AES_CFB8:
    case ACVP_AES_CFB128:
    case ACVP_AES_CTR:
    case ACVP_AES_OFB:
    case ACVP_AES_CBC:
    case ACVP_AES_KW:
    case ACVP_AES_KWP:
    case ACVP_AES_XTS:
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
    case ACVP_SHA1:
    case ACVP_SHA224:
    case ACVP_SHA256:
    case ACVP_SHA384:
    case ACVP_SHA512:
        return ACVP_INVALID_ARG;
        break;
    case ACVP_HASHDRBG:
    case ACVP_HMACDRBG:
    case ACVP_CTRDRBG:
        if (pre_req == ACVP_PREREQ_AES ||
            pre_req == ACVP_PREREQ_DRBG ||
            pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_TDES) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_HMAC_SHA1:
    case ACVP_HMAC_SHA2_224:
    case ACVP_HMAC_SHA2_256:
    case ACVP_HMAC_SHA2_384:
    case ACVP_HMAC_SHA2_512:
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
    case ACVP_ECDSA_KEYGEN:
    case ACVP_ECDSA_KEYVER:
    case ACVP_ECDSA_SIGGEN:
    case ACVP_ECDSA_SIGVER:
        if (pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_DRBG) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF135_TLS:
    case ACVP_KDF135_SNMP:
    case ACVP_KDF135_TPM:
        if (pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_HMAC) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF135_SSH:
        if (pre_req == ACVP_PREREQ_SHA ||
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
    case ACVP_KAS_ECC_COMP:
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
        if (pre_req == ACVP_PREREQ_DRBG ||
            pre_req == ACVP_PREREQ_HMAC ||
            pre_req == ACVP_PREREQ_CMAC ||
            pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_CCM ||
            pre_req == ACVP_PREREQ_DSA) {
            return ACVP_SUCCESS;
        }
        break;
    case ACVP_KDF135_X963:
        if (pre_req == ACVP_PREREQ_SHA) {
            return ACVP_SUCCESS;
        }
        break;
    default:
        break;
    }
    
    return ACVP_INVALID_ARG;
}

/*
 * Append a pre req val to the list of prereqs
 */
static ACVP_RESULT acvp_add_prereq_val (ACVP_CIPHER cipher,
                                        ACVP_CAPS_LIST *cap_list,
                                        ACVP_PREREQ_ALG pre_req, char *value) {
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
    return (ACVP_SUCCESS);
}

ACVP_RESULT acvp_enable_prereq_cap (ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    ACVP_PREREQ_ALG pre_req_cap,
                                    char *value) {
    ACVP_CAPS_LIST *cap_list;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!value || strnlen(value, 12) == 0) {
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
    return (acvp_add_prereq_val(cipher, cap_list, pre_req_cap, value));
}

/*
 * The user should call this after invoking acvp_enable_sym_cipher_cap()
 * to specify the supported key lengths, PT lengths, AAD lengths, IV
 * lengths, and tag lengths.  This is called by the user multiple times,
 * once for each length supported.
 */
ACVP_RESULT acvp_enable_sym_cipher_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_SYM_CIPH_PARM parm,
        int length) {
    
    ACVP_CAPS_LIST *cap;
    switch (cipher) {
    case ACVP_AES_GCM:
    case ACVP_AES_CCM:
    case ACVP_AES_ECB:
    case ACVP_AES_CBC:
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
        break;
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
    
    if (acvp_validate_sym_cipher_parm_value(cipher, parm, length) != ACVP_SUCCESS) {
        return ACVP_INVALID_ARG;
    }
    
    switch (parm) {
    case ACVP_SYM_CIPH_KEYLEN:
        acvp_cap_add_length(&cap->cap.sym_cap->keylen, length);
        break;
    case ACVP_SYM_CIPH_TAGLEN:
        acvp_cap_add_length(&cap->cap.sym_cap->taglen, length);
        break;
    case ACVP_SYM_CIPH_IVLEN:
        acvp_cap_add_length(&cap->cap.sym_cap->ivlen, length);
        break;
    case ACVP_SYM_CIPH_PTLEN:
        acvp_cap_add_length(&cap->cap.sym_cap->ptlen, length);
        break;
    case ACVP_SYM_CIPH_TWEAK:
        acvp_cap_add_length(&cap->cap.sym_cap->tweak, length);
        break;
    case ACVP_SYM_CIPH_AADLEN:
        acvp_cap_add_length(&cap->cap.sym_cap->aadlen, length);
        break;
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
ACVP_RESULT acvp_enable_sym_cipher_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_SYM_CIPH_DIR dir,
        ACVP_SYM_CIPH_KO keying_option,
        ACVP_SYM_CIPH_IVGEN_SRC ivgen_source,
        ACVP_SYM_CIPH_IVGEN_MODE ivgen_mode,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_SYM_CIPHER_CAP *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    switch (cipher) {
    case ACVP_AES_GCM:
    case ACVP_AES_CCM:
    case ACVP_AES_ECB:
    case ACVP_AES_CBC:
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
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    
    cap = calloc(1, sizeof(ACVP_SYM_CIPHER_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    //TODO: need to validate that cipher, mode, etc. are valid values
    //      we also need to make sure we're not adding a duplicate
    cap->direction = dir;
    cap->keying_option = keying_option;
    cap->ivgen_source = ivgen_source;
    cap->ivgen_mode = ivgen_mode;
    
    return (acvp_append_sym_cipher_caps_entry(ctx, cap, cipher, crypto_handler));
}

/*
 * Add Sym parms that are not length based
 */
ACVP_RESULT acvp_enable_sym_cipher_cap_value (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_SYM_CIPH_PARM param,
        int value
) {
    ACVP_CAPS_LIST *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    
    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }
    
    switch (param) {
    case ACVP_SYM_CIPH_KW_MODE:
        if (value < ACVP_SYM_KW_MAX) {
            cap->cap.sym_cap->kw_mode |= value;
        } else {
            return ACVP_INVALID_ARG;
        }
        break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_hash_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_HASH_CAP *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    cap = calloc(1, sizeof(ACVP_HASH_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    //TODO: need to validate that cipher, mode, etc. are valid values
    //      we also need to make sure we're not adding a duplicate
    
    return (acvp_append_hash_caps_entry(ctx, cap, cipher, crypto_handler));
}

static ACVP_RESULT acvp_validate_hash_parm_value (ACVP_HASH_PARM parm, int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;
    
    switch (parm) {
    case ACVP_HASH_IN_BIT:
    case ACVP_HASH_IN_EMPTY:
        retval = is_valid_tf_param(value);
        break;
    default:
        break;
    }
    
    return retval;
}

/*
 * Add HASH(SHA) parameters
 */
ACVP_RESULT acvp_enable_hash_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_HASH_PARM param,
        int value
) {
    ACVP_CAPS_LIST *cap;
    ACVP_HASH_CAP *hash_cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
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
    
    switch (cipher) {
    case ACVP_SHA1:
    case ACVP_SHA224:
    case ACVP_SHA256:
    case ACVP_SHA384:
    case ACVP_SHA512:
        switch (param) {
        case ACVP_HASH_IN_BIT:
            hash_cap->in_bit = value;
            break;
        case ACVP_HASH_IN_EMPTY:
            hash_cap->in_empty = value;
            break;
        default:
            return ACVP_INVALID_ARG;
            break;
        }
        break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_validate_hmac_parm_value (ACVP_CIPHER cipher,
                                                  ACVP_HMAC_PARM parm,
                                                  int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;
    int max_val = 0;
    
    switch (parm) {
    case ACVP_HMAC_KEYLEN_MIN:
    case ACVP_HMAC_KEYLEN_MAX:
        if (value >= 8 && value <= 524288) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_HMAC_MACLEN:
        switch (cipher) {
        case ACVP_HMAC_SHA1:
            max_val = 160;
            break;
        case ACVP_HMAC_SHA2_224:
        case ACVP_HMAC_SHA2_512_224:
        case ACVP_HMAC_SHA3_224:
            max_val = 224;
            break;
        case ACVP_HMAC_SHA2_256:
        case ACVP_HMAC_SHA2_512_256:
        case ACVP_HMAC_SHA3_256:
            max_val = 256;
            break;
        case ACVP_HMAC_SHA2_384:
        case ACVP_HMAC_SHA3_384:
            max_val = 384;
            break;
        case ACVP_HMAC_SHA2_512:
        case ACVP_HMAC_SHA3_512:
            max_val = 512;
            break;
        default:
            break;
        }
        if (value >= 32 && value <= max_val) {
            retval = ACVP_SUCCESS;
        }
        break;
    default:
        break;
    }
    
    return retval;
}

ACVP_RESULT acvp_enable_hmac_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_HMAC_CAP *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    switch (cipher) {
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
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    
    cap = calloc(1, sizeof(ACVP_HMAC_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    return (acvp_append_hmac_caps_entry(ctx, cap, cipher, crypto_handler));
}

/*
 * The user should call this after invoking acvp_enable_hmac_cap()
 * to specify the supported key ranges, keyblock value, and
 * suuported mac lengths. This is called by the user multiple times,
 * once for each length supported.
 */
ACVP_RESULT acvp_enable_hmac_cap_parm (
        ACVP_CTX *ctx,
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
        return ACVP_INVALID_ARG;
    }
    
    switch (parm) {
    case ACVP_HMAC_KEYLEN_MIN:
        cap->cap.hmac_cap->key_len_min = value;
        break;
    case ACVP_HMAC_KEYLEN_MAX:
        cap->cap.hmac_cap->key_len_max = value;
        break;
    case ACVP_HMAC_MACLEN:
        acvp_cap_add_length(&cap->cap.hmac_cap->mac_len, value);
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_validate_cmac_parm_value (ACVP_CMAC_PARM parm, int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;
    
    switch (parm) {
    case ACVP_CMAC_BLK_DIVISIBLE_1:
    case ACVP_CMAC_BLK_DIVISIBLE_2:
    case ACVP_CMAC_BLK_NOT_DIVISIBLE_1:
    case ACVP_CMAC_BLK_NOT_DIVISIBLE_2:
    case ACVP_CMAC_MSG_LEN_MAX:
        if (value >= 0 && value <= 524288 && value % 8 == 0) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_CMAC_MACLEN:
        // TODO: need to validate max vals based on cmac
        // mode... 128 for cmac-aes, 64 for cmac-tdes
        if (value >= 8 && value <= 524288 && value % 8 == 0) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_CMAC_KEYLEN:
        if (value == 128 || value == 192 || value == 256) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_CMAC_DIRECTION_GEN:
    case ACVP_CMAC_DIRECTION_VER:
        retval = is_valid_tf_param(value);
        break;
    case ACVP_CMAC_KEYING_OPTION:
        if (value == 1 || value == 2) {
            retval = ACVP_SUCCESS;
        }
        break;
    default:
        break;
    }
    
    return retval;
}

ACVP_RESULT acvp_enable_cmac_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CMAC_CAP *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    switch (cipher) {
    case ACVP_CMAC_AES:
    case ACVP_CMAC_TDES:
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    
    cap = calloc(1, sizeof(ACVP_CMAC_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    return (acvp_append_cmac_caps_entry(ctx, cap, cipher, crypto_handler));
}

/*
 * The user should call this after invoking acvp_enable_cmac_cap()
 * to specify the supported msg lengths, mac lengths, and diretion.
 * This is called by the user multiple times,
 * once for each length supported.
 */
ACVP_RESULT acvp_enable_cmac_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_CMAC_PARM parm,
        int value) {
    
    ACVP_CAPS_LIST *cap;
    
    /*
     * Locate this cipher in the caps array
     */
    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        ACVP_LOG_ERR("Cap entry not found, use acvp_enable_cmac_cipher_cap() first.");
        return ACVP_NO_CAP;
    }
    
    if (acvp_validate_cmac_parm_value(parm, value) != ACVP_SUCCESS) {
        return ACVP_INVALID_ARG;
    }
    
    switch (parm) {
    case ACVP_CMAC_BLK_DIVISIBLE_1:
        cap->cap.cmac_cap->msg_len[CMAC_BLK_DIVISIBLE_1] = value;
        break;
    case ACVP_CMAC_BLK_DIVISIBLE_2:
        cap->cap.cmac_cap->msg_len[CMAC_BLK_DIVISIBLE_2] = value;
        break;
    case ACVP_CMAC_BLK_NOT_DIVISIBLE_1:
        cap->cap.cmac_cap->msg_len[CMAC_BLK_NOT_DIVISIBLE_1] = value;
        break;
    case ACVP_CMAC_BLK_NOT_DIVISIBLE_2:
        cap->cap.cmac_cap->msg_len[CMAC_BLK_NOT_DIVISIBLE_2] = value;
        break;
    case ACVP_CMAC_MSG_LEN_MAX:
        cap->cap.cmac_cap->msg_len[CMAC_MSG_LEN_MAX] = value;
        break;
    case ACVP_CMAC_DIRECTION_GEN:
        cap->cap.cmac_cap->direction_gen = value;
        break;
    case ACVP_CMAC_DIRECTION_VER:
        cap->cap.cmac_cap->direction_ver = value;
        break;
    case ACVP_CMAC_MACLEN:
        acvp_cap_add_length(&cap->cap.cmac_cap->mac_len, value);
        break;
    case ACVP_CMAC_KEYLEN:
        acvp_cap_add_length(&cap->cap.cmac_cap->key_len, value);
        break;
    case ACVP_CMAC_KEYING_OPTION:
        if (cipher == ACVP_CMAC_TDES) {
            acvp_cap_add_length(&cap->cap.cmac_cap->keying_option, value);
            break;
        }
    default:
        return ACVP_INVALID_ARG;
    }
    
    return ACVP_SUCCESS;
}

/*
 * Add DRBG Length Range
 */
static ACVP_RESULT acvp_add_drbg_length_range (
        ACVP_DRBG_CAP_MODE *drbg_cap_mode,
        ACVP_DRBG_PARM param,
        int min,
        int step,
        int max
) {
    if (!drbg_cap_mode) {
        return ACVP_INVALID_ARG;
    }
    
    switch (param) {
    case ACVP_DRBG_ENTROPY_LEN:
        drbg_cap_mode->entropy_len_min = min;
        drbg_cap_mode->entropy_len_step = step;
        drbg_cap_mode->entropy_len_max = max;
        break;
    case ACVP_DRBG_NONCE_LEN:
        drbg_cap_mode->nonce_len_min = min;
        drbg_cap_mode->nonce_len_step = step;
        drbg_cap_mode->nonce_len_max = max;
        break;
    case ACVP_DRBG_PERSO_LEN:
        drbg_cap_mode->perso_len_min = min;
        drbg_cap_mode->perso_len_step = step;
        drbg_cap_mode->perso_len_max = max;
        break;
    case ACVP_DRBG_ADD_IN_LEN:
        drbg_cap_mode->additional_in_len_min = min;
        drbg_cap_mode->additional_in_len_step = step;
        drbg_cap_mode->additional_in_len_max = max;
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

ACVP_RESULT acvp_enable_drbg_length_cap (ACVP_CTX *ctx,
                                         ACVP_CIPHER cipher,
                                         ACVP_DRBG_MODE mode,
                                         ACVP_DRBG_PARM param,
                                         int min,
                                         int step,
                                         int max) {
    ACVP_DRBG_CAP_MODE_LIST *drbg_cap_mode_list;
    ACVP_CAPS_LIST *cap_list;
    
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
    drbg_cap_mode_list = acvp_locate_drbg_mode_entry(cap_list, mode);
    if (!drbg_cap_mode_list) {
        drbg_cap_mode_list = calloc(1, sizeof(ACVP_DRBG_CAP_MODE_LIST));
        if (!drbg_cap_mode_list) {
            ACVP_LOG_ERR("Malloc Failed.");
            return ACVP_MALLOC_FAIL;
        }
        drbg_cap_mode_list->cap_mode.mode = mode;
        cap_list->cap.drbg_cap->drbg_cap_mode_list = drbg_cap_mode_list;
    }
    
    /*
     * Add the length range to the cap
     */
    return (acvp_add_drbg_length_range(&drbg_cap_mode_list->cap_mode,
                                       param, min, step, max));
}

static ACVP_RESULT acvp_validate_drbg_parm_value (ACVP_DRBG_PARM parm, int value) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;
    
    switch (parm) {
    case ACVP_DRBG_DER_FUNC_ENABLED:
    case ACVP_DRBG_PRED_RESIST_ENABLED:
    case ACVP_DRBG_RESEED_ENABLED:
        retval = is_valid_tf_param(value);
        break;
    case ACVP_DRBG_ENTROPY_LEN:
    case ACVP_DRBG_NONCE_LEN:
    case ACVP_DRBG_PERSO_LEN:
    case ACVP_DRBG_ADD_IN_LEN:
    case ACVP_DRBG_RET_BITS_LEN:
    case ACVP_DRBG_PRE_REQ_VALS:
        // TODO: add proper validation for these parameters
        retval = ACVP_SUCCESS;
        break;
    default:
        break;
    }
    
    return retval;
}

/*
 * Add CTR DRBG parameters
 */
static ACVP_RESULT acvp_add_ctr_drbg_cap_parm (
        ACVP_DRBG_CAP_MODE *drbg_cap_mode,
        ACVP_DRBG_MODE mode,
        ACVP_DRBG_PARM param,
        int value
) {
    if (!drbg_cap_mode) {
        return ACVP_INVALID_ARG;
    }
    
    if (acvp_validate_drbg_parm_value(param, value) != ACVP_SUCCESS) {
        return ACVP_INVALID_ARG;
    }
    
    switch (mode) {
    case ACVP_DRBG_3KEYTDEA:
    case ACVP_DRBG_AES_128:
    case ACVP_DRBG_AES_192:
    case ACVP_DRBG_AES_256:
        drbg_cap_mode->mode = mode;
        switch (param) {
        case ACVP_DRBG_DER_FUNC_ENABLED:
            drbg_cap_mode->der_func_enabled = value;
            break;
        case ACVP_DRBG_PRED_RESIST_ENABLED:
            drbg_cap_mode->pred_resist_enabled = value;
            break;
        case ACVP_DRBG_RESEED_ENABLED:
            drbg_cap_mode->reseed_implemented = value;
            break;
        case ACVP_DRBG_ENTROPY_LEN:
            drbg_cap_mode->entropy_input_len = value;
            break;
        case ACVP_DRBG_NONCE_LEN:
            drbg_cap_mode->nonce_len = value;
            break;
        case ACVP_DRBG_PERSO_LEN:
            drbg_cap_mode->perso_string_len = value;
            break;
        case ACVP_DRBG_ADD_IN_LEN:
            drbg_cap_mode->additional_input_len = value;
            break;
        case ACVP_DRBG_RET_BITS_LEN:
            drbg_cap_mode->returned_bits_len = value;
            break;
        case ACVP_DRBG_PRE_REQ_VALS:
        default:
            break;
        }
        break;
    
    
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    
    return ACVP_SUCCESS;
}

/*
 * Add HASH DRBG parameters
 */
static ACVP_RESULT acvp_add_hash_drbg_cap_parm (
        ACVP_DRBG_CAP_MODE *drbg_cap_mode,
        ACVP_DRBG_MODE mode,
        ACVP_DRBG_PARM param,
        int value
) {
    switch (mode) {
    case ACVP_DRBG_SHA_1:
    case ACVP_DRBG_SHA_224:
    case ACVP_DRBG_SHA_256:
    case ACVP_DRBG_SHA_384:
    case ACVP_DRBG_SHA_512:
        drbg_cap_mode->mode = mode;
        switch (param) {
        case ACVP_DRBG_DER_FUNC_ENABLED:
            drbg_cap_mode->der_func_enabled = value;
            break;
        case ACVP_DRBG_PRED_RESIST_ENABLED:
            drbg_cap_mode->pred_resist_enabled = value;
            break;
        case ACVP_DRBG_RESEED_ENABLED:
            drbg_cap_mode->reseed_implemented = value;
            break;
        case ACVP_DRBG_ENTROPY_LEN:
            drbg_cap_mode->entropy_input_len = value;
            break;
        case ACVP_DRBG_NONCE_LEN:
            drbg_cap_mode->nonce_len = value;
            break;
        case ACVP_DRBG_PERSO_LEN:
            drbg_cap_mode->perso_string_len = value;
            break;
        case ACVP_DRBG_ADD_IN_LEN:
            drbg_cap_mode->additional_input_len = value;
            break;
        case ACVP_DRBG_RET_BITS_LEN:
            drbg_cap_mode->returned_bits_len = value;
            break;
        case ACVP_DRBG_PRE_REQ_VALS:
        default:
            return ACVP_INVALID_ARG;
            break;
        }
        break;
    case ACVP_DRBG_SHA_512_224:
    case ACVP_DRBG_SHA_512_256:
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}

/*
 * Add HMAC DRBG parameters
 */
static ACVP_RESULT acvp_add_hmac_drbg_cap_parm (
        ACVP_DRBG_CAP_MODE *drbg_cap_mode,
        ACVP_DRBG_MODE mode,
        ACVP_DRBG_PARM param,
        int value
) {
    switch (mode) {
    case ACVP_DRBG_SHA_1:
    case ACVP_DRBG_SHA_224:
    case ACVP_DRBG_SHA_256:
    case ACVP_DRBG_SHA_384:
    case ACVP_DRBG_SHA_512:
        drbg_cap_mode->mode = mode;
        switch (param) {
        case ACVP_DRBG_DER_FUNC_ENABLED:
            drbg_cap_mode->der_func_enabled = value;
            break;
        case ACVP_DRBG_PRED_RESIST_ENABLED:
            drbg_cap_mode->pred_resist_enabled = value;
            break;
        case ACVP_DRBG_RESEED_ENABLED:
            drbg_cap_mode->reseed_implemented = value;
            break;
        case ACVP_DRBG_ENTROPY_LEN:
            drbg_cap_mode->entropy_input_len = value;
            break;
        case ACVP_DRBG_NONCE_LEN:
            drbg_cap_mode->nonce_len = value;
            break;
        case ACVP_DRBG_PERSO_LEN:
            drbg_cap_mode->perso_string_len = value;
            break;
        case ACVP_DRBG_ADD_IN_LEN:
            drbg_cap_mode->additional_input_len = value;
            break;
        case ACVP_DRBG_RET_BITS_LEN:
            drbg_cap_mode->returned_bits_len = value;
            break;
        case ACVP_DRBG_PRE_REQ_VALS:
        default:
            return ACVP_INVALID_ARG;
        }
        break;
    
    case ACVP_DRBG_SHA_512_224:
    case ACVP_DRBG_SHA_512_256:
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    
    return ACVP_SUCCESS;
}

/*
 * Append a DRBG pre req val to the
 */
static ACVP_RESULT acvp_add_drbg_prereq_val (ACVP_DRBG_CAP_MODE *drbg_cap_mode,
                                             ACVP_DRBG_MODE mode, ACVP_PREREQ_ALG pre_req, char *value) {
    ACVP_PREREQ_LIST *prereq_entry, *prereq_entry_2;
    
    prereq_entry = calloc(1, sizeof(ACVP_PREREQ_LIST));
    if (!prereq_entry) {
        return ACVP_MALLOC_FAIL;
    }
    prereq_entry->prereq_alg_val.alg = pre_req;
    prereq_entry->prereq_alg_val.val = value;
    
    /*
     * 1st entry
     */
    if (!drbg_cap_mode->prereq_vals) {
        drbg_cap_mode->prereq_vals = prereq_entry;
    } else {
        /*
         * append to the last in the list
         */
        prereq_entry_2 = drbg_cap_mode->prereq_vals;
        while (prereq_entry_2->next) {
            prereq_entry_2 = prereq_entry_2->next;
        }
        prereq_entry_2->next = prereq_entry;
    }
    return (ACVP_SUCCESS);
}

ACVP_RESULT acvp_enable_drbg_prereq_cap (ACVP_CTX *ctx,
                                         ACVP_CIPHER cipher,
                                         ACVP_DRBG_MODE mode,
                                         ACVP_PREREQ_ALG pre_req,
                                         char *value) {
    ACVP_DRBG_CAP_MODE_LIST *drbg_cap_mode_list;
    ACVP_CAPS_LIST *cap_list;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    
    switch (pre_req) {
    case ACVP_PREREQ_AES:
    case ACVP_PREREQ_TDES:
    case ACVP_PREREQ_DRBG:
    case ACVP_PREREQ_HMAC:
    case ACVP_PREREQ_SHA:
        break;
    default:
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
     * if the mode does not exist yet then create it.
     */
    drbg_cap_mode_list = acvp_locate_drbg_mode_entry(cap_list, mode);
    if (!drbg_cap_mode_list) {
        drbg_cap_mode_list = calloc(1, sizeof(ACVP_DRBG_CAP_MODE_LIST));
        if (!drbg_cap_mode_list) {
            ACVP_LOG_ERR("Malloc Failed.");
            return ACVP_MALLOC_FAIL;
        }
        drbg_cap_mode_list->cap_mode.mode = mode;
        cap_list->cap.drbg_cap->drbg_cap_mode_list = drbg_cap_mode_list;
    }
    
    /*
     * Add the value to the cap
     */
    return (acvp_add_drbg_prereq_val(&drbg_cap_mode_list->cap_mode, mode, pre_req, value));
}

/*
 * The user should call this after invoking acvp_enable_drbg_cap_parm().
 */
ACVP_RESULT acvp_enable_drbg_cap_parm (ACVP_CTX *ctx,
                                       ACVP_CIPHER cipher,
                                       ACVP_DRBG_MODE mode,
                                       ACVP_DRBG_PARM param,
                                       int value
) {
    ACVP_DRBG_CAP_MODE_LIST *drbg_cap_mode_list;
    ACVP_CAPS_LIST *cap_list;
    ACVP_RESULT result;
    
    /*
     * Validate input
     */
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    
    switch (cipher) {
    case ACVP_HASHDRBG:
    case ACVP_HMACDRBG:
    case ACVP_CTRDRBG:
        break;
    default:
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
     * if the mode does not exist yet then create it.
     */
    if (!cap_list->cap.drbg_cap) {
        ACVP_LOG_ERR("DRBG Cap entry not found.");
        return ACVP_NO_CAP;
    }
    
    drbg_cap_mode_list = acvp_locate_drbg_mode_entry(cap_list, mode);
    if (!drbg_cap_mode_list) {
        drbg_cap_mode_list = calloc(1, sizeof(ACVP_DRBG_CAP_MODE_LIST));
        if (!drbg_cap_mode_list) {
            ACVP_LOG_ERR("Malloc Failed.");
            return ACVP_MALLOC_FAIL;
        }
        
        drbg_cap_mode_list->cap_mode.mode = mode;
        cap_list->cap.drbg_cap->drbg_cap_mode_list = drbg_cap_mode_list;
    }
    
    /*
     * Add the value to the cap
     */
    switch (cipher) {
    case ACVP_HASHDRBG:
        result = acvp_add_hash_drbg_cap_parm(&drbg_cap_mode_list->cap_mode, mode, param, value);
        break;
    case ACVP_HMACDRBG:
        result = acvp_add_hmac_drbg_cap_parm(&drbg_cap_mode_list->cap_mode, mode, param, value);
        break;
    case ACVP_CTRDRBG:
        result = acvp_add_ctr_drbg_cap_parm(&drbg_cap_mode_list->cap_mode, mode, param, value);
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    
    return (result);
}

ACVP_RESULT acvp_enable_drbg_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_DRBG_CAP *drbg_cap;
    ACVP_RESULT result;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    //Check for duplicate entry
    if (acvp_locate_cap_entry(ctx, cipher)) {
        return ACVP_DUP_CIPHER;
    }
    
    drbg_cap = calloc(1, sizeof(ACVP_DRBG_CAP));
    if (!drbg_cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    drbg_cap->cipher = cipher;
    result = acvp_append_drbg_caps_entry(ctx, drbg_cap, cipher, crypto_handler);
    if (result != ACVP_SUCCESS) {
        free(drbg_cap);
        drbg_cap = NULL;
    }
    return result;
}

/*
 * The user should call this after invoking acvp_enable_rsa_keygen_cap().
 */
ACVP_RESULT acvp_enable_rsa_keygen_mode (ACVP_CTX *ctx,
                                         ACVP_RSA_KEYGEN_MODE value
) {
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
        keygen_cap->rand_pq_str = (char *)ACVP_RSA_RANDPQ32_STR;
        break;
    case ACVP_RSA_KEYGEN_B33:
        keygen_cap->rand_pq_str = (char *)ACVP_RSA_RANDPQ33_STR;
        break;
    case ACVP_RSA_KEYGEN_B34:
        keygen_cap->rand_pq_str = (char *)ACVP_RSA_RANDPQ34_STR;
        break;
    case ACVP_RSA_KEYGEN_B35:
        keygen_cap->rand_pq_str = (char *)ACVP_RSA_RANDPQ35_STR;
        break;
    case ACVP_RSA_KEYGEN_B36:
        keygen_cap->rand_pq_str = (char *)ACVP_RSA_RANDPQ36_STR;
        break;
    default:
        break;
    }
    
    return result;
}

/*
 * The user should call this after invoking acvp_enable_rsa_keygen_cap().
 */
ACVP_RESULT acvp_enable_rsa_keygen_cap_parm (ACVP_CTX *ctx,
                                             ACVP_RSA_PARM param,
                                             int value
) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_RESULT rv = ACVP_SUCCESS;
    
    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_KEYGEN);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    
    switch (param) {
    case ACVP_PUB_EXP_MODE:
        cap_list->cap.rsa_keygen_cap->pub_exp_mode = value;
        break;
    case ACVP_RSA_INFO_GEN_BY_SERVER:
        rv = is_valid_tf_param(value);
        if (rv != ACVP_SUCCESS) {
            break;
        }
        cap_list->cap.rsa_keygen_cap->info_gen_by_server = value;
        break;
    case ACVP_KEY_FORMAT_CRT:
        rv = is_valid_tf_param(value);
        if (rv != ACVP_SUCCESS) {
            break;
        }
        cap_list->cap.rsa_keygen_cap->key_format_crt = value;
        break;
    case ACVP_RAND_PQ:
    case ACVP_FIXED_PUB_EXP_VAL:
        ACVP_LOG_ERR("Use acvp_enable_rsa_keygen_mode() or acvp_enable_rsa_keygen_exp_parm() API to enable a new randPQ or exponent.");
    default:
        rv = ACVP_INVALID_ARG;
        break;
    }
    return rv;
}

ACVP_RESULT acvp_enable_rsa_keygen_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_RSA_KEYGEN_CAP *rsa_keygen_cap;
    ACVP_RESULT result;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (cipher != ACVP_RSA_KEYGEN) {
        return ACVP_INVALID_ARG;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    /*
     * Check for duplicate entry
     */
    if (acvp_locate_cap_entry(ctx, cipher)) {
        return ACVP_DUP_CIPHER;
    }
    
    rsa_keygen_cap = calloc(1, sizeof(ACVP_RSA_KEYGEN_CAP));
    if (!rsa_keygen_cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    result = acvp_append_rsa_keygen_caps_entry(ctx, rsa_keygen_cap, cipher, crypto_handler);
    if (result != ACVP_SUCCESS) {
        free(rsa_keygen_cap);
        rsa_keygen_cap = NULL;
    }
    return result;
}

/*
 * The user should call this after invoking acvp_enable_rsa_sigver_cap().
 */
ACVP_RESULT acvp_enable_rsa_sigver_cap_parm (ACVP_CTX *ctx,
                                             ACVP_RSA_PARM param,
                                             int value
) {
    ACVP_CAPS_LIST *cap_list;
    
    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_SIGVER);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    
    switch (param) {
    case ACVP_PUB_EXP_MODE:
        cap_list->cap.rsa_sigver_cap->pub_exp_mode = value;
        break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_rsa_sigver_cap().
 */
ACVP_RESULT acvp_enable_rsa_sigver_type (ACVP_CTX *ctx,
                                         ACVP_RSA_SIG_TYPE value
) {
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
    case RSA_SIG_TYPE_X931:
        sigver_cap->sig_type_str = (char *)RSA_SIG_TYPE_X931_NAME;
        break;
    case RSA_SIG_TYPE_PKCS1V15:
        sigver_cap->sig_type_str = (char *)RSA_SIG_TYPE_PKCS1V15_NAME;
        break;
    case RSA_SIG_TYPE_PKCS1PSS:
        sigver_cap->sig_type_str = (char *)RSA_SIG_TYPE_PKCS1PSS_NAME;
        break;
    default:
        break;
    }
    
    return result;
}

/*
 * The user should call this after invoking acvp_enable_rsa_siggen_cap().
 */
ACVP_RESULT acvp_enable_rsa_siggen_type (ACVP_CTX *ctx,
                                         ACVP_RSA_SIG_TYPE value
) {
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
    case RSA_SIG_TYPE_X931:
        siggen_cap->sig_type_str = RSA_SIG_TYPE_X931_NAME;
        break;
    case RSA_SIG_TYPE_PKCS1V15:
        siggen_cap->sig_type_str = RSA_SIG_TYPE_PKCS1V15_NAME;
        break;
    case RSA_SIG_TYPE_PKCS1PSS:
        siggen_cap->sig_type_str = RSA_SIG_TYPE_PKCS1PSS_NAME;
        break;
    default:
        break;
    }
    
    return result;
}

/*
 * The user should call this after invoking acvp_enable_rsa_keygen_cap_parm().
 */
ACVP_RESULT acvp_enable_rsa_keygen_exp_parm (ACVP_CTX *ctx,
                                             ACVP_RSA_PARM param,
                                             char *value
) {
    ACVP_CAPS_LIST *cap_list;
    
    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_KEYGEN);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    
    /*
     * Add the value to the cap
     */
    switch (param) {
    case ACVP_FIXED_PUB_EXP_VAL:
        if (cap_list->cap.rsa_keygen_cap->pub_exp_mode == RSA_PUB_EXP_FIXED) {
            cap_list->cap.rsa_keygen_cap->fixed_pub_exp = (unsigned char *)value;
        }
        break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    
    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_rsa_sigver_cap_parm().
 */
// TODO: maybe we can collapse these bignums into a shared internal method
ACVP_RESULT acvp_enable_rsa_sigver_exp_parm (ACVP_CTX *ctx,
                                             ACVP_RSA_PARM param,
                                             char *value
) {
    ACVP_CAPS_LIST *cap_list;
    
    cap_list = acvp_locate_cap_entry(ctx, ACVP_RSA_SIGVER);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    
    /*
     * Add the value to the cap
     */
    switch (param) {
    case ACVP_FIXED_PUB_EXP_VAL:
        if (cap_list->cap.rsa_sigver_cap->pub_exp_mode == RSA_PUB_EXP_FIXED) {
            cap_list->cap.rsa_sigver_cap->fixed_pub_exp = (unsigned char *)value;
        }
        break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    
    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_rsa_cap_parm()
 * and setting the randPQ value.
 */
ACVP_RESULT acvp_enable_rsa_keygen_primes_parm (ACVP_CTX *ctx,
                                                ACVP_RSA_KEYGEN_MODE mode,
                                                int mod,
                                                char *name
) {
    ACVP_RSA_KEYGEN_CAP *keygen_cap;
    ACVP_CAPS_LIST *cap_list;
    int found;
    
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
    
    ACVP_RSA_MODE_CAPS_LIST *current_prime = NULL;
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
    
    if (is_valid_hash_alg(name) == ACVP_SUCCESS) {
        ACVP_NAME_LIST *current_hash = NULL;
        if (!current_prime->hash_algs) {
            current_prime->hash_algs = calloc(1, sizeof(ACVP_NAME_LIST));
            if (!current_prime->hash_algs) {
                ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                return ACVP_MALLOC_FAIL;
            }
            current_prime->hash_algs->name = name;
        } else {
            current_hash = current_prime->hash_algs;
            while (current_hash->next != NULL) {
                current_hash = current_hash->next;
            }
            current_hash->next = calloc(1, sizeof(ACVP_NAME_LIST));
            if (!current_hash->next) {
                ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                return ACVP_MALLOC_FAIL;
            }
            current_hash->next->name = name;
        }
    } else if (is_valid_prime_test(name) == ACVP_SUCCESS) {
        ACVP_NAME_LIST *current_prime_test = NULL;
        if (!current_prime->prime_tests) {
            current_prime->prime_tests = calloc(1, sizeof(ACVP_NAME_LIST));
            if (!current_prime->prime_tests) {
                ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                return ACVP_MALLOC_FAIL;
            }
            current_prime->prime_tests->name = name;
        } else {
            current_prime_test = current_prime->prime_tests;
            while (current_prime_test->next != NULL) {
                current_prime_test = current_prime_test->next;
            }
            current_prime_test->next = calloc(1, sizeof(ACVP_NAME_LIST));
            if (!current_prime_test->next) {
                ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                return ACVP_MALLOC_FAIL;
            }
            current_prime_test->next->name = name;
        }
    } else {
        return ACVP_INVALID_ARG;
    }
    
    return (ACVP_SUCCESS);
}

/*
 * The user should call this after invoking acvp_enable_rsa_sigver_cap()
 * and setting the randPQ value.
 */
ACVP_RESULT acvp_enable_rsa_sigver_caps_parm (ACVP_CTX *ctx,
                                              ACVP_RSA_SIG_TYPE sig_type,
                                              int mod,
                                              char *hash_name,
                                              int salt_len
) {
    ACVP_RSA_SIG_CAP *sigver_cap;
    ACVP_CAPS_LIST *cap_list;
    int found;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    
    if (!hash_name || !mod) {
        ACVP_LOG_ERR("Must specify modulo and hash name");
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
    
    ACVP_RSA_MODE_CAPS_LIST *current_cap = NULL;
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
    
    ACVP_RSA_HASH_PAIR_LIST *current_hash = NULL;
    if (!current_cap->hash_pair) {
        current_cap->hash_pair = calloc(1, sizeof(ACVP_RSA_HASH_PAIR_LIST));
        if (!current_cap->hash_pair) {
            ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return ACVP_MALLOC_FAIL;
        }
        current_cap->hash_pair->name = hash_name;
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
        current_hash->next->name = hash_name;
        if (salt_len) {
            current_hash->next->salt = salt_len;
        }
    }
    
    return (ACVP_SUCCESS);
}


/*
 * The user should call this after invoking acvp_enable_rsa_siggen_cap()
 * and setting the randPQ value.
 */
ACVP_RESULT acvp_enable_rsa_siggen_caps_parm (ACVP_CTX *ctx,
                                              ACVP_RSA_SIG_TYPE sig_type,
                                              int mod,
                                              char *hash_name,
                                              int salt_len
) {
    ACVP_RSA_SIG_CAP *siggen_cap;
    ACVP_CAPS_LIST *cap_list;
    int found;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    
    if (!hash_name || !mod) {
        ACVP_LOG_ERR("Must specify modulo and hash name");
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
    
    ACVP_RSA_MODE_CAPS_LIST *current_cap = NULL;
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
    
    ACVP_RSA_HASH_PAIR_LIST *current_hash = NULL;
    if (!current_cap->hash_pair) {
        current_cap->hash_pair = calloc(1, sizeof(ACVP_RSA_HASH_PAIR_LIST));
        if (!current_cap->hash_pair) {
            ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return ACVP_MALLOC_FAIL;
        }
        current_cap->hash_pair->name = hash_name;
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
        current_hash->next->name = hash_name;
        if (salt_len) {
            current_hash->next->salt = salt_len;
        }
    }
    
    return (ACVP_SUCCESS);
}

static ACVP_RESULT acvp_enable_rsa_sig_cap_internal (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_RSA_SIG_CAP *rsa_sig_cap;
    ACVP_RESULT result;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler ||
        ((cipher != ACVP_RSA_SIGVER) &&
         (cipher != ACVP_RSA_SIGGEN))) {
        return ACVP_INVALID_ARG;
    }
    
    /*
     * Check for duplicate entry
     */
    if (acvp_locate_cap_entry(ctx, cipher)) {
        return ACVP_DUP_CIPHER;
    }
    
    rsa_sig_cap = calloc(1, sizeof(ACVP_RSA_SIG_CAP));
    if (!rsa_sig_cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    result = acvp_append_rsa_sig_caps_entry(ctx, rsa_sig_cap, cipher, crypto_handler);
    if (result != ACVP_SUCCESS) {
        free(rsa_sig_cap);
        rsa_sig_cap = NULL;
    }
    return result;
}

ACVP_RESULT acvp_enable_rsa_siggen_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    
    return acvp_enable_rsa_sig_cap_internal(ctx, cipher, crypto_handler);
    
}

ACVP_RESULT acvp_enable_rsa_sigver_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    
    return acvp_enable_rsa_sig_cap_internal(ctx, cipher, crypto_handler);
}


/*
 * The user should call this after invoking acvp_enable_ecdsa_cap().
 */
ACVP_RESULT acvp_enable_ecdsa_cap_parm (ACVP_CTX *ctx,
                                        ACVP_CIPHER cipher,
                                        ACVP_ECDSA_PARM param,
                                        char *value
) {
    ACVP_CAPS_LIST *cap_list;
    int curve = 0;
    ACVP_NAME_LIST *current_curve, *current_secret_mode, *current_hash;
    ACVP_ECDSA_CAP *cap;
    
    switch(cipher) {
    case ACVP_ECDSA_KEYGEN:
    case ACVP_ECDSA_KEYVER:
    case ACVP_ECDSA_SIGGEN:
    case ACVP_ECDSA_SIGVER:
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    
    switch(cipher) {
    case ACVP_ECDSA_KEYGEN:
        cap = cap_list->cap.ecdsa_keygen_cap;
        break;
    case ACVP_ECDSA_KEYVER:
        cap = cap_list->cap.ecdsa_keyver_cap;
        break;
    case ACVP_ECDSA_SIGGEN:
        cap = cap_list->cap.ecdsa_siggen_cap;
        break;
    case ACVP_ECDSA_SIGVER:
        cap = cap_list->cap.ecdsa_sigver_cap;
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    
    switch (param) {
    case ACVP_CURVE:
        curve = acvp_lookup_ecdsa_curve(cipher, value);
        if (!curve) {
            return ACVP_INVALID_ARG;
        }
        current_curve = cap->curves;
        if (current_curve) {
            while (current_curve->next) {
                current_curve = current_curve->next;
            }
            current_curve->next = calloc(1, sizeof(ACVP_NAME_LIST));
            current_curve->next->name = value;
        } else {
            cap->curves = calloc(1, sizeof(ACVP_NAME_LIST));
            cap->curves->name = value;
        }
        break;
    case ACVP_SECRET_GEN_MODE:
        if (cipher != ACVP_ECDSA_KEYGEN) {
            return ACVP_INVALID_ARG;
        }
        current_secret_mode = cap->secret_gen_modes;
        if (current_secret_mode) {
            while (current_secret_mode->next) {
                current_secret_mode = current_secret_mode->next;
            }
            current_secret_mode->next = calloc(1, sizeof(ACVP_NAME_LIST));
            current_secret_mode->next->name = value;
        } else {
            cap->secret_gen_modes = calloc(1, sizeof(ACVP_NAME_LIST));
            cap->secret_gen_modes->name = value;
        }
        break;
    case ACVP_HASH_ALG:
        if (cipher != ACVP_ECDSA_SIGGEN && cipher != ACVP_ECDSA_SIGVER) {
            return ACVP_INVALID_ARG;
        }
        current_hash = cap->hash_algs;
        if (current_hash) {
            while (current_hash->next) {
                current_hash = current_hash->next;
            }
            current_hash->next = calloc(1, sizeof(ACVP_NAME_LIST));
            current_hash->next->name = value;
        } else {
            cap->hash_algs = calloc(1, sizeof(ACVP_NAME_LIST));
            cap->hash_algs->name = value;
        }
        break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_ecdsa_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_ECDSA_CAP *ecdsa_cap;
    ACVP_RESULT result;
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    /*
     * Check for duplicate entry
     */
    if (acvp_locate_cap_entry(ctx, cipher)) {
        return ACVP_DUP_CIPHER;
    }
    
    ecdsa_cap = calloc(1, sizeof(ACVP_ECDSA_CAP));
    if (!ecdsa_cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    result = acvp_append_ecdsa_caps_entry(ctx, ecdsa_cap, cipher, crypto_handler);
    if (result != ACVP_SUCCESS) {
        free(ecdsa_cap);
        ecdsa_cap = NULL;
    }
    return result;
}

/*
 * The user should call this after invoking acvp_enable_dsa_cap().
 */
ACVP_RESULT acvp_enable_dsa_cap_parm (ACVP_CTX *ctx,
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
    
    return (result);
}

ACVP_RESULT acvp_enable_kdf135_tpm_cap (
        ACVP_CTX *ctx,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_KDF135_TPM_CAP *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    cap = calloc(1, sizeof(ACVP_KDF135_TPM_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    return (acvp_append_kdf135_tpm_caps_entry(ctx, cap, crypto_handler));
}

ACVP_RESULT acvp_enable_kdf135_tls_cap (
        ACVP_CTX *ctx,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_KDF135_TLS_CAP *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    cap = calloc(1, sizeof(ACVP_KDF135_TLS_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    return (acvp_append_kdf135_tls_caps_entry(ctx, cap, crypto_handler));
}

/*
 * The user should call this after invoking acvp_enable_kdf135_snmp_cap()
 * to specify kdf parameters
 */
ACVP_RESULT acvp_enable_kdf135_snmp_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER kcap,
        ACVP_KDF135_SNMP_PARAM param,
        int value) {
    
    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_SNMP_CAP *kdf135_snmp_cap;
    ACVP_SL_LIST *current_len;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    
    if (param != ACVP_KDF135_SNMP_PASS_LEN) {
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
    
    if (kdf135_snmp_cap->pass_lens) {
        current_len = kdf135_snmp_cap->pass_lens;
        while (current_len->next) {
            current_len = current_len->next;
        }
        current_len->next = calloc(1, sizeof(ACVP_SL_LIST));
        current_len = current_len->next;
    } else {
        kdf135_snmp_cap->pass_lens = calloc(1, sizeof(ACVP_SL_LIST));
        current_len = kdf135_snmp_cap->pass_lens;
    }
    current_len->length = value;
    
    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_kdf135_snmp_cap()
 * to specify the hex string engine id. acvp_enable_kdf135_snmp_cap_parm()
 * should be used to specify password length
 */
ACVP_RESULT acvp_enable_kdf135_snmp_engid_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER kcap,
        char *engid) {
    
    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_SNMP_CAP *kdf135_snmp_cap;
    ACVP_NAME_LIST *engids;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    
    if (!engid) {
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
    
    if (kdf135_snmp_cap->eng_ids) {
        engids = kdf135_snmp_cap->eng_ids;
        while (engids->next) {
            engids = engids->next;
        }
        engids->next = calloc(1, sizeof(ACVP_NAME_LIST));
        engids = engids->next;
    } else {
        kdf135_snmp_cap->eng_ids = calloc(1, sizeof(ACVP_NAME_LIST));
        engids = kdf135_snmp_cap->eng_ids;
    }
    engids->name = engid;
    
    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_kdf135_tls_cap()
 * to specify the kdf parameters.
 */
ACVP_RESULT acvp_enable_kdf135_tls_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER kcap,
        ACVP_KDF135_TLS_METHOD method,
        ACVP_KDF135_TLS_CAP_PARM param) {
    
    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_TLS_CAP *kdf135_tls_cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    
    cap = acvp_locate_cap_entry(ctx, kcap);
    if (!cap) {
        return ACVP_NO_CAP;
    }
    
    kdf135_tls_cap = cap->cap.kdf135_tls_cap;
    if (!kdf135_tls_cap) {
        return ACVP_NO_CAP;
    }
    
    if (acvp_validate_kdf135_tls_param_value(method, param) != ACVP_SUCCESS) {
        return ACVP_INVALID_ARG;
    }
    
    /* only support two method types so just use whichever is available */
    if (!kdf135_tls_cap->method[0]) {
        kdf135_tls_cap->method[0] = method;
    } else {
        kdf135_tls_cap->method[1] = method;
    }
    
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_kdf135_srtp_cap (
        ACVP_CTX *ctx,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_KDF135_SRTP_CAP *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    cap = calloc(1, sizeof(ACVP_KDF135_SRTP_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    return (acvp_append_kdf135_srtp_caps_entry(ctx, cap, crypto_handler));
}


ACVP_RESULT acvp_enable_kdf135_ikev2_cap (
        ACVP_CTX *ctx,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_KDF135_IKEV2_CAP *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    cap = calloc(1, sizeof(ACVP_KDF135_IKEV2_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    return (acvp_append_kdf135_ikev2_caps_entry(ctx, cap, crypto_handler));
}


ACVP_RESULT acvp_enable_kdf135_x963_cap (
        ACVP_CTX *ctx,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_KDF135_X963_CAP *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    cap = calloc(1, sizeof(ACVP_KDF135_X963_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    return (acvp_append_kdf135_x963_caps_entry(ctx, cap, crypto_handler));
}

ACVP_RESULT acvp_enable_kdf135_ikev1_cap (
        ACVP_CTX *ctx,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_KDF135_IKEV1_CAP *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    cap = calloc(1, sizeof(ACVP_KDF135_IKEV1_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    return (acvp_append_kdf135_ikev1_caps_entry(ctx, cap, crypto_handler));
}

ACVP_RESULT acvp_enable_kdf108_cap (
        ACVP_CTX *ctx,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_KDF108_CAP *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    cap = calloc(1, sizeof(ACVP_KDF108_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    return (acvp_append_kdf108_caps_entry(ctx, cap, crypto_handler));
}

ACVP_RESULT acvp_enable_kdf135_snmp_cap (
        ACVP_CTX *ctx,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_KDF135_SNMP_CAP *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    cap = calloc(1, sizeof(ACVP_KDF135_SNMP_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    return (acvp_append_kdf135_snmp_caps_entry(ctx, cap, crypto_handler));
}

ACVP_RESULT acvp_enable_kdf135_ssh_cap (
        ACVP_CTX *ctx,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_KDF135_SSH_CAP *cap;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    cap = calloc(1, sizeof(ACVP_KDF135_SSH_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    return (acvp_append_kdf135_ssh_caps_entry(ctx, cap, crypto_handler));
}

/*
 * The user should call this after invoking acvp_enable_kdf135_ssh_cap()
 * to specify the kdf parameters.
 */
ACVP_RESULT acvp_enable_kdf135_ssh_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER kcap,
        ACVP_KDF135_SSH_METHOD method,
        ACVP_KDF135_SSH_CAP_PARM param) {
    
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
ACVP_RESULT acvp_enable_kdf108_cap_param (
        ACVP_CTX *ctx,
        ACVP_KDF108_MODE mode,
        ACVP_KDF108_PARM param,
        int value) {
    
    ACVP_CAPS_LIST *cap;
    ACVP_KDF108_CAP *kdf108_cap;
    ACVP_KDF108_MODE_PARAMS *mode_obj;
    ACVP_NAME_LIST *nl_obj;
    ACVP_SL_LIST *sl_obj;
    
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
    
    if (acvp_validate_kdf108_param_value(param, value) != ACVP_SUCCESS) {
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
        if (mode_obj->mac_mode) {
            nl_obj = mode_obj->mac_mode;
            while (nl_obj->next) {
                nl_obj = nl_obj->next;
            }
            nl_obj->next = calloc(1, sizeof(ACVP_NAME_LIST));
            nl_obj = nl_obj->next;
        } else {
            mode_obj->mac_mode = calloc(1, sizeof(ACVP_NAME_LIST));
            nl_obj = mode_obj->mac_mode;
        }
        switch (value) {
        case ACVP_KDF108_MAC_MODE_CMAC_AES128:
            nl_obj->name = ACVP_ALG_CMAC_AES_128;
            break;
        case ACVP_KDF108_MAC_MODE_CMAC_AES192:
            nl_obj->name = ACVP_ALG_CMAC_AES_192;
            break;
        case ACVP_KDF108_MAC_MODE_CMAC_AES256:
            nl_obj->name = ACVP_ALG_CMAC_AES_256;
            break;
        case ACVP_KDF108_MAC_MODE_CMAC_TDES:
            nl_obj->name = ACVP_ALG_CMAC_TDES;
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA1:
            nl_obj->name = ACVP_ALG_HMAC_SHA1;
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA224:
            nl_obj->name = ACVP_ALG_HMAC_SHA2_224;
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA256:
            nl_obj->name = ACVP_ALG_HMAC_SHA2_256;
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA384:
            nl_obj->name = ACVP_ALG_HMAC_SHA2_384;
            break;
        case ACVP_KDF108_MAC_MODE_HMAC_SHA512:
            nl_obj->name = ACVP_ALG_HMAC_SHA2_512;
            break;
        default:
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_KDF108_COUNTER_LEN:
        if (mode_obj->counter_lens) {
            sl_obj = mode_obj->counter_lens;
            while (sl_obj->next) {
                sl_obj = sl_obj->next;
            }
            sl_obj->next = calloc(1, sizeof(ACVP_SL_LIST));
            sl_obj = sl_obj->next;
        } else {
            mode_obj->counter_lens = calloc(1, sizeof(ACVP_SL_LIST));
            sl_obj = mode_obj->counter_lens;
        }
        sl_obj->length = value;
        break;
    case ACVP_KDF108_FIXED_DATA_ORDER:
        if (mode_obj->data_order) {
            nl_obj = mode_obj->data_order;
            while (nl_obj->next) {
                nl_obj = nl_obj->next;
            }
            nl_obj->next = calloc(1, sizeof(ACVP_NAME_LIST));
            nl_obj = nl_obj->next;
        } else {
            mode_obj->data_order = calloc(1, sizeof(ACVP_NAME_LIST));
            nl_obj = mode_obj->data_order;
        }
        switch (value) {
        case ACVP_KDF108_FIXED_DATA_ORDER_AFTER:
            nl_obj->name = ACVP_FIXED_DATA_ORDER_AFTER_STR;
            break;
        case ACVP_KDF108_FIXED_DATA_ORDER_BEFORE:
            nl_obj->name = ACVP_FIXED_DATA_ORDER_BEFORE_STR;
            break;
        case ACVP_KDF108_FIXED_DATA_ORDER_MIDDLE:
            nl_obj->name = ACVP_FIXED_DATA_ORDER_MIDDLE_STR;
            break;
        case ACVP_KDF108_FIXED_DATA_ORDER_NONE:
            nl_obj->name = ACVP_FIXED_DATA_ORDER_NONE_STR;
            break;
        case ACVP_KDF108_FIXED_DATA_ORDER_BEFORE_ITERATOR:
            nl_obj->name = ACVP_FIXED_DATA_ORDER_BEFORE_ITERATOR_STR;
            break;
        default:
            return ACVP_INVALID_ARG;
        }
        break;
    case ACVP_KDF108_SUPPORTS_EMPTY_IV:
        mode_obj->empty_iv_support = value;
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    
    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_kdf135_ssh_cap()
 * to specify the kdf parameters.
 */
ACVP_RESULT acvp_enable_kdf135_srtp_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_KDF135_SRTP_PARAM param,
        int value) {
    
    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_SRTP_CAP *kdf135_srtp_cap;
    ACVP_SL_LIST *current_aes_keylen;
    
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
        current_aes_keylen = kdf135_srtp_cap->aes_keylens;
        if (!current_aes_keylen) {
            kdf135_srtp_cap->aes_keylens = calloc(1, sizeof(ACVP_SL_LIST));
            kdf135_srtp_cap->aes_keylens->length = value;
        } else {
            while (current_aes_keylen->next) {
                current_aes_keylen = current_aes_keylen->next;
            }
            current_aes_keylen->next = calloc(1, sizeof(ACVP_SL_LIST));
            current_aes_keylen->next->length = value;
        }
        break;
    case ACVP_SRTP_SUPPORT_ZERO_KDR:
        kdf135_srtp_cap->supports_zero_kdr = value;
        break;
    case ACVP_SRTP_KDF_EXPONENT:
        kdf135_srtp_cap->kdr_exp[value - 1] = 1;
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    
    return ACVP_SUCCESS;
}


ACVP_RESULT acvp_enable_dsa_cap (ACVP_CTX *ctx,
                                 ACVP_CIPHER cipher,
                                 ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_DSA_CAP *dsa_cap;
    ACVP_RESULT result;
    void *dsa_modes;
    int i;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    /*
     * Check for duplicate entry
     */
    if (acvp_locate_cap_entry(ctx, cipher)) {
        return ACVP_DUP_CIPHER;
    }
    
    dsa_cap = calloc(1, sizeof(ACVP_DSA_CAP));
    if (!dsa_cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    dsa_cap->cipher = cipher;
    
    dsa_modes = calloc(1, ACVP_DSA_MAX_MODES * sizeof(ACVP_DSA_CAP_MODE) + 1);
    if (!dsa_modes) {
        free(dsa_cap);
        return ACVP_MALLOC_FAIL;
    }
    
    dsa_cap->dsa_cap_mode = (ACVP_DSA_CAP_MODE *)dsa_modes;
    for (i = 1; i <= ACVP_DSA_MAX_MODES; i++) {
        dsa_cap->dsa_cap_mode[i - 1].cap_mode = (ACVP_DSA_MODE)i;
    }
    
    result = acvp_append_dsa_caps_entry(ctx, dsa_cap, cipher, crypto_handler);
    if (result != ACVP_SUCCESS) {
        free(dsa_cap);
        free(dsa_modes);
        dsa_cap = NULL;
    }
    return result;
}


ACVP_RESULT acvp_enable_kdf135_ikev2_cap_param (ACVP_CTX *ctx,
                                                ACVP_KDF135_IKEV2_PARM param,
                                                char *value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_NAME_LIST *current_hash;
    ACVP_KDF135_IKEV2_CAP *cap;
    
    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF135_IKEV2);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_ikev2_cap;
    
    if (param != ACVP_KDF_HASH_ALG) {
        return ACVP_INVALID_ARG;
    }
    
    current_hash = cap->hash_algs;
    if (current_hash) {
        while (current_hash->next) {
            current_hash = current_hash->next;
        }
        current_hash->next = calloc(1, sizeof(ACVP_NAME_LIST));
        current_hash->next->name = value;
    } else {
        cap->hash_algs = calloc(1, sizeof(ACVP_NAME_LIST));
        cap->hash_algs->name = value;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_kdf135_ikev2_cap_len_param (ACVP_CTX *ctx,
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
        domain = &cap->init_nonce_len_domain;
        break;
    case ACVP_RESPOND_NONCE_LEN:
        domain = &cap->respond_nonce_len_domain;
        break;
    case ACVP_DH_SECRET_LEN:
        domain = &cap->dh_secret_len;
        break;
    case ACVP_KEY_MATERIAL_LEN:
        domain = &cap->key_material_len;
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    if (domain->min || domain->max || domain->increment) {
        ACVP_LOG_ERR("Already registered domain value for this parameter");
        return ACVP_INVALID_ARG;
    }
    domain->value = value;
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_kdf135_ikev1_cap_param (ACVP_CTX *ctx,
                                                ACVP_KDF135_IKEV1_PARM param,
                                                char *value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_NAME_LIST *current_hash;
    ACVP_KDF135_IKEV1_CAP *cap;
    
    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF135_IKEV1);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_ikev1_cap;
    
    if (param == ACVP_KDF_IKEv1_HASH_ALG) {
        current_hash = cap->hash_algs;
        if (current_hash) {
            while (current_hash->next) {
                current_hash = current_hash->next;
            }
            current_hash->next = calloc(1, sizeof(ACVP_NAME_LIST));
            current_hash->next->name = value;
        } else {
            cap->hash_algs = calloc(1, sizeof(ACVP_NAME_LIST));
            cap->hash_algs->name = value;
        }
    } else if (param == ACVP_KDF_IKEv1_AUTH_METHOD) {
        memcpy(cap->auth_method, value, 3);
    } else {
        return ACVP_INVALID_ARG;
    }
    
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_kdf135_x963_cap_param (ACVP_CTX *ctx,
                                               ACVP_KDF135_X963_PARM param,
                                               int value) {
    ACVP_CAPS_LIST *cap_list;
    ACVP_NAME_LIST *current_hash;
    ACVP_SL_LIST *current_sl;
    ACVP_KDF135_X963_CAP *cap;
    
    cap_list = acvp_locate_cap_entry(ctx, ACVP_KDF135_X963);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_x963_cap;
    
    if (param == ACVP_KDF_X963_HASH_ALG) {
        current_hash = cap->hash_algs;
        if (current_hash) {
            while (current_hash->next) {
                current_hash = current_hash->next;
            }
            current_hash->next = calloc(1, sizeof(ACVP_NAME_LIST));
            switch (value) {
            case ACVP_KDF_X963_SHA224:
                current_hash->next->name = "SHA2-224";
                break;
            case ACVP_KDF_X963_SHA256:
                current_hash->next->name = "SHA2-256";
                break;
            case ACVP_KDF_X963_SHA384:
                current_hash->next->name = "SHA2-384";
                break;
            case ACVP_KDF_X963_SHA512:
                current_hash->next->name = "SHA2-512";
                break;
            default:
                return ACVP_INVALID_ARG;
            }
        } else {
            cap->hash_algs = calloc(1, sizeof(ACVP_NAME_LIST));
            switch (value) {
            case ACVP_KDF_X963_SHA224:
                cap->hash_algs->name = "SHA2-224";
                break;
            case ACVP_KDF_X963_SHA256:
                cap->hash_algs->name = "SHA2-256";
                break;
            case ACVP_KDF_X963_SHA384:
                cap->hash_algs->name = "SHA2-384";
                break;
            case ACVP_KDF_X963_SHA512:
                cap->hash_algs->name = "SHA2-512";
                break;
            default:
                return ACVP_INVALID_ARG;
            }
        }
    } else {
        switch (param) {
        case ACVP_KDF_X963_KEY_DATA_LEN:
            if (cap->key_data_lengths) {
                current_sl = cap->key_data_lengths;
                while (current_sl->next) {
                    current_sl = current_sl->next;
                }
                current_sl->next = calloc(1, sizeof(ACVP_SL_LIST));
                current_sl->next->length = value;
            } else {
                cap->key_data_lengths = calloc(1, sizeof(ACVP_SL_LIST));
                cap->key_data_lengths->length = value;
            }
            break;
        case ACVP_KDF_X963_FIELD_SIZE:
            if (cap->field_sizes) {
                current_sl = cap->field_sizes;
                while (current_sl->next) {
                    current_sl = current_sl->next;
                }
                current_sl->next = calloc(1, sizeof(ACVP_SL_LIST));
                current_sl->next->length = value;
            } else {
                cap->field_sizes = calloc(1, sizeof(ACVP_SL_LIST));
                cap->field_sizes->length = value;
            }
            break;
        case ACVP_KDF_X963_SHARED_INFO_LEN:
            if (cap->shared_info_lengths) {
                current_sl = cap->shared_info_lengths;
                while (current_sl->next) {
                    current_sl = current_sl->next;
                }
                current_sl->next = calloc(1, sizeof(ACVP_SL_LIST));
                current_sl->next->length = value;
            } else {
                cap->shared_info_lengths = calloc(1, sizeof(ACVP_SL_LIST));
                cap->shared_info_lengths->length = value;
            }
            break;
        default:
            return ACVP_INVALID_ARG;
        }
    }
    
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_kdf135_ikev2_domain_param (ACVP_CTX *ctx,
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
        domain = &cap_list->cap.kdf135_ikev2_cap->init_nonce_len_domain;
        break;
    case ACVP_RESPOND_NONCE_LEN:
        domain = &cap_list->cap.kdf135_ikev2_cap->respond_nonce_len_domain;
        break;
    case ACVP_DH_SECRET_LEN:
        domain = &cap_list->cap.kdf135_ikev2_cap->dh_secret_len;
        break;
    case ACVP_KEY_MATERIAL_LEN:
        domain = &cap_list->cap.kdf135_ikev2_cap->key_material_len;
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    if (domain->value) {
        ACVP_LOG_ERR("Already registered single value for this parameter");
        return ACVP_INVALID_ARG;
    }
    domain->min = min;
    domain->max = max;
    domain->increment = increment;
    
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_kdf135_ikev1_domain_param (ACVP_CTX *ctx,
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
        domain = &cap_list->cap.kdf135_ikev1_cap->init_nonce_len_domain;
        break;
    case ACVP_KDF_IKEv1_RESPOND_NONCE_LEN:
        domain = &cap_list->cap.kdf135_ikev1_cap->respond_nonce_len_domain;
        break;
    case ACVP_KDF_IKEv1_DH_SECRET_LEN:
        domain = &cap_list->cap.kdf135_ikev1_cap->dh_secret_len;
        break;
    case ACVP_KDF_IKEv1_PSK_LEN:
        domain = &cap_list->cap.kdf135_ikev1_cap->psk_len;
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    domain->min = min;
    domain->max = max;
    domain->increment = increment;
    
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_kdf108_domain_param (ACVP_CTX *ctx,
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
    default:
        return ACVP_INVALID_ARG;
    }
    domain->min = min;
    domain->max = max;
    domain->increment = increment;
    
    return ACVP_SUCCESS;
}

/*
 * Append a KAS-ECC pre req val to the capabilities
 */
static ACVP_RESULT acvp_add_kas_ecc_prereq_val (ACVP_KAS_ECC_CAP_MODE *kas_ecc_mode,
                                                ACVP_KAS_ECC_MODE mode, ACVP_PREREQ_ALG pre_req,
                                                char *value) {
    ACVP_PREREQ_LIST *prereq_entry, *prereq_entry_2;
    
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
    return (ACVP_SUCCESS);
}

ACVP_RESULT acvp_enable_kas_ecc_prereq_cap (ACVP_CTX *ctx,
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
    kas_ecc_mode = &kas_ecc_cap->kas_ecc_mode[mode-1];
    
    /*
     * Add the value to the cap
     */
    return (acvp_add_kas_ecc_prereq_val(kas_ecc_mode, mode, pre_req, value));
}


static ACVP_RESULT acvp_append_kas_ecc_caps_entry (
        ACVP_CTX *ctx,
        ACVP_KAS_ECC_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.kas_ecc_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    if (cipher == ACVP_KAS_ECC_CDH)
        cap_entry->cap_type = ACVP_KAS_ECC_CDH_TYPE;
    if (cipher == ACVP_KAS_ECC_COMP)
        cap_entry->cap_type = ACVP_KAS_ECC_COMP_TYPE;
    if (cipher == ACVP_KAS_ECC_NOCOMP)
        cap_entry->cap_type = ACVP_KAS_ECC_NOCOMP_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

ACVP_RESULT acvp_enable_kas_ecc_cap (ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    
    ACVP_KAS_ECC_CAP *kas_ecc_cap;
    ACVP_RESULT result;
    void *kas_ecc_mode;
    int i;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    /*
     * Check for duplicate entry
     */
    if (acvp_locate_cap_entry(ctx, cipher)) {
        return ACVP_DUP_CIPHER;
    }
    
    kas_ecc_cap = calloc(1, sizeof(ACVP_KAS_ECC_CAP));
    if (!kas_ecc_cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    kas_ecc_cap->cipher = cipher;
    
    kas_ecc_mode = calloc(1, ACVP_KAS_ECC_MAX_MODES * sizeof(ACVP_KAS_ECC_CAP_MODE) + 1);
    if (!kas_ecc_mode) {
        free(kas_ecc_cap);
        return ACVP_MALLOC_FAIL;
    }
    
    kas_ecc_cap->kas_ecc_mode = (ACVP_KAS_ECC_CAP_MODE *)kas_ecc_mode;
    for (i = 1; i <= ACVP_KAS_ECC_MAX_MODES; i++) {
        kas_ecc_cap->kas_ecc_mode[i - 1].cap_mode = (ACVP_KAS_ECC_MODE)i;
    }
    
    result = acvp_append_kas_ecc_caps_entry(ctx, kas_ecc_cap, cipher, crypto_handler);
    if (result != ACVP_SUCCESS) {
        free(kas_ecc_cap);
        free(kas_ecc_mode);
        kas_ecc_cap = NULL;
    }
    return result;
}

ACVP_RESULT acvp_enable_kas_ecc_cap_parm (ACVP_CTX *ctx,
                                          ACVP_CIPHER cipher,
                                          ACVP_KAS_ECC_MODE mode,
                                          ACVP_KAS_ECC_PARAM param,
                                          int value) {
    
    ACVP_CAPS_LIST *cap;
    ACVP_KAS_ECC_CAP *kas_ecc_cap;
    ACVP_KAS_ECC_CAP_MODE *kas_ecc_cap_mode;
    ACVP_PARAM_LIST *current_func;
    ACVP_PARAM_LIST *current_curve;
    
    if (!ctx) {
        return ACVP_NO_CTX;
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
    switch (mode)
    {
    case ACVP_KAS_ECC_MODE_CDH:
        switch (param)
        {
        case ACVP_KAS_ECC_FUNCTION:
            current_func = kas_ecc_cap_mode->function;
            if (current_func) {
                while (current_func->next) {
                    current_func = current_func->next;
                }
                current_func->next = calloc(1, sizeof(ACVP_PARAM_LIST));
                current_func->next->param = value;
            } else {
                kas_ecc_cap_mode->function = calloc(1, sizeof(ACVP_PARAM_LIST));
                kas_ecc_cap_mode->function->param = value;
            }
            break;
        case ACVP_KAS_ECC_CURVE:
            current_curve = kas_ecc_cap_mode->curve;
            if (current_curve) {
                while (current_curve->next) {
                    current_curve = current_curve->next;
                }
                current_curve->next = calloc(1, sizeof(ACVP_PARAM_LIST));
                current_curve->next->param = value;
            } else {
                kas_ecc_cap_mode->curve = calloc(1, sizeof(ACVP_PARAM_LIST));
                kas_ecc_cap_mode->curve->param = value;
            }
            break;
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-ECC param %d", param);
            return ACVP_INVALID_ARG;
            break;
        }
        break;
    case ACVP_KAS_ECC_MODE_COMPONENT:
        switch (param)
        {
        case ACVP_KAS_ECC_FUNCTION:
            current_func = kas_ecc_cap_mode->function;
            if (current_func) {
                while (current_func->next) {
                    current_func = current_func->next;
                }
                current_func->next = calloc(1, sizeof(ACVP_PARAM_LIST));
                current_func->next->param = value;
            } else {
                kas_ecc_cap_mode->function = calloc(1, sizeof(ACVP_PARAM_LIST));
                kas_ecc_cap_mode->function->param = value;
            }
            break;
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-ECC param %d", param);
            return ACVP_INVALID_ARG;
            break;
        }
        break;
    default:
        ACVP_LOG_ERR("\nUnsupported KAS-ECC mode %d", mode);
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_kas_ecc_cap_scheme (ACVP_CTX *ctx,
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
    ACVP_KAS_ECC_PSET *last_pset;
    ACVP_PARAM_LIST *current_role;
    ACVP_PARAM_LIST *current_hash;
    
    if (!ctx) {
        return ACVP_NO_CTX;
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
    switch (mode)
    {
    case ACVP_KAS_ECC_MODE_COMPONENT:
    case ACVP_KAS_ECC_MODE_NOCOMP:
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
        switch (param)
        {
        case ACVP_KAS_ECC_KDF:
            current_scheme->kdf = value;
            break;
        case ACVP_KAS_ECC_ROLE:
            current_role = current_scheme->role;
            if (current_role) {
                while (current_role->next) {
                    current_role = current_role->next;
                }
                current_role->next = calloc(1, sizeof(ACVP_PARAM_LIST));
                current_role->next->param = value;
            } else {
                current_role = calloc(1, sizeof(ACVP_PARAM_LIST));
                current_role->param = value;
                current_scheme->role = current_role;
            }
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
            current_hash = current_pset->sha;
            if (current_hash) {
                while (current_hash->next) {
                    current_hash = current_hash->next;
                }
                current_hash->next = calloc(1, sizeof(ACVP_PARAM_LIST));
                current_hash->next->param = value;
            } else {
                current_pset->sha = calloc(1, sizeof(ACVP_PARAM_LIST));
                current_pset->sha->param = value;
            }
            break;
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-ECC param %d", param);
            return ACVP_INVALID_ARG;
            break;
        }
        break;
    case ACVP_KAS_ECC_MODE_CDH:
    default:
        ACVP_LOG_ERR("Scheme parameter sets not supported for this mode %d\n", mode);
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}

/*
 * Append a KAS-FFC pre req val to the capabilities
 */
static ACVP_RESULT acvp_add_kas_ffc_prereq_val (ACVP_KAS_FFC_CAP_MODE *kas_ffc_mode,
                                                ACVP_KAS_FFC_MODE mode, ACVP_PREREQ_ALG pre_req,
                                                char *value) {
    ACVP_PREREQ_LIST *prereq_entry, *prereq_entry_2;
    
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
    return (ACVP_SUCCESS);
}

ACVP_RESULT acvp_enable_kas_ffc_prereq_cap (ACVP_CTX *ctx,
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
        break;
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
    kas_ffc_mode = &kas_ffc_cap->kas_ffc_mode[mode-1];
    
    /*
     * Add the value to the cap
     */
    return (acvp_add_kas_ffc_prereq_val(kas_ffc_mode, mode, pre_req, value));
}


static ACVP_RESULT acvp_append_kas_ffc_caps_entry (
        ACVP_CTX *ctx,
        ACVP_KAS_FFC_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    ACVP_CAPS_LIST *cap_entry, *cap_e2;
    
    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.kas_ffc_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    if (cipher == ACVP_KAS_FFC_COMP)
        cap_entry->cap_type = ACVP_KAS_FFC_COMP_TYPE;
    if (cipher == ACVP_KAS_FFC_NOCOMP)
        cap_entry->cap_type = ACVP_KAS_FFC_NOCOMP_TYPE;
    
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

ACVP_RESULT acvp_enable_kas_ffc_cap (ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case)) {
    
    ACVP_KAS_FFC_CAP *kas_ffc_cap;
    ACVP_RESULT result;
    void *kas_ffc_mode;
    int i;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }
    
    /*
     * Check for duplicate entry
     */
    if (acvp_locate_cap_entry(ctx, cipher)) {
        return ACVP_DUP_CIPHER;
    }
    
    kas_ffc_cap = calloc(1, sizeof(ACVP_KAS_FFC_CAP));
    if (!kas_ffc_cap) {
        return ACVP_MALLOC_FAIL;
    }
    
    kas_ffc_cap->cipher = cipher;
    
    kas_ffc_mode = calloc(1, ACVP_KAS_FFC_MAX_MODES * sizeof(ACVP_KAS_FFC_CAP_MODE) + 1);
    if (!kas_ffc_mode) {
        free(kas_ffc_cap);
        return ACVP_MALLOC_FAIL;
    }
    
    kas_ffc_cap->kas_ffc_mode = (ACVP_KAS_FFC_CAP_MODE *)kas_ffc_mode;
    for (i = 1; i <= ACVP_KAS_FFC_MAX_MODES; i++) {
        kas_ffc_cap->kas_ffc_mode[i - 1].cap_mode = (ACVP_KAS_FFC_MODE)i;
    }
    
    result = acvp_append_kas_ffc_caps_entry(ctx, kas_ffc_cap, cipher, crypto_handler);
    if (result != ACVP_SUCCESS) {
        free(kas_ffc_cap);
        free(kas_ffc_mode);
        kas_ffc_cap = NULL;
    }
    return result;
}

ACVP_RESULT acvp_enable_kas_ffc_cap_parm (ACVP_CTX *ctx,
                                          ACVP_CIPHER cipher,
                                          ACVP_KAS_FFC_MODE mode,
                                          ACVP_KAS_FFC_PARAM param,
                                          int value) {
    
    ACVP_CAPS_LIST *cap;
    ACVP_KAS_FFC_CAP *kas_ffc_cap;
    ACVP_KAS_FFC_CAP_MODE *kas_ffc_cap_mode;
    ACVP_PARAM_LIST *current_func;
    
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
    switch (mode)
    {
    case ACVP_KAS_FFC_MODE_COMPONENT:
        switch (param)
        {
        case ACVP_KAS_FFC_FUNCTION:
            current_func = kas_ffc_cap_mode->function;
            if (current_func) {
                while (current_func->next) {
                    current_func = current_func->next;
                }
                current_func->next = calloc(1, sizeof(ACVP_PARAM_LIST));
                current_func->next->param = value;
            } else {
                kas_ffc_cap_mode->function = calloc(1, sizeof(ACVP_PARAM_LIST));
                kas_ffc_cap_mode->function->param = value;
            }
            break;
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-FFC param %d", param);
            return ACVP_INVALID_ARG;
            break;
        }
        break;
    default:
        ACVP_LOG_ERR("\nUnsupported KAS-FFC mode %d", mode);
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_kas_ffc_cap_scheme (ACVP_CTX *ctx,
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
    ACVP_KAS_FFC_PSET *last_pset;
    ACVP_PARAM_LIST *current_role;
    ACVP_PARAM_LIST *current_hash;
    
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
    switch (mode)
    {
    case ACVP_KAS_FFC_MODE_COMPONENT:
    case ACVP_KAS_FFC_MODE_NOCOMP:
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
        switch (param)
        {
        case ACVP_KAS_FFC_KDF:
            current_scheme->kdf = value;
            break;
        case ACVP_KAS_FFC_ROLE:
            current_role = current_scheme->role;
            if (current_role) {
                while (current_role->next) {
                    current_role = current_role->next;
                }
                current_role->next = calloc(1, sizeof(ACVP_PARAM_LIST));
                current_role->next->param = value;
            } else {
                current_role = calloc(1, sizeof(ACVP_PARAM_LIST));
                current_role->param = value;
                current_scheme->role = current_role;
            }
            break;
        case ACVP_KAS_FFC_FB:
        case ACVP_KAS_FFC_FC:
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
            current_hash = current_pset->sha;
            if (current_hash) {
                while (current_hash->next) {
                    current_hash = current_hash->next;
                }
                current_hash->next = calloc(1, sizeof(ACVP_PARAM_LIST));
                current_hash->next->param = value;
            } else {
                current_pset->sha = calloc(1, sizeof(ACVP_PARAM_LIST));
                current_pset->sha->param = value;
            }
            break;
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-FFC param %d", param);
            return ACVP_INVALID_ARG;
            break;
        }
        break;
    default:
        ACVP_LOG_ERR("Scheme parameter sets not supported for this mode %d\n", mode);
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}