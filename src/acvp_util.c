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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include "acvp.h"
#include "acvp_lcl.h"
#include "safe_lib.h"

#ifdef _WIN32
#include <io.h>
#include <Windows.h>
#else
#include <unistd.h>
#endif

#ifdef USE_MURL
#include "murl.h"
#elif !defined ACVP_OFFLINE
#include <curl/curl.h>
#endif

#include <openssl/evp.h>

extern ACVP_ALG_HANDLER alg_tbl[];

static int acvp_char_to_int(char ch);

/*
 * Basic logging for libacvp
 */
void acvp_log_msg(ACVP_CTX *ctx, ACVP_LOG_LVL level, const char *func, int line, const char *fmt, ...) {
    va_list arguments;
    int iter = 0, ret = 0;
    //One extra char for null terminator
    char tmp[ACVP_LOG_MAX_MSG_LEN + 1];
    tmp[ACVP_LOG_MAX_MSG_LEN] = '\0';

    if (!ctx) {
        return;
    }

    if (ctx->debug) {
        iter = snprintf(tmp, ACVP_LOG_MAX_MSG_LEN, "[%s:%d]: ", func, line);
    }

    if (ctx->test_progress_cb && (ctx->log_lvl >= level)) {
        /*  Pull the arguments from the stack and invoke the logger function */
        va_start(arguments, fmt);
        ret = vsnprintf(tmp + iter, ACVP_LOG_MAX_MSG_LEN + 1 - iter, fmt, arguments);
        if (ret < 0 || ret >= ACVP_LOG_MAX_MSG_LEN + 1 - iter) {
            memcpy_s(tmp + ACVP_LOG_MAX_MSG_LEN - ACVP_LOG_TRUNCATED_STR_LEN,
                     ACVP_LOG_TRUNCATED_STR_LEN,
                     ACVP_LOG_TRUNCATED_STR, ACVP_LOG_TRUNCATED_STR_LEN);
            tmp[ACVP_LOG_MAX_MSG_LEN] = '\0';
        } else {
            iter += ret;
            tmp[iter] = '\0';
        }
        ctx->test_progress_cb(tmp, level);
        va_end(arguments);
        fflush(stdout);
    }
}

/*
 * Sometimes there is a need for line separation in the logs, but we still prefer for
 * the app handler to deal with it instead of making assumptions about output
 */
void acvp_log_newline(ACVP_CTX *ctx) {
     char tmp[] = "\n";
     ctx->test_progress_cb(tmp, ACVP_LOG_LVL_STATUS);
 }

/*!
 *
 * @brief Free all memory in the libacvp library.
 *        Please use this before you application exits.
 *
 * The libacvp library allocates memory internally that needs
 * to be freed before the calling application exits. The user
 * of libacvp should ensure that this function is called upon
 * encountering an error, or successful program termination.
 *
 * Curl requires a cleanup function to be invoked when done.
 * We must extend this to our user, which is done here.
 * Our users shouldn't have to include curl.h.
 *
 * @param ctx Pointer to ACVP_CTX to be freed. May be NULL.
 *
 */
ACVP_RESULT acvp_cleanup(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (ctx) {
        /* Only call if ctx is not null */
        rv = acvp_free_test_session(ctx);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to free parameter 'ctx'");
        }
    }
#ifndef ACVP_OFFLINE
    curl_global_cleanup();
#endif
    return rv;
}

/*
 * This function is used to locate the callback function that's needed
 * when a particular crypto operation is needed by libacvp.
 */
ACVP_CAPS_LIST *acvp_locate_cap_entry(ACVP_CTX *ctx, ACVP_CIPHER cipher) {
    ACVP_CAPS_LIST *cap;

    if (!ctx || !ctx->caps_list) {
        return NULL;
    }

    cap = ctx->caps_list;
    while (cap) {
        if (cap->cipher == cipher) {
            return cap;
        }
        cap = cap->next;
    }
    return NULL;
}

/*
 * This function returns the name of an algorithm given
 * a ACVP_CIPHER value.  It looks for the cipher in
 * the master algorithm table, returns NULL if none match.
 *
 * IMPORTANT: If using an asymmetric cipher with a mode,
 * note that this API only returns the alg string
 */
const char *acvp_lookup_cipher_name(ACVP_CIPHER alg) {
    int i;

    for (i = 0; i < ACVP_ALG_MAX; i++) {
        if (alg_tbl[i].cipher == alg) {
            return alg_tbl[i].name;
        }
    }
    return NULL;
}

/**
 * @brief This function returns the default revision of an algorithm given a ACVP_CIPHER value.
 *
 *        If the mode is given, then it will also use that to
 *        narrow down the search to entries that only match
 *        both the \p alg and \p mode.
 * 
 *        Note that this should not be used when the user registers an alternative revision for a
 *        cipher.
 *
 * @return String representing the Revision
 * @return NULL no match
 *
 */
const char *acvp_lookup_cipher_revision(ACVP_CIPHER alg) {
    int i = 0;

    for (i = 0; i < ACVP_ALG_MAX; i++) {
        if (alg_tbl[i].cipher == alg) {
            return alg_tbl[i].revision;
        }
    }

    return NULL;
}

/**
 * This table maintains a list of strings for revisions that can be registered as capabilities.
 */
static struct acvp_alt_revision_info alt_revision_tbl[] = {
    { ACVP_REVISION_SP800_56AR3, ACVP_REV_STR_SP800_56AR3 },
    { ACVP_REVISION_SP800_56CR1, ACVP_REV_STR_SP800_56CR1 },
    { ACVP_REVISION_FIPS186_4, ACVP_REV_STR_1_0 },
    { ACVP_REVISION_1_0, ACVP_REV_STR_1_0 }
};
static int alt_revision_tbl_length =
    sizeof(alt_revision_tbl) / sizeof(struct acvp_alt_revision_info);

/**
 * this function returns the string used in registration for an alternative revision registered by
 * a user.
 */
const char *acvp_lookup_alt_revision_string(ACVP_REVISION rev) {
    int i = 0;
    for (i = 0; i < alt_revision_tbl_length; i++) {
        if (alt_revision_tbl[i].revision == rev) {
            return alt_revision_tbl[i].name;
        }
    }
    return NULL;
}

/**
 * This function returns the enum for a given alternative revision string, or 0 if not found
 */
ACVP_REVISION acvp_lookup_alt_revision(const char *str) {
    int i = 0, diff = 1;
    for (i = 0; i < alt_revision_tbl_length; i++) {
        strcmp_s(alt_revision_tbl[i].name, ACVP_ALG_NAME_MAX, str, &diff);
        if (!diff) {
            return alt_revision_tbl[i].revision;
        }
    }
    return 0;
}

/**
 * @brief Loop through all entries in alg_tbl, trying to match
 *        \p algorithm to each name field. If successful, will
 *        return the ACVP_CIPHER id field.
 *
 * IMPORTANT: This only works accurately for algorithms that have
 * a 1:1 name to id entry. I.e. does not work for algorithms that
 * have multiple entries with the same name but different mode.
 * Use acvp_lookup_cipher_w_mode_index() for that!
 *
 * @return ACVP_CIPHER
 * @return 0 if no-match
 */
ACVP_CIPHER acvp_lookup_cipher_index(const char *algorithm) {
    int i = 0;

    if (!algorithm) {
        return 0;
    }

    for (i = 0; i < ACVP_ALG_MAX; i++) {
        int diff = 1;

        strcmp_s(alg_tbl[i].name,
                 ACVP_ALG_NAME_MAX,
                 algorithm, &diff);

        if (!diff) {
            return alg_tbl[i].cipher;
        }
    }

    return 0;
}

/**
 * @brief Loop through all entries in alg_tbl, trying to match
 *        both \p algorithm and \p mode to their respective fields.
 *        If successful, will return the ACVP_CIPHER id field.
 *
 * Useful for algorithms that have multiple modes (i.e. asymmetric).
 *
 * @return ACVP_CIPHER
 * @return 0 if no-match
 */
ACVP_CIPHER acvp_lookup_cipher_w_mode_index(const char *algorithm,
                                            const char *mode) {
    int i = 0;

    if (!algorithm || !mode) {
        return 0;
    }

    for (i = 0; i < ACVP_ALG_MAX; i++) {
        int diff = 0;

        if (alg_tbl[i].mode == NULL) continue;

        /* Compare the algorithm string */
        strcmp_s(alg_tbl[i].name,
                 ACVP_ALG_NAME_MAX,
                 algorithm, &diff);

        if (!diff) {
            /* Compare the mode string */
            strcmp_s(alg_tbl[i].mode,
                     ACVP_ALG_MODE_MAX,
                     mode, &diff);

            if (!diff) return alg_tbl[i].cipher;
        }
    }

    return 0;
}

/**
 * @brief Look through all of the entries in alg_tbl for the given cipher
 * and return the mode string if applicable or NULL if not
 *
 * @return const string representing the "mode" to be used for the given cipher
 * @return NULL if the given alg does not have a mode string (most do not)
 */
const char* acvp_lookup_cipher_mode_str(ACVP_CIPHER cipher) {
    int i;
    for (i = 0; i < ACVP_ALG_MAX; i++) {
        if (alg_tbl[i].cipher == cipher) {
            const char* mode_str = alg_tbl[i].mode;
            if (!mode_str || strnlen_s(mode_str, ACVP_ALG_MODE_MAX) < 1) {
                return NULL;
            } else {
                return mode_str;
            }
        }
    }
    return NULL;
}

/*
 * This method returns the string that corresponds to a randPQ
 * index value
 */
const char *acvp_lookup_rsa_randpq_name(int value) {
    switch (value) {
    case ACVP_RSA_KEYGEN_B32:
        return "B.3.2"; // "provRP"

    case ACVP_RSA_KEYGEN_B33:
        return "B.3.3"; // "probRP"

    case ACVP_RSA_KEYGEN_B34:
        return "B.3.4"; // "provPC"

    case ACVP_RSA_KEYGEN_B35:
        return "B.3.5"; // "bothPC"

    case ACVP_RSA_KEYGEN_B36:
        return "B.3.6"; // "probPC"

    default:
        return NULL;
    }
}

ACVP_RSA_PUB_EXP_MODE acvp_lookup_rsa_pub_exp_mode(const char *str) {
    int diff = 1;

    strcmp_s(ACVP_RSA_PUB_EXP_MODE_FIXED_STR,
             ACVP_RSA_PUB_EXP_MODE_FIXED_STR_LEN, str, &diff);
    if (!diff) return ACVP_RSA_PUB_EXP_MODE_FIXED;

    strcmp_s(ACVP_RSA_PUB_EXP_MODE_RANDOM_STR,
             ACVP_RSA_PUB_EXP_MODE_RANDOM_STR_LEN, str, &diff);
    if (!diff) return ACVP_RSA_PUB_EXP_MODE_RANDOM;

    return 0;
}

int acvp_lookup_rsa_randpq_index(const char *value) {
    int diff = 0;

    if (!value) {
        return 0;
    }

    strcmp_s("B.3.2", 5, value, &diff);
    if (!diff) return ACVP_RSA_KEYGEN_B32;

    strcmp_s("B.3.3", 5, value, &diff);
    if (!diff) return ACVP_RSA_KEYGEN_B33;

    strcmp_s("B.3.4", 5, value, &diff);
    if (!diff) return ACVP_RSA_KEYGEN_B34;

    strcmp_s("B.3.5", 5, value, &diff);
    if (!diff) return ACVP_RSA_KEYGEN_B35;

    strcmp_s("B.3.6", 5, value, &diff);
    if (!diff) return ACVP_RSA_KEYGEN_B36;

    return 0;
}

#define DRBG_MODE_NAME_MAX 12
static struct acvp_drbg_mode_name_t drbg_mode_tbl[] = {
    { ACVP_DRBG_SHA_1,       ACVP_STR_SHA_1          },
    { ACVP_DRBG_SHA_224,     ACVP_STR_SHA2_224       },
    { ACVP_DRBG_SHA_256,     ACVP_STR_SHA2_256       },
    { ACVP_DRBG_SHA_384,     ACVP_STR_SHA2_384       },
    { ACVP_DRBG_SHA_512,     ACVP_STR_SHA2_512       },
    { ACVP_DRBG_SHA_512_224, ACVP_STR_SHA2_512_224   },
    { ACVP_DRBG_SHA_512_256, ACVP_STR_SHA2_512_256   },
    { ACVP_DRBG_TDES,        ACVP_DRBG_MODE_TDES },
    { ACVP_DRBG_AES_128,     ACVP_DRBG_MODE_AES_128  },
    { ACVP_DRBG_AES_192,     ACVP_DRBG_MODE_AES_192  },
    { ACVP_DRBG_AES_256,     ACVP_DRBG_MODE_AES_256  }
};
static int drbg_mode_tbl_length =
    sizeof(drbg_mode_tbl) / sizeof(struct acvp_drbg_mode_name_t);

/*
 * This function returns the ID of a DRBG mode given an
 * algorithm name (as defined in the ACVP spec).  It
 * returns 0 if none match.
 */
ACVP_DRBG_MODE acvp_lookup_drbg_mode_index(const char *mode) {
    int i = 0;

    for (i = 0; i < drbg_mode_tbl_length; i++) {
        int diff = 0;
        strcmp_s(drbg_mode_tbl[i].name,
                 DRBG_MODE_NAME_MAX,
                 mode, &diff);

        if (!diff) {
            return drbg_mode_tbl[i].mode;
        }
    }

    return 0;
}

/* This function checks to see if the value is a valid
   true / false param */
ACVP_RESULT is_valid_tf_param(int value) {
    if (value == 0 || value == 1) { return ACVP_SUCCESS; } else { return ACVP_INVALID_ARG; }
}

#define HASH_ALG_NAME_MAX 12
/*
 * Local table for matching ACVP_HASH_ALG to name string and vice versa.
 */
static struct acvp_hash_alg_info hash_alg_tbl[] = {
    { ACVP_SHA1,       ACVP_STR_SHA_1        },
    { ACVP_SHA224,     ACVP_STR_SHA2_224     },
    { ACVP_SHA256,     ACVP_STR_SHA2_256     },
    { ACVP_SHA384,     ACVP_STR_SHA2_384     },
    { ACVP_SHA512,     ACVP_STR_SHA2_512     },
    { ACVP_SHA512_224, ACVP_STR_SHA2_512_224 },
    { ACVP_SHA512_256, ACVP_STR_SHA2_512_256 },
    { ACVP_SHA3_224,   ACVP_STR_SHA3_224     },
    { ACVP_SHA3_256,   ACVP_STR_SHA3_256     },
    { ACVP_SHA3_384,   ACVP_STR_SHA3_384     },
    { ACVP_SHA3_512,   ACVP_STR_SHA3_512     }
};
static int hash_alg_tbl_length =
    sizeof(hash_alg_tbl) / sizeof(struct acvp_hash_alg_info);

/**
 * @brief Using \p name, find the corresponding ACVP_HASH_ALG.
 *
 * @param[in] name The string representation of hash algorithm.
 *
 * @return ACVP_HASH_ALG
 * @return 0 - fail
 */
ACVP_HASH_ALG acvp_lookup_hash_alg(const char *name) {
    int i = 0;

    if (!name) return 0;

    for (i = 0; i < hash_alg_tbl_length; i++) {
        int diff = 0;

        strcmp_s(hash_alg_tbl[i].name,
                 HASH_ALG_NAME_MAX,
                 name, &diff);

        if (!diff) {
            return hash_alg_tbl[i].id;
        }
    }

    return 0;
}

/**
 * @brief Using ACVP_HASH_ALG \p id, find the string representation.
 *
 * @param[in] name The string representation of hash algorithm.
 *
 * @return char*
 * @return NULL - fail
 */
const char *acvp_lookup_hash_alg_name(ACVP_HASH_ALG id) {
    int i = 0;

    if (!id) return NULL;

    for (i = 0; i < hash_alg_tbl_length; i++) {
        if (id == hash_alg_tbl[i].id) {
            return hash_alg_tbl[i].name;
        }
    }

    return NULL;
}

const char *acvp_lookup_rsa_prime_test_name(ACVP_RSA_PRIME_TEST_TYPE type) {
    switch (type) {
    case ACVP_RSA_PRIME_TEST_TBLC2:
        return ACVP_RSA_PRIME_TEST_TBLC2_STR;

    case ACVP_RSA_PRIME_TEST_TBLC3:
        return ACVP_RSA_PRIME_TEST_TBLC3_STR;

    default:
        return NULL;
    }
}

/* This function checks to see if the value is a valid prime test (RSA) */
ACVP_RESULT is_valid_prime_test(const char *value) {
    int diff = 0;

    if (!value) { return ACVP_INVALID_ARG; }

    strcmp_s(ACVP_RSA_PRIME_TEST_TBLC2_STR, 5, value, &diff);
    if (!diff) return ACVP_SUCCESS;

    strcmp_s(ACVP_RSA_PRIME_TEST_TBLC3_STR, 5, value, &diff);
    if (!diff) return ACVP_SUCCESS;

    return ACVP_INVALID_ARG;
}

/* This function checks to see if the value is a valid prime test (RSA) */
ACVP_RESULT is_valid_rsa_mod(int value) {
    if (value != 2048 &&
        value != 3072 &&
        value != 4096) {
        return ACVP_INVALID_ARG;
    } else { return ACVP_SUCCESS; }
}

#define EC_CURVE_NAME_MAX 5
/*
 * Local table for matching ACVP_EC_CURVE to name string and vice versa.
 */
static struct acvp_ec_curve_info ec_curve_tbl[] = {
    { ACVP_EC_CURVE_P224, "P-224" },
    { ACVP_EC_CURVE_P256, "P-256" },
    { ACVP_EC_CURVE_P384, "P-384" },
    { ACVP_EC_CURVE_P521, "P-521" },
    { ACVP_EC_CURVE_B233, "B-233" },
    { ACVP_EC_CURVE_B283, "B-283" },
    { ACVP_EC_CURVE_B409, "B-409" },
    { ACVP_EC_CURVE_B571, "B-571" },
    { ACVP_EC_CURVE_K233, "K-233" },
    { ACVP_EC_CURVE_K283, "K-283" },
    { ACVP_EC_CURVE_K409, "K-409" },
    { ACVP_EC_CURVE_K571, "K-571" }
};
static int ec_curve_tbl_length =
    sizeof(ec_curve_tbl) / sizeof(struct acvp_ec_curve_info);

/*
 * Local table for matching ACVP_EC_CURVE to name string and vice versa.
 * Containes "deprecated" curves (still allowed for ECDSA_KEYVER and ECDSA_SIGVER).
 */
static struct acvp_ec_curve_info ec_curve_depr_tbl[] = {
    { ACVP_EC_CURVE_P192, "P-192" },
    { ACVP_EC_CURVE_B163, "B-163" },
    { ACVP_EC_CURVE_K163, "K-163" }
};
static int ec_curve_depr_tbl_length =
    sizeof(ec_curve_depr_tbl) / sizeof(struct acvp_ec_curve_info);

const char *acvp_lookup_ec_curve_name(ACVP_CIPHER cipher, ACVP_EC_CURVE id) {
    int i = 0;

    for (i = 0; i < ec_curve_tbl_length; i++) {
        if (id == ec_curve_tbl[i].id) {
            return ec_curve_tbl[i].name;
        }
    }

    if (cipher == ACVP_ECDSA_KEYVER || cipher == ACVP_ECDSA_SIGVER) {
        /* Check the deprecated curves */
        for (i = 0; i < ec_curve_depr_tbl_length; i++) {
            if (id == ec_curve_depr_tbl[i].id) {
                return ec_curve_depr_tbl[i].name;
            }
        }
    }

    return NULL;
}

ACVP_EC_CURVE acvp_lookup_ec_curve(ACVP_CIPHER cipher, const char *name) {
    int i = 0;

    for (i = 0; i < ec_curve_tbl_length; i++) {
        int diff = 0;

        strcmp_s(ec_curve_tbl[i].name,
                 EC_CURVE_NAME_MAX,
                 name, &diff);

        if (!diff) {
            return ec_curve_tbl[i].id;
        }
    }

    if (cipher == ACVP_ECDSA_KEYVER || cipher == ACVP_ECDSA_SIGVER) {
        /* Check the deprecated curves */
        for (i = 0; i < ec_curve_depr_tbl_length; i++) {
            int diff = 0;

            strcmp_s(ec_curve_depr_tbl[i].name,
                     EC_CURVE_NAME_MAX,
                     name, &diff);

            if (!diff) {
                return ec_curve_depr_tbl[i].id;
            }
        }
    }

    return 0;
}

static struct acvp_function_info acvp_aux_function_tbl[] = {
    { ACVP_HASH_SHA224, ACVP_ALG_SHA224 },
    { ACVP_HASH_SHA256, ACVP_ALG_SHA256 },
    { ACVP_HASH_SHA384, ACVP_ALG_SHA384 },
    { ACVP_HASH_SHA512, ACVP_ALG_SHA512 },
    { ACVP_HASH_SHA512_224, ACVP_ALG_SHA512_224 },
    { ACVP_HASH_SHA512_256, ACVP_ALG_SHA512_256 },
    { ACVP_HASH_SHA3_224, ACVP_ALG_SHA3_224 },
    { ACVP_HASH_SHA3_256, ACVP_ALG_SHA3_256 },
    { ACVP_HASH_SHA3_384, ACVP_ALG_SHA3_384 },
    { ACVP_HASH_SHA3_512, ACVP_ALG_SHA3_512 },
    { ACVP_HMAC_SHA2_224, ACVP_ALG_HMAC_SHA2_224 },
    { ACVP_HMAC_SHA2_256, ACVP_ALG_HMAC_SHA2_256 },
    { ACVP_HMAC_SHA2_384, ACVP_ALG_HMAC_SHA2_384 },
    { ACVP_HMAC_SHA2_512, ACVP_ALG_HMAC_SHA2_512 },
    { ACVP_HMAC_SHA2_512_224, ACVP_ALG_HMAC_SHA2_512_224 },
    { ACVP_HMAC_SHA2_512_256, ACVP_ALG_HMAC_SHA2_512_256 },
    { ACVP_HMAC_SHA3_224, ACVP_ALG_HMAC_SHA3_224 },
    { ACVP_HMAC_SHA3_256, ACVP_ALG_HMAC_SHA3_256 },
    { ACVP_HMAC_SHA3_384, ACVP_ALG_HMAC_SHA3_384 },
    { ACVP_HMAC_SHA3_512, ACVP_ALG_HMAC_SHA3_512 },
    { ACVP_KMAC_128, ACVP_ALG_KMAC_128 },
    { ACVP_KMAC_256, ACVP_ALG_KMAC_256 }
};
static int acvp_aux_function_tbl_len = sizeof(acvp_aux_function_tbl) / sizeof(struct acvp_function_info);

const char* acvp_lookup_aux_function_alg_str(ACVP_CIPHER alg) {
    int i = 0;
    for (i = 0; i < acvp_aux_function_tbl_len; i++) {
        if (alg == acvp_aux_function_tbl[i].cipher) {
            return acvp_aux_function_tbl[i].name;
        }
    }
    return NULL;
}

ACVP_CIPHER acvp_lookup_aux_function_alg_tbl(const char *str) {
    int diff = 1, i = 0;
    for (i = 0; i < acvp_aux_function_tbl_len; i++) {
    strcmp_s(acvp_aux_function_tbl[i].name, strnlen_s(acvp_aux_function_tbl[i].name, ACVP_ALG_NAME_MAX), str, &diff);
        if (!diff) {
            return acvp_aux_function_tbl[i].cipher;
        }
    }
    return 0;
}

#define ACVP_LMS_MODE_STR_MAX 64 /* arbitrary */

static struct acvp_enum_string_pair lms_mode_tbl[] = {
    { ACVP_LMS_MODE_SHA256_M24_H5, "LMS_SHA256_M24_H5"},
    { ACVP_LMS_MODE_SHA256_M24_H10, "LMS_SHA256_M24_H10"},
    { ACVP_LMS_MODE_SHA256_M24_H15, "LMS_SHA256_M24_H15"},
    { ACVP_LMS_MODE_SHA256_M24_H20, "LMS_SHA256_M24_H20"},
    { ACVP_LMS_MODE_SHA256_M24_H25, "LMS_SHA256_M24_H25"},
    { ACVP_LMS_MODE_SHA256_M32_H5, "LMS_SHA256_M32_H5"},
    { ACVP_LMS_MODE_SHA256_M32_H10, "LMS_SHA256_M32_H10"},
    { ACVP_LMS_MODE_SHA256_M32_H15, "LMS_SHA256_M32_H15"},
    { ACVP_LMS_MODE_SHA256_M32_H20, "LMS_SHA256_M32_H20"},
    { ACVP_LMS_MODE_SHA256_M32_H25, "LMS_SHA256_M32_H25"},
    { ACVP_LMS_MODE_SHAKE_M24_H5, "LMS_SHAKE_M24_H5"},
    { ACVP_LMS_MODE_SHAKE_M24_H10, "LMS_SHAKE_M24_H10"},
    { ACVP_LMS_MODE_SHAKE_M24_H15, "LMS_SHAKE_M24_H15"},
    { ACVP_LMS_MODE_SHAKE_M24_H20, "LMS_SHAKE_M24_H20"},
    { ACVP_LMS_MODE_SHAKE_M24_H25, "LMS_SHAKE_M24_H25"},
    { ACVP_LMS_MODE_SHAKE_M32_H5, "LMS_SHAKE_M32_H5"},
    { ACVP_LMS_MODE_SHAKE_M32_H10, "LMS_SHAKE_M32_H10"},
    { ACVP_LMS_MODE_SHAKE_M32_H15, "LMS_SHAKE_M32_H15"},
    { ACVP_LMS_MODE_SHAKE_M32_H20, "LMS_SHAKE_M32_H20"},
    { ACVP_LMS_MODE_SHAKE_M32_H25, "LMS_SHAKE_M32_H25"}
};

static int lms_mode_tbl_len = sizeof(lms_mode_tbl) / sizeof(struct acvp_enum_string_pair);

ACVP_LMS_MODE acvp_lookup_lms_mode(const char *str) {
    int diff = 1, i = 0;
    for (i = 0; i < lms_mode_tbl_len; i++) {
        strcmp_s(lms_mode_tbl[i].string, strnlen_s(lms_mode_tbl[i].string, ACVP_LMS_MODE_STR_MAX), str, &diff);
        if (!diff) {
            return lms_mode_tbl[i].enum_value;
        }
    }
    return 0;
}

const char *acvp_lookup_lms_mode_str(ACVP_LMS_MODE mode) {
    int i = 0;
    for (i = 0; i < lms_mode_tbl_len; i++) {
        if (mode == lms_mode_tbl[i].enum_value) {
            return lms_mode_tbl[i].string;
        }
    }
    return NULL;
}

static struct acvp_enum_string_pair lmots_mode_tbl[] = {
    { ACVP_LMOTS_MODE_SHA256_N24_W1, "LMOTS_SHA256_N24_W1" },
    { ACVP_LMOTS_MODE_SHA256_N24_W2, "LMOTS_SHA256_N24_W2" },
    { ACVP_LMOTS_MODE_SHA256_N24_W4, "LMOTS_SHA256_N24_W4" },
    { ACVP_LMOTS_MODE_SHA256_N24_W8, "LMOTS_SHA256_N24_W8" },
    { ACVP_LMOTS_MODE_SHA256_N32_W1, "LMOTS_SHA256_N32_W1" },
    { ACVP_LMOTS_MODE_SHA256_N32_W2, "LMOTS_SHA256_N32_W2" },
    { ACVP_LMOTS_MODE_SHA256_N32_W4, "LMOTS_SHA256_N32_W4" },
    { ACVP_LMOTS_MODE_SHA256_N32_W8, "LMOTS_SHA256_N32_W8" },
    { ACVP_LMOTS_MODE_SHAKE_N24_W1, "LMOTS_SHAKE_N24_W1" },
    { ACVP_LMOTS_MODE_SHAKE_N24_W2, "LMOTS_SHAKE_N24_W2" },
    { ACVP_LMOTS_MODE_SHAKE_N24_W4, "LMOTS_SHAKE_N24_W4" },
    { ACVP_LMOTS_MODE_SHAKE_N24_W8, "LMOTS_SHAKE_N24_W8" },
    { ACVP_LMOTS_MODE_SHAKE_N32_W1, "LMOTS_SHAKE_N32_W1" },
    { ACVP_LMOTS_MODE_SHAKE_N32_W2, "LMOTS_SHAKE_N32_W2" },
    { ACVP_LMOTS_MODE_SHAKE_N32_W4, "LMOTS_SHAKE_N32_W4" },
    { ACVP_LMOTS_MODE_SHAKE_N32_W8, "LMOTS_SHAKE_N32_W8" }
};

static int lmots_mode_tbl_len = sizeof(lmots_mode_tbl) / sizeof(struct acvp_enum_string_pair);

ACVP_LMOTS_MODE acvp_lookup_lmots_mode(const char *str) {
    int diff = 1, i = 0;
    for (i = 0; i < lmots_mode_tbl_len; i++) {
        strcmp_s(lmots_mode_tbl[i].string, strnlen_s(lmots_mode_tbl[i].string, ACVP_LMS_MODE_STR_MAX), str, &diff);
        if (!diff) {
            return lmots_mode_tbl[i].enum_value;
        }
    }
    return 0;
}

const char *acvp_lookup_lmots_mode_str(ACVP_LMOTS_MODE mode) {
    int i = 0;
    for (i = 0; i < lmots_mode_tbl_len; i++) {
        if (mode == lmots_mode_tbl[i].enum_value) {
            return lmots_mode_tbl[i].string;
        }
    }
    return NULL;
}

/* This seems too small to dictate having its own table/function, but future expandability may be useful */
static struct acvp_enum_string_pair rsa_key_format_tbl[] = {
    { ACVP_RSA_KEY_FORMAT_STANDARD, "standard" },
    { ACVP_RSA_KEY_FORMAT_CRT, "crt" }
};

static int rsa_key_format_tbl_len = sizeof(rsa_key_format_tbl) / sizeof(struct acvp_enum_string_pair);

const char *acvp_lookup_rsa_format_str(ACVP_RSA_KEY_FORMAT format) {
    int i = 0;
    for (i = 0; i < rsa_key_format_tbl_len; i++) {
        if (format == rsa_key_format_tbl[i].enum_value) {
            return rsa_key_format_tbl[i].string;
        }
    }
    return NULL;
}

/*
 * Convert a byte array from source to a hexadecimal string which is
 * stored in the destination.
 */
ACVP_RESULT acvp_bin_to_hexstr(const unsigned char *src, int src_len, char *dest, int dest_max) {
    int i, j;
    unsigned char nibb_a, nibb_b;
    unsigned char hex_chars[] = "0123456789ABCDEF";

    if (!src || !dest) {
        return ACVP_CONVERT_DATA_ERR;
    }

    if ((src_len * 2) > dest_max) {
        return ACVP_CONVERT_DATA_ERR;
    }

    for (i = 0, j = 0; i < src_len; i++, j += 2) {
        nibb_a = *src >> 4;   /* Get first half of byte */
        nibb_b = *src & 0x0f; /* Get second half of byte */

        *dest = hex_chars[nibb_a];
        *(dest + 1) = hex_chars[nibb_b];

        dest += 2;
        src++;
    }
    *dest = '\0';

    return ACVP_SUCCESS;
}

/*
 * Convert a source hexadecimal string to a byte array which is stored
 * in the destination.
 * TODO: Enable the function to handle odd number of hex characters
 */
ACVP_RESULT acvp_hexstr_to_bin(const char *src, unsigned char *dest, int dest_max, int *converted_len) {
    int src_len;
    int byte_a, byte_b;
    int is_odd = 0;
    int length_converted = 0;

    if (!src || !dest) {
        return ACVP_INVALID_ARG;
    }

    src_len = strnlen_s(src, ACVP_HEXSTR_MAX);

    /*
     * Make sure the hex value isn't too large
     */
    if (src_len > (2 * dest_max)) {
        return ACVP_DATA_TOO_LARGE;
    }

    if (src_len & 1) {
        is_odd = 1;
    }

    if (!is_odd) {
        while (*src && src[1]) {
            byte_a = acvp_char_to_int((char)*src) << 4; /* Shift to left half of byte */
            byte_b = acvp_char_to_int(*(src + 1));

            *dest = byte_a + byte_b; /* Combine left half with right half */

            dest++;
            src += 2;
            length_converted++;
        }
    } else {
        return ACVP_UNSUPPORTED_OP;
    }

    if (converted_len) *converted_len = length_converted;
    return ACVP_SUCCESS;
}

/*
 * Local - helper function for acvp_hexstring_to_bytes
 * Used to convert a hexadecimal character to it's byte
 * representation.
 */
static int acvp_char_to_int(char ch) {
    int ch_i;

    if (ch >= '0' && ch <= '9') {
        ch_i = ch - '0';
    } else if (ch >= 'A' && ch <= 'F') {
        ch_i = ch - 'A' + 10;
    } else if (ch >= 'a' && ch <= 'f') {
        ch_i = ch - 'a' + 10;
    } else {
        ch_i = 0;
    }

    return ch_i;
}

ACVP_DRBG_MODE_LIST *acvp_locate_drbg_mode_entry(ACVP_CAPS_LIST *cap, ACVP_DRBG_MODE mode) {
    ACVP_DRBG_MODE_LIST *cap_mode = NULL;
    ACVP_DRBG_CAP *drbg_cap = NULL;

    drbg_cap = cap->cap.drbg_cap;

    /* No entires yet */
    cap_mode = drbg_cap->drbg_cap_mode;

    while (cap_mode) {
        if (cap_mode->mode == mode) {
            return cap_mode;
        }
        cap_mode = cap_mode->next;
    }
    return NULL;
}

ACVP_DRBG_MODE_LIST *acvp_create_drbg_mode_entry(ACVP_CAPS_LIST *cap, ACVP_DRBG_MODE mode) {
    ACVP_DRBG_MODE_LIST *entry = NULL, *list = NULL;

    if (acvp_locate_drbg_mode_entry(cap, mode) != NULL) {
        return NULL;
    }

    entry = calloc(1, sizeof(ACVP_DRBG_MODE_LIST));
    if (!entry) {
        return NULL;
    }

    entry->mode = mode;

    list = cap->cap.drbg_cap->drbg_cap_mode;
    if (!list) {
        cap->cap.drbg_cap->drbg_cap_mode = entry;
    } else {
        while (list->next) {
            list = list->next;
        }
        list->next = entry;
    }

    return entry;
}

ACVP_DRBG_CAP_GROUP *acvp_locate_drbg_group_entry(ACVP_DRBG_MODE_LIST *mode, int group) {
    ACVP_DRBG_GROUP_LIST *list = NULL;

    list = mode->groups;
    while (list) {
        if (group == list->id) {
            return list->group;
        }
        list = list->next;
    }

    return NULL;
}


ACVP_DRBG_CAP_GROUP *acvp_create_drbg_group(ACVP_DRBG_MODE_LIST *mode, int group) {
    ACVP_DRBG_GROUP_LIST *entry = NULL, *list = NULL;
    ACVP_DRBG_CAP_GROUP *grp = NULL;

    if (acvp_locate_drbg_group_entry(mode, group) != NULL) {
        return NULL;
    }

    entry = calloc(1, sizeof(ACVP_DRBG_GROUP_LIST));
    if (!entry) {
        return NULL;
    }
    grp = calloc(1, sizeof(ACVP_DRBG_CAP_GROUP));
    if (!grp) {
        free(entry);
        return NULL;
    }

    entry->id = group;
    entry->group = grp;

    list = mode->groups;
    if (!list) {
        mode->groups = entry;
    } else {
        while (list->next) {
            list = list->next;
        }
        list->next = entry;
    }

    return grp;
}

/*
 * Creates a JSON acvp array which consists of
 * [{preamble}, {object}]
 * preamble is populated with the version string
 * returns ACVP_SUCCESS or ACVP_JSON_ERR
 */
ACVP_RESULT acvp_create_array(JSON_Object **obj, JSON_Value **val, JSON_Array **arry) {
    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Value *ver_val = NULL;
    JSON_Object *ver_obj = NULL;
    JSON_Array *reg_arry = NULL;

    reg_arry_val = json_value_init_array();
    if (!reg_arry_val) {
        return ACVP_JSON_ERR;
    }

    reg_obj = json_value_get_object(reg_arry_val);
    reg_arry = json_array((const JSON_Value *)reg_arry_val);
    if (!reg_arry) {
        return ACVP_JSON_ERR;
    }

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);
    if (!ver_obj) {
        return ACVP_JSON_ERR;
    }

    json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
    if (json_array_append_value(reg_arry, ver_val) != JSONSuccess) {
        return ACVP_JSON_ERR;
    }

    *obj = reg_obj;
    *val = reg_arry_val;
    *arry = reg_arry;
    return ACVP_SUCCESS;
}

/*
 * This function returns a string that describes the error
 * code passed in.
 */
const char *acvp_lookup_error_string(ACVP_RESULT rv) {
    int i;
    struct acvp_result_desc_t error_desc_tbl[ACVP_RESULT_MAX - 1] = {
        { ACVP_MALLOC_FAIL,        "Error allocating memory"                          },
        { ACVP_NO_CTX,             "No valid context found"                           },
        { ACVP_TRANSPORT_FAIL,     "Error using transport library"                    },
        { ACVP_NO_DATA,            "Trying to use data but none was found"            },
        { ACVP_UNSUPPORTED_OP,     "Unsupported operation"                            },
        { ACVP_CLEANUP_FAIL,       "Error cleaning up ACVP context"                   },
        { ACVP_KAT_DOWNLOAD_RETRY, "Error, need to retry"                             },
        { ACVP_INVALID_ARG,        "Invalid argument"                                 },
        { ACVP_MISSING_ARG,        "Missing a required argument"                      },
        { ACVP_CRYPTO_MODULE_FAIL, "Error from crypto module processing a vector set" },
        { ACVP_NO_CAP,             "No matching capability found"                     },
        { ACVP_MALFORMED_JSON,     "Unable to process JSON"                           },
        { ACVP_JSON_ERR,           "Error using JSON library"                         },
        { ACVP_TC_MISSING_DATA,    "Provided test case is missing required data"      },
        { ACVP_TC_INVALID_DATA,    "Provided test case has invalid data"              },
        { ACVP_DATA_TOO_LARGE,     "Data too large"                                   },
        { ACVP_CONVERT_DATA_ERR,   "Failed converting data between hex/binary"        },
        { ACVP_DUP_CIPHER,         "Duplicate cipher, may have already registered"    },
        { ACVP_TOTP_FAIL,          "Failed to base64 decode TOTP seed"                },
        { ACVP_CTX_NOT_EMPTY,      "ctx already initialized"                          },
        { ACVP_JWT_MISSING,        "Error using JWT"                                  },
        { ACVP_JWT_EXPIRED,        "Provided JWT has expired"                         },
        { ACVP_JWT_INVALID,        "Proivded JWT is not valid"                        },
        { ACVP_INTERNAL_ERR,       "Unexpected error occured internally"              }
    };

    for (i = 0; i < ACVP_RESULT_MAX - 1; i++) {
        if (rv == error_desc_tbl[i].rv) {
            return error_desc_tbl[i].desc;
        }
    }
    return "Unknown error";
}

#define ACVP_UTIL_KV_STR_MAX 256

ACVP_RESULT acvp_kv_list_append(ACVP_KV_LIST **kv_list,
                                const char *key,
                                const char *value) {
    ACVP_KV_LIST *kv = NULL;

    if (kv_list == NULL || key == NULL || value == NULL) {
        return ACVP_INVALID_ARG;
    }
    if (!string_fits(key, ACVP_UTIL_KV_STR_MAX)) {
        return ACVP_INVALID_ARG;
    }
    if (!string_fits(value, ACVP_UTIL_KV_STR_MAX)) {
        return ACVP_INVALID_ARG;
    }

    if (*kv_list == NULL) {
        *kv_list = calloc(1, sizeof(ACVP_KV_LIST));
        if (*kv_list == NULL) return ACVP_MALLOC_FAIL;
        kv = *kv_list;
    } else {
        ACVP_KV_LIST *current = *kv_list;
        while (current->next) {
            current = current->next;
        }

        // Append the next entry
        current->next = calloc(1, sizeof(ACVP_KV_LIST));
        if (current->next == NULL) return ACVP_MALLOC_FAIL;
        kv = current->next;
    }

    kv->key = calloc(ACVP_UTIL_KV_STR_MAX + 1, sizeof(char));
    if (kv->key == NULL) return ACVP_MALLOC_FAIL;
    kv->value = calloc(ACVP_UTIL_KV_STR_MAX + 1, sizeof(char));
    if (kv->value == NULL) return ACVP_MALLOC_FAIL;

    strcpy_s(kv->key, ACVP_UTIL_KV_STR_MAX + 1, key);
    strcpy_s(kv->value, ACVP_UTIL_KV_STR_MAX + 1, value);

    return ACVP_SUCCESS;
}

void acvp_kv_list_free(ACVP_KV_LIST *kv_list) {
    ACVP_KV_LIST *tmp;

    while (kv_list) {
        tmp = kv_list;
        kv_list = kv_list->next;
        if (tmp->key) free(tmp->key);
        if (tmp->value) free(tmp->value);
        free(tmp);
    }
}

ACVP_RESULT acvp_setup_json_rsp_group(ACVP_CTX **ctx,
                                      JSON_Value **outer_arr_val,
                                      JSON_Value **r_vs_val,
                                      JSON_Object **r_vs,
                                      const char *alg_str,
                                      JSON_Array **groups_arr) {
    if ((*ctx)->kat_resp) {
        json_value_free((*ctx)->kat_resp);
    }
    (*ctx)->kat_resp = *outer_arr_val;

    *r_vs_val = json_value_init_object();
    *r_vs = json_value_get_object(*r_vs_val);
    if (!*r_vs) {
        return ACVP_JSON_ERR;
    } 

    if (json_object_set_number(*r_vs, "vsId", (*ctx)->vs_id) != JSONSuccess ||
            json_object_set_string(*r_vs, "algorithm", alg_str) != JSONSuccess) {
        return ACVP_JSON_ERR;
    }

    /* create an array of response test groups */
    json_object_set_value(*r_vs, "testGroups", json_value_init_array());
    (*groups_arr) = json_object_get_array(*r_vs, "testGroups");
    if (!*groups_arr) {
        return ACVP_JSON_ERR;
    }

    return ACVP_SUCCESS;
}

static const char *acvp_get_version_from_rsp(JSON_Value *arry_val) {
    const char *version = NULL;
    JSON_Object *ver_obj = NULL;

    JSON_Array *reg_array;

    reg_array = json_value_get_array(arry_val);
    ver_obj = json_array_get_object(reg_array, 0);
    version = json_object_get_string(ver_obj, "acvVersion");
    if (version == NULL) {
        return NULL;
    }

    return version;
}

JSON_Object *acvp_get_obj_from_rsp(ACVP_CTX *ctx, JSON_Value *arry_val) {
    JSON_Object *obj = NULL;
    JSON_Array *reg_array;
    const char *ver = NULL;

    if (!ctx || !arry_val) {
        ACVP_LOG_ERR("Missing arguments");
        return NULL;
    }
    reg_array = json_value_get_array(arry_val);
    ver = acvp_get_version_from_rsp(arry_val);
    if (ver == NULL) {
        return NULL;
    }


    obj = json_array_get_object(reg_array, 1);
    return obj;
}

void acvp_release_json(JSON_Value *r_vs_val,
                       JSON_Value *r_gval) {

    if (r_gval) json_value_free(r_gval);
    if (r_vs_val) json_value_free(r_vs_val);
}

/**
 * @brief Determine if the given \p string fits within the \p max_allowed length.
 *
 * Measure the length of the \p string to see whether it's length
 * (not including terminator) is <= \p max_allowed.
 *
 * @return 1 Length of \string <= \p max_allowed
 * @return 0 Length of \string > \p max_allowed
 * 
 */
int string_fits(const char *string, unsigned int max_allowed) {
    if (strnlen_s(string, max_allowed + 1) > max_allowed) {
        return 0;
    }

    return 1;
}

/*
 * Simple utility function to free a string
 * list.
 */
void acvp_free_str_list(ACVP_STRING_LIST **list) {
    ACVP_STRING_LIST *top = NULL;
    ACVP_STRING_LIST *tmp = NULL;

    if (list == NULL) return;
    top = *list;
    if (top == NULL) return;

    while (top) {
        if (top->string) free(top->string);
        tmp = top;
        top = top->next;
        free(tmp);
    }

    *list = NULL;
}

/**
 * Simple utility function to add an entry to a SL list. if the list is NULL, it is created
 * with the given entry being the first one.
 */
ACVP_RESULT acvp_append_sl_list(ACVP_SL_LIST **list, int length) {
    ACVP_SL_LIST *current = NULL;
    if (!list) {
        return ACVP_NO_DATA;
    }
    
    if (*list == NULL) {
        *list = calloc(1, sizeof(ACVP_SL_LIST));
        if (!*list) {
            return ACVP_MALLOC_FAIL;
        }
        (*list)->length = length;
        return ACVP_SUCCESS;
    }
    current = *list;
    while (current) {
        if (!current->next) {
            current->next = calloc(1, sizeof(ACVP_SL_LIST));
            if (!current->next) {
                return ACVP_MALLOC_FAIL;
            }
            current->next->length = length;
            return ACVP_SUCCESS;
        }
        current = current->next;
    }

    /* Code should never reach here */
    return ACVP_UNSUPPORTED_OP;
}

/**
 * Simple utility function to add an entry to a param list. if the list is NULL, it is created
 * with the given entry being the first one.
 */
ACVP_RESULT acvp_append_param_list(ACVP_PARAM_LIST **list, int param) {
    ACVP_PARAM_LIST *current = NULL;
    if (!list) {
        return ACVP_NO_DATA;
    }
    
    if (*list == NULL) {
        *list = calloc(1, sizeof(ACVP_PARAM_LIST));
        if (!*list) {
            return ACVP_MALLOC_FAIL;
        }
        (*list)->param = param;
        return ACVP_SUCCESS;
    }
    current = *list;
    while (current) {
        if (!current->next) {
            current->next = calloc(1, sizeof(ACVP_PARAM_LIST));
            if (!current->next) {
                return ACVP_MALLOC_FAIL;
            }
            current->next->param = param;
            return ACVP_SUCCESS;
        }
        current = current->next;
    }

    /* Code should never reach here */
    return ACVP_INTERNAL_ERR;
}

/**
 * Simple utility function to add a entry to a name list. If the list is NULL, it is created
 * with the given entry being the first one. Note the string is REFERENCED, not copied.
 * This function should be able to accomdate the removal of names from the list if needed in the
 * future; if a name is removed from the list but its node remains (with a NULL value) then
 * the given string will be added to the "dummy" node
 */
ACVP_RESULT acvp_append_name_list(ACVP_NAME_LIST **list, const char *string) {
    ACVP_NAME_LIST *current = NULL;
    if (!list) {
        return ACVP_NO_DATA;
    }

    if (!*list) {
        *list = calloc(1, sizeof(ACVP_NAME_LIST));
        if (!*list) {
            return ACVP_MALLOC_FAIL;
        }
    }
    current = *list;
    while (current) {
        if (!current->name) {
            current->name = string;
            return ACVP_SUCCESS;
        }
        if (!current->next) {
            current->next = calloc(1, sizeof(ACVP_NAME_LIST));
            if (!current->next) {
                return ACVP_MALLOC_FAIL;
            }
        }
        current = current->next;
    }
    /* Code should never reach here */
    return ACVP_UNSUPPORTED_OP;
}

/**
 * Check if a REFERENCE to a certain string already exists in a name list
 */
int acvp_is_in_name_list(ACVP_NAME_LIST *list, const char *string) {
    ACVP_NAME_LIST *current = NULL;
    if (!list) {
        return 0;
    }
    current = list;
    while (current) {
        if (current->name && current->name == string) {
            return 1;
        }
        current = current->next;
    }
    return 0;
}

/**
 * Simple utility function to add a string to a string list.
 * Note that the string is COPIED and not referenced.
 */
ACVP_RESULT acvp_append_str_list(ACVP_STRING_LIST **list, const char *string) {
    ACVP_STRING_LIST *current = NULL;
    ACVP_STRING_LIST *prev = NULL;
    char *word = NULL;

    if (!list) {
        return ACVP_NO_DATA;
    }

    int len = strnlen_s(string, ACVP_STRING_LIST_MAX_LEN);
    word = calloc(len + 1, sizeof(char));
    if (!word) {
        return ACVP_MALLOC_FAIL;
    }
    strncpy_s(word, len + 1, string, len);

    if (*list == NULL) {
        *list = calloc(1, sizeof(ACVP_STRING_LIST));
        if (*list == NULL) {
            free(word);
            return ACVP_MALLOC_FAIL;
        }
        (*list)->string = word;
        return ACVP_SUCCESS;
    } else {
        current = *list;
        while (current) {
            prev = current;
            current = current->next;
        }
        prev->next = calloc(1, sizeof(ACVP_STRING_LIST));
        if (!prev->next) {
            free(word);
            return ACVP_MALLOC_FAIL;
        }
        prev->next->string = word;
        return ACVP_SUCCESS;
    }

}

/**
 * Simple utility for looking to see if a string already exists
 * inside of a string list.
 */
int acvp_lookup_str_list(ACVP_STRING_LIST **list, const char *string) {
    ACVP_STRING_LIST *tmp = NULL;
    if (!list || *list == NULL || !string) {
        return 0;
    }
    tmp = *list;
    int diff = 1;
    int len1 = 0;
    int len2 = 0;
    int minlen = 0;
    while(tmp && tmp->string) {
        len1 = strnlen_s(tmp->string, ACVP_STRING_LIST_MAX_LEN);
        len2 = strnlen_s(string, ACVP_STRING_LIST_MAX_LEN);
        minlen = len1 < len2 ? len1 : len2;
        strncmp_s(tmp->string, len1, string, minlen, &diff);
        if (!diff) {
            return 1;
        }
        tmp = tmp->next;
    }
    return 0;
}

/**
 * Simple utility for searching if a value already exists in a
 * param list.
 */
int acvp_lookup_param_list(ACVP_PARAM_LIST *list, int value) {
    if (!list) {
        return 0;
    }
    while(list) {
        if (value == list->param) {
            return 1;
        } else {
            list = list->next;
        }
    }
    return 0;
}

/**
 * Checks if a domain value in a capability object has already been set
 * if all values are 0, then domain is considered empty
 * helps keep code cleaner in places where we woud need to reference
 * through several unions/pointers
 */
int acvp_is_domain_already_set(ACVP_JSON_DOMAIN_OBJ *domain) {
    return domain->min + domain->max + domain->increment;
}

ACVP_RESULT acvp_json_serialize_to_file_pretty_a(const JSON_Value *value, const char *filename) {
    ACVP_RESULT return_code = ACVP_SUCCESS;
    FILE *fp = NULL;
    char *serialized_string = NULL; 

    if (!filename) {
        return ACVP_INVALID_ARG;
    }

    fp = fopen(filename, "a");
    if (fp == NULL) {
        return ACVP_JSON_ERR;
    }
    if (!value) {
        if (fputs(" ]", fp) == EOF) {
            return_code = ACVP_JSON_ERR;
        }
    } else {

        serialized_string = json_serialize_to_string_pretty(value, NULL);
        if (serialized_string == NULL) {
            fclose(fp);
            return ACVP_JSON_ERR;
        }
        if (fputs(", ", fp) == EOF) {
            return_code = ACVP_JSON_ERR;
            goto end;
        }
        if (fputs(serialized_string, fp) == EOF) {
            return_code = ACVP_JSON_ERR;
        }
    }
end:
    if (fclose(fp) == EOF) {
        return_code = ACVP_JSON_ERR;
    }
    json_free_serialized_string(serialized_string);
    return return_code;
}

ACVP_RESULT acvp_json_serialize_to_file_pretty_w(const JSON_Value *value, const char *filename) {
    ACVP_RESULT return_code = ACVP_SUCCESS;
    FILE *fp = NULL;
    char *serialized_string = NULL;

    if (!value) {
        return ACVP_JSON_ERR;
    }
    if (!filename) {
        return ACVP_INVALID_ARG;
    }

    serialized_string = json_serialize_to_string_pretty(value, NULL);
    if (serialized_string == NULL) {
        return ACVP_JSON_ERR;
    }
    fp = fopen(filename, "w");
    if (fp == NULL) {
        json_free_serialized_string(serialized_string);
        return ACVP_JSON_ERR;
    }
    if (fputs("[ ", fp) == EOF) {
        return_code = ACVP_JSON_ERR;
        goto end;
    }
    if (fputs(serialized_string, fp) == EOF) {
        json_free_serialized_string(serialized_string);
        return_code = ACVP_JSON_ERR;
    }
end:
    if (fclose(fp) == EOF) {
        return_code = ACVP_JSON_ERR;
    }
    json_free_serialized_string(serialized_string);
    return return_code;
}

void acvp_sleep(int seconds) {
#ifdef _WIN32
    Sleep(seconds * 1000);
#else
    sleep(seconds);
#endif
}

ACVP_RESULT acvp_digest(ACVP_HASH_ALG alg,
                        const unsigned char *src,
                        size_t src_len,
                        unsigned char *dest,
                        size_t dest_max,
                        size_t *dest_len) {
    unsigned char md[EVP_MAX_MD_SIZE] = {0};
    size_t md_len = 0;
    const char *alg_name = NULL;
    
    alg_name = acvp_lookup_hash_alg_name(alg);
    if (alg_name == NULL) {
        return ACVP_INVALID_ARG;
    }

    if (EVP_Q_digest(NULL, alg_name, NULL, src, src_len, md, &md_len) == 0) {
        return ACVP_INTERNAL_ERR;
    }

    if (memcpy_s(dest, dest_max, md, md_len) != EOK) {
        return ACVP_MALLOC_FAIL;
    }

    if (dest_len != NULL) {
        *dest_len = md_len;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_bin_to_hashstr(ACVP_HASH_ALG alg,
                                const unsigned char *src,
                                size_t src_len,
                                char *dest,
                                size_t dest_max) {
    int rv = ACVP_SUCCESS;
    unsigned char md[EVP_MAX_MD_SIZE] = {0};
    size_t md_len = 0;
    
    rv = acvp_digest(alg, src, src_len, md, sizeof(md), &md_len);
    if (rv != ACVP_SUCCESS) {
        return rv;
    }

    rv = acvp_bin_to_hexstr(md, md_len, dest, dest_max);
    if (rv != ACVP_SUCCESS) {
        return rv;
    }

    return ACVP_SUCCESS;
}
