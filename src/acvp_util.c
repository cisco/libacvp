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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "acvp.h"
#include "acvp_lcl.h"
#include "safe_lib.h"

#ifdef USE_MURL
#include <murl/murl.h>
#else
#include <curl/curl.h>
#endif

extern ACVP_ALG_HANDLER alg_tbl[];

static int acvp_char_to_int(char ch);

/*
 * This is a rudimentary logging facility for libacvp.
 * We will need more when moving beyond the PoC phase.
 */
void acvp_log_msg(ACVP_CTX *ctx, ACVP_LOG_LVL level, const char *format, ...) {
    va_list arguments;
    char tmp[1024 * 2];

    if (ctx && ctx->test_progress_cb && (ctx->debug >= level)) {
        /*
         * Pull the arguments from the stack and invoke
         * the logger function
         */
        va_start(arguments, format);
        vsnprintf(tmp, 1023 * 2, format, arguments);
        ctx->test_progress_cb(tmp);
        va_end(arguments);
        fflush(stdout);
    }
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

    curl_global_cleanup();

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
char *acvp_lookup_cipher_name(ACVP_CIPHER alg) {
    int i;

    for (i = 0; i < ACVP_ALG_MAX; i++) {
        if (alg_tbl[i].cipher == alg) {
            return alg_tbl[i].name;
        }
    }
    return NULL;
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
                 strnlen_s(alg_tbl[i].name, ACVP_ALG_NAME_MAX),
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
                 strnlen_s(alg_tbl[i].name, ACVP_ALG_NAME_MAX),
                 algorithm, &diff);

        if (!diff) {
            /* Compare the mode string */
            strcmp_s(alg_tbl[i].mode,
                     strnlen_s(alg_tbl[i].mode, ACVP_ALG_MODE_MAX),
                     mode, &diff);

            if (!diff) return alg_tbl[i].cipher;
        }
    }

    return 0;
}

/*
 * This method returns the string that corresponds to a randPQ
 * index value
 */
char *acvp_lookup_rsa_randpq_name(int value) {
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
    { ACVP_DRBG_3KEYTDEA,    ACVP_DRBG_MODE_3KEYTDEA },
    { ACVP_DRBG_AES_128,     ACVP_DRBG_MODE_AES_128  },
    { ACVP_DRBG_AES_192,     ACVP_DRBG_MODE_AES_192  },
    { ACVP_DRBG_AES_256,     ACVP_DRBG_MODE_AES_256  }
};
static int drbg_mode_tbl_length =
    sizeof(drbg_mode_tbl) / sizeof(struct acvp_drbg_mode_name_t);

/*
 * This function returns the ID of a DRBG mode given an
 * algorithm name (as defined in the ACVP spec).  It
 * returns ACVP_DRBG_MODE_END if none match.
 */
ACVP_DRBG_MODE acvp_lookup_drbg_mode_index(const char *mode) {
    int i = 0;

    for (i = 0; i < drbg_mode_tbl_length; i++) {
        int diff = 0;
        strcmp_s(drbg_mode_tbl[i].name,
                 strnlen_s(drbg_mode_tbl[i].name, DRBG_MODE_NAME_MAX),
                 mode, &diff);

        if (!diff) {
            return drbg_mode_tbl[i].mode;
        }
    }

    return ACVP_DRBG_MODE_END;
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
    { ACVP_SHA512_256, ACVP_STR_SHA2_512_256 }
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
                 strnlen_s(hash_alg_tbl[i].name, HASH_ALG_NAME_MAX),
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
char *acvp_lookup_hash_alg_name(ACVP_HASH_ALG id) {
    int i = 0;

    if (!id) return NULL;

    for (i = 0; i < hash_alg_tbl_length; i++) {
        if (id == hash_alg_tbl[i].id) {
            return hash_alg_tbl[i].name;
        }
    }

    return NULL;
}

char *acvp_lookup_rsa_prime_test_name(ACVP_RSA_PRIME_TEST_TYPE type) {
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
ACVP_RESULT is_valid_prime_test(char *value) {
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

char *acvp_lookup_ec_curve_name(ACVP_CIPHER cipher, ACVP_EC_CURVE id) {
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
                 strnlen_s(ec_curve_tbl[i].name, EC_CURVE_NAME_MAX),
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
                     strnlen_s(ec_curve_depr_tbl[i].name, EC_CURVE_NAME_MAX),
                     name, &diff);

            if (!diff) {
                return ec_curve_depr_tbl[i].id;
            }
        }
    }

    return 0;
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
        return ACVP_MISSING_ARG;
    }

    if ((src_len * 2) > dest_max) {
        return ACVP_DATA_TOO_LARGE;
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
 * Convert a bit character string from *char ptr to
 * the destination as a concatenated bit value with bit0 = 0x80
 */
ACVP_RESULT acvp_bit_to_bin(const unsigned char *in, int len, unsigned char *out) {
    int n;

    if (!out || !in) {
        return ACVP_INVALID_ARG;
    }

    memzero_s(out, len);
    for (n = 0; n < len; ++n) {
        if (in[n] == '1') {
            out[n / 8] |= (0x80 >> (n % 8));
        }
    }

    return ACVP_SUCCESS;
}

/*
 * Convert characters in hexidecimal format from a *char ptr to a
 * the destination as a binary bit string
 */
ACVP_RESULT acvp_bin_to_bit(const unsigned char *in, int len, unsigned char *out) {
    int n;

    if (!len || !out || !in) {
        return ACVP_INVALID_ARG;
    }
    for (n = 0; n < len; ++n) {
        out[n] = (in[n / 8] & (0x80 >> (n % 8))) ? '1' : '0';
    }

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

    src_len = strnlen_s((char *)src, ACVP_HEXSTR_MAX);

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

/*
 * This function is used to locate the callback function that's needed
 * when a particular crypto operation is needed by libacvp.
 */
ACVP_DRBG_CAP_MODE_LIST *acvp_locate_drbg_mode_entry(ACVP_CAPS_LIST *cap, ACVP_DRBG_MODE mode) {
    ACVP_DRBG_CAP_MODE_LIST *cap_mode_list;
    ACVP_DRBG_CAP_MODE *cap_mode;
    ACVP_DRBG_CAP *drbg_cap;

    drbg_cap = cap->cap.drbg_cap;

    /*
     * No entires yet
     */
    cap_mode_list = drbg_cap->drbg_cap_mode_list;
    if (!cap_mode_list) {
        return NULL;
    }

    cap_mode = &cap_mode_list->cap_mode;
    if (!cap_mode) {
        return NULL;
    }

    while (cap_mode_list) {
        if (cap_mode->mode == mode) {
            return cap_mode_list;
        }
        cap_mode_list = cap_mode_list->next;
        cap_mode = &cap_mode_list->cap_mode;
    }
    return NULL;
}

/*
 * Creates a JSON acvp array which consists of
 * [{preamble}, {object}]
 * preamble is populated with the version string
 * returns ACVP_SUCCESS or ACVP_JSON_ERR
 */
ACVP_RESULT acvp_create_array(JSON_Object **obj, JSON_Value **val, JSON_Array **arry) {
    ACVP_RESULT result = ACVP_SUCCESS;
    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Value *ver_val = NULL;
    JSON_Object *ver_obj = NULL;
    JSON_Array *reg_arry = NULL;

    reg_arry_val = json_value_init_array();
    reg_obj = json_value_get_object(reg_arry_val);
    reg_arry = json_array((const JSON_Value *)reg_arry_val);

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
    json_array_append_value(reg_arry, ver_val);

    *obj = reg_obj;
    *val = reg_arry_val;
    *arry = reg_arry;
    return result;
}

/*
 * This function returns a string that describes the error
 * code passed in.
 */
char *acvp_lookup_error_string(ACVP_RESULT rv) {
    int i;
    struct acvp_result_desc_t error_desc_tbl[ACVP_RESULT_MAX - 1] = {
        { ACVP_MALLOC_FAIL,        "Error allocating memory"                          },
        { ACVP_NO_CTX,             "No valid context found"                           },
        { ACVP_TRANSPORT_FAIL,     "Error using transport library"                    },
        { ACVP_JSON_ERR,           "Error using JSON library"                         },
        { ACVP_NO_DATA,            "Trying to use data but none was found"            },
        { ACVP_UNSUPPORTED_OP,     "Unsupported operation"                            },
        { ACVP_CLEANUP_FAIL,       "Error cleaning up ACVP context"                   },
        { ACVP_KAT_DOWNLOAD_RETRY, "Error, need to retry"                             },
        { ACVP_INVALID_ARG,        "Invalid argument"                                 },
        { ACVP_MISSING_ARG,        "Missing a required argument"                      },
        { ACVP_CRYPTO_MODULE_FAIL, "Error from crypto module processing a vector set" },
        { ACVP_CRYPTO_TAG_FAIL,    "Error from crypto module processing a vector set" },
        { ACVP_CRYPTO_WRAP_FAIL,   "Error from crypto module processing a vector set" },
        { ACVP_NO_TOKEN,           "Error using JWT"                                  },
        { ACVP_NO_CAP,             "No matching capability found"                     },
        { ACVP_MALFORMED_JSON,     "Unable to process JSON"                           },
        { ACVP_DATA_TOO_LARGE,     "Data too large"                                   },
        { ACVP_DUP_CIPHER,         "Duplicate cipher, may have already registered"    },
        { ACVP_TOTP_DECODE_FAIL,   "Failed to base64 decode TOTP seed"                },
        { ACVP_TOTP_MISSING_SEED,  "Missing TOTP seed"                                },
        { ACVP_DUPLICATE_CTX,      "ctx already initialized"                          }
    };

    for (i = 0; i < ACVP_RESULT_MAX - 1; i++) {
        if (rv == error_desc_tbl[i].rv) {
            return error_desc_tbl[i].desc;
        }
    }
    return "Unknown error";
}

/* increment counter (64-bit int) by 1 */
void ctr64_inc(unsigned char *counter) {
    int n = 8;
    unsigned char c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

/* increment counter (128-bit int) by 1 */
void ctr128_inc(unsigned char *counter) {
    unsigned int n = 16, c = 1;

    do {
        --n;
        c += counter[n];
        counter[n] = (unsigned char)c;
        c >>= 8;
    } while (n);
}

void acvp_free_kv_list(ACVP_KV_LIST *kv_list) {
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

    json_object_set_number(*r_vs, "vsId", (*ctx)->vs_id);
    json_object_set_string(*r_vs, "algorithm", alg_str);
    /*
     * create an array of response test groups
     */
    json_object_set_value(*r_vs, "testGroups", json_value_init_array());
    (*groups_arr) = json_object_get_array(*r_vs, "testGroups");

    return ACVP_SUCCESS;
}

void acvp_release_json(JSON_Value *r_vs_val,
                       JSON_Value *r_gval) {

    if (r_gval) json_value_free(r_gval);
    if (r_vs_val) json_value_free(r_vs_val);
}

