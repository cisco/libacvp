/*****************************************************************************
* Copyright (c) 2016, Cisco Systems, Inc.
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
#include <stdarg.h>
#include "acvp.h"
#include "acvp_lcl.h"
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
void acvp_log_msg (ACVP_CTX *ctx, ACVP_LOG_LVL level, const char *format, ...)
{
    va_list arguments;
    char tmp[16384];

    if (ctx && ctx->test_progress_cb && (ctx->debug >= level)) {
        /*
         * Pull the arguments from the stack and invoke
         * the logger function
         */
        va_start(arguments, format);
        vsnprintf(tmp, 16383, format, arguments);
        ctx->test_progress_cb(tmp);
        va_end(arguments);
        fflush(stdout);
    }
}

/*
 * Curl requires a cleanup function to be invoked when done.
 * We must extend this to our user, which is done here.
 * Our users shouldn't have to include curl.h.
 */
void acvp_cleanup(void)
{
    curl_global_cleanup();
}

/*
 * This function is used to locate the callback function that's needed
 * when a particular crypto operation is needed by libacvp.
 */
ACVP_CAPS_LIST* acvp_locate_cap_entry(ACVP_CTX *ctx, ACVP_CIPHER cipher)
{
    ACVP_CAPS_LIST *cap;

    if (!ctx->caps_list) {
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
 */
char * acvp_lookup_cipher_name(ACVP_CIPHER alg)
{
    int i;

    for (i = 0; i < ACVP_ALG_MAX; i++) {
        if (alg_tbl[i].cipher == alg) {
            return alg_tbl[i].name;
        }
    }
    return NULL;
}

/*
 * This function returns the ID of a cipher given an
 * algorithm name (as defined in the ACVP spec).  It
 * returns -1 if none match.
 */
ACVP_CIPHER acvp_lookup_cipher_index(const char *algorithm)
{
    int i;

    for (i = 0; i < ACVP_ALG_MAX; i++) {
        if (!strncmp(algorithm, alg_tbl[i].name, strlen(alg_tbl[i].name))) {
            return alg_tbl[i].cipher;
        }
    }
    return -1;
}

/*
 * This function returns the ID of a DRBG mode given an
 * algorithm name (as defined in the ACVP spec).  It
 * returns ACVP_DRBG_MODE_END if none match.
 */
ACVP_DRBG_MODE acvp_lookup_drbg_mode_index(const char *mode)
{
    int i;
    struct acvp_drbg_mode_name_t drbg_mode_tbl[ACVP_DRBG_MODE_END] = {
            {ACVP_DRBG_SHA_1, ACVP_DRBG_MODE_SHA_1},
            {ACVP_DRBG_SHA_224, ACVP_DRBG_MODE_SHA_224},
            {ACVP_DRBG_SHA_256, ACVP_DRBG_MODE_SHA_256},
            {ACVP_DRBG_SHA_384, ACVP_DRBG_MODE_SHA_384},
            {ACVP_DRBG_SHA_512, ACVP_DRBG_MODE_SHA_512},
            {ACVP_DRBG_SHA_512_224, ACVP_DRBG_MODE_SHA_512_224},
            {ACVP_DRBG_SHA_512_256, ACVP_DRBG_MODE_SHA_512_256},
            {ACVP_DRBG_3KEYTDEA, ACVP_DRBG_MODE_3KEYTDEA},
            {ACVP_DRBG_AES_128, ACVP_DRBG_MODE_AES_128},
            {ACVP_DRBG_AES_192, ACVP_DRBG_MODE_AES_192},
            {ACVP_DRBG_AES_256, ACVP_DRBG_MODE_AES_256}
    };

    for (i = 0; i < ACVP_DRBG_MODE_END; i++) {
        if (!strncmp(mode, drbg_mode_tbl[i].name, strlen(drbg_mode_tbl[i].name))) {
            return drbg_mode_tbl[i].mode;
        }
    }
    return ACVP_DRBG_MODE_END;
}

//TODO: the next 3 functions could possibly be replaced using OpenSSL bignum,
//      which has support for reading/writing hex strings.  But do we want
//      to include a new dependency on OpenSSL?
/*
 * Convert a byte array from source to a hexadecimal string which is
 * stored in the destination.
 */
ACVP_RESULT acvp_bin_to_hexstr(const unsigned char *src,
                               unsigned int src_len,
                               unsigned char *dest)
{
    int i, j;
    unsigned char nibb_a, nibb_b;
    unsigned char hex_chars[] = "0123456789ABCDEF";

    for (i = 0, j = 0; i < src_len; i++, j += 2) {
        nibb_a = *src >> 4; /* Get first half of byte */
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
ACVP_RESULT acvp_hexstr_to_bin(const unsigned char *src, unsigned char *dest, int dest_max)
{
    int src_len;
    int byte_a, byte_b;
    int is_odd = 0;

    if (!src || !dest) {
        return ACVP_INVALID_ARG;
    }

    src_len = (int)strlen((char*)src);

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
        }
    } else {
        return ACVP_UNSUPPORTED_OP;
    }

    return ACVP_SUCCESS;
}

/*
 * Local - helper function for acvp_hexstring_to_bytes
 * Used to convert a hexadecimal character to it's byte
 * representation.
 */
static int acvp_char_to_int(char ch)
{
    int ch_i;

    if (ch >= '0' && ch <= '9') {
        ch_i = ch - '0';
    }
    else if (ch >= 'A' && ch <= 'F') {
        ch_i = ch - 'A' + 10;
    }
    else if (ch >= 'a' && ch <= 'f') {
        ch_i = ch - 'a' + 10;
    }
    else {
        ch_i = 0;
    }

    return ch_i;
}


/*
 * This function is used to locate the callback function that's needed
 * when a particular crypto operation is needed by libacvp.
 */
ACVP_DRBG_CAP_MODE_LIST* acvp_locate_drbg_mode_entry(ACVP_CAPS_LIST *cap, ACVP_DRBG_MODE mode)
{
    ACVP_DRBG_CAP_MODE_LIST *cap_mode_list;
    ACVP_DRBG_CAP_MODE      *cap_mode;
    ACVP_DRBG_CAP           *drbg_cap;

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
        cap_mode_list = drbg_cap->drbg_cap_mode_list->next;
        cap_mode = &cap_mode_list->cap_mode;
    }
    return NULL;
}

unsigned int yes_or_no(ACVP_CTX *ctx, const char *text)
{
    unsigned int result;
    if (!ctx || !text) return 0;
    if (!strncmp(text, "yes", 3)) {
        result = 1;
    } else if (!strncmp(text, "no", 2)) {
        result = 0;
    } else {
        ACVP_LOG_ERR("ERROR: unsupported yes/no value from server treated as 'no': (%s)", text);
        result = 0;
    }
    return result;
}

/*
 * Creates a JSON acvp array which consists of
 * [{preamble}, {object}]
 * preamble is populated with the version string
 * returns ACVP_SUCCESS or ACVP_JSON_ERR
 */
ACVP_RESULT acvp_create_array (JSON_Object **obj, JSON_Value **val, JSON_Array **arry)
{
    ACVP_RESULT result = ACVP_SUCCESS;
    JSON_Value          *reg_arry_val  = NULL;
    JSON_Object         *reg_obj       = NULL;
    JSON_Value          *ver_val       = NULL;
    JSON_Object         *ver_obj       = NULL;
    JSON_Array          *reg_arry      = NULL;

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
    return(result);
}
