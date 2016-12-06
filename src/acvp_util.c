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
void acvp_log_msg (ACVP_CTX *ctx, const char *format, ...)
{
    va_list arguments;
    char tmp[1024];

    if (ctx && ctx->test_progress_cb) {
        /*
         * Pull the arguments from the stack and invoke
         * the logger function
         */
        va_start(arguments, format);
        vsnprintf(tmp, 1023, format, arguments);
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
ACVP_CAPS_LIST* acvp_locate_cap_entry(ACVP_CTX *ctx, ACVP_SYM_CIPHER cipher)
{
    ACVP_CAPS_LIST *cap;

    if (!ctx->caps_list) {
        return NULL;
    }

    cap = ctx->caps_list;
    while (cap) {
        if (cap->cap.sym_cap->cipher == cipher) {
            return cap;
        }
        cap = cap->next;
    }
    return NULL;
}

/*
 * This function returns the name of an algorithm given
 * a ACVP_SYM_CIPHER value.  It looks for the cipher in
 * the master algorithm table, returns NULL if none match.
 */
char * acvp_lookup_sym_cipher_name(ACVP_SYM_CIPHER alg)
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
ACVP_SYM_CIPHER acvp_lookup_sym_cipher_index(const char *algorithm)
{
    int i;

    for (i = 0; i < ACVP_ALG_MAX; i++) {
        if (!strncmp(algorithm, alg_tbl[i].name, strlen(alg_tbl[i].name))) {
            return alg_tbl[i].cipher;
        }
    }
    return -1;
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

