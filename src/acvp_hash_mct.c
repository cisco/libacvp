/** @file */
/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"
#include "safe_lib.h"

#define ACVP_HOST_LITTLE_ENDIAN (__BYTE_ORDER == __LITTLE_ENDIAN)
#define SWAP_16(x) ((x>>8) | (x<<8))

/**
 * This file handles monte-carlo testing logic for all hash algorithms (SHA1 through SHA3 and SHAKE).
 * There are two different methods of MCT testing: standard and alternate. Standard is the default and
 * is the same MCT algorithm that has been used since the beginning of ACVP. Alternate was introduced
 * in 2023 to handle cases the original method could not; namely, some implementations could not handle
 * the required 3 * digestSize message length for the standard method. The initial call functions
 * are declared here and defined below.
 */

ACVP_RESULT acvp_hash_perform_mct(ACVP_CTX *ctx,
                                  ACVP_TEST_CASE *tc,
                                  int (*crypto_handler)(ACVP_TEST_CASE *test_case),
                                  JSON_Array *res_array);

static ACVP_RESULT acvp_hash_output_mct_tc(ACVP_CTX *ctx, ACVP_HASH_TC *stc, JSON_Object *r_tobj) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    if (stc->cipher == ACVP_HASH_SHAKE_128 || stc->cipher == ACVP_HASH_SHAKE_256) {
        tmp = calloc(ACVP_HASH_XOF_MD_STR_MAX + 1, sizeof(char));
    } else {
        tmp = calloc(ACVP_HASH_MD_STR_MAX + 1, sizeof(char));
    }
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_hash_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->cipher == ACVP_HASH_SHAKE_128 || stc->cipher == ACVP_HASH_SHAKE_256) {
        rv = acvp_bin_to_hexstr(stc->md, stc->md_len, tmp, ACVP_HASH_XOF_MD_STR_MAX);
    } else {
        rv = acvp_bin_to_hexstr(stc->md, stc->md_len, tmp, ACVP_HASH_MD_STR_MAX);
    }
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (md)");
        goto end;
    }

    json_object_set_string(r_tobj, "md", tmp);
    if (stc->cipher == ACVP_HASH_SHAKE_128 || stc->cipher == ACVP_HASH_SHAKE_256) {
        json_object_set_number(r_tobj, "outLen", stc->md_len * 8);
    }

end:
    if (tmp) free(tmp);
    return rv;
}

static ACVP_RESULT acvp_hash_mct_sha_std(ACVP_CTX *ctx,
                             int (*crypto_handler)(ACVP_TEST_CASE *test_case),
                             ACVP_TEST_CASE *tc,
                             JSON_Array *res_array) {
    int i, j;
    ACVP_RESULT rv;
    JSON_Value *r_tval = NULL;  /* Response testval */
    JSON_Object *r_tobj = NULL; /* Response testobj */
    char *tmp = NULL;
    ACVP_HASH_TC *stc = NULL;

    stc = tc->tc.hash;
    if (!stc) {
        ACVP_LOG_ERR("Internal error - test case data missing for MCT");
        return ACVP_INTERNAL_ERR;
    }

    tmp = calloc(ACVP_HASH_MSG_STR_MAX * 3, sizeof(char));
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc");
        return ACVP_MALLOC_FAIL;
    }

    memcpy_s(stc->m1, ACVP_HASH_MD_BYTE_MAX, stc->msg, stc->msg_len);
    memcpy_s(stc->m2, ACVP_HASH_MD_BYTE_MAX, stc->msg, stc->msg_len);
    memcpy_s(stc->m3, ACVP_HASH_MD_BYTE_MAX, stc->msg, stc->msg_len);

    for (i = 0; i < ACVP_HASH_MCT_OUTER; ++i) {
        /*
         * Create a new test case in the response
         */
        r_tval = json_value_init_object();
        r_tobj = json_value_get_object(r_tval);

        for (j = 0; j < ACVP_HASH_MCT_INNER; ++j) {
            /* Process the current SHA test vector... */
            rv = (crypto_handler)(tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("crypto module failed the operation");
                free(tmp);
                json_value_free(r_tval);
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /* feed hash into the next message for MCT */
            rv = 0;
            rv += memcpy_s(stc->m1, ACVP_HASH_MD_BYTE_MAX, stc->m2, stc->md_len);
            rv += memcpy_s(stc->m2, ACVP_HASH_MD_BYTE_MAX, stc->m3, stc->md_len);
            rv += memcpy_s(stc->m3, ACVP_HASH_MD_BYTE_MAX, stc->md, stc->md_len);
            if (rv != 0) {
                ACVP_LOG_ERR("Failed the MCT iteration changes");
                rv = ACVP_INTERNAL_ERR;
                free(tmp);
                json_value_free(r_tval);
                return rv;
            }
        }
        /*
         * Output the test case request values using JSON
         */
        rv = acvp_hash_output_mct_tc(ctx, stc, r_tobj);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("JSON output failure in HASH module");
            free(tmp);
            json_value_free(r_tval);
            return rv;
        }

        /* Append the test response value to array */
        json_array_append_value(res_array, r_tval);

        memcpy_s(stc->m1, ACVP_HASH_MD_BYTE_MAX, stc->m3, stc->msg_len);
        memcpy_s(stc->m2, ACVP_HASH_MD_BYTE_MAX, stc->m3, stc->msg_len);

    }

    free(tmp);
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_hash_mct_sha3_std(ACVP_CTX *ctx,
                               int (*crypto_handler)(ACVP_TEST_CASE *test_case),
                               ACVP_TEST_CASE *tc,
                               JSON_Array *res_array) {
    int i = 0, j = 0;
    ACVP_RESULT rv = 0;
    JSON_Value *r_tval = NULL;  /* Response testval */
    JSON_Object *r_tobj = NULL; /* Response testobj */
    ACVP_HASH_TC *stc = NULL;

    stc = tc->tc.hash;
    if (!stc) {
        ACVP_LOG_ERR("Internal error - test case data missing for MCT");
        return ACVP_INTERNAL_ERR;
    }

    /* ***********
     * OUTER LOOP
     * ***********
     */
    for (j = 0; j < ACVP_HASH_MCT_OUTER; j++) {
        /*
         * Create a new test case in the response
         */
        r_tval = json_value_init_object();
        r_tobj = json_value_get_object(r_tval);

        /* ***********
         * INNER LOOP
         * ***********
         */
        for (i = 0; i <= ACVP_HASH_MCT_INNER; i++) {
            if (i != 0) {
                /*
                 * Use the MD[i-1] as the new Msg
                 * Zeroize the msg buffer, and copy in the md.
                 */
                memzero_s(stc->msg, ACVP_HASH_MSG_BYTE_MAX);
                memcpy_s(stc->msg, ACVP_HASH_MSG_BYTE_MAX, stc->md, stc->md_len);
                stc->msg_len = stc->md_len;

                if (i == ACVP_HASH_MCT_INNER) {
                    /*
                     * We will use the final MD as the starting MSG
                     * for next outer loop. Break here before
                     * doing another digest.
                     */
                    break;
                }
            }

            /* Now clear the md buffer */
            memzero_s(stc->md, ACVP_HASH_MD_BYTE_MAX);

            /* Process the current SHA test vector... */
            rv = (crypto_handler)(tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("crypto module failed the operation");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                goto end;
            }
        }

        /*
         * Output the test case request values using JSON
         */
        rv = acvp_hash_output_mct_tc(ctx, stc, r_tobj);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("JSON output failure");
            goto end;
        }

        /* Append the test response value to array */
        json_array_append_value(res_array, r_tval);
    }

end:
    if (rv != ACVP_SUCCESS && r_tval) json_value_free(r_tval);

    return rv;
}

static ACVP_RESULT acvp_hash_mct_shake_std(ACVP_CTX *ctx,
                                int (*crypto_handler)(ACVP_TEST_CASE *test_case),
                                ACVP_TEST_CASE *tc,
                                JSON_Array *res_array) {
    int i = 0, j = 0;
    ACVP_RESULT rv = 0;
    JSON_Value *r_tval = NULL;  /* Response testval */
    JSON_Object *r_tobj = NULL; /* Response testobj */
    unsigned int xof_len = 0;
    unsigned int leftmost_bytes = 16;
    unsigned int min_xof_bytes = 0;
    unsigned int max_xof_bytes = 0;
    unsigned int range = 0;
    ACVP_HASH_TC *stc = NULL;

    stc = tc->tc.hash;
    if (!stc) {
        ACVP_LOG_ERR("Internal error - test case data missing for MCT");
        return ACVP_INTERNAL_ERR;
    }

    min_xof_bytes = stc->mct_shake_min_xof_bits / 8;
    max_xof_bytes = stc->mct_shake_max_xof_bits / 8;
    range = max_xof_bytes - min_xof_bytes + 1;
    /*
     * Initial Outputlen = (floor(maxoutlen/8) )*8
     */
    xof_len = (stc->mct_shake_max_xof_bits / 8) * 8;
    /* Convert from bits to bytes */
    stc->xof_len = (xof_len + 7) / 8;

    /* ***********
     * OUTER LOOP
     * ***********
     */
    for (j = 0; j < ACVP_HASH_MCT_OUTER; j++) {
        /*
         * Create a new test case in the response
         */
        r_tval = json_value_init_object();
        r_tobj = json_value_get_object(r_tval);

        /* ***********
         * INNER LOOP
         * ***********
         */
        for (i = 0; i <= ACVP_HASH_MCT_INNER; i++) {
            uint8_t   rob[2] = {0};
            uint16_t *rightmost_out_bits = (uint16_t*) &rob;

            if (i != 0) {
                /*
                 * Use the MD[i-1] as the new Msg
                 * Zeroize the msg buffer, and copy in the md.
                 */
                memzero_s(stc->msg, ACVP_SHAKE_MSG_BYTE_MAX);
                if (stc->md_len <= leftmost_bytes) {
                    memcpy_s(stc->msg, ACVP_SHAKE_MSG_BYTE_MAX, stc->md, stc->md_len);
                } else {
                    /* Only copy the leftmost 128 bits */
                    memcpy_s(stc->msg, ACVP_SHAKE_MSG_BYTE_MAX, stc->md, leftmost_bytes);
                }

                if (i == ACVP_HASH_MCT_INNER) {
                    /*
                     * We will use the final MD as the starting MSG
                     * for next outer loop. Break here before
                     * doing another digest.
                     */
                    break;
                }
            }
            stc->msg_len = leftmost_bytes;

            /* Now clear the md buffer */
            memzero_s(stc->md, ACVP_HASH_XOF_MD_BYTE_MAX);

            /* Process the current SHA test vector... */
            rv = (crypto_handler)(tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("crypto module failed the operation");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                goto end;
            }

            /* Get the right-most 16bits and convert to an integer */
#if ACVP_HOST_LITTLE_ENDIAN || defined(__WIN32) || defined(__APPLE__)
            rob[0] = stc->md[stc->md_len-1];
            rob[1] = stc->md[stc->md_len-2];
#else
            rob[0] = stc->md[stc->md_len-2];
            rob[1] = stc->md[stc->md_len-1];
#endif

            /* Calculate the next expected outputLen */
            stc->xof_len = min_xof_bytes + ((*rightmost_out_bits) % range);
        }

        /*
         * Output the test case request values using JSON
         */
        rv = acvp_hash_output_mct_tc(ctx, stc, r_tobj);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("JSON output failure");
            goto end;
        }

        /* Append the test response value to array */
        json_array_append_value(res_array, r_tval);
    }

end:
    if (rv != ACVP_SUCCESS && r_tval) json_value_free(r_tval);

    return rv;
}

ACVP_RESULT acvp_hash_perform_mct(ACVP_CTX *ctx,
                                  ACVP_TEST_CASE *tc,
                                  int (*crypto_handler)(ACVP_TEST_CASE *test_case),
                                  JSON_Array *res_array) {

    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_HASH_TC *stc = NULL;
    ACVP_SUB_HASH alg = 0;
    stc = tc->tc.hash;
    if (!stc) {
        ACVP_LOG_ERR("Internal error - test case data missing for MCT");
        return ACVP_INTERNAL_ERR;
    }

    alg = acvp_get_hash_alg(stc->cipher);

    switch (stc->mct_version) {
    case ACVP_HASH_MCT_VERSION_STANDARD:
        switch (alg) {
        case ACVP_SUB_HASH_SHA1:
        case ACVP_SUB_HASH_SHA2_224:
        case ACVP_SUB_HASH_SHA2_256:
        case ACVP_SUB_HASH_SHA2_384:
        case ACVP_SUB_HASH_SHA2_512:
        case ACVP_SUB_HASH_SHA2_512_224:
        case ACVP_SUB_HASH_SHA2_512_256:
            rv = acvp_hash_mct_sha_std(ctx, crypto_handler, tc, res_array);
            break;
        case ACVP_SUB_HASH_SHA3_224:
        case ACVP_SUB_HASH_SHA3_256:
        case ACVP_SUB_HASH_SHA3_384:
        case ACVP_SUB_HASH_SHA3_512:
            rv = acvp_hash_mct_sha3_std(ctx, crypto_handler, tc, res_array);
            break;
        case ACVP_SUB_HASH_SHAKE_128:
        case ACVP_SUB_HASH_SHAKE_256:
            rv = acvp_hash_mct_shake_std(ctx, crypto_handler, tc, res_array);
            break;
        default:
            ACVP_LOG_ERR("Internal error - invalid cipher provided when initializing hash MCT test");
            return ACVP_INTERNAL_ERR;
        }
        break;
    case ACVP_HASH_MCT_VERSION_ALTERNATE:
        switch (stc->cipher) {
        case ACVP_SUB_HASH_SHA1:
        case ACVP_SUB_HASH_SHA2_224:
        case ACVP_SUB_HASH_SHA2_256:
        case ACVP_SUB_HASH_SHA2_384:
        case ACVP_SUB_HASH_SHA2_512:
        case ACVP_SUB_HASH_SHA2_512_224:
        case ACVP_SUB_HASH_SHA2_512_256:
       //     rv = acvp_hash_mct_sha_alt(ctx, NULL, NULL, tc, NULL);
         //   break;
        case ACVP_SUB_HASH_SHA3_224:
        case ACVP_SUB_HASH_SHA3_256:
        case ACVP_SUB_HASH_SHA3_384:
        case ACVP_SUB_HASH_SHA3_512:
          //  rv = acvp_hash_mct_sha3_alt(ctx, NULL, NULL, tc, NULL);
          //  break;
        case ACVP_SUB_HASH_SHAKE_128:
        case ACVP_SUB_HASH_SHAKE_256:
        //    rv = acvp_hash_mct_shake_alt(ctx, NULL, NULL, tc, NULL,
         //  break;
        default:
            ACVP_LOG_ERR("Internal error - invalid cipher provided when initializing hash MCT test");
            return ACVP_INTERNAL_ERR;
        }
        break;
    case ACVP_HASH_MCT_VERSION_MAX:
    default:
        ACVP_LOG_ERR("Internal error - invalid MCT version provided when initializing hash MCT test");
        return ACVP_INTERNAL_ERR;
    }

    return rv;
}
