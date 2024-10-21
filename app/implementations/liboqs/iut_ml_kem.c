/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"
#include "safe_lib.h"

#include <oqs/kem.h>

/* Seed buffer for keygen, m buffer for encap */
static unsigned char *rng_buffer = NULL;
/* Total size of the seed buffer */
static size_t rng_buf_size = 0;
/* Iterator for the seed buffer */
static int rng_buf_pos = 0;

void iut_ml_kem_cleanup(void) {
    if (rng_buffer) free(rng_buffer);
    rng_buffer = NULL;
}

/**
 * This function loops through the rng_buffer buffer and returns it as RNG; once at the end
 * of the buffer, it goes back to the beginning
 */
void oqs_rng_callback_acvp(uint8_t *random_array, size_t bytes_to_read) {
    int remaining_bytes = bytes_to_read;
    int bytes_sent = 0;
    int bytes_going_this_round = 0;

    if (!rng_buffer || !rng_buf_size) {
        return;
    }

    while (remaining_bytes > 0) {
        //if we need to send more bytes than there is space left in the buffer, send only until the end of the buffer
        bytes_going_this_round = remaining_bytes < rng_buf_size - rng_buf_pos ? remaining_bytes : rng_buf_size - rng_buf_pos;
        memcpy_s(random_array + bytes_sent, bytes_to_read - bytes_sent, rng_buffer + rng_buf_pos, bytes_going_this_round);
        bytes_sent += bytes_going_this_round;
        remaining_bytes -= bytes_going_this_round;
        rng_buf_pos += bytes_sent;
        //if we hit end of buffer, go back to beginning
        if (rng_buf_pos >= rng_buf_size - 1) {
            rng_buf_pos = 0;
        }
    }
}

 
int app_ml_kem_handler(ACVP_TEST_CASE *test_case) {
    ACVP_ML_KEM_TC *tc =NULL;
    int rv = ACVP_CRYPTO_MODULE_FAIL;
    OQS_KEM *kem = NULL;
    const char *param_set = NULL;
    if (!test_case) {
        return -1;
    }

    tc = test_case->tc.ml_kem;
    if (!tc) return rv;

    switch (tc->param_set) {
    case ACVP_ML_KEM_PARAM_SET_ML_KEM_512:
        param_set = OQS_KEM_alg_ml_kem_512;
        break;
    case ACVP_ML_KEM_PARAM_SET_ML_KEM_768:
        param_set = OQS_KEM_alg_ml_kem_768;
        break;
    case ACVP_ML_KEM_PARAM_SET_ML_KEM_1024:
        param_set = OQS_KEM_alg_ml_kem_1024;
        break;
    case ACVP_ML_KEM_PARAM_SET_NONE:
    case ACVP_ML_KEM_PARAM_SET_MAX:
    default:
        printf("Invalid param set for ML-KEM\n");
        goto end;
    }

    kem = OQS_KEM_new(param_set);
    if (!kem) {
        printf("Error creating KEM object\n");
        goto end;
    }

    if (tc->cipher == ACVP_ML_KEM_KEYGEN) {
        /** 
         * We need to specify the D and Z seed values that ML-KEM uses. We cannot do that directly.
         * However, we can specify a custom RNG function. For testing's sake, we set a RNG function
         * that really just returns bytes for the D and Z values the server specifies. This is not
         * ideal and hopefully there will be a more refined way of handling this in the future.
         */
        if (rng_buffer) {
            printf("Error: rng_buffer value should not already be set\n");
            goto end;
        }
        rng_buf_size = tc->d_len + tc->z_len;
        rng_buffer = calloc(rng_buf_size, sizeof(unsigned char));
        if (!rng_buffer) {
            printf("Error allocating seed buffer for ML-KEM\n");
            goto end;
        }
        /* append D and Z in the buffer */
        memcpy_s(rng_buffer, rng_buf_size, tc->d, tc->d_len);
        memcpy_s(rng_buffer + tc->d_len, rng_buf_size - tc->d_len, tc->z, tc->z_len);

        OQS_randombytes_custom_algorithm(&oqs_rng_callback_acvp);

        if (OQS_KEM_keypair(kem, tc->ek, tc->dk) != OQS_SUCCESS) {
            printf("Error generating keypair for ML-KEM\n");
            goto end;
        }
        tc->ek_len = kem->length_public_key;
        tc->dk_len = kem->length_secret_key;

    } else if (tc->cipher == ACVP_ML_KEM_XCAP) {

        if (tc->function == ACVP_ML_KEM_FUNCTION_ENCAPSULATE) {
            /* encapsulation needs to set a random m value the same way keygen needs D and Z described above */
            rng_buf_size = tc->m_len;
            rng_buffer = calloc(rng_buf_size, sizeof(unsigned char));
            if (!rng_buffer) {
                printf("Error allocating m buffer for ML-KEM\n");
                goto end;
            }
            /* Place m in the buffer */
            memcpy_s(rng_buffer, rng_buf_size, tc->m, tc->m_len);

            OQS_randombytes_custom_algorithm(&oqs_rng_callback_acvp);

            OQS_KEM_encaps(kem, tc->c, tc->k, tc->ek);
            tc->c_len = kem->length_ciphertext;
            tc->k_len = kem->length_shared_secret;
        } else { //decapsulate
            OQS_KEM_decaps(kem, tc->k, tc->c, tc->dk);
            tc->k_len = kem->length_shared_secret;
        }
    } else {
        printf("Error: invalid cipher given for ML-KEM\n");
        goto end;
    }

    rv = 0;
end:
    if (rng_buffer) free(rng_buffer);
    rng_buffer = NULL;
    if (kem) OQS_KEM_free(kem);
    return rv;
}
