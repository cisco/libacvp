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

#include <oqs/sig.h>

/* Seed buffer for keygen */
static unsigned char *rng_buffer = NULL;
/* Total size of the seed buffer */
static size_t rng_buf_size = 0;
/* Iterator for the seed buffer */
static int rng_buf_pos = 0;

void iut_slh_dsa_cleanup(void) {
    if (rng_buffer) free(rng_buffer);
    rng_buffer = NULL;
    rng_buf_pos = 0;
    rng_buf_size = 0;
}

/**
 * This function loops through the rng_buffer buffer and returns it as RNG; once at the end
 * of the buffer, it goes back to the beginning
 */
static void oqs_rng_callback_acvp(uint8_t *random_array, size_t bytes_to_read) {
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

int app_slh_dsa_handler(ACVP_TEST_CASE *test_case) {
    /*
     * "tc" is test_case->tc.slh_dsa. All modes use tc->param_set to specify the parameter set.
     *
     * For keygen, take tc->secret_seed, tc->secret_prf, and tc->pub_seed
     * and use them to generate tc->secret_key and tc->pub_key (and their _len values)
     *
     * For siggen, a secret key and message are provided (tc->secret_key, tc->msg) and are expected to be
     * used to generate a signature (tc->sig) and its len value. If the test case is NOT deterministic
     * (!tc->is_deterministic) then the additional randomness value (tc->rnd) must be integrated.
     *
     * For sigver, a message, signature, and public key (tc->msg, tc->sig, tc->pub_key) value are each provided,
     * and the IuT must indicate if the signature is valid (tc->ver_disposition = 1 if so, 0 if not).
     */

    ACVP_SLH_DSA_TC *tc = NULL;
    ACVP_SUB_SLH_DSA alg = 0;
    int rv = ACVP_CRYPTO_MODULE_FAIL, iter = 0;
    size_t out = 0;
    OQS_SIG *sig = NULL;
    const char *param_set = NULL;
    if (!test_case) {
        return -1;
    }

    tc = test_case->tc.slh_dsa;
    if (!tc) return rv;

    alg = acvp_get_slh_dsa_alg(tc->cipher);
    if (!alg) return rv;

    switch (tc->param_set) {
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHA2_128S:
        param_set = OQS_SIG_alg_sphincs_sha2_128s_simple;
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHA2_128F:
        param_set = OQS_SIG_alg_sphincs_sha2_128f_simple;
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHA2_192S:
        param_set = OQS_SIG_alg_sphincs_sha2_192s_simple;
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHA2_192F:
        param_set = OQS_SIG_alg_sphincs_sha2_192f_simple;
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHA2_256S:
        param_set = OQS_SIG_alg_sphincs_sha2_256s_simple;
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHA2_256F:
        param_set = OQS_SIG_alg_sphincs_sha2_256f_simple;
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHAKE_128S:
        param_set = OQS_SIG_alg_sphincs_shake_128s_simple;
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHAKE_128F:
        param_set = OQS_SIG_alg_sphincs_shake_128f_simple;
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHAKE_192S:
        param_set = OQS_SIG_alg_sphincs_shake_192s_simple;
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHAKE_192F:
        param_set = OQS_SIG_alg_sphincs_shake_192f_simple;
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHAKE_256S:
        param_set = OQS_SIG_alg_sphincs_shake_256s_simple;
        break;
    case ACVP_SLH_DSA_PARAM_SET_SLH_DSA_SHAKE_256F:
        param_set = OQS_SIG_alg_sphincs_shake_256f_simple;
        break;
    case ACVP_SLH_DSA_PARAM_SET_NONE:
    case ACVP_SLH_DSA_PARAM_SET_MAX:
    default:
        printf("Invalid parameter set provided for SLH-DSA\n");
        break;
    }

    sig = OQS_SIG_new(param_set);
    if (!sig) {
        printf("Error creating SIG object\n");
        goto end;
    }

    switch (alg) {
    case ACVP_SUB_SLH_DSA_KEYGEN:
        /**
         * We need to specify seed values that SLH-DSA keygen uses. We cannot do that directly.
         * However, we can specify a custom RNG function. For testing's sake, we set a RNG function
         * that really just returns bytes for the seed valued the server specifies. This is not
         * ideal and hopefully there will be a more refined way of handling this in the future.
         */
        if (rng_buffer) {
            printf("Error: rng_buffer value should not already be set\n");
            goto end;
        }
        rng_buf_size = tc->secret_seed_len + tc->secret_prf_len + tc->pub_seed_len;
        rng_buffer = calloc(rng_buf_size, sizeof(unsigned char));
        if (!rng_buffer) {
            printf("Error allocating seed buffer for SLH-DSA\n");
            goto end;
        }
        /* append secret seed, prf, and pub seed in the buffer */
        memcpy_s(rng_buffer, rng_buf_size, tc->secret_seed, tc->secret_seed_len);
        iter += tc->secret_seed_len;
        memcpy_s(rng_buffer + iter, rng_buf_size - iter, tc->secret_prf, tc->secret_prf_len);
        iter += tc->secret_prf_len;
        memcpy_s(rng_buffer + iter, rng_buf_size - iter, tc->pub_seed, tc->pub_seed_len);

        OQS_randombytes_custom_algorithm(&oqs_rng_callback_acvp);

        if (OQS_SIG_keypair(sig, tc->pub_key, tc->secret_key) != OQS_SUCCESS) {
            printf("Failure generating keypair in SLH-DSA\n");
            goto end;
        }
        tc->pub_key_len = (int)sig->length_public_key;
        tc->secret_key_len = (int)sig->length_secret_key;
        break;
    case ACVP_SUB_SLH_DSA_SIGGEN:
        if (!tc->is_deterministic) {
            if (rng_buffer) {
                printf("Error: rng_buffer value should not already be set\n");
                goto end;
            }
            rng_buf_size = tc->rnd_len;
            rng_buffer = calloc(rng_buf_size, sizeof(unsigned char));
            if (!rng_buffer) {
                printf("Error allocating rnd buffer for SLH-DSA\n");
                goto end;
            }
            memcpy_s(rng_buffer, rng_buf_size, tc->rnd, tc->rnd_len);
            OQS_randombytes_custom_algorithm(&oqs_rng_callback_acvp);
        }
        if (OQS_SIG_sign(sig, tc->sig, &out, tc->msg, tc->msg_len, tc->secret_key) != OQS_SUCCESS) {
            printf("Failure generating signature in SLH-DSA\n");
            goto end;
        }
        tc->sig_len = (int)out;
        break;
    case ACVP_SUB_SLH_DSA_SIGVER:
        if (OQS_SIG_verify(sig, tc->msg, (size_t)tc->msg_len, tc->sig, (size_t)tc->sig_len, tc->pub_key) == OQS_SUCCESS) {
            tc->ver_disposition = 1;
        }
        break;
    default:
        printf("Invalid algorithm provided in SLH-DSA handler\n");
        goto end;
    }

    rv = 0;
end:
    if (rng_buffer) free(rng_buffer);
    rng_buffer = NULL;
    rng_buf_pos = 0;
    rng_buf_size = 0;
    if (sig) OQS_SIG_free(sig);
    return rv;

}
