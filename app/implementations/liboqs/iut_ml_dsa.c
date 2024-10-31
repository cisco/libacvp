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

#if 0

#include <oqs/sig.h>

/* Seed buffer for keygen */
static unsigned char *rng_buffer = NULL;
/* Total size of the seed buffer */
static size_t rng_buf_size = 0;
/* Iterator for the seed buffer */
static int rng_buf_pos = 0;

/* Siggen handles some data per-group, this keeps track of the current group */
static int current_tg = 0;
static unsigned char *group_key = NULL;

void iut_ml_dsa_cleanup(void) {
    if (rng_buffer) free(rng_buffer);
    rng_buffer = NULL;
    rng_buf_pos = 0;
    rng_buf_size = 0;
    if (group_key) free(group_key);
    group_key = NULL;
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

int app_ml_dsa_handler(ACVP_TEST_CASE *test_case) {
    /*
     * "tc" is test_case->tc.ml_dsa. All modes use tc->param_set to specify ML-DSA-44, 65, or 87.
     *
     * For keygen, take tc->seed and use it to generate tc->pub_key and tc->secret_key (and their
     * _len values)
     *
     * For siggen, there are two test types (tc->type). AFT, and GDT. GDT tests provide a message,
     * tc->msg, and expects a pub key and a signature, tc->sig, value in response. the pk value is
     * generated once PER GROUP. The library will take the pk value from the first test case in the
     * test group.
     * Siggen AFT provides a message and a secret key value, and expects a signature in
     * response. if you are not testing deterministically (tc->deterministic flag), then a random
     * value (tc->rnd) is also provided to incorporate.
     *
     * For sigver, a pub key value is provided (it is constant for each test case in a test group
     * and varies between groups), as well as a message and a signature. IuTs are expected to
     * indicate that the provided signature is correct based on the message and other parameters.
     * If correct, tc->ver_disposition should be set to 1. If incorrect, set it to 0 (is 0 by
     * default).
     */

    ACVP_ML_DSA_TC *tc = NULL;
    ACVP_SUB_ML_DSA alg = 0;
    int rv = ACVP_CRYPTO_MODULE_FAIL;
    OQS_SIG *sig = NULL;
    const char *param_set = NULL;
    if (!test_case) {
        return -1;
    }

    tc = test_case->tc.ml_dsa;
    if (!tc) return rv;

    alg = acvp_get_ml_dsa_alg(tc->cipher);
    if (!alg) return rv;

    switch (tc->param_set) {
    case ACVP_ML_DSA_PARAM_SET_ML_DSA_44:
        param_set = OQS_SIG_alg_ml_dsa_44;
        break;
    case ACVP_ML_DSA_PARAM_SET_ML_DSA_65:
        param_set = OQS_SIG_alg_ml_dsa_65;
        break;
    case ACVP_ML_DSA_PARAM_SET_ML_DSA_87:
        param_set = OQS_SIG_alg_ml_dsa_87;
        break;
    case ACVP_ML_DSA_PARAM_SET_NONE:
    case ACVP_ML_DSA_PARAM_SET_MAX:
    default:
        printf("Invalid parameter set provided for ML-DSA\n");
        break;
}

    sig = OQS_SIG_new(param_set);
    if (!sig) {
        printf("Error creating SIG object\n");
        goto end;
    }

    switch (alg) {
    case ACVP_SUB_ML_DSA_KEYGEN:
        /** 
         * We need to specify seed value that ML-DSA keygen uses. We cannot do that directly.
         * However, we can specify a custom RNG function. For testing's sake, we set a RNG function
         * that really just returns bytes for the seed value the server specifies. This is not
         * ideal and hopefully there will be a more refined way of handling this in the future.
         */
        if (rng_buffer) {
            printf("Error: rng_buffer value should not already be set\n");
            goto end;
        }
        rng_buf_size = tc->seed_len;
        rng_buffer = calloc(rng_buf_size, sizeof(unsigned char));
        if (!rng_buffer) {
            printf("Error allocating seed buffer for ML-DSA\n");
            goto end;
        }
        /* place seed in the buffer */
        memcpy_s(rng_buffer, rng_buf_size, tc->seed, tc->seed_len);

        OQS_randombytes_custom_algorithm(&oqs_rng_callback_acvp);

        if (OQS_SIG_keypair(sig, tc->pub_key, tc->secret_key) != OQS_SUCCESS) {
            printf("Failure generating keypair in ML-DSA\n");
            goto end;
        }
        tc->pub_key_len = (int)sig->length_public_key;
        tc->secret_key_len = (int)sig->length_secret_key;
        break;
    case ACVP_SUB_ML_DSA_SIGGEN:
    case ACVP_SUB_ML_DSA_SIGVER:
    default:
        printf("Invalid algorithm provided in ML-DSA handler\n");
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

#else
int app_ml_dsa_handler(ACVP_TEST_CASE *test_case) {

    if (!test_case) {
        return -1;
    }

    return 0;
}
#endif
