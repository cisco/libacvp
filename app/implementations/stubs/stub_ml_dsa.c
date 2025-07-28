/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"

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


    if (!test_case) {
        return -1;
    }

    return 0;
}

