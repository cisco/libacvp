/*
 * Copyright (c) 2023, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"

int app_lms_handler(ACVP_TEST_CASE *test_case) {

    /**
     * For LMS sigver, the output is the ver_disposition flag (1 if verified, <= 0 if failed)
     * For LMS siggen, the output for each test case is the signature in sig/sig_len. However, each test group also needs
     *     a public key. The library will grab your generated public key from pub_key/pub_key_len in the first test case
     *     for each test group (see RSA and ECDSA siggen as they work similarly).
     * For LMS keygen, the output is the generated public key stored in pub_key/pub_key_len.
     */
    if (!test_case) {
        return -1;
    }
    return 1;
}

