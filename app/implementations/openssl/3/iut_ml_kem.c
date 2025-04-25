/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "acvp/acvp.h"
#include "safe_lib.h"
#include "implementations/openssl/3/iut.h"


int app_ml_kem_handler(ACVP_TEST_CASE *test_case) {
    if (!test_case) {
        return -1;
    } else {
        return 1;
    }
}
