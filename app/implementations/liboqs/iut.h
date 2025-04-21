/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#ifndef ACVP_APP_IUT_H
#define ACVP_APP_IUT_H

#include "acvp/acvp.h"

int app_ml_kem_handler(ACVP_TEST_CASE *test_case);
int app_ml_dsa_handler(ACVP_TEST_CASE *test_case);

void iut_ml_kem_cleanup(void);

#endif // ACVP_APP_IUT_H
