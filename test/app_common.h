/** @file */
/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#ifndef ACVP_UT_APP_COMMON_H
#define ACVP_UT_APP_COMMON_H

#include "app_lcl.h"

ACVP_RESULT totp(char **token, int token_max);
void dummy_call(void);

#endif
