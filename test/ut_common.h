/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include <string.h>
#include <stdio.h>
#include <criterion/criterion.h>
#include <criterion/logging.h>
#include "parson.h"
#include "safe_lib.h"
#include "acvp.h"
#include "app_lcl.h"
#include "app_fips_lcl.h"

int counter_set;
int counter_fail;

void teardown_ctx(ACVP_CTX **ctx);
ACVP_RESULT progress(char *msg);
void setup_empty_ctx(ACVP_CTX **ctx);
int dummy_handler_success(ACVP_TEST_CASE *test_case);
int dummy_handler_failure(ACVP_TEST_CASE *test_case);
JSON_Object *ut_get_obj_from_rsp (JSON_Value *arry_val);
ACVP_RESULT totp(char **token, int token_max);
void dummy_call(void);
