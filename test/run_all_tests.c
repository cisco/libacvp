/** @file */
/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "ut_common.h"

// Declare runner functions
#ifndef LIB_NOT_SUPPORTED
void run_lib_tests(void);
#endif

#ifndef APP_NOT_SUPPORTED
void run_app_tests(void);
#endif

// Main test runner function
static void RunAllTests(void) {
#ifndef LIB_NOT_SUPPORTED
    run_lib_tests();
#endif
#ifndef APP_NOT_SUPPORTED
    run_app_tests();
#endif
}

// Main entry point
int main(int argc, const char *argv[]) {
    return UnityMain(argc, argv, RunAllTests);
}
