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

#ifdef _WIN32
#include <direct.h>
#else
#include <unistd.h>
#endif

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

/* Tests use relative "json/..." paths, so we chdir to the first dir containing this file */
#define TEST_DATA_SAMPLE_FILE "/json/aes/aes.json"
#define TEST_PATH_MAX 4096

/* Returns 1 if test_dir contains the JSON test data and we changed into it */
static int change_to_test_data_dir(const char *test_dir) {
    char sample_path[TEST_PATH_MAX] = {0};
    FILE *sample_file = NULL;

    if (!test_dir || !test_dir[0]) return 0;
    if (snprintf(sample_path, sizeof(sample_path), "%s%s", test_dir, TEST_DATA_SAMPLE_FILE) >= (int)sizeof(sample_path)) return 0;
    sample_file = fopen(sample_path, "r");
    if (!sample_file) return 0;
    fclose(sample_file);
    return chdir(test_dir) == 0;
}

/*
 * Searches for the JSON test data in priority order and changes into the first match.
 * The executable's parent dir covers libtool builds, where the real binary is in test/.libs/
 */
static int find_test_data_dir(const char *exe_path) {
    char exe_dir[TEST_PATH_MAX] = {0};
    char exe_parent_dir[TEST_PATH_MAX] = {0};
    const char *candidate_dirs[] = { getenv("ACVP_TEST_DATA_DIR"), ".", exe_dir, exe_parent_dir };
    const char *last_slash = NULL;
    size_t i = 0;

    /* argv[0] has no slash when launched by bare name via PATH; the exe dirs then stay empty */
    if (exe_path) last_slash = strrchr(exe_path, '/');
    if (last_slash) {
        int dir_len = (int)(last_slash - exe_path);
        snprintf(exe_dir, sizeof(exe_dir), "%.*s", dir_len, exe_path);
        snprintf(exe_parent_dir, sizeof(exe_parent_dir), "%.*s/..", dir_len, exe_path);
    }

    for (i = 0; i < sizeof(candidate_dirs) / sizeof(candidate_dirs[0]); i++) {
        if (change_to_test_data_dir(candidate_dirs[i])) return 1;
    }
    return 0;
}

// Main entry point
int main(int argc, const char *argv[]) {
    if (!find_test_data_dir(argv[0])) {
        fprintf(stderr, "Cannot find json/aes/aes.json. Set ACVP_TEST_DATA_DIR, run from the "
                        "test directory, or place json/ beside the executable.\n");
        return EXIT_FAILURE;
    }

    return UnityMain(argc, argv, RunAllTests);
}
