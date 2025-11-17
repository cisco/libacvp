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

TEST_GROUP(CreateSession);
TEST_GROUP(SetupSessionParams);

static ACVP_CTX *ctx = NULL;

TEST_SETUP(CreateSession) {}
TEST_TEAR_DOWN(CreateSession) {}

TEST_SETUP(SetupSessionParams) {}
TEST_TEAR_DOWN(SetupSessionParams) {}

TEST(CreateSession, properly) {
    ACVP_RESULT rv;
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;

    rv = acvp_create_test_session(&ctx, &progress, level);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

TEST(CreateSession, null_ctx) {
    ACVP_RESULT rv;
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;

    rv = acvp_create_test_session(NULL, &progress, level);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    teardown_ctx(&ctx);
}

TEST(SetupSessionParams, proper_ctx_params) {
    ACVP_RESULT rv;
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;
    char *server = "127.0.0.1";
    int port = 443;

    rv = acvp_create_test_session(&ctx, &progress, level);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    //Next we setup ctx params
    rv = acvp_set_server(ctx, server, port);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
#if 0
    rv = acvp_set_vendor_info(ctx, "Cisco", "www.cisco.com", "Unit Tests", "ut@123.com");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
#endif

    teardown_ctx(&ctx);
}

TEST(SetupSessionParams, null_server_param) {
    ACVP_RESULT rv;
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;
    char *server = NULL;
    int port = 443;

    rv = acvp_create_test_session(&ctx, &progress, level);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Next we setup ctx params
    rv = acvp_set_server(ctx, server, port);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    teardown_ctx(&ctx);
}

#if 0
TEST(SetupSessionParams, null_vendor_info_params) {
    ACVP_RESULT rv;
    setup_empty_ctx(&ctx);
    
    rv = acvp_set_vendor_info(ctx, NULL, "www.cisco.com", "Unit Tests", "ut@123.com");
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_set_vendor_info(ctx, "Cisco", NULL, "Unit Tests", "ut@123.com");
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_set_vendor_info(ctx, "Cisco", "www.cisco.com", NULL, "ut@123.com");
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_set_vendor_info(ctx, "Cisco", "www.cisco.com", "Unit Tests", NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    teardown_ctx(&ctx);
}
#endif
