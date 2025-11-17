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
#include "acvp/acvp_lcl.h"

TEST_GROUP(DEPENDENCY_NEW);
TEST_GROUP(FIPS_VALIDATION_METADATA);
TEST_GROUP(FREE_OPERATING_ENV);
TEST_GROUP(INGEST_METADATA);
TEST_GROUP(MODULE_NEW);
TEST_GROUP(MODULE_SET_TYPE_VERSION_DESC);
TEST_GROUP(OE_NEW);
TEST_GROUP(OE_SET_DEPENDENCY);
TEST_GROUP(VERIFY_FIPS_OPERATING_ENV);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;

static void free_operating_env_setup_helper(void) {
    setup_empty_ctx(&ctx);
}

static void free_operating_env_tear_down_helper(void) {
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
}

TEST_SETUP(DEPENDENCY_NEW) {
    free_operating_env_setup_helper();
}

TEST_TEAR_DOWN(DEPENDENCY_NEW) {
    free_operating_env_tear_down_helper();
}

TEST_SETUP(FIPS_VALIDATION_METADATA) {
    free_operating_env_setup_helper();
}

TEST_TEAR_DOWN(FIPS_VALIDATION_METADATA) {
    free_operating_env_tear_down_helper();
}

TEST_SETUP(FREE_OPERATING_ENV) {
    free_operating_env_setup_helper();
}

TEST_TEAR_DOWN(FREE_OPERATING_ENV) {
    free_operating_env_tear_down_helper();
}

TEST_SETUP(INGEST_METADATA) {
    free_operating_env_setup_helper();
}

TEST_TEAR_DOWN(INGEST_METADATA) {
    free_operating_env_tear_down_helper();
}

TEST_SETUP(MODULE_NEW) {
    free_operating_env_setup_helper();
}

TEST_TEAR_DOWN(MODULE_NEW) {
    free_operating_env_tear_down_helper();
}

TEST_SETUP(MODULE_SET_TYPE_VERSION_DESC) {
    free_operating_env_setup_helper();
}

TEST_TEAR_DOWN(MODULE_SET_TYPE_VERSION_DESC) {
    free_operating_env_tear_down_helper();
}

TEST_SETUP(OE_NEW) {
    free_operating_env_setup_helper();
}

TEST_TEAR_DOWN(OE_NEW) {
    free_operating_env_tear_down_helper();
}

TEST_SETUP(OE_SET_DEPENDENCY) {
    free_operating_env_setup_helper();
}

TEST_TEAR_DOWN(OE_SET_DEPENDENCY) {
    free_operating_env_tear_down_helper();
}

TEST_SETUP(VERIFY_FIPS_OPERATING_ENV) {
    free_operating_env_setup_helper();
}

TEST_TEAR_DOWN(VERIFY_FIPS_OPERATING_ENV) {
    free_operating_env_tear_down_helper();
}

// Test  acvp_oe_free_operating_env
TEST(FREE_OPERATING_ENV, free_operating_env) {

    acvp_oe_free_operating_env(NULL);
    acvp_oe_free_operating_env(ctx);
}

// Test  acvp_oe_ingest_metadata
TEST(INGEST_METADATA, ingest_metadata) {

    rv = acvp_oe_ingest_metadata(NULL, "json/meta.json");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_oe_ingest_metadata(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_oe_ingest_metadata(ctx, "invalid.json");
    TEST_ASSERT_EQUAL(ACVP_JSON_ERR, rv);

    rv = acvp_oe_ingest_metadata(ctx, "json/meta.json");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

}

// Test  acvp_oe_set_fips_validation_metadata
TEST(FIPS_VALIDATION_METADATA, set_fips_validation_metadata) {

    rv = acvp_oe_set_fips_validation_metadata(NULL, 1, 1);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_oe_set_fips_validation_metadata(ctx, 1, 1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_oe_set_fips_validation_metadata(ctx, 0, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_oe_set_fips_validation_metadata(ctx, 1, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_oe_set_fips_validation_metadata(ctx, 0, 1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

}

// Test  acvp_verify_fips_validation_metadata
TEST(VERIFY_FIPS_OPERATING_ENV, verify_fips_operating_env) {

    rv = acvp_verify_fips_validation_metadata(NULL);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_oe_ingest_metadata(ctx, "json/meta.json");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_oe_set_fips_validation_metadata(ctx, 1, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_verify_fips_validation_metadata(ctx);
#ifdef ACVP_OFFLINE
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
#else
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
#endif
}

// Test  acvp_oe_dependency_new
TEST(DEPENDENCY_NEW, dependency_new) {

    rv = acvp_oe_dependency_new(NULL, 1);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_oe_dependency_new(ctx, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_oe_dependency_new(ctx, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

}

// Test  acvp_oe_oe_new
TEST(OE_NEW, oe_new) {

    rv = acvp_oe_oe_new(NULL, 1, "name");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_oe_oe_new(ctx, 0, "name");
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_oe_oe_new(ctx, 1, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_oe_oe_new(ctx, 1, "name");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

}

// Test  acvp_oe_oe_set_dependency
TEST(OE_SET_DEPENDENCY, oe_set_dependency) {

    rv = acvp_oe_oe_set_dependency(NULL, 1, 1);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_oe_oe_set_dependency(ctx, 1, 1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

}

// Test  acvp_oe_module_new
TEST(MODULE_NEW, module_new) {

    rv = acvp_oe_module_new(NULL, 1, "name");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_oe_module_new(ctx, 1, "name");
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

}

// Test  acvp_oe_module_set_type_version_desc
TEST(MODULE_SET_TYPE_VERSION_DESC, module_set_type_version_desc) {

    rv = acvp_oe_module_set_type_version_desc(NULL, 1, "type", "ver", "desc");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    rv = acvp_oe_module_set_type_version_desc(ctx, 1, "type", "ver", "desc");
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

}
