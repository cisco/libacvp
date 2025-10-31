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

TEST_GROUP(HMAC_HANDLER);
TEST_GROUP(HmacApi);
TEST_GROUP(HmacFunc);

static ACVP_CTX *ctx = NULL;
static char cvalue[] = "same";
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;

static void setup(ACVP_CTX *ctx) {
    ACVP_RESULT rv;

    /* Enable capabilites */
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_KEYLEN, 256, 448, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_MACLEN, 32, 160, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA1, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_224, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_KEYLEN, 256, 448, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_MACLEN, 32, 224, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_224, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_256, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_KEYLEN, 256, 448, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_MACLEN, 32, 256, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_256, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_384, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_KEYLEN, 256, 448, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_MACLEN, 32, 384, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_384, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN, 256, 448, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_MACLEN, 32, 512, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_512, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// Empty setup/teardown for groups without fixtures
TEST_SETUP(HMAC_HANDLER) {
    ACVP_RESULT rv;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_KEYLEN, 256, 448, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_MACLEN, 32, 160, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA1, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_224, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_KEYLEN, 256, 448, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_MACLEN, 32, 224, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_224, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_256, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_KEYLEN, 256, 448, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_MACLEN, 32, 256, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_256, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_384, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_KEYLEN, 256, 448, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_MACLEN, 32, 384, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_384, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN, 256, 448, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_MACLEN, 32, 512, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_512, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

TEST_TEAR_DOWN(HMAC_HANDLER) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;

    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(HmacApi) {}
TEST_TEAR_DOWN(HmacApi) {}

TEST_SETUP(HmacFunc) {}
TEST_TEAR_DOWN(HmacFunc) {}

// Test HMAC handler API inputs
TEST(HmacApi, null_ctx) {
    ACVP_RESULT rv;

    setup_empty_ctx(&ctx);

    val = json_parse_file("json/hmac/hmac1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with unregistered ctx */
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);

    setup(ctx);

    /* Test with NULL ctx */
    rv  = acvp_hmac_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    /* Test with NULL JSON object */
    rv  = acvp_hmac_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);

    teardown_ctx(&ctx);
    json_value_free(val);
    val = NULL;
}

// Test HMAC handler functionally
TEST(HmacFunc, null_ctx) {
    ACVP_RESULT rv;

    setup_empty_ctx(&ctx);

    /* This is a proper JSON, positive test */
    val = json_parse_file("json/hmac/hmac1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    setup(ctx);

    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;

    /* Test failing case, failed to include keyLen */
    val = json_parse_file("json/hmac/hmac2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;

    /* Test failing case, failed to include msgLen */
    val = json_parse_file("json/hmac/hmac3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;

    /* Test failing case, failed to include macLen */
    val = json_parse_file("json/hmac/hmac4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;

    /* Test failing case, failed to include key */
    val = json_parse_file("json/hmac/hmac5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;

    /* Test failing case, failed to include msg */
    val = json_parse_file("json/hmac/hmac6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;

    /* Test failing case, failed to include key */
    val = json_parse_file("json/hmac/hmac7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    json_value_free(val);
    val = NULL;

    /* Test failing case, msg does not match msgLen */
    val = json_parse_file("json/hmac/hmac8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;

    /* Test failing case, key does not match keyLen */
    val = json_parse_file("json/hmac/hmac9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;

    /* Test failing case, failed to include tests */
    val = json_parse_file("json/hmac/hmac10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;

    /* Test failing case, failed to include testGroups */
    val = json_parse_file("json/hmac/hmac11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/hmac/hmac12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;

    /* Test failing case, failed to include test array */
    val = json_parse_file("json/hmac/hmac13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;

    /* Positive test case for coverage */
    val = json_parse_file("json/hmac/hmac14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;

    /* missing tgId */
    val = json_parse_file("json/hmac/hmac15.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;

    /* missing keyLen in second tg */
    val = json_parse_file("json/hmac/hmac16.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;

    /* missing key in last tc */
    val = json_parse_file("json/hmac/hmac17.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    teardown_ctx(&ctx);
    json_value_free(val);
    val = NULL;
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
TEST(HMAC_HANDLER, cryptoFail1) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    ACVP_RESULT rv;

    val = json_parse_file("json/hmac/hmac1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration of AFT */

    rv = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
TEST(HMAC_HANDLER, cryptoFail2) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    ACVP_RESULT rv;

    val = json_parse_file("json/hmac/hmac1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 5;  /* fail on 6th iteration of AFT */

    rv = acvp_hmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}
