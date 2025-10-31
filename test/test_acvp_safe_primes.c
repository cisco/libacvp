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

TEST_GROUP(SAFE_PRIMES_API);
TEST_GROUP(SAFE_PRIMES_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void safe_primes_api_setup_helper(void) {
    setup_empty_ctx(&ctx);

    // Register Safe Prime Key Generation testing
    rv = acvp_cap_safe_primes_enable(ctx, ACVP_SAFE_PRIMES_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYGEN,
                                  ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYGEN,
                                  ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE2048);

    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE3072);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE4096);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE6144);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE8192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP2048);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP3072);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP4096);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP6144);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP8192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Register Safe Prime Key Verify testing
    rv = acvp_cap_safe_primes_enable(ctx, ACVP_SAFE_PRIMES_KEYVER, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYVER,
                                  ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYVER,
                                  ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE2048);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE3072);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE4096);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE6144);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE8192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP2048);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP3072);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP4096);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP6144);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP8192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

static void safe_primes_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(SAFE_PRIMES_API) {
    safe_primes_api_setup_helper();
}

TEST_TEAR_DOWN(SAFE_PRIMES_API) {
    safe_primes_api_tear_down_helper();
}

TEST_SETUP(SAFE_PRIMES_HANDLER) {
    safe_primes_api_setup_helper();
}

TEST_TEAR_DOWN(SAFE_PRIMES_HANDLER) {
    safe_primes_api_tear_down_helper();
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 * Component mode.
 */
TEST(SAFE_PRIMES_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/safe_primes/safe_primes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_safe_primes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    json_value_free(val);
    val = NULL;

end:
    if (ctx) teardown_ctx(&ctx);
}

TEST(SAFE_PRIMES_API, null_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/safe_primes/safe_primes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_safe_primes_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(SAFE_PRIMES_API, null_json_obj) {
    rv  = acvp_kas_ifc_ssc_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(SAFE_PRIMES_HANDLER, good) {
    val = json_parse_file("json/safe_primes/safe_primes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

TEST(SAFE_PRIMES_HANDLER, missing_mode) {
    val = json_parse_file("json/safe_primes/safe_primes_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

TEST(SAFE_PRIMES_HANDLER, bad_mode) {
    val = json_parse_file("json/safe_primes/safe_primes_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(SAFE_PRIMES_HANDLER, missing_alg) {
    val = json_parse_file("json/safe_primes/safe_primes_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

TEST(SAFE_PRIMES_HANDLER, missing_tg) {
    val = json_parse_file("json/safe_primes/safe_primes_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(SAFE_PRIMES_HANDLER, missing_tc) {
    val = json_parse_file("json/safe_primes/safe_primes_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(SAFE_PRIMES_HANDLER, missing_dgm) {
    val = json_parse_file("json/safe_primes/safe_primes_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(SAFE_PRIMES_HANDLER, bad_dgm) {
    val = json_parse_file("json/safe_primes/safe_primes_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(SAFE_PRIMES_HANDLER, missing_y) {
    val = json_parse_file("json/safe_primes/safe_primes_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(SAFE_PRIMES_HANDLER, missing_x) {
    val = json_parse_file("json/safe_primes/safe_primes_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(SAFE_PRIMES_HANDLER, missing_testtype) {
    val = json_parse_file("json/safe_primes/safe_primes_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(SAFE_PRIMES_HANDLER, bad_testtype) {
    val = json_parse_file("json/safe_primes/safe_primes_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}
