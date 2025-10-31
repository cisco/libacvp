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

TEST_GROUP(PBKDF_API);
TEST_GROUP(PBKDF_CAPABILITY);
TEST_GROUP(PBKDF_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void pbkdf_api_setup_helper(void) {
    setup_empty_ctx(&ctx);

        rv = acvp_cap_pbkdf_enable(ctx, &dummy_handler_success);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_PBKDF, ACVP_PREREQ_HMAC, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA1);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA224);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA256);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA384);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA512);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA3_224);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA3_256);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA3_384);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA3_512);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_ITERATION_COUNT, 10, 1000, 1);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_KEY_LEN, 112, 4096, 8);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_PASSWORD_LEN, 8, 128, 1);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_SALT_LEN, 128, 4096, 8);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

static void pbkdf_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(PBKDF_API) {
    pbkdf_api_setup_helper();
}

TEST_TEAR_DOWN(PBKDF_API) {
    pbkdf_api_tear_down_helper();
}

TEST_SETUP(PBKDF_CAPABILITY) {}
TEST_TEAR_DOWN(PBKDF_CAPABILITY) {}

TEST_SETUP(PBKDF_HANDLER) {
    pbkdf_api_setup_helper();
}

TEST_TEAR_DOWN(PBKDF_HANDLER) {
    pbkdf_api_tear_down_helper();
}

// Test capabilites API.
TEST(PBKDF_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_pbkdf_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_PBKDF, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA3_224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA3_256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA3_384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA3_512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_ITERATION_COUNT, 10, 1000, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_KEY_LEN, 112, 4096, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_PASSWORD_LEN, 8, 128, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_SALT_LEN, 128, 4096, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(PBKDF_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/pbkdf/pbkdf.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    json_value_free(val);
    val = NULL;

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
TEST(PBKDF_API, null_ctx) {
    val = json_parse_file("json/pbkdf/pbkdf.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_pbkdf_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(PBKDF_API, null_json_obj) {
    rv  = acvp_pbkdf_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(PBKDF_HANDLER, good) {
    val = json_parse_file("json/pbkdf/pbkdf.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"algorithm" is wrong.
TEST(PBKDF_HANDLER, wrong_algorithm) {
    val = json_parse_file("json/pbkdf/pbkdf_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"algorithm" is missing.
TEST(PBKDF_HANDLER, no_algorithm) {
    val = json_parse_file("json/pbkdf/pbkdf_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"hmacAlg" is missing.
TEST(PBKDF_HANDLER, no_hmacalg) {
    val = json_parse_file("json/pbkdf/pbkdf_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"hmacAlg" is wrong.
TEST(PBKDF_HANDLER, bad_hmacalg) {
    val = json_parse_file("json/pbkdf/pbkdf_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"testType" is wrong.
TEST(PBKDF_HANDLER, bad_testtype) {
    val = json_parse_file("json/pbkdf/pbkdf_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"testType" is missing.
TEST(PBKDF_HANDLER, no_testtype) {
    val = json_parse_file("json/pbkdf/pbkdf_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"tcId" is missing.
TEST(PBKDF_HANDLER, no_tcid) {
    val = json_parse_file("json/pbkdf/pbkdf_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"keyLen" is too high.
TEST(PBKDF_HANDLER, bad_keylen) {
    val = json_parse_file("json/pbkdf/pbkdf_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"keyLen" is missing/too low.
TEST(PBKDF_HANDLER, no_keylen) {
    val = json_parse_file("json/pbkdf/pbkdf_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"salt" is too long.
TEST(PBKDF_HANDLER, bad_salt) {
    val = json_parse_file("json/pbkdf/pbkdf_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"salt" is missing.
TEST(PBKDF_HANDLER, no_salt) {
    val = json_parse_file("json/pbkdf/pbkdf_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"password" is too long.
TEST(PBKDF_HANDLER, bad_password) {
    val = json_parse_file("json/pbkdf/pbkdf_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"password" is too short.
TEST(PBKDF_HANDLER, bad_password_2) {
    val = json_parse_file("json/pbkdf/pbkdf_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"password" is missing.
TEST(PBKDF_HANDLER, no_password) {
    val = json_parse_file("json/pbkdf/pbkdf_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"iterationCount" is too long.
TEST(PBKDF_HANDLER, bad_iterationCount) {
    val = json_parse_file("json/pbkdf/pbkdf_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"iterationCount" is too short.
TEST(PBKDF_HANDLER, bad_iterationCount_2) {
    val = json_parse_file("json/pbkdf/pbkdf_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iterationCount" is missing.
TEST(PBKDF_HANDLER, no_iterationCount) {
    val = json_parse_file("json/pbkdf/pbkdf_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"salt" is of the wrong type.
TEST(PBKDF_HANDLER, bad_salt_2) {
    val = json_parse_file("json/pbkdf/pbkdf_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}
