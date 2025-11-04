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

TEST_GROUP(KDF108_API);
TEST_GROUP(KDF108_CAPABILITY);
TEST_GROUP(KDF108_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void kdf108_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(KDF108_API) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf108_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF108, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_COUNTER_LEN, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_AFTER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTS_EMPTY_IV, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

TEST_TEAR_DOWN(KDF108_API) {
    kdf108_api_tear_down_helper();
}

TEST_SETUP(KDF108_CAPABILITY) {}
TEST_TEAR_DOWN(KDF108_CAPABILITY) {}

TEST_SETUP(KDF108_HANDLER) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf108_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF108, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_COUNTER_LEN, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_AFTER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTS_EMPTY_IV, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

TEST_TEAR_DOWN(KDF108_HANDLER) {
    kdf108_api_tear_down_helper();
}

// Test capabilites API.
TEST(KDF108_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf108_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF108, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_COUNTER_LEN, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_AFTER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTS_EMPTY_IV, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_REQUIRES_EMPTY_IV, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTS_EMPTY_IV, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_REQUIRES_EMPTY_IV, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(KDF108_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kdf108/kdf108.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kdf108_kat_handler(ctx, obj);
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
TEST(KDF108_API, null_ctx) {
    val = json_parse_file("json/kdf108/kdf108.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kdf108_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(KDF108_API, null_json_obj) {
    rv  = acvp_kdf108_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(KDF108_HANDLER, good) {
    val = json_parse_file("json/kdf108/kdf108.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"algorithm" is wrong.
TEST(KDF108_HANDLER, wrong_algorithm) {
    val = json_parse_file("json/kdf108/kdf108_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"kdfMode" is missing.
TEST(KDF108_HANDLER, missing_kdfMode) {
    val = json_parse_file("json/kdf108/kdf108_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"kdfMode" is wrong.
TEST(KDF108_HANDLER, wrong_kdfMode) {
    val = json_parse_file("json/kdf108/kdf108_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"macMode" is missing.
TEST(KDF108_HANDLER, missing_macMode) {
    val = json_parse_file("json/kdf108/kdf108_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"macMode" is wrong.
TEST(KDF108_HANDLER, wrong_macMode) {
    val = json_parse_file("json/kdf108/kdf108_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"keyOutLength" is missing.
TEST(KDF108_HANDLER, missing_keyOutLength) {
    val = json_parse_file("json/kdf108/kdf108_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"keyOutLength" is too big.
TEST(KDF108_HANDLER, big_keyOutLength) {
    val = json_parse_file("json/kdf108/kdf108_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"counterLength" is missing.
TEST(KDF108_HANDLER, missing_counterLength) {
    val = json_parse_file("json/kdf108/kdf108_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"counterLength" is wrong.
TEST(KDF108_HANDLER, wrong_counterLength) {
    val = json_parse_file("json/kdf108/kdf108_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"counterLocation" is missing.
TEST(KDF108_HANDLER, missing_counterLocation) {
    val = json_parse_file("json/kdf108/kdf108_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"counterLocation" is wrong.
TEST(KDF108_HANDLER, wrong_counterLocation) {
    val = json_parse_file("json/kdf108/kdf108_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"keyIn" is missing.
TEST(KDF108_HANDLER, missing_keyIn) {
    val = json_parse_file("json/kdf108/kdf108_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"keyIn" string is too long.
TEST(KDF108_HANDLER, long_keyIn) {
    val = json_parse_file("json/kdf108/kdf108_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iv" is missing.
TEST(KDF108_HANDLER, missing_iv) {
    val = json_parse_file("json/kdf108/kdf108_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"iv" string is too long.
TEST(KDF108_HANDLER, long_iv) {
    val = json_parse_file("json/kdf108/kdf108_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"deferred" is missing.
TEST(KDF108_HANDLER, missing_deferred) {
    val = json_parse_file("json/kdf108/kdf108_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"tgId" is missing.
TEST(KDF108_HANDLER, missing_tgId) {
    val = json_parse_file("json/kdf108/kdf108_17.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key: counterLoop is missing after multiple tgIds processed
TEST(KDF108_HANDLER, missing_tgLoop) {
    val = json_parse_file("json/kdf108/kdf108_18.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"keyIn" is missing after tcIds processed within tgId.
TEST(KDF108_HANDLER, missing_tcLoop) {
    val = json_parse_file("json/kdf108/kdf108_19.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key: crypto handler operation fails on first call
TEST(KDF108_HANDLER, cryptoFail1) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/kdf108/kdf108.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key:"keyIn" is missing after tcIds processed within tgId.
TEST(KDF108_HANDLER, cryptoFail2) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/kdf108/kdf108.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 4;  /* fail on fourth iteration */
    rv  = acvp_kdf108_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}
