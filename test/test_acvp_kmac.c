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

TEST_GROUP(KMAC_128_CAPABILITY);
TEST_GROUP(KMAC_256_CAPABILITY);
TEST_GROUP(KMAC_API);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;

TEST_SETUP(KMAC_128_CAPABILITY) {}
TEST_TEAR_DOWN(KMAC_128_CAPABILITY) {}

TEST_SETUP(KMAC_256_CAPABILITY) {}
TEST_TEAR_DOWN(KMAC_256_CAPABILITY) {}

TEST_SETUP(KMAC_API) {
    setup_empty_ctx(&ctx);
    rv = acvp_cap_kmac_enable(ctx, ACVP_KMAC_128, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kmac_enable(ctx, ACVP_KMAC_256, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

}

TEST_TEAR_DOWN(KMAC_API) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

// Test capabilites API.
TEST(KMAC_128_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kmac_enable(ctx, ACVP_KMAC_128, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_128, ACVP_KMAC_MSGLEN, 0, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_128, ACVP_KMAC_MACLEN, 32, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_128, ACVP_KMAC_KEYLEN, 128, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_128, ACVP_KMAC_XOF_SUPPORT, ACVP_XOF_SUPPORT_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_128, ACVP_KMAC_HEX_CUSTOM_SUPPORT, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

// Test capabilites API.
TEST(KMAC_256_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kmac_enable(ctx, ACVP_KMAC_256, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_256, ACVP_KMAC_MSGLEN, 0, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_256, ACVP_KMAC_MACLEN, 32, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_256, ACVP_KMAC_KEYLEN, 128, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_256, ACVP_KMAC_XOF_SUPPORT, ACVP_XOF_SUPPORT_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_256, ACVP_KMAC_HEX_CUSTOM_SUPPORT, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(KMAC_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kmac/kmac.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kmac_kat_handler(ctx, obj);
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
TEST(KMAC_API, null_ctx) {
    val = json_parse_file("json/kmac/kmac.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kmac_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(KMAC_API, null_json_obj) {
    rv  = acvp_kmac_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(KMAC_API, good_aes) {
    val = json_parse_file("json/kmac/kmac.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"algorithm" is wrong.
TEST(KMAC_API, wrong_algorithm) {
    val = json_parse_file("json/kmac/kmac_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    json_value_free(val);
    val = NULL;
}

/* any below failure cases could have the JSON modified anywhere in the file, not just the top */

/* The value for key:"testType" is wrong. */
TEST(KMAC_API, wrong_test_type) {
    val = json_parse_file("json/kmac/kmac_3.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

/* The key:"xof" is missing. */
TEST(KMAC_API, missing_xof) {
    val = json_parse_file("json/kmac/kmac_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

/* The key:"hexCustomization" is missing. */
TEST(KMAC_API, missing_hex_customization) {
    val = json_parse_file("json/kmac/kmac_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

/* The key:"msgLen" is missing. */
TEST(KMAC_API, missing_msgLen) {
    val = json_parse_file("json/kmac/kmac_6.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

/* The key:"macLen" is missing or 0. */
TEST(KMAC_API, missing_macLen) {
    val = json_parse_file("json/kmac/kmac_7.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

/* The key:"keyLen" is missing or 0. */
TEST(KMAC_API, missing_keyLen) {
    val = json_parse_file("json/kmac/kmac_8.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

/* The value for msgLen does not match the actual length of "msg" */
TEST(KMAC_API, bad_msgLen) {
    val = json_parse_file("json/kmac/kmac_9.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

/* The value for keyLen does not match the actual length of "key" */
TEST(KMAC_API, bad_keyLen) {
    val = json_parse_file("json/kmac/kmac_10.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

/* The value for macLen does not match the actual length of "mac" (MVT only) */
TEST(KMAC_API, bad_macLen) {
    val = json_parse_file("json/kmac/kmac_11.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

/* The key:"msg" is missing. */
TEST(KMAC_API, missing_msg) {
    val = json_parse_file("json/kmac/kmac_12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

/* The key:"key" is missing. */
TEST(KMAC_API, missing_key) {
    val = json_parse_file("json/kmac/kmac_13.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

/* The key:"mac" is missing. (MVT only) */
TEST(KMAC_API, missing_mac) {
    val = json_parse_file("json/kmac/kmac_14.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}
