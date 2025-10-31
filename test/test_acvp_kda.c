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

TEST_GROUP(KDA_API);
TEST_GROUP(KDA_CAPABILITY);
TEST_GROUP(KDA_HANDLER);
TEST_GROUP(KDA_HKDF_HANDLER);
TEST_GROUP(KDA_ONESTEP_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void kda_api_setup_helper(void) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_HKDF, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_HKDF, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LITERAL, "0123456789ABCDEF");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_CONTEXT, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LABEL, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA224, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA256, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA384, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA512, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_L, 2048, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_HKDF, ACVP_KDA_Z, 224, 1024, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // kdf onestep
    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_ONESTEP, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_ONESTEP, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LITERAL, "0123456789ABCDEF");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_CONTEXT, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LABEL, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA224, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA256, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA384, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA512, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_224, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_256, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_384, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_512, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_L, 2048, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_Z, 224, 1024, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

static void kda_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

// Empty setup/teardown for groups without fixtures
// Wrapper setup/teardown for groups sharing fixtures
TEST_SETUP(KDA_API) {
    kda_api_setup_helper();
}

TEST_TEAR_DOWN(KDA_API) {
    kda_api_tear_down_helper();
}

TEST_SETUP(KDA_CAPABILITY) {}
TEST_TEAR_DOWN(KDA_CAPABILITY) {}

TEST_SETUP(KDA_HANDLER) {
    kda_api_setup_helper();
}

TEST_TEAR_DOWN(KDA_HANDLER) {
    kda_api_tear_down_helper();
}

TEST_SETUP(KDA_HKDF_HANDLER) {
    kda_api_setup_helper();
}

TEST_TEAR_DOWN(KDA_HKDF_HANDLER) {
    kda_api_tear_down_helper();
}

TEST_SETUP(KDA_ONESTEP_HANDLER) {
    kda_api_setup_helper();
}

TEST_TEAR_DOWN(KDA_ONESTEP_HANDLER) {
    kda_api_tear_down_helper();
}

// Test capabilites API.
TEST(KDA_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_HKDF, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_HKDF, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LITERAL, "0123456789ABCDEF");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_CONTEXT, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LABEL, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA224, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA256, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA384, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA512, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_L, 2048, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_HKDF, ACVP_KDA_Z, 224, 1024, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // kdf onestep
    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_ONESTEP, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_ONESTEP, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LITERAL, "0123456789ABCDEF");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_CONTEXT, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LABEL, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA224, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA256, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA384, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA512, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_224, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_256, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_384, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_512, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_L, 2048, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_Z, 224, 1024, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(KDA_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kda/kda_hkdf_1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    rv = ACVP_SUCCESS;
    json_value_free(val);
    val = NULL;

    val = json_parse_file("json/kda/kda_onestep_1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv = acvp_kda_onestep_kat_handler(ctx, obj);
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
TEST(KDA_API, null_ctx) {
    val = json_parse_file("json/kda/kda_hkdf_1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kda_hkdf_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    rv = ACVP_SUCCESS;
    json_value_free(val);
    val = NULL;

    val = json_parse_file("json/kda/kda_onestep_1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kda_onestep_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(KDA_API, null_json_obj) {
    rv  = acvp_kda_hkdf_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    rv = ACVP_SUCCESS;
    rv  = acvp_kda_onestep_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);

}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(KDA_HANDLER, good) {
    val = json_parse_file("json/kda/kda_hkdf_1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
    rv = ACVP_UNSUPPORTED_OP;

    val = json_parse_file("json/kda/kda_onestep_1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_onestep_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: The key:"algorithm" is missing.
TEST(KDA_HKDF_HANDLER, missing_algorithm) {
    val = json_parse_file("json/kda/kda_hkdf_2.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: The key:"mode" is missing.
TEST(KDA_HKDF_HANDLER, missing_mode) {
    val = json_parse_file("json/kda/kda_hkdf_3.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: The key:"mode" is wrong.
TEST(KDA_HKDF_HANDLER, bad_mode) {
    val = json_parse_file("json/kda/kda_hkdf_4.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: The key:"testType" is missing.
TEST(KDA_HKDF_HANDLER, missing_type) {
    val = json_parse_file("json/kda/kda_hkdf_5.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: The key:"testType" is wrong.
TEST(KDA_HKDF_HANDLER, bad_type) {
    val = json_parse_file("json/kda/kda_hkdf_6.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: The group "kdfConfiguration" is missing.
TEST(KDA_HKDF_HANDLER, missing_kdfConfiguration) {
    val = json_parse_file("json/kda/kda_hkdf_7.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

/* NOTE: at time of creation, many of these fields
exist in both the test case objects and in the 
kdfConfiguration object. Libacvp parses from the 
kdfConfiguration object as NIST has indicated
they may remove the redundancy from the 
test case stuctures in the future */

// HKDF: The key:"l" is missing.
TEST(KDA_HKDF_HANDLER, missing_l) {
    val = json_parse_file("json/kda/kda_hkdf_8.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    //no cap registered, so suppose unsupported op.
    rv = ACVP_UNSUPPORTED_OP;
    json_value_free(val);
    val = NULL;
}

/** temporarily disabling due to NIST issue workaround
 *
 * HKDF: The key:"saltLen" is wrong.
 *
TEST(KDA_HKDF_HANDLER, bad_saltlen) {
    val = json_parse_file("json/kda/kda_hkdf_9.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}
*/

// HKDF: The key:"saltMethod" is missing.
TEST(KDA_HKDF_HANDLER, missing_saltmethod) {
    val = json_parse_file("json/kda/kda_hkdf_10.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: The key:"saltMethod" is wrong.
TEST(KDA_HKDF_HANDLER, bad_saltmethod) {
    val = json_parse_file("json/kda/kda_hkdf_11.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: The key:"fixedInfoEncoding" is missing
TEST(KDA_HKDF_HANDLER, missing_fixedinfoencoding) {
    val = json_parse_file("json/kda/kda_hkdf_12.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: The key:"fixedInfoEncoding" is wrong
TEST(KDA_HKDF_HANDLER, bad_fixedinfoencoding) {
    val = json_parse_file("json/kda/kda_hkdf_13.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: The key:"hmacAlg" is missing
TEST(KDA_HKDF_HANDLER, missing_hmacalg) {
    val = json_parse_file("json/kda/kda_hkdf_14.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: The key:"hmacAlg" is wrong
TEST(KDA_HKDF_HANDLER, bad_hmacalg) {
    val = json_parse_file("json/kda/kda_hkdf_15.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: The key:"fixedInfoPattern" is missing
TEST(KDA_HKDF_HANDLER, missing_fixedinfopattern) {
    val = json_parse_file("json/kda/kda_hkdf_16.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

//Test various malformed versions of fixed info pattern

// HKDF: Empty fixedInfoPattern
TEST(KDA_HKDF_HANDLER, empty_fixedinfopattern) {
    val = json_parse_file("json/kda/kda_hkdf_17.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: Invalid hex string in literal pattern candidate
TEST(KDA_HKDF_HANDLER, bad_hex_fixedinfopattern) {
    val = json_parse_file("json/kda/kda_hkdf_18.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: missing vPartyInfo
TEST(KDA_HKDF_HANDLER, missing_vpartyinfo_fixedinfopattern) {
    val = json_parse_file("json/kda/kda_hkdf_19.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: missing uPartyInfo
TEST(KDA_HKDF_HANDLER, missing_upartyinfo_fixedinfopattern) {
    val = json_parse_file("json/kda/kda_hkdf_20.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: missing salt
TEST(KDA_HKDF_HANDLER, missing_salt) {
    val = json_parse_file("json/kda/kda_hkdf_21.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: missing Z
TEST(KDA_HKDF_HANDLER, missing_z) {
    val = json_parse_file("json/kda/kda_hkdf_22.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: missing fixedInfoPartyU
TEST(KDA_HKDF_HANDLER, missing_fixedinfopartyu) {
    val = json_parse_file("json/kda/kda_hkdf_23.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: fixedInfoPartyU exists, but partyId is missing
TEST(KDA_HKDF_HANDLER, missing_upartyid) {
    val = json_parse_file("json/kda/kda_hkdf_24.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: missing fixedInfoPartyV
TEST(KDA_HKDF_HANDLER, missing_fixedinfopartyv) {
    val = json_parse_file("json/kda/kda_hkdf_25.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: fixedInfoPartyV exists, but partyId is missing
TEST(KDA_HKDF_HANDLER, missing_vpartyid) {
    val = json_parse_file("json/kda/kda_hkdf_26.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: algorithmId is missing
TEST(KDA_HKDF_HANDLER, missing_algorithmid) {
    val = json_parse_file("json/kda/kda_hkdf_27.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: label is missing
TEST(KDA_HKDF_HANDLER, missing_label) {
    val = json_parse_file("json/kda/kda_hkdf_28.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// HKDF: context is missing
TEST(KDA_HKDF_HANDLER, missing_context) {
    val = json_parse_file("json/kda/kda_hkdf_29.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

//Since they share much of the same code, test the common code using
//HKDF and test the diffs using onestep

// OneStep: The key:"algorithm" is missing.
TEST(KDA_ONESTEP_HANDLER, missing_algorithm) {
    val = json_parse_file("json/kda/kda_onestep_2.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_onestep_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"mode" is missing
TEST(KDA_ONESTEP_HANDLER, missing_mode) {
    val = json_parse_file("json/kda/kda_onestep_3.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_onestep_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"mode" is wrong
TEST(KDA_ONESTEP_HANDLER, wrong_mode) {
    val = json_parse_file("json/kda/kda_onestep_4.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_onestep_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"auxFunction" is missing
TEST(KDA_ONESTEP_HANDLER, missing_auxfunction) {
    val = json_parse_file("json/kda/kda_onestep_5.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_onestep_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"auxFunction" is wrong
TEST(KDA_ONESTEP_HANDLER, bad_auxfunction) {
    val = json_parse_file("json/kda/kda_onestep_6.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_onestep_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}
