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

TEST_GROUP(KDF_TLS12_API);
TEST_GROUP(KDF_TLS12_CAPABILITY);
TEST_GROUP(KDF_TLS12_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void kdf_tls12_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(KDF_TLS12_API) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf_tls12_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

TEST_TEAR_DOWN(KDF_TLS12_API) {
    kdf_tls12_api_tear_down_helper();
}

TEST_SETUP(KDF_TLS12_CAPABILITY) {}
TEST_TEAR_DOWN(KDF_TLS12_CAPABILITY) {}

TEST_SETUP(KDF_TLS12_HANDLER) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf_tls12_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

TEST_TEAR_DOWN(KDF_TLS12_HANDLER) {
    kdf_tls12_api_tear_down_helper();
}

// Test kdf_tls12 capabilites API.
TEST(KDF_TLS12_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf_tls12_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(KDF_TLS12_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kdf_tls12/tls12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    json_value_free(val);
    val = NULL;

end:
    if (ctx) teardown_ctx(&ctx);
}

// Test kdf_tls12 capabilites API.
TEST(KDF_TLS12_API, null_ctx) {
    val = json_parse_file("json/kdf_tls12/tls12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kdf_tls12_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The obj is null, expecting failure.
 */
TEST(KDF_TLS12_API, null_json_obj) {
    rv  = acvp_kdf_tls12_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/*
 * Test the kdf_tls12 KAT handler.
 * This is a good JSON.
 * Expecting success.
 */
TEST(KDF_TLS12_HANDLER, good) {
    val = json_parse_file("json/kdf_tls12/tls12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The value for key:"algorihm" is wrong.
 */
TEST(KDF_TLS12_HANDLER, wrong_algorithm) {
    val = json_parse_file("json/kdf_tls12/tls12_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The value for key:"mode" is wrong.
 */
TEST(KDF_TLS12_HANDLER, wrong_mode) {
    val = json_parse_file("json/kdf_tls12/tls12_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:"mode" is missing.
 */
TEST(KDF_TLS12_HANDLER, missing_mode) {
    val = json_parse_file("json/kdf_tls12/tls12_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The value for key:"hashAlg" is wrong.
 */
TEST(KDF_TLS12_HANDLER, wrong_hashAlg) {
    val = json_parse_file("json/kdf_tls12/tls12_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:"hashAlg" is missing.
 */
TEST(KDF_TLS12_HANDLER, missing_hashAlg) {
    val = json_parse_file("json/kdf_tls12/tls12_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The value for key:"preMasterSecretLength" is wrong.
 */
TEST(KDF_TLS12_HANDLER, wrong_preMasterSecretLength) {
    val = json_parse_file("json/kdf_tls12/tls12_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:"preMasterSecretLength" is missing.
 */
TEST(KDF_TLS12_HANDLER, missing_preMasterSecretLength) {
    val = json_parse_file("json/kdf_tls12/tls12_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:"keyBlockLength" is missing.
 */
TEST(KDF_TLS12_HANDLER, missing_keyBlockLength) {
    val = json_parse_file("json/kdf_tls12/tls12_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The value for key:"preMasterSecret" is wrong.
 */
TEST(KDF_TLS12_HANDLER, wrong_preMasterSecret) {
    val = json_parse_file("json/kdf_tls12/tls12_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:"preMasterSecret" is missing.
 */
TEST(KDF_TLS12_HANDLER, missing_preMasterSecret) {
    val = json_parse_file("json/kdf_tls12/tls12_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:sessionHash" is missing.
 */
TEST(KDF_TLS12_HANDLER, missing_sessionHash) {
    val = json_parse_file("json/kdf_tls12/tls12_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:clientRandom" is missing.
 */
TEST(KDF_TLS12_HANDLER, missing_clientRandom) {
    val = json_parse_file("json/kdf_tls12/tls12_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:serverRandom" is missing.
 */
TEST(KDF_TLS12_HANDLER, missing_serverRandom) {
    val = json_parse_file("json/kdf_tls12/tls12_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:"tgId" is missing.
 */
TEST(KDF_TLS12_HANDLER, missing_tgId) {
    val = json_parse_file("json/kdf_tls12/tls12_14.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The key: crypto handler operation fails on last crypto call
TEST(KDF_TLS12_HANDLER, cryptoFail1) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/kdf_tls12/tls12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(KDF_TLS12_HANDLER, cryptoFail2) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/kdf_tls12/tls12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on tenth iteration */
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}
