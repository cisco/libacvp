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

TEST_GROUP(KDF135_IKEV2_API);
TEST_GROUP(KDF135_IKEV2_CAPABILITY);
TEST_GROUP(KDF135_IKEV2_HANDLER);
TEST_GROUP(Kdf135ikeV2Fail);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void kdf135_ikev2_api_setup_helper(void) {
    setup_empty_ctx(&ctx);

        rv = acvp_cap_kdf135_ikev2_enable(ctx, &dummy_handler_success);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV2, ACVP_PREREQ_SHA, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV2, ACVP_PREREQ_DRBG, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_INIT_NONCE_LEN, 128);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_INIT_NONCE_LEN, 2048);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_RESPOND_NONCE_LEN, 128);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_RESPOND_NONCE_LEN, 2048);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_DH_SECRET_LEN, 2048);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_KEY_MATERIAL_LEN, 1056);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_KEY_MATERIAL_LEN, 3072);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kdf135_ikev2_set_parm(ctx, ACVP_KDF_HASH_ALG, ACVP_SHA1);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

static void kdf135_ikev2_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(KDF135_IKEV2_API) {
    kdf135_ikev2_api_setup_helper();
}

TEST_TEAR_DOWN(KDF135_IKEV2_API) {
    kdf135_ikev2_api_tear_down_helper();
}

TEST_SETUP(KDF135_IKEV2_CAPABILITY) {}
TEST_TEAR_DOWN(KDF135_IKEV2_CAPABILITY) {}

TEST_SETUP(KDF135_IKEV2_HANDLER) {
    kdf135_ikev2_api_setup_helper();
}

TEST_TEAR_DOWN(KDF135_IKEV2_HANDLER) {
    kdf135_ikev2_api_tear_down_helper();
}

TEST_SETUP(Kdf135ikeV2Fail) {
    kdf135_ikev2_api_setup_helper();
}

TEST_TEAR_DOWN(Kdf135ikeV2Fail) {
    kdf135_ikev2_api_tear_down_helper();
}

// Test capabilites API.
TEST(KDF135_IKEV2_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf135_ikev2_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV2, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV2, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_INIT_NONCE_LEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_INIT_NONCE_LEN, 2048);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_RESPOND_NONCE_LEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_RESPOND_NONCE_LEN, 2048);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_DH_SECRET_LEN, 2048);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_KEY_MATERIAL_LEN, 1056);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_KEY_MATERIAL_LEN, 3072);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_parm(ctx, ACVP_KDF_HASH_ALG, ACVP_SHA1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(KDF135_IKEV2_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
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
TEST(KDF135_IKEV2_API, null_ctx) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kdf135_ikev2_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(KDF135_IKEV2_API, null_json_obj) {
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(KDF135_IKEV2_HANDLER, good) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"algorithm" is wrong.
TEST(KDF135_IKEV2_HANDLER, wrong_algorithm) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"hashAlg" is missing.
TEST(KDF135_IKEV2_HANDLER, missing_hashAlg) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"hashAlg" is wrong.
TEST(KDF135_IKEV2_HANDLER, wrong_hashAlg) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"nInitLength" is missing.
TEST(KDF135_IKEV2_HANDLER, missing_nInitLength) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nInitLength" is too small.
TEST(KDF135_IKEV2_HANDLER, small_nInitLength) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nInitLength" is too big.
TEST(KDF135_IKEV2_HANDLER, big_nInitLength) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"nRespLength" is missing.
TEST(KDF135_IKEV2_HANDLER, missing_nRespLength) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nRespLength" is too small.
TEST(KDF135_IKEV2_HANDLER, small_nRespLength) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nRespLength" is too big.
TEST(KDF135_IKEV2_HANDLER, big_nRespLength) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"dhLength" is missing.
TEST(KDF135_IKEV2_HANDLER, missing_dhLength) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"dhLength" is too small.
TEST(KDF135_IKEV2_HANDLER, small_dhLength) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"dhLength" is too big.
TEST(KDF135_IKEV2_HANDLER, big_dhLength) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"derivedKeyingMaterialLength" is missing.
TEST(KDF135_IKEV2_HANDLER, missing_derivedKeyingMaterialLength) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"derivedKeyingMaterialLength" is too small.
TEST(KDF135_IKEV2_HANDLER, small_derivedKeyingMaterialLength) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"derivedKeyingMaterialLength" is too big.
TEST(KDF135_IKEV2_HANDLER, big_derivedKeyingMaterialLength) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"nInit" is missing.
TEST(KDF135_IKEV2_HANDLER, missing_nInit) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nInit" has wrong string length.
TEST(KDF135_IKEV2_HANDLER, wrong_nInit) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"nResp" is missing.
TEST(KDF135_IKEV2_HANDLER, missing_nResp) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nResp" has wrong string length.
TEST(KDF135_IKEV2_HANDLER, wrong_nResp) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"spiInit" is missing.
TEST(KDF135_IKEV2_HANDLER, missing_spiInit) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"spiInit" string is too long.
TEST(KDF135_IKEV2_HANDLER, long_spiInit) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_21.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"spiResp" is missing.
TEST(KDF135_IKEV2_HANDLER, missing_spiResp) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_22.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"spiResp" string is too long.
TEST(KDF135_IKEV2_HANDLER, long_spiResp) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_23.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"gir" is missing.
TEST(KDF135_IKEV2_HANDLER, missing_gir) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_24.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"gir" string is too long.
TEST(KDF135_IKEV2_HANDLER, long_gir) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_25.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"girNew" is missing.
TEST(KDF135_IKEV2_HANDLER, missing_girNew) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_26.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"girNew" string is too long.
TEST(KDF135_IKEV2_HANDLER, long_girNew) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_27.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"tgId" is missing.
TEST(KDF135_IKEV2_HANDLER, missing_tgId) {
    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_28.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The key: crypto handler operation fails on last crypto call
TEST(Kdf135ikeV2Fail, cryptoFail1) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(Kdf135ikeV2Fail, cryptoFail2) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on tenth iteration */
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key:"nInitLength" is missing in last tg
TEST(Kdf135ikeV2Fail, tgFail) {

    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_29.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"nInit" is missing in last tc
TEST(Kdf135ikeV2Fail, tcFail) {

    val = json_parse_file("json/kdf135_ikev2/kdf135_ikev2_31.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev2_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}
