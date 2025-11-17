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

TEST_GROUP(KDF135_IKEV1_API);
TEST_GROUP(KDF135_IKEV1_CAPABILITY);
TEST_GROUP(KDF135_IKEV1_HANDLER);
TEST_GROUP(Kdf135ikeV1Fail);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void kdf135_ikev1_api_setup_helper(void) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf135_ikev1_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV1, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV1, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_INIT_NONCE_LEN, 64, 2048, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_RESPOND_NONCE_LEN, 64, 2048, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_DH_SECRET_LEN, 224, 8192, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_PSK_LEN, 8, 8192, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, ACVP_SHA1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_AUTH_METHOD, ACVP_KDF135_IKEV1_AMETH_PSK);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

static void kdf135_ikev1_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(KDF135_IKEV1_API) {
    kdf135_ikev1_api_setup_helper();
}

TEST_TEAR_DOWN(KDF135_IKEV1_API) {
    kdf135_ikev1_api_tear_down_helper();
}

TEST_SETUP(KDF135_IKEV1_CAPABILITY) {}
TEST_TEAR_DOWN(KDF135_IKEV1_CAPABILITY) {}

TEST_SETUP(KDF135_IKEV1_HANDLER) {
    kdf135_ikev1_api_setup_helper();
}

TEST_TEAR_DOWN(KDF135_IKEV1_HANDLER) {
    kdf135_ikev1_api_tear_down_helper();
}

TEST_SETUP(Kdf135ikeV1Fail) {
    kdf135_ikev1_api_setup_helper();
}

TEST_TEAR_DOWN(Kdf135ikeV1Fail) {
    kdf135_ikev1_api_tear_down_helper();
}

// Test capabilites API.
TEST(KDF135_IKEV1_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf135_ikev1_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV1, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV1, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_INIT_NONCE_LEN, 64, 2048, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_RESPOND_NONCE_LEN, 64, 2048, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_DH_SECRET_LEN, 224, 8192, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_PSK_LEN, 8, 8192, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, ACVP_SHA1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_AUTH_METHOD, ACVP_KDF135_IKEV1_AMETH_PSK);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(KDF135_IKEV1_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
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
TEST(KDF135_IKEV1_API, null_ctx) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kdf135_ikev1_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(KDF135_IKEV1_API, null_json_obj) {
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(KDF135_IKEV1_HANDLER, good) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"algorithm" is wrong.
TEST(KDF135_IKEV1_HANDLER, wrong_algorithm) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"hashAlg" is missing.
TEST(KDF135_IKEV1_HANDLER, missing_hashAlg) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"hashAlg" is wrong.
TEST(KDF135_IKEV1_HANDLER, wrong_hashAlg) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"authenticationMethod" is missing.
TEST(KDF135_IKEV1_HANDLER, missing_authenticationMethod) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"authenticationMethod" is wrong.
TEST(KDF135_IKEV1_HANDLER, wrong_authenticationMethod) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"nInitLength" is missing.
TEST(KDF135_IKEV1_HANDLER, missing_nInitLength) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nInitLength" is too small.
TEST(KDF135_IKEV1_HANDLER, small_nInitLength) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nInitLength" is too big.
TEST(KDF135_IKEV1_HANDLER, big_nInitLength) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"nRespLength" is missing.
TEST(KDF135_IKEV1_HANDLER, missing_nRespLength) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nRespLength" is too small.
TEST(KDF135_IKEV1_HANDLER, small_nRespLength) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nRespLength" is too big.
TEST(KDF135_IKEV1_HANDLER, big_nRespLength) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"dhLength" is missing.
TEST(KDF135_IKEV1_HANDLER, missing_dhLength) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"dhLength" is too small.
TEST(KDF135_IKEV1_HANDLER, small_dhLength) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"dhLength" is too big.
TEST(KDF135_IKEV1_HANDLER, big_dhLength) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"preSharedKeyLength" is missing.
TEST(KDF135_IKEV1_HANDLER, missing_preSharedKeyLength) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"preSharedKeyLength" is too small.
TEST(KDF135_IKEV1_HANDLER, small_preSharedKeyLength) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"preSharedKeyLength" is too big.
TEST(KDF135_IKEV1_HANDLER, big_preSharedKeyLength) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"nInit" is missing.
TEST(KDF135_IKEV1_HANDLER, missing_nInit) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nInit" has wrong string length.
TEST(KDF135_IKEV1_HANDLER, wrong_nInit) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"nResp" is missing.
TEST(KDF135_IKEV1_HANDLER, missing_nResp) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nResp" has wrong string length.
TEST(KDF135_IKEV1_HANDLER, wrong_nResp) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_21.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ckyInit" is missing.
TEST(KDF135_IKEV1_HANDLER, missing_ckyInit) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_22.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ckyInit" string is too long.
TEST(KDF135_IKEV1_HANDLER, long_ckyInit) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_23.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ckyResp" is missing.
TEST(KDF135_IKEV1_HANDLER, missing_ckyResp) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_24.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ckyResp" string is too long.
TEST(KDF135_IKEV1_HANDLER, long_ckyResp) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_25.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"gxy" is missing.
TEST(KDF135_IKEV1_HANDLER, missing_gxy) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_26.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"gxy" string is too long.
TEST(KDF135_IKEV1_HANDLER, long_gxy) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_27.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"preSharedKey" is missing.
TEST(KDF135_IKEV1_HANDLER, missing_preSharedKey) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_28.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"preSharedKey" string is too long.
TEST(KDF135_IKEV1_HANDLER, long_preSharedKey) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_29.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"tgId" is missing.
TEST(KDF135_IKEV1_HANDLER, missing_tgId) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_30.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key: crypto handler operation fails on last crypto call
TEST(Kdf135ikeV1Fail, cryptoFail1) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(Kdf135ikeV1Fail, cryptoFail2) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on tenth iteration */
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key:"nInitLength" is missing in last tg
TEST(Kdf135ikeV1Fail, tgFail) {

    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_31.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"nInit" is missing in last tc
TEST(Kdf135ikeV1Fail, tcFail) {

    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_32.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ikev1_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}
