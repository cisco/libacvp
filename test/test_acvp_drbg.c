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

TEST_GROUP(DRBG_API);
TEST_GROUP(DRBG_CAPABILITY);
TEST_GROUP(DRBG_HANDDLER);
TEST_GROUP(DRBG_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void drbg_api_setup_helper(void) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_drbg_enable(ctx, ACVP_HASHDRBG, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
                                    ACVP_DRBG_DER_FUNC_ENABLED, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_set_prereq(ctx, ACVP_HASHDRBG,
            ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_PRED_RESIST_ENABLED, ACVP_DRBG_PRED_RESIST_YES);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_RESEED_ENABLED, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_ENTROPY_LEN, (int)128, (int)64,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_NONCE_LEN, (int)96, (int)32,(int) 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_RET_BITS_LEN, 160);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_enable(ctx, ACVP_HMACDRBG, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_set_prereq(ctx, ACVP_HMACDRBG, 
            ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMACDRBG, 
            ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
                                    ACVP_DRBG_DER_FUNC_ENABLED, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_PRED_RESIST_ENABLED, ACVP_DRBG_PRED_RESIST_YES);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_RESEED_ENABLED, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_RET_BITS_LEN, 224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    //Add length range
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_ENTROPY_LEN, (int)192, (int)64,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_NONCE_LEN, (int)192, (int)64,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // ACVP_CTRDRBG
    rv = acvp_cap_drbg_enable(ctx, ACVP_CTRDRBG, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    //Add length range
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_ENTROPY_LEN, (int)128, (int)128, (int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_NONCE_LEN, (int)64, (int)64,(int) 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_PERSO_LEN, (int)0, (int)256,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_ADD_IN_LEN, (int)0, (int)256,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
                                    ACVP_DRBG_DER_FUNC_ENABLED, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_PRED_RESIST_ENABLED, ACVP_DRBG_PRED_RESIST_YES);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_RESEED_ENABLED, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_RET_BITS_LEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

static void drbg_api_tear_down_helper(void) {
    if (val) json_value_free(val);
        val = NULL;
        obj = NULL;

        if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(DRBG_API) {
    drbg_api_setup_helper();
}

TEST_TEAR_DOWN(DRBG_API) {
    drbg_api_tear_down_helper();
}

TEST_SETUP(DRBG_CAPABILITY) {}
TEST_TEAR_DOWN(DRBG_CAPABILITY) {}

TEST_SETUP(DRBG_HANDDLER) {
    drbg_api_setup_helper();
}

TEST_TEAR_DOWN(DRBG_HANDDLER) {
    drbg_api_tear_down_helper();
}

TEST_SETUP(DRBG_HANDLER) {
    drbg_api_setup_helper();
}

TEST_TEAR_DOWN(DRBG_HANDLER) {
    drbg_api_tear_down_helper();
}

// Test capabilites API.
TEST(DRBG_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_drbg_enable(ctx, ACVP_HASHDRBG, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
                                    ACVP_DRBG_DER_FUNC_ENABLED, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_set_prereq(ctx, ACVP_HASHDRBG,
            ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_PRED_RESIST_ENABLED, ACVP_DRBG_PRED_RESIST_YES);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_RESEED_ENABLED, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_ENTROPY_LEN, (int)128, (int)64,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_NONCE_LEN, (int)96, (int)32,(int) 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
            ACVP_DRBG_RET_BITS_LEN, 160);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_enable(ctx, ACVP_HMACDRBG, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_set_prereq(ctx, ACVP_HMACDRBG, 
            ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMACDRBG, 
            ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
                                    ACVP_DRBG_DER_FUNC_ENABLED, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_PRED_RESIST_ENABLED, ACVP_DRBG_PRED_RESIST_YES);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_RESEED_ENABLED, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_RET_BITS_LEN, 224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    //Add length range
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_ENTROPY_LEN, (int)192, (int)64,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_NONCE_LEN, (int)192, (int)64,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
            ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // ACVP_CTRDRBG
    rv = acvp_cap_drbg_enable(ctx, ACVP_CTRDRBG, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    //Add length range
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_ENTROPY_LEN, (int)128, (int)128, (int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_NONCE_LEN, (int)64, (int)64,(int) 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_PERSO_LEN, (int)0, (int)256,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_ADD_IN_LEN, (int)0, (int)256,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
                                    ACVP_DRBG_DER_FUNC_ENABLED, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_PRED_RESIST_ENABLED, ACVP_DRBG_PRED_RESIST_YES);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_RESEED_ENABLED, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
            ACVP_DRBG_RET_BITS_LEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(DRBG_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/drbg/drbg.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);

end:
    if (ctx) teardown_ctx(&ctx);
    json_value_free(val);
    val = NULL;
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
TEST(DRBG_API, null_ctx) {
    val = json_parse_file("json/drbg/drbg.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_drbg_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;

}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(DRBG_API, null_json_obj) {
    rv  = acvp_drbg_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(DRBG_HANDLER, good) {
    val = json_parse_file("json/drbg/drbg.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;

}

// The key:"algorithm" is missing.
TEST(DRBG_HANDLER, missing_algorithm) {
    val = json_parse_file("json/drbg/drbg_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"algorithm" is wrong.
TEST(DRBG_HANDLER, wrong_algorithm) {
    val = json_parse_file("json/drbg/drbg_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"mode" is missing.
TEST(DRBG_HANDLER, missing_mode) {
    val = json_parse_file("json/drbg/drbg_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"mode" is wrong.
TEST(DRBG_HANDLER, wrong_mode) {
    val = json_parse_file("json/drbg/drbg_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"predResistance" is missing.
TEST(DRBG_HANDLER, missing_predResistance) {
    val = json_parse_file("json/drbg/drbg_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"derFunc" is missing.
TEST(DRBG_HANDLER, missing_derFunc) {
    val = json_parse_file("json/drbg/drbg_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"entropyInputLen" is missing.
TEST(DRBG_HANDLER, missing_entropyInputLen) {
    val = json_parse_file("json/drbg/drbg_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"entropyInputLen" is too small.
TEST(DRBG_HANDLER, small_entropyInputLen) {
    val = json_parse_file("json/drbg/drbg_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"entropyInputLen" is too big.
TEST(DRBG_HANDLER, big_entropyInputLen) {
    val = json_parse_file("json/drbg/drbg_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"nonceLen" is missing.
TEST(DRBG_HANDLER, missing_nonceLen) {
    val = json_parse_file("json/drbg/drbg_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nonceLen" is too small.
TEST(DRBG_HANDLER, small_nonceLen) {
    val = json_parse_file("json/drbg/drbg_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nonceLen" is too big.
TEST(DRBG_HANDLER, big_nonceLen) {
    val = json_parse_file("json/drbg/drbg_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"persoStringLen" is too big.
TEST(DRBG_HANDLER, big_persoStringLen) {
    val = json_parse_file("json/drbg/drbg_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"returnedBitsLen" is missing.
TEST(DRBG_HANDLER, missing_returnedBitsLen) {
    val = json_parse_file("json/drbg/drbg_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"returnedBitsLen" is too big.
TEST(DRBG_HANDLER, big_returnedBitsLen) {
    val = json_parse_file("json/drbg/drbg_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"additionalInputLen" is too big.
TEST(DRBG_HANDLER, big_additionalInputLen) {
    val = json_parse_file("json/drbg/drbg_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"persoString" is missing.
TEST(DRBG_HANDLER, missing_persoString) {
    val = json_parse_file("json/drbg/drbg_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"persoString" string is too long.
TEST(DRBG_HANDLER, long_persoString) {
    val = json_parse_file("json/drbg/drbg_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"entropyInput" is missing.
TEST(DRBG_HANDLER, missing_entropyInput) {
    val = json_parse_file("json/drbg/drbg_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"entropyInput" string is too long.
TEST(DRBG_HANDLER, long_entropyInput) {
    val = json_parse_file("json/drbg/drbg_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"nonce" is missing.
TEST(DRBG_HANDLER, missing_nonce) {
    val = json_parse_file("json/drbg/drbg_21.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"nonce" string is too long.
TEST(DRBG_HANDLER, long_nonce) {
    val = json_parse_file("json/drbg/drbg_22.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"otherInput" is missing.
TEST(DRBG_HANDLER, missing_otherInput) {
    val = json_parse_file("json/drbg/drbg_23.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"otherInput" array is empty.
TEST(DRBG_HANDLER, empty_otherInput) {
    val = json_parse_file("json/drbg/drbg_24.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"additionalInput" for otherInput[0] is missing.
TEST(DRBG_HANDLER, missing_additionalInput_oi0) {
    val = json_parse_file("json/drbg/drbg_25.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"additionalInput" for otherInput[0] string is too long.
TEST(DRBG_HANDLER, long_additionalInput_oi0) {
    val = json_parse_file("json/drbg/drbg_26.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"entropyInput" for otherInput[0] is missing.
TEST(DRBG_HANDLER, missing_entropyInput_oi0) {
    val = json_parse_file("json/drbg/drbg_27.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"entropyInput" for otherInput[0] string is too long.
TEST(DRBG_HANDLER, long_entropyInput_oi0) {
    val = json_parse_file("json/drbg/drbg_28.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"additionalInput" for otherInput[1] is missing.
TEST(DRBG_HANDLER, missing_additionalInput_oi1) {
    val = json_parse_file("json/drbg/drbg_29.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"additionalInput" for otherInput[1] string is too long.
TEST(DRBG_HANDLER, long_additionalInput_oi1) {
    val = json_parse_file("json/drbg/drbg_30.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"entropyInput" for otherInput[1] is missing.
TEST(DRBG_HANDLER, missing_entropyInput_oi1) {
    val = json_parse_file("json/drbg/drbg_31.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"entropyInput" for otherInput[1] string is too long.
TEST(DRBG_HANDLER, long_entropyInput_oi1) {
    val = json_parse_file("json/drbg/drbg_32.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key: crypto handler operation fails on last crypto call
TEST(DRBG_HANDDLER, cryptoFail1) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/drbg/drbg.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(DRBG_HANDDLER, cryptoFail2) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/drbg/drbg.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 809; /* fail on last iteration */
    rv  = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key:"mode" is missing in last tg
TEST(DRBG_HANDDLER, tgFail1) {

    val = json_parse_file("json/drbg/drbg_33.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"nonce" is missing in last tc
TEST(DRBG_HANDDLER, tcFail1) {

    val = json_parse_file("json/drbg/drbg_34.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_drbg_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}
