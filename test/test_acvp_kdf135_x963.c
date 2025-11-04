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

TEST_GROUP(Kdf135x963Fail);
TEST_GROUP(Kdf135x963Func);
TEST_GROUP(Kdf135x963Func1);
TEST_GROUP(Kdf135x963Func10);
TEST_GROUP(Kdf135x963Func11);
TEST_GROUP(Kdf135x963Func2);
TEST_GROUP(Kdf135x963Func3);
TEST_GROUP(Kdf135x963Func4);
TEST_GROUP(Kdf135x963Func5);
TEST_GROUP(Kdf135x963Func6);
TEST_GROUP(Kdf135x963Func7);
TEST_GROUP(Kdf135x963Func8);
TEST_GROUP(Kdf135x963Func9);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

TEST_SETUP(Kdf135x963Fail) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135x963Fail) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135x963Func) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135x963Func) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135x963Func1) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135x963Func1) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135x963Func10) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135x963Func10) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135x963Func11) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135x963Func11) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135x963Func2) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135x963Func2) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135x963Func3) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135x963Func3) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135x963Func4) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135x963Func4) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135x963Func5) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135x963Func5) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135x963Func6) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135x963Func6) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135x963Func7) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135x963Func7) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135x963Func8) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135x963Func8) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135x963Func9) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135x963Func9) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST(Kdf135x963Func, null_ctx) {
      
    val = json_parse_file("json/kdf135_x963/kdf135_x963_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    
    /* Test with unregistered ctx */
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);

}

// Test kdf135 x963 handler functionally
TEST(Kdf135x963Func1, null_ctx) {
    
    val = json_parse_file("json/kdf135_x963/kdf135_x963_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    
    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_KEY_DATA_LEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_KEY_DATA_LEN, 1024);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_FIELD_SIZE, 224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_FIELD_SIZE, 521);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_SHARED_INFO_LEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_SHARED_INFO_LEN, 1024);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    /* Test with NULL ctx */
    rv  = acvp_kdf135_x963_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

}

// Test kdf135 x963 handler functionally
TEST(Kdf135x963Func2, null_obj) {
    
    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    /* Test with NULL JSON object */
    rv  = acvp_kdf135_ssh_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    
}

// Test kdf135 x963 handler functionally
TEST(Kdf135x963Func3, properly) {

    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    /* This is a proper JSON */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
}

// Test kdf135 x963 handler functionally
TEST(Kdf135x963Func4, missing) {
    
    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    /* This is a corrupt JSON, missing field size */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    
}

// Test kdf135 x963 handler functionally
TEST(Kdf135x963Func5, missing) {
    
    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    /* This is a corrupt JSON, missing key data length */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    
}

// Test kdf135 x963 handler functionally
TEST(Kdf135x963Func6, missing) {
    
    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    /* This is a corrupt JSON, missing hash alg */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    
}

// Test kdf135 x963 handler functionally
TEST(Kdf135x963Func7, invalid) {
    
    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    /* This is a corrupt JSON, corrupt algorithm */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
}

// Test kdf135 x963 handler functionally
TEST(Kdf135x963Func8, missing) {
    
    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    /* Test failing case, failed to include test array */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    
}

// Test kdf135 x963 handler functionally
TEST(Kdf135x963Func9, missing) {
    
    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    /* Test failing case, failed to include tests */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    
}

// Test kdf135 x963 handler functionally
TEST(Kdf135x963Func10, missing) {
    
    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    /* Test failing case, failed to include testGroups */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    
}

// Test kdf135 x963 handler functionally
TEST(Kdf135x963Func11, missing) {
    
    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    
}

// Test kdf135 x963 handler functionally
TEST(Kdf135x963Func11, missing_tgid) {
    
    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_10.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);

}

// The key: crypto handler operation fails on last crypto call
TEST(Kdf135x963Fail, cryptoFail1) {
    force_handler_failure = 1;

    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    val = json_parse_file("json/kdf135_x963/kdf135_x963_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(Kdf135x963Fail, cryptoFail2) {
    force_handler_failure = 1;

    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    val = json_parse_file("json/kdf135_x963/kdf135_x963_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on tenth iteration */
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    force_handler_failure = 0;
}

// The key:"hashAlg" is missing in secong tg
TEST(Kdf135x963Fail, tgFail) {

    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    val = json_parse_file("json/kdf135_x963/kdf135_x963_11.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
}

// The key:"z" is missing in last tc
TEST(Kdf135x963Fail, tcFail) {

    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    val = json_parse_file("json/kdf135_x963/kdf135_x963_12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_x963_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
}
