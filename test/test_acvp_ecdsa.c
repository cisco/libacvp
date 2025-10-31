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

TEST_GROUP(ECDSA_API);
TEST_GROUP(ECDSA_CAPABILITY);
TEST_GROUP(ECDSA_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void ecdsa_api_setup_helper(void) {
    setup_empty_ctx(&ctx);
    
        // Enable ECDSA keygen
        rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYGEN, &dummy_handler_success);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_DRBG, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_SECRET_GEN, ACVP_ECDSA_SECRET_GEN_TEST_CAND);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
        // Enable ECDSA keyVer...
        rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYVER, &dummy_handler_success);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_SHA, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_DRBG, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
        // Enable ECDSA sigGen...
        rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGGEN, &dummy_handler_success);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_SHA, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_DRBG, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA224);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
        // Enable ECDSA sigVer...
        rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGVER, &dummy_handler_success);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_SHA, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_DRBG, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA384);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

static void ecdsa_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(ECDSA_API) {
    ecdsa_api_setup_helper();
}

TEST_TEAR_DOWN(ECDSA_API) {
    ecdsa_api_tear_down_helper();
}

TEST_SETUP(ECDSA_CAPABILITY) {}
TEST_TEAR_DOWN(ECDSA_CAPABILITY) {}

TEST_SETUP(ECDSA_HANDLER) {
    ecdsa_api_setup_helper();
}

TEST_TEAR_DOWN(ECDSA_HANDLER) {
    ecdsa_api_tear_down_helper();
}

// Test capabilites API.
TEST(ECDSA_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_SECRET_GEN, ACVP_ECDSA_SECRET_GEN_TEST_CAND);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(ECDSA_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/ecdsa/ecdsa_keygen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    /* All four APIs point to the same internal code... */
    rv  = acvp_ecdsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    json_value_free(val);
    val = NULL;

    val = json_parse_file("json/ecdsa/ecdsa_keyver.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_ecdsa_keyver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    json_value_free(val);
    val = NULL;
    
    val = json_parse_file("json/ecdsa/ecdsa_siggen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_ecdsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    json_value_free(val);
    val = NULL;
    
    val = json_parse_file("json/ecdsa/ecdsa_sigver.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_ecdsa_sigver_kat_handler(ctx, obj);
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
TEST(ECDSA_API, null_ctx) {
    val = json_parse_file("json/ecdsa/ecdsa_keygen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* All four APIs point to the same internal code... */
    rv  = acvp_ecdsa_keygen_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 * All four APIs point to the same internal method so
 * this is just a sanity check...
 */
TEST(ECDSA_API, null_json_obj) {
    rv  = acvp_ecdsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    
    rv  = acvp_ecdsa_keyver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    
    rv  = acvp_ecdsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    
    rv  = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(ECDSA_HANDLER, good_sv) {
    val = json_parse_file("json/ecdsa/ecdsa_sigver.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(ECDSA_HANDLER, good_kg) {
    val = json_parse_file("json/ecdsa/ecdsa_keygen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(ECDSA_HANDLER, good_kv) {
    val = json_parse_file("json/ecdsa/ecdsa_keyver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_keyver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(ECDSA_HANDLER, good_sg) {
    val = json_parse_file("json/ecdsa/ecdsa_siggen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"algorithm" is wrong.
TEST(ECDSA_HANDLER, wrong_algorithm) {
    val = json_parse_file("json/ecdsa/ecdsa_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"mode" is missing.
TEST(ECDSA_HANDLER, missing_mode) {
    val = json_parse_file("json/ecdsa/ecdsa_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"mode" is wrong.
TEST(ECDSA_HANDLER, wrong_mode) {
    val = json_parse_file("json/ecdsa/ecdsa_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"testGroups" is missing.
TEST(ECDSA_HANDLER, missing_testgroups) {
    val = json_parse_file("json/ecdsa/ecdsa_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"curve" is missing.
TEST(ECDSA_HANDLER, missing_curve) {
    val = json_parse_file("json/ecdsa/ecdsa_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"curve" string is wrong.
TEST(ECDSA_HANDLER, wrong_curve) {
    val = json_parse_file("json/ecdsa/ecdsa_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_keyver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"tgId" is missing.
TEST(ECDSA_HANDLER, missing_tgid) {
    val = json_parse_file("json/ecdsa/ecdsa_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_ecdsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"hashAlg" is missing. (siggen, sigver only)
TEST(ECDSA_HANDLER, missing_hashalg_sg) {
    val = json_parse_file("json/ecdsa/ecdsa_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"hashAlg" is wrong. (siggen, sigver only)
TEST(ECDSA_HANDLER, wrong_hashalg) {
    val = json_parse_file("json/ecdsa/ecdsa_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"message" is missing. (siggen, sigver only)
TEST(ECDSA_HANDLER, missing_message) {
    val = json_parse_file("json/ecdsa/ecdsa_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_ecdsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"message" is too long. (siggen, sigver only)
TEST(ECDSA_HANDLER, too_long_message) {
    val = json_parse_file("json/ecdsa/ecdsa_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"qx" is missing. (keyver, sigver only)
TEST(ECDSA_HANDLER, missing_qx) {
    val = json_parse_file("json/ecdsa/ecdsa_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_ecdsa_keyver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"qy" is missing. (keyver, sigver only)
TEST(ECDSA_HANDLER, missing_qy) {
    val = json_parse_file("json/ecdsa/ecdsa_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"qx" is too long. (keyver, sigver only)
TEST(ECDSA_HANDLER, too_long_qx) {
    val = json_parse_file("json/ecdsa/ecdsa_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"qy" is too long. (keyver, sigver only)
TEST(ECDSA_HANDLER, too_long_qy) {
    val = json_parse_file("json/ecdsa/ecdsa_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_keyver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"r" is missing. (sigver only)
TEST(ECDSA_HANDLER, missing_r) {
    val = json_parse_file("json/ecdsa/ecdsa_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"s" is missing. (sigver only)
TEST(ECDSA_HANDLER, missing_s) {
    val = json_parse_file("json/ecdsa/ecdsa_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"r" is too long. (sigver only)
TEST(ECDSA_HANDLER, too_long_r) {
    val = json_parse_file("json/ecdsa/ecdsa_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"s" is too long. (sigver only)
TEST(ECDSA_HANDLER, too_long_s) {
    val = json_parse_file("json/ecdsa/ecdsa_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key: crypto handler operation fails on last crypto call
TEST(ECDSA_HANDLER, cryptoFail1) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/ecdsa/ecdsa_keygen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_ecdsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(ECDSA_HANDLER, cryptoFail2) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/ecdsa/ecdsa_keygen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 1; /* fail on last iteration */
    rv  = acvp_ecdsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(ECDSA_HANDLER, cryptoFail3) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/ecdsa/ecdsa_keyver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_ecdsa_keyver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(ECDSA_HANDLER, cryptoFail4) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/ecdsa/ecdsa_keyver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 1; /* fail on last iteration */
    rv  = acvp_ecdsa_keyver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(ECDSA_HANDLER, cryptoFail5) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/ecdsa/ecdsa_siggen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_ecdsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(ECDSA_HANDLER, cryptoFail6) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/ecdsa/ecdsa_siggen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 1; /* fail on last iteration */
    rv  = acvp_ecdsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(ECDSA_HANDLER, cryptoFail7) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/ecdsa/ecdsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(ECDSA_HANDLER, cryptoFail8) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/ecdsa/ecdsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 1; /* fail on last iteration */
    rv  = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key:"curve" is missing in last tg
TEST(ECDSA_HANDLER, tgFail1) {

    val = json_parse_file("json/ecdsa/ecdsa_keygen_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_ecdsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"tests" is missing in last tc
TEST(ECDSA_HANDLER, tcFail1) {

    val = json_parse_file("json/ecdsa/ecdsa_keygen_2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_ecdsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"curve" is missing in last tg
TEST(ECDSA_HANDLER, tgFail2) {

    val = json_parse_file("json/ecdsa/ecdsa_keyver_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_ecdsa_keyver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"qx" is missing in last tc
TEST(ECDSA_HANDLER, tcFail2) {

    val = json_parse_file("json/ecdsa/ecdsa_keyver_2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_ecdsa_keyver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"curve" is missing in last tg
TEST(ECDSA_HANDLER, tgFail3) {

    val = json_parse_file("json/ecdsa/ecdsa_siggen_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_ecdsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"message" is missing in last tc
TEST(ECDSA_HANDLER, tcFail3) {

    val = json_parse_file("json/ecdsa/ecdsa_siggen_2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_ecdsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"curve" is missing in last tg
TEST(ECDSA_HANDLER, tgFail4) {

    val = json_parse_file("json/ecdsa/ecdsa_sigver_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"message" is missing in last tc
TEST(ECDSA_HANDLER, tcFail4) {

    val = json_parse_file("json/ecdsa/ecdsa_sigver_2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_ecdsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}
