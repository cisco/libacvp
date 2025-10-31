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

TEST_GROUP(KDF_TLS13_API);
TEST_GROUP(KDF_TLS13_CAPABILITY);
TEST_GROUP(KDF_TLS13_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void kdf_tls13_api_setup_helper(void) {
    setup_empty_ctx(&ctx);

        rv = acvp_cap_kdf_tls13_enable(ctx, &dummy_handler_success);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS13, ACVP_PREREQ_HMAC, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_SHA256);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_SHA384);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_DHE);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK_DHE);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

static void kdf_tls13_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(KDF_TLS13_API) {
    kdf_tls13_api_setup_helper();
}

TEST_TEAR_DOWN(KDF_TLS13_API) {
    kdf_tls13_api_tear_down_helper();
}

TEST_SETUP(KDF_TLS13_CAPABILITY) {}
TEST_TEAR_DOWN(KDF_TLS13_CAPABILITY) {}

TEST_SETUP(KDF_TLS13_HANDLER) {
    kdf_tls13_api_setup_helper();
}

TEST_TEAR_DOWN(KDF_TLS13_HANDLER) {
    kdf_tls13_api_tear_down_helper();
}

// Test capabilites API.
TEST(KDF_TLS13_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf_tls13_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS13, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_DHE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK_DHE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(KDF_TLS13_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kdf_tls13/tls13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
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
TEST(KDF_TLS13_API, null_ctx) {
    val = json_parse_file("json/kdf_tls13/tls13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kdf_tls13_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(KDF_TLS13_API, null_json_obj) {
    rv  = acvp_kdf_tls13_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(KDF_TLS13_HANDLER, good) {
    val = json_parse_file("json/kdf_tls13/tls13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"algorithm" is wrong.
TEST(KDF_TLS13_HANDLER, bad_algorithm) {
    val = json_parse_file("json/kdf_tls13/tls13_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"algorithm" is missing.
TEST(KDF_TLS13_HANDLER, no_algorithm) {
    val = json_parse_file("json/kdf_tls13/tls13_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"mode" is wrong.
TEST(KDF_TLS13_HANDLER, bad_mode) {
    val = json_parse_file("json/kdf_tls13/tls13_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"mode" is missing.
TEST(KDF_TLS13_HANDLER, no_mode) {
    val = json_parse_file("json/kdf_tls13/tls13_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"hmacAlg" is wrong.
TEST(KDF_TLS13_HANDLER, bad_hmacalg) {
    val = json_parse_file("json/kdf_tls13/tls13_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"hmacAlg" is missing.
TEST(KDF_TLS13_HANDLER, no_hmacalg) {
    val = json_parse_file("json/kdf_tls13/tls13_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"runningMode" is wrong.
TEST(KDF_TLS13_HANDLER, bad_runningmode) {
    val = json_parse_file("json/kdf_tls13/tls13_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"runningMode" is missing.
TEST(KDF_TLS13_HANDLER, no_runningmode) {
    val = json_parse_file("json/kdf_tls13/tls13_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"testType" is wrong.
TEST(KDF_TLS13_HANDLER, bad_testtype) {
    val = json_parse_file("json/kdf_tls13/tls13_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"testType" is missing.
TEST(KDF_TLS13_HANDLER, no_testtype) {
    val = json_parse_file("json/kdf_tls13/tls13_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"tcId" is missing.
TEST(KDF_TLS13_HANDLER, no_tcid) {
    val = json_parse_file("json/kdf_tls13/tls13_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"helloClientRandom" is missing.
TEST(KDF_TLS13_HANDLER, no_hcr) {
    val = json_parse_file("json/kdf_tls13/tls13_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"helloServerRandom" is missing.
TEST(KDF_TLS13_HANDLER, no_hsr) {
    val = json_parse_file("json/kdf_tls13/tls13_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"finishedClientRandom" is missing.
TEST(KDF_TLS13_HANDLER, no_fcr) {
    val = json_parse_file("json/kdf_tls13/tls13_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"finishedServerRandom" is missing.
TEST(KDF_TLS13_HANDLER, no_fsr) {
    val = json_parse_file("json/kdf_tls13/tls13_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"psk" is missing.
TEST(KDF_TLS13_HANDLER, no_psk) {
    val = json_parse_file("json/kdf_tls13/tls13_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"dhe" is missing.
TEST(KDF_TLS13_HANDLER, no_dhe) {
    val = json_parse_file("json/kdf_tls13/tls13_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}
