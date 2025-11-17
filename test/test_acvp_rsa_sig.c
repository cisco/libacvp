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

TEST_GROUP(RSA_SIGGEN_API);
TEST_GROUP(RSA_SIGGEN_CAPABILITY);
TEST_GROUP(RSA_SIGGEN_HANDLER);
TEST_GROUP(RSA_SIGVER_API);
TEST_GROUP(RSA_SIGVER_CAPABILITY);
TEST_GROUP(RSA_SIGVER_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void rsa_siggen_api_setup_helper(void) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGGEN, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA256, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA512, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA256, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA512, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA256, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

static void rsa_sigver_api_setup_helper(void) {
    setup_empty_ctx(&ctx);

    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGVER, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGVER, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA1, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA384, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA224, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA1, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA224, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    free(expo_str);
}

static void rsa_siggen_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(RSA_SIGGEN_API) {
    rsa_siggen_api_setup_helper();
}

TEST_TEAR_DOWN(RSA_SIGGEN_API) {
    rsa_siggen_api_tear_down_helper();
}

TEST_SETUP(RSA_SIGGEN_CAPABILITY) {}

TEST_TEAR_DOWN(RSA_SIGGEN_CAPABILITY) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(RSA_SIGGEN_HANDLER) {
    rsa_siggen_api_setup_helper();
}

TEST_TEAR_DOWN(RSA_SIGGEN_HANDLER) {
    rsa_siggen_api_tear_down_helper();
}

TEST_SETUP(RSA_SIGVER_API) {
    rsa_sigver_api_setup_helper();
}

TEST_TEAR_DOWN(RSA_SIGVER_API) {
    rsa_siggen_api_tear_down_helper();
}

TEST_SETUP(RSA_SIGVER_CAPABILITY) {}
TEST_TEAR_DOWN(RSA_SIGVER_CAPABILITY) {}

TEST_SETUP(RSA_SIGVER_HANDLER) {
    rsa_sigver_api_setup_helper();
}

TEST_TEAR_DOWN(RSA_SIGVER_HANDLER) {
    rsa_siggen_api_tear_down_helper();
}

// Test capabilites API.
TEST(RSA_SIGGEN_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGGEN, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA256, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA512, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA256, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA512, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA256, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(RSA_SIGGEN_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/rsa/rsa_siggen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
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
TEST(RSA_SIGGEN_API, null_ctx) {
    val = json_parse_file("json/rsa/rsa_siggen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_rsa_siggen_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(RSA_SIGGEN_API, null_json_obj) {
    rv  = acvp_rsa_siggen_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(RSA_SIGGEN_HANDLER, good) {
    val = json_parse_file("json/rsa/rsa_siggen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"algorithm" is wrong.
TEST(RSA_SIGGEN_HANDLER, wrong_algorithm) {
    val = json_parse_file("json/rsa/rsa_siggen_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"mode" is missing.
TEST(RSA_SIGGEN_HANDLER, missing_mode) {
    val = json_parse_file("json/rsa/rsa_siggen_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"mode" is wrong.
TEST(RSA_SIGGEN_HANDLER, wrong_mode) {
    val = json_parse_file("json/rsa/rsa_siggen_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"sigType" is missing.
TEST(RSA_SIGGEN_HANDLER, missing_sigType) {
    val = json_parse_file("json/rsa/rsa_siggen_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"hashAlg" is missing.
TEST(RSA_SIGGEN_HANDLER, missing_hashAlg) {
    val = json_parse_file("json/rsa/rsa_siggen_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"modulo" is missing.
TEST(RSA_SIGGEN_HANDLER, missing_mod) {
    val = json_parse_file("json/rsa/rsa_siggen_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"modulo" is wrong.
TEST(RSA_SIGGEN_HANDLER, wrong_mod) {
    val = json_parse_file("json/rsa/rsa_siggen_7.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"message" is missing.
TEST(RSA_SIGGEN_HANDLER, missing_message) {
    val = json_parse_file("json/rsa/rsa_siggen_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"tcId" is missing.
TEST(RSA_SIGGEN_HANDLER, missing_tcId) {
    val = json_parse_file("json/rsa/rsa_siggen_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"message" is too long.
TEST(RSA_SIGGEN_HANDLER, message_too_long) {
    val = json_parse_file("json/rsa/rsa_siggen_10.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// Test capabilites API.
TEST(RSA_SIGVER_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4
    
    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGVER, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGVER, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA1, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA384, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA224, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA1, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA224, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    free(expo_str);    
    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(RSA_SIGVER_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    val = json_parse_file("json/rsa/rsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    
    rv  = acvp_rsa_sigver_kat_handler(ctx, obj);
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
TEST(RSA_SIGVER_API, null_ctx) {
    val = json_parse_file("json/rsa/rsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    
    /* Test with NULL JSON object */
    rv  = acvp_rsa_sigver_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(RSA_SIGVER_API, null_json_obj) {
    rv  = acvp_rsa_sigver_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(RSA_SIGVER_HANDLER, good) {
    val = json_parse_file("json/rsa/rsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"e" is missing
TEST(RSA_SIGVER_HANDLER, missing_e) {
    val = json_parse_file("json/rsa/rsa_sigver_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"n" is missing
TEST(RSA_SIGVER_HANDLER, missing_n) {
    val = json_parse_file("json/rsa/rsa_sigver_2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"signature" is missing
TEST(RSA_SIGVER_HANDLER, missing_signature) {
    val = json_parse_file("json/rsa/rsa_sigver_3.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"signature" is too long
TEST(RSA_SIGVER_HANDLER, invalid_signature_len) {
    val = json_parse_file("json/rsa/rsa_sigver_4.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"e" is too long
TEST(RSA_SIGVER_HANDLER, invalid_e_len) {
    val = json_parse_file("json/rsa/rsa_sigver_5.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"n" is too long
TEST(RSA_SIGVER_HANDLER, invalid_n_len) {
    val = json_parse_file("json/rsa/rsa_sigver_6.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"tgId" is missing
TEST(RSA_SIGVER_HANDLER, missing_tgid) {
    val = json_parse_file("json/rsa/rsa_sigver_7.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key: crypto handler operation fails on last crypto call
TEST(RSA_SIGGEN_HANDLER, cryptoFail1) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/rsa/rsa_siggen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(RSA_SIGGEN_HANDLER, cryptoFail2) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/rsa/rsa_siggen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 1; /* fail on last iteration */
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key:"hashAlg" is missing in last tg
TEST(RSA_SIGGEN_HANDLER, tgFail1) {

    val = json_parse_file("json/rsa/rsa_siggen_11.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"message" is missing in last tc
TEST(RSA_SIGGEN_HANDLER, tcFail1) {

    val = json_parse_file("json/rsa/rsa_siggen_12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key: crypto handler operation fails on last crypto call
TEST(RSA_SIGVER_HANDLER, cryptoFail1) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/rsa/rsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_rsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(RSA_SIGVER_HANDLER, cryptoFail2) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/rsa/rsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 2; /* fail on last iteration */
    rv  = acvp_rsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key:"hashAlg" is missing in last tg
TEST(RSA_SIGVER_HANDLER, tgFail1) {

    val = json_parse_file("json/rsa/rsa_sigver_8.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"message" is missing in last tc
TEST(RSA_SIGVER_HANDLER, tcFail1) {

    val = json_parse_file("json/rsa/rsa_sigver_9.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_sigver_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}
