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

TEST_GROUP(RSA_KEYGEN_API);
TEST_GROUP(RSA_KEYGEN_CAPABILITY);
TEST_GROUP(RSA_KEYGEN_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void rsa_keygen_api_setup_helper(void) {
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    setup_empty_ctx(&ctx);

    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_INFO_GEN_BY_SERVER, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_KEY_FORMAT, ACVP_RSA_KEY_FORMAT_STANDARD);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_rsa_keygen_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B34);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 2048, ACVP_RSA_PRIME_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 2048, ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    free(expo_str);
}

static void rsa_keygen_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(RSA_KEYGEN_API) {
    rsa_keygen_api_setup_helper();
}

TEST_TEAR_DOWN(RSA_KEYGEN_API) {
    rsa_keygen_api_tear_down_helper();
}

TEST_SETUP(RSA_KEYGEN_CAPABILITY) {}
TEST_TEAR_DOWN(RSA_KEYGEN_CAPABILITY) {}

TEST_SETUP(RSA_KEYGEN_HANDLER) {
    rsa_keygen_api_setup_helper();
}

TEST_TEAR_DOWN(RSA_KEYGEN_HANDLER) {
    rsa_keygen_api_tear_down_helper();
}

// Test capabilites API.
TEST(RSA_KEYGEN_CAPABILITY, good) {
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    setup_empty_ctx(&ctx);

    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_INFO_GEN_BY_SERVER, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_KEY_FORMAT, ACVP_RSA_KEY_FORMAT_STANDARD);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_rsa_keygen_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B34);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 2048, ACVP_RSA_PRIME_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 2048, ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    free(expo_str);
    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(RSA_KEYGEN_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/rsa/rsa_keygen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
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
TEST(RSA_KEYGEN_API, null_ctx) {
    val = json_parse_file("json/rsa/rsa_keygen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_rsa_keygen_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(RSA_KEYGEN_API, null_json_obj) {
    rv  = acvp_rsa_keygen_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(RSA_KEYGEN_HANDLER, good) {
    val = json_parse_file("json/rsa/rsa_keygen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"algorithm" is wrong.
TEST(RSA_KEYGEN_HANDLER, wrong_algorithm) {
    val = json_parse_file("json/rsa/rsa_keygen_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"mode" is missing.
TEST(RSA_KEYGEN_HANDLER, missing_mode) {
    val = json_parse_file("json/rsa/rsa_keygen_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"mode" is wrong.
TEST(RSA_KEYGEN_HANDLER, wrong_mode) {
    val = json_parse_file("json/rsa/rsa_keygen_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"infoGeneratedByServer" is missing.
TEST(RSA_KEYGEN_HANDLER, missing_infoGeneratedByServer) {
    val = json_parse_file("json/rsa/rsa_keygen_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"pubExpMode" is missing.
TEST(RSA_KEYGEN_HANDLER, missing_pubExpMode) {
    val = json_parse_file("json/rsa/rsa_keygen_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"pubExpMode" is wrong.
TEST(RSA_KEYGEN_HANDLER, wrong_pubExpMode) {
    val = json_parse_file("json/rsa/rsa_keygen_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"fixedPubExp" is missing.
TEST(RSA_KEYGEN_HANDLER, missing_fixedPubExp) {
    val = json_parse_file("json/rsa/rsa_keygen_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"keyFormat" is missing.
TEST(RSA_KEYGEN_HANDLER, missing_keyFormat) {
    val = json_parse_file("json/rsa/rsa_keygen_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"keyFormat" is wrong.
TEST(RSA_KEYGEN_HANDLER, wrong_keyFormat) {
    val = json_parse_file("json/rsa/rsa_keygen_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"randPQ" is missing.
TEST(RSA_KEYGEN_HANDLER, missing_randPQ) {
    val = json_parse_file("json/rsa/rsa_keygen_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"randPQ" is wrong.
TEST(RSA_KEYGEN_HANDLER, wrong_randPQ) {
    val = json_parse_file("json/rsa/rsa_keygen_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"primeTest" is missing.
TEST(RSA_KEYGEN_HANDLER, missing_primeTest) {
    val = json_parse_file("json/rsa/rsa_keygen_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"primeTest" is wrong.
TEST(RSA_KEYGEN_HANDLER, wrong_primeTest) {
    val = json_parse_file("json/rsa/rsa_keygen_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"modulo" is missing.
TEST(RSA_KEYGEN_HANDLER, missing_modulo) {
    val = json_parse_file("json/rsa/rsa_keygen_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"modulo" is wrong.
TEST(RSA_KEYGEN_HANDLER, wrong_modulo) {
    val = json_parse_file("json/rsa/rsa_keygen_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"hashAlg" is missing.
TEST(RSA_KEYGEN_HANDLER, missing_hashAlg) {
    val = json_parse_file("json/rsa/rsa_keygen_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"hashAlg" is wrong.
TEST(RSA_KEYGEN_HANDLER, wrong_hashAlg) {
    val = json_parse_file("json/rsa/rsa_keygen_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"e" is missing.
TEST(RSA_KEYGEN_HANDLER, missing_e) {
    val = json_parse_file("json/rsa/rsa_keygen_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"e" string is too long.
TEST(RSA_KEYGEN_HANDLER, long_e) {
    val = json_parse_file("json/rsa/rsa_keygen_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"bitlens" list is wrong size.
TEST(RSA_KEYGEN_HANDLER, wrong_size_bitlens) {
    val = json_parse_file("json/rsa/rsa_keygen_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"seed" is missing.
TEST(RSA_KEYGEN_HANDLER, missing_seed) {
    val = json_parse_file("json/rsa/rsa_keygen_21.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"seed" string is too long.
TEST(RSA_KEYGEN_HANDLER, long_seed) {
    val = json_parse_file("json/rsa/rsa_keygen_22.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"tgId" string is missing.
TEST(RSA_KEYGEN_HANDLER, missing_tgid) {
    val = json_parse_file("json/rsa/rsa_keygen_23.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The key: crypto handler operation fails on last crypto call
TEST(RSA_KEYGEN_HANDLER, cryptoFail1) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/rsa/rsa_keygen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(RSA_KEYGEN_HANDLER, cryptoFail2) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/rsa/rsa_keygen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 5; /* fail on last iteration */
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key:"hashAlg" is missing in last tg
TEST(RSA_KEYGEN_HANDLER, tgFail1) {

    val = json_parse_file("json/rsa/rsa_keygen_24.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"seed" is missing in last tc
TEST(RSA_KEYGEN_HANDLER, tcFail1) {

    val = json_parse_file("json/rsa/rsa_keygen_25.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}
