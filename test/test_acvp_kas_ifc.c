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

TEST_GROUP(KAS_IFC_API);
TEST_GROUP(KAS_IFC_CAPABILITY);
TEST_GROUP(KAS_IFC_SSC_API);
TEST_GROUP(KAS_IFC_SSC_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void kas_ifc_api_setup_helper(void) {
    setup_empty_ctx(&ctx);
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    /* Support is for IFC-SSC for hashZ only */
    rv = acvp_cap_kas_ifc_enable(ctx, ACVP_KAS_IFC_SSC, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_RSA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_RSADP, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_INITIATOR);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_RESPONDER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 2048);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 3072);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 4096);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG1_BASIC);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_exponent(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_FIXEDPUBEXP, expo_str);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    free(expo_str);
}

static void kas_ifc_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

// Empty setup/teardown for groups without fixtures
// Wrapper setup/teardown for groups sharing fixtures
TEST_SETUP(KAS_IFC_API) {
    kas_ifc_api_setup_helper();
}

TEST_TEAR_DOWN(KAS_IFC_API) {
    kas_ifc_api_tear_down_helper();
}

TEST_SETUP(KAS_IFC_CAPABILITY) {}

TEST_TEAR_DOWN(KAS_IFC_CAPABILITY) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(KAS_IFC_SSC_API) {}
TEST_TEAR_DOWN(KAS_IFC_SSC_API) {}

TEST_SETUP(KAS_IFC_SSC_HANDLER) {
    kas_ifc_api_setup_helper();
}

TEST_TEAR_DOWN(KAS_IFC_SSC_HANDLER) {
    kas_ifc_api_tear_down_helper();
}

// Test capabilites API.
TEST(KAS_IFC_CAPABILITY, good) {
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    setup_empty_ctx(&ctx);
    /* Support is for IFC-SSC for hashZ only */
    rv = acvp_cap_kas_ifc_enable(ctx, ACVP_KAS_IFC_SSC, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_RSA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_RSADP, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_INITIATOR);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_RESPONDER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 2048);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 3072);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 4096);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG1_BASIC);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ifc_set_exponent(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_FIXEDPUBEXP, expo_str);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
    free(expo_str);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 * SSC mode.
 */
TEST(KAS_IFC_SSC_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kas_ifc/kas_ifc_ssc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
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
TEST(KAS_IFC_API, null_ctx) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kas_ifc_ssc_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(KAS_IFC_API, null_json_obj) {
    rv  = acvp_kas_ifc_ssc_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/* //////////////////////
 * SSC mode
 * /////////////////////
 */

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(KAS_IFC_SSC_HANDLER, good) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"algorithm" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_algorithm) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"testType" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_testType) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"testType" is wrong.
TEST(KAS_IFC_SSC_HANDLER, wrong_testType) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"hashFunctionZ" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_hashFunctionZ) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"hashFunctionZ" is wrong.
TEST(KAS_IFC_SSC_HANDLER, wrong_hashFunctionZ) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iutP" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_p) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iutQ" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_q) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iutD" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_d) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iutE" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_e) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iutN" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_n) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ServerC" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_serverc) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ServerE" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_servere) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iutC" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_c) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"z" is missing. NOTE: This only applies to test groups where a hash function is NOT provided
TEST(KAS_IFC_SSC_HANDLER, missing_z) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

#if 0 /* hashZ is not required for KAS1 test. Re-enable when KAS2 tests are added if needed */
// The key:"hashZ" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_hashz) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}
#endif
// The key:"scheme" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_scheme) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"kasRole" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_kasrole) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"keygen" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_keygen) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"modulo" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_modulo) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"fixedPubExp" is missing.
TEST(KAS_IFC_SSC_HANDLER, missing_fixedpub) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}
