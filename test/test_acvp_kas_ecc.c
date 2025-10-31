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

TEST_GROUP(KAS_ECC_API);
TEST_GROUP(KAS_ECC_CAPABILITY);
TEST_GROUP(KAS_ECC_CDH_API);
TEST_GROUP(KAS_ECC_CDH_HANDLER);
TEST_GROUP(KAS_ECC_COMP_API);
TEST_GROUP(KAS_ECC_COMP_HANDLER);
TEST_GROUP(KAS_ECC_SSC_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void kas_ecc_api_setup_helper(void) {
    setup_empty_ctx(&ctx);

        rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &dummy_handler_success);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_PREREQ_ECDSA, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P384);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P521);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K233);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K283);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K409);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K571);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B233);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B283);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B409);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B571);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

        rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_COMP, &dummy_handler_success);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_ECDSA, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_SHA, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_DRBG, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CCM, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CMAC, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_HMAC, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_INITIATOR);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_RESPONDER);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_KDF, 0, ACVP_KAS_ECC_NOKDFNOKC);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EB, ACVP_EC_CURVE_P224, ACVP_SHA224);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EC, ACVP_EC_CURVE_P256, ACVP_SHA256);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ED, ACVP_EC_CURVE_P384, ACVP_SHA384);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EE, ACVP_EC_CURVE_P521, ACVP_SHA512);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

        rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_SSC, &dummy_handler_success);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_ECDSA, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_SHA, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_DRBG, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_HMAC, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_INITIATOR);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_RESPONDER);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P384);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P521);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_HASH, ACVP_SHA512);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

static void kas_ecc_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(KAS_ECC_API) {
    kas_ecc_api_setup_helper();
}

TEST_TEAR_DOWN(KAS_ECC_API) {
    kas_ecc_api_tear_down_helper();
}

TEST_SETUP(KAS_ECC_CAPABILITY) {}
TEST_TEAR_DOWN(KAS_ECC_CAPABILITY) {}

TEST_SETUP(KAS_ECC_CDH_API) {}
TEST_TEAR_DOWN(KAS_ECC_CDH_API) {}

TEST_SETUP(KAS_ECC_CDH_HANDLER) {
    kas_ecc_api_setup_helper();
}

TEST_TEAR_DOWN(KAS_ECC_CDH_HANDLER) {
    kas_ecc_api_tear_down_helper();
}

TEST_SETUP(KAS_ECC_COMP_API) {}
TEST_TEAR_DOWN(KAS_ECC_COMP_API) {}

TEST_SETUP(KAS_ECC_COMP_HANDLER) {
    kas_ecc_api_setup_helper();
}

TEST_TEAR_DOWN(KAS_ECC_COMP_HANDLER) {
    kas_ecc_api_tear_down_helper();
}

TEST_SETUP(KAS_ECC_SSC_HANDLER) {
    kas_ecc_api_setup_helper();
}

TEST_TEAR_DOWN(KAS_ECC_SSC_HANDLER) {
    kas_ecc_api_tear_down_helper();
}

// Test capabilites API.
TEST(KAS_ECC_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_PREREQ_ECDSA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P521);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K233);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K283);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K409);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K571);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B233);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B283);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B409);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B571);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_COMP, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_ECDSA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CCM, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_INITIATOR);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_RESPONDER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_KDF, 0, ACVP_KAS_ECC_NOKDFNOKC);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EB, ACVP_EC_CURVE_P224, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EC, ACVP_EC_CURVE_P256, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ED, ACVP_EC_CURVE_P384, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EE, ACVP_EC_CURVE_P521, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 * CDH mode.
 */
TEST(KAS_ECC_CDH_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kas_ecc/kas_ecc_cdh.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    json_value_free(val);
    val = NULL;

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 * Component mode.
 */
TEST(KAS_ECC_COMP_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kas_ecc/kas_ecc_comp.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
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
TEST(KAS_ECC_API, null_ctx) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kas_ecc_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(KAS_ECC_API, null_json_obj) {
    rv  = acvp_kas_ecc_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/* //////////////////////
 * CDH mode
 * /////////////////////
 */

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(KAS_ECC_CDH_HANDLER, good) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"algorithm" is missing.
TEST(KAS_ECC_CDH_HANDLER, missing_algorithm) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"mode" is wrong.
TEST(KAS_ECC_CDH_HANDLER, wrong_mode) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"testType" is missing.
TEST(KAS_ECC_CDH_HANDLER, missing_testType) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"testType" is wrong.
TEST(KAS_ECC_CDH_HANDLER, wrong_testType) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"curve" is missing.
TEST(KAS_ECC_CDH_HANDLER, missing_curve) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"curve" is wrong.
TEST(KAS_ECC_CDH_HANDLER, wrong_curve) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"publicServerX" is missing.
TEST(KAS_ECC_CDH_HANDLER, missing_publicServerX) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"publicServerX" string is too long.
TEST(KAS_ECC_CDH_HANDLER, wrong_publicServerX) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"publicServerY" is missing.
TEST(KAS_ECC_CDH_HANDLER, missing_publicServerY) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"publicServerY" string is too long.
TEST(KAS_ECC_CDH_HANDLER, wrong_publicServerY) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

/* //////////////////////
 * Component mode
 * /////////////////////
 */

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(KAS_ECC_COMP_HANDLER, good) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"algorithm" is missing.
TEST(KAS_ECC_COMP_HANDLER, missing_algorithm) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"mode" is wrong.
TEST(KAS_ECC_COMP_HANDLER, wrong_mode) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"testType" is missing.
TEST(KAS_ECC_COMP_HANDLER, missing_testType) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"testType" is wrong.
TEST(KAS_ECC_COMP_HANDLER, wrong_testType) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"curve" is missing.
TEST(KAS_ECC_COMP_HANDLER, missing_curve) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"curve" is wrong.
TEST(KAS_ECC_COMP_HANDLER, wrong_curve) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"hashAlg" is missing.
TEST(KAS_ECC_COMP_HANDLER, missing_hashAlg) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"hashAlg" is wrong.
TEST(KAS_ECC_COMP_HANDLER, wrong_hashAlg) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ephemeralPublicServerX" is missing.
TEST(KAS_ECC_COMP_HANDLER, missing_ephemeralPublicServerX) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ephemeralPublicServerX" string is too long.
TEST(KAS_ECC_COMP_HANDLER, wrong_ephemeralPublicServerX) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ephemeralPublicServerY" is missing.
TEST(KAS_ECC_COMP_HANDLER, missing_ephemeralPublicServerY) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ephemeralPublicServerY" string is too long.
TEST(KAS_ECC_COMP_HANDLER, wrong_ephemeralPublicServerY) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ephemeralPrivateIut" is missing.
TEST(KAS_ECC_COMP_HANDLER, missing_ephemeralPrivateIut) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ephemeralPrivateIut" string is too long.
TEST(KAS_ECC_COMP_HANDLER, wrong_ephemeralPrivateIut) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ephemeralPublicIutX" is missing.
TEST(KAS_ECC_COMP_HANDLER, missing_ephemeralPublicIutX) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ephemeralPublicIutX" string is too long.
TEST(KAS_ECC_COMP_HANDLER, wrong_ephemeralPublicIutX) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ephemeralPublicIutY" is missing.
TEST(KAS_ECC_COMP_HANDLER, missing_ephemeralPublicIutY) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ephemeralPublicIutY" string is too long.
TEST(KAS_ECC_COMP_HANDLER, wrong_ephemeralPublicIutY) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"hashZIut" is missing.
TEST(KAS_ECC_COMP_HANDLER, missing_hashZIut) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"hashZIut" string is too long.
TEST(KAS_ECC_COMP_HANDLER, wrong_hashZIut) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key: crypto handler operation fails on last crypto call
TEST(KAS_ECC_COMP_HANDLER, cryptoFail1) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/kas_ecc/kas_ecc_cdh.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(KAS_ECC_COMP_HANDLER, cryptoFail2) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/kas_ecc/kas_ecc_cdh.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 299; /* fail on last iteration */
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(KAS_ECC_COMP_HANDLER, cryptoFail3) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/kas_ecc/kas_ecc_comp.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(KAS_ECC_COMP_HANDLER, cryptoFail4) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/kas_ecc/kas_ecc_comp.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 279; /* fail on last iteration */
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

// The key:"curve" is missing in last tg
TEST(KAS_ECC_CDH_HANDLER, tgFail1) {

    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_11.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"publicServerY" is missing in last tc
TEST(KAS_ECC_CDH_HANDLER, tcFail1) {

    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"curve" is missing in last tg
TEST(KAS_ECC_COMP_HANDLER, tgFail1) {

    val = json_parse_file("json/kas_ecc/kas_ecc_comp_21.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ephemeralPublicServerY" is missing in last tc
TEST(KAS_ECC_COMP_HANDLER, tcFail1) {

    val = json_parse_file("json/kas_ecc/kas_ecc_comp_22.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

/* //////////////////////
 * SSC  mode
 * /////////////////////
 */

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(KAS_ECC_SSC_HANDLER, good) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"algorithm" is missing.
TEST(KAS_ECC_SSC_HANDLER, missing_algorithm) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"testType" is missing.
TEST(KAS_ECC_SSC_HANDLER, missing_testType) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"testType" is wrong.
TEST(KAS_ECC_SSC_HANDLER, wrong_testType) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"domainParameterGenerationMode" is missing.
TEST(KAS_ECC_SSC_HANDLER, missing_curve) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"domainParameterGenerationMode" is wrong.
TEST(KAS_ECC_SSC_HANDLER, wrong_curve) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"hashFunctionZ" is missing.
TEST(KAS_ECC_SSC_HANDLER, missing_hashFunctionZ) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"hashFunctionZ" is wrong.
TEST(KAS_ECC_SSC_HANDLER, wrong_hashFunctionZ) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ephemeralPublicServerX" is missing.
TEST(KAS_ECC_SSC_HANDLER, missing_ephemeralPublicServerX) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ephemeralPublicServerX" string is too long.
TEST(KAS_ECC_SSC_HANDLER, wrong_ephemeralPublicServerX) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ephemeralPublicServerY" is missing.
TEST(KAS_ECC_SSC_HANDLER, missing_ephemeralPublicServerY) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ephemeralPublicServerY" is too long
TEST(KAS_ECC_SSC_HANDLER, wrong_ephemeralPublicServerY) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ephemeralPrivateIut" is missing.
TEST(KAS_ECC_SSC_HANDLER, missing_ephemeralPrivateIut) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ephemeralPublicIutX" is missing.
TEST(KAS_ECC_SSC_HANDLER, missing_ephemeralPublicIutX) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ephemeralPublicIutY" is missing.
TEST(KAS_ECC_SSC_HANDLER, missing_ephemeralPublicIutY) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}
