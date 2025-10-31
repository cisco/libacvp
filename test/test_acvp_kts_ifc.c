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

TEST_GROUP(KTS_IFC_API);
TEST_GROUP(KTS_IFC_CAPABILITY);
TEST_GROUP(KTS_IFC_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void kts_ifc_api_setup_helper(void) {
    setup_empty_ctx(&ctx);
        char *expo_str = calloc(7, sizeof(char));
        strncpy(expo_str, "010001", 7); // RSA_F4

        rv = acvp_cap_kts_ifc_enable(ctx, ACVP_KTS_IFC, &dummy_handler_success);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_RSA, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_RSADP, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_SHA, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_DRBG, cvalue);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kts_ifc_set_param_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FIXEDPUBEXP, expo_str);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kts_ifc_set_param_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_IUT_ID, "CAFEBABE");
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FUNCTION, ACVP_KTS_IFC_KEYPAIR_GEN);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FUNCTION, ACVP_KTS_IFC_PARTIAL_VAL);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 2048);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 3072);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 4096);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG1_BASIC);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

        rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_SCHEME, ACVP_KTS_IFC_KAS1_BASIC);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ROLE, ACVP_KTS_IFC_RESPONDER);
        rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ROLE, ACVP_KTS_IFC_INITIATOR);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA256);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_NULL_ASSOC_DATA, 1);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kts_ifc_set_scheme_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ENCODING, "concatenation");
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
        rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_L, 512);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

        if (expo_str) free(expo_str);
}

static void kts_ifc_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(KTS_IFC_API) {
    kts_ifc_api_setup_helper();
}

TEST_TEAR_DOWN(KTS_IFC_API) {
    kts_ifc_api_tear_down_helper();
}

TEST_SETUP(KTS_IFC_CAPABILITY) {}
TEST_TEAR_DOWN(KTS_IFC_CAPABILITY) {}

TEST_SETUP(KTS_IFC_HANDLER) {
    kts_ifc_api_setup_helper();
}

TEST_TEAR_DOWN(KTS_IFC_HANDLER) {
    kts_ifc_api_tear_down_helper();
}

// Test capabilites API.
TEST(KTS_IFC_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    rv = acvp_cap_kts_ifc_enable(ctx, ACVP_KTS_IFC, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_RSA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_RSADP, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kts_ifc_set_param_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FIXEDPUBEXP, expo_str);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kts_ifc_set_param_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_IUT_ID, "CAFEBABE");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FUNCTION, ACVP_KTS_IFC_KEYPAIR_GEN);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FUNCTION, ACVP_KTS_IFC_PARTIAL_VAL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 2048);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 3072);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 4096);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG1_BASIC);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_SCHEME, ACVP_KTS_IFC_KAS1_BASIC);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ROLE, ACVP_KTS_IFC_RESPONDER);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ROLE, ACVP_KTS_IFC_INITIATOR);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_NULL_ASSOC_DATA, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kts_ifc_set_scheme_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ENCODING, "concatenation");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_L, 512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    if (expo_str) free(expo_str);
    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(KTS_IFC_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kts_ifc/kts_ifc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kts_ifc_kat_handler(ctx, obj);
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
TEST(KTS_IFC_API, null_ctx) {
    val = json_parse_file("json/kts_ifc/kts_ifc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kts_ifc_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(KTS_IFC_API, null_json_obj) {
    rv  = acvp_kts_ifc_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

/* //////////////////////
 * KTS-IFC
 * /////////////////////
 */

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(KTS_IFC_HANDLER, good) {
    val = json_parse_file("json/kts_ifc/kts_ifc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"algorithm" is missing.
TEST(KTS_IFC_HANDLER, missing_algorithm) {
    val = json_parse_file("json/kts_ifc/kts_ifc_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"testType" is missing.
TEST(KTS_IFC_HANDLER, missing_testType) {
    val = json_parse_file("json/kts_ifc/kts_ifc_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"testType" is wrong.
TEST(KTS_IFC_HANDLER, wrong_testType) {
    val = json_parse_file("json/kts_ifc/kts_ifc_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"hashAlg" is missing.
TEST(KTS_IFC_HANDLER, missing_hashAlg) {
    val = json_parse_file("json/kts_ifc/kts_ifc_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"hashAlg" is wrong.
TEST(KTS_IFC_HANDLER, wrong_hashAlg) {
    val = json_parse_file("json/kts_ifc/kts_ifc_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"adp" is missing.
TEST(KTS_IFC_HANDLER, missing_adp) {
    val = json_parse_file("json/kts_ifc/kts_ifc_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"encoding" is missing.
TEST(KTS_IFC_HANDLER, missing_encoding) {
    val = json_parse_file("json/kts_ifc/kts_ifc_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"l" is missing.
TEST(KTS_IFC_HANDLER, missing_l) {
    val = json_parse_file("json/kts_ifc/kts_ifc_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

#if 0
/* library no longer needs to check for fixedpubexp; since we are just using serverE or iutE from test cases */
TEST(KTS_IFC_HANDLER, missing_fpe) {
    val = json_parse_file("json/kts_ifc/kts_ifc_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}
#endif
// The key:"modulo" is missing.
TEST(KTS_IFC_HANDLER, missing_modulo) {
    val = json_parse_file("json/kts_ifc/kts_ifc_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"keyGenerationMethod" is missing.
TEST(KTS_IFC_HANDLER, missing_kgm) {
    val = json_parse_file("json/kts_ifc/kts_ifc_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"kasRole" is missing.
TEST(KTS_IFC_HANDLER, missing_kr) {
    val = json_parse_file("json/kts_ifc/kts_ifc_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"scheme" is missing.
TEST(KTS_IFC_HANDLER, missing_scheme) {
    val = json_parse_file("json/kts_ifc/kts_ifc_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iutId" is missing.
TEST(KTS_IFC_HANDLER, missing_ii) {
    val = json_parse_file("json/kts_ifc/kts_ifc_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"serverId" is missing.
TEST(KTS_IFC_HANDLER, missing_si) {
    val = json_parse_file("json/kts_ifc/kts_ifc_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"keyConfirmationDirection" is missing.
TEST(KTS_IFC_HANDLER, missing_kcd) {
    val = json_parse_file("json/kts_ifc/kts_ifc_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"keyConfirmationRole" is missing.
TEST(KTS_IFC_HANDLER, missing_kcr) {
    val = json_parse_file("json/kts_ifc/kts_ifc_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iutN" is missing.
TEST(KTS_IFC_HANDLER, missing_iutn) {
    val = json_parse_file("json/kts_ifc/kts_ifc_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iutE" is missing.
TEST(KTS_IFC_HANDLER, missing_iute) {
    val = json_parse_file("json/kts_ifc/kts_ifc_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iutP" is missing.
TEST(KTS_IFC_HANDLER, missing_iutp) {
    val = json_parse_file("json/kts_ifc/kts_ifc_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iutQ" is missing.
TEST(KTS_IFC_HANDLER, missing_iutq) {
    val = json_parse_file("json/kts_ifc/kts_ifc_21.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iutD" is missing.
TEST(KTS_IFC_HANDLER, missing_iutd) {
    val = json_parse_file("json/kts_ifc/kts_ifc_22.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"serverC" is missing.
TEST(KTS_IFC_HANDLER, missing_serverc) {
    val = json_parse_file("json/kts_ifc/kts_ifc_23.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"serverN" is missing.
TEST(KTS_IFC_HANDLER, missing_servern) {
    val = json_parse_file("json/kts_ifc/kts_ifc_24.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"serverE" is missing.
TEST(KTS_IFC_HANDLER, missing_servere) {
    val = json_parse_file("json/kts_ifc/kts_ifc_25.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}
