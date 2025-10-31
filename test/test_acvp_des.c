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

TEST_GROUP(DES_API);
TEST_GROUP(DES_CAPABILITY);
TEST_GROUP(DES_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;

/* Setup/Teardown helper functions */
static void des_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(DES_API) {
    setup_empty_ctx(&ctx);

    // Enable 3DES-CBC
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CBC, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable TDES-CTR
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CTR, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_CTR_INCR, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

TEST_TEAR_DOWN(DES_API) {
    des_api_tear_down_helper();
}

TEST_SETUP(DES_CAPABILITY) {}
TEST_TEAR_DOWN(DES_CAPABILITY) {}

TEST_SETUP(DES_HANDLER) {
    setup_empty_ctx(&ctx);

    // Enable 3DES-CBC
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CBC, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable TDES-CTR
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CTR, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_CTR_INCR, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

TEST_TEAR_DOWN(DES_HANDLER) {
    des_api_tear_down_helper();
}

/* Test cases */
TEST(DES_CAPABILITY, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    // Enable 3DES-ECB
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_ECB, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable 3DES-CBC
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CBC, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable 3DES-OFB
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_OFB, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable 3DES-CFB64
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB64, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable 3DES-CFB8
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB8, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable 3DES-CFB1
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable TDES-CTR
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CTR, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_CTR_INCR, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

TEST(DES_API, empty_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    json_value_free(val);
    val = NULL;

end:
    if (ctx) teardown_ctx(&ctx);
}

TEST(DES_API, null_ctx) {
    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_des_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_API, null_json_obj) {
    rv  = acvp_des_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

TEST(DES_HANDLER, good) {
    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, wrong_algorithm) {
    val = json_parse_file("json/des/des_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, missing_direction) {
    val = json_parse_file("json/des/des_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, wrong_direction) {
    val = json_parse_file("json/des/des_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, missing_testType) {
    val = json_parse_file("json/des/des_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, wrong_testType) {
    val = json_parse_file("json/des/des_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, missing_key1) {
    val = json_parse_file("json/des/des_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, wrong_key1) {
    val = json_parse_file("json/des/des_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, missing_key2) {
    val = json_parse_file("json/des/des_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, wrong_key2) {
    val = json_parse_file("json/des/des_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, missing_key3) {
    val = json_parse_file("json/des/des_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, wrong_key3) {
    val = json_parse_file("json/des/des_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, missing_pt) {
    val = json_parse_file("json/des/des_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, wrong_pt) {
    val = json_parse_file("json/des/des_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, missing_ct) {
    val = json_parse_file("json/des/des_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, wrong_ct) {
    val = json_parse_file("json/des/des_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, missing_iv) {
    val = json_parse_file("json/des/des_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, wrong_iv) {
    val = json_parse_file("json/des/des_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, missing_tgid) {
    val = json_parse_file("json/des/des_18.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, bad_inc_ctr) {
    val = json_parse_file("json/des/des_19.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, bad_ovrflw_ctr) {
    val = json_parse_file("json/des/des_20.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, tgLast) {
    val = json_parse_file("json/des/des_21.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, tcLast) {
    val = json_parse_file("json/des/des_22.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
    json_value_free(val);
    val = NULL;
}

TEST(DES_HANDLER, cryptoFail1) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration of AFT */

    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

TEST(DES_HANDLER, cryptoFail2) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 5;  /* fail on 6th iteration of AFT */

    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

TEST(DES_HANDLER, cryptoFail3) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 490; /* fail on first iteration of MCT */

    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

TEST(DES_HANDLER, cryptoFail4) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 495; /* fail on sixth iteration of MCT */

    rv = acvp_des_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}
