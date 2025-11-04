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

TEST_GROUP(Kdf135SnmpApi);
TEST_GROUP(Kdf135SnmpFail);
TEST_GROUP(Kdf135SnmpFunc);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

TEST_SETUP(Kdf135SnmpApi) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135SnmpApi) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135SnmpFail) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135SnmpFail) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135SnmpFunc) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135SnmpFunc) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST(Kdf135SnmpApi, null_ctx) {
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with unregistered ctx */
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);

    /* Enable capabilites */
    rv = acvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SNMP, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 64);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_engid(ctx, ACVP_KDF135_SNMP, "AB37BDE5657AB");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    /* Test with NULL ctx */
    rv  = acvp_kdf135_snmp_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    /* Test with NULL JSON object */
    rv  = acvp_kdf135_snmp_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

// Test kdf135 SNMP handler functionally
TEST(Kdf135SnmpFunc, null_ctx) {

    /* Enable capabilites */
    rv = acvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SNMP, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 64);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_engid(ctx, ACVP_KDF135_SNMP, "AB37BDE5657AB");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    /* This is a proper JSON, positive test */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);

    /* This is a corrupt JSON, missing engineId */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    

    /* This is a corrupt JSON, missing passwordLength */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    
    /* This is a corrupt JSON, password does not match passwordLength */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);
    
    /* This is a corrupt JSON, password not in test case */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    
    /* This is a corrupt JSON, no tests */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    
    /* This is a corrupt JSON, no testGroups */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    
    /* This is a corrupt JSON, no tcId */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    
    /* This is a corrupt JSON, corrupt algorithm */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);

    /* This is a corrupt JSON, no tgId */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp_10.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
}

// The key: crypto handler operation fails on first call
TEST(Kdf135SnmpFail, cryptoFail1) {
    force_handler_failure = 1;

    /* Enable capabilites */
    rv = acvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SNMP, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 64);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_engid(ctx, ACVP_KDF135_SNMP, "AB37BDE5657AB");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    val = json_parse_file("json/kdf135_snmp/kdf135_snmp1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(Kdf135SnmpFail, cryptoFail2) {
    force_handler_failure = 1;

    /* Enable capabilites */
    rv = acvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SNMP, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 64);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_engid(ctx, ACVP_KDF135_SNMP, "AB37BDE5657AB");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    val = json_parse_file("json/kdf135_snmp/kdf135_snmp1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on tenth iteration */
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    force_handler_failure = 0;
}

// The key:"engineId" is missing in secong tg
TEST(Kdf135SnmpFail, tcidFail) {

    /* Enable capabilites */
    rv = acvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SNMP, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 64);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_engid(ctx, ACVP_KDF135_SNMP, "AB37BDE5657AB");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    val = json_parse_file("json/kdf135_snmp/kdf135_snmp11.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
}

// The key:"password" is missing in eighth tc
TEST(Kdf135SnmpFail, tcFail) {

    /* Enable capabilites */
    rv = acvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SNMP, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 64);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_engid(ctx, ACVP_KDF135_SNMP, "AB37BDE5657AB");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    val = json_parse_file("json/kdf135_snmp/kdf135_snmp12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_snmp_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
}
