/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include "ut_common.h"
#include "acvp/acvp_lcl.h"

ACVP_CTX *ctx;
static char cvalue[] = "same";
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

static void setup(ACVP_CTX *ctx) {
    ACVP_RESULT rv;

    /* Enable capabilites */
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA1, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_MACLEN, 32, 160, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA1, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_224, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_MACLEN, 32, 224, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_224, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_256, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_MACLEN, 32, 256, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_256, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_384, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_MACLEN, 32, 384, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_384, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_MACLEN, 32, 512, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_512, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
}

static void setup_fail(void) {
    ACVP_RESULT rv;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA1, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_MACLEN, 32, 160, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA1, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_224, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_MACLEN, 32, 224, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_224, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_256, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_MACLEN, 32, 256, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_256, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_384, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_MACLEN, 32, 384, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_384, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_MACLEN, 32, 512, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_512, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * Test HMAC handler API inputs
 */
Test(HmacApi, null_ctx) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    val = json_parse_file("json/hmac/hmac1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with unregistered ctx */
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);

    setup(ctx);

    /* Test with NULL ctx */
    rv  = acvp_hmac_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);

    /* Test with NULL JSON object */
    rv  = acvp_hmac_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);

    teardown_ctx(&ctx);
    json_value_free(val);
}

/*
 * Test HMAC handler functionally
 */
Test(HmacFunc, null_ctx) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* This is a proper JSON, positive test */
    val = json_parse_file("json/hmac/hmac1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    setup(ctx);

    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);

    /* Test failing case, failed to include keyLen */
    val = json_parse_file("json/hmac/hmac2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include msgLen */
    val = json_parse_file("json/hmac/hmac3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include macLen */
    val = json_parse_file("json/hmac/hmac4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include key */
    val = json_parse_file("json/hmac/hmac5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include msg */
    val = json_parse_file("json/hmac/hmac6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include key */
    val = json_parse_file("json/hmac/hmac7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

    /* Test failing case, msg does not match msgLen */
    val = json_parse_file("json/hmac/hmac8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);

    /* Test failing case, key does not match keyLen */
    val = json_parse_file("json/hmac/hmac9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tests */
    val = json_parse_file("json/hmac/hmac10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include testGroups */
    val = json_parse_file("json/hmac/hmac11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/hmac/hmac12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include test array */
    val = json_parse_file("json/hmac/hmac13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* Positive test case for coverage */
    val = json_parse_file("json/hmac/hmac14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);

    /* missing tgId */
    val = json_parse_file("json/hmac/hmac15.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);

    /* missing keyLen in second tg */
    val = json_parse_file("json/hmac/hmac16.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* missing key in last tc */
    val = json_parse_file("json/hmac/hmac17.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);

    teardown_ctx(&ctx);
    json_value_free(val);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(HMAC_HANDLER, cryptoFail1, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;

    val = json_parse_file("json/hmac/hmac1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration of AFT */

    rv = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(HMAC_HANDLER, cryptoFail2, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;

    val = json_parse_file("json/hmac/hmac1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 5;  /* fail on 6th iteration of AFT */

    rv = acvp_hmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}
