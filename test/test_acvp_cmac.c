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

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void setup(void) {
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_AES, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_TDES, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_TDES, ACVP_PREREQ_TDES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    
}

static void setup_fail(void) {
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_AES, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_TDES, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_TDES, ACVP_PREREQ_TDES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(CMAC_AES_CAPABILITY, good) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_AES, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_AES, ACVP_CMAC_MSGLEN, 0, 65536, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_MACLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_AES, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_GEN, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_VER, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(CMAC_TDES_CAPABILITY, good) {
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_TDES, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_TDES, ACVP_PREREQ_TDES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_TDES, ACVP_CMAC_MSGLEN, 0, 65536, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_MACLEN, 64);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_DIRECTION_GEN, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_DIRECTION_VER, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_KEYING_OPTION, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_TDES, ACVP_PREREQ_TDES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    
    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(CMAC_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/cmac/cmac_aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(CMAC_API, null_ctx) {
    val = json_parse_file("json/cmac/cmac_aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_cmac_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}


/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(CMAC_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_cmac_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(CMAC_API, good_aes, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}


/*
 * This is a good JSON.
 * Expecting success.
 */
Test(CMAC_API, good_tdes, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_tdes.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}


/*
 * The value for key:"algorithm" is wrong.
 */
Test(CMAC_API, wrong_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_aes_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);
}


/*
 * The value for key:"direction" is missing.
 */
Test(CMAC_API, missing_direction, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_aes_2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}


/*
 * The value for key:"direction" is wrong.
 */
Test(CMAC_API, wrong_direction, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_aes_3.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);
}


/*
 * The key:"keyLen" is missing.
 */
Test(CMAC_API, missing_keyLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_aes_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}



/*
 * The key:"msgLen" is missing with non-empty msg.
 */
Test(CMAC_API, missing_msgLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_aes_5.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"macLen" is missing.
 */
Test(CMAC_API, missing_macLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_aes_6.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"key" is missing.
 */
Test(CMAC_API, missing_key_aes, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_aes_7.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"msg" is missing with nonzero msglen
 */
Test(CMAC_API, missing_msg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_aes_8.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"mac" is missing.
 */
Test(CMAC_API, missing_mac, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_aes_9.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The length of "key" is wrong.
 */
Test(CMAC_API, key_wrong_length, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_aes_10.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"keyingOption" is missing.
 */
Test(CMAC_API, missing_keyingOption_tdes, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_tdes_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}



/*
 * The key:"keyingOption" is wrong.
 */
Test(CMAC_API, wrong_keyingOption_tdes, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_tdes_2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"key1" is missing.
 */
Test(CMAC_API, missing_key1_tdes, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_tdes_3.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"key2" is missing.
 */
Test(CMAC_API, missing_key2_tdes, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_tdes_4.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"key3" is missing.
 */
Test(CMAC_API, missing_key3_tdes, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_tdes_5.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}



/*
 * The value for key:"msg" is too long
 */
Test(CMAC_API, msg_too_long, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_tdes_6.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The length of "key1" is wrong
 */
Test(CMAC_API, key1_wrong_length, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_tdes_7.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The length of "key2" is wrong
 */
Test(CMAC_API, key2_wrong_length, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_tdes_8.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The length of "key3" is wrong
 */
Test(CMAC_API, key3_wrong_length, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_tdes_9.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The length of "tgId" is missing
 */
Test(CMAC_API, tgid_missing, .init = setup, .fini = teardown) {
    val = json_parse_file("json/cmac/cmac_tdes_10.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(CMAC_API, cryptoFail1, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/cmac/cmac_aes.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(CMAC_API, cryptoFail2, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/cmac/cmac_aes.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 12; /* fail on last iteration */
    rv  = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(CMAC_API, cryptoFail3, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/cmac/cmac_tdes.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(CMAC_API, cryptoFail4, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/cmac/cmac_tdes.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 11; /* fail on last iteration */
    rv  = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key:"keyLen" is missing in last tg
 */
Test(CMAC_API, tgFail1, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/cmac/cmac_aes_11.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"mac" is missing in last tc
 */
Test(CMAC_API, tcFail1, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/cmac/cmac_aes_12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"keyingOption" is missing in last tg
 */
Test(CMAC_API, tgFail2, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/cmac/cmac_tdes_11.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"mac" is missing in last tc
 */
Test(CMAC_API, tcFail2, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/cmac/cmac_tdes_12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_cmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

