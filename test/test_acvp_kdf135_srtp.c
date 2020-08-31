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
    int i = 0;

    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf135_srtp_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SRTP, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_SUPPORT_ZERO_KDR, 0);
    cr_assert(rv == ACVP_SUCCESS);
    for (i = 0; i < 24; i++) {
       rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_KDF_EXPONENT, i + 1);
       cr_assert(rv == ACVP_SUCCESS);
    }
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
}

static void setup_fail(void) {
    int i = 0;

    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf135_srtp_enable(ctx, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SRTP, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_SUPPORT_ZERO_KDR, 0);
    cr_assert(rv == ACVP_SUCCESS);
    for (i = 0; i < 24; i++) {
       rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_KDF_EXPONENT, i + 1);
       cr_assert(rv == ACVP_SUCCESS);
    }
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(KDF135_SRTP_CAPABILITY, good) {
    int i = 0;

    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf135_srtp_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SRTP, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_SUPPORT_ZERO_KDR, 0);
    cr_assert(rv == ACVP_SUCCESS);
    for (i = 0; i < 24; i++) {
       rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_KDF_EXPONENT, i + 1);
       cr_assert(rv == ACVP_SUCCESS);
    }
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(KDF135_SRTP_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kdf135_srtp/kdf135_srtp.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kdf135_srtp_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(KDF135_SRTP_API, null_ctx) {
    val = json_parse_file("json/kdf135_srtp/kdf135_srtp.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kdf135_srtp_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(KDF135_SRTP_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_kdf135_srtp_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(KDF135_SRTP_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_srtp/kdf135_srtp.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_srtp_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}

/*
 * The value for key:"algorithm" is wrong.
 */
Test(KDF135_SRTP_HANDLER, wrong_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_srtp/kdf135_srtp1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_srtp_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"aesKeyLength" is missing.
 */
Test(KDF135_SRTP_HANDLER, missing_aesKeyLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_srtp/kdf135_srtp2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_srtp_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"kdr" is missing.
 */
Test(KDF135_SRTP_HANDLER, missing_kdr, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_srtp/kdf135_srtp3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_srtp_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"masterKey" is missing.
 */
Test(KDF135_SRTP_HANDLER, missing_masterKey, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_srtp/kdf135_srtp4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_srtp_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"index" is missing.
 */
Test(KDF135_SRTP_HANDLER, missing_index, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_srtp/kdf135_srtp6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_srtp_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"srtcpIndex" is missing.
 */
Test(KDF135_SRTP_HANDLER, missing_srtcpIndex, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_srtp/kdf135_srtp7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_srtp_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"tgId" is missing.
 */
Test(KDF135_SRTP_HANDLER, missing_tgId, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_srtp/kdf135_srtp8.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_srtp_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on first call
 */
Test(Kdf135SrtpFail, cryptoFail1, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kdf135_srtp/kdf135_srtp.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kdf135_srtp_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(Kdf135SrtpFail, cryptoFail2, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kdf135_srtp/kdf135_srtp.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on tenth iteration */
    rv  = acvp_kdf135_srtp_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key:"aesKeyLength" is missing in last tg
 */
Test(Kdf135SrtpFail, tcidFail, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kdf135_srtp/kdf135_srtp9.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_srtp_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"index" is missing in sixth tc
 */
Test(Kdf135SrtpFail, tcFail, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kdf135_srtp/kdf135_srtp10.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_srtp_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

