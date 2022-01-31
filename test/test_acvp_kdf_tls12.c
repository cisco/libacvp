/** @file */
/*
 * Copyright (c) 2021, Cisco Systems, Inc.
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

    rv = acvp_cap_kdf_tls12_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
}

static void setup_fail(void) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf_tls12_enable(ctx, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test kdf_tls12 capabilites API.
 */
Test(KDF_TLS12_CAPABILITY, good) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf_tls12_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(KDF_TLS12_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kdf_tls12/tls12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test kdf_tls12 capabilites API.
 */
Test(KDF_TLS12_API, null_ctx) {
    val = json_parse_file("json/kdf_tls12/tls12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kdf_tls12_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The obj is null, expecting failure.
 */
Test(KDF_TLS12_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_kdf_tls12_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/*
 * Test the kdf_tls12 KAT handler.
 * This is a good JSON.
 * Expecting success.
 */
Test(KDF_TLS12_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The value for key:"algorihm" is wrong.
 */
Test(KDF_TLS12_HANDLER, wrong_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The value for key:"mode" is wrong.
 */
Test(KDF_TLS12_HANDLER, wrong_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:"mode" is missing.
 */
Test(KDF_TLS12_HANDLER, missing_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The value for key:"hashAlg" is wrong.
 */
Test(KDF_TLS12_HANDLER, wrong_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_NO_CAP);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:"hashAlg" is missing.
 */
Test(KDF_TLS12_HANDLER, missing_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The value for key:"preMasterSecretLength" is wrong.
 */
Test(KDF_TLS12_HANDLER, wrong_preMasterSecretLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:"preMasterSecretLength" is missing.
 */
Test(KDF_TLS12_HANDLER, missing_preMasterSecretLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:"keyBlockLength" is missing.
 */
Test(KDF_TLS12_HANDLER, missing_keyBlockLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The value for key:"preMasterSecret" is wrong.
 */
Test(KDF_TLS12_HANDLER, wrong_preMasterSecret, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:"preMasterSecret" is missing.
 */
Test(KDF_TLS12_HANDLER, missing_preMasterSecret, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:sessionHash" is missing.
 */
Test(KDF_TLS12_HANDLER, missing_sessionHash, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:clientRandom" is missing.
 */
Test(KDF_TLS12_HANDLER, missing_clientRandom, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:serverRandom" is missing.
 */
Test(KDF_TLS12_HANDLER, missing_serverRandom, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * Test the kdf_tls12 KAT handler.
 * The key:"tgId" is missing.
 */
Test(KDF_TLS12_HANDLER, missing_tgId, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls12/tls12_14.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(KDF_TLS12_HANDLER, cryptoFail1, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kdf_tls12/tls12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(KDF_TLS12_HANDLER, cryptoFail2, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kdf_tls12/tls12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on tenth iteration */
    rv  = acvp_kdf_tls12_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}
