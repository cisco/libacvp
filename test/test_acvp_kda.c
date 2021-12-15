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

    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_HKDF, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_HKDF, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LITERAL, "0123456789ABCDEF");
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_CONTEXT, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LABEL, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_HKDF_HMAC_ALG, ACVP_HMAC_ALG_SHA224, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_HKDF_HMAC_ALG, ACVP_HMAC_ALG_SHA256, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_HKDF_HMAC_ALG, ACVP_HMAC_ALG_SHA384, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_HKDF_HMAC_ALG, ACVP_HMAC_ALG_SHA512, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_L, 2048, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_HKDF, ACVP_KDA_Z, 224, 1024, 8);
    cr_assert(rv == ACVP_SUCCESS);

    // kdf onestep
    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_ONESTEP, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_ONESTEP, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LITERAL, "0123456789ABCDEF");
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_CONTEXT, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LABEL, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA224, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA256, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA384, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA512, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_224, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_256, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_384, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_512, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_L, 2048, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_Z, 224, 1024, 8);
    cr_assert(rv == ACVP_SUCCESS);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(KDA_CAPABILITY, good) {
    setup_empty_ctx(&ctx);


    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_HKDF, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_HKDF, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LITERAL, "0123456789ABCDEF");
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_CONTEXT, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LABEL, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_HKDF_HMAC_ALG, ACVP_HMAC_ALG_SHA224, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_HKDF_HMAC_ALG, ACVP_HMAC_ALG_SHA256, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_HKDF_HMAC_ALG, ACVP_HMAC_ALG_SHA384, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_HKDF_HMAC_ALG, ACVP_HMAC_ALG_SHA512, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_L, 2048, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_HKDF, ACVP_KDA_Z, 224, 1024, 8);
    cr_assert(rv == ACVP_SUCCESS);

    // kdf onestep
    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_ONESTEP, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_ONESTEP, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LITERAL, "0123456789ABCDEF");
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_CONTEXT, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_LABEL, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA224, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA256, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA384, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA512, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_224, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_256, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_384, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_512, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_L, 2048, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_Z, 224, 1024, 8);
    cr_assert(rv == ACVP_SUCCESS);
    
    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(KDA_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kda/kda_hkdf_1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    rv = ACVP_SUCCESS;
    json_value_free(val);

    val = json_parse_file("json/kda/kda_onestep_1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv = acvp_kda_onestep_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(KDA_API, null_ctx) {
    val = json_parse_file("json/kda/kda_hkdf_1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kda_hkdf_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    rv = ACVP_SUCCESS;
    json_value_free(val);

    val = json_parse_file("json/kda/kda_onestep_1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kda_onestep_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(KDA_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_kda_hkdf_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    rv = ACVP_SUCCESS;
    rv  = acvp_kda_onestep_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);

}

/*h 
 * This is a good JSON.
 * Expecting success.
 */
Test(KDA_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
    rv = ACVP_UNSUPPORTED_OP;

    val = json_parse_file("json/kda/kda_onestep_1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_onestep_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}

/*
 * HKDF: The key:"algorithm" is missing.
 */
Test(KDA_HKDF_HANDLER, missing_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_2.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: The key:"mode" is missing.
 */
Test(KDA_HKDF_HANDLER, missing_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_3.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: The key:"mode" is wrong.
 */
Test(KDA_HKDF_HANDLER, bad_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_4.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: The key:"testType" is missing.
 */
Test(KDA_HKDF_HANDLER, missing_type, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_5.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: The key:"testType" is wrong.
 */
Test(KDA_HKDF_HANDLER, bad_type, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_6.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: The group "kdfConfiguration" is missing.
 */
Test(KDA_HKDF_HANDLER, missing_kdfConfiguration, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_7.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/* NOTE: at time of creation, many of these fields
exist in both the test case objects and in the 
kdfConfiguration object. Libacvp parses from the 
kdfConfiguration object as NIST has indicated
they may remove the redundancy from the 
test case stuctures in the future */

/*
 * HKDF: The key:"l" is missing.
 */
Test(KDA_HKDF_HANDLER, missing_l, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_8.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    //no cap registered, so suppose unsupported op.
    rv = ACVP_UNSUPPORTED_OP;
    json_value_free(val);
}

/** temporarily disabling due to NIST issue workaround
 *
 * HKDF: The key:"saltLen" is wrong.
 *
Test(KDA_HKDF_HANDLER, bad_saltlen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_9.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}
*/

/*
 * HKDF: The key:"saltMethod" is missing.
 */
Test(KDA_HKDF_HANDLER, missing_saltmethod, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_10.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: The key:"saltMethod" is wrong.
 */
Test(KDA_HKDF_HANDLER, bad_saltmethod, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_11.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: The key:"fixedInfoEncoding" is missing
 */
Test(KDA_HKDF_HANDLER, missing_fixedinfoencoding, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_12.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: The key:"fixedInfoEncoding" is wrong
 */
Test(KDA_HKDF_HANDLER, bad_fixedinfoencoding, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_13.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: The key:"hmacAlg" is missing
 */
Test(KDA_HKDF_HANDLER, missing_hmacalg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_14.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: The key:"hmacAlg" is wrong
 */
Test(KDA_HKDF_HANDLER, bad_hmacalg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_15.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: The key:"fixedInfoPattern" is missing
 */
Test(KDA_HKDF_HANDLER, missing_fixedinfopattern, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_16.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

//Test various malformed versions of fixed info pattern
/*
 * HKDF: Empty fixedInfoPattern
 */
Test(KDA_HKDF_HANDLER, empty_fixedinfopattern, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_17.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: Invalid hex string in literal pattern candidate
 */
Test(KDA_HKDF_HANDLER, bad_hex_fixedinfopattern, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_18.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: missing vPartyInfo
 */
Test(KDA_HKDF_HANDLER, missing_vpartyinfo_fixedinfopattern, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_19.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: missing uPartyInfo
 */
Test(KDA_HKDF_HANDLER, missing_upartyinfo_fixedinfopattern, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_20.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: missing salt
 */
Test(KDA_HKDF_HANDLER, missing_salt, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_21.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: missing Z
 */
Test(KDA_HKDF_HANDLER, missing_z, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_22.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: missing fixedInfoPartyU
 */
Test(KDA_HKDF_HANDLER, missing_fixedinfopartyu, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_23.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: fixedInfoPartyU exists, but partyId is missing
 */
Test(KDA_HKDF_HANDLER, missing_upartyid, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_24.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: missing fixedInfoPartyV
 */
Test(KDA_HKDF_HANDLER, missing_fixedinfopartyv, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_25.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: fixedInfoPartyV exists, but partyId is missing
 */
Test(KDA_HKDF_HANDLER, missing_vpartyid, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_26.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: algorithmId is missing
 */
Test(KDA_HKDF_HANDLER, missing_algorithmid, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_27.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: label is missing
 */
Test(KDA_HKDF_HANDLER, missing_label, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_28.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * HKDF: context is missing
 */
Test(KDA_HKDF_HANDLER, missing_context, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_hkdf_29.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_hkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

//Since they share much of the same code, test the common code using
//HKDF and test the diffs using onestep
/*
 * OneStep: The key:"algorithm" is missing.
 */
Test(KDA_ONESTEP_HANDLER, missing_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_onestep_2.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_onestep_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The value for key:"mode" is missing
 */
Test(KDA_ONESTEP_HANDLER, missing_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_onestep_3.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_onestep_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The value for key:"mode" is wrong
 */
Test(KDA_ONESTEP_HANDLER, wrong_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_onestep_4.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_onestep_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The value for key:"auxFunction" is missing
 */
Test(KDA_ONESTEP_HANDLER, missing_auxfunction, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_onestep_5.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_onestep_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The value for key:"auxFunction" is wrong
 */
Test(KDA_ONESTEP_HANDLER, bad_auxfunction, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kda/kda_onestep_6.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kda_onestep_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}