/** @file */
/*
 * Copyright (c) 2020, Cisco Systems, Inc.
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

    rv = acvp_cap_pbkdf_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_PBKDF, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA3_224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA3_256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA3_384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA3_512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_ITERATION_COUNT, 10, 1000, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_KEY_LEN, 112, 4096, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_PASSWORD_LEN, 8, 128, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_SALT_LEN, 128, 4096, 8);
    cr_assert(rv == ACVP_SUCCESS);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(PBKDF_CAPABILITY, good) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_pbkdf_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_PBKDF, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA3_224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA3_256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA3_384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_PBKDF_HMAC_ALG_SHA3_512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_ITERATION_COUNT, 10, 1000, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_KEY_LEN, 112, 4096, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_PASSWORD_LEN, 8, 128, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_SALT_LEN, 128, 4096, 8);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(PBKDF_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/pbkdf/pbkdf.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(PBKDF_API, null_ctx) {
    val = json_parse_file("json/pbkdf/pbkdf.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_pbkdf_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(PBKDF_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_pbkdf_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(PBKDF_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}

/*
 * The value for key:"algorithm" is wrong.
 */
Test(PBKDF_HANDLER, wrong_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"algorithm" is missing.
 */
Test(PBKDF_HANDLER, no_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The key:"hmacAlg" is missing.
 */
Test(PBKDF_HANDLER, no_hmacalg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"hmacAlg" is wrong.
 */
Test(PBKDF_HANDLER, bad_hmacalg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"testType" is wrong.
 */
Test(PBKDF_HANDLER, bad_testtype, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"testType" is missing.
 */
Test(PBKDF_HANDLER, no_testtype, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"tcId" is missing.
 */
Test(PBKDF_HANDLER, no_tcid, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"keyLen" is too high.
 */
Test(PBKDF_HANDLER, bad_keylen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"keyLen" is missing/too low.
 */
Test(PBKDF_HANDLER, no_keylen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"salt" is too long.
 */
Test(PBKDF_HANDLER, bad_salt, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"salt" is missing.
 */
Test(PBKDF_HANDLER, no_salt, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"password" is too long.
 */
Test(PBKDF_HANDLER, bad_password, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"password" is too short.
 */
Test(PBKDF_HANDLER, bad_password_2, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"password" is missing.
 */
Test(PBKDF_HANDLER, no_password, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"iterationCount" is too long.
 */
Test(PBKDF_HANDLER, bad_iterationCount, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"iterationCount" is too short.
 */
Test(PBKDF_HANDLER, bad_iterationCount_2, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"iterationCount" is missing.
 */
Test(PBKDF_HANDLER, no_iterationCount, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"salt" is of the wrong type.
 */
Test(PBKDF_HANDLER, bad_salt_2, .init = setup, .fini = teardown) {
    val = json_parse_file("json/pbkdf/pbkdf_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_pbkdf_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}
