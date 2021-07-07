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

    rv = acvp_cap_kdf_tls13_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS13, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_HMAC_ALG_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_HMAC_ALG_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_DHE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK_DHE);
    cr_assert(rv == ACVP_SUCCESS);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(KDF_TLS13_CAPABILITY, good) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf_tls13_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS13, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_HMAC_ALG_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_HMAC_ALG_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_DHE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK_DHE);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(KDF_TLS13_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kdf_tls13/tls13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(KDF_TLS13_API, null_ctx) {
    val = json_parse_file("json/kdf_tls13/tls13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kdf_tls13_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(KDF_TLS13_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_kdf_tls13_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(KDF_TLS13_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}
#
/*
 * The value for key:"algorithm" is wrong.
 */
Test(KDF_TLS13_HANDLER, bad_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"algorithm" is missing.
 */
Test(KDF_TLS13_HANDLER, no_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The key:"mode" is wrong.
 */
Test(KDF_TLS13_HANDLER, bad_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"mode" is missing.
 */
Test(KDF_TLS13_HANDLER, no_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The value for key:"hmacAlg" is wrong.
 */
Test(KDF_TLS13_HANDLER, bad_hmacalg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The value for key:"hmacAlg" is missing.
 */
Test(KDF_TLS13_HANDLER, no_hmacalg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"runningMode" is wrong.
 */
Test(KDF_TLS13_HANDLER, bad_runningmode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The value for key:"runningMode" is missing.
 */
Test(KDF_TLS13_HANDLER, no_runningmode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"testType" is wrong.
 */
Test(KDF_TLS13_HANDLER, bad_testtype, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}


/*
 * The key:"testType" is missing.
 */
Test(KDF_TLS13_HANDLER, no_testtype, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"tcId" is missing.
 */
Test(KDF_TLS13_HANDLER, no_tcid, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"helloClientRandom" is missing.
 */
Test(KDF_TLS13_HANDLER, no_hcr, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"helloServerRandom" is missing.
 */
Test(KDF_TLS13_HANDLER, no_hsr, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"finishedClientRandom" is missing.
 */
Test(KDF_TLS13_HANDLER, no_fcr, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"finishedServerRandom" is missing.
 */
Test(KDF_TLS13_HANDLER, no_fsr, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"psk" is missing.
 */
Test(KDF_TLS13_HANDLER, no_psk, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"dhe" is missing.
 */
Test(KDF_TLS13_HANDLER, no_dhe, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf_tls13/tls13_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf_tls13_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}