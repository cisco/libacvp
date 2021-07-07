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

    /*
     * Register Safe Prime Key Generation testing
     */
    rv = acvp_cap_safe_primes_enable(ctx, ACVP_SAFE_PRIMES_KEYGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYGEN,
                                  ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYGEN,
                                  ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE2048);

    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE3072);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE4096);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE6144);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE8192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP2048);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP3072);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP4096);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP6144);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP8192);
    cr_assert(rv == ACVP_SUCCESS);

    /*
     * Register Safe Prime Key Verify testing
     */
    rv = acvp_cap_safe_primes_enable(ctx, ACVP_SAFE_PRIMES_KEYVER, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYVER,
                                  ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYVER,
                                  ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE2048);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE3072);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE4096);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE6144);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE8192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP2048);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP3072);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP4096);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP6144);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_MODP8192);
    cr_assert(rv == ACVP_SUCCESS);


}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 * Component mode.
 */
Test(SAFE_PRIMES_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/safe_primes/safe_primes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_safe_primes_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}


Test(SAFE_PRIMES_API, null_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/safe_primes/safe_primes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_safe_primes_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(SAFE_PRIMES_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_kas_ifc_ssc_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(SAFE_PRIMES_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/safe_primes/safe_primes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}

Test(SAFE_PRIMES_HANDLER, missing_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/safe_primes/safe_primes_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

Test(SAFE_PRIMES_HANDLER, bad_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/safe_primes/safe_primes_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

Test(SAFE_PRIMES_HANDLER, missing_alg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/safe_primes/safe_primes_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

Test(SAFE_PRIMES_HANDLER, missing_tg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/safe_primes/safe_primes_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

Test(SAFE_PRIMES_HANDLER, missing_tc, .init = setup, .fini = teardown) {
    val = json_parse_file("json/safe_primes/safe_primes_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

Test(SAFE_PRIMES_HANDLER, missing_dgm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/safe_primes/safe_primes_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

Test(SAFE_PRIMES_HANDLER, bad_dgm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/safe_primes/safe_primes_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

Test(SAFE_PRIMES_HANDLER, missing_y, .init = setup, .fini = teardown) {
    val = json_parse_file("json/safe_primes/safe_primes_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

Test(SAFE_PRIMES_HANDLER, missing_x, .init = setup, .fini = teardown) {
    val = json_parse_file("json/safe_primes/safe_primes_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


Test(SAFE_PRIMES_HANDLER, missing_testtype, .init = setup, .fini = teardown) {
    val = json_parse_file("json/safe_primes/safe_primes_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

Test(SAFE_PRIMES_HANDLER, bad_testtype, .init = setup, .fini = teardown) {
    val = json_parse_file("json/safe_primes/safe_primes_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_safe_primes_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

