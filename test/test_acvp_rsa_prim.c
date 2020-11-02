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
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    setup_empty_ctx(&ctx);

    /*
     * Enable Decryption Primitive
     */
    rv = acvp_cap_rsa_prim_enable(ctx, ACVP_RSA_DECPRIM, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_DECPRIM, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_DECPRIM, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    /*
     * Enable Signature Primitive
     */
    rv = acvp_cap_rsa_prim_enable(ctx, ACVP_RSA_SIGPRIM, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGPRIM, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGPRIM, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_PARM_KEY_FORMAT_CRT, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_prim_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    cr_assert(rv == ACVP_SUCCESS);
    free(expo_str);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(RSA_PRIM_CAPABILITY, good) {
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    setup_empty_ctx(&ctx);

    /*
     * Enable Decryption Primitive
     */
    rv = acvp_cap_rsa_prim_enable(ctx, ACVP_RSA_DECPRIM, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_DECPRIM, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_DECPRIM, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    /*
     * Enable Signature Primitive
     */
    rv = acvp_cap_rsa_prim_enable(ctx, ACVP_RSA_SIGPRIM, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGPRIM, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGPRIM, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_PARM_KEY_FORMAT_CRT, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_prim_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    cr_assert(rv == ACVP_SUCCESS);
    free(expo_str);
    teardown();
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(RSA_DECPRIM_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/rsa/rsa_decprim.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_rsa_decprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown();
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(RSA_SIGPRIM_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/rsa/rsa_sigprim.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_rsa_sigprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown();
}

#if 0 /* Cannot test a successful decrypt prim because it can take a long time */
/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(RSA_DECPRIM_API, pass) {

    setup();

    val = json_parse_file("json/rsa/rsa_decprim.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_rsa_decprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);

end:
    if (ctx) teardown();
}
#endif

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(RSA_SIGPRIM_API, pass) {

    setup();

    val = json_parse_file("json/rsa/rsa_sigprim.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_rsa_sigprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);

end:
    if (ctx) teardown();
}

/*
 * Test the KAT handler API paths.
 */
Test(RSA_DECPRIM_API, error_paths) {
    setup_empty_ctx(&ctx);

    /*
     * Enable Decryption Primitive
     */
    rv = acvp_cap_rsa_prim_enable(ctx, ACVP_RSA_DECPRIM, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_DECPRIM, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_DECPRIM, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    val = json_parse_file("json/rsa/rsa_decprim1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_decprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);

    val = json_parse_file("json/rsa/rsa_decprim2.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_decprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);

    val = json_parse_file("json/rsa/rsa_decprim3.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_decprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);

    val = json_parse_file("json/rsa/rsa_decprim4.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_decprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);

    val = json_parse_file("json/rsa/rsa_decprim5.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_decprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);

    val = json_parse_file("json/rsa/rsa_decprim6.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_decprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);

    val = json_parse_file("json/rsa/rsa_decprim7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_decprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);

    val = json_parse_file("json/rsa/rsa_decprim8.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_decprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);

    val = json_parse_file("json/rsa/rsa_decprim9.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_decprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);


    json_value_free(val);

end:
    if (ctx) teardown();
}

/*
 * Test the KAT handler API paths.
 */
Test(RSA_SIGPRIM_API, error_paths) {
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    setup_empty_ctx(&ctx);

    /*
     * Enable Signature Primitive
     */
    rv = acvp_cap_rsa_prim_enable(ctx, ACVP_RSA_SIGPRIM, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGPRIM, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGPRIM, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_PARM_KEY_FORMAT_CRT, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_prim_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    cr_assert(rv == ACVP_SUCCESS);

    val = json_parse_file("json/rsa/rsa_sigprim1.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_sigprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);

    val = json_parse_file("json/rsa/rsa_sigprim2.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_sigprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);

    val = json_parse_file("json/rsa/rsa_sigprim3.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_sigprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);

    val = json_parse_file("json/rsa/rsa_sigprim4.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_sigprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);

    val = json_parse_file("json/rsa/rsa_sigprim5.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_sigprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);

    val = json_parse_file("json/rsa/rsa_sigprim6.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_sigprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);

    val = json_parse_file("json/rsa/rsa_sigprim7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_sigprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);

    val = json_parse_file("json/rsa/rsa_sigprim8.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_sigprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);

    val = json_parse_file("json/rsa/rsa_sigprim9.json");
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    rv  = acvp_rsa_sigprim_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);

    json_value_free(val);

end:
    free(expo_str);
    if (ctx) teardown();
}
