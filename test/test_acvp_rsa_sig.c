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

static void setup_siggen(void) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGGEN, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
}

static void setup_siggen_fail(void) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGGEN, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGGEN, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
}

static void setup_sigver(void) {
    setup_empty_ctx(&ctx);
    
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4
    
    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGVER, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGVER, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    free(expo_str);
}
static void setup_sigver_fail(void) {
    setup_empty_ctx(&ctx);
    
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4
    
    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGVER, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGVER, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    free(expo_str);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(RSA_SIGGEN_CAPABILITY, good) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGGEN, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(RSA_SIGGEN_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/rsa/rsa_siggen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(RSA_SIGGEN_API, null_ctx) {
    val = json_parse_file("json/rsa/rsa_siggen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_rsa_siggen_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}


/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(RSA_SIGGEN_API, null_json_obj, .init = setup_siggen, .fini = teardown) {
    rv  = acvp_rsa_siggen_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(RSA_SIGGEN_HANDLER, good, .init = setup_siggen, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_siggen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}


/*
 * The value for key:"algorithm" is wrong.
 */
Test(RSA_SIGGEN_HANDLER, wrong_algorithm, .init = setup_siggen, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_siggen_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"mode" is missing.
 */
Test(RSA_SIGGEN_HANDLER, missing_mode, .init = setup_siggen, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_siggen_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"mode" is wrong.
 */
Test(RSA_SIGGEN_HANDLER, wrong_mode, .init = setup_siggen, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_siggen_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"sigType" is missing.
 */
Test(RSA_SIGGEN_HANDLER, missing_sigType, .init = setup_siggen, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_siggen_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"hashAlg" is missing.
 */
Test(RSA_SIGGEN_HANDLER, missing_hashAlg, .init = setup_siggen, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_siggen_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"modulo" is missing.
 */
Test(RSA_SIGGEN_HANDLER, missing_mod, .init = setup_siggen, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_siggen_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"modulo" is wrong.
 */
Test(RSA_SIGGEN_HANDLER, wrong_mod, .init = setup_siggen, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_siggen_7.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"message" is missing.
 */
Test(RSA_SIGGEN_HANDLER, missing_message, .init = setup_siggen, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_siggen_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"tcId" is missing.
 */
Test(RSA_SIGGEN_HANDLER, missing_tcId, .init = setup_siggen, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_siggen_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}


/*
 * The value for key:"message" is too long.
 */
Test(RSA_SIGGEN_HANDLER, message_too_long, .init = setup_siggen, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_siggen_10.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * Test capabilites API.
 */
Test(RSA_SIGVER_CAPABILITY, good) {
    setup_empty_ctx(&ctx);
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4
    
    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGVER, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGVER, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    free(expo_str);    
    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(RSA_SIGVER_API, empty_ctx) {
    setup_empty_ctx(&ctx);
    
    val = json_parse_file("json/rsa/rsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    
    rv  = acvp_rsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);
   
end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(RSA_SIGVER_API, null_ctx) {
    val = json_parse_file("json/rsa/rsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    
    /* Test with NULL JSON object */
    rv  = acvp_rsa_sigver_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}


/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(RSA_SIGVER_API, null_json_obj, .init = setup_sigver, .fini = teardown) {
    rv  = acvp_rsa_sigver_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(RSA_SIGVER_HANDLER, good, .init = setup_sigver, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}


/*
 * The key:"e" is missing
 */
Test(RSA_SIGVER_HANDLER, missing_e, .init = setup_sigver, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_sigver_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"n" is missing
 */
Test(RSA_SIGVER_HANDLER, missing_n, .init = setup_sigver, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_sigver_2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"signature" is missing
 */
Test(RSA_SIGVER_HANDLER, missing_signature, .init = setup_sigver, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_sigver_3.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"signature" is too long
 */
Test(RSA_SIGVER_HANDLER, invalid_signature_len, .init = setup_sigver, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_sigver_4.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"e" is too long
 */
Test(RSA_SIGVER_HANDLER, invalid_e_len, .init = setup_sigver, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_sigver_5.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"n" is too long
 */
Test(RSA_SIGVER_HANDLER, invalid_n_len, .init = setup_sigver, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_sigver_6.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"tgId" is missing
 */
Test(RSA_SIGVER_HANDLER, missing_tgid, .init = setup_sigver, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_sigver_7.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(RSA_SIGGEN_HANDLER, cryptoFail1, .init = setup_siggen_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/rsa/rsa_siggen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(RSA_SIGGEN_HANDLER, cryptoFail2, .init = setup_siggen_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/rsa/rsa_siggen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 1; /* fail on last iteration */
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key:"hashAlg" is missing in last tg
 */
Test(RSA_SIGGEN_HANDLER, tgFail1, .init = setup_siggen, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/rsa/rsa_siggen_11.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"message" is missing in last tc
 */
Test(RSA_SIGGEN_HANDLER, tcFail1, .init = setup_siggen, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/rsa/rsa_siggen_12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(RSA_SIGVER_HANDLER, cryptoFail1, .init = setup_sigver_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/rsa/rsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_rsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(RSA_SIGVER_HANDLER, cryptoFail2, .init = setup_sigver_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/rsa/rsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 2; /* fail on last iteration */
    rv  = acvp_rsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key:"hashAlg" is missing in last tg
 */
Test(RSA_SIGVER_HANDLER, tgFail1, .init = setup_sigver, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/rsa/rsa_sigver_8.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"message" is missing in last tc
 */
Test(RSA_SIGVER_HANDLER, tcFail1, .init = setup_sigver, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/rsa/rsa_sigver_9.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

