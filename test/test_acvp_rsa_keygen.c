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
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    setup_empty_ctx(&ctx);

    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_INFO_GEN_BY_SERVER, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_KEY_FORMAT_CRT, 0);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_rsa_keygen_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B34);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 2048, ACVP_RSA_PRIME_HASH_ALG, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 2048, ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    cr_assert(rv == ACVP_SUCCESS);
    free(expo_str);
}

static void setup_fail(void) {
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    setup_empty_ctx(&ctx);

    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_INFO_GEN_BY_SERVER, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_KEY_FORMAT_CRT, 0);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_rsa_keygen_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B34);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 2048, ACVP_RSA_PRIME_HASH_ALG, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 2048, ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    cr_assert(rv == ACVP_SUCCESS);
    free(expo_str);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(RSA_KEYGEN_CAPABILITY, good) {
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    setup_empty_ctx(&ctx);

    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_INFO_GEN_BY_SERVER, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_KEY_FORMAT_CRT, 0);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_rsa_keygen_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B34);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 2048, ACVP_RSA_PRIME_HASH_ALG, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 2048, ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    cr_assert(rv == ACVP_SUCCESS);
    free(expo_str);
    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(RSA_KEYGEN_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/rsa/rsa_keygen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(RSA_KEYGEN_API, null_ctx) {
    val = json_parse_file("json/rsa/rsa_keygen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_rsa_keygen_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}


/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(RSA_KEYGEN_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_rsa_keygen_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(RSA_KEYGEN_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}


/*
 * The value for key:"algorithm" is wrong.
 */
Test(RSA_KEYGEN_HANDLER, wrong_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"mode" is missing.
 */
Test(RSA_KEYGEN_HANDLER, missing_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}


/*
 * The value for key:"mode" is wrong.
 */
Test(RSA_KEYGEN_HANDLER, wrong_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"infoGeneratedByServer" is missing.
 */
Test(RSA_KEYGEN_HANDLER, missing_infoGeneratedByServer, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"pubExpMode" is missing.
 */
Test(RSA_KEYGEN_HANDLER, missing_pubExpMode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"pubExpMode" is wrong.
 */
Test(RSA_KEYGEN_HANDLER, wrong_pubExpMode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"fixedPubExp" is missing.
 */
Test(RSA_KEYGEN_HANDLER, missing_fixedPubExp, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"keyFormat" is missing.
 */
Test(RSA_KEYGEN_HANDLER, missing_keyFormat, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"keyFormat" is wrong.
 */
Test(RSA_KEYGEN_HANDLER, wrong_keyFormat, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"randPQ" is missing.
 */
Test(RSA_KEYGEN_HANDLER, missing_randPQ, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"randPQ" is wrong.
 */
Test(RSA_KEYGEN_HANDLER, wrong_randPQ, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"primeTest" is missing.
 */
Test(RSA_KEYGEN_HANDLER, missing_primeTest, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"primeTest" is wrong.
 */
Test(RSA_KEYGEN_HANDLER, wrong_primeTest, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"modulo" is missing.
 */
Test(RSA_KEYGEN_HANDLER, missing_modulo, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"modulo" is wrong.
 */
Test(RSA_KEYGEN_HANDLER, wrong_modulo, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"hashAlg" is missing.
 */
Test(RSA_KEYGEN_HANDLER, missing_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"hashAlg" is wrong.
 */
Test(RSA_KEYGEN_HANDLER, wrong_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"e" is missing.
 */
Test(RSA_KEYGEN_HANDLER, missing_e, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"e" string is too long.
 */
Test(RSA_KEYGEN_HANDLER, long_e, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"bitlens" list is wrong size.
 */
Test(RSA_KEYGEN_HANDLER, wrong_size_bitlens, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"seed" is missing.
 */
Test(RSA_KEYGEN_HANDLER, missing_seed, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_21.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"seed" string is too long.
 */
Test(RSA_KEYGEN_HANDLER, long_seed, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_22.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"tgId" string is missing.
 */
Test(RSA_KEYGEN_HANDLER, missing_tgid, .init = setup, .fini = teardown) {
    val = json_parse_file("json/rsa/rsa_keygen_23.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(RSA_KEYGEN_HANDDLER, cryptoFail1, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/rsa/rsa_keygen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(RSA_KEYGEN_HANDDLER, cryptoFail2, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/rsa/rsa_keygen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 5; /* fail on last iteration */
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key:"hashAlg" is missing in last tg
 */
Test(RSA_KEYGEN_HANDDLER, tgFail1, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/rsa/rsa_keygen_24.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"seed" is missing in last tc
 */
Test(RSA_KEYGEN_HANDDLER, tcFail1, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/rsa/rsa_keygen_25.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_rsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

