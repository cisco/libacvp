/** @file */
/*
 * Copyright (c) 2023, Cisco Systems, Inc.
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

static void setup(void) {
    setup_empty_ctx(&ctx);
    rv = acvp_enable_algorithm(ctx, ACVP_KMAC_128, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_enable_algorithm(ctx, ACVP_KMAC_256, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);

}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(KMAC_128_CAPABILITY, good) {
    setup_empty_ctx(&ctx);

    rv = acvp_enable_algorithm(ctx, ACVP_KMAC_128, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_128, ACVP_KMAC_MSGLEN, 0, 65536, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_128, ACVP_KMAC_MACLEN, 32, 65536, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_128, ACVP_KMAC_KEYLEN, 128, 65536, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_128, ACVP_KMAC_XOF_SUPPORT, ACVP_XOF_SUPPORT_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_128, ACVP_KMAC_HEX_CUSTOM_SUPPORT, 1);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(KMAC_256_CAPABILITY, good) {
    setup_empty_ctx(&ctx);

    rv = acvp_enable_algorithm(ctx, ACVP_KMAC_256, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_256, ACVP_KMAC_MSGLEN, 0, 65536, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_256, ACVP_KMAC_MACLEN, 32, 65536, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_256, ACVP_KMAC_KEYLEN, 128, 65536, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_256, ACVP_KMAC_XOF_SUPPORT, ACVP_XOF_SUPPORT_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_256, ACVP_KMAC_HEX_CUSTOM_SUPPORT, 1);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(KMAC_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kmac/kmac.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(KMAC_API, null_ctx) {
    val = json_parse_file("json/kmac/kmac.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kmac_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}


/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(KMAC_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_kmac_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(KMAC_API, good_aes, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}

/*
 * The value for key:"algorithm" is wrong.
 */
Test(KMAC_API, wrong_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);
}

/* any below failure cases could have the JSON modified anywhere in the file, not just the top */

/* The value for key:"testType" is wrong. */
Test(KMAC_API, wrong_test_type, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac_3.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_TC_INVALID_DATA);
    json_value_free(val);
}


/* The key:"xof" is missing. */
Test(KMAC_API, missing_xof, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_TC_MISSING_DATA);
    json_value_free(val);
}

/* The key:"hexCustomization" is missing. */
Test(KMAC_API, missing_hex_customization, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_TC_MISSING_DATA);
    json_value_free(val);
}


/* The key:"msgLen" is missing. 0 is acceptable length and API returns 0, but it mis-matches read length
   so it will return invalid instead of missing data. */
Test(KMAC_API, missing_msgLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac_6.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_TC_INVALID_DATA);
    json_value_free(val);
}


/* The key:"macLen" is missing or 0. */
Test(KMAC_API, missing_macLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac_7.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_TC_MISSING_DATA);
    json_value_free(val);
}

/* The key:"keyLen" is missing or 0. */
Test(KMAC_API, missing_keyLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac_8.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_TC_MISSING_DATA);
    json_value_free(val);
}

/* The value for msgLen does not match the actual length of "msg" */
Test(KMAC_API, bad_msgLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac_9.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_TC_INVALID_DATA);
    json_value_free(val);
}

/* The value for keyLen does not match the actual length of "key" */
Test(KMAC_API, bad_keyLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac_10.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_TC_INVALID_DATA);
    json_value_free(val);
}

/* The value for macLen does not match the actual length of "mac" (MVT only) */
Test(KMAC_API, bad_macLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac_11.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_TC_INVALID_DATA);
    json_value_free(val);
}

/* The key:"msg" is missing. */
Test(KMAC_API, missing_msg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac_12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_TC_MISSING_DATA);
    json_value_free(val);
}

/* The key:"key" is missing. */
Test(KMAC_API, missing_key, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac_13.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_TC_MISSING_DATA);
    json_value_free(val);
}

/* The key:"mac" is missing. (MVT only) */
Test(KMAC_API, missing_mac, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kmac/kmac_14.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kmac_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_TC_MISSING_DATA);
    json_value_free(val);
}
