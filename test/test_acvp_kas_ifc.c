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
    setup_empty_ctx(&ctx);
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    /* Support is for IFC-SSC for hashZ only */
    rv = acvp_cap_kas_ifc_enable(ctx, ACVP_KAS_IFC_SSC, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_RSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_RSADP, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 2048);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 3072);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 4096);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG1_BASIC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_exponent(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_FIXEDPUBEXP, expo_str);
    cr_assert(rv == ACVP_SUCCESS);

}

static void setup_fail(void) {
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    setup_empty_ctx(&ctx);
    /* Support is for IFC-SSC for hashZ only */
    rv = acvp_cap_kas_ifc_enable(ctx, ACVP_KAS_IFC_SSC, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_RSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_RSADP, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 2048);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 3072);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 4096);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG1_BASIC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_exponent(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_FIXEDPUBEXP, expo_str);
    cr_assert(rv == ACVP_SUCCESS);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(KAS_IFC_CAPABILITY, good) {
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    setup_empty_ctx(&ctx);
    /* Support is for IFC-SSC for hashZ only */
    rv = acvp_cap_kas_ifc_enable(ctx, ACVP_KAS_IFC_SSC, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_RSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_RSADP, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 2048);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 3072);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 4096);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG1_BASIC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_HASH, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ifc_set_exponent(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_FIXEDPUBEXP, expo_str);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 * SSC mode.
 */
Test(KAS_IFC_SSC_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kas_ifc/kas_ifc_ssc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(KAS_IFC_API, null_ctx) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kas_ifc_ssc_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(KAS_IFC_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_kas_ifc_ssc_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/* //////////////////////
 * SSC mode
 * /////////////////////
 */

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(KAS_IFC_SSC_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}

/*
 * The key:"algorithm" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The key:"testType" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"testType" is wrong.
 */
Test(KAS_IFC_SSC_HANDLER, wrong_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"hashFunctionZ" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_hashFunctionZ, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"hashFunctionZ" is wrong.
 */
Test(KAS_IFC_SSC_HANDLER, wrong_hashFunctionZ, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"iutP" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_p, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"iutQ" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_q, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"iutD" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_d, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"iutE" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_e, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"iutN" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_n, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"ServerC" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_serverc, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"ServerE" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_servere, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"iutC" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_c, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}
/*
 * The key:"z" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_z, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}
/*
 * The key:"hashZ" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_hashz, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"scheme" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_scheme, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"kaskRole" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_kasrole, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"keygen" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_keygen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"modulo" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_modulo, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"fixedPubExp" is missing.
 */
Test(KAS_IFC_SSC_HANDLER, missing_fixedpub, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ifc/kas_ifc_ssc_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ifc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


