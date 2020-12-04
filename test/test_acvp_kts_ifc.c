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

    rv = acvp_cap_kts_ifc_enable(ctx, ACVP_KTS_IFC, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_RSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_RSADP, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_param_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FIXEDPUBEXP, expo_str);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_param_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_IUT_ID, "CAFEBABE");
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FUNCTION, ACVP_KTS_IFC_KEYPAIR_GEN);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FUNCTION, ACVP_KTS_IFC_PARTIAL_VAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 2048);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 3072);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 4096);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG1_BASIC);
    cr_assert(rv == ACVP_SUCCESS);


    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_SCHEME, ACVP_KTS_IFC_KAS1_BASIC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ROLE, ACVP_KTS_IFC_RESPONDER);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ROLE, ACVP_KTS_IFC_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_NULL_ASSOC_DATA, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_scheme_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ENCODING, "concatenation");
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_L, 512);
    cr_assert(rv == ACVP_SUCCESS);

    if (expo_str) free(expo_str);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(KTS_IFC_CAPABILITY, good) {
    setup_empty_ctx(&ctx);
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7); // RSA_F4

    rv = acvp_cap_kts_ifc_enable(ctx, ACVP_KTS_IFC, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_RSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_RSADP, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_param_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FIXEDPUBEXP, expo_str);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_param_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_IUT_ID, "CAFEBABE");
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FUNCTION, ACVP_KTS_IFC_KEYPAIR_GEN);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FUNCTION, ACVP_KTS_IFC_PARTIAL_VAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 2048);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 3072);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 4096);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG1_BASIC);
    cr_assert(rv == ACVP_SUCCESS);


    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_SCHEME, ACVP_KTS_IFC_KAS1_BASIC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ROLE, ACVP_KTS_IFC_RESPONDER);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ROLE, ACVP_KTS_IFC_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_NULL_ASSOC_DATA, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_scheme_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ENCODING, "concatenation");
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_L, 512);
    cr_assert(rv == ACVP_SUCCESS);

    if (expo_str) free(expo_str);
    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(KTS_IFC_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kts_ifc/kts_ifc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(KTS_IFC_API, null_ctx) {
    val = json_parse_file("json/kts_ifc/kts_ifc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kts_ifc_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(KTS_IFC_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_kts_ifc_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/* //////////////////////
 * KTS-IFC
 * /////////////////////
 */

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(KTS_IFC_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}

/*
 * The key:"algorithm" is missing.
 */
Test(KTS_IFC_HANDLER, missing_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The key:"testType" is missing.
 */
Test(KTS_IFC_HANDLER, missing_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"testType" is wrong.
 */
Test(KTS_IFC_HANDLER, wrong_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"hashAlg" is missing.
 */
Test(KTS_IFC_HANDLER, missing_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"hashAlg" is wrong.
 */
Test(KTS_IFC_HANDLER, wrong_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"adp" is missing.
 */
Test(KTS_IFC_HANDLER, missing_adp, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"encoding" is missing.
 */
Test(KTS_IFC_HANDLER, missing_encoding, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"l" is missing.
 */
Test(KTS_IFC_HANDLER, missing_l, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"fixedPubExp" is missing.
 */
Test(KTS_IFC_HANDLER, missing_fpe, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"modulo" is missing.
 */
Test(KTS_IFC_HANDLER, missing_modulo, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"keyGenerationMethod" is missing.
 */
Test(KTS_IFC_HANDLER, missing_kgm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"kasRole" is missing.
 */
Test(KTS_IFC_HANDLER, missing_kr, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"scheme" is missing.
 */
Test(KTS_IFC_HANDLER, missing_scheme, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}
/*
 * The key:"iutId" is missing.
 */
Test(KTS_IFC_HANDLER, missing_ii, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}
/*
 * The key:"serverId" is missing.
 */
Test(KTS_IFC_HANDLER, missing_si, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"keyConfirmationDirection" is missing.
 */
Test(KTS_IFC_HANDLER, missing_kcd, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"keyConfirmationRole" is missing.
 */
Test(KTS_IFC_HANDLER, missing_kcr, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"iutN" is missing.
 */
Test(KTS_IFC_HANDLER, missing_iutn, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"iutE" is missing.
 */
Test(KTS_IFC_HANDLER, missing_iute, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"iutP" is missing.
 */
Test(KTS_IFC_HANDLER, missing_iutp, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"iutQ" is missing.
 */
Test(KTS_IFC_HANDLER, missing_iutq, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_21.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"iutD" is missing.
 */
Test(KTS_IFC_HANDLER, missing_iutd, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_22.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"serverC" is missing.
 */
Test(KTS_IFC_HANDLER, missing_serverc, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_23.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"serverN" is missing.
 */
Test(KTS_IFC_HANDLER, missing_servern, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_24.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"serverE" is missing.
 */
Test(KTS_IFC_HANDLER, missing_servere, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kts_ifc/kts_ifc_25.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kts_ifc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


