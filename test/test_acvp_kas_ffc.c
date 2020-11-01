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

    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_COMP, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_DSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_CCM, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_CMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPGEN);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPVAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_KDF, ACVP_KAS_FFC_NOKDFNOKC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FC, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);

    /* Support is for FFC-SSC for hashZ only */
    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_SSC, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_DSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FB);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_HASH, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);

}

static void setup_fail(void) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_COMP, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_DSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_CCM, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_CMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPGEN);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPVAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_KDF, ACVP_KAS_FFC_NOKDFNOKC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FC, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);

    /* Support is for FFC-SSC for hashZ only */
    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_SSC, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_DSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FB);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_HASH, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(KAS_FFC_CAPABILITY, good) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_COMP, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_DSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_CCM, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_CMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPGEN);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPVAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_KDF, ACVP_KAS_FFC_NOKDFNOKC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FC, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 * Component mode.
 */
Test(KAS_FFC_COMP_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kas_ffc/kas_ffc_comp.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(KAS_FFC_API, null_ctx) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kas_ffc_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(KAS_FFC_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_kas_ffc_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/* //////////////////////
 * Component mode
 * /////////////////////
 */

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(KAS_FFC_COMP_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}

/*
 * The key:"algorithm" is missing.
 */
Test(KAS_FFC_COMP_HANDLER, missing_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The value for key:"mode" is wrong.
 */
Test(KAS_FFC_COMP_HANDLER, wrong_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"testType" is missing.
 */
Test(KAS_FFC_COMP_HANDLER, missing_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"testType" is wrong.
 */
Test(KAS_FFC_COMP_HANDLER, wrong_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"hashAlg" is missing.
 */
Test(KAS_FFC_COMP_HANDLER, missing_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"hashAlg" is wrong.
 */
Test(KAS_FFC_COMP_HANDLER, wrong_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"p" is missing.
 */
Test(KAS_FFC_COMP_HANDLER, missing_p, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"p" string is too long.
 */
Test(KAS_FFC_COMP_HANDLER, wrong_p, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"q" is missing.
 */
Test(KAS_FFC_COMP_HANDLER, missing_q, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"q" string is too long.
 */
Test(KAS_FFC_COMP_HANDLER, wrong_q, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"g" is missing.
 */
Test(KAS_FFC_COMP_HANDLER, missing_g, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"g" string is too long.
 */
Test(KAS_FFC_COMP_HANDLER, wrong_g, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPublicServer" is missing.
 */
Test(KAS_FFC_COMP_HANDLER, missing_ephemeralPublicServer, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"ephemeralPublicServer" string is too long.
 */
Test(KAS_FFC_COMP_HANDLER, wrong_ephemeralPublicServer, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPrivateIut" is missing.
 */
Test(KAS_FFC_COMP_HANDLER, missing_ephemeralPrivateIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"ephemeralPrivateIut" string is too long.
 */
Test(KAS_FFC_COMP_HANDLER, wrong_ephemeralPrivateIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPublicIut" is missing.
 */
Test(KAS_FFC_COMP_HANDLER, missing_ephemeralPublicIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"ephemeralPublicIut" string is too long.
 */
Test(KAS_FFC_COMP_HANDLER, wrong_ephemeralPublicIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"hashZ" is missing.
 */
Test(KAS_FFC_COMP_HANDLER, missing_hashZ, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"hashZIut" string is too long.
 */
Test(KAS_FFC_COMP_HANDLER, wrong_hashZIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_comp_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(KAS_FFC_COMP_HANDLER, cryptoFail1, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ffc/kas_ffc_comp.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(KAS_FFC_COMP_HANDLER, cryptoFail2, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ffc/kas_ffc_comp.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 139; /* fail on last iteration */
    rv  = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key:"hashAlg" is missing in last tg
 */
Test(KAS_FFC_COMP_HANDLER, tgFail1, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ffc/kas_ffc_comp_21.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"hashZIut" is missing in last tc
 */
Test(KAS_FFC_COMP_HANDLER, tcFail1, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ffc/kas_ffc_comp_22.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kas_ffc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/* //////////////////////
 * SSC mode
 * /////////////////////
 */

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(KAS_FFC_SSC_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}

/*
 * The key:"algorithm" is missing.
 */
Test(KAS_FFC_SSC_HANDLER, missing_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The key:"testType" is missing.
 */
Test(KAS_FFC_SSC_HANDLER, missing_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"testType" is wrong.
 */
Test(KAS_FFC_SSC_HANDLER, wrong_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"hashAlg" is missing.
 */
Test(KAS_FFC_SSC_HANDLER, missing_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"hashAlg" is wrong.
 */
Test(KAS_FFC_SSC_HANDLER, wrong_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"p" is missing.
 */
Test(KAS_FFC_SSC_HANDLER, missing_p, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"p" string is too long.
 */
Test(KAS_FFC_SSC_HANDLER, wrong_p, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"q" is missing.
 */
Test(KAS_FFC_SSC_HANDLER, missing_q, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"q" string is too long.
 */
Test(KAS_FFC_SSC_HANDLER, wrong_q, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"g" is missing.
 */
Test(KAS_FFC_SSC_HANDLER, missing_g, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"g" string is too long.
 */
Test(KAS_FFC_SSC_HANDLER, wrong_g, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPublicServer" is missing.
 */
Test(KAS_FFC_SSC_HANDLER, missing_ephemeralPublicServer, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"ephemeralPublicServer" string is too long.
 */
Test(KAS_FFC_SSC_HANDLER, wrong_ephemeralPublicServer, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPrivateIut" is missing.
 */
Test(KAS_FFC_SSC_HANDLER, missing_ephemeralPrivateIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"ephemeralPrivateIut" string is too long.
 */
Test(KAS_FFC_SSC_HANDLER, wrong_ephemeralPrivateIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPublicIut" is missing.
 */
Test(KAS_FFC_SSC_HANDLER, missing_ephemeralPublicIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"ephemeralPublicIut" string is too long.
 */
Test(KAS_FFC_SSC_HANDLER, wrong_ephemeralPublicIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"hashZ" is missing.
 */
Test(KAS_FFC_SSC_HANDLER, missing_hashZ, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"hashZ" string is too long.
 */
Test(KAS_FFC_SSC_HANDLER, wrong_hashZ, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(KAS_FFC_SSC_HANDLER, cryptoFail1, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ffc/kas_ffc_ssc.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(KAS_FFC_SSC_HANDLER, cryptoFail2, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ffc/kas_ffc_ssc.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 74; /* fail on last iteration */
    rv  = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key:"hashFunctionZ" is missing
 */
Test(KAS_FFC_SSC_HANDLER, tgFail1, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_20.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"hashZ" is missing in last tc
 */
Test(KAS_FFC_SSC_HANDLER, tcFail1, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ffc/kas_ffc_ssc_21.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kas_ffc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

