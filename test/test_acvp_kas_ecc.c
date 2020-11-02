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

    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_PREREQ_ECDSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P521);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K571);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B571);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_COMP, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_ECDSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CCM, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_KDF, 0, ACVP_KAS_ECC_NOKDFNOKC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EB, ACVP_EC_CURVE_P224, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EC, ACVP_EC_CURVE_P256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ED, ACVP_EC_CURVE_P384, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EE, ACVP_EC_CURVE_P521, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_SSC, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_ECDSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P521);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_HASH, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);

}

static void setup_fail(void) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_PREREQ_ECDSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P521);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K571);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B571);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_COMP, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_ECDSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CCM, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_KDF, 0, ACVP_KAS_ECC_NOKDFNOKC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EB, ACVP_EC_CURVE_P224, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EC, ACVP_EC_CURVE_P256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ED, ACVP_EC_CURVE_P384, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EE, ACVP_EC_CURVE_P521, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(KAS_ECC_CAPABILITY, good) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_PREREQ_ECDSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P521);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K571);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B571);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_COMP, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_ECDSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CCM, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_KDF, 0, ACVP_KAS_ECC_NOKDFNOKC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EB, ACVP_EC_CURVE_P224, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EC, ACVP_EC_CURVE_P256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ED, ACVP_EC_CURVE_P384, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EE, ACVP_EC_CURVE_P521, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 * CDH mode.
 */
Test(KAS_ECC_CDH_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kas_ecc/kas_ecc_cdh.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 * Component mode.
 */
Test(KAS_ECC_COMP_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kas_ecc/kas_ecc_comp.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(KAS_ECC_API, null_ctx) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_kas_ecc_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(KAS_ECC_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_kas_ecc_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/* //////////////////////
 * CDH mode
 * /////////////////////
 */

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(KAS_ECC_CDH_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}

/*
 * The key:"algorithm" is missing.
 */
Test(KAS_ECC_CDH_HANDLER, missing_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The value for key:"mode" is wrong.
 */
Test(KAS_ECC_CDH_HANDLER, wrong_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"testType" is missing.
 */
Test(KAS_ECC_CDH_HANDLER, missing_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"testType" is wrong.
 */
Test(KAS_ECC_CDH_HANDLER, wrong_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"curve" is missing.
 */
Test(KAS_ECC_CDH_HANDLER, missing_curve, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"curve" is wrong.
 */
Test(KAS_ECC_CDH_HANDLER, wrong_curve, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"publicServerX" is missing.
 */
Test(KAS_ECC_CDH_HANDLER, missing_publicServerX, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"publicServerX" string is too long.
 */
Test(KAS_ECC_CDH_HANDLER, wrong_publicServerX, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"publicServerY" is missing.
 */
Test(KAS_ECC_CDH_HANDLER, missing_publicServerY, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"publicServerY" string is too long.
 */
Test(KAS_ECC_CDH_HANDLER, wrong_publicServerY, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/* //////////////////////
 * Component mode
 * /////////////////////
 */

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(KAS_ECC_COMP_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}

/*
 * The key:"algorithm" is missing.
 */
Test(KAS_ECC_COMP_HANDLER, missing_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The value for key:"mode" is wrong.
 */
Test(KAS_ECC_COMP_HANDLER, wrong_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"testType" is missing.
 */
Test(KAS_ECC_COMP_HANDLER, missing_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"testType" is wrong.
 */
Test(KAS_ECC_COMP_HANDLER, wrong_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"curve" is missing.
 */
Test(KAS_ECC_COMP_HANDLER, missing_curve, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"curve" is wrong.
 */
Test(KAS_ECC_COMP_HANDLER, wrong_curve, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"hashAlg" is missing.
 */
Test(KAS_ECC_COMP_HANDLER, missing_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"hashAlg" is wrong.
 */
Test(KAS_ECC_COMP_HANDLER, wrong_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPublicServerX" is missing.
 */
Test(KAS_ECC_COMP_HANDLER, missing_ephemeralPublicServerX, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"ephemeralPublicServerX" string is too long.
 */
Test(KAS_ECC_COMP_HANDLER, wrong_ephemeralPublicServerX, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPublicServerY" is missing.
 */
Test(KAS_ECC_COMP_HANDLER, missing_ephemeralPublicServerY, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"ephemeralPublicServerY" string is too long.
 */
Test(KAS_ECC_COMP_HANDLER, wrong_ephemeralPublicServerY, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPrivateIut" is missing.
 */
Test(KAS_ECC_COMP_HANDLER, missing_ephemeralPrivateIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"ephemeralPrivateIut" string is too long.
 */
Test(KAS_ECC_COMP_HANDLER, wrong_ephemeralPrivateIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPublicIutX" is missing.
 */
Test(KAS_ECC_COMP_HANDLER, missing_ephemeralPublicIutX, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"ephemeralPublicIutX" string is too long.
 */
Test(KAS_ECC_COMP_HANDLER, wrong_ephemeralPublicIutX, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPublicIutY" is missing.
 */
Test(KAS_ECC_COMP_HANDLER, missing_ephemeralPublicIutY, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"ephemeralPublicIutY" string is too long.
 */
Test(KAS_ECC_COMP_HANDLER, wrong_ephemeralPublicIutY, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"hashZIut" is missing.
 */
Test(KAS_ECC_COMP_HANDLER, missing_hashZIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"hashZIut" string is too long.
 */
Test(KAS_ECC_COMP_HANDLER, wrong_hashZIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_comp_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(KAS_ECC_COMP_HANDLER, cryptoFail1, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ecc/kas_ecc_cdh.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(KAS_ECC_COMP_HANDLER, cryptoFail2, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ecc/kas_ecc_cdh.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 299; /* fail on last iteration */
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(KAS_ECC_COMP_HANDLER, cryptoFail3, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ecc/kas_ecc_comp.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(KAS_ECC_COMP_HANDLER, cryptoFail4, .init = setup_fail, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ecc/kas_ecc_comp.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 279; /* fail on last iteration */
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key:"curve" is missing in last tg
 */
Test(KAS_ECC_CDH_HANDLER, tgFail1, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_11.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"publicServerY" is missing in last tc
 */
Test(KAS_ECC_CDH_HANDLER, tcFail1, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ecc/kas_ecc_cdh_12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"curve" is missing in last tg
 */
Test(KAS_ECC_COMP_HANDLER, tgFail1, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ecc/kas_ecc_comp_21.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPublicServerY" is missing in last tc
 */
Test(KAS_ECC_COMP_HANDLER, tcFail1, .init = setup, .fini = teardown) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kas_ecc/kas_ecc_comp_22.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kas_ecc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/* //////////////////////
 * SSC  mode
 * /////////////////////
 */

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(KAS_ECC_SSC_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}

/*
 * The key:"algorithm" is missing.
 */
Test(KAS_ECC_SSC_HANDLER, missing_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}


/*
 * The key:"testType" is missing.
 */
Test(KAS_ECC_SSC_HANDLER, missing_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"testType" is wrong.
 */
Test(KAS_ECC_SSC_HANDLER, wrong_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"domainParameterGenerationMode" is missing.
 */
Test(KAS_ECC_SSC_HANDLER, missing_curve, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"domainParameterGenerationMode" is wrong.
 */
Test(KAS_ECC_SSC_HANDLER, wrong_curve, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"hashFunctionZ" is missing.
 */
Test(KAS_ECC_SSC_HANDLER, missing_hashFunctionZ, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"hashFunctionZ" is wrong.
 */
Test(KAS_ECC_SSC_HANDLER, wrong_hashFunctionZ, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPublicServerX" is missing.
 */
Test(KAS_ECC_SSC_HANDLER, missing_ephemeralPublicServerX, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"ephemeralPublicServerX" string is too long.
 */
Test(KAS_ECC_SSC_HANDLER, wrong_ephemeralPublicServerX, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPublicServerY" is missing.
 */
Test(KAS_ECC_SSC_HANDLER, missing_ephemeralPublicServerY, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"ephemeralPublicServerY" is too long
 */
Test(KAS_ECC_SSC_HANDLER, wrong_ephemeralPublicServerY, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"ephemeralPrivateIut" is missing.
 */
Test(KAS_ECC_SSC_HANDLER, missing_ephemeralPrivateIut, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"ephemeralPublicIutX" is missing.
 */
Test(KAS_ECC_SSC_HANDLER, missing_ephemeralPublicIutX, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"ephemeralPublicIutY" is missing.
 */
Test(KAS_ECC_SSC_HANDLER, missing_ephemeralPublicIutY, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kas_ecc/kas_ecc_ssc_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_kas_ecc_ssc_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


