//
// Created by edaw on 2/7/18.
//

#include "ut_common.h"

ACVP_CTX *ctx;

Test(RegisterHash, properly) {
    ACVP_RESULT rv;
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;

    rv = acvp_create_test_session(&ctx, &progress, level);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_enable_hash_cap(ctx, ACVP_SHA1, &test_sha_handler);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA1, ACVP_HASH_IN_BIT, 0);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * This test should return ACVP_NO_CAP because we are trying
 * to register a parameter for an alg that we haven't added
 * to the list yet.
 */
Test(RegisterHash, param_alg_mismatch) {
    ACVP_RESULT rv;
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;
    
    rv = acvp_create_test_session(&ctx, &progress, level);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_enable_hash_cap(ctx, ACVP_SHA1, &test_sha_handler);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA256, ACVP_HASH_IN_BIT, 0);
    cr_assert(rv == ACVP_NO_CAP);
    
    teardown_ctx(&ctx);
}

