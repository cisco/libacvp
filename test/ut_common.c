//
// Created by edaw on 2/8/18.
//

#include "ut_common.h"

/*
 * This is a minimal and rudimentary logging handler.
 * libacvp calls this function to for debugs, warnings,
 * and errors.
 */
ACVP_RESULT progress(char *msg)
{
    printf("%s", msg);
    return ACVP_SUCCESS;
}

ACVP_RESULT test_sha_handler(ACVP_TEST_CASE *tc) {
    return ACVP_SUCCESS;
}

void teardown_ctx(ACVP_CTX **ctx) {
    acvp_free_test_session(*ctx);
    acvp_cleanup();
}