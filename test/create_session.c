//
// Created by edaw on 2/7/18.
//

#include "ut_common.h"

ACVP_CTX *ctx;

Test(CreateSession, properly) {
    ACVP_RESULT rv;
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;

    rv = acvp_create_test_session(&ctx, &progress, level);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

Test(CreateSession, null_ctx) {
    ACVP_RESULT rv;
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;

    rv = acvp_create_test_session(NULL, &progress, level);
    cr_assert(rv == ACVP_INVALID_ARG);

    teardown_ctx(&ctx);
}

Test(SetupSessionParams, proper_ctx_params) {
    ACVP_RESULT rv;
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;
    char *server = "127.0.0.1";
    int port = 443;

    rv = acvp_create_test_session(&ctx, &progress, level);
    cr_assert(rv == ACVP_SUCCESS);

    /*
     * Next we setup ctx params
     */
    rv = acvp_set_server(ctx, server, port);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_set_vendor_info(ctx, "Cisco", "www.cisco.com", "Unit Tests", "ut@123.com");
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

Test(SetupSessionParams, null_server_param) {
    ACVP_RESULT rv;
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;
    char *server = NULL;
    int port = 443;

    rv = acvp_create_test_session(&ctx, &progress, level);
    cr_assert(rv == ACVP_SUCCESS);

    /*
     * Next we setup ctx params
     */
    rv = acvp_set_server(ctx, server, port);
    cr_assert(rv == ACVP_INVALID_ARG);

    teardown_ctx(&ctx);
}