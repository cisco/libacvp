/** @file */
/*****************************************************************************
* Copyright (c) 2019, Cisco Systems, Inc.
* All rights reserved.

* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

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

Test(SetupSessionParams, null_vendor_info_params) {
    ACVP_RESULT rv;
    setup_empty_ctx(&ctx);
    
    rv = acvp_set_vendor_info(ctx, NULL, "www.cisco.com", "Unit Tests", "ut@123.com");
    cr_assert(rv == ACVP_INVALID_ARG);
    rv = acvp_set_vendor_info(ctx, "Cisco", NULL, "Unit Tests", "ut@123.com");
    cr_assert(rv == ACVP_INVALID_ARG);
    rv = acvp_set_vendor_info(ctx, "Cisco", "www.cisco.com", NULL, "ut@123.com");
    cr_assert(rv == ACVP_INVALID_ARG);
    rv = acvp_set_vendor_info(ctx, "Cisco", "www.cisco.com", "Unit Tests", NULL);
    cr_assert(rv == ACVP_INVALID_ARG);
    
    teardown_ctx(&ctx);
}