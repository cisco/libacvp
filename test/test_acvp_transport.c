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
#include "acvp_lcl.h"

char *vsid_url = "/acvp/v1/testSessions/0/vectorSets/0";
ACVP_CTX *ctx = NULL;
ACVP_RESULT rv;
char *reg = "{}";
char *little_reg = "[{\"acvVersion\": \"0.5\"},{\"algorithms\": [{\"algorithm\": \"SHA-1\",\"inBit\": false,\n"
                   "                \"inEmpty\": true\n"
                   "            },\n"
                   "            {\n"
                   "                \"algorithm\": \"SHA-224\",\n"
                   "                \"inBit\": false,\n"
                   "                \"inEmpty\": true\n"
                   "            },\n"
                   "            {\n"
                   "                \"algorithm\": \"SHA-256\",\n"
                   "                \"inBit\": false,\n"
                   "                \"inEmpty\": true\n"
                   "            },\n"
                   "            {\n"
                   "                \"algorithm\": \"SHA-384\",\n"
                   "                \"inBit\": false,\n"
                   "                \"inEmpty\": true\n"
                   "            },\n"
                   "            {\n"
                   "                \"algorithm\": \"SHA-512\",\n"
                   "                \"inBit\": false,\n"
                   "                \"inEmpty\": true\n"
                   "            }\n"
                   "        ]\n"
                   "    }\n"
                   "]";
char *login_reg = "[\n"
                  "    {\n"
                  "        \"acvVersion\": \"0.5\"\n"
                  "    },\n"
                  "    {\n"
                  "        \"password\": \"31135756\"\n"
                  "    }\n"
                  "]";

char *server;
int port;
char *ca_chain_file;
char *cert_file;
char *key_file;
char *path_segment;
char *api_context;

/*
 * Read the operational parameters from the various environment
 * variables.
 */
static void setup_session_parameters(void)
{
    setup_empty_ctx(&ctx);
    
    char *tmp;
    server = getenv("ACV_SERVER");
    tmp = getenv("ACV_PORT");
    if (tmp) port = atoi(tmp);
    path_segment = getenv("ACV_URI_PREFIX");
    api_context = getenv("ACV_API_CONTEXT");
    ca_chain_file = getenv("ACV_CA_FILE");
    cert_file = getenv("ACV_CERT_FILE");
    key_file = getenv("ACV_KEY_FILE");
    
    printf("Using the following parameters:\n\n");
    printf("    ACV_SERVER:     %s\n", server);
    printf("    ACV_PORT:       %d\n", port);
    printf("    ACV_URI_PREFIX: %s\n", path_segment);
    printf("    ACV_CA_FILE:    %s\n", ca_chain_file);
    printf("    ACV_CERT_FILE:  %s\n", cert_file);
    printf("    ACV_KEY_FILE:   %s\n\n", key_file);
    
    acvp_set_server(ctx, server, port);
    acvp_set_cacerts(ctx, ca_chain_file);
    acvp_set_certkey(ctx, cert_file, key_file);
    acvp_set_path_segment(ctx, path_segment);
    rv = acvp_set_api_context(ctx, api_context);
    acvp_set_2fa_callback(ctx, &totp);
}

static void add_hash_details_good(void) {
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA1, ACVP_HASH_IN_BIT, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA1, ACVP_HASH_IN_EMPTY, 1);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA512, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512, ACVP_HASH_IN_BIT, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA512, ACVP_HASH_IN_EMPTY, 1);
    cr_assert(rv == ACVP_SUCCESS);
}

#ifdef TEST_TRANSPORT
static void setup(void) {
    setup_empty_ctx(&ctx);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
}

/*
 * ctx has not set server and port
 */
Test(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS, incomplete_ctx, .init = setup, .fini = teardown) {
    rv = acvp_retrieve_expected_result(ctx, vsid_url);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS, missing_vsid_url, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_retrieve_expected_result(ctx, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * null ctx
 */
Test(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS, missing_ctx) {
    rv = acvp_retrieve_expected_result(NULL, vsid_url);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * Even if the vector set or test session doesn't exist and gives a 404,
 * we expect success because the API did what it was supposed to - GET sample
 * answers
 */
Test(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS, good, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_retrieve_expected_result(ctx, vsid_url);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * ctx has not set server and port
 */
Test(TRANSPORT_RETRIEVE_VECTOR_SET, incomplete_ctx, .init = setup, .fini = teardown) {
    rv = acvp_retrieve_vector_set(ctx, vsid_url);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_RETRIEVE_VECTOR_SET, missing_vsid_url, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_retrieve_vector_set(ctx, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * null ctx
 */
Test(TRANSPORT_RETRIEVE_VECTOR_SET, missing_ctx) {
    rv = acvp_retrieve_vector_set(NULL, vsid_url);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * Even if the vector set or test session doesn't exist and gives a 404,
 * we expect success because the API did what it was supposed to - GET sample
 * answers
 */
Test(TRANSPORT_RETRIEVE_VECTOR_SET, good, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_retrieve_vector_set(ctx, vsid_url);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * ctx has not set server and port
 */
Test(TRANSPORT_SUBMIT_VECTOR_SET, incomplete_ctx, .init = setup, .fini = teardown) {
    rv = acvp_submit_vector_responses(ctx, vsid_url);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * null ctx
 */
Test(TRANSPORT_SUBMIT_VECTOR_SET, missing_ctx) {
    rv = acvp_submit_vector_responses(NULL, NULL);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * missing vsid_url
 */
Test(TRANSPORT_SUBMIT_VECTOR_SET, missing_vsid, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_submit_vector_responses(ctx, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * ctx has not set server and port
 */
Test(TRANSPORT_RETRIEVE_RESULT, incomplete_ctx, .init = setup, .fini = teardown) {
    rv = acvp_retrieve_vector_set_result(ctx, vsid_url);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_RETRIEVE_RESULT, missing_vsid_url, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_retrieve_vector_set_result(ctx, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * null ctx
 */
Test(TRANSPORT_RETRIEVE_RESULT, missing_ctx) {
    rv = acvp_retrieve_vector_set_result(NULL, vsid_url);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * Even if the vector set or test session doesn't exist and gives a 404,
 * we expect success because the API did what it was supposed to - GET sample
 * answers
 */
Test(TRANSPORT_RETRIEVE_RESULT, good, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_test_session_registration(ctx, little_reg, strlen(little_reg));
    cr_assert(rv == ACVP_TRANSPORT_FAIL);
    rv = acvp_retrieve_vector_set_result(ctx, vsid_url);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_TEST_SESSION_REG, missing_reg, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_test_session_registration(ctx, NULL, 0);
    cr_assert(rv == ACVP_NO_DATA);
}

/*
 * null ctx
 */
Test(TRANSPORT_SEND_TEST_SESSION_REG, missing_ctx) {
    rv = acvp_send_test_session_registration(NULL, reg, strlen(reg));
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_TEST_SESSION_REG, incomplete_ctx, .init = setup, .fini = teardown) {
    rv = acvp_send_test_session_registration(ctx, reg, strlen(reg));
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * Because we aren't calling acvp_register which logs in the session, we expect
 * a 401 (unaurhtorized) which gives ACVP_TRANSPORT_FAIL
 */
Test(TRANSPORT_SEND_TEST_SESSION_REG, good, .init = setup_session_parameters, .fini = teardown) {
    rv = acvp_send_test_session_registration(ctx, little_reg, strlen(little_reg));
    cr_assert(rv == ACVP_TRANSPORT_FAIL);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_LOGIN, missing_reg, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_login(ctx, NULL, 0);
    cr_assert(rv == ACVP_NO_DATA);
}

/*
 * null ctx
 */
Test(TRANSPORT_SEND_LOGIN, missing_ctx) {
    rv = acvp_send_login(NULL, reg, strlen(reg));
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_LOGIN, incomplete_ctx, .init = setup, .fini = teardown) {
    rv = acvp_send_login(ctx, reg, strlen(reg));
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * Because we aren't calling acvp_register which builds login JSON, we expect
 * a 401 (unaurhtorized) which gives ACVP_TRANSPORT_FAIL
 */
Test(TRANSPORT_SEND_LOGIN, good, .init = setup_session_parameters, .fini = teardown) {
    rv = acvp_send_login(ctx, login_reg, strlen(login_reg));
    cr_assert(rv == ACVP_TRANSPORT_FAIL);
}

Test(TRANSPORT_FULL_INTERACTION, good, .init = setup_session_parameters, .fini = teardown) {
    add_hash_details_good();
    
    rv = acvp_register(ctx);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_process_tests(ctx);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_check_test_results(ctx);
    cr_assert(rv == ACVP_SUCCESS);
}

#if 0 // TODO NIST does not have these enabled via API, we don't have Cisco server yet
/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_VENDOR_REG, missing_reg, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_vendor_registration(ctx, NULL);
    cr_assert(rv == ACVP_NO_DATA);
}

/*
 * null ctx
 */
Test(TRANSPORT_SEND_VENDOR_REG, missing_ctx) {
    rv = acvp_send_vendor_registration(NULL, reg);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_VENDOR_REG, incomplete_ctx, .init = setup, .fini = teardown) {
    rv = acvp_send_vendor_registration(ctx, reg);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * Even if the vector set or test session doesn't exist and gives an err code,
 * we expect success because the API did what it was supposed to - POST
 */
Test(TRANSPORT_SEND_VENDOR_REG, good, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_vendor_registration(ctx, reg);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_MODULE_REG, missing_reg, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_module_registration(ctx, NULL);
    cr_assert(rv == ACVP_NO_DATA);
}

/*
 * null ctx
 */
Test(TRANSPORT_SEND_MODULE_REG, missing_ctx) {
    rv = acvp_send_module_registration(NULL, reg);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_MODULE_REG, incomplete_ctx, .init = setup, .fini = teardown) {
    rv = acvp_send_module_registration(ctx, reg);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * Even if the vector set or test session doesn't exist and gives an err code,
 * we expect success because the API did what it was supposed to - POST
 */
Test(TRANSPORT_SEND_MODULE_REG, good, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_module_registration(ctx, reg);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_DEP_REG, missing_reg, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_dep_registration(ctx, NULL);
    cr_assert(rv == ACVP_NO_DATA);
}

/*
 * null ctx
 */
Test(TRANSPORT_SEND_DEP_REG, missing_ctx) {
    rv = acvp_send_dep_registration(NULL, reg);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_DEP_REG, incomplete_ctx, .init = setup, .fini = teardown) {
    rv = acvp_send_dep_registration(ctx, reg);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * Even if the vector set or test session doesn't exist and gives an err code,
 * we expect success because the API did what it was supposed to - POST
 */
Test(TRANSPORT_SEND_DEP_REG, good, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_dep_registration(ctx, reg);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_OE_REG, missing_reg, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_oe_registration(ctx, NULL);
    cr_assert(rv == ACVP_NO_DATA);
}

/*
 * null ctx
 */
Test(TRANSPORT_SEND_OE_REG, missing_ctx) {
    rv = acvp_send_oe_registration(NULL, reg);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_OE_REG, incomplete_ctx, .init = setup, .fini = teardown) {
    rv = acvp_send_oe_registration(ctx, reg);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * Even if the vector set or test session doesn't exist and gives an err code,
 * we expect success because the API did what it was supposed to - POST
 */
Test(TRANSPORT_SEND_OE_REG, good, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "demo.acvts.nist.gov", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_oe_registration(ctx, reg);
    cr_assert(rv == ACVP_SUCCESS);
}
#endif

#endif
