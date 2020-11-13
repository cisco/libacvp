/** @file */
/*
 * Copyright (c) 2020, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#ifndef ACVP_OFFLINE
#include "ut_common.h"
#include "acvp/acvp_lcl.h"

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
static void test_setup_session_parameters(void)
{
    setup_empty_ctx(&ctx);
    
    server = "noserver";
    port = 443;
    path_segment = "/acvp/v1/";
    api_context = "acvp/";
    ca_chain_file = NULL;
    cert_file = NULL;
    key_file = NULL;

    acvp_set_server(ctx, server, port);
    acvp_set_cacerts(ctx, ca_chain_file);
    acvp_set_certkey(ctx, cert_file, key_file);
    acvp_set_path_segment(ctx, path_segment);
    rv = acvp_set_api_context(ctx, api_context);
    acvp_set_2fa_callback(ctx, &dummy_totp);
}

#ifdef TEST_TRANSPORT
static void add_hash_details_good(void) {
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA1, ACVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA512, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA512, ACVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    cr_assert(rv == ACVP_SUCCESS);
}
#endif
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
    rv = acvp_set_server(ctx, "noserver", 443);
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
    rv = acvp_set_server(ctx, "noserver", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_retrieve_expected_result(ctx, vsid_url);
    cr_assert(rv == ACVP_TRANSPORT_FAIL);

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
    rv = acvp_set_server(ctx, "noserver", 443);
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
    rv = acvp_set_server(ctx, "noserver", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_retrieve_vector_set(ctx, vsid_url);
    cr_assert(rv == ACVP_TRANSPORT_FAIL);

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
    rv = acvp_set_server(ctx, "noserver", 443);
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
    rv = acvp_set_server(ctx, "noserver", 443);
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
    rv = acvp_set_server(ctx, "noserver", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_test_session_registration(ctx, little_reg, strlen(little_reg));
    cr_assert(rv == ACVP_MISSING_ARG);

    rv = acvp_retrieve_vector_set_result(ctx, vsid_url);
    cr_assert(rv == ACVP_TRANSPORT_FAIL);

}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_TEST_SESSION_REG, missing_reg, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "noserver", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_test_session_registration(ctx, NULL, 0);
    cr_assert(rv == ACVP_MISSING_ARG);

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
Test(TRANSPORT_SEND_TEST_SESSION_REG, good, .init = test_setup_session_parameters, .fini = teardown) {
    rv = acvp_send_test_session_registration(ctx, little_reg, strlen(little_reg));
#ifdef TEST_TRANSPORT
    cr_assert(rv == ACVP_TRANSPORT_FAIL);
#endif
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_LOGIN, missing_reg, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "noserver", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_login(ctx, NULL, 0);
    cr_assert(rv == ACVP_MISSING_ARG);

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
Test(TRANSPORT_SEND_LOGIN, good, .init = test_setup_session_parameters, .fini = teardown) {
    rv = acvp_send_login(ctx, login_reg, strlen(login_reg));
#ifdef TEST_TRANSPORT
    cr_assert(rv == ACVP_TRANSPORT_FAIL);
#endif
}

#if 0
Test(TRANSPORT_FULL_INTERACTION, good, .init = test_setup_session_parameters, .fini = teardown) {
    add_hash_details_good();
    
    rv = acvp_register(ctx);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_process_tests(ctx);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_check_test_results(ctx);
    cr_assert(rv == ACVP_SUCCESS);
}
#endif

/*
 * Exercise acvp_transport_post logic
 * 
 */
Test(TRANSPORT_POST, good, .init = test_setup_session_parameters, .fini = teardown) {
    char *save_ptr = NULL;
    int save_int = 0;
    rv = acvp_transport_post(NULL, "uri", "data", 4);
    cr_assert(rv == ACVP_NO_CTX);

    save_int = ctx->server_port;
    ctx->server_port = 0;
    rv = acvp_transport_post(ctx, "uri", "data", 4);
    cr_assert(rv == ACVP_MISSING_ARG);

    ctx->server_port = save_int;
    
    save_ptr = ctx->server_name;
    ctx->server_name = NULL;
    rv = acvp_transport_post(ctx, "uri", "data", 4);
    cr_assert(rv == ACVP_MISSING_ARG);

    ctx->server_name = save_ptr;

    rv = acvp_transport_post(ctx, NULL, "data", 4);
    cr_assert(rv == ACVP_MISSING_ARG);

#ifdef TEST_TRANSPORT
    rv = acvp_transport_post(ctx, "uri", "data", 4);
    cr_assert(rv == ACVP_TRANSPORT_FAIL);
#endif
}

/*
 * Exercise acvp_transport_put logic
 * 
 */
Test(TRANSPORT_PUT, good, .init = test_setup_session_parameters, .fini = teardown) {
    char *save_ptr = NULL;
    int save_int = 0;
    rv = acvp_transport_put(NULL, "uri", "data", 4);
    cr_assert(rv == ACVP_NO_CTX);

    save_int = ctx->server_port;
    ctx->server_port = 0;
    rv = acvp_transport_put(ctx, "uri", "data", 4);
    cr_assert(rv == ACVP_MISSING_ARG);

    ctx->server_port = save_int;
    
    save_ptr = ctx->server_name;
    ctx->server_name = NULL;
    rv = acvp_transport_put(ctx, "uri", "data", 4);
    cr_assert(rv == ACVP_MISSING_ARG);

    ctx->server_name = save_ptr;

    rv = acvp_transport_put(ctx, NULL, "data", 4);
    cr_assert(rv == ACVP_MISSING_ARG);

#ifdef TEST_TRANSPORT
    rv = acvp_transport_put(ctx, "uri", "data", 4);
    cr_assert(rv == ACVP_TRANSPORT_FAIL);
#endif
}

/*
 * Exercise acvp_transport_put_validation logic
 * 
 */
Test(TRANSPORT_PUT_VALIDATION, good, .init = test_setup_session_parameters, .fini = teardown) {
    char *save_ptr = NULL;
    int save_int = 0;

    rv = acvp_transport_put_validation(NULL, "data", 4);
    cr_assert(rv == ACVP_NO_CTX);

    save_int = ctx->server_port;
    ctx->server_port = 0;
    rv = acvp_transport_put_validation(ctx, "data", 4);
    cr_assert(rv == ACVP_MISSING_ARG);

    ctx->server_port = save_int;
    
    save_ptr = ctx->server_name;
    ctx->server_name = NULL;
    rv = acvp_transport_put_validation(ctx, "data", 4);
    cr_assert(rv == ACVP_MISSING_ARG);

    ctx->server_name = save_ptr;

    rv = acvp_transport_put_validation(ctx, NULL, 4);
    cr_assert(rv == ACVP_INVALID_ARG);

    rv = acvp_transport_put_validation(ctx, "data", 4);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * Exercise acvp_transport_get logic
 * 
 */
Test(TRANSPORT_GET, good, .init = test_setup_session_parameters, .fini = teardown) {
    char *save_ptr = NULL, *key = NULL, *value = NULL;
    int save_int = 0;
    ACVP_KV_LIST *parms = NULL;

    rv = acvp_transport_get(NULL, "uri", parms);
    cr_assert(rv == ACVP_NO_CTX);

    save_int = ctx->server_port;
    ctx->server_port = 0;
    rv = acvp_transport_get(ctx, "uri", parms);
    cr_assert(rv == ACVP_MISSING_ARG);

    ctx->server_port = save_int;
    
    save_ptr = ctx->server_name;
    ctx->server_name = NULL;
    rv = acvp_transport_get(ctx, "uri", parms);
    cr_assert(rv == ACVP_MISSING_ARG);

    ctx->server_name = save_ptr;

    rv = acvp_transport_get(ctx, NULL, parms);
    cr_assert(rv == ACVP_MISSING_ARG);


    key = calloc(strlen("this is the key") + 1, sizeof(char));
    value = calloc(strlen("value") + 1, sizeof(char));
    memcpy(value, "value", 5);
    memcpy(key, "This is the key", 15);
    rv = acvp_kv_list_append(&parms, key, value);

#ifdef TEST_TRANSPORT
    rv = acvp_transport_get(ctx, "uri", parms);
    cr_assert(rv == ACVP_TRANSPORT_FAIL);
#endif
    acvp_kv_list_free(parms);
    free(key);
    free(value);
    
}


#if 0 // TODO NIST does not have these enabled via API, we don't have Cisco server yet
/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_VENDOR_REG, missing_reg, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "noserver", 443);
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
    rv = acvp_set_server(ctx, "noserver", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_vendor_registration(ctx, reg);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_MODULE_REG, missing_reg, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "noserver", 443);
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
    rv = acvp_set_server(ctx, "noserver", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_module_registration(ctx, reg);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_DEP_REG, missing_reg, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "noserver", 443);
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
    rv = acvp_set_server(ctx, "noserver", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_dep_registration(ctx, reg);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * missing vector set id url
 */
Test(TRANSPORT_SEND_OE_REG, missing_reg, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "noserver", 443);
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
    rv = acvp_set_server(ctx, "noserver", 443);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_send_oe_registration(ctx, reg);
    cr_assert(rv == ACVP_SUCCESS);
}
#endif

#endif //ACVP_OFFLINE
