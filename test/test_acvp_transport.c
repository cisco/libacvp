/** @file */
/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#ifndef ACVP_OFFLINE
#include "ut_common.h"
#include "acvp/acvp_lcl.h"
// Test group declarations
TEST_GROUP(TRANSPORT_DELETE);
TEST_GROUP(TRANSPORT_GET);
TEST_GROUP(TRANSPORT_POST);
TEST_GROUP(TRANSPORT_PUT);
TEST_GROUP(TRANSPORT_PUT_VALIDATION);
TEST_GROUP(TRANSPORT_RETRIEVE_RESULT);
TEST_GROUP(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS);
TEST_GROUP(TRANSPORT_RETRIEVE_VECTOR_SET);
#ifdef TEST_TRANSPORT
TEST_GROUP(TRANSPORT_SEND_VENDOR_REG);
TEST_GROUP(TRANSPORT_SEND_OE_REG);
TEST_GROUP(TRANSPORT_SEND_MODULE_REG);
TEST_GROUP(TRANSPORT_SEND_DEP_REG);
TEST_GROUP(TRANSPORT_FULL_INTERACTION);
#endif
TEST_GROUP(TRANSPORT_SEND_LOGIN);
TEST_GROUP(TRANSPORT_SEND_TEST_SESSION_REG);
TEST_GROUP(TRANSPORT_SUBMIT_VECTOR_SET);

static char *vsid_url = "/acvp/v1/testSessions/0/vectorSets/0";
static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static char *reg = "{}";
static char *little_reg = "[{\"acvVersion\": \"0.5\"},{\"algorithms\": [{\"algorithm\": \"SHA-1\",\"inBit\": false,\n"
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
static char *login_reg = "[\n"
                  "    {\n"
                  "        \"acvVersion\": \"0.5\"\n"
                  "    },\n"
                  "    {\n"
                  "        \"password\": \"31135756\"\n"
                  "    }\n"
                  "]";

static char *server = NULL;
static int port = 0;
static char *ca_chain_file = NULL;
static char *cert_file = NULL;
static char *key_file = NULL;
static char *path_segment = NULL;
static char *api_context = NULL;

/*
 * Read the operational parameters from the various environment
 * variables.
 */
static void transport_send_test_session_reg_setup_helper(void) {
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

TEST_SETUP(TRANSPORT_SEND_TEST_SESSION_REG) {
    transport_send_test_session_reg_setup_helper();
}

#ifdef TEST_TRANSPORT
static void add_hash_details_good(void) {
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA1, ACVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA512, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA512, ACVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}
#endif
static void transport_retrieve_sample_answers_setup_helper(void) {
    setup_empty_ctx(&ctx);
}

TEST_SETUP(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS) {
    transport_retrieve_sample_answers_setup_helper();
}

static void transport_retrieve_sample_answers_tear_down_helper(void) {
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
}

TEST_TEAR_DOWN(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS) {
    transport_retrieve_sample_answers_tear_down_helper();
}
// Wrapper setup/teardown for groups sharing fixtures

TEST_SETUP(TRANSPORT_DELETE) {
    transport_send_test_session_reg_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_DELETE) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_SETUP(TRANSPORT_FULL_INTERACTION) {
    transport_send_test_session_reg_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_FULL_INTERACTION) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_SETUP(TRANSPORT_GET) {
    transport_send_test_session_reg_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_GET) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_SETUP(TRANSPORT_POST) {
    transport_send_test_session_reg_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_POST) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_SETUP(TRANSPORT_PUT) {
    transport_send_test_session_reg_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_PUT) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_SETUP(TRANSPORT_PUT_VALIDATION) {
    transport_send_test_session_reg_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_PUT_VALIDATION) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_SETUP(TRANSPORT_RETRIEVE_RESULT) {
    transport_retrieve_sample_answers_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_RETRIEVE_RESULT) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_SETUP(TRANSPORT_RETRIEVE_VECTOR_SET) {
    transport_retrieve_sample_answers_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_RETRIEVE_VECTOR_SET) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_SETUP(TRANSPORT_SEND_DEP_REG) {
    transport_retrieve_sample_answers_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_SEND_DEP_REG) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_SETUP(TRANSPORT_SEND_LOGIN) {
    transport_send_test_session_reg_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_SEND_LOGIN) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_SETUP(TRANSPORT_SEND_MODULE_REG) {
    transport_retrieve_sample_answers_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_SEND_MODULE_REG) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_SETUP(TRANSPORT_SEND_OE_REG) {
    transport_retrieve_sample_answers_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_SEND_OE_REG) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_TEAR_DOWN(TRANSPORT_SEND_TEST_SESSION_REG) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_SETUP(TRANSPORT_SEND_VENDOR_REG) {
    transport_retrieve_sample_answers_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_SEND_VENDOR_REG) {
    transport_retrieve_sample_answers_tear_down_helper();
}

TEST_SETUP(TRANSPORT_SUBMIT_VECTOR_SET) {
    transport_retrieve_sample_answers_setup_helper();
}

TEST_TEAR_DOWN(TRANSPORT_SUBMIT_VECTOR_SET) {
    transport_retrieve_sample_answers_tear_down_helper();
}

// ctx has not set server and port
TEST(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS, incomplete_ctx) {
    rv = acvp_retrieve_expected_result(ctx, vsid_url);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

// missing vector set id url
TEST(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS, missing_vsid_url) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_retrieve_expected_result(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

// null ctx
TEST(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS, missing_ctx) {
    rv = acvp_retrieve_expected_result(NULL, vsid_url);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

/*
 * Even if the vector set or test session doesn't exist and gives a 404,
 * we expect success because the API did what it was supposed to - GET sample
 * answers
 */
TEST(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS, good) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_retrieve_expected_result(ctx, vsid_url);
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);

}

// ctx has not set server and port
TEST(TRANSPORT_RETRIEVE_VECTOR_SET, incomplete_ctx) {
    rv = acvp_retrieve_vector_set(ctx, vsid_url);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

// missing vector set id url
TEST(TRANSPORT_RETRIEVE_VECTOR_SET, missing_vsid_url) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_retrieve_vector_set(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

// null ctx
TEST(TRANSPORT_RETRIEVE_VECTOR_SET, missing_ctx) {
    rv = acvp_retrieve_vector_set(NULL, vsid_url);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

/*
 * Even if the vector set or test session doesn't exist and gives a 404,
 * we expect success because the API did what it was supposed to - GET sample
 * answers
 */
TEST(TRANSPORT_RETRIEVE_VECTOR_SET, good) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_retrieve_vector_set(ctx, vsid_url);
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);

}

// ctx has not set server and port
TEST(TRANSPORT_SUBMIT_VECTOR_SET, incomplete_ctx) {
    rv = acvp_submit_vector_responses(ctx, vsid_url);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

// null ctx
TEST(TRANSPORT_SUBMIT_VECTOR_SET, missing_ctx) {
    rv = acvp_submit_vector_responses(NULL, NULL);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// missing vsid_url
TEST(TRANSPORT_SUBMIT_VECTOR_SET, missing_vsid) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_submit_vector_responses(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

// ctx has not set server and port
TEST(TRANSPORT_RETRIEVE_RESULT, incomplete_ctx) {
    rv = acvp_retrieve_vector_set_result(ctx, vsid_url);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

// missing vector set id url
TEST(TRANSPORT_RETRIEVE_RESULT, missing_vsid_url) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_retrieve_vector_set_result(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

// null ctx
TEST(TRANSPORT_RETRIEVE_RESULT, missing_ctx) {
    rv = acvp_retrieve_vector_set_result(NULL, vsid_url);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

/*
 * Even if the vector set or test session doesn't exist and gives a 404,
 * we expect success because the API did what it was supposed to - GET sample
 * answers
 */
TEST(TRANSPORT_RETRIEVE_RESULT, good) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_send_test_session_registration(ctx, little_reg, strlen(little_reg));
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    rv = acvp_retrieve_vector_set_result(ctx, vsid_url);
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);

}

// missing vector set id url
TEST(TRANSPORT_SEND_TEST_SESSION_REG, missing_reg) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_send_test_session_registration(ctx, NULL, 0);
    TEST_ASSERT_EQUAL(ACVP_NO_DATA, rv);

}

// null ctx
TEST(TRANSPORT_SEND_TEST_SESSION_REG, missing_ctx) {
    rv = acvp_send_test_session_registration(NULL, reg, strlen(reg));
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// missing vector set id url
TEST(TRANSPORT_SEND_TEST_SESSION_REG, incomplete_ctx) {
    rv = acvp_send_test_session_registration(ctx, reg, strlen(reg));
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
}

/*
 * Because we aren't calling acvp_register which logs in the session, we expect
 * a 401 (unaurhtorized) which gives ACVP_TRANSPORT_FAIL
 */
TEST(TRANSPORT_SEND_TEST_SESSION_REG, good) {
    rv = acvp_send_test_session_registration(ctx, little_reg, strlen(little_reg));
#ifdef TEST_TRANSPORT
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
#endif
}

// missing vector set id url
TEST(TRANSPORT_SEND_LOGIN, missing_reg) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_send_login(ctx, NULL, 0);
    TEST_ASSERT_EQUAL(ACVP_NO_DATA, rv);

}

// null ctx
TEST(TRANSPORT_SEND_LOGIN, missing_ctx) {
    rv = acvp_send_login(NULL, reg, strlen(reg));
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// missing vector set id url
TEST(TRANSPORT_SEND_LOGIN, incomplete_ctx) {
    rv = acvp_send_login(ctx, reg, strlen(reg));
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
}

/*
 * Because we aren't calling acvp_register which builds login JSON, we expect
 * a 401 (unaurhtorized) which gives ACVP_TRANSPORT_FAIL
 */
TEST(TRANSPORT_SEND_LOGIN, good) {
    rv = acvp_send_login(ctx, login_reg, strlen(login_reg));
#ifdef TEST_TRANSPORT
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
#endif
}

#if 0
TEST(TRANSPORT_FULL_INTERACTION, good) {
    add_hash_details_good();
    
    rv = acvp_register(ctx);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_process_tests(ctx);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_check_test_results(ctx);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}
#endif

/*
 * Exercise acvp_transport_post logic
 * 
 */
TEST(TRANSPORT_POST, good) {
    char *save_ptr = NULL;
    int save_int = 0;
    rv = acvp_transport_post(NULL, "uri", "data", 4);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    save_int = ctx->server_port;
    ctx->server_port = 0;
    rv = acvp_transport_post(ctx, "uri", "data", 4);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    ctx->server_port = save_int;
    
    save_ptr = ctx->server_name;
    ctx->server_name = NULL;
    rv = acvp_transport_post(ctx, "uri", "data", 4);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    ctx->server_name = save_ptr;

    rv = acvp_transport_post(ctx, NULL, "data", 4);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

#ifdef TEST_TRANSPORT
    rv = acvp_transport_post(ctx, "uri", "data", 4);
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
#endif
}

/*
 * Exercise acvp_transport_put logic
 * 
 */
TEST(TRANSPORT_PUT, good) {
    char *save_ptr = NULL;
    int save_int = 0;
    rv = acvp_transport_put(NULL, "uri", "data", 4);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    save_int = ctx->server_port;
    ctx->server_port = 0;
    rv = acvp_transport_put(ctx, "uri", "data", 4);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    ctx->server_port = save_int;
    
    save_ptr = ctx->server_name;
    ctx->server_name = NULL;
    rv = acvp_transport_put(ctx, "uri", "data", 4);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    ctx->server_name = save_ptr;

    rv = acvp_transport_put(ctx, NULL, "data", 4);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

#ifdef TEST_TRANSPORT
    rv = acvp_transport_put(ctx, "uri", "data", 4);
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
#endif
}

/*
 * Exercise acvp_transport_put_validation logic
 * 
 */
TEST(TRANSPORT_PUT_VALIDATION, good) {
    char *save_ptr = NULL;
    int save_int = 0;

    rv = acvp_transport_put_validation(NULL, "data", 4);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    save_int = ctx->server_port;
    ctx->server_port = 0;
    rv = acvp_transport_put_validation(ctx, "data", 4);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    ctx->server_port = save_int;
    
    save_ptr = ctx->server_name;
    ctx->server_name = NULL;
    rv = acvp_transport_put_validation(ctx, "data", 4);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    ctx->server_name = save_ptr;

    rv = acvp_transport_put_validation(ctx, NULL, 4);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_transport_put_validation(ctx, "data", 4);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

/*
 * Exercise acvp_transport_get logic
 * 
 */
TEST(TRANSPORT_GET, good) {
    char *save_ptr = NULL, *key = NULL, *value = NULL;
    int save_int = 0;
    ACVP_KV_LIST *parms = NULL;

    rv = acvp_transport_get(NULL, "uri", parms);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    save_int = ctx->server_port;
    ctx->server_port = 0;
    rv = acvp_transport_get(ctx, "uri", parms);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    ctx->server_port = save_int;
    
    save_ptr = ctx->server_name;
    ctx->server_name = NULL;
    rv = acvp_transport_get(ctx, "uri", parms);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    ctx->server_name = save_ptr;

    rv = acvp_transport_get(ctx, NULL, parms);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    key = calloc(strlen("this is the key") + 1, sizeof(char));
    value = calloc(strlen("value") + 1, sizeof(char));
    memcpy(value, "value", 5);
    memcpy(key, "This is the key", 15);
    rv = acvp_kv_list_append(&parms, key, value);

#ifdef TEST_TRANSPORT
    rv = acvp_transport_get(ctx, "uri", parms);
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
#endif
    acvp_kv_list_free(parms);
    free(key);
    free(value);
    
}

/*
 * Exercise acvp_transport_delete logic
 *
 */
TEST(TRANSPORT_DELETE, good) {
    char *save_ptr = NULL;
    int save_int = 0;

    rv = acvp_transport_delete(NULL, "uri");
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    save_int = ctx->server_port;
    ctx->server_port = 0;
    rv = acvp_transport_delete(ctx, "uri");
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    ctx->server_port = save_int;

    save_ptr = ctx->server_name;
    ctx->server_name = NULL;
    rv = acvp_transport_delete(ctx, "uri");
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

    ctx->server_name = save_ptr;

    rv = acvp_transport_delete(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);

#ifdef TEST_TRANSPORT
    rv = acvp_transport_delete(ctx, "uri");
    TEST_ASSERT_EQUAL(ACVP_TRANSPORT_FAIL, rv);
#endif

}

#if 0 // TODO NIST does not have these enabled via API, we don't have Cisco server yet
// missing vector set id url
TEST(TRANSPORT_SEND_VENDOR_REG, missing_reg) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_send_vendor_registration(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_NO_DATA, rv);
}

// null ctx
TEST(TRANSPORT_SEND_VENDOR_REG, missing_ctx) {
    rv = acvp_send_vendor_registration(NULL, reg);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// missing vector set id url
TEST(TRANSPORT_SEND_VENDOR_REG, incomplete_ctx) {
    rv = acvp_send_vendor_registration(ctx, reg);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

/*
 * Even if the vector set or test session doesn't exist and gives an err code,
 * we expect success because the API did what it was supposed to - POST
 */
TEST(TRANSPORT_SEND_VENDOR_REG, good) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_send_vendor_registration(ctx, reg);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// missing vector set id url
TEST(TRANSPORT_SEND_MODULE_REG, missing_reg) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_send_module_registration(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_NO_DATA, rv);
}

// null ctx
TEST(TRANSPORT_SEND_MODULE_REG, missing_ctx) {
    rv = acvp_send_module_registration(NULL, reg);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// missing vector set id url
TEST(TRANSPORT_SEND_MODULE_REG, incomplete_ctx) {
    rv = acvp_send_module_registration(ctx, reg);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

/*
 * Even if the vector set or test session doesn't exist and gives an err code,
 * we expect success because the API did what it was supposed to - POST
 */
TEST(TRANSPORT_SEND_MODULE_REG, good) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_send_module_registration(ctx, reg);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// missing vector set id url
TEST(TRANSPORT_SEND_DEP_REG, missing_reg) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_send_dep_registration(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_NO_DATA, rv);
}

// null ctx
TEST(TRANSPORT_SEND_DEP_REG, missing_ctx) {
    rv = acvp_send_dep_registration(NULL, reg);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// missing vector set id url
TEST(TRANSPORT_SEND_DEP_REG, incomplete_ctx) {
    rv = acvp_send_dep_registration(ctx, reg);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

/*
 * Even if the vector set or test session doesn't exist and gives an err code,
 * we expect success because the API did what it was supposed to - POST
 */
TEST(TRANSPORT_SEND_DEP_REG, good) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_send_dep_registration(ctx, reg);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// missing vector set id url
TEST(TRANSPORT_SEND_OE_REG, missing_reg) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_send_oe_registration(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_NO_DATA, rv);
}

// null ctx
TEST(TRANSPORT_SEND_OE_REG, missing_ctx) {
    rv = acvp_send_oe_registration(NULL, reg);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// missing vector set id url
TEST(TRANSPORT_SEND_OE_REG, incomplete_ctx) {
    rv = acvp_send_oe_registration(ctx, reg);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

/*
 * Even if the vector set or test session doesn't exist and gives an err code,
 * we expect success because the API did what it was supposed to - POST
 */
TEST(TRANSPORT_SEND_OE_REG, good) {
    rv = acvp_set_server(ctx, "noserver", 443);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_send_oe_registration(ctx, reg);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}
#endif

#endif //ACVP_OFFLINE
