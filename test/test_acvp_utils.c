/** @file */
/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "ut_common.h"
#include "acvp/acvp_lcl.h"

TEST_GROUP(Cleanup);
TEST_GROUP(GetObjFromRsp);
TEST_GROUP(JsonSerializeToFilePrettyA);
TEST_GROUP(JsonSerializeToFilePrettyW);
TEST_GROUP(KvList);
TEST_GROUP(LocateCapEntry);
TEST_GROUP(LogMsg);
TEST_GROUP(LookupCipherIndex);
TEST_GROUP(LookupCipherRevision);
TEST_GROUP(LookupErrorString);
TEST_GROUP(LookupRSARandPQIndex);
TEST_GROUP(StringFits);
TEST_GROUP(ValidRsaMod);

static ACVP_CTX *ctx = NULL;

// Empty setup/teardown for groups without fixtures
TEST_SETUP(Cleanup) {}
TEST_TEAR_DOWN(Cleanup) {}

TEST_SETUP(GetObjFromRsp) {}
TEST_TEAR_DOWN(GetObjFromRsp) {}

TEST_SETUP(JsonSerializeToFilePrettyA) {}
TEST_TEAR_DOWN(JsonSerializeToFilePrettyA) {}

TEST_SETUP(JsonSerializeToFilePrettyW) {}
TEST_TEAR_DOWN(JsonSerializeToFilePrettyW) {}

TEST_SETUP(KvList) {}
TEST_TEAR_DOWN(KvList) {}

TEST_SETUP(LocateCapEntry) {}
TEST_TEAR_DOWN(LocateCapEntry) {}

TEST_SETUP(LogMsg) {}
TEST_TEAR_DOWN(LogMsg) {}

TEST_SETUP(LookupCipherIndex) {}
TEST_TEAR_DOWN(LookupCipherIndex) {}

TEST_SETUP(LookupCipherRevision) {}
TEST_TEAR_DOWN(LookupCipherRevision) {}

TEST_SETUP(LookupErrorString) {}
TEST_TEAR_DOWN(LookupErrorString) {}

TEST_SETUP(LookupRSARandPQIndex) {}
TEST_TEAR_DOWN(LookupRSARandPQIndex) {}

TEST_SETUP(StringFits) {}
TEST_TEAR_DOWN(StringFits) {}

TEST_SETUP(ValidRsaMod) {}
TEST_TEAR_DOWN(ValidRsaMod) {}

TEST(LogMsg, null_ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_CTX *test_ctx = NULL;

    acvp_log_msg(NULL, ACVP_LOG_LVL_MAX, __func__, __LINE__, "test");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    setup_empty_ctx(&test_ctx);
    acvp_log_msg(test_ctx, ACVP_LOG_LVL_MAX+1, __func__, __LINE__, "test");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    acvp_log_msg(test_ctx, ACVP_LOG_LVL_MAX, __func__, __LINE__, NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    if (test_ctx) teardown_ctx(&test_ctx);
}

// Try to pass NULL to acvp_cleanup
TEST(Cleanup, null_ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    acvp_cleanup(NULL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

}

// Try to pass valid and invalid alg to acvp_lookup_cipher_revision
TEST(LookupCipherRevision, null_ctx) {
    const char *ptr = NULL;

    ptr = acvp_lookup_cipher_revision(ACVP_KAS_FFC_NOCOMP);
    TEST_ASSERT_NOT_EQUAL(NULL, ptr);

    ptr = acvp_lookup_cipher_revision(ACVP_CIPHER_END);
    TEST_ASSERT_NULL(ptr);

    ptr = acvp_lookup_cipher_revision(ACVP_CIPHER_START);
    TEST_ASSERT_NULL(ptr);

}

// Try to pass acvp_locate_cap_entry NULL ctx
TEST(LocateCapEntry, null_ctx) {
    ACVP_CAPS_LIST *list;

    list = acvp_locate_cap_entry(NULL, ACVP_AES_GCM);
    TEST_ASSERT_NULL(list);
}

TEST(LookupCipherIndex, null_param) {
    ACVP_CIPHER cipher;
    cipher = acvp_lookup_cipher_index(NULL);
    TEST_ASSERT_EQUAL(ACVP_CIPHER_START, cipher);

    cipher = acvp_lookup_cipher_index("Bad Name");
    TEST_ASSERT_EQUAL(ACVP_CIPHER_START, cipher);

    cipher = acvp_lookup_cipher_index(ACVP_ALG_AES_CBC);
    TEST_ASSERT_EQUAL(ACVP_AES_CBC, cipher);

}

TEST(LookupRSARandPQIndex, null_param) {
    int rv = acvp_lookup_rsa_randpq_index(NULL);
    TEST_ASSERT_EQUAL(0, rv);  // Function returns 0 for NULL input (not found)
}

TEST(JsonSerializeToFilePrettyW, null_param) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *value;

    rv = acvp_json_serialize_to_file_pretty_w(NULL, "test");
    TEST_ASSERT_EQUAL(ACVP_JSON_ERR, rv);
    if (rv == ACVP_SUCCESS) {
        remove("test");
    }

    value = json_value_init_object();
    rv = acvp_json_serialize_to_file_pretty_w(value, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_json_serialize_to_file_pretty_w(value, "no_file");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    if (rv == ACVP_SUCCESS) {
        remove("no_file");
    }

    json_value_free(value);
}

TEST(JsonSerializeToFilePrettyA, null_param) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *value;

    rv = acvp_json_serialize_to_file_pretty_a(NULL, "test");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    if (rv == ACVP_SUCCESS) {
        remove("test");
    }

    value = json_value_init_object();
    rv = acvp_json_serialize_to_file_pretty_a(value, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_json_serialize_to_file_pretty_a(value, "no_file");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    if (rv == ACVP_SUCCESS) {
        remove("no_file");
    }

    json_value_free(value);
}

// Exercise string_fits logic
TEST(StringFits, null_ctx) {
     int rc = 0;

    rc = string_fits("tests", 3);
    TEST_ASSERT_EQUAL(0, rc);

    rc = string_fits("test", 6);
    TEST_ASSERT_EQUAL(1, rc);
}

// Exercise is_valid_rsa_mod logic
TEST(ValidRsaMod, null_ctx) {
     ACVP_RESULT rv = ACVP_SUCCESS;

    rv = is_valid_rsa_mod(4096);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = is_valid_rsa_mod(4097);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// Exercise acvp_lookup_error_string logic
TEST(LookupErrorString, null_ctx) {
    const char *str = NULL;
    char *dup = "ctx already initialized";
    char *ukn = "Unknown error";

    str = acvp_lookup_error_string(ACVP_CTX_NOT_EMPTY);
    TEST_ASSERT_TRUE(!strncmp(str, dup, strlen(dup)));

    str = acvp_lookup_error_string(ACVP_RESULT_MAX);
    TEST_ASSERT_TRUE(!strncmp(str, ukn, strlen(ukn)));
}

// Exercise acvp_kv_list_append, acvp_kvlist_free and acvp_free_str_list logic
TEST(KvList, null_ctx) {
    ACVP_KV_LIST *kv = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *key = NULL, *value = NULL;
    ACVP_STRING_LIST *list = NULL;

    rv = acvp_kv_list_append(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_kv_list_append(&kv, NULL, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_kv_list_append(&kv, "this is the key", NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    key = calloc(strlen("this is the key") + 1, sizeof(char));
    value = calloc(strlen("value") + 1, sizeof(char));
    memcpy(value, "value", 5);
    memcpy(key, "This is the key", 15);
    rv = acvp_kv_list_append(&kv, key, value);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    acvp_kv_list_free(NULL);
    acvp_kv_list_free(kv);
    acvp_free_str_list(NULL);
    acvp_free_str_list(&list);
    list = calloc(sizeof(ACVP_STRING_LIST), sizeof(char));
    list->string = key;
    acvp_free_str_list(&list);
    TEST_ASSERT_EQUAL(NULL, list);
    free(value);
}

// Exercise acvp_get_obj_from_rsp logic
TEST(GetObjFromRsp, null_ctx) {
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;

    obj = acvp_get_obj_from_rsp(NULL, NULL);
    TEST_ASSERT_EQUAL(NULL, obj);

    setup_empty_ctx(&ctx);
    obj = acvp_get_obj_from_rsp(ctx, NULL);
    TEST_ASSERT_EQUAL(NULL, obj);

    val = json_parse_file("json/aes/aes.json");
    obj = acvp_get_obj_from_rsp(ctx, val);
    TEST_ASSERT_NOT_EQUAL(NULL, obj);
    
    json_value_free(val);
    acvp_free_test_session(ctx);
}
