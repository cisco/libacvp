/** @file */
/*
 * Copyright (c) 2020, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include "ut_common.h"
#include "acvp/acvp_lcl.h"

ACVP_CTX *ctx;

/*
 * Try to pass variety of parms to acvp_log_msg
 */
Test(LogMsg, null_ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    acvp_log_msg(NULL, ACVP_LOG_LVL_MAX, "test");
    cr_assert(rv == ACVP_SUCCESS);

    setup_empty_ctx(&ctx);
    acvp_log_msg(ctx, ACVP_LOG_LVL_MAX+1, "test");
    cr_assert(rv == ACVP_SUCCESS);

    acvp_log_msg(ctx, ACVP_LOG_LVL_MAX, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    
    acvp_cleanup(ctx);
}

/*
 * Try to pass NULL to acvp_cleanup
 */
Test(Cleanup, null_ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    acvp_cleanup(NULL);
    cr_assert(rv == ACVP_SUCCESS);

}

/*
 * Try to pass valid and invalid alg to acvp_lookup_cipher_revision
 */
Test(LookupCipherRevision, null_ctx) {
    const char *ptr = NULL;

    ptr = acvp_lookup_cipher_revision(ACVP_KAS_FFC_NOCOMP);
    cr_assert(ptr != NULL);

    ptr = acvp_lookup_cipher_revision(ACVP_CIPHER_END);
    cr_assert_null(ptr);

    ptr = acvp_lookup_cipher_revision(ACVP_CIPHER_START);
    cr_assert_null(ptr);

}


/*
 * Try to pass acvp_locate_cap_entry NULL ctx
 */
Test(LocateCapEntry, null_ctx) {
    ACVP_CAPS_LIST *list;

    list = acvp_locate_cap_entry(NULL, ACVP_AES_GCM);
    cr_assert_null(list);
}


Test(LookupCipherIndex, null_param) {
    ACVP_CIPHER cipher;
    cipher = acvp_lookup_cipher_index(NULL);
    cr_assert(cipher == ACVP_CIPHER_START);

    cipher = acvp_lookup_cipher_index("Bad Name");
    cr_assert(cipher == ACVP_CIPHER_START);

    cipher = acvp_lookup_cipher_index(ACVP_ALG_AES_CBC);
    cr_assert(cipher == ACVP_AES_CBC);

}

Test(LookupRSARandPQIndex, null_param) {
    int rv = acvp_lookup_rsa_randpq_index(NULL);
    cr_assert(!rv);
}

Test(JsonSerializeToFilePrettyW, null_param) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *value;

    rv = acvp_json_serialize_to_file_pretty_w(NULL, "test");
    cr_assert(rv == ACVP_JSON_ERR);

    value = json_value_init_object();
    rv = acvp_json_serialize_to_file_pretty_w(value, NULL);
    cr_assert(rv == ACVP_INVALID_ARG);

    rv = acvp_json_serialize_to_file_pretty_w(value, "no_file");
    cr_assert(rv == ACVP_SUCCESS);
    
    json_value_free(value);
}

Test(JsonSerializeToFilePrettyA, null_param) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *value;

    rv = acvp_json_serialize_to_file_pretty_a(NULL, "test");
    cr_assert(rv == ACVP_SUCCESS);

    value = json_value_init_object();
    rv = acvp_json_serialize_to_file_pretty_a(value, NULL);
    cr_assert(rv == ACVP_INVALID_ARG);

    rv = acvp_json_serialize_to_file_pretty_a(value, "no_file");
    cr_assert(rv == ACVP_SUCCESS);
    
    json_value_free(value);
}

/*
 * Exercise string_fits logic
 */
Test(StringFits, null_ctx) {
     int rc = 0;

    rc = string_fits("tests", 3);
    cr_assert(rc == 0);

    rc = string_fits("test", 6);
    cr_assert(rc == 1);
}

/*
 * Exercise is_valid_rsa_mod logic
 */
Test(ValidRsaMod, null_ctx) {
     ACVP_RESULT rv = ACVP_SUCCESS;

    rv = is_valid_rsa_mod(4096);
    cr_assert(rv == ACVP_SUCCESS);

    rv = is_valid_rsa_mod(4097);
    cr_assert(rv == ACVP_INVALID_ARG);
}

/*
 * Exercise acvp_lookup_error_string logic
 */
Test(LookupErrorString, null_ctx) {
    const char *str = NULL;
    char *dup = "ctx already initialized";
    char *ukn = "Unknown error";

    str = acvp_lookup_error_string(ACVP_DUPLICATE_CTX);
    cr_assert(!strncmp(str, dup, strlen(dup)));

    str = acvp_lookup_error_string(ACVP_RESULT_MAX);
    cr_assert(!strncmp(str, ukn, strlen(ukn)));
}


/*
 * Exercise acvp_kv_list_append, acvp_kvlist_free and acvp_free_str_list logic
 */
Test(KvList, null_ctx) {
    ACVP_KV_LIST *kv = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *key = NULL, *value = NULL;
    ACVP_STRING_LIST *list = NULL;

    rv = acvp_kv_list_append(NULL, NULL, NULL);
    cr_assert(rv == ACVP_INVALID_ARG);

    rv = acvp_kv_list_append(&kv, NULL, NULL);
    cr_assert(rv == ACVP_INVALID_ARG);

    rv = acvp_kv_list_append(&kv, "this is the key", NULL);
    cr_assert(rv == ACVP_INVALID_ARG);

    key = calloc(strlen("this is the key") + 1, sizeof(char));
    value = calloc(strlen("value") + 1, sizeof(char));
    memcpy(value, "value", 5);
    memcpy(key, "This is the key", 15);
    rv = acvp_kv_list_append(&kv, key, value);
    cr_assert(rv == ACVP_SUCCESS);

    acvp_kv_list_free(NULL);
    acvp_kv_list_free(kv);
    acvp_free_str_list(NULL);
    acvp_free_str_list(&list);
    list = calloc(sizeof(ACVP_STRING_LIST), sizeof(char));
    list->string = key;
    acvp_free_str_list(&list);
    cr_assert(list == NULL);
    free(value);
}

/*
 * Exercise acvp_get_obj_from_rsp logic
 */
Test(GetObjFromRsp, null_ctx) {
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;

    obj = acvp_get_obj_from_rsp(NULL, NULL);
    cr_assert(obj == NULL);

    setup_empty_ctx(&ctx);
    obj = acvp_get_obj_from_rsp(ctx, NULL);
    cr_assert(obj == NULL);

    val = json_parse_file("json/aes/aes.json");
    obj = acvp_get_obj_from_rsp(ctx, val);
    cr_assert(obj != NULL);
    
    json_value_free(val);
    acvp_free_test_session(ctx);
}

