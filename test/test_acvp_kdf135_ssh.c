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

TEST_GROUP(Kdf135SshApi);
TEST_GROUP(Kdf135SshFail);
TEST_GROUP(Kdf135SshFunc);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

TEST_SETUP(Kdf135SshApi) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135SshApi) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135SshFail) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135SshFail) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST_SETUP(Kdf135SshFunc) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(Kdf135SshFunc) {
    if (ctx) teardown_ctx(&ctx);
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
}

TEST(Kdf135SshApi, null_ctx) {
    int flags = 0;

    val = json_parse_file("json/kdf135_ssh/kdf135_ssh1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with unregistered ctx */
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);

    /* Enable capabilites */
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    //Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 |ACVP_SHA256
    | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    /* Test with NULL ctx */
    rv  = acvp_kdf135_ssh_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);

    /* Test with NULL JSON object */
    rv  = acvp_kdf135_ssh_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_MALFORMED_JSON, rv);
}

// Test kdf135 SSH handler functionally
TEST(Kdf135SshFunc, null_ctx) {
    int flags = 0;

    /* Enable capabilites */
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    //Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 |ACVP_SHA256
    | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    /* This is a proper JSON, positive test TDES SHA-1 */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);

    /* This is a corrupt JSON, missing cipher */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    
    /* This is a corrupt JSON, missing hashAlg */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    
    /* This is a corrupt JSON, failed to include k */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    
    /* This is a corrupt JSON, failed to include h */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    
    /* This is a corrupt JSON, failed to include session_id */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);

    /* This is a corrupt JSON, corrupt algorithm */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    json_value_free(val);

    /* This is a corrupt JSON, failed to include tests */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);

    /* This is a corrupt JSON, failed to include testGroups */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);

    /* This is a corrupt JSON, failed to include tc_id */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);

    /* This is a proper JSON, positive test AES-128 thru 256 SHA-224 thru SHA-512 */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);

    /* This is a corrupt JSON, failed to include tgid */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
}

// The key: crypto handler operation fails on last crypto call
TEST(Kdf135SshFail, cryptoFail1) {
    force_handler_failure = 1;
    int flags = 0;

    /* Enable capabilites */
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    //Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 |ACVP_SHA256
    | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    val = json_parse_file("json/kdf135_ssh/kdf135_ssh1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on first iteration */
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    force_handler_failure = 0;
}

// The key: crypto handler operation fails on last crypto call
TEST(Kdf135SshFail, cryptoFail2) {
    force_handler_failure = 1;
    int flags = 0;

    /* Enable capabilites */
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    //Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 |ACVP_SHA256
    | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    val = json_parse_file("json/kdf135_ssh/kdf135_ssh1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on last iteration */
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    force_handler_failure = 0;
}

// The key:"cipher" is missing in secong tg
TEST(Kdf135SshFail, tcidFail) {
    int flags = 0;

    /* Enable capabilites */
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    //Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 |ACVP_SHA256
    | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    val = json_parse_file("json/kdf135_ssh/kdf135_ssh13.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
}

// The key:"h" is missing in last tc
TEST(Kdf135SshFail, tcFail) {
    int flags = 0;

    /* Enable capabilites */
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    //Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 |ACVP_SHA256
    | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    val = json_parse_file("json/kdf135_ssh/kdf135_ssh14.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
}
