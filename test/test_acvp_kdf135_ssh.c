/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include "ut_common.h"
#include "acvp/acvp_lcl.h"

ACVP_CTX *ctx;
static char cvalue[] = "same";

/*
 * Test kdf135 SSH handler API inputs
 */
Test(Kdf135SshApi, null_ctx) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;
    int flags = 0;

    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kdf135_ssh/kdf135_ssh1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with unregistered ctx */
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);

    /* Enable capabilites */
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    //Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 |ACVP_SHA256
    | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);

    /* Test with NULL ctx */
    rv  = acvp_kdf135_ssh_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);

    /* Test with NULL JSON object */
    rv  = acvp_kdf135_ssh_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);

    teardown_ctx(&ctx);
    json_value_free(val);
}

/*
 * Test kdf135 SSH handler functionally
 */
Test(Kdf135SshFunc, null_ctx) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;
    int flags = 0;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    //Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 |ACVP_SHA256
    | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);


    /* This is a proper JSON, positive test TDES SHA-1 */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);

    /* This is a corrupt JSON, missing cipher */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, missing hashAlg */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, failed to include k */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, failed to include h */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, failed to include session_id */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* This is a corrupt JSON, corrupt algorithm */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);

    /* This is a corrupt JSON, failed to include tests */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* This is a corrupt JSON, failed to include testGroups */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* This is a corrupt JSON, failed to include tc_id */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);

    /* This is a proper JSON, positive test AES-128 thru 256 SHA-224 thru SHA-512 */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);

    /* This is a corrupt JSON, failed to include tgid */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);

    teardown_ctx(&ctx);

}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(Kdf135SshFail, cryptoFail1) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;
    int flags = 0;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    //Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 |ACVP_SHA256
    | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);

    val = json_parse_file("json/kdf135_ssh/kdf135_ssh1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on first iteration */
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
    teardown_ctx(&ctx);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(Kdf135SshFail, cryptoFail2) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;
    int flags = 0;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    //Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 |ACVP_SHA256
    | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);


    val = json_parse_file("json/kdf135_ssh/kdf135_ssh1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on last iteration */
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
    teardown_ctx(&ctx);
}

/*
 * The key:"cipher" is missing in secong tg
 */
Test(Kdf135SshFail, tcidFail) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;
    int flags = 0;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    //Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 |ACVP_SHA256
    | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);

    val = json_parse_file("json/kdf135_ssh/kdf135_ssh13.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
    teardown_ctx(&ctx);
}

/*
 * The key:"h" is missing in last tc
 */
Test(Kdf135SshFail, tcFail) {
    ACVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;
    int flags = 0;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    //Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 |ACVP_SHA256
    | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    cr_assert(rv == ACVP_SUCCESS);

    val = json_parse_file("json/kdf135_ssh/kdf135_ssh14.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
    teardown_ctx(&ctx);
}

