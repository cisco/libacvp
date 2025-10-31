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

TEST_GROUP(AES_API);
TEST_GROUP(AES_CAPABILITY);
TEST_GROUP(AES_HANDLER);

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void aes_api_tear_down_helper(void) {
    if (val) json_value_free(val);
    val = NULL;
    obj = NULL;
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(AES_API) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 96);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_IVLEN, 96);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 136);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 264);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 136);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-ECB 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_ECB, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PTLEN, 1536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CBC 128 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PTLEN, 1536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CBC-CS1, CS2, and CS3
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS2, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS3, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CFB1 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PTLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CFB8 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB8, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PTLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CFB128 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB128, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PTLEN, 1536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-OFB 128, 192, 256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_OFB, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PTLEN, 1536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Register AES CCM capabilities
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CCM, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_CCM, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PTLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PTLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 32);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 56);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 104);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    /*
     * Enable AES keywrap for various key sizes and PT lengths
     * Note: this is with padding disabled, minimum PT length is 128 bits and must be
     *       a multiple of 64 bits. openssl does not support INVERSE mode.
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_KW, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 320);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 1280);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

#ifdef OPENSSL_KWP
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_KWP, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_enable_value(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 32);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 72);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 96);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 808);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
#endif

    // Enable AES-XTS 128 and 256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_XTS, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PTLEN, 65536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_TWEAK, ACVP_SYM_CIPH_TWEAK_HEX);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CTR 128, 192, 256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CTR, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CTR_INCR, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PTLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

}

TEST_TEAR_DOWN(AES_API) {
    aes_api_tear_down_helper();
}

TEST_SETUP(AES_CAPABILITY) {
    setup_empty_ctx(&ctx);
}

TEST_TEAR_DOWN(AES_CAPABILITY) {
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(AES_HANDLER) {
    setup_empty_ctx(&ctx);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 96);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_IVLEN, 96);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 136);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 264);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 136);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-ECB 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_ECB, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PTLEN, 1536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CBC 128 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PTLEN, 1536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CFB1 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PTLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CFB8 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB8, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PTLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CFB128 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB128, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PTLEN, 1536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-OFB 128, 192, 256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_OFB, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PTLEN, 1536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Register AES CCM capabilities
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CCM, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_CCM, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PTLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PTLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 32);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 56);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 104);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    /*
     * Enable AES keywrap for various key sizes and PT lengths
     * Note: this is with padding disabled, minimum PT length is 128 bits and must be
     *       a multiple of 64 bits. openssl does not support INVERSE mode.
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_KW, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 320);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 1280);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

#ifdef OPENSSL_KWP
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_KWP, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_enable_value(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 32);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 72);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 96);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 808);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
#endif

    // Enable AES-XTS 128 and 256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_XTS, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PTLEN, 65536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_TWEAK, ACVP_SYM_CIPH_TWEAK_HEX);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CTR 128, 192, 256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CTR, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CTR_INCR, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PTLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_XPN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_XPN, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_XPN, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_PARM_SALT_SRC, ACVP_SYM_CIPH_SALT_SRC_EXT);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_TAGLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_DOMAIN_PTLEN, 0, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

}

TEST_TEAR_DOWN(AES_HANDLER) {
    aes_api_tear_down_helper();
}

// Test capabilites API.
TEST(AES_CAPABILITY, good) {
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 96);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_IVLEN, 96);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 136);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 264);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 136);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-ECB 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_ECB, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PTLEN, 1536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CBC 128 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PTLEN, 1536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CBC-CS1, CS2, and CS3
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS2, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS3, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CFB1 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PTLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CFB8 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB8, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PTLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CFB128 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB128, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PTLEN, 1536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-OFB 128, 192, 256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_OFB, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PTLEN, 1536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Register AES CCM capabilities
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CCM, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_CCM, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PTLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PTLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 32);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 56);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 104);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    /*
     * Enable AES keywrap for various key sizes and PT lengths
     * Note: this is with padding disabled, minimum PT length is 128 bits and must be
     *       a multiple of 64 bits. openssl does not support INVERSE mode.
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_KW, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 320);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 1280);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

#ifdef OPENSSL_KWP
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_KWP, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_enable_value(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 32);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 72);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 96);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PTLEN, 808);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
#endif

    // Enable AES-XTS 128 and 256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_XTS, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PTLEN, 65536);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_TWEAK, ACVP_SYM_CIPH_TWEAK_HEX);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    // Enable AES-CTR 128, 192, 256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CTR, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CTR_INCR, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PTLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_XPN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_XPN, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_XPN, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_PARM_SALT_SRC, ACVP_SYM_CIPH_SALT_SRC_EXT);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_TAGLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_DOMAIN_PTLEN, 0, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_XPN, ACVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
TEST(AES_API, empty_ctx) {
    ACVP_CTX *test_ctx = NULL;
    
    // Create a ctx without any capabilities registered
    setup_empty_ctx(&test_ctx);
    
    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_aes_kat_handler(test_ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;

end:
    if (test_ctx) teardown_ctx(&test_ctx);
    return;
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
TEST(AES_API, null_ctx) {
    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_aes_kat_handler(NULL, obj);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
TEST(AES_API, null_json_obj) {
    rv  = acvp_aes_kat_handler(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_JSON_ERR, rv);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
TEST(AES_HANDLER, good) {
    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"algorithm" is wrong.
TEST(AES_HANDLER, wrong_algorithm) {
    val = json_parse_file("json/aes/aes_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"direction" is missing.
TEST(AES_HANDLER, missing_direction) {
    val = json_parse_file("json/aes/aes_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"direction" is wrong.
TEST(AES_HANDLER, wrong_direction) {
    val = json_parse_file("json/aes/aes_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"testType" is missing.
TEST(AES_HANDLER, missing_testType) {
    val = json_parse_file("json/aes/aes_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"testType" is wrong.
TEST(AES_HANDLER, wrong_testType) {
    val = json_parse_file("json/aes/aes_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"keyLen" is missing.
TEST(AES_HANDLER, missing_keyLen) {
    val = json_parse_file("json/aes/aes_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"keyLen" is wrong.
TEST(AES_HANDLER, wrong_keyLen) {
    val = json_parse_file("json/aes/aes_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ptLen" is too big.
TEST(AES_HANDLER, big_ptLen) {
    val = json_parse_file("json/aes/aes_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ivLen" is missing.
TEST(AES_HANDLER, missing_ivLen) {
    val = json_parse_file("json/aes/aes_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ivLen" is too small (GCM).
TEST(AES_HANDLER, small_ivLen_gcm) {
    val = json_parse_file("json/aes/aes_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ivLen" is too big (GCM).
TEST(AES_HANDLER, big_ivLen_gcm) {
    val = json_parse_file("json/aes/aes_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ivLen" is too small (CCM).
TEST(AES_HANDLER, small_ivLen_ccm) {
    val = json_parse_file("json/aes/aes_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ivLen" is too big (CCM).
TEST(AES_HANDLER, big_ivLen_ccm) {
    val = json_parse_file("json/aes/aes_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ivLen" is not an increment of 8 (CCM)
TEST(AES_HANDLER, wrong_ivLen_ccm) {
    val = json_parse_file("json/aes/aes_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"tagLen" is too small.
TEST(AES_HANDLER, small_tagLen) {
    val = json_parse_file("json/aes/aes_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"tagLen" is too big.
TEST(AES_HANDLER, big_tagLen) {
    val = json_parse_file("json/aes/aes_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"aadLen" is too big.
TEST(AES_HANDLER, big_aadLen) {
    val = json_parse_file("json/aes/aes_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"key" is missing.
TEST(AES_HANDLER, missing_key) {
    val = json_parse_file("json/aes/aes_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"key" string is too long.
TEST(AES_HANDLER, long_key) {
    val = json_parse_file("json/aes/aes_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"pt" is missing.
TEST(AES_HANDLER, missing_pt) {
    val = json_parse_file("json/aes/aes_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"pt" string is too long.
TEST(AES_HANDLER, long_pt) {
    val = json_parse_file("json/aes/aes_21.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"ct" is missing.
TEST(AES_HANDLER, missing_ct) {
    val = json_parse_file("json/aes/aes_22.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"ct" string is too long.
TEST(AES_HANDLER, long_ct) {
    val = json_parse_file("json/aes/aes_23.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"tag" is missing.
TEST(AES_HANDLER, missing_tag) {
    val = json_parse_file("json/aes/aes_24.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"tag" string is too long.
TEST(AES_HANDLER, long_tag) {
    val = json_parse_file("json/aes/aes_25.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"iv" is missing.
TEST(AES_HANDLER, missing_iv) {
    val = json_parse_file("json/aes/aes_26.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"iv" string is too long.
TEST(AES_HANDLER, long_iv) {
    val = json_parse_file("json/aes/aes_27.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The key:"aad" is missing.
TEST(AES_HANDLER, missing_aad) {
    val = json_parse_file("json/aes/aes_28.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"aad" string is too long.
TEST(AES_HANDLER, long_aad) {
    val = json_parse_file("json/aes/aes_29.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The value for key:"tgId" is missing
TEST(AES_HANDLER, missing_gid) {
    val = json_parse_file("json/aes/aes_30.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The boolean for "incrementalCounter" is missing/not a boolean
TEST(AES_HANDLER, bad_inc_ctr) {
    val = json_parse_file("json/aes/aes_31.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// The boolean for "overflowCounter" is missing/not a boolean
TEST(AES_HANDLER, bad_ovrflw_ctr) {
    val = json_parse_file("json/aes/aes_32.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_INVALID_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// Missing tg info in last tg
TEST(AES_HANDLER, tgLast) {
    val = json_parse_file("json/aes/aes_33.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

// Missing field in last tc
TEST(AES_HANDLER, tcLast) {
    val = json_parse_file("json/aes/aes_34.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_TC_MISSING_DATA, rv);
    json_value_free(val);
    val = NULL;
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
TEST(AES_HANDLER, cryptoFail1) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration of AFT */

    rv = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
TEST(AES_HANDLER, cryptoFail2) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 5;  /* fail on 6th iteration of AFT */

    rv = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
TEST(AES_HANDLER, cryptoFail3) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 2138; /* fail on first iteration of MCT */

    rv = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
TEST(AES_HANDLER, cryptoFail4) {
    // Enable failure mode for this test (originally used setup_fail)
    force_handler_failure = 1;
    counter_set = 0;
    counter_fail = 0;

    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 2144; /* fail on sixth iteration of MCT */

    rv = acvp_aes_kat_handler(ctx, obj);
    TEST_ASSERT_EQUAL(ACVP_CRYPTO_MODULE_FAIL, rv);
    json_value_free(val);
    val = NULL;
    
    // Reset failure mode
    force_handler_failure = 0;
}
