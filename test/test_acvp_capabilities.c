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

TEST_GROUP(EnableCapAES);
TEST_GROUP(EnableCapCMAC);
TEST_GROUP(EnableCapDRBG);
TEST_GROUP(EnableCapECDSA);
TEST_GROUP(EnableCapHMAC);
TEST_GROUP(EnableCapHash);
TEST_GROUP(EnableCapKASECC);
TEST_GROUP(EnableCapKASFFC);
TEST_GROUP(EnableCapKASHKDF);
TEST_GROUP(EnableCapKASKDFONESTEP);
TEST_GROUP(EnableCapKDF108);
TEST_GROUP(EnableCapKDF135IKEv1);
TEST_GROUP(EnableCapKDF135IKEv2);
TEST_GROUP(EnableCapKDFSNMP);
TEST_GROUP(EnableCapKDFSRTP);
TEST_GROUP(EnableCapKDFSSH);
TEST_GROUP(EnableCapKDFTLS13);
TEST_GROUP(EnableCapKDFx963);
TEST_GROUP(EnableCapRSAkeyGen);
TEST_GROUP(EnableCapTDES);

static ACVP_CTX *ctx = NULL;
static char cvalue[] = "same";
static ACVP_RESULT rv = 0;

static void enable_cap_hash_tear_down_helper(void) {
    if (ctx) teardown_ctx(&ctx);
}

TEST_SETUP(EnableCapAES) {}
TEST_TEAR_DOWN(EnableCapAES) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapCMAC) {}
TEST_TEAR_DOWN(EnableCapCMAC) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapDRBG) {}
TEST_TEAR_DOWN(EnableCapDRBG) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapECDSA) {}
TEST_TEAR_DOWN(EnableCapECDSA) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapHMAC) {}
TEST_TEAR_DOWN(EnableCapHMAC) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapHash) {}
TEST_TEAR_DOWN(EnableCapHash) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapKASECC) {}
TEST_TEAR_DOWN(EnableCapKASECC) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapKASFFC) {}
TEST_TEAR_DOWN(EnableCapKASFFC) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapKASHKDF) {}
TEST_TEAR_DOWN(EnableCapKASHKDF) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapKASKDFONESTEP) {}
TEST_TEAR_DOWN(EnableCapKASKDFONESTEP) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapKDF108) {}
TEST_TEAR_DOWN(EnableCapKDF108) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapKDF135IKEv1) {}
TEST_TEAR_DOWN(EnableCapKDF135IKEv1) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapKDF135IKEv2) {}
TEST_TEAR_DOWN(EnableCapKDF135IKEv2) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapKDFSNMP) {}
TEST_TEAR_DOWN(EnableCapKDFSNMP) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapKDFSRTP) {}
TEST_TEAR_DOWN(EnableCapKDFSRTP) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapKDFSSH) {}
TEST_TEAR_DOWN(EnableCapKDFSSH) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapKDFTLS13) {}
TEST_TEAR_DOWN(EnableCapKDFTLS13) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapKDFx963) {}
TEST_TEAR_DOWN(EnableCapKDFx963) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapRSAkeyGen) {}
TEST_TEAR_DOWN(EnableCapRSAkeyGen) {
    enable_cap_hash_tear_down_helper();
}

TEST_SETUP(EnableCapTDES) {}
TEST_TEAR_DOWN(EnableCapTDES) {
    enable_cap_hash_tear_down_helper();
}

TEST(EnableCapHash, properly) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA1, ACVP_HASH_MESSAGE_LEN,
                                  0, 65528, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA1, ACVP_HASH_MESSAGE_LEN,
                                  0, 65532, 4);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA1, ACVP_HASH_MESSAGE_LEN,
                                  0, 65534, 2);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA1, ACVP_HASH_MESSAGE_LEN,
                                  0, 65535, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

/*
 * This test should return ACVP_NO_CAP because we are trying
 * to register a parameter for an alg that we haven't added
 * to the list yet.
 */
TEST(EnableCapHash, param_alg_mismatch) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA256, ACVP_HASH_MESSAGE_LEN,
                                  0, 65535, 1);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
}

// Attempts to register with a NULL handler
TEST(EnableCapHash, null_handler) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// Tests invalid values to enable_hash_cap_parm API
TEST(EnableCapHash, invalid_args) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA1, ACVP_HASH_MESSAGE_LEN,
                                  0, 65535, 2);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA1, ACVP_HASH_MESSAGE_LEN,
                                  0, 65535, 4);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA1, ACVP_HASH_MESSAGE_LEN,
                                  0, 65535, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// Tests a good kdf108 api sequence
TEST(EnableCapKDF108, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf108_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF108, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_DPI, ACVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_TDES);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_COUNTER_LEN, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_AFTER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_BEFORE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_MIDDLE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_NONE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_BEFORE_ITERATOR);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTS_EMPTY_IV, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// This tests invalid kdf108 mode
TEST(EnableCapKDF108, alg_mismatch) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf108_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_domain(ctx, 0, ACVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, 999, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// This tests invalid params to kdf108_domain_param API
TEST(EnableCapKDF108, invalid_domain) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf108_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 0, 384, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 8, 99999, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// Tests invalid values to the kdf108_cap_param API
TEST(EnableCapKDF108, invalid_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf108_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, 999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_COUNTER_LEN, 7);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_COUNTER_LEN, 999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_FIXED_DATA_ORDER, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTS_EMPTY_IV, 3);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTS_EMPTY_IV, 3);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTS_EMPTY_IV, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTS_EMPTY_IV, 2);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

TEST(EnableCapKDFx963, properly) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    /* Enable capabilites */
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_KEY_DATA_LEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_KEY_DATA_LEN, 1024);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_FIELD_SIZE, 224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_FIELD_SIZE, 521);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_SHARED_INFO_LEN, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_SHARED_INFO_LEN, 1024);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// tries to enable kdf x963 with empty ctx, expect fail
TEST(EnableCapKDFx963, null_ctx) {
    rv = acvp_cap_kdf135_x963_enable(NULL, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// tries to enable kdf x963 with invalid params, expect fail
TEST(EnableCapKDFx963, invalid_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    // shouldn't be called before enable_cap
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, 999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_KEY_DATA_LEN, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_KEY_DATA_LEN, 99999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_FIELD_SIZE, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_FIELD_SIZE, 99999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_SHARED_INFO_LEN, -1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_SHARED_INFO_LEN, 9999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

TEST(EnableCapKDFSNMP, properly) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SNMP, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 64);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_engid(ctx, ACVP_KDF135_SNMP, "0a0a0a0a0a0a0a0a0a");
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

/*
 * This test should return ACVP_NO_CAP because we are trying
 * to register a parameter for an alg that we haven't added
 * to the list yet.
 */
TEST(EnableCapKDFSNMP, param_alg_mismatch) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
}

// This test gives invalid params to kdf_snmp api
TEST(EnableCapKDFSNMP, invalid_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 99999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_snmp_set_engid(ctx, ACVP_KDF135_SNMP, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a");
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// Good srtp registration
TEST(EnableCapKDFSRTP, good) {
    int i = 0;
    
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_srtp_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SRTP, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_SUPPORT_ZERO_KDR, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    for (i = 0; i < 24; i++) {
        rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_KDF_EXPONENT, i + 1);
        TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    }
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// enable srtp with null ctx
TEST(EnableCapKDFSRTP, null_ctx) {
    rv = acvp_cap_kdf135_srtp_enable(NULL, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// enable srtp with invalid params, expect fail
TEST(EnableCapKDFSRTP, invalid_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_srtp_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_SUPPORT_ZERO_KDR, 3);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_KDF_EXPONENT, -1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_KDF_EXPONENT, 25);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 512);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

TEST(EnableCapKDFSSH, properly) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// tries to enable kdf ssh with null_ctx, expect failure
TEST(EnableCapKDFSSH, null_ctx) {
    rv = acvp_cap_kdf135_ssh_enable(NULL, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// tries to enable kdf ssh with invalid params, expect failure
TEST(EnableCapKDFSSH, invalid_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

/*
 * This test should return ACVP_NO_CAP because we are trying
 * to register a parameter for an alg that we haven't added
 * to the list yet.
 */
TEST(EnableCapKDFSSH, param_alg_mismatch) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_SSH_METH_TDES_CBC, ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SSH_METH_TDES_CBC, ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
}

TEST(EnableCapCMAC, properly) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_AES, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_AES, ACVP_CMAC_MSGLEN, 0, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_MACLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_GEN, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_VER, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

/*
 * This test should return ACVP_NO_CAP because we are trying
 * to register a parameter for an alg that we haven't added
 * to the list yet.
 */
TEST(EnableCapCMAC, param_alg_mismatch) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_TDES, ACVP_CMAC_MSGLEN, 0, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
}

// Attempts to register with a NULL handler
TEST(EnableCapCMAC, null_handler) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

TEST(EnableCapCMAC, invalid_args) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_TDES, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_AES, ACVP_PREREQ_AES, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_AES, ACVP_CMAC_MSGLEN, -1, 65536, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_AES, ACVP_CMAC_MSGLEN, 0, 9999999, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_AES, ACVP_CMAC_MSGLEN, 0, 65536, 7);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    /*
     * CMAC-AES has different keylen requirements than other MACs
     * 128, 192, 256 are allowed
     */
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 191);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 512);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    /* the rest are a range */
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_KEYLEN, 7);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_KEYLEN, 524289);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_MACLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 513);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    /* Only applicable to TDES */
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYING_OPTION, 1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_KEYING_OPTION, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_KEYING_OPTION, 3);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    /* these are flags... 0 or 1 */
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_GEN, -1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_GEN, 2);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_VER, -1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_VER, 2);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

TEST(EnableCapHMAC, properly) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_224, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_224, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_KEYLEN, 256, 448, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_MACLEN, 32, 224, 8);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

TEST(EnableCapHMAC, param_alg_mismatch) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_256, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_hmac_enable(ctx, ACVP_CMAC_AES, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_cap_hmac_set_parm(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_KEYLEN, 32 * 8);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
}

// Attempts to register with a NULL handler
TEST(EnableCapHMAC, null_handler) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_384, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

TEST(EnableCapHMAC, invalid_args) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_512, ACVP_PREREQ_SHA, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_hmac_set_parm(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN, 7);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    /*
     * TODO: need to make sure the library checks if the max is greater than the min
     * [edaw] the domain here needs refactoring
     */
    rv = acvp_cap_hmac_set_parm(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN, 524889);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN, 7, 256, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN, 8, 524889, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    rv = acvp_cap_hmac_set_parm(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_MACLEN, 31);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_hmac_set_parm(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_MACLEN, 513);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_MACLEN, 31, 512, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_MACLEN, 32, 513, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

TEST(EnableCapRSAkeyGen, proper_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_INFO_GEN_BY_SERVER, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

TEST(EnableCapRSAkeyGen, proper_modes) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    /* skip the other outer params for now */
    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B32);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B33);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B34);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B35);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B36);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

TEST(EnableCapRSAkeyGen, proper_modes_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    /* skip the other outer params for now */
    
    /* B.3.5 takes both a hash_alg and a prime_test
     * so we can test with that one... */
    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B35);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B35, 2048, ACVP_RSA_PRIME_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B35, 2048, ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B35, 3072, ACVP_RSA_PRIME_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B35, 3072, ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

TEST(EnableCapRSAkeyGen, alg_mismatch) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_HASH_SHA1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
}

/*
 * Most of these params are members of enums, so the app
 * won't even build if it has an invalid value
 */
TEST(EnableCapRSAkeyGen, invalid_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
    
    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, "");
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    /* should only accept true or false... 0 or 1 */
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_INFO_GEN_BY_SERVER, 3);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    /* should only valid enum */
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_KEY_FORMAT, 99);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

TEST(EnableCapRSAkeyGen, invalid_modes_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    /* skip the other outer params for now */
    
    /* B.3.5 takes both a hash_alg and a prime_test
     * so we can test with that one... */
    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B35);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B35, 2048, ACVP_RSA_PRIME_HASH_ALG, 257);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B35, 2048, ACVP_RSA_PRIME_TEST, 256);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

/*
 * Enable an AES cipher mode, then attempt to register
 * a parameter for a different mode
 */
TEST(EnableCapRSAkeyGen, cipher_param_mismatch) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_RAND_PQ, 128);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    /*
     * Interesting here:
     * Commented out as an example (doesn't compile)
     *
     *   rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_SYM_CIPH_PTLEN, 128);
     *
     * if the compiler lets you compile with the wrong enum type here,
     * if that value has a valid value in the expected enum then the
     * test may not fail. The compiler flag to error on implicit casting
     * is -Werror=enum-conversion but we can't control what an app
     * on the outside compiles with...
     */
    
}

TEST(EnableCapAES, properly) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
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

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_IVLEN, 96);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

TEST(EnableCapAES, alg_mismatch) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_ECDSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
}

TEST(EnableCapAES, bad_conformance) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CTR, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CONFORMANCE, ACVP_CONFORMANCE_DEFAULT);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_CONFORMANCE, ACVP_CONFORMANCE_RFC3686);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

/*
 * Most of these params are members of enums, so the app
 * won't even build if it has an invalid value
 */
TEST(EnableCapAES, invalid_callback) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
}

/*
 * Most of these params are members of enums, so the app
 * won't even build if it has an invalid value
 */
TEST(EnableCapAES, invalid_dir) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_DIR, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

/*
 * Enable an AES cipher mode, then attempt to register
 * a parameter for a different mode
 */
TEST(EnableCapAES, cipher_param_mismatch) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 128);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
}

/*
 * Enable an AES cipher mode, then attempt to register
 * a parameter for a different mode
 */
TEST(EnableCapAES, invalid_keylens) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 333);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 999999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

/*
 * Enable an AES cipher mode, then attempt to register
 * a parameter for a different mode
 */
TEST(EnableCapAES, invalid_param_lens) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PTLEN, 999999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CCM, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 333);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 999999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, 999999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, -333);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

/*
 * Enable an AES cipher mode, then attempt to register
 * a domain for a non-domain value 
 */
TEST(EnableCapAES, cipher_invalid_parm_domain) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS2, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_KEYLEN, 0, 128, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// null CTX set domain
TEST(EnableCapAES, cipher_domain_no_ctx) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_XPN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(NULL, ACVP_AES_XPN, ACVP_SYM_CIPH_DOMAIN_PTLEN, 0, 128, 8);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// bad domain values
TEST(EnableCapAES, cipher_domain_bad_values) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS3, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_DOMAIN_PTLEN, -64, 128, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 64, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_DOMAIN_PTLEN, 0, 128, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_KEYLEN, 0, 0, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// Enable an AES cipher, register a payloadLen, then register a payloadLen domain
TEST(EnableCapAES, dup_payload_registration) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS1, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_PTLEN, 33333);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_DOMAIN_PTLEN, 0, 1024, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

}

TEST(EnableCapTDES, properly) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CBC, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

TEST(EnableCapTDES, alg_param_mismatch) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CBC, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_TAGLEN, 256);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_AADLEN, 64);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// This calls enable ikev1 api properly
TEST(EnableCapKDF135IKEv1, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_ikev1_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV1, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV1, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_INIT_NONCE_LEN, 64, 2048, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_RESPOND_NONCE_LEN, 64, 2048, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_DH_SECRET_LEN, 224, 8192, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_PSK_LEN, 8, 8192, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, ACVP_SHA1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_AUTH_METHOD, ACVP_KDF135_IKEV1_AMETH_PSK);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_AUTH_METHOD, ACVP_KDF135_IKEV1_AMETH_DSA);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_AUTH_METHOD, ACVP_KDF135_IKEV1_AMETH_PKE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

/*
 * This calls enable ikev1 api with null values
 * TODO this is another case that might be allowed
 * when running in non-realtime
 */
TEST(EnableCapKDF135IKEv1, null_vals) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_ikev1_enable(NULL, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    rv = acvp_cap_kdf135_ikev1_enable(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// This calls enable ikev1 domain api with invalid params
TEST(EnableCapKDF135IKEv1, invalid_domain) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_ikev1_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_INIT_NONCE_LEN, 0, 2048, 1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_INIT_NONCE_LEN, 64, 9999, 1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_RESPOND_NONCE_LEN, 0, 2048, 1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_RESPOND_NONCE_LEN, 64, 9999, 1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_DH_SECRET_LEN, 0, 8192, 1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_DH_SECRET_LEN, 224, 99999, 1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_PSK_LEN, 0, 8192, 1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_PSK_LEN, 8, 99999, 1);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// This calls enable ikev1 param api with invalid params
TEST(EnableCapKDF135IKEv1, invalid_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, 999);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
    rv = acvp_cap_kdf135_ikev1_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, 999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_AUTH_METHOD, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

}

// This calls enable ikev2 api properly
TEST(EnableCapKDF135IKEv2, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_ikev2_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV2, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV2, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_INIT_NONCE_LEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_INIT_NONCE_LEN, 2048);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_RESPOND_NONCE_LEN, 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_RESPOND_NONCE_LEN, 2048);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_DH_SECRET_LEN, 2048);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_KEY_MATERIAL_LEN, 1056);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_KEY_MATERIAL_LEN, 3072);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_parm(ctx, ACVP_KDF_HASH_ALG, ACVP_SHA1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_parm(ctx, ACVP_KDF_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_parm(ctx, ACVP_KDF_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_parm(ctx, ACVP_KDF_HASH_ALG, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_parm(ctx, ACVP_KDF_HASH_ALG, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// This calls enable ikev2 domain api properly
TEST(EnableCapKDF135IKEv2, good_domain) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_ikev2_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_domain(ctx, ACVP_RESPOND_NONCE_LEN, 64, 2048, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_domain(ctx, ACVP_INIT_NONCE_LEN, 64, 2048, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_domain(ctx, ACVP_DH_SECRET_LEN, 224, 8192, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_domain(ctx, ACVP_KEY_MATERIAL_LEN, 160, 2048, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// This calls enable ikev2 api properly
TEST(EnableCapKDF135IKEv2, null_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_ikev2_enable(NULL, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    rv = acvp_cap_kdf135_ikev2_enable(ctx, NULL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// This calls enable ikev2 len/domain api with invalid params
TEST(EnableCapKDF135IKEv2, invalid_len_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_INIT_NONCE_LEN, 9999);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
    rv = acvp_cap_kdf135_ikev2_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_INIT_NONCE_LEN, 9999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_RESPOND_NONCE_LEN, 9999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_DH_SECRET_LEN, 9999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_KEY_MATERIAL_LEN, 99999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);

    rv = acvp_cap_kdf135_ikev2_set_domain(ctx, ACVP_INIT_NONCE_LEN, 0, 256, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev2_set_domain(ctx, ACVP_INIT_NONCE_LEN, 64, 9999, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev2_set_domain(ctx, ACVP_RESPOND_NONCE_LEN, 0, 256, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev2_set_domain(ctx, ACVP_RESPOND_NONCE_LEN, 64, 9999, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev2_set_domain(ctx, ACVP_DH_SECRET_LEN, 0, 256, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev2_set_domain(ctx, ACVP_DH_SECRET_LEN, 224, 9999, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev2_set_domain(ctx, ACVP_KEY_MATERIAL_LEN, 0, 256, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf135_ikev2_set_domain(ctx, ACVP_KEY_MATERIAL_LEN, 224, 99999, 8);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// This calls enable ikev2 api properly
TEST(EnableCapKDF135IKEv2, invalid_hash_alg) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf135_ikev2_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf135_ikev2_set_parm(ctx, ACVP_KDF_HASH_ALG, 999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// enable ecdsa keygen with valid params
TEST(EnableCapECDSA, good_keygen) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_SECRET_GEN, ACVP_ECDSA_SECRET_GEN_TEST_CAND);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// enable ecdsa cipher mismatch
TEST(EnableCapECDSA, mode_mismatch_kg) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    TEST_ASSERT_EQUAL(ACVP_NO_CAP, rv);
}

// enable ecdsa keygen with invalid params
TEST(EnableCapECDSA, invalid_params_kg) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, 256);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_SECRET_GEN, 256);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_SECRET_GEN, -1);
    TEST_ASSERT_EQUAL(ACVP_MISSING_ARG, rv);
}

// enable ecdsa keyver with valid params
TEST(EnableCapECDSA, good_keyver) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYVER, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// enable ecdsa keyver with invalid params
TEST(EnableCapECDSA, invalid_params_kv) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYVER, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, 256);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// enable ecdsa siggen with valid params
TEST(EnableCapECDSA, good_siggen) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    //rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA384);
    rv = acvp_cap_ecdsa_set_curve_hash_alg(ctx, ACVP_ECDSA_SIGGEN, ACVP_EC_CURVE_B409, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// enable ecdsa siggen with invalid params
TEST(EnableCapECDSA, invalid_args_sg) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGGEN, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, 256);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, 257);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_ecdsa_set_curve_hash_alg(ctx, ACVP_ECDSA_SIGGEN, ACVP_EC_CURVE_K233, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_curve_hash_alg(ctx, ACVP_ECDSA_SIGGEN, ACVP_EC_CURVE_P192, 3);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// enable ecdsa sigver with valid params
TEST(EnableCapECDSA, good_sigver) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGVER, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    //rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA384);
    rv = acvp_cap_ecdsa_set_curve_hash_alg(ctx, ACVP_ECDSA_SIGVER, ACVP_EC_CURVE_B409, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// enable ecdsa sigver with invalid params
TEST(EnableCapECDSA, invalid_args_sv) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGVER, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, 256);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, 257);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_ecdsa_set_curve_hash_alg(ctx, ACVP_ECDSA_SIGVER, ACVP_EC_CURVE_K233, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_UNSUPPORTED_OP, rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P192);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_ecdsa_set_curve_hash_alg(ctx, ACVP_ECDSA_SIGVER, ACVP_EC_CURVE_P192, 3);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// enable hash drbg with valid params
TEST(EnableCapDRBG, good_hash) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_drbg_enable(ctx, ACVP_HASHDRBG, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
                                   ACVP_DRBG_DER_FUNC_ENABLED, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HASHDRBG, 
                                     ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
                                   ACVP_DRBG_PRED_RESIST_ENABLED, ACVP_DRBG_PRED_RESIST_YES);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
                                   ACVP_DRBG_RESEED_ENABLED, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
                                     ACVP_DRBG_ENTROPY_LEN, (int)128, (int)64,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
                                     ACVP_DRBG_NONCE_LEN, (int)96, (int)32,(int) 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
                                     ACVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
                                     ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0,
                                   ACVP_DRBG_RET_BITS_LEN, 160);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// enable hmac drbg with valid params
TEST(EnableCapDRBG, good_hmac) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_drbg_enable(ctx, ACVP_HMACDRBG, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMACDRBG, 
                                     ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);    
    rv = acvp_cap_set_prereq(ctx, ACVP_HMACDRBG, 
                                     ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
                                   ACVP_DRBG_DER_FUNC_ENABLED, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
                                   ACVP_DRBG_PRED_RESIST_ENABLED, ACVP_DRBG_PRED_RESIST_YES);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
                                   ACVP_DRBG_RESEED_ENABLED, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
                                   ACVP_DRBG_RET_BITS_LEN, 224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    //Add length range
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
                                     ACVP_DRBG_ENTROPY_LEN, (int)192, (int)64,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
                                     ACVP_DRBG_NONCE_LEN, (int)192, (int)64,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
                                     ACVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0,
                                     ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// enable ctr drbg with valid params
TEST(EnableCapDRBG, good_ctr) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_drbg_enable(ctx, ACVP_CTRDRBG, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_CTRDRBG, 
                                     ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_CTRDRBG, 
                                     ACVP_PREREQ_TDES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_CTRDRBG, 
                                     ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
                                     ACVP_DRBG_ENTROPY_LEN, (int)128, (int)128, (int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
                                     ACVP_DRBG_NONCE_LEN, (int)64, (int)64,(int) 128);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
                                     ACVP_DRBG_PERSO_LEN, (int)0, (int)256,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
                                     ACVP_DRBG_ADD_IN_LEN, (int)0, (int)256,(int) 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
                                   ACVP_DRBG_DER_FUNC_ENABLED, 1);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
                                   ACVP_DRBG_PRED_RESIST_ENABLED, ACVP_DRBG_PRED_RESIST_YES);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
                                   ACVP_DRBG_RESEED_ENABLED, 0);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
                                   ACVP_DRBG_RET_BITS_LEN, 256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// enable drbg with null ctx
TEST(EnableCapDRBG, null_ctx) {
    rv = acvp_cap_drbg_enable(NULL, ACVP_HASHDRBG, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// enable kas ecc with valid params
TEST(EnableCapKASECC, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_PREREQ_ECDSA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P521);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K233);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K283);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K409);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K571);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B233);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B283);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B409);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B571);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    
    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_COMP, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_ECDSA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CCM, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_INITIATOR);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_RESPONDER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_KDF, 0, ACVP_KAS_ECC_NOKDFNOKC);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EB, ACVP_EC_CURVE_P224, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EC, ACVP_EC_CURVE_P256, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ED, ACVP_EC_CURVE_P384, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EE, ACVP_EC_CURVE_P521, ACVP_SHA512);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);

}

// enable kas ecc with valid params
TEST(EnableCapKASECC, null_ctx) {
    rv = acvp_cap_kas_ecc_enable(NULL, ACVP_KAS_ECC_CDH, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// enable kas ecc with invalid
TEST(EnableCapKASECC, invalid_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_FUNCTION, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    // invalid cipher
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_AES_CBC, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    // invalid mode
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, 0, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, 999);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_COMP, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_FUNCTION, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    
    // invalid cipher
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_RSA_KEYGEN, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_INITIATOR);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    // invalid mode
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, 0, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_RESPONDER);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    // invalid kdf set
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_KDF, 0, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    // invalid scheme
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, 0, ACVP_KAS_ECC_EB, ACVP_EC_CURVE_P224, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    // invalid set
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, 0, ACVP_EC_CURVE_P256, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// enable kas ffc with valid params
TEST(EnableCapKASFFC, good) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_COMP, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_DSA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_SHA, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_DRBG, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_CCM, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_CMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPGEN);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPVAL);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_INITIATOR);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_RESPONDER);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_KDF, ACVP_KAS_FFC_NOKDFNOKC);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FC, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

// enable kas ffc with valid params
TEST(EnableCapKASFFC, null_ctx) {
    rv = acvp_cap_kas_ffc_enable(NULL, ACVP_KAS_FFC_COMP, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
}

// enable kas ffc with invalid params
TEST(EnableCapKASFFC, invalid_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_COMP, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    // invalid cipher
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPGEN);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    // invalid mode
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, 0, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPVAL);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    // invalid role
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_ROLE, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    // invalid scheme
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, 0, ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_RESPONDER);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}

// enable kda hkdf with invalid params
TEST(EnableCapKASHKDF, invalid_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_HKDF, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    // invalid cipher
    rv = acvp_cap_kda_set_parm(ctx, ACVP_HASH_SHA256, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid pattern
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_MAX, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid hmac alg
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_HASH_ALG_MAX, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid l
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_L, 0, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid salt method
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_MAX, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid encoding
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_MAX, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid call to set Z on set parm
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_Z, 1024, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid call to set AUX_FUNCTION on hkdf
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA256, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid alg calls to set_domain
    rv = acvp_cap_kda_set_domain(ctx, ACVP_HASH_SHA256, ACVP_KDA_Z, 0, 4096, 8);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid param call to set_domain
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_HKDF, ACVP_KDA_L, 0, 4096, 8);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);

}

// enable kda onestep with invalid params
TEST(EnableCapKASKDFONESTEP, invalid_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_ONESTEP, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    // invalid cipher
    rv = acvp_cap_kda_set_parm(ctx, ACVP_HASH_SHA256, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid pattern
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_MAX, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid aux function
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_AES_GCM, ACVP_HASH_ALG_MAX, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid l
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_L, 0, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid salt method
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_MAX, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid encoding
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_MAX, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid call to set Z on set parm
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_Z, 1024, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid call to set HMAC_ALG on hkdf
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_ALG, ACVP_HASH_SHA256, NULL);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid alg calls to set_domain
    rv = acvp_cap_kda_set_domain(ctx, ACVP_HASH_SHA256, ACVP_KDA_Z, 0, 4096, 8);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
    //invalid param call to set_domain
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_L, 0, 4096, 8);
    TEST_ASSERT_TRUE(rv = ACVP_INVALID_ARG);
}

 // enable kdf tls 1.3 with valid parms
TEST(EnableCapKDFTLS13, valid_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);

    rv = acvp_cap_kdf_tls13_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS13, ACVP_PREREQ_HMAC, cvalue);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_SHA384);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_DHE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK_DHE);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
}

 // enable kdf tls 1.3 with invalid parms
TEST(EnableCapKDFTLS13, invalid_params) {
    // TODO: Move setup_empty_ctx to TEST_SETUP and remove teardown_ctx from test
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kdf_tls13_enable(NULL, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_NO_CTX, rv);
    rv = acvp_cap_kdf_tls13_enable(ctx, &dummy_handler_success);
    TEST_ASSERT_EQUAL(ACVP_SUCCESS, rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS13, ACVP_PREREQ_AES, cvalue);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_SHA224);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, 0);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, 0, ACVP_SHA256);
    TEST_ASSERT_EQUAL(ACVP_INVALID_ARG, rv);
}
