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
#include "app_common.h"
#include "acvp/acvp_lcl.h"

ACVP_CTX *ctx;
ACVP_TEST_CASE *test_case;
ACVP_SYM_CIPHER_TC *aes_tc;
ACVP_RESULT rv;

int initialize_aes_tc(ACVP_SYM_CIPHER_TC *aes_tc, int alg_id, char *pt, 
                      int pt_len, char *ct, int ct_len, char *key, int key_len, char *aad,
                      int aad_len, char *tag, int tag_len, ACVP_SYM_CIPH_IVGEN_SRC ivGen, 
                      ACVP_SYM_CIPH_IVGEN_MODE ivGenMode, char *iv, int iv_len, 
                      ACVP_SYM_CIPH_DIR direction, ACVP_SYM_CIPH_TESTTYPE test_type) {

    aes_tc->ct = calloc(ACVP_SYM_CT_BYTE_MAX, sizeof(char));
    if (!aes_tc->ct) { return 0; }
    if (ct) {
        rv = acvp_hexstr_to_bin(ct, aes_tc->ct, ACVP_SYM_CT_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (ct)");
            return 0;
        }
    }

    aes_tc->pt = calloc(ACVP_SYM_PT_BYTE_MAX, sizeof(char));
    if (!aes_tc->pt) { return 0; }
    if (pt) {
        rv = acvp_hexstr_to_bin(pt, aes_tc->pt, ACVP_SYM_PT_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (pt)");
            return 0;
        }
    }


    aes_tc->key = calloc(ACVP_SYM_KEY_MAX_BYTES, sizeof(char));
    if (!aes_tc->key) { return 0; }
    if (key) {
        rv = acvp_hexstr_to_bin(key, aes_tc->key, ACVP_SYM_KEY_MAX_BYTES, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (key)");
            return 0;
        }
    }
    

    aes_tc->aad = calloc(ACVP_SYM_AAD_BYTE_MAX, sizeof(char));
    if (!aes_tc->aad) { return 0; }
    if (aad) {
        rv = acvp_hexstr_to_bin(aad, aes_tc->aad, ACVP_SYM_AAD_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (aad)");
            return 0;
        }
    }
    

    aes_tc->tag = calloc(ACVP_SYM_TAG_BYTE_MAX, sizeof(char));
    if (!aes_tc->tag) { return 0; }
    if (tag) {
        rv = acvp_hexstr_to_bin(tag, aes_tc->tag, ACVP_SYM_TAG_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (tag)");
            return 0;
        }
    }
    

    aes_tc->iv = calloc(ACVP_SYM_IV_BYTE_MAX, sizeof(char));
    if (!aes_tc->iv) { return 0; }
    if (iv) {
        rv = acvp_hexstr_to_bin(iv, aes_tc->iv, ACVP_SYM_IV_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (iv)");
            return 0;
        }
    }
        

    aes_tc->ivgen_source = ivGen;
    aes_tc->ivgen_mode = ivGenMode;
    aes_tc->iv_len = iv_len / 8;
    aes_tc->direction = direction;
    aes_tc->test_type = test_type;
    
    aes_tc->pt_len = pt_len / 8;
    aes_tc->ct_len = ct_len / 8;
    aes_tc->key_len = key_len;
    aes_tc->aad_len = aad_len / 8;
    aes_tc->tag_len = tag_len / 8;
    aes_tc->cipher = alg_id;

    return 1;
}

void free_aes_tc(ACVP_SYM_CIPHER_TC *aes_tc) {
    if (aes_tc->pt) free(aes_tc->pt);
    if (aes_tc->ct) free(aes_tc->ct);
    if (aes_tc->tag) free(aes_tc->tag);
    if (aes_tc->aad) free(aes_tc->aad);
    if (aes_tc->key) free(aes_tc->key);
    if (aes_tc->iv) free(aes_tc->iv);
    if (aes_tc->iv_ret) free(aes_tc->iv_ret);
    if (aes_tc->iv_ret_after) free(aes_tc->iv_ret_after);
    free(aes_tc);
}

/*
 * bad keyLen AEAD
 */
Test(APP_AES_AEAD_HANDLER, missing_msg) {
    char *payload = "668CB4DF";
    char *key = "C6E121A756C238C468B376CE50D6A14F";
    char *aad = "3A2C";
    char *tag = "C2861950B8B3F26EF6B694ADD4265088";
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_AES_GCM, payload, 32, NULL, 0,
        key, 24, aad, 16, tag, 128, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, ACVP_SYM_CIPH_DIR_ENCRYPT,
        ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("aes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_handler_aead(test_case);
    cr_assert_neq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}

/*
 * Test case has bad direction AEAD
 */
Test(APP_AES_AEAD_HANDLER, missing_dir) {
    char *payload = "1836252B";
    char *key = "025CF21F049CBEE1327629AFCD7F6A60";
    char *aad = "3A2C";
    char *tag = NULL;
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_AES_CCM, payload, 32, NULL, 0,
        key, 128, aad, 16, tag, 0, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, 3,
        ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("aes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_handler_aead(test_case);
    cr_assert_neq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}

/*
 * Bad cipher AEAD
 */
 Test(APP_AES_AEAD_HANDLER, bad_cipher) {
    char *payload = "8C7A3135";
    char *key = "5A6F5D2B6856356449E5A8A91FB33737";
    char *aad = "";
    char *tag = "73AF899B98E800A743224017527649CF";
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_HASH_SHA224, payload, 32, NULL, 0,
        key, 128, aad, 0, tag, 128, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, ACVP_SYM_CIPH_DIR_ENCRYPT,
        ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("aes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_handler_aead(test_case);
    cr_assert_neq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}

/*
 * Bad tagLen for decrypt AEAD
 */
 Test(APP_AES_AEAD_HANDLER, bad_taglen) {
    char *payload = "4ECCBC36";
    char *key = "2A7725F66621F77B92CE2D10DFC94093";
    char *aad = "";
    char *tag = "687B62AF98D02B6FC4EFFFA91ECAE916";
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_AES_GCM, NULL, 0, payload, 32,
        key, 128, aad, 0, tag, 64, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, ACVP_SYM_CIPH_DIR_DECRYPT,
        ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("aes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_handler_aead(test_case);
    cr_assert_neq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}

/*
 * Bad aadLen for encrypt AEAD - this behavior is undefined in SSL (?) - ensure it causes no issues with app
 * Crypto library does not return positive values in tests if built with FOM
 */
#ifndef ACVP_NO_RUNTIME
 Test(APP_AES_AEAD_HANDLER, bad_aadlen) {
    char *payload = "7E0BDE80";
    char *key = "B5BF1BD15DA1DE75B37BEAE1B7ABBC90";
    char *aad = "5BA9";
    char *tag = "687B62AF98D02B6F";
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_AES_CCM, payload, 32, NULL, 0,
        key, 128, aad, 7, tag, 64, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, ACVP_SYM_CIPH_DIR_ENCRYPT,
        ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("aes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_handler_aead(test_case);
    cr_assert_eq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}
#endif

/*
 * GMAC case that has plain or cipher text, make sure it fails
 */
 Test(APP_AES_AEAD_HANDLER, bad_gmac) {
    char *payload = "6DDB7E03";
    char *key = "360B5EE0C3DA2D2F1DF50B65C4378D0A5E3A701263EEAECCB541DA3165E5558D";
    char *aad = NULL;
    char *tag = "687B62AF98D02B6FC4EFFFA91ECAE916";
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_AES_GMAC, payload, 32, NULL, 0,
        key, 256, aad, 0, tag, 128, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, ACVP_SYM_CIPH_DIR_ENCRYPT,
        ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("aes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_handler_aead(test_case);
    cr_assert_neq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}

/*
 * bad keyLen
 */
Test(APP_AES_HANDLER, bad_keylen) {
    char *payload = "CAC0E8B7";
    char *key = "86FEBF763FD923F956FC8924D67C0DA4";
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_AES_ECB, payload, 32, NULL, 0,
        key, 48, NULL, 0, NULL, 0, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, ACVP_SYM_CIPH_DIR_ENCRYPT,
        ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("aes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}

/*
 * Test case has bad direction
 */
Test(APP_AES_HANDLER, missing_dir) {
    char *payload = "39B0837B";
    char *key = "56392E22AE93E653DDB2F7CCEB1C5D71";
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_AES_CTR, payload, 32, NULL, 0,
        key, 128, NULL, 0, NULL, 0, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, 3,
        ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("aes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}

/*
 * Bad cipher
 */
 Test(APP_AES_HANDLER, bad_cipher) {
    char *payload = "C60A1E7B";
    char *key = "EE78590CED470D96A80A1BADDF627E7F";
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_KDF108, NULL, 0, payload, 32,
        key, 128, NULL, 0, NULL, 0, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, ACVP_SYM_CIPH_DIR_ENCRYPT,
        ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("aes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}

/*
 * monte carlo bad direction 
 */
 Test(APP_AES_HANDLER, bad_mct_dir) {
    char *payload = "3308D695";
    char *key = "87683ACFBEDC23D25571352E6DA5C70E";
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_AES_ECB, payload, 32, NULL, 0,
        key, 128, NULL, 0, NULL, 0, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, 3,
        ACVP_SYM_TEST_TYPE_MCT)) {
        cr_assert_fail("aes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}


/*
 * monte carlo bad payload length - undefined behavior (?) ensure that it causes no issues with app
 */
 Test(APP_AES_HANDLER, bad_mct_payloadLen) {
    char *payload = "3ACA556E";
    char *key = "E0CD57A31C3206089EF0C07152B03249";
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_AES_ECB, NULL, 0, payload, 24,
        key, 128, NULL, 0, NULL, 0, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, ACVP_SYM_CIPH_DIR_DECRYPT,
        ACVP_SYM_TEST_TYPE_MCT)) {
        cr_assert_fail("aes init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_handler(test_case);
    cr_assert_eq(rv, 0);
    //skip to last iteration to ensure end works normally as well
    aes_tc->mct_index = 999;
    rv = app_aes_handler(test_case);
    cr_assert_eq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}

/*
 * Bad cipher - keywrap
 */
 Test(APP_AES_KW_HANDLER, bad_cipher) {
    char *payload = "B9917B1E";
    char *key = "66091ED955FA5412E177F151C1E032A1";
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_AES_GCM, NULL, 0, payload, 32,
        key, 128, NULL, 0, NULL, 0, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, ACVP_SYM_CIPH_DIR_ENCRYPT,
        ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("aes init tc failure");
    }
    aes_tc->kwcipher = ACVP_SYM_KW_CIPHER;
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_keywrap_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}

/*
 * Bad direction - keywrap
 */
 Test(APP_AES_KW_HANDLER, bad_dir) {
    char *payload = "C1688D91";
    char *key = "29B4BE41BECC9EC2327ACBDD18BD4F88";
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_AES_KW, payload, 32, NULL, 0,
        key, 128, NULL, 0, NULL, 0, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, 3,
        ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("aes init tc failure");
    }
    aes_tc->kwcipher = ACVP_SYM_KW_CIPHER;
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_keywrap_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}

/*
 * null payload - keywrap 
 */
 Test(APP_AES_KW_HANDLER, bad_payload) {
    char *payload = NULL;
    char *key = "C7BFB2CDBFC38BB55B486329623962D8";
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_AES_KW, NULL, 0, payload, 0,
        key, 128, NULL, 0, NULL, 0, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, ACVP_SYM_CIPH_DIR_ENCRYPT,
        ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("aes init tc failure");
    }
    aes_tc->kwcipher = ACVP_SYM_KW_CIPHER;
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_keywrap_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}

/*
 * null key decrypt - keywrap
 */
 Test(APP_AES_KW_HANDLER, bad_key) {
    char *payload = "497E9A22";
    char *key = NULL;
    aes_tc = calloc(1, sizeof(ACVP_SYM_CIPHER_TC));
    
    if (!initialize_aes_tc(aes_tc, ACVP_AES_KW, payload, 32, payload, 32,
        key, 128, NULL, 0, NULL, 0, ACVP_SYM_CIPH_IVGEN_SRC_INT, 
        ACVP_SYM_CIPH_IVGEN_MODE_821, NULL, 96, ACVP_SYM_CIPH_DIR_DECRYPT,
        ACVP_SYM_TEST_TYPE_AFT)) {
        cr_assert_fail("aes init tc failure");
    }
    aes_tc->kwcipher = ACVP_SYM_KW_CIPHER;
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.symmetric = aes_tc;
    
    rv = app_aes_keywrap_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_aes_tc(aes_tc);
    free(test_case);
}
