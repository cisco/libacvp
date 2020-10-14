/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

//
// Created by edaw on 2019-01-07.
//

#include "ut_common.h"
#include "app_common.h"
#include "acvp/acvp_lcl.h"

ACVP_CTX *ctx;
ACVP_TEST_CASE *test_case;
ACVP_RSA_SIG_TC *rsa_sig_tc;
ACVP_RESULT rv;

void free_rsa_sig_tc(ACVP_RSA_SIG_TC *stc) {
    if (stc->msg) { free(stc->msg); }
    if (stc->e) { free(stc->e); }
    if (stc->n) { free(stc->n); }
    if (stc->signature) { free(stc->signature); }
    if (stc->salt) { free(stc->salt); }
    free(stc);
}

int initialize_rsa_sig_tc(ACVP_CIPHER cipher,
                      ACVP_RSA_SIG_TC *stc,
                      int tgId,
                      ACVP_RSA_SIG_TYPE sig_type,
                      unsigned int mod,
                      ACVP_HASH_ALG hash_alg,
                      char *e,
                      char *n,
                      char *msg,
                      char *signature,
                      char *salt,
                      int salt_len,
                      int corrupt) {
    ACVP_RESULT rv;
    
    memzero_s(stc, sizeof(ACVP_RSA_SIG_TC));
    
    stc->salt = calloc(ACVP_RSA_SIGNATURE_MAX, sizeof(char));
    if (!stc->salt) { goto err; }
    
    if (msg) {
        stc->msg = calloc(ACVP_RSA_MSGLEN_MAX, sizeof(char));
        if (!stc->msg) { goto err; }
        rv = acvp_hexstr_to_bin(msg, stc->msg, ACVP_RSA_MSGLEN_MAX, &(stc->msg_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (msg)");
            goto err;
        }
    }
    
    if (cipher == ACVP_RSA_SIGVER) {
        stc->sig_mode = ACVP_RSA_SIGVER;
    
        if (e) {
            stc->e = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
            if (!stc->e) { goto err; }
            rv = acvp_hexstr_to_bin(e, stc->e, ACVP_RSA_EXP_LEN_MAX, &(stc->e_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (e)");
                goto err;
            }
        }
        if (n) {
            stc->n = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
            if (!stc->n) { goto err; }
            rv = acvp_hexstr_to_bin(n, stc->n, ACVP_RSA_EXP_LEN_MAX, &(stc->n_len));
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (n)");
                goto err;
            }
        }
        if (signature) {
            stc->signature = calloc(ACVP_RSA_SIGNATURE_MAX, sizeof(char));
            if (!stc->signature) { goto err; }
            rv = acvp_hexstr_to_bin(signature, stc->signature, ACVP_RSA_SIGNATURE_MAX, &stc->sig_len);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (signature)");
                goto err;
            }
        }
    } else {
        stc->sig_mode = ACVP_RSA_SIGGEN;
        if (!corrupt) {
            stc->e = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
            if (!stc->e) { goto err; }
            stc->n = calloc(ACVP_RSA_EXP_LEN_MAX, sizeof(char));
            if (!stc->n) { goto err; }
            stc->signature = calloc(ACVP_RSA_SIGNATURE_MAX, sizeof(char));
            if (!stc->signature) { goto err; }
        }
    }
    
    if (salt_len) {
        if (salt) {
            memcpy_s(stc->salt, ACVP_RSA_SIGNATURE_MAX,
                     salt, strnlen_s((const char *)salt, 256));
        }
    }
    stc->salt_len = salt_len;
    
    stc->tg_id = tgId;
    stc->modulo = mod;
    stc->hash_alg = hash_alg;
    stc->sig_type = sig_type;
    
    return 1;
    
err:
    free_rsa_sig_tc(stc);
    return 0;
}

/*
 * invalid hash alg rsa sig handler
 */
Test(APP_RSA_SIG_HANDLER, invalid_hash_alg) {
    ACVP_CIPHER cipher = ACVP_RSA_SIGGEN;
    int tgid = 0;
    int mod = 2048;
    int hash_alg = 0;
    char *e = "aa";
    char *n = "aa";
    char *msg = "aa";
    char *signature = "aa";
    char *salt = "aa";
    int salt_len = 0;
    int corrupt = 0;
    int sig_type = ACVP_RSA_SIG_TYPE_X931;
    
    rsa_sig_tc = calloc(1, sizeof(ACVP_RSA_SIG_TC));
    
    if (!initialize_rsa_sig_tc(cipher, rsa_sig_tc, tgid, sig_type,
            mod, hash_alg, e, n, msg, signature, salt, salt_len,
            corrupt)) {
        cr_assert_fail("rsa sig init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.rsa_sig = rsa_sig_tc;
    
    rv = app_rsa_sig_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_rsa_sig_tc(rsa_sig_tc);
    free(test_case);
}


