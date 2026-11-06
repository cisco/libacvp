/*
 * Copyright (c) 2026, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"
#include "safe_lib.h"
#include "implementations/openssl/3/iut.h"

#include <openssl/evp.h>
#include <openssl/err.h>

static int get_x_curve_params(ACVP_X_CURVE curve, const char **name, size_t *key_len) {
    switch (curve) {
    case ACVP_X_CURVE_25519:
        *name = "X25519";
        *key_len = 32;
        return 0;
    case ACVP_X_CURVE_448:
        *name = "X448";
        *key_len = 56;
        return 0;
    case ACVP_X_CURVE_START:
    case ACVP_X_CURVE_END:
    default:
        return 1;
    }
}

static EVP_PKEY *generate_key(const char *name) {
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;

    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    if (!pkey_ctx) {
        printf("Error creating pkey CTX in XECDH\n");
        return NULL;
    }
    if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
        printf("Error initializing keygen in XECDH\n");
        goto end;
    }
    if (EVP_PKEY_generate(pkey_ctx, &pkey) != 1) {
        printf("Error generating key in XECDH\n");
        pkey = NULL;
    }
end:
    EVP_PKEY_CTX_free(pkey_ctx);
    return pkey;
}

int app_xecdh_handler(ACVP_TEST_CASE *test_case) {
    int rv = 1;
    size_t key_len = 0, len = 0;
    const char *name = NULL;
    ACVP_XECDH_TC *tc = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL, *peer = NULL;

    if (!test_case) {
        printf("No test case found\n");
        return 1;
    }
    tc = test_case->tc.xecdh;
    if (!tc) {
        printf("Error: test case not found in XECDH handler\n");
        return 1;
    }

    if (get_x_curve_params(tc->curve, &name, &key_len)) {
        printf("Unable to lookup curve name for XECDH\n");
        return 1;
    }

    switch (acvp_get_xecdh_alg(tc->cipher)) {
    case ACVP_SUB_XECDH_KEYGEN:
        if (!tc->private_key || !tc->public_key) {
            printf("Missing output buffers in XECDH keygen\n");
            goto err;
        }
        pkey = generate_key(name);
        if (!pkey) {
            goto err;
        }
        len = key_len;
        if (EVP_PKEY_get_raw_private_key(pkey, tc->private_key, &len) != 1) {
            printf("Error getting private key in XECDH keygen\n");
            goto err;
        }
        tc->private_key_len = (int)len;
        len = key_len;
        if (EVP_PKEY_get_raw_public_key(pkey, tc->public_key, &len) != 1) {
            printf("Error getting public key in XECDH keygen\n");
            goto err;
        }
        tc->public_key_len = (int)len;
        break;
    case ACVP_SUB_XECDH_KEYVER:
        tc->ver_disposition = ACVP_TEST_DISPOSITION_FAIL;
        if (!tc->public_key) {
            printf("Missing public key in XECDH keyver\n");
            goto err;
        }
        pkey = EVP_PKEY_new_raw_public_key_ex(NULL, name, NULL, tc->public_key, tc->public_key_len);
        if (!pkey) {
            // An import failure means the key is invalid
            ERR_clear_error();
            break;
        }
        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (!pkey_ctx) {
            printf("Error creating pkey CTX in XECDH keyver\n");
            goto err;
        }
        if (EVP_PKEY_public_check(pkey_ctx) == 1) {
            tc->ver_disposition = ACVP_TEST_DISPOSITION_PASS;
        }
        ERR_clear_error();
        break;
    case ACVP_SUB_XECDH_SSC:
        if (!tc->public_server || !tc->public_iut || !tc->z) {
            printf("Missing buffers in XECDH SSC\n");
            goto err;
        }
        pkey = generate_key(name);
        if (!pkey) {
            goto err;
        }
        len = key_len;
        if (EVP_PKEY_get_raw_public_key(pkey, tc->public_iut, &len) != 1) {
            printf("Error getting public key in XECDH SSC\n");
            goto err;
        }
        tc->public_iut_len = (int)len;

        peer = EVP_PKEY_new_raw_public_key_ex(NULL, name, NULL, tc->public_server, tc->public_server_len);
        if (!peer) {
            printf("Error importing server public key in XECDH SSC\n");
            goto err;
        }
        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (!pkey_ctx) {
            printf("Error creating pkey CTX in XECDH SSC\n");
            goto err;
        }
        if (EVP_PKEY_derive_init(pkey_ctx) != 1) {
            printf("Error initializing derive in XECDH SSC\n");
            goto err;
        }
        if (EVP_PKEY_derive_set_peer(pkey_ctx, peer) != 1) {
            printf("Error setting peer key in XECDH SSC\n");
            goto err;
        }
        len = key_len;
        if (EVP_PKEY_derive(pkey_ctx, tc->z, &len) != 1) {
            printf("Error deriving shared secret in XECDH SSC\n");
            goto err;
        }
        tc->z_len = (int)len;
        break;
    default:
        printf("Invalid XECDH alg in test case\n");
        goto err;
    }

    rv = 0;
err:
    if (rv != 0) ERR_print_errors_fp(stderr);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (peer) EVP_PKEY_free(peer);
    if (pkey) EVP_PKEY_free(pkey);
    return rv;
}
