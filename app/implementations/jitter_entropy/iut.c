/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include <stdio.h>

#include "app_lcl.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"

#include <jitterentropy.h>
#include <jitterentropy-sha3.h>

static int app_sha_handler(ACVP_TEST_CASE *test_case) {
    ACVP_HASH_TC *tc =NULL;
    void *ctx = NULL;
    int rc = ACVP_CRYPTO_MODULE_FAIL;

    tc = test_case->tc.hash;
    if (!tc) return rc;

    if (tc->cipher != ACVP_HASH_SHA3_256) {
        printf("Error: Unsupported hash algorithm requested by ACVP server\n");
        return ACVP_NO_CAP;
    }

    if (!tc->msg) {
        printf("\nCrypto module error, msg missing in sha test case\n");
        goto end;
    }

    if (sha3_alloc(&ctx)) {
        printf("\nCrypto module error, JENT SHA3 alloc failed\n");
        goto end;
    }

    sha3_256_init(ctx);
    sha3_update(ctx, tc->msg, tc->msg_len);
    sha3_final(ctx, tc->md);
    tc->md_len = 32;  /* always 256 bit */
    sha3_dealloc(ctx);

    rc = 0;
end:
    return rc;
}

ACVP_RESULT iut_setup(APP_CONFIG *cfg) {
    /* No specific setup needed */
    if (!cfg) {
        return ACVP_INTERNAL_ERR;
    }
    return ACVP_SUCCESS;
}

void iut_print_version(APP_CONFIG *cfg) {
    if (!cfg) {
        return;
    }
    unsigned int jentver = 0, major = 0, minor = 0, patch = 0;
    jentver = jent_version();
    /* See jent code for how the jent int is formatted */
    major = jentver / 1000000;
    minor = jentver % 1000000 / 10000;
    patch = jentver % 1000000 % 10000 / 100;
    printf("Linked JENT version: %u.%u.%u\n", major, minor, patch);
}

ACVP_RESULT iut_register_capabilities(ACVP_CTX *ctx, APP_CONFIG *cfg) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (cfg->hash || cfg->testall) {
        rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA3_256, &app_sha_handler);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_IN_BIT, 0);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_IN_EMPTY, 1);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
        CHECK_ENABLE_CAP_RV(rv);
    }
end:
    return rv;
}

ACVP_RESULT iut_cleanup() {
    /* No specific cleanup needed */
    return ACVP_SUCCESS;
}
