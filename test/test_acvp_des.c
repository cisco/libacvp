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

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;

static void setup(void) {
    setup_empty_ctx(&ctx);

    /*
     * Enable 3DES-CBC
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CBC, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_IVLEN, 192 / 3);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 2);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 3);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 12);
    cr_assert(rv == ACVP_SUCCESS);

    /*
     * Enable TDES-CTR
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CTR, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_CTR_INCR, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PTLEN, 64);
    cr_assert(rv == ACVP_SUCCESS);
}

static void setup_fail(void) {
    setup_empty_ctx(&ctx);

    /*
     * Enable 3DES-CBC
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CBC, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_IVLEN, 192 / 3);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 2);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 3);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 12);
    cr_assert(rv == ACVP_SUCCESS);

    /*
     * Enable TDES-CTR
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CTR, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_CTR_INCR, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PTLEN, 64);
    cr_assert(rv == ACVP_SUCCESS);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(DES_CAPABILITY, good) {
    setup_empty_ctx(&ctx);

    /*
     * Enable 3DES-ECB
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_ECB, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PTLEN, 512);
    cr_assert(rv == ACVP_SUCCESS);

    /*
     * Enable 3DES-CBC
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CBC, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_IVLEN, 192 / 3);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 2);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 3);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PTLEN, 64 * 12);
    cr_assert(rv == ACVP_SUCCESS);

    /*
     * Enable 3DES-OFB
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_OFB, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_IVLEN, 192 / 3);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_OFB, ACVP_SYM_CIPH_PTLEN, 64);
    cr_assert(rv == ACVP_SUCCESS);

    /*
     * Enable 3DES-CFB64
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB64, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_IVLEN, 192/3);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB64, ACVP_SYM_CIPH_PTLEN, 64 * 5);
    cr_assert(rv == ACVP_SUCCESS);

    /*
     * Enable 3DES-CFB8
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB8, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_IVLEN, 192/3);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PTLEN, 64);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB8, ACVP_SYM_CIPH_PTLEN, 64 * 4);
    cr_assert(rv == ACVP_SUCCESS);

    /*
     * Enable 3DES-CFB1
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB1, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_IVLEN, 192/3);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CFB1, ACVP_SYM_CIPH_PTLEN, 64);
    cr_assert(rv == ACVP_SUCCESS);


    /*
     * Enable TDES-CTR
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CTR, &dummy_handler_failure);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_THREE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_CTR_INCR, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CTR, ACVP_SYM_CIPH_PTLEN, 64);
    cr_assert(rv == ACVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(DES_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(DES_API, null_ctx) {
    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = acvp_des_kat_handler(NULL, obj);
    cr_assert(rv == ACVP_NO_CTX);
    json_value_free(val);
}


/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(DES_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = acvp_des_kat_handler(ctx, NULL);
    cr_assert(rv == ACVP_MALFORMED_JSON);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(DES_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_SUCCESS);
    json_value_free(val);
}


/*
 * The value for key:"algorithm" is wrong.
 */
Test(DES_HANDLER, wrong_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_UNSUPPORTED_OP);
    json_value_free(val);
}


/*
 * The key:"direction" is missing.
 */
Test(DES_HANDLER, missing_direction, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"direction" is wrong.
 */
Test(DES_HANDLER, wrong_direction, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"testType" is missing.
 */
Test(DES_HANDLER, missing_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"testType" is wrong.
 */
Test(DES_HANDLER, wrong_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"key1" is missing.
 */
Test(DES_HANDLER, missing_key1, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"key1" string is wrong length.
 */
Test(DES_HANDLER, wrong_key1, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"key2" is missing.
 */
Test(DES_HANDLER, missing_key2, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"key2" string is wrong length.
 */
Test(DES_HANDLER, wrong_key2, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"key3" is missing.
 */
Test(DES_HANDLER, missing_key3, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"key3" string is wrong length.
 */
Test(DES_HANDLER, wrong_key3, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"pt" is missing.
 */
Test(DES_HANDLER, missing_pt, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"pt" string is too long.
 */
Test(DES_HANDLER, wrong_pt, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"ct" is missing.
 */
Test(DES_HANDLER, missing_ct, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"ct" string is too long.
 */
Test(DES_HANDLER, wrong_ct, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"iv" is missing.
 */
Test(DES_HANDLER, missing_iv, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"iv" string is wrong length.
 */
Test(DES_HANDLER, wrong_iv, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"tgId" string is missing.
 */
Test(DES_HANDLER, missing_tgid, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_18.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}


/*
 * The boolean for "incrementalCounter" is missing/not a boolean for DES-CTR
 */
Test(DES_HANDLER, bad_inc_ctr, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_19.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}


/*
 * The boolean for "overflowCounter" is missing/not a boolean for DES-CTR
 */
Test(DES_HANDLER, bad_ovrflw_ctr, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_20.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MALFORMED_JSON);
    json_value_free(val);
}


/*
 * Missing tg info in last tg
 */
Test(DES_HANDLER, tgLast, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_21.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * Missing field in last tc
 */
Test(DES_HANDLER, tcLast, .init = setup, .fini = teardown) {
    val = json_parse_file("json/des/des_22.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(DES_HANDLER, cryptoFail1, .init = setup_fail, .fini = teardown) {
    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration of AFT */

    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(DES_HANDLER, cryptoFail2, .init = setup_fail, .fini = teardown) {
    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 5;  /* fail on 6th iteration of AFT */

    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(DES_HANDLER, cryptoFail3, .init = setup_fail, .fini = teardown) {
    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 490; /* fail on first iteration of MCT */

    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(DES_HANDLER, cryptoFail4, .init = setup_fail, .fini = teardown) {
    val = json_parse_file("json/des/des.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 495; /* fail on sixth iteration of MCT */

    rv = acvp_des_kat_handler(ctx, obj);
    cr_assert(rv == ACVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}


