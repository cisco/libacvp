/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


/*
 * This file tests the build_registration API
 * including when some of the capability APIs aren't called
 * (some required values weren't added, for example)
 * test_acvp_capabilities.c tests the enable_* APIs
 */

#include "ut_common.h"
#include "acvp/acvp_lcl.h"

static ACVP_CTX *ctx = NULL;
static ACVP_RESULT rv = 0;
static char *cvalue = "same";
static char *reg;
static JSON_Value *generated_value;
static JSON_Value *known_good_value;
static JSON_Object *generated_obj;
static JSON_Object *known_good_obj;


static void add_des_details_good(void) {
    /*
     * Enable 3DES-ECB
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_ECB, &dummy_handler_success);
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
     * Enable 3DES-OFB
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_OFB, &dummy_handler_success);
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
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB64, &dummy_handler_success);
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
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB8, &dummy_handler_success);
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
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CFB1, &dummy_handler_success);
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
}

static void add_aes_details_good(void) {
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 96);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_IVLEN, 96);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 136);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 264);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 136);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * Enable AES-ECB 128,192,256 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_ECB, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PTLEN, 1536);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * Enable AES-CBC 128 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PTLEN, 1536);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * Enable AES-CFB1 128,192,256 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB1, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PTLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * Enable AES-CFB8 128,192,256 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB8, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PTLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * Enable AES-CFB128 128,192,256 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB128, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PTLEN, 1536);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * Enable AES-OFB 128, 192, 256 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_OFB, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PTLEN, 1536);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * Register AES CCM capabilities
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CCM, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_CCM, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PTLEN, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PTLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 32);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 56);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_IVLEN, 104);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_AADLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * Enable AES keywrap for various key sizes and PT lengths
     * Note: this is with padding disabled, minimum PT length is 128 bits and must be
     *       a multiple of 64 bits. openssl does not support INVERSE mode.
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_KW, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 320);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PTLEN, 1280);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * Enable AES-XTS 128 and 256 bit key
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_XTS, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PTLEN, 65536);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_TWEAK, ACVP_SYM_CIPH_TWEAK_HEX);
    cr_assert(rv == ACVP_SUCCESS);
}

static void add_hash_details_good(void) {
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA1, ACVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA224, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA224, ACVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA256, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA256, ACVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA384, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA384, ACVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA512, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA512, ACVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    cr_assert(rv == ACVP_SUCCESS);
}

static void add_drbg_details_good(void) {
    rv = acvp_cap_drbg_enable(ctx, ACVP_HASHDRBG, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                   ACVP_DRBG_DER_FUNC_ENABLED, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HASHDRBG, 
                                     ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                   ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                   ACVP_DRBG_RESEED_ENABLED, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                     ACVP_DRBG_ENTROPY_LEN, (int)128, (int)64,(int) 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                     ACVP_DRBG_NONCE_LEN, (int)96, (int)32,(int) 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                     ACVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                     ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,
                                   ACVP_DRBG_RET_BITS_LEN, 160);
    cr_assert(rv == ACVP_SUCCESS);
    
    //ACVP_HMACDRBG
    rv = acvp_cap_drbg_enable(ctx, ACVP_HMACDRBG, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMACDRBG, 
                                     ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMACDRBG, 
                                     ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                   ACVP_DRBG_DER_FUNC_ENABLED, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                   ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                   ACVP_DRBG_RESEED_ENABLED, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                   ACVP_DRBG_RET_BITS_LEN, 224);
    cr_assert(rv == ACVP_SUCCESS);
    //Add length range
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                     ACVP_DRBG_ENTROPY_LEN, (int)192, (int)64,(int) 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                     ACVP_DRBG_NONCE_LEN, (int)192, (int)64,(int) 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                     ACVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224,
                                     ACVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == ACVP_SUCCESS);
    
    // ACVP_CTRDRBG
    rv = acvp_cap_drbg_enable(ctx, ACVP_CTRDRBG, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_CTRDRBG, 
                                     ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                     ACVP_DRBG_ENTROPY_LEN, (int)128, (int)128, (int) 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                     ACVP_DRBG_NONCE_LEN, (int)64, (int)64,(int) 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                     ACVP_DRBG_PERSO_LEN, (int)0, (int)256,(int) 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                     ACVP_DRBG_ADD_IN_LEN, (int)0, (int)256,(int) 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                   ACVP_DRBG_DER_FUNC_ENABLED, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                   ACVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                   ACVP_DRBG_RESEED_ENABLED, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128,
                                   ACVP_DRBG_RET_BITS_LEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
}

static void add_cmac_details_good(void) {
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_AES, ACVP_CMAC_MSGLEN, 0, 65536, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_MACLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_GEN, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_VER, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_AES, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_TDES, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_TDES, ACVP_CMAC_MSGLEN, 0, 65536, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_MACLEN, 64);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_KEYING_OPTION, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_DIRECTION_GEN, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_DIRECTION_VER, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_TDES, ACVP_PREREQ_TDES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
}

static void add_hmac_details_good(void) {
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA1, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_MACLEN, 32, 160, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA1, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_224, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_MACLEN, 32, 224, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_224, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_256, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_MACLEN, 32, 256, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_256, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_384, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_MACLEN, 32, 384, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_384, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_MACLEN, 32, 512, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_512, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
}

static void add_dsa_details_good(void) {
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGGEN, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGGEN, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENPQ, ACVP_DSA_PROBABLE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENG, ACVP_DSA_CANONICAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_256, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_256, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN3072_256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN3072_256, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN3072_256, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGVER, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGVER, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGVER, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_GENPQ, ACVP_DSA_PROBABLE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_GENG, ACVP_DSA_CANONICAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_256, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_256, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN3072_256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN3072_256, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN3072_256, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    
    
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_KEYGEN, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_224, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_224, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_224, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_224, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_256, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_256, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_256, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN3072_256, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN3072_256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN3072_256, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN3072_256, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    
    
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGGEN, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGGEN, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    
    
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_SIGVER, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGVER, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGVER, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
}

static void add_rsa_details_good(void) {
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7);
    
    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_INFO_GEN_BY_SERVER, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_KEY_FORMAT_CRT, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_keygen_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B34);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 2048, ACVP_RSA_PRIME_HASH_ALG, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    // TODO: leaving this in here as a workaround until the server allows it as optional
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 2048, ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 3072, ACVP_RSA_PRIME_HASH_ALG, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    // TODO: leaving this in here as a workaround until the server allows it as optional
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B34, 3072, ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * Enable siggen
     */
    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    
    // RSA w/ sigType: X9.31
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    // RSA w/ sigType: PKCS1v1.5
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * Enable sigver
     */
    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGVER, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_sigver_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_exponent(ctx, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    cr_assert(rv == ACVP_SUCCESS);
    
    // RSA w/ sigType: X9.31
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    // RSA w/ sigType: PKCS1v1.5
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA1, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA224, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA384, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512, 0);
    cr_assert(rv == ACVP_SUCCESS);
    free(expo_str);
}

static void add_ecdsa_details_good(void) {
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_SECRET_GEN, ACVP_ECDSA_SECRET_GEN_TEST_CAND);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * Enable ECDSA keyVer...
     */
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYVER, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    cr_assert(rv == ACVP_SUCCESS);
    
    
    /*
     * Enable ECDSA sigGen...
     */
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * Enable ECDSA sigVer...
     */
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGVER, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
}

static void add_kdf_details_good(void) {
    int i, flags = 0;
    
    /*
     * Enable KDF-135
     */
    rv = acvp_cap_kdf135_tls_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_TLS, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_TLS, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_tls_set_parm(ctx, ACVP_KDF135_TLS, ACVP_KDF135_TLS12, ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SNMP, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_snmp_set_parm(ctx, ACVP_KDF135_SNMP, ACVP_KDF135_SNMP_PASS_LEN, 64);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_snmp_set_engid(ctx, ACVP_KDF135_SNMP, "testengidtestengid");
    cr_assert(rv == ACVP_SUCCESS);
    
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
    
    rv = acvp_cap_kdf135_srtp_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SRTP, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_SUPPORT_ZERO_KDR, 0);
    cr_assert(rv == ACVP_SUCCESS);
    for (i = 0; i < 24; i++) {
        rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_KDF_EXPONENT, i + 1);
        cr_assert(rv == ACVP_SUCCESS);
    }
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 192);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_srtp_set_parm(ctx, ACVP_KDF135_SRTP, ACVP_SRTP_AES_KEYLEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_kdf135_ikev2_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV2, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV2, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    // can use len_param or domain_param for these attributes
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_INIT_NONCE_LEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_INIT_NONCE_LEN, 2048);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_RESPOND_NONCE_LEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_RESPOND_NONCE_LEN, 2048);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_DH_SECRET_LEN, 2048);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_KEY_MATERIAL_LEN, 1056);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev2_set_length(ctx, ACVP_KEY_MATERIAL_LEN, 3072);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev2_set_parm(ctx, ACVP_KDF_HASH_ALG, ACVP_SHA1);
    cr_assert(rv == ACVP_SUCCESS);
    
    /*
     * KDF108 Counter Mode
     */
    rv = acvp_cap_kdf108_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF108, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_COUNTER_LEN, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_AFTER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTS_EMPTY_IV, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_REQUIRES_EMPTY_IV, 0);
    cr_assert(rv == ACVP_INVALID_ARG);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTS_EMPTY_IV, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_REQUIRES_EMPTY_IV, 1);
    cr_assert(rv == ACVP_SUCCESS);

}

static void add_kas_ecc_details_good(void) {
    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_PREREQ_ECDSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P521);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K571);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B233);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B283);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B409);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B571);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_COMP, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_ECDSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CCM, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_CMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED,  ACVP_KAS_ECC_KDF, 0, ACVP_KAS_ECC_NOKDFNOKC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EB, ACVP_EC_CURVE_P224, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EC, ACVP_EC_CURVE_P256, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ED, ACVP_EC_CURVE_P384, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_COMP, ACVP_KAS_ECC_MODE_COMPONENT, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_EE, ACVP_EC_CURVE_P521, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
}

static void add_kas_ffc_details_good(void) {
    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_COMP, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_DSA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_CCM, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_CMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPGEN);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPVAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_RESPONDER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_KDF, ACVP_KAS_FFC_NOKDFNOKC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FC, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
    if (reg) {
        free(reg);
        reg = NULL;
    }

    if (known_good_value) {
        json_value_free(known_good_value);
        known_good_value = NULL;
    }
    if (generated_value) {
        json_value_free(generated_value);
        generated_value = NULL;
    }
    generated_obj = NULL;
    known_good_obj = NULL;
    
}


#if 0
/*
 * The ctx is null, expecting failure.
 */
Test(BUILD_VENDORS, null_ctx) {
    rv  = acvp_build_vendors(NULL, &reg);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * The ctx is null, expecting failure.
 */
Test(BUILD_MODULES, null_ctx) {
    rv  = acvp_build_modules(NULL, &reg);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * The ctx is null, expecting failure.
 */
Test(BUILD_DEPS, null_dep) {
    rv  = acvp_build_dependency(NULL, &reg);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * The ctx is null, expecting failure.
 */
Test(BUILD_OES, null_ctx) {
    rv  = acvp_build_oes(NULL, &reg);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_VENDORS, good_vendors_output, .init = setup_empty_with_vendor_and_module_info, .fini = teardown) {
    rv = acvp_build_vendors(ctx, &reg);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/registration_setup/vendors.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)known_good_obj, (JSON_Value *)generated_obj) == JSONSuccess);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_MODULES, good_modules_output, .init = setup_empty_with_vendor_and_module_info, .fini = teardown) {
    rv = acvp_build_modules(ctx, &reg);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/registration_setup/modules.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)known_good_obj, (JSON_Value *)generated_obj) == JSONSuccess);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_OES, good_oes_output, .init = setup_empty_with_vendor_and_module_info, .fini = teardown) {
    rv = acvp_build_oes(ctx, &reg);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/registration_setup/oes.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)known_good_obj, (JSON_Value *)generated_obj) == JSONSuccess);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_DEPS, good_deps_output, .init = setup_empty_with_vendor_and_module_info, .fini = teardown) {
    rv = acvp_build_dependency(ctx->dependency_list, &reg);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/registration_setup/deps.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *) known_good_obj, (JSON_Value *) generated_obj) == JSONSuccess);
}
#endif

/*
 * The ctx is null, expecting failure.
 */
Test(BUILD_TEST_SESSION, null_ctx) {
    rv  = acvp_build_test_session(NULL, &reg, NULL);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * The ctx is has no capabilities, expecting failure.
 */
Test(BUILD_TEST_SESSION, np_caps_ctx, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_NO_CAP);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_TEST_SESSION, good_aes_output, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_aes_details_good();
    
    rv = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/aes/aes_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The ctx has an aes registration that is missing keylen
 * (a required val)
 */
Test(BUILD_TEST_SESSION, missing_required_keylen_aes, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);;
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 96);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_IVLEN, 96);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * The ctx has an aes registration where enable_sym_cipher_cap_parm was
 * never called
 */
Test(BUILD_TEST_SESSION, missing_required_direction_aes, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * The ctx has a good hash registration
 */
Test(BUILD_TEST_SESSION, good_hash, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_hash_details_good();
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/hash/hash_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The ctx has a good drbg registration
 */
Test(BUILD_TEST_SESSION, good_drbg, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_drbg_details_good();
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/drbg/drbg_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The detail capability APIs for drbg are never called
 */
Test(BUILD_TEST_SESSION, drbg_missing_cap_parms, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = acvp_cap_drbg_enable(ctx, ACVP_HASHDRBG, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);

    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_TEST_SESSION, good_cmac_output, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_cmac_details_good();
    
    rv = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/cmac/cmac_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * cmac direction attribute never enabled
 */
Test(BUILD_TEST_SESSION, cmac_missing_direction, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_AES, ACVP_CMAC_MSGLEN, 0, 65536, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_MACLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_AES, ACVP_PREREQ_AES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * cmac direction attribute never enabled
 */
Test(BUILD_TEST_SESSION, cmac_missing_tdes_ko, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_TDES, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_TDES, ACVP_CMAC_MSGLEN, 0, 65536, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_MACLEN, 64);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_DIRECTION_GEN, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_TDES, ACVP_CMAC_DIRECTION_VER, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_TDES, ACVP_PREREQ_TDES, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * The ctx has a good hmac registration
 */
Test(BUILD_TEST_SESSION, good_hmac, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_hmac_details_good();
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/hmac/hmac_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The ctx has a good dsa registration
 */
Test(BUILD_TEST_SESSION, good_dsa, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_dsa_details_good();
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/dsa/dsa_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * dsa registration with missing args
 */
Test(BUILD_TEST_SESSION, dsa_missing_pqgen, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENG, ACVP_DSA_CANONICAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
    
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGVER, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_GENG, ACVP_DSA_CANONICAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * dsa registration with missing args
 */
Test(BUILD_TEST_SESSION, dsa_missing_ggen, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENPQ, ACVP_DSA_PROBABLE);
    cr_assert(rv == ACVP_SUCCESS);
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
    
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGVER, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_GENPQ, ACVP_DSA_PROBABLE);
    cr_assert(rv == ACVP_SUCCESS);
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * dsa registration with missing args
 */
Test(BUILD_TEST_SESSION, dsa_missing_hashalgs, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENPQ, ACVP_DSA_PROBABLE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENG, ACVP_DSA_CANONICAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
    
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGVER, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_GENPQ, ACVP_DSA_PROBABLE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_GENG, ACVP_DSA_CANONICAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
    
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
    
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
    
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_SIGVER, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_TEST_SESSION, good_des_output, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_des_details_good();
    
    rv = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }

    known_good_value = json_parse_file("json/des/des_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The ctx has a good rsa registration
 */
Test(BUILD_TEST_SESSION, good_rsa, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_rsa_details_good();
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/rsa/rsa_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The rsa registration never calls params API
 */
Test(BUILD_TEST_SESSION, rsa_no_params, .fini = teardown) {
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * The ctx has a good ecdsa registration
 */
Test(BUILD_TEST_SESSION, good_ecdsa, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_ecdsa_details_good();
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/ecdsa/ecdsa_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The ecdsa registration never calls params API
 */
Test(BUILD_TEST_SESSION, ecdsa_no_params, .fini = teardown) {
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYVER, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * The ctx has a good kdf registration
 */
Test(BUILD_TEST_SESSION, good_kdf, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_kdf_details_good();
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/kdf/kdf_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * kdf enable modes not in ciscossl
 */
Test(BUILD_TEST_SESSION, kdf_more_modes, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = acvp_cap_kdf108_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_COUNTER_LEN, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_AFTER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTS_EMPTY_IV, 0);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_kdf108_set_domain(ctx, ACVP_KDF108_MODE_DPI, ACVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_DPI, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_DPI, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_DPI, ACVP_KDF108_COUNTER_LEN, 8);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_DPI, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_AFTER);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_DPI, ACVP_KDF108_SUPPORTS_EMPTY_IV, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_KEY_DATA_LEN, 256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_FIELD_SIZE, 224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_SHARED_INFO_LEN, 256);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_kdf135_ikev1_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV1, ACVP_PREREQ_SHA, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_IKEV1, ACVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_INIT_NONCE_LEN, 64, 2048, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_RESPOND_NONCE_LEN, 64, 2048, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_DH_SECRET_LEN, 224, 8192, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev1_set_domain(ctx, ACVP_KDF_IKEv1_PSK_LEN, 8, 8192, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, ACVP_SHA1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, ACVP_SHA384);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, ACVP_SHA256);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_HASH_ALG, ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_AUTH_METHOD, ACVP_KDF135_IKEV1_AMETH_PSK);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_AUTH_METHOD, ACVP_KDF135_IKEV1_AMETH_DSA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_ikev1_set_parm(ctx, ACVP_KDF_IKEv1_AUTH_METHOD, ACVP_KDF135_IKEV1_AMETH_PKE);
    cr_assert(rv == ACVP_SUCCESS);

    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * The ctx has a good kas ecc registration
 */
Test(BUILD_TEST_SESSION, good_kas_ecc, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_kas_ecc_details_good();
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/kas_ecc/kas_ecc_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The kas registration never calls params API
 */
Test(BUILD_TEST_SESSION, kas_ecc_no_params, .fini = teardown) {
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * The ctx has a good kas ffc registration
 */
Test(BUILD_TEST_SESSION, good_kas_ffc, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_kas_ffc_details_good();
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_SUCCESS);
    
    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        ACVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/kas_ffc/kas_ffc_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        ACVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }
    
    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The kas registration never calls params API
 */
Test(BUILD_TEST_SESSION, kas_ffc_no_params, .fini = teardown) {
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_COMP, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv  = acvp_build_test_session(ctx, &reg, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}
