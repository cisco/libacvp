/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include <stdio.h>

#include "app_lcl.h"
#include "implementations/openssl/3/iut.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/provider.h>
#include <openssl/evp.h>



static int enable_dsa(ACVP_CTX *ctx);
static int enable_kas_ffc(ACVP_CTX *ctx);
static int enable_safe_primes(ACVP_CTX *ctx);
static int enable_aes(ACVP_CTX *ctx);
static int enable_tdes(ACVP_CTX *ctx);
static int enable_hash(ACVP_CTX *ctx);
static int enable_cmac(ACVP_CTX *ctx);
static int enable_hmac(ACVP_CTX *ctx);
static int enable_kmac(ACVP_CTX *ctx);
static int enable_rsa(ACVP_CTX *ctx);
static int enable_ecdsa(ACVP_CTX *ctx);
static int enable_drbg(ACVP_CTX *ctx);
static int enable_kas_ecc(ACVP_CTX *ctx);
static int enable_kas_ifc(ACVP_CTX *ctx);
static int enable_kda(ACVP_CTX *ctx);
static int enable_kts_ifc(ACVP_CTX *ctx);
static int enable_kdf(ACVP_CTX *ctx);

ACVP_RESULT register_capabilities_fp_30X(ACVP_CTX *ctx, APP_CONFIG *cfg) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (cfg->aes || cfg->testall) { if ((rv = enable_aes(ctx))) goto end; }
    if (cfg->tdes || cfg->testall) { if ((rv = enable_tdes(ctx))) goto end; }
    if (cfg->hash || cfg->testall) { if ((rv = enable_hash(ctx))) goto end; }
    if (cfg->cmac || cfg->testall) { if ((rv = enable_cmac(ctx))) goto end; }
    if (cfg->hmac || cfg->testall) { if ((rv = enable_hmac(ctx))) goto end; }
    if (cfg->kmac || cfg->testall) { if ((rv = enable_kmac(ctx))) goto end; }
    if (cfg->kdf || cfg->testall) { if ((rv = enable_kdf(ctx))) goto end; }
    if (cfg->rsa || cfg->testall) { if ((rv = enable_rsa(ctx))) goto end; }
    if (cfg->ecdsa || cfg->testall) { if ((rv = enable_ecdsa(ctx))) goto end; }
    if (cfg->drbg || cfg->testall) { if ((rv = enable_drbg(ctx))) goto end; }
    if (cfg->kas_ecc || cfg->testall) { if ((rv = enable_kas_ecc(ctx))) goto end; }
    if (cfg->kas_ifc || cfg->testall) { if ((rv = enable_kas_ifc(ctx))) goto end; }
    if (cfg->kts_ifc || cfg->testall) { if ((rv = enable_kts_ifc(ctx))) goto end; }
    if (cfg->kda || cfg->testall) { if ((rv = enable_kda(ctx))) goto end; }
    if (cfg->dsa || cfg->testall) { if ((rv = enable_dsa(ctx))) goto end; }
    if (cfg->kas_ffc || cfg->testall) { if ((rv = enable_kas_ffc(ctx))) goto end; }
    if (cfg->safe_primes || cfg->testall) { if ((rv = enable_safe_primes(ctx))) goto end; }

end:
    return rv;
}

static int enable_aes(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    // Enable AES_GCM
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_EITHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_DOMAIN_IVLEN, 96, 1024, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 104);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 112);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 120);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_DOMAIN_PTLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable AES-ECB 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_ECB, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_ECB, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable AES-CBC 128 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable AES-CBC-CS1, CS2, and CS3
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS1, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS1, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS2, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS2, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC_CS3, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CBC_CS3, ACVP_SYM_CIPH_DOMAIN_PTLEN, 136, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable AES-CFB1 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB1, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB1, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable AES-CFB8 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB8, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB8, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable AES-CFB128 128,192,256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB128, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CFB128, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable AES-OFB 128, 192, 256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_OFB, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_OFB, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    // Register AES CCM capabilities
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CCM, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_CCM, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_DOMAIN_PTLEN, 0, 256, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 80);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 112);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_DOMAIN_IVLEN, 56, 104, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CCM, ACVP_SYM_CIPH_DOMAIN_AADLEN, 0, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);

    // AES-KW
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_KW, &app_aes_keywrap_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_INVERSE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 524288, 128);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KW, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_KWP, &app_aes_keywrap_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_CIPHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KW_MODE, ACVP_SYM_KW_INVERSE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_KWP, ACVP_SYM_CIPH_DOMAIN_PTLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable AES-XTS 128 and 256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_XTS, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_TWEAK, ACVP_SYM_CIPH_TWEAK_HEX);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 128);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable AES-CTR 128, 192, 256 bit key
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CTR, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);

    // CTR_INCR and CTR_OVRFLW are ignored by server if PERFORM_CTR is false - can remove those calls if so
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_PERFORM_CTR, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CTR_INCR, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_PARM_CTR_OVRFLW, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_CTR, ACVP_SYM_CIPH_DOMAIN_PTLEN, 8, 128, 8);
    CHECK_ENABLE_CAP_RV(rv);

    // GMAC
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GMAC, &app_aes_handler_gmac);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GMAC, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GMAC, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_EITHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 104);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 112);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 120);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GMAC, ACVP_SYM_CIPH_IVLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

static int enable_tdes(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    // Enable 3DES-ECB
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_ECB, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_ECB, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable 3DES-CBC
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CBC, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_TDES_CBC, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

end:
    return rv;
}

static int enable_hash(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    int i = 0;

    // Enable SHA-1 and SHA-2
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA1, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA224, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA224, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA256, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA384, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA384, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA512, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA512, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA512_224, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA512_224, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA512_256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA512_256, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA3_224, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_224, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_224, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA3_224, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA3_256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA3_384, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_384, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_384, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA3_384, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA3_512, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_512, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_512, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA3_512, ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHAKE_128, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHAKE_128, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHAKE_128, ACVP_HASH_OUT_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHAKE_128, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHAKE_128, ACVP_HASH_OUT_LENGTH, 16, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHAKE_256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHAKE_256, ACVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHAKE_256, ACVP_HASH_OUT_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHAKE_256, ACVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHAKE_256, ACVP_HASH_OUT_LENGTH, 16, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    // Run large data tests for SHA3 for 3.0.8 and greater
    if (fips_ver >= OPENSSL_FIPS_308) {
        for (i = 1; i <= max_ldt_size; i *= 2) {
            rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_224, ACVP_HASH_LARGE_DATA, i);
            CHECK_ENABLE_CAP_RV(rv);
            rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_256, ACVP_HASH_LARGE_DATA, i);
            CHECK_ENABLE_CAP_RV(rv);
            rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_384, ACVP_HASH_LARGE_DATA, i);
            CHECK_ENABLE_CAP_RV(rv);
            rv = acvp_cap_hash_set_parm(ctx, ACVP_HASH_SHA3_512, ACVP_HASH_LARGE_DATA, i);
            CHECK_ENABLE_CAP_RV(rv);
        }
    }
end:
    return rv;
}

static int enable_cmac(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    // Enable CMAC
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &app_cmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_domain(ctx, ACVP_CMAC_AES, ACVP_CMAC_MSGLEN, 0, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_MACLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_CMAC_AES, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_GEN, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_VER, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

static int enable_kmac(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    // Enable KMAC
    rv = acvp_cap_kmac_enable(ctx, ACVP_KMAC_128, &app_kmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_128, ACVP_KMAC_MSGLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_128, ACVP_KMAC_MACLEN, 32, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_128, ACVP_KMAC_KEYLEN, 128, 1024, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_128, ACVP_KMAC_XOF_SUPPORT, ACVP_XOF_SUPPORT_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    // OpenSSL 3.X supports hex customization strings, but they are not on the FIPS cert, so leaving disabled
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_128, ACVP_KMAC_HEX_CUSTOM_SUPPORT, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kmac_enable(ctx, ACVP_KMAC_256, &app_kmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_256, ACVP_KMAC_MSGLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_256, ACVP_KMAC_MACLEN, 32, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_domain(ctx, ACVP_KMAC_256, ACVP_KMAC_KEYLEN, 128, 1024, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_256, ACVP_KMAC_XOF_SUPPORT, ACVP_XOF_SUPPORT_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    // OpenSSL 3.X supports hex customization strings, but they are not on the FIPS cert, so leaving disabled
    rv = acvp_cap_kmac_set_parm(ctx, ACVP_KMAC_256, ACVP_KMAC_HEX_CUSTOM_SUPPORT, 0);
    CHECK_ENABLE_CAP_RV(rv);
end:
    return rv;
}

static int enable_hmac(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA1, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA1, ACVP_HMAC_MACLEN, 32, 160, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA1, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_224, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_224, ACVP_HMAC_MACLEN, 32, 224, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_224, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_256, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_MACLEN, 32, 256, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_256, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_384, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_384, ACVP_HMAC_MACLEN, 32, 384, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_384, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512, ACVP_HMAC_MACLEN, 32, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_512, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512_224, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512_224, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512_224, ACVP_HMAC_MACLEN, 32, 224, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_512_224, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512_256, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512_256, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_512_256, ACVP_HMAC_MACLEN, 32, 256, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA2_512_256, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA3_224, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_224, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_224, ACVP_HMAC_MACLEN, 32, 224, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA3_224, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA3_256, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_256, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_256, ACVP_HMAC_MACLEN, 32, 256, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA3_256, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA3_384, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_384, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_384, ACVP_HMAC_MACLEN, 32, 384, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA3_384, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA3_512, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_512, ACVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA3_512, ACVP_HMAC_MACLEN, 32, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMAC_SHA3_512, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
end:

    return rv;
}

static int enable_kdf(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    int flags = 0;

    rv = acvp_cap_kdf_tls12_enable(ctx, &app_kdf_tls12_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS12, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls12_set_parm(ctx, ACVP_KDF_TLS12_HASH_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kdf135_ssh_enable(ctx, &app_kdf135_ssh_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_TDES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_SSH, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);

    // Bit flags for kdf135_ssh sha capabilities
    flags = ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256
            | ACVP_SHA384 | ACVP_SHA512;

    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_TDES_CBC, flags);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_128_CBC, flags);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_192_CBC, flags);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_ssh_set_parm(ctx, ACVP_KDF135_SSH, ACVP_SSH_METH_AES_256_CBC, flags);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kdf135_x942_enable(ctx, &app_kdf135_x942_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X942, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_KDF_TYPE, ACVP_KDF_X942_KDF_TYPE_DER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA3_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA3_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA3_384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_HASH_ALG, ACVP_SHA3_512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_domain(ctx, ACVP_KDF_X942_KEY_LEN, 8, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_domain(ctx, ACVP_KDF_X942_OTHER_INFO_LEN, 0, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_domain(ctx, ACVP_KDF_X942_ZZ_LEN, 8, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_domain(ctx, ACVP_KDF_X942_SUPP_INFO_LEN, 0, 120, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_OID, ACVP_KDF_X942_OID_AES128KW);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_OID, ACVP_KDF_X942_OID_AES192KW);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x942_set_parm(ctx, ACVP_KDF_X942_OID, ACVP_KDF_X942_OID_AES256KW);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kdf135_x963_enable(ctx, &app_kdf135_x963_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_X963, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_HASH_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_KEY_DATA_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_KEY_DATA_LEN, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_FIELD_SIZE, 224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_FIELD_SIZE, 571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_SHARED_INFO_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf135_x963_set_parm(ctx, ACVP_KDF_X963_SHARED_INFO_LEN, 1024);
    CHECK_ENABLE_CAP_RV(rv);

    // KDF108 Counter Mode
    rv = acvp_cap_kdf108_enable(ctx, &app_kdf108_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF108, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF108, ACVP_PREREQ_CMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 72);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 776);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 3456);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_SUPPORTED_LEN, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_COUNTER_LEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_COUNTER, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_BEFORE);
    CHECK_ENABLE_CAP_RV(rv);
    // KDF108 Feedback Mode
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 72);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 776);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 3456);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTED_LEN, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_CMAC_AES256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_MAC_MODE, ACVP_KDF108_MAC_MODE_HMAC_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_SUPPORTS_EMPTY_IV, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_REQUIRES_EMPTY_IV, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_COUNTER_LEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf108_set_parm(ctx, ACVP_KDF108_MODE_FEEDBACK, ACVP_KDF108_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_BEFORE);
    CHECK_ENABLE_CAP_RV(rv);

    // PBKDF
    rv = acvp_cap_pbkdf_enable(ctx, &app_pbkdf_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_PBKDF, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_parm(ctx, ACVP_PBKDF_HMAC_ALG, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_ITERATION_COUNT, 1, 10000, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_KEY_LEN, 112, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_PASSWORD_LEN, 8, 128, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_pbkdf_set_domain(ctx, ACVP_PBKDF_SALT_LEN, 128, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kdf_tls13_enable(ctx, &app_kdf_tls13_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF_TLS13, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_HMAC_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_DHE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kdf_tls13_set_parm(ctx, ACVP_KDF_TLS13_RUNNING_MODE, ACVP_KDF_TLS13_RUN_MODE_PSK_DHE);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

static int enable_kas_ecc(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    // Enable KAS-ECC....
    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &app_kas_ecc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_PREREQ_ECDSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_REVISION, ACVP_REVISION_SP800_56AR3);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_SSC, &app_kas_ecc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_ECDSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_scheme(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_EPHEMERAL_UNIFIED, ACVP_KAS_ECC_ROLE, 0, ACVP_KAS_ECC_ROLE_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_SSC, ACVP_KAS_ECC_MODE_NONE, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

static int enable_kas_ifc(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    BIGNUM *expo = NULL;
    char *expo_str = NULL;

    expo = BN_new();
    if (!expo || !BN_set_word(expo, RSA_F4)) {
        printf("oh no\n");
        return 1;
    }
    expo_str = BN_bn2hex(expo);
    BN_free(expo);

    rv = acvp_cap_kas_ifc_enable(ctx, ACVP_KAS_IFC_SSC, &app_kas_ifc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_RSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KAS_IFC_SSC, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS1, ACVP_KAS_IFC_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_exponent(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_FIXEDPUBEXP, expo_str);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS2, ACVP_KAS_IFC_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KAS2, ACVP_KAS_IFC_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_MODULO, 8192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG1_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG2_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG1_PRIME_FACTOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG2_PRIME_FACTOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG1_CRT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ifc_set_parm(ctx, ACVP_KAS_IFC_SSC, ACVP_KAS_IFC_KEYGEN_METHOD, ACVP_KAS_IFC_RSAKPG2_CRT);
    CHECK_ENABLE_CAP_RV(rv);

end:
    if (expo_str) free(expo_str);
    return rv;
}

static int enable_kts_ifc(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    BIGNUM *expo = NULL;
    char *expo_str = NULL;
    char iut_id[] = "DEADDEAD";
    char concatenation[] = "concatenation";

    expo = BN_new();
    if (!expo || !BN_set_word(expo, RSA_F4)) {
        printf("oh no\n");
        return 1;
    }
    expo_str = BN_bn2hex(expo);
    BN_free(expo);

    rv = acvp_cap_kts_ifc_enable(ctx, ACVP_KTS_IFC, &app_kts_ifc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_RSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KTS_IFC, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_param_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FIXEDPUBEXP, expo_str);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_param_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_IUT_ID, iut_id);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FUNCTION, ACVP_KTS_IFC_KEYPAIR_GEN);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_FUNCTION, ACVP_KTS_IFC_PARTIAL_VAL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_MODULO, 6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG1_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG2_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG1_PRIME_FACTOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG2_PRIME_FACTOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG1_CRT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KEYGEN_METHOD, ACVP_KTS_IFC_RSAKPG2_CRT);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kts_ifc_set_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_SCHEME, ACVP_KTS_IFC_KAS1_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ROLE, ACVP_KTS_IFC_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ROLE, ACVP_KTS_IFC_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA3_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA3_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA3_384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_HASH, ACVP_SHA3_512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_L, 1024);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kts_ifc_set_scheme_parm(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_NULL_ASSOC_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kts_ifc_set_scheme_string(ctx, ACVP_KTS_IFC, ACVP_KTS_IFC_KAS1_BASIC, ACVP_KTS_IFC_ENCODING, concatenation);
    CHECK_ENABLE_CAP_RV(rv);

end:
    if (expo_str) free(expo_str);
    return rv;
}

#if !defined OPENSSL_NO_DSA
static int enable_kas_ffc(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_SSC, &app_kas_ffc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_SAFE_PRIMES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_DSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FB);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FFDHE2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FFDHE3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FFDHE4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FFDHE6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_SSC, ACVP_KAS_FFC_MODE_NONE, ACVP_KAS_FFC_GEN_METH, ACVP_KAS_FFC_FFDHE8192);
    CHECK_ENABLE_CAP_RV(rv);
end:

    return rv;
}
#endif

static int enable_kda(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_HKDF, &app_kda_hkdf_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_HKDF, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA1, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_HKDF, ACVP_KDA_Z, 224, 8192, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA512_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA512_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA3_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA3_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA3_384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_ALG, ACVP_SHA3_512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_HKDF, ACVP_KDA_L, 2048, NULL);
    CHECK_ENABLE_CAP_RV(rv);

    // kdf onestep
    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_ONESTEP, &app_kda_onestep_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_ONESTEP, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_ONESTEP, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_ONESTEP, ACVP_PREREQ_KMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HASH_SHA512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_HMAC_SHA2_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ONESTEP_AUX_FUNCTION, ACVP_KMAC_128, NULL);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kda_set_domain(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_Z, 224, 8192, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_set_parm(ctx, ACVP_KDA_ONESTEP, ACVP_KDA_L, 2048, NULL);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_kda_enable(ctx, ACVP_KDA_TWOSTEP, &app_kda_twostep_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDA_TWOSTEP, ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_L, 2048, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_domain(ctx, ACVP_KDA_Z, 224, 8192, 8, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_ALGID, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_L, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_UPARTYINFO, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_PATTERN, ACVP_KDA_PATTERN_VPARTYINFO, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_ENCODING_TYPE, ACVP_KDA_ENCODING_CONCAT, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_DEFAULT, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_SALT, ACVP_KDA_MAC_SALT_METHOD_RANDOM, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);

    // Most parameters are set in groups based on the KDF108 mode
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA1, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA224, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA256, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA384, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA512, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA512_224, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA512_256, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA3_224, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA3_256, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA3_384, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_MAC_ALG, ACVP_KDF108_MAC_MODE_HMAC_SHA3_512, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_TWOSTEP_FIXED_DATA_ORDER, ACVP_KDF108_FIXED_DATA_ORDER_AFTER, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_TWOSTEP_COUNTER_LEN, 8, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV, 1, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV, 1, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_kda_twostep_set_parm(ctx, ACVP_KDA_TWOSTEP_SUPPORTED_LEN, 2048, ACVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);

end:
   return rv;
}

#if !defined OPENSSL_NO_DSA
static int enable_dsa(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

        // Enable DSA....
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGGEN, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENPQ, ACVP_DSA_PROBABLE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENG, ACVP_DSA_CANONICAL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENG, ACVP_DSA_UNVERIFIABLE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN3072_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN3072_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN3072_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN3072_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGVER, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_GENPQ, ACVP_DSA_PROBABLE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_GENG, ACVP_DSA_CANONICAL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_GENG, ACVP_DSA_UNVERIFIABLE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN1024_160, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN3072_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN3072_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN3072_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_224, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN2048_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGVER, ACVP_DSA_MODE_PQGVER, ACVP_DSA_LN3072_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_KEYGEN, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_KEYGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_KEYGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_224, ACVP_NO_SHA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN2048_256, ACVP_NO_SHA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_KEYGEN, ACVP_DSA_MODE_KEYGEN, ACVP_DSA_LN3072_256, ACVP_NO_SHA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_SIGGEN, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_224, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN2048_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGGEN, ACVP_DSA_MODE_SIGGEN, ACVP_DSA_LN3072_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_SIGVER, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_SIGVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN1024_160, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_224, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN2048_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_SIGVER, ACVP_DSA_MODE_SIGVER, ACVP_DSA_LN3072_256, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
end:

    return rv;
}
#endif

static int enable_rsa(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    BIGNUM *expo = NULL;
    char *expo_str = NULL;

    expo = BN_new();
    if (!expo || !BN_set_word(expo, RSA_F4)) {
        printf("oh no\n");
        return 1;
    }
    expo_str = BN_bn2hex(expo);
    BN_free(expo);

    // Enable RSA keygen...
    rv = acvp_cap_rsa_keygen_enable(ctx, ACVP_RSA_KEYGEN, &app_rsa_keygen_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_KEYGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_rsa_keygen_set_mode(ctx, ACVP_RSA_KEYGEN_B36);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B36, 2048, ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B36, 3072, ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_primes(ctx, ACVP_RSA_KEYGEN_B36, 4096, ACVP_RSA_PRIME_TEST, ACVP_RSA_PRIME_TEST_TBLC2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_RANDOM);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_INFO_GEN_BY_SERVER, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_keygen_set_parm(ctx, ACVP_RSA_PARM_KEY_FORMAT, ACVP_RSA_KEY_FORMAT_STANDARD);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable siggen
    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGGEN, &app_rsa_sig_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1v1.5
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable sigver
    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGVER, &app_rsa_sig_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_parm(ctx, ACVP_RSA_PARM_REVISION, ACVP_REVISION_FIPS186_4);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_rsa_sigver_set_parm(ctx, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_RANDOM);
    CHECK_ENABLE_CAP_RV(rv);

     // RSA w/ sigType: X9.31
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 1024, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 1024, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 1024, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 1024, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 3072, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 4096, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1v1.5
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 1024, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 1024, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 1024, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 1024, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 1024, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 2048, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 3072, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1V15, 4096, ACVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = acvp_cap_rsa_sigver_set_type(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA1, 20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA512, 62);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 1024, ACVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA1, 20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA1, 20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA1, 20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 2048, ACVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 3072, ACVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_sigver_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_PKCS1PSS, 4096, ACVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable Signature Primitive
    rv = acvp_cap_rsa_prim_enable(ctx, ACVP_RSA_SIGPRIM, &app_rsa_sigprim_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGPRIM, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_RSA_SIGPRIM, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_SIGPRIM, ACVP_RSA_PARM_KEY_FORMAT, ACVP_RSA_KEY_FORMAT_CRT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_SIGPRIM, ACVP_RSA_PARM_PUB_EXP_MODE, ACVP_RSA_PUB_EXP_MODE_FIXED);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_rsa_prim_set_parm(ctx, ACVP_RSA_SIGPRIM, ACVP_RSA_PARM_MODULO, 2048);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_rsa_prim_set_exponent(ctx, ACVP_RSA_SIGPRIM, ACVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    CHECK_ENABLE_CAP_RV(rv);

end:
    if (expo_str) free(expo_str);

    return rv;
}

static int enable_ecdsa(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    // Enable ECDSA keyGen...
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYGEN, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_REVISION, ACVP_REVISION_1_0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_SECRET_GEN, ACVP_ECDSA_SECRET_GEN_TEST_CAND);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable ECDSA keyVer...
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYVER, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_REVISION, ACVP_REVISION_1_0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B163);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K163);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable ECDSA sigGen...
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGGEN, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_COMPONENT_TEST, ACVP_ECDSA_COMPONENT_MODE_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_REVISION, ACVP_REVISION_1_0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGGEN, ACVP_ECDSA_HASH_ALG, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);

    // Enable ECDSA sigVer...
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_SIGVER, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_SIGVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_REVISION, ACVP_REVISION_1_0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_B163);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_K163);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_SIGVER, ACVP_ECDSA_HASH_ALG, ACVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

static int enable_drbg(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    // Hash DRBG
    rv = acvp_cap_drbg_enable(ctx, ACVP_HASHDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_set_prereq(ctx, ACVP_HASHDRBG, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_PRED_RESIST_ENABLED, ACVP_DRBG_PRED_RESIST_YES);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_ENTROPY_LEN, 128, 64, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_NONCE_LEN, 96, 32, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_RET_BITS_LEN, 160);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_ENTROPY_LEN, 192, 64, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_RET_BITS_LEN, 384);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_RET_BITS_LEN, 512);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    // HMAC DRBG
    rv = acvp_cap_drbg_enable(ctx, ACVP_HMACDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMACDRBG, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_HMACDRBG,ACVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_PRED_RESIST_ENABLED, ACVP_DRBG_PRED_RESIST_YES);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    // Group number for these should be 0
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_RET_BITS_LEN, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_ENTROPY_LEN, 160, 32, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_1, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_ENTROPY_LEN, 192, 64, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_PERSO_LEN, 0, 64, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_224, 0, ACVP_DRBG_ADD_IN_LEN, 0, 0, 192);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_ENTROPY_LEN, 256, 64, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_256, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_RET_BITS_LEN, 384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_ENTROPY_LEN, 384, 64, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_384, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_RET_BITS_LEN, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_ENTROPY_LEN, 512, 64, 1024);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_ENTROPY_LEN, 512, 64, 1024);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_224, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_ENTROPY_LEN, 512, 64, 1024);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_HMACDRBG, ACVP_DRBG_SHA_512_256, 0, ACVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    // CTR DRBG
    rv = acvp_cap_drbg_enable(ctx, ACVP_CTRDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_CTRDRBG, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);

    // Group number for these should be 0
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_DER_FUNC_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_PRED_RESIST_ENABLED, ACVP_DRBG_PRED_RESIST_YES);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_ENTROPY_LEN, 128, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_PERSO_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0, ACVP_DRBG_ADD_IN_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 1, ACVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 1, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 1, ACVP_DRBG_ENTROPY_LEN, 256, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 1, ACVP_DRBG_NONCE_LEN, 0, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 1, ACVP_DRBG_PERSO_LEN, 256, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 1, ACVP_DRBG_ADD_IN_LEN, 256, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 0, ACVP_DRBG_DER_FUNC_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 0, ACVP_DRBG_ENTROPY_LEN, 256, 128, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 0, ACVP_DRBG_PERSO_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 0, ACVP_DRBG_ADD_IN_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 1, ACVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 1, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 1, ACVP_DRBG_ENTROPY_LEN, 320, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 1, ACVP_DRBG_NONCE_LEN, 0, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 1, ACVP_DRBG_PERSO_LEN, 320, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_192, 1, ACVP_DRBG_ADD_IN_LEN, 320, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_DER_FUNC_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_PRED_RESIST_ENABLED, ACVP_DRBG_PRED_RESIST_YES);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_ENTROPY_LEN, 256, 128, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_PERSO_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 0, ACVP_DRBG_ADD_IN_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 1, ACVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 1, ACVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 1, ACVP_DRBG_ENTROPY_LEN, 384, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 1, ACVP_DRBG_NONCE_LEN, 0, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 1, ACVP_DRBG_PERSO_LEN, 384, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_drbg_set_length(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_256, 1, ACVP_DRBG_ADD_IN_LEN, 384, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
end:
    return rv;
}

#if !defined OPENSSL_NO_DSA
static int enable_safe_primes(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    // Register Safe Prime Key Generation testing
    rv = acvp_cap_safe_primes_enable(ctx, ACVP_SAFE_PRIMES_KEYGEN, &app_safe_primes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYGEN, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE8192);
    CHECK_ENABLE_CAP_RV(rv);

    // Register Safe Prime Key Verify testing
    rv = acvp_cap_safe_primes_enable(ctx, ACVP_SAFE_PRIMES_KEYVER, &app_safe_primes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_safe_primes_set_parm(ctx, ACVP_SAFE_PRIMES_KEYVER, ACVP_SAFE_PRIMES_GENMETH, ACVP_SAFE_PRIMES_FFDHE8192);
    CHECK_ENABLE_CAP_RV(rv);
end:
    return rv;
}
#endif
