/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include "app_common.h"
#include "ut_common.h"
#include <openssl/hmac.h>
#ifdef ACVP_NO_RUNTIME
#include "app_fips_init_lcl.h"
#endif

ACVP_RESULT totp(char **token, int token_max);


/* Here just to avoid warning */

void dummy_call(void)
{
#ifdef ACVP_NO_RUNTIME
    fips_algtest_init_nofips();
#endif
}
const int DIGITS_POWER[]
        //  0  1   2    3     4      5       6        7         8
        = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };
#define T_LEN 8
#define MAX_LEN 512

static int hmac_totp(const char *key, const unsigned char *msg, char *hash,
                     const EVP_MD *md, unsigned int key_len) {
    int len = 0;
    unsigned char buff[MAX_LEN];
    HMAC_CTX *ctx;
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    HMAC_CTX static_ctx;
    
    ctx = &static_ctx;
    HMAC_CTX_init(ctx);
#else
    ctx = HMAC_CTX_new();
#endif
    
    HMAC_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    if (!HMAC_Init_ex(ctx, key, key_len, md, NULL)) goto end;
    if (!HMAC_Update(ctx, msg, T_LEN)) goto end;
    if (!HMAC_Final(ctx, buff, (unsigned int *)&len)) goto end;
    memcpy(hash, buff, len);
    
    end:
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    HMAC_CTX_cleanup(ctx);
#else
    if (ctx) HMAC_CTX_free(ctx);
#endif
    
    return len;
}

ACVP_RESULT totp(char **token, int token_max)
{
    char msg[T_LEN];
    char hash[MAX_LEN];
    int os, bin, otp;
    int md_len;
    char format[5];
    time_t t;
    unsigned char token_buff[T_LEN + 1];
    char *new_seed = malloc(ACVP_TOTP_TOKEN_MAX);
    char *seed = NULL;
    int seed_len = 0;
    
    if (!new_seed) {
        printf("Failed to malloc new_seed\n");
        return ACVP_MALLOC_FAIL;
    }
    
    seed = getenv("ACV_TOTP_SEED");
    if (!seed) {
        printf("Failed to get TOTP seed\n");
        free(new_seed);
        return ACVP_TOTP_MISSING_SEED;
    }
    
    t = time(NULL);
    memset(new_seed, 0, ACVP_TOTP_TOKEN_MAX);
    
    // RFC4226
    memset(msg, 0, T_LEN);
    memset(token_buff, 0, T_LEN);
    t = t/30;
    token_buff[0] = (t>>T_LEN*7) & 0xff;
    token_buff[1] = (t>>T_LEN*6) & 0xff;
    token_buff[2] = (t>>T_LEN*5) & 0xff;
    token_buff[3] = (t>>T_LEN*4) & 0xff;
    token_buff[4] = (t>>T_LEN*3) & 0xff;
    token_buff[5] = (t>>T_LEN*2) & 0xff;
    token_buff[6] = (t>>T_LEN*1) & 0xff;
    token_buff[7] = t & 0xff;
    
    memset(hash, 0, MAX_LEN);
    
    seed_len = base64_decode(seed, strlen(seed), (unsigned char *)new_seed);
    if (seed_len  == 0) {
        printf("Failed to decode TOTP seed\n");
        free(new_seed);
        return ACVP_TOTP_DECODE_FAIL;
    }
    
    
    // use passed hash function
    md_len = hmac_totp(new_seed, token_buff, hash, EVP_sha256(), seed_len);
    if (md_len == 0) {
        printf("Failed to create TOTP\n");
        free(new_seed);
        return ACVP_CRYPTO_MODULE_FAIL;
    }
    os = hash[(int)md_len - 1] & 0xf;
    
    bin = ((hash[os + 0] & 0x7f) << 24) |
          ((hash[os + 1] & 0xff) << 16) |
          ((hash[os + 2] & 0xff) <<  8) |
          ((hash[os + 3] & 0xff) <<  0) ;
    
    otp = bin % DIGITS_POWER[ACVP_TOTP_LENGTH];
    
    // generate format string like "%06d" to fix digits using 0
    sprintf(format, "%c0%ldd", '%', (long int)ACVP_TOTP_LENGTH);
    
    sprintf((char *)token_buff, format, otp);
    memcpy((char *)*token, token_buff, ACVP_TOTP_LENGTH);
    free(new_seed);
    return ACVP_SUCCESS;
}
