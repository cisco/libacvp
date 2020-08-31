/*****************************************************************************
* Copyright (c) 2019, Cisco Systems, Inc.
* All rights reserved.

* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

#ifndef LIBACVP_APP_FIPS_INIT_LCL_H
#define LIBACVP_APP_FIPS_INIT_LCL_H

#ifdef ACVP_NO_RUNTIME

#ifdef __cplusplus
extern "C"
{
#endif

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/fips_rand.h>
#include "safe_mem_lib.h"

/*
 * These stubs are needed when linking with FOM7.0,
 * otherwise we get "undefined reference".
 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#ifndef ACVP_OFFLINE
void FINGERPRINT_premain(void);
void FINGERPRINT_premain(void) {}
#endif

int FIPS_get_selftest_completed(int version)
{
    return version;
}
#endif

static int no_err;
static void put_err_cb(int lib, int func,int reason,const char *file,int line)
    {
    if (no_err)
        return;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    fprintf(stderr, "ERROR:%08lX:lib=%d,func=%d,reason=%d"
                ":file=%s:line=%d\n",
            ERR_PACK(lib, func, reason),
            lib, func, reason, file, line);
#else
    fprintf(stderr, "ERROR:%08X:lib=%d,func=%d,reason=%d"
                ":file=%s:line=%d\n",
            ERR_PACK(lib, func, reason),
            lib, func, reason, file, line);
#endif
    }

static void add_err_cb(int num, va_list args)
    {
    int i;
    char *str;
    if (no_err)
        return;
    fputs("\t", stderr);
    for (i = 0; i < num; i++)
        {
        str = va_arg(args, char *);
        if (str)
            fputs(str, stderr);
        }
    fputs("\n", stderr);
    }

static unsigned char dummy_entropy[1024];

static size_t dummy_cb(DRBG_CTX *ctx, unsigned char **pout,
                                int entropy, size_t min_len, size_t max_len)
    {
        if (!ctx || !entropy || !max_len) {
            return min_len;
        }
    *pout = dummy_entropy;
    return min_len;
    }

static int entropy_stick = 0;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
void FIPS_set_locking_callbacks(CRYPTO_RWLOCK *(*FIPS_thread_lock_new)(void),
                   int (*FIPS_thread_read_lock)(CRYPTO_RWLOCK *lock),
                   int (*FIPS_thread_write_lock)(CRYPTO_RWLOCK *lock),
                   int (*FIPS_thread_unlock)(CRYPTO_RWLOCK *lock),
                   void (*FIPS_thread_lock_free)(CRYPTO_RWLOCK *lock),
                   CRYPTO_THREAD_ID (*FIPS_thread_get_current_id)(void),
                   int (*FIPS_thread_compare_id)(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b),
                   int (*FIPS_atomic_add)(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock));

/* Dummy lock CBs*/
static int dummy_alg_testing_lock = 5;
static CRYPTO_RWLOCK* fips_test_suite_dummy_new_lock(void) {
    return (CRYPTO_RWLOCK*) &dummy_alg_testing_lock;
}
static void fips_test_suite_dummy_free_lock(CRYPTO_RWLOCK* lock){
    // do nothing
    (void)lock;
}
#endif
#ifdef ACVP_NO_RUNTIME
static void fips_algtest_init_nofips(void)
    {
    DRBG_CTX *ctx;
    size_t i;
#if FIPS_MODULE_VERSION_NUMBER >= 0x70000002L
    FIPS_set_error_callbacks(put_err_cb, add_err_cb, NULL, NULL, NULL, NULL);
#else
    FIPS_set_error_callbacks(put_err_cb, add_err_cb);
#endif
    for (i = 0; i < sizeof(dummy_entropy); i++)
        dummy_entropy[i] = i & 0xff;
    if (entropy_stick)
        memcpy_s(dummy_entropy + 32, (sizeof(dummy_entropy) - 32), dummy_entropy + 16, 16);
    ctx = FIPS_get_default_drbg();
    FIPS_drbg_init(ctx, NID_aes_256_ctr, DRBG_FLAG_CTR_USE_DF);
    FIPS_drbg_set_callbacks(ctx, dummy_cb, 0, 16, dummy_cb, 0);
    FIPS_drbg_instantiate(ctx, dummy_entropy, 10);
    FIPS_rand_set_method(FIPS_drbg_method());
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    FIPS_set_locking_callbacks(&fips_test_suite_dummy_new_lock,
                               NULL,
                               NULL,
                               NULL,
                               &fips_test_suite_dummy_free_lock,
                               NULL,
                               NULL,
                               NULL);
#endif

    }
#endif
#ifdef __cplusplus
}
#endif

#endif // ACVP_NO_RUNTIME

#endif // LIBACVP_APP_FIPS_INIT_LCL_H

