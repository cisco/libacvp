/** @file
 *  This is the private header file to be included by CiscoSSL
 *  using libacvp.
 */
/*****************************************************************************
* Copyright (c) 2016, Cisco Systems, Inc.
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
#ifndef app_lcl_h
#define app_lcl_h

#ifdef __cplusplus
extern "C"
{
#endif
#ifdef ACVP_NO_RUNTIME
#include <openssl/fipssyms.h>
#include <openssl/fips_rand.h>
#include <openssl/fips.h>

/* TODO: These need to be put in fips.h */
void FIPS_cipher_ctx_init(EVP_CIPHER_CTX *ctx);
const EVP_CIPHER *FIPS_evp_aes_128_wrap(void);
const EVP_CIPHER *FIPS_evp_aes_192_wrap(void);
const EVP_CIPHER *FIPS_evp_aes_256_wrap(void);
void FIPS_md_ctx_init(EVP_MD_CTX *ctx);
int FIPS_cipher_ctx_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
void FIPS_hmac_ctx_init(HMAC_CTX *ctx);
CMAC_CTX *FIPS_cmac_ctx_new(void);

static int no_err;
static void put_err_cb(int lib, int func,int reason,const char *file,int line)
	{
	if (no_err)
		return;
	fprintf(stderr, "ERROR:%08lX:lib=%d,func=%d,reason=%d"
				":file=%s:line=%d\n",
			ERR_PACK(lib, func, reason),
			lib, func, reason, file, line);
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
	*pout = dummy_entropy;
	return min_len;
	}

static int entropy_stick = 0;

static void fips_algtest_init_nofips(void)
	{
	DRBG_CTX *ctx;
	size_t i;
	FIPS_set_error_callbacks(put_err_cb, add_err_cb);
	for (i = 0; i < sizeof(dummy_entropy); i++)
		dummy_entropy[i] = i & 0xff;
	if (entropy_stick)
		memcpy(dummy_entropy + 32, dummy_entropy + 16, 16);
	ctx = FIPS_get_default_drbg();
	FIPS_drbg_init(ctx, NID_aes_256_ctr, DRBG_FLAG_CTR_USE_DF);
	FIPS_drbg_set_callbacks(ctx, dummy_cb, 0, 16, dummy_cb, 0);
	FIPS_drbg_instantiate(ctx, dummy_entropy, 10);
	FIPS_rand_set_method(FIPS_drbg_method());
	}

#endif

#endif
