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

/*
 * OpenSSL >= 1.1.0 has it's own macro defines for these symbols.
 * Undefine before loading the fipssyms.h file to avoid "redefine" warnings.
 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
# ifdef EVP_CIPHER_CTX_init
#  undef EVP_CIPHER_CTX_init
# endif
# ifdef EVP_CIPHER_CTX_cleanup
#  undef EVP_CIPHER_CTX_cleanup
# endif
# ifdef CRYPTO_THREADID_cmp
#  undef CRYPTO_THREADID_cmp
# endif
# ifdef CRYPTO_THREADID_cpy
#  undef CRYPTO_THREADID_cpy
# endif
# ifdef CRYPTO_THREADID_current
#  undef CRYPTO_THREADID_current
# endif
# ifdef CRYPTO_THREADID_get_callback
#  undef CRYPTO_THREADID_get_callback
# endif
# ifdef CRYPTO_THREADID_hash
#  undef CRYPTO_THREADID_hash
# endif
# ifdef CRYPTO_THREADID_set_callback
#  undef CRYPTO_THREADID_set_callback
# endif
# ifdef CRYPTO_THREADID_set_numeric
#  undef CRYPTO_THREADID_set_numeric
# endif
# ifdef CRYPTO_THREADID_set_pointer
#  undef CRYPTO_THREADID_set_pointer
# endif
# ifdef CRYPTO_get_id_callback
#  undef CRYPTO_get_id_callback
# endif
# ifdef CRYPTO_set_id_callback
#  undef CRYPTO_set_id_callback
# endif
# ifdef CRYPTO_thread_id
#  undef CRYPTO_thread_id
# endif
# ifdef OpenSSLDie
#  undef OpenSSLDie
# endif
# ifdef OPENSSL_clear_free
#  undef OPENSSL_clear_free
# endif
#endif /* OPENSSL_VERSION_NUMBER */

#include <openssl/fipssyms.h>
#include <openssl/fips_rand.h>
#include <openssl/fips.h>

#include "safe_mem_lib.h"

#if defined(dsa_builtin_paramgen2) && OPENSSL_VERSION_NUMBER <= 0x10100000L
# undef dsa_builtin_paramgen2
int dsa_builtin_paramgen2(DSA *ret, size_t L, size_t N,
     const EVP_MD *evpmd, const unsigned char *seed_in, size_t seed_len,
     int idx, unsigned char *seed_out,
     int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
#endif

/*
 * TODO: These need to be put in fips.h
 * These are here so that the app knows about
 * the FOM specific API's being used
 */
EVP_CIPHER_CTX *FIPS_cipher_ctx_new(void);
void FIPS_cipher_ctx_init(EVP_CIPHER_CTX *ctx);
void FIPS_cipher_ctx_free(EVP_CIPHER_CTX *a);
EVP_MD_CTX *FIPS_md_ctx_create(void);
EVP_MD_CTX *FIPS_md_ctx_new(void);
void FIPS_md_ctx_destroy(EVP_MD_CTX *ctx);
const EVP_CIPHER *FIPS_evp_aes_128_wrap(void);
const EVP_CIPHER *FIPS_evp_aes_192_wrap(void);
const EVP_CIPHER *FIPS_evp_aes_256_wrap(void);
void FIPS_md_ctx_init(EVP_MD_CTX *ctx);
int FIPS_cipher_ctx_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
HMAC_CTX *FIPS_hmac_ctx_new(void);
void FIPS_hmac_ctx_init(HMAC_CTX *ctx);
void FIPS_hmac_ctx_set_flags(HMAC_CTX *ctx, unsigned long flags);
CMAC_CTX *FIPS_cmac_ctx_new(void);
void FIPS_cmac_ctx_free(CMAC_CTX *ctx);
BIGNUM *FIPS_bn_new(void);
BN_CTX *fips_bn_ctx_new(void);
void fips_bn_ctx_free(BN_CTX *a);
void FIPS_bn_free(BIGNUM *a);
int fips_BN_hex2bn(BIGNUM **bn, const char *a);
char *fips_BN_bn2hex(const BIGNUM *a);
BIGNUM *FIPS_bn_bin2bn(const unsigned char *s,int len,BIGNUM *ret);
int	FIPS_bn_bn2bin(const BIGNUM *a, unsigned char *to);
int fips_bn_set_word(BIGNUM *a, BN_ULONG w);
int rsa_generate_key_internal(BIGNUM **p, BIGNUM **q, BIGNUM **n, BIGNUM **d,
                              void *seed, unsigned int seed_len,
                              unsigned int bitlen1, unsigned int bitlen2,
                              unsigned int bitlen3, unsigned int bitlen4,
                              BIGNUM *e_value, unsigned int nlen, BN_GENCB *cb);
int RSA_X931_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e, BN_GENCB *cb);
int RSA_size(const RSA *r);
DSA *	FIPS_dsa_new(void);
void	FIPS_dsa_free (DSA *r);
int FIPS_dsa_verify(DSA *dsa, const unsigned char *msg, size_t msglen,
			const EVP_MD *mhash, DSA_SIG *s);
DSA_SIG * FIPS_dsa_sign(DSA *dsa, const unsigned char *msg, size_t msglen,
			const EVP_MD *mhash);
void FIPS_dsa_sig_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
DSA_SIG *FIPS_dsa_sig_new(void);
void FIPS_dsa_sig_free(DSA_SIG *sig);
BIGNUM *fips_bn_ctx_get(BN_CTX *ctx);
void FIPS_bn_clear_free(BIGNUM *a);
int	fips_bn_cmp(const BIGNUM *a, const BIGNUM *b);
BIGNUM *fips_bn_dup(const BIGNUM *a);
int FIPS_bn_num_bits(const BIGNUM *a);
EC_POINT *FIPS_ec_point_new(const EC_GROUP *group);
void FIPS_ec_point_free(EC_POINT *point);
const BIGNUM *FIPS_ec_key_get0_private_key(const EC_KEY *key);
const EC_POINT *FIPS_ec_key_get0_public_key(const EC_KEY *key);
const EC_GROUP *FIPS_ec_key_get0_group(const EC_KEY *key);
const EC_METHOD *FIPS_ec_group_method_of(const EC_GROUP *group);
EC_GROUP *FIPS_ec_group_new_by_curve_name(int nid);
void fips_ec_group_free(EC_GROUP *group);
int FIPS_ec_group_get_degree(const EC_GROUP *group);
int FIPS_ec_method_get_field_type(const EC_METHOD *meth);
int fips_ec_point_set_affine_coordinates_gfp(const EC_GROUP *group, EC_POINT *p,
                                             const BIGNUM *x, const BIGNUM *y,
                                             BN_CTX *ctx);
int FIPS_ec_point_get_affine_coordinates_gfp(const EC_GROUP *group,
                                        const EC_POINT *p, BIGNUM *x,
                                        BIGNUM *y, BN_CTX *ctx);
int fips_ec_point_set_affine_coordinates_gf2m(const EC_GROUP *group, EC_POINT *p,
                                              const BIGNUM *x, const BIGNUM *y,
                                              BN_CTX *ctx);
int FIPS_ec_point_get_affine_coordinates_gf2m(const EC_GROUP *group,
                                         const EC_POINT *p, BIGNUM *x,
                                         BIGNUM *y, BN_CTX *ctx);
EC_KEY *FIPS_ec_key_new(void);
EC_KEY *FIPS_ec_key_new_by_curve_name(int nid);
void FIPS_ec_key_free(EC_KEY *key);
void FIPS_ec_key_set_flags(EC_KEY *key, int flags);
int FIPS_ec_key_set_group(EC_KEY *key, const EC_GROUP *group);
int FIPS_ec_key_set_private_key(EC_KEY *key, const BIGNUM *prv);
int FIPS_ec_key_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x,
                                                  BIGNUM *y);
ECDSA_SIG *FIPS_ecdsa_sig_new(void);
void FIPS_ecdsa_sig_free(ECDSA_SIG *sig);
ECDSA_SIG * FIPS_ecdsa_sign(EC_KEY *key,
                            const unsigned char *msg, size_t msglen,
                            const EVP_MD *mhash);
int FIPS_ecdsa_verify(EC_KEY *key, const unsigned char *msg, size_t msglen,
			          const EVP_MD *mhash, ECDSA_SIG *s);
int FIPS_ecdh_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
                          EC_KEY *ecdh, void *(*KDF) (const void *in, size_t inlen,
                                                      void *out, size_t *outlen));
DH *FIPS_dh_new(void );
void FIPS_dh_free(DH *dh);
int FIPS_dh_generate_key(DH *dh);
int FIPS_dh_compute_key_padded(unsigned char *key,const BIGNUM *pub_key,DH *dh);
void *FIPS_malloc(int num, const char *file, int line);
void FIPS_free(void *ptr);
int FIPS_digest(const void *data, size_t count,
                unsigned char *md, unsigned int *size, const EVP_MD *type);
void FIPS_openssl_cleanse(void *ptr, size_t len);
int FIPS_rsa_verify(struct rsa_st *rsa, const unsigned char *msg, int msglen,
			const struct env_md_st *mhash, int rsa_pad_mode,
			int saltlen, const struct env_md_st *mgf1Hash,
			const unsigned char *sigbuf, unsigned int siglen);

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
		memcpy_s(dummy_entropy + 32, (sizeof(dummy_entropy) - 32), dummy_entropy + 16, 16);
	ctx = FIPS_get_default_drbg();
	FIPS_drbg_init(ctx, NID_aes_256_ctr, DRBG_FLAG_CTR_USE_DF);
	FIPS_drbg_set_callbacks(ctx, dummy_cb, 0, 16, dummy_cb, 0);
	FIPS_drbg_instantiate(ctx, dummy_entropy, 10);
	FIPS_rand_set_method(FIPS_drbg_method());
	}

#endif

#endif
