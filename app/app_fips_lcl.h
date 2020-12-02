/** @file
 *  This is the private header file to be included by CiscoSSL
 *  using libacvp.
 */
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

#ifndef LIBACVP_APP_FIPS_LCL_H
#define LIBACVP_APP_FIPS_LCL_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef ACVP_NO_RUNTIME

/* Need these headers for the subsequent symbols usage */
#include <openssl/ossl_typ.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/cmac.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>

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

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
#define fips_dsa_builtin_paramgen2 fips_h_bad_dsa_builtin_paramgen2 
#include <openssl/fips.h>
#undef fips_dsa_builtin_paramgen2
int fips_dsa_builtin_paramgen2(DSA *ret, size_t L, size_t N,
     const EVP_MD *evpmd, const unsigned char *seed_in, size_t seed_len,
     int idx, unsigned char *seed_out,
     int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
#else
#include <openssl/fips.h>
#endif

#include <openssl/fipssyms.h>
#include <openssl/fips_rand.h>

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
#define fips_dsa_builtin_paramgen2 fips_h_bad_dsa_builtin_paramgen2 
#include <openssl/fips.h>
#undef fips_dsa_builtin_paramgen2
#ifndef OPENSSL_NO_DSA
int fips_dsa_builtin_paramgen2(DSA *ret, size_t L, size_t N,
     const EVP_MD *evpmd, const unsigned char *seed_in, size_t seed_len,
     int idx, unsigned char *seed_out,
     int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
#endif
#else
#include <openssl/fips.h>
#endif


/*
 * TODO: These need to be put in fips.h
 * These are here so that the app knows about
 * the FOM specific API's being used
 */
#define M_EVP_CIPHER_CTX_set_flags(ctx,flgs) ((ctx)->flags|=(flgs))

#define EVP_CIPHER_CTX_set_padding(ctx, pad) {}

int fips_evp_MD_size(const EVP_MD *md);
const unsigned char *fips_EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);
void fips_evp_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);
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
int fips_bn_sub_word(BIGNUM *b, int i);
BIGNUM *FIPS_bn_bin2bn(const unsigned char *s,int len,BIGNUM *ret);
int FIPS_bn_bn2bin(const BIGNUM *a, unsigned char *to);
int fips_bn_set_word(BIGNUM *a, BN_ULONG w);
int rsa_generate_key_internal(BIGNUM **p, BIGNUM **q, BIGNUM **n, BIGNUM **d,
                              void *seed, unsigned int seed_len,
                              unsigned int bitlen1, unsigned int bitlen2,
                              unsigned int bitlen3, unsigned int bitlen4,
                              BIGNUM *e_value, unsigned int nlen, BN_GENCB *cb);
int RSA_X931_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e, BN_GENCB *cb);
int RSA_size(const RSA *r);
int fips_RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
void fips_RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);

#ifndef OPENSSL_NO_DSA
DSA * FIPS_dsa_new(void);
void FIPS_dsa_free(DSA *r);
int FIPS_dsa_verify(DSA *dsa, const unsigned char *msg, size_t msglen,
            const EVP_MD *mhash, DSA_SIG *s);
DSA_SIG * FIPS_dsa_sign(DSA *dsa, const unsigned char *msg, size_t msglen,
            const EVP_MD *mhash);
void fips_DSA_get0_key(const DSA *d,
                       const BIGNUM **pub_key, const BIGNUM **priv_key);
void FIPS_dsa_sig_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int FIPS_dsa_sig_set0(DSA_SIG *sig, BIGNUM *pr, BIGNUM *ps);
DSA_SIG *FIPS_dsa_sig_new(void);
void FIPS_dsa_sig_free(DSA_SIG *sig);
#endif

void fips_rsa_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
int FIPS_rsa_private_decrypt(int flen, const unsigned char *from, 
		             unsigned char *to, RSA *rsa,int padding);
int FIPS_rsa_private_encrypt(int flen, const unsigned char *from,
		             unsigned char *to, RSA *rsa,int padding);
int FIPS_rsa_public_encrypt(int flen, const unsigned char *from,
		             unsigned char *to, RSA *rsa,int padding);
BIGNUM *fips_bn_ctx_get(BN_CTX *ctx);
void FIPS_bn_clear_free(BIGNUM *a);
int fips_bn_cmp(const BIGNUM *a, const BIGNUM *b);
BIGNUM *fips_bn_dup(const BIGNUM *a);
int FIPS_bn_num_bits(const BIGNUM *a);
EC_POINT *FIPS_ec_point_new(const EC_GROUP *group);
int fips_EC_POINT_set_affine_coordinates(const EC_GROUP *group, EC_POINT *p,
                                        const BIGNUM *x, const BIGNUM *y,
                                        BN_CTX *ctx);
void FIPS_ec_point_free(EC_POINT *point);
const BIGNUM *FIPS_ec_key_get0_private_key(const EC_KEY *key);
const EC_POINT *FIPS_ec_key_get0_public_key(const EC_KEY *key);
const EC_GROUP *FIPS_ec_key_get0_group(const EC_KEY *key);
const EC_METHOD *FIPS_ec_group_method_of(const EC_GROUP *group);
int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);
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
int FIPS_ec_key_set_private_key(EC_KEY *key, const BIGNUM *prv);
int FIPS_ec_key_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x,
                                                  BIGNUM *y);
const EVP_MD *fips_evp_sha512_224(void);
const EVP_MD *fips_evp_sha512_256(void);
const EVP_MD *FIPS_evp_sha3_224(void);
const EVP_MD *FIPS_evp_sha3_256(void);
const EVP_MD *FIPS_evp_sha3_384(void);
const EVP_MD *FIPS_evp_sha3_512(void);
const EVP_MD *FIPS_evp_shake128(void);
const EVP_MD *FIPS_evp_shake256(void);

ECDSA_SIG *FIPS_ecdsa_sig_new(void);
void FIPS_ecdsa_sig_free(ECDSA_SIG *sig);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
ECDSA_SIG * FIPS_ecdsa_sign(EC_KEY *key,
                            const unsigned char *msg, size_t msglen,
                            const EVP_MD *mhash);
int FIPS_ecdsa_verify(EC_KEY *key, const unsigned char *msg, size_t msglen,
                      const EVP_MD *mhash, ECDSA_SIG *s);
#endif
ECDSA_SIG * FIPS_ecdsa_sign_md(EC_KEY *key,
                               const unsigned char *msg, size_t msglen,
                               const EVP_MD *mhash);
int FIPS_ecdsa_verify_md(EC_KEY *key, const unsigned char *msg, size_t msglen,
             const EVP_MD *mhash, ECDSA_SIG *s);
int FIPS_ecdh_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
                          const EC_KEY *ecdh, void *(*KDF) (const void *in, size_t inlen,
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
#endif // ACVP_NO_RUNTIME

#ifdef __cplusplus
}
#endif

#endif // LIBACVP_APP_FIPS_LCL_H

