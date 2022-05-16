/** @file */
/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef _WIN32
#include <io.h>
#include <Windows.h>
#else
#include <unistd.h>
#endif
#include <math.h>
#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"
#include "safe_lib.h"

/*
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_login(ACVP_CTX *ctx, int refresh);

static ACVP_RESULT acvp_validate_test_session(ACVP_CTX *ctx);

static ACVP_RESULT acvp_append_vsid_url(ACVP_CTX *ctx, const char *vsid_url);

static ACVP_RESULT acvp_parse_login(ACVP_CTX *ctx);

static ACVP_RESULT acvp_parse_test_session_register(ACVP_CTX *ctx);

static ACVP_RESULT acvp_parse_session_info_file(ACVP_CTX *ctx, const char *filename);

static ACVP_RESULT acvp_process_vsid(ACVP_CTX *ctx, char *vsid_url, int count);

static ACVP_RESULT acvp_process_vector_set(ACVP_CTX *ctx, JSON_Object *obj);

static ACVP_RESULT acvp_dispatch_vector_set(ACVP_CTX *ctx, JSON_Object *obj);

static void acvp_cap_free_sl(ACVP_SL_LIST *list);

static void acvp_cap_free_nl(ACVP_NAME_LIST *list);

static void acvp_cap_free_pl(ACVP_PARAM_LIST *list);

static void acvp_cap_free_hash_pairs(ACVP_RSA_HASH_PAIR_LIST *list);

static ACVP_RESULT acvp_get_result_test_session(ACVP_CTX *ctx, char *session_url);

static ACVP_RESULT acvp_put_data_from_ctx(ACVP_CTX *ctx);

/*
 * This table maps ACVP operations to handlers within libacvp.
 * Each ACVP operation may have unique parameters.  For instance,
 * the parameters to test RSA are different than AES.  Therefore,
 * we allow for a unique handler to be registered for each
 * ACVP operation.
 *
 * WARNING:
 * This table is not sparse, it must contain ACVP_OP_MAX entries.
 */
ACVP_ALG_HANDLER alg_tbl[ACVP_ALG_MAX] = {
    { ACVP_AES_GCM,           &acvp_aes_kat_handler,             ACVP_ALG_AES_GCM,           NULL, ACVP_REV_AES_GCM, {ACVP_SUB_AES_GCM}},
    { ACVP_AES_GCM_SIV,       &acvp_aes_kat_handler,             ACVP_ALG_AES_GCM_SIV,       NULL, ACVP_REV_AES_GCM_SIV, {ACVP_SUB_AES_GCM_SIV}},
    { ACVP_AES_CCM,           &acvp_aes_kat_handler,             ACVP_ALG_AES_CCM,           NULL, ACVP_REV_AES_CCM, {ACVP_SUB_AES_CCM}},
    { ACVP_AES_ECB,           &acvp_aes_kat_handler,             ACVP_ALG_AES_ECB,           NULL, ACVP_REV_AES_ECB, {ACVP_SUB_AES_ECB}},
    { ACVP_AES_CBC,           &acvp_aes_kat_handler,             ACVP_ALG_AES_CBC,           NULL, ACVP_REV_AES_CBC, {ACVP_SUB_AES_CBC}},
    { ACVP_AES_CBC_CS1,       &acvp_aes_kat_handler,             ACVP_ALG_AES_CBC_CS1,       NULL, ACVP_REV_AES_CBC_CS1, {ACVP_SUB_AES_CBC_CS1}},
    { ACVP_AES_CBC_CS2,       &acvp_aes_kat_handler,             ACVP_ALG_AES_CBC_CS2,       NULL, ACVP_REV_AES_CBC_CS2, {ACVP_SUB_AES_CBC_CS2}},
    { ACVP_AES_CBC_CS3,       &acvp_aes_kat_handler,             ACVP_ALG_AES_CBC_CS3,       NULL, ACVP_REV_AES_CBC_CS3, {ACVP_SUB_AES_CBC_CS3}},
    { ACVP_AES_CFB1,          &acvp_aes_kat_handler,             ACVP_ALG_AES_CFB1,          NULL, ACVP_REV_AES_CFB1, {ACVP_SUB_AES_CFB1}},
    { ACVP_AES_CFB8,          &acvp_aes_kat_handler,             ACVP_ALG_AES_CFB8,          NULL, ACVP_REV_AES_CFB8, {ACVP_SUB_AES_CFB8}},
    { ACVP_AES_CFB128,        &acvp_aes_kat_handler,             ACVP_ALG_AES_CFB128,        NULL, ACVP_REV_AES_CFB128, {ACVP_SUB_AES_CFB128}},
    { ACVP_AES_OFB,           &acvp_aes_kat_handler,             ACVP_ALG_AES_OFB,           NULL, ACVP_REV_AES_OFB, {ACVP_SUB_AES_OFB}},
    { ACVP_AES_CTR,           &acvp_aes_kat_handler,             ACVP_ALG_AES_CTR,           NULL, ACVP_REV_AES_CTR, {ACVP_SUB_AES_CTR}},
    { ACVP_AES_XTS,           &acvp_aes_kat_handler,             ACVP_ALG_AES_XTS,           NULL, ACVP_REV_AES_XTS, {ACVP_SUB_AES_XTS}},
    { ACVP_AES_KW,            &acvp_aes_kat_handler,             ACVP_ALG_AES_KW,            NULL, ACVP_REV_AES_KW, {ACVP_SUB_AES_KW}},
    { ACVP_AES_KWP,           &acvp_aes_kat_handler,             ACVP_ALG_AES_KWP,           NULL, ACVP_REV_AES_KWP, {ACVP_SUB_AES_KWP}},
    { ACVP_AES_GMAC,          &acvp_aes_kat_handler,             ACVP_ALG_AES_GMAC,          NULL, ACVP_REV_AES_GMAC, {ACVP_SUB_AES_GMAC}},
    { ACVP_AES_XPN,           &acvp_aes_kat_handler,             ACVP_ALG_AES_XPN ,          NULL, ACVP_REV_AES_XPN, {ACVP_SUB_AES_XPN}},
    { ACVP_TDES_ECB,          &acvp_des_kat_handler,             ACVP_ALG_TDES_ECB,          NULL, ACVP_REV_TDES_ECB, {ACVP_SUB_TDES_ECB}},
    { ACVP_TDES_CBC,          &acvp_des_kat_handler,             ACVP_ALG_TDES_CBC,          NULL, ACVP_REV_TDES_CBC, {ACVP_SUB_TDES_CBC}},
    { ACVP_TDES_CBCI,         &acvp_des_kat_handler,             ACVP_ALG_TDES_CBCI,         NULL, ACVP_REV_TDES_CBCI, {ACVP_SUB_TDES_CBCI}},
    { ACVP_TDES_OFB,          &acvp_des_kat_handler,             ACVP_ALG_TDES_OFB,          NULL, ACVP_REV_TDES_OFB, {ACVP_SUB_TDES_OFB}},
    { ACVP_TDES_OFBI,         &acvp_des_kat_handler,             ACVP_ALG_TDES_OFBI,         NULL, ACVP_REV_TDES_OFBI, {ACVP_SUB_TDES_OFBI}},
    { ACVP_TDES_CFB1,         &acvp_des_kat_handler,             ACVP_ALG_TDES_CFB1,         NULL, ACVP_REV_TDES_CFB1, {ACVP_SUB_TDES_CFB1}},
    { ACVP_TDES_CFB8,         &acvp_des_kat_handler,             ACVP_ALG_TDES_CFB8,         NULL, ACVP_REV_TDES_CFB8, {ACVP_SUB_TDES_CFB8}},
    { ACVP_TDES_CFB64,        &acvp_des_kat_handler,             ACVP_ALG_TDES_CFB64,        NULL, ACVP_REV_TDES_CFB64, {ACVP_SUB_TDES_CFB64}},
    { ACVP_TDES_CFBP1,        &acvp_des_kat_handler,             ACVP_ALG_TDES_CFBP1,        NULL, ACVP_REV_TDES_CFBP1, {ACVP_SUB_TDES_CFBP1}},
    { ACVP_TDES_CFBP8,        &acvp_des_kat_handler,             ACVP_ALG_TDES_CFBP8,        NULL, ACVP_REV_TDES_CFBP8, {ACVP_SUB_TDES_CFBP8}},
    { ACVP_TDES_CFBP64,       &acvp_des_kat_handler,             ACVP_ALG_TDES_CFBP64,       NULL, ACVP_REV_TDES_CFBP64, {ACVP_SUB_TDES_CFBP64}},
    { ACVP_TDES_CTR,          &acvp_des_kat_handler,             ACVP_ALG_TDES_CTR,          NULL, ACVP_REV_TDES_CTR, {ACVP_SUB_TDES_CTR}},
    { ACVP_TDES_KW,           &acvp_des_kat_handler,             ACVP_ALG_TDES_KW,           NULL, ACVP_REV_TDES_KW, {ACVP_SUB_TDES_KW}},
    { ACVP_HASH_SHA1,         &acvp_hash_kat_handler,            ACVP_ALG_SHA1,              NULL, ACVP_REV_HASH_SHA1, {ACVP_SUB_HASH_SHA1}},
    { ACVP_HASH_SHA224,       &acvp_hash_kat_handler,            ACVP_ALG_SHA224,            NULL, ACVP_REV_HASH_SHA224, {ACVP_SUB_HASH_SHA2_224}},
    { ACVP_HASH_SHA256,       &acvp_hash_kat_handler,            ACVP_ALG_SHA256,            NULL, ACVP_REV_HASH_SHA256, {ACVP_SUB_HASH_SHA2_256}},
    { ACVP_HASH_SHA384,       &acvp_hash_kat_handler,            ACVP_ALG_SHA384,            NULL, ACVP_REV_HASH_SHA384, {ACVP_SUB_HASH_SHA2_384}},
    { ACVP_HASH_SHA512,       &acvp_hash_kat_handler,            ACVP_ALG_SHA512,            NULL, ACVP_REV_HASH_SHA512, {ACVP_SUB_HASH_SHA2_512}},
    { ACVP_HASH_SHA512_224,   &acvp_hash_kat_handler,            ACVP_ALG_SHA512_224,        NULL, ACVP_REV_HASH_SHA512_224, {ACVP_SUB_HASH_SHA2_512_224}},
    { ACVP_HASH_SHA512_256,   &acvp_hash_kat_handler,            ACVP_ALG_SHA512_256,        NULL, ACVP_REV_HASH_SHA512_256, {ACVP_SUB_HASH_SHA2_512_256}},
    { ACVP_HASH_SHA3_224,     &acvp_hash_kat_handler,            ACVP_ALG_SHA3_224,          NULL, ACVP_REV_HASH_SHA3_224, {ACVP_SUB_HASH_SHA3_224}},
    { ACVP_HASH_SHA3_256,     &acvp_hash_kat_handler,            ACVP_ALG_SHA3_256,          NULL, ACVP_REV_HASH_SHA3_256, {ACVP_SUB_HASH_SHA3_256}},
    { ACVP_HASH_SHA3_384,     &acvp_hash_kat_handler,            ACVP_ALG_SHA3_384,          NULL, ACVP_REV_HASH_SHA3_384, {ACVP_SUB_HASH_SHA3_384}},
    { ACVP_HASH_SHA3_512,     &acvp_hash_kat_handler,            ACVP_ALG_SHA3_512,          NULL, ACVP_REV_HASH_SHA3_512, {ACVP_SUB_HASH_SHA3_512}},
    { ACVP_HASH_SHAKE_128,    &acvp_hash_kat_handler,            ACVP_ALG_SHAKE_128,         NULL, ACVP_REV_HASH_SHAKE_128, {ACVP_SUB_HASH_SHAKE_128}},
    { ACVP_HASH_SHAKE_256,    &acvp_hash_kat_handler,            ACVP_ALG_SHAKE_256,         NULL, ACVP_REV_HASH_SHAKE_256, {ACVP_SUB_HASH_SHAKE_256}},
    { ACVP_HASHDRBG,          &acvp_drbg_kat_handler,            ACVP_ALG_HASHDRBG,          NULL, ACVP_REV_HASHDRBG, {ACVP_SUB_DRBG_HASH}},
    { ACVP_HMACDRBG,          &acvp_drbg_kat_handler,            ACVP_ALG_HMACDRBG,          NULL, ACVP_REV_HMACDRBG, {ACVP_SUB_DRBG_HMAC}},
    { ACVP_CTRDRBG,           &acvp_drbg_kat_handler,            ACVP_ALG_CTRDRBG,           NULL, ACVP_REV_CTRDRBG, {ACVP_SUB_DRBG_CTR}},
    { ACVP_HMAC_SHA1,         &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA1,         NULL, ACVP_REV_HMAC_SHA1, {ACVP_SUB_HMAC_SHA1}},
    { ACVP_HMAC_SHA2_224,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA2_224,     NULL, ACVP_REV_HMAC_SHA2_224, {ACVP_SUB_HMAC_SHA2_224}},
    { ACVP_HMAC_SHA2_256,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA2_256,     NULL, ACVP_REV_HMAC_SHA2_256, {ACVP_SUB_HMAC_SHA2_256}},
    { ACVP_HMAC_SHA2_384,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA2_384,     NULL, ACVP_REV_HMAC_SHA2_384, {ACVP_SUB_HMAC_SHA2_384}},
    { ACVP_HMAC_SHA2_512,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA2_512,     NULL, ACVP_REV_HMAC_SHA2_512, {ACVP_SUB_HMAC_SHA2_512}},
    { ACVP_HMAC_SHA2_512_224, &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA2_512_224, NULL, ACVP_REV_HMAC_SHA2_512_224, {ACVP_SUB_HMAC_SHA2_512_224}},
    { ACVP_HMAC_SHA2_512_256, &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA2_512_256, NULL, ACVP_REV_HMAC_SHA2_512_256, {ACVP_SUB_HMAC_SHA2_512_256}},
    { ACVP_HMAC_SHA3_224,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA3_224,     NULL, ACVP_REV_HMAC_SHA3_224, {ACVP_SUB_HMAC_SHA3_224}},
    { ACVP_HMAC_SHA3_256,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA3_256,     NULL, ACVP_REV_HMAC_SHA3_256, {ACVP_SUB_HMAC_SHA3_256}},
    { ACVP_HMAC_SHA3_384,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA3_384,     NULL, ACVP_REV_HMAC_SHA3_384, {ACVP_SUB_HMAC_SHA3_384}},
    { ACVP_HMAC_SHA3_512,     &acvp_hmac_kat_handler,            ACVP_ALG_HMAC_SHA3_512,     NULL, ACVP_REV_HMAC_SHA3_512, {ACVP_SUB_HMAC_SHA3_512}},
    { ACVP_CMAC_AES,          &acvp_cmac_kat_handler,            ACVP_ALG_CMAC_AES,          NULL, ACVP_REV_CMAC_AES, {ACVP_SUB_CMAC_AES}},
    { ACVP_CMAC_TDES,         &acvp_cmac_kat_handler,            ACVP_ALG_CMAC_TDES,         NULL, ACVP_REV_CMAC_TDES, {ACVP_SUB_CMAC_TDES}},
    { ACVP_DSA_KEYGEN,        &acvp_dsa_kat_handler,             ACVP_ALG_DSA,               ACVP_ALG_DSA_KEYGEN, ACVP_REV_DSA, {ACVP_SUB_DSA_KEYGEN}},
    { ACVP_DSA_PQGGEN,        &acvp_dsa_kat_handler,             ACVP_ALG_DSA,               ACVP_ALG_DSA_PQGGEN, ACVP_REV_DSA, {ACVP_SUB_DSA_PQGGEN}},
    { ACVP_DSA_PQGVER,        &acvp_dsa_kat_handler,             ACVP_ALG_DSA,               ACVP_ALG_DSA_PQGVER, ACVP_REV_DSA, {ACVP_SUB_DSA_PQGVER}},
    { ACVP_DSA_SIGGEN,        &acvp_dsa_kat_handler,             ACVP_ALG_DSA,               ACVP_ALG_DSA_SIGGEN, ACVP_REV_DSA, {ACVP_SUB_DSA_SIGGEN}},
    { ACVP_DSA_SIGVER,        &acvp_dsa_kat_handler,             ACVP_ALG_DSA,               ACVP_ALG_DSA_SIGVER, ACVP_REV_DSA, {ACVP_SUB_DSA_SIGVER}},
    { ACVP_RSA_KEYGEN,        &acvp_rsa_keygen_kat_handler,      ACVP_ALG_RSA,               ACVP_MODE_KEYGEN, ACVP_REV_RSA, {ACVP_SUB_RSA_KEYGEN}},
    { ACVP_RSA_SIGGEN,        &acvp_rsa_siggen_kat_handler,      ACVP_ALG_RSA,               ACVP_MODE_SIGGEN, ACVP_REV_RSA, {ACVP_SUB_RSA_SIGGEN}},
    { ACVP_RSA_SIGVER,        &acvp_rsa_sigver_kat_handler,      ACVP_ALG_RSA,               ACVP_MODE_SIGVER, ACVP_REV_RSA, {ACVP_SUB_RSA_SIGVER}},
    { ACVP_RSA_DECPRIM,       &acvp_rsa_decprim_kat_handler,     ACVP_ALG_RSA,               ACVP_MODE_DECPRIM, ACVP_REV_RSA_PRIM, {ACVP_SUB_RSA_DECPRIM}},
    { ACVP_RSA_SIGPRIM,       &acvp_rsa_sigprim_kat_handler,     ACVP_ALG_RSA,               ACVP_MODE_SIGPRIM, ACVP_REV_RSA_PRIM, {ACVP_SUB_RSA_SIGPRIM}},
    { ACVP_ECDSA_KEYGEN,      &acvp_ecdsa_keygen_kat_handler,    ACVP_ALG_ECDSA,             ACVP_MODE_KEYGEN, ACVP_REV_ECDSA, {ACVP_SUB_ECDSA_KEYGEN}},
    { ACVP_ECDSA_KEYVER,      &acvp_ecdsa_keyver_kat_handler,    ACVP_ALG_ECDSA,             ACVP_MODE_KEYVER, ACVP_REV_ECDSA, {ACVP_SUB_ECDSA_KEYVER}},
    { ACVP_ECDSA_SIGGEN,      &acvp_ecdsa_siggen_kat_handler,    ACVP_ALG_ECDSA,             ACVP_MODE_SIGGEN, ACVP_REV_ECDSA, {ACVP_SUB_ECDSA_SIGGEN}},
    { ACVP_ECDSA_SIGVER,      &acvp_ecdsa_sigver_kat_handler,    ACVP_ALG_ECDSA,             ACVP_MODE_SIGVER, ACVP_REV_ECDSA, {ACVP_SUB_ECDSA_SIGVER}},
    { ACVP_KDF135_SNMP,       &acvp_kdf135_snmp_kat_handler,     ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_SNMP, ACVP_REV_KDF135_SNMP, {ACVP_SUB_KDF_SNMP}},
    { ACVP_KDF135_SSH,        &acvp_kdf135_ssh_kat_handler,      ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_SSH, ACVP_REV_KDF135_SSH, {ACVP_SUB_KDF_SSH}},
    { ACVP_KDF135_SRTP,       &acvp_kdf135_srtp_kat_handler,     ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_SRTP, ACVP_REV_KDF135_SRTP, {ACVP_SUB_KDF_SRTP}},
    { ACVP_KDF135_IKEV2,      &acvp_kdf135_ikev2_kat_handler,    ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_IKEV2, ACVP_REV_KDF135_IKEV2, {ACVP_SUB_KDF_IKEV2}},
    { ACVP_KDF135_IKEV1,      &acvp_kdf135_ikev1_kat_handler,    ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_IKEV1, ACVP_REV_KDF135_IKEV1, {ACVP_SUB_KDF_IKEV1}},
    { ACVP_KDF135_X963,       &acvp_kdf135_x963_kat_handler,     ACVP_KDF135_ALG_STR,        ACVP_ALG_KDF135_X963, ACVP_REV_KDF135_X963, {ACVP_SUB_KDF_X963}},
    { ACVP_KDF108,            &acvp_kdf108_kat_handler,          ACVP_ALG_KDF108,            NULL, ACVP_REV_KDF108, {ACVP_SUB_KDF_108}},
    { ACVP_PBKDF,             &acvp_pbkdf_kat_handler,           ACVP_ALG_PBKDF,             NULL, ACVP_REV_PBKDF, {ACVP_SUB_KDF_PBKDF}},
    { ACVP_KDF_TLS12,         &acvp_kdf_tls12_kat_handler,       ACVP_ALG_TLS12,             ACVP_ALG_KDF_TLS12, ACVP_REV_KDF_TLS12, {ACVP_SUB_KDF_TLS12}},
    { ACVP_KDF_TLS13,         &acvp_kdf_tls13_kat_handler,       ACVP_ALG_TLS13,             ACVP_ALG_KDF_TLS13, ACVP_REV_KDF_TLS13, {ACVP_SUB_KDF_TLS13}},
    { ACVP_KAS_ECC_CDH,       &acvp_kas_ecc_kat_handler,         ACVP_ALG_KAS_ECC,           ACVP_ALG_KAS_ECC_CDH, ACVP_REV_KAS_ECC, {ACVP_SUB_KAS_ECC_CDH}},
    { ACVP_KAS_ECC_COMP,      &acvp_kas_ecc_kat_handler,         ACVP_ALG_KAS_ECC,           ACVP_ALG_KAS_ECC_COMP, ACVP_REV_KAS_ECC, {ACVP_SUB_KAS_ECC_COMP}},
    { ACVP_KAS_ECC_NOCOMP,    &acvp_kas_ecc_kat_handler,         ACVP_ALG_KAS_ECC,           ACVP_ALG_KAS_ECC_NOCOMP, ACVP_REV_KAS_ECC, {ACVP_SUB_KAS_ECC_NOCOMP}},
    { ACVP_KAS_ECC_SSC,       &acvp_kas_ecc_ssc_kat_handler,     ACVP_ALG_KAS_ECC_SSC,       ACVP_ALG_KAS_ECC_COMP, ACVP_REV_KAS_ECC_SSC, {ACVP_SUB_KAS_ECC_SSC}},
    { ACVP_KAS_FFC_COMP,      &acvp_kas_ffc_kat_handler,         ACVP_ALG_KAS_FFC,           ACVP_ALG_KAS_FFC_COMP, ACVP_REV_KAS_FFC, {ACVP_SUB_KAS_FFC_COMP}},
    { ACVP_KAS_FFC_NOCOMP,    &acvp_kas_ffc_kat_handler,         ACVP_ALG_KAS_FFC,           ACVP_ALG_KAS_FFC_NOCOMP, ACVP_REV_KAS_FFC, {ACVP_SUB_KAS_FFC_NOCOMP}},
    { ACVP_KAS_FFC_SSC,       &acvp_kas_ffc_ssc_kat_handler,     ACVP_ALG_KAS_FFC_SSC,       ACVP_ALG_KAS_FFC_COMP, ACVP_REV_KAS_FFC_SSC, {ACVP_SUB_KAS_FFC_SSC}},
    { ACVP_KAS_IFC_SSC,       &acvp_kas_ifc_ssc_kat_handler,     ACVP_ALG_KAS_IFC_SSC,       ACVP_ALG_KAS_IFC_COMP, ACVP_REV_KAS_IFC_SSC, {ACVP_SUB_KAS_IFC_SSC}},
    { ACVP_KDA_ONESTEP,       &acvp_kda_onestep_kat_handler,     ACVP_ALG_KDA_ALG_STR,       ACVP_ALG_KDA_ONESTEP, ACVP_REV_KDA_ONESTEP, {ACVP_SUB_KDA_ONESTEP}},
    { ACVP_KDA_HKDF,          &acvp_kda_hkdf_kat_handler,        ACVP_ALG_KDA_ALG_STR,       ACVP_ALG_KDA_HKDF, ACVP_REV_KDA_HKDF, {ACVP_SUB_KDA_HKDF}},
    { ACVP_KTS_IFC,           &acvp_kts_ifc_kat_handler,         ACVP_ALG_KTS_IFC,           ACVP_ALG_KTS_IFC_COMP, ACVP_REV_KTS_IFC, {ACVP_SUB_KTS_IFC}},
    { ACVP_SAFE_PRIMES_KEYGEN, &acvp_safe_primes_kat_handler,    ACVP_ALG_SAFE_PRIMES_STR,   ACVP_ALG_SAFE_PRIMES_KEYGEN, ACVP_REV_SAFE_PRIMES, {ACVP_SUB_SAFE_PRIMES_KEYGEN}},
    { ACVP_SAFE_PRIMES_KEYVER, &acvp_safe_primes_kat_handler,    ACVP_ALG_SAFE_PRIMES_STR,   ACVP_ALG_SAFE_PRIMES_KEYVER, ACVP_REV_SAFE_PRIMES, {ACVP_SUB_SAFE_PRIMES_KEYVER}}
};

/*
 * This is the first function the user should invoke to allocate
 * a new context to be used for the test session.
 */
ACVP_RESULT acvp_create_test_session(ACVP_CTX **ctx,
                                     ACVP_RESULT (*progress_cb)(char *msg),
                                     ACVP_LOG_LVL level) {
    if (!ctx) {
        return ACVP_INVALID_ARG;
    }
    if (*ctx) {
        printf("ERROR: Cannot initialize non-null ctx; clear ctx & set to NULL first\n");
        return ACVP_DUPLICATE_CTX;
    }
    *ctx = calloc(1, sizeof(ACVP_CTX));
    if (!*ctx) {
        return ACVP_MALLOC_FAIL;
    }

    if (progress_cb) {
        (*ctx)->test_progress_cb = progress_cb;
    }

    (*ctx)->debug = level;

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_set_2fa_callback(ACVP_CTX *ctx, ACVP_RESULT (*totp_cb)(char **token, int token_max)) {
    if (totp_cb == NULL) {
        return ACVP_MISSING_ARG;
    }
    if (ctx == NULL) {
        return ACVP_NO_CTX;
    }
    ctx->totp_cb = totp_cb;
    return ACVP_SUCCESS;
}

static void acvp_free_prereqs(ACVP_CAPS_LIST *cap_list) {
    while (cap_list->prereq_vals) {
        ACVP_PREREQ_LIST *temp_ptr;
        temp_ptr = cap_list->prereq_vals;
        cap_list->prereq_vals = cap_list->prereq_vals->next;
        free(temp_ptr);
    }
}

/*
 * Free internal memory for EC curve/hash alg list
 */
static void acvp_cap_free_ec_alg_list(ACVP_CURVE_ALG_COMPAT_LIST *list) {
    ACVP_CURVE_ALG_COMPAT_LIST *tmp = NULL, *tmp2 = NULL;

    if (!list) {
        return;
    }

    tmp = list;
    while (tmp) {
        tmp2 = tmp;
        tmp = tmp->next;
        free(tmp2);
    }
}

/*
 * Free Internal memory for DSA operations. Since it supports
 * multiple modes, we have to free the whole list
 */
static void acvp_cap_free_dsa_attrs(ACVP_CAPS_LIST *cap_entry) {
    ACVP_DSA_ATTRS *attrs = NULL, *next = NULL;
    ACVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    int i;

    for (i = 0; i <= ACVP_DSA_MAX_MODES - 1; i++) {
        dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[i];
        if (dsa_cap_mode->defined) {
            next = dsa_cap_mode->dsa_attrs;
            while (next) {
                attrs = next;
                next = attrs->next;
                free(attrs);
            }
        }
    }
    dsa_cap_mode = cap_entry->cap.dsa_cap->dsa_cap_mode;
    free(dsa_cap_mode);
}

/*
 * Free Internal memory for keygen struct. Since it supports
 * multiple modes, we have to free the whole list
 */
static void acvp_cap_free_rsa_keygen_list(ACVP_CAPS_LIST *cap_list) {
    ACVP_RSA_KEYGEN_CAP *keygen_cap = cap_list->cap.rsa_keygen_cap;
    ACVP_RSA_KEYGEN_CAP *temp_keygen_cap;

    acvp_free_prereqs(cap_list);

    while (keygen_cap) {
        if (keygen_cap->fixed_pub_exp) {
            free(keygen_cap->fixed_pub_exp);
        }

        ACVP_RSA_MODE_CAPS_LIST *mode_list = keygen_cap->mode_capabilities;
        ACVP_RSA_MODE_CAPS_LIST *temp_mode_list;

        while (mode_list) {
            acvp_cap_free_nl(mode_list->hash_algs);
            acvp_cap_free_nl(mode_list->prime_tests);

            temp_mode_list = mode_list;
            mode_list = mode_list->next;
            free(temp_mode_list);
            temp_mode_list = NULL;
        }

        temp_keygen_cap = keygen_cap;
        keygen_cap = keygen_cap->next;
        free(temp_keygen_cap);
        temp_keygen_cap = NULL;
    }
}

/*
 * Free Internal memory for keygen struct. Since it supports
 * multiple modes, we have to free the whole list
 */
static void acvp_cap_free_rsa_sig_list(ACVP_CAPS_LIST *cap_list) {
    ACVP_RSA_SIG_CAP *sig_cap = NULL, *temp_sig_cap = NULL;

    if (cap_list->cipher == ACVP_RSA_SIGGEN) {
        sig_cap = cap_list->cap.rsa_siggen_cap;
    } else if (cap_list->cipher == ACVP_RSA_SIGVER) {
        sig_cap = cap_list->cap.rsa_sigver_cap;
    } else {
        return;
    }

    acvp_free_prereqs(cap_list);

    while (sig_cap) {
        ACVP_RSA_MODE_CAPS_LIST *mode_list = sig_cap->mode_capabilities;
        ACVP_RSA_MODE_CAPS_LIST *temp_mode_list;

        if (sig_cap->fixed_pub_exp) {
            free(sig_cap->fixed_pub_exp);
        }
        while (mode_list) {
            acvp_cap_free_hash_pairs(mode_list->hash_pair);

            temp_mode_list = mode_list;
            mode_list = mode_list->next;
            free(temp_mode_list);
            temp_mode_list = NULL;
        }

        temp_sig_cap = sig_cap;
        sig_cap = sig_cap->next;
        free(temp_sig_cap);
        temp_sig_cap = NULL;
    }
}

/*
 * Free Internal memory for KAS-ECC Data struct
 */
static void acvp_cap_free_kas_ecc_mode(ACVP_CAPS_LIST *cap_list) {
    ACVP_KAS_ECC_CAP *kas_ecc_cap = cap_list->cap.kas_ecc_cap;
    ACVP_KAS_ECC_CAP_MODE *mode;
    int i;

    if (kas_ecc_cap) {
        ACVP_PREREQ_LIST *current_pre_req_vals;
        ACVP_PREREQ_LIST *next_pre_req_vals;
        ACVP_KAS_ECC_PSET *current_pset;
        ACVP_KAS_ECC_PSET *next_pset;
        ACVP_KAS_ECC_SCHEME *current_scheme;
        ACVP_KAS_ECC_SCHEME *next_scheme;

        if (kas_ecc_cap->kas_ecc_mode) {
            for (i = 0; i < ACVP_KAS_ECC_MAX_MODES; i++) {
                mode = &kas_ecc_cap->kas_ecc_mode[i];
                current_pre_req_vals = mode->prereq_vals;
                /*
                 * Delete all pre_req
                 */
                if (current_pre_req_vals) {
                    do {
                        next_pre_req_vals = current_pre_req_vals->next;
                        free(current_pre_req_vals);
                        current_pre_req_vals = next_pre_req_vals;
                    } while (current_pre_req_vals);
                }
                /*
                 * Delete all function name lists
                 */
                acvp_cap_free_pl(mode->function);

                /*
                 * Delete all curve name lists
                 */
                acvp_cap_free_pl(mode->curve);

                /*
                 * Delete all schemes, psets and their param lists
                 */
                current_scheme = mode->scheme;
                if (current_scheme) {
                    do {
                        acvp_cap_free_pl(current_scheme->role);
                        current_pset = current_scheme->pset;
                        if (current_pset) {
                            do {
                                acvp_cap_free_pl(current_pset->sha);
                                next_pset = current_pset->next;
                                free(current_pset);
                                current_pset = next_pset;
                            } while (current_pset);
                        }
                        next_scheme = current_scheme->next;
                        free(current_scheme);
                        current_scheme = next_scheme;
                    } while (current_scheme);
                }
            }
        }
    }
    free(cap_list->cap.kas_ecc_cap->kas_ecc_mode);
    free(cap_list->cap.kas_ecc_cap);
}

/*
 * Free Internal memory for KAS-FFC Data struct
 */
static void acvp_cap_free_kas_ffc_mode(ACVP_CAPS_LIST *cap_list) {
    ACVP_KAS_FFC_CAP *kas_ffc_cap = cap_list->cap.kas_ffc_cap;
    ACVP_KAS_FFC_CAP_MODE *mode;
    int i;

    if (kas_ffc_cap) {
        ACVP_PREREQ_LIST *current_pre_req_vals;
        ACVP_PREREQ_LIST *next_pre_req_vals;
        ACVP_KAS_FFC_PSET *current_pset;
        ACVP_KAS_FFC_PSET *next_pset;
        ACVP_KAS_FFC_SCHEME *current_scheme;
        ACVP_KAS_FFC_SCHEME *next_scheme;

        if (kas_ffc_cap->kas_ffc_mode) {
            for (i = 0; i < ACVP_KAS_FFC_MAX_MODES; i++) {
                mode = &kas_ffc_cap->kas_ffc_mode[i];
                current_pre_req_vals = mode->prereq_vals;
                /*
                 * Delete all pre_req
                 */
                if (current_pre_req_vals) {
                    do {
                        next_pre_req_vals = current_pre_req_vals->next;
                        free(current_pre_req_vals);
                        current_pre_req_vals = next_pre_req_vals;
                    } while (current_pre_req_vals);
                }
                /*
                 * Delete all generation methods
                 */
                acvp_cap_free_pl(mode->genmeth);

                /*
                 * Delete all function name lists
                 */
                acvp_cap_free_pl(mode->function);

                /*
                 * Delete all schemes, psets and their param lists
                 */
                current_scheme = mode->scheme;
                if (current_scheme) {
                    do {
                        acvp_cap_free_pl(current_scheme->role);
                        current_pset = current_scheme->pset;
                        if (current_pset) {
                            do {
                                acvp_cap_free_pl(current_pset->sha);
                                next_pset = current_pset->next;
                                free(current_pset);
                                current_pset = next_pset;
                            } while (current_pset);
                        }
                        next_scheme = current_scheme->next;
                        free(current_scheme);
                        current_scheme = next_scheme;
                    } while (current_scheme);
                }
            }
        }
    }
    free(cap_list->cap.kas_ffc_cap->kas_ffc_mode);
    free(cap_list->cap.kas_ffc_cap);
}

/*
 * Free Internal memory for DRBG Data struct
 */
static void acvp_free_drbg_struct(ACVP_CAPS_LIST *cap_list) {
    ACVP_DRBG_CAP *drbg_cap = cap_list->cap.drbg_cap;

    if (drbg_cap) {
        ACVP_DRBG_CAP_MODE_LIST *mode_list = drbg_cap->drbg_cap_mode_list;
        ACVP_DRBG_CAP_MODE_LIST *next_mode_list;
        ACVP_PREREQ_LIST *current_pre_req_vals;
        ACVP_PREREQ_LIST *next_pre_req_vals;

        if (mode_list) {
            do {
                //Top of list
                current_pre_req_vals = mode_list->cap_mode.prereq_vals;
                /*
                 * Delete all pre_req
                 */
                if (current_pre_req_vals) {
                    do {
                        next_pre_req_vals = current_pre_req_vals->next;
                        free(current_pre_req_vals);
                        current_pre_req_vals = next_pre_req_vals;
                    } while (current_pre_req_vals);
                }
                next_mode_list = mode_list->next;
                free(mode_list);
                mode_list = next_mode_list;
            } while (mode_list);
        }
        free(drbg_cap);
        drbg_cap = NULL;
        cap_list->cap.drbg_cap = NULL;
    }
}

/*
 * Free Internal memory for KDF108 Cap struct
 */
static void acvp_cap_free_kdf108(ACVP_CAPS_LIST *cap_list) {
    ACVP_KDF108_CAP *cap = cap_list->cap.kdf108_cap;
    ACVP_KDF108_MODE_PARAMS *mode_obj = NULL;

    if (cap) {
        if (cap->counter_mode.kdf_mode) {
            mode_obj = &cap->counter_mode;
            if (mode_obj->mac_mode) {
                acvp_cap_free_nl(mode_obj->mac_mode);
            }
            if (mode_obj->data_order) {
                acvp_cap_free_nl(mode_obj->data_order);
            }
            if (mode_obj->counter_lens) {
                acvp_cap_free_sl(mode_obj->counter_lens);
            }
        }

        if (cap->feedback_mode.kdf_mode) {
            mode_obj = &cap->feedback_mode;
            if (mode_obj->mac_mode) {
                acvp_cap_free_nl(mode_obj->mac_mode);
            }
            if (mode_obj->data_order) {
                acvp_cap_free_nl(mode_obj->data_order);
            }
            if (mode_obj->counter_lens) {
                acvp_cap_free_sl(mode_obj->counter_lens);
            }
        }

        if (cap->dpi_mode.kdf_mode) {
            mode_obj = &cap->dpi_mode;
            if (mode_obj->mac_mode) {
                acvp_cap_free_nl(mode_obj->mac_mode);
            }
            if (mode_obj->data_order) {
                acvp_cap_free_nl(mode_obj->data_order);
            }
            if (mode_obj->counter_lens) {
                acvp_cap_free_sl(mode_obj->counter_lens);
            }
        }

        free(cap);
        cap = NULL;
        cap_list->cap.kdf108_cap = NULL;
    }
}

static void acvp_cap_free_kts_ifc_schemes(ACVP_CAPS_LIST *cap_entry) {
    ACVP_KTS_IFC_SCHEMES *current_scheme;


    current_scheme = cap_entry->cap.kts_ifc_cap->schemes;
    while (current_scheme) {
        acvp_cap_free_pl(current_scheme->roles);
        acvp_cap_free_pl(current_scheme->hash);
        free(current_scheme->assoc_data_pattern);
        free(current_scheme->encodings);
        current_scheme = current_scheme->next;
    }
    free(cap_entry->cap.kts_ifc_cap->schemes);
}
/*
 * The application will invoke this to free the ACVP context
 * when the test session is finished.
 */
ACVP_RESULT acvp_free_test_session(ACVP_CTX *ctx) {
    ACVP_VS_LIST *vs_entry, *vs_e2;
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    if (!ctx) {
        ACVP_LOG_STATUS("No ctx to free");
        return ACVP_SUCCESS;
    }

    if (ctx->kat_resp) { json_value_free(ctx->kat_resp); }
    if (ctx->curl_buf) { free(ctx->curl_buf); }
    if (ctx->server_name) { free(ctx->server_name); }
    if (ctx->path_segment) { free(ctx->path_segment); }
    if (ctx->api_context) { free(ctx->api_context); }
    if (ctx->cacerts_file) { free(ctx->cacerts_file); }
    if (ctx->tls_cert) { free(ctx->tls_cert); }
    if (ctx->tls_key) { free(ctx->tls_key); }
    if (ctx->http_user_agent) { free(ctx->http_user_agent); }
    if (ctx->session_file_path) { free(ctx->session_file_path); }
    if (ctx->json_filename) { free(ctx->json_filename); }
    if (ctx->session_url) { free(ctx->session_url); }
    if (ctx->vector_req_file) { free(ctx->vector_req_file); }
    if (ctx->get_string) { free(ctx->get_string); }
    if (ctx->delete_string) { free(ctx->delete_string); }
    if (ctx->save_filename) { free(ctx->save_filename); }
    if (ctx->post_filename) { free(ctx->post_filename); }
    if (ctx->put_filename) { free(ctx->put_filename); }
    if (ctx->jwt_token) { free(ctx->jwt_token); }
    if (ctx->tmp_jwt) { free(ctx->tmp_jwt); }
    if (ctx->vs_list) {
        vs_entry = ctx->vs_list;
        while (vs_entry) {
            vs_e2 = vs_entry->next;
            free(vs_entry);
            vs_entry = vs_e2;
        }
    }
    if (ctx->vsid_url_list) {
        acvp_free_str_list(&ctx->vsid_url_list);
    }
    if (ctx->registration) {
            json_value_free(ctx->registration);
    }
    if (ctx->caps_list) {
        cap_entry = ctx->caps_list;
        while (cap_entry) {
            cap_e2 = cap_entry->next;
            if (cap_entry->prereq_vals) {
                acvp_free_prereqs(cap_entry);
            }
            switch (cap_entry->cap_type) {
            case ACVP_SYM_TYPE:
                acvp_cap_free_sl(cap_entry->cap.sym_cap->keylen);
                acvp_cap_free_sl(cap_entry->cap.sym_cap->ptlen);
                acvp_cap_free_sl(cap_entry->cap.sym_cap->ivlen);
                acvp_cap_free_sl(cap_entry->cap.sym_cap->aadlen);
                acvp_cap_free_sl(cap_entry->cap.sym_cap->taglen);
                acvp_cap_free_sl(cap_entry->cap.sym_cap->tweak);
                free(cap_entry->cap.sym_cap);
                break;
            case ACVP_HASH_TYPE:
                free(cap_entry->cap.hash_cap);
                break;
            case ACVP_DRBG_TYPE:
                acvp_free_drbg_struct(cap_entry);
                break;
            case ACVP_HMAC_TYPE:
                free(cap_entry->cap.hmac_cap);
                break;
            case ACVP_CMAC_TYPE:
                acvp_cap_free_sl(cap_entry->cap.cmac_cap->key_len);
                acvp_cap_free_sl(cap_entry->cap.cmac_cap->keying_option);
                free(cap_entry->cap.cmac_cap);
                break;
            case ACVP_DSA_TYPE:
                acvp_cap_free_dsa_attrs(cap_entry);
                free(cap_entry->cap.dsa_cap);
                break;
            case ACVP_KAS_ECC_CDH_TYPE:
            case ACVP_KAS_ECC_COMP_TYPE:
            case ACVP_KAS_ECC_NOCOMP_TYPE:
            case ACVP_KAS_ECC_SSC_TYPE:
                acvp_cap_free_kas_ecc_mode(cap_entry);
                break;
            case ACVP_KAS_FFC_SSC_TYPE:
            case ACVP_KAS_FFC_COMP_TYPE:
            case ACVP_KAS_FFC_NOCOMP_TYPE:
                acvp_cap_free_kas_ffc_mode(cap_entry);
                break;
            case ACVP_KAS_IFC_TYPE:
                acvp_cap_free_pl(cap_entry->cap.kas_ifc_cap->kas1_roles);
                acvp_cap_free_pl(cap_entry->cap.kas_ifc_cap->kas2_roles);
                acvp_cap_free_pl(cap_entry->cap.kas_ifc_cap->keygen_method);
                acvp_cap_free_sl(cap_entry->cap.kas_ifc_cap->modulo);
                free(cap_entry->cap.kas_ifc_cap->fixed_pub_exp);
                free(cap_entry->cap.kas_ifc_cap);
                break;
            case ACVP_KDA_ONESTEP_TYPE:
                if (cap_entry->cap.kda_onestep_cap->literal_pattern_candidate) {
                    free(cap_entry->cap.kda_onestep_cap->literal_pattern_candidate);
                }
                acvp_cap_free_pl(cap_entry->cap.kda_onestep_cap->patterns);
                acvp_cap_free_pl(cap_entry->cap.kda_onestep_cap->encodings);
                acvp_cap_free_nl(cap_entry->cap.kda_onestep_cap->aux_functions);
                acvp_cap_free_nl(cap_entry->cap.kda_onestep_cap->mac_salt_methods);
                free(cap_entry->cap.kda_onestep_cap);
                break;
            case ACVP_KDA_HKDF_TYPE:
                if (cap_entry->cap.kda_hkdf_cap->literal_pattern_candidate) {
                    free(cap_entry->cap.kda_hkdf_cap->literal_pattern_candidate);
                }
                acvp_cap_free_pl(cap_entry->cap.kda_hkdf_cap->patterns);
                acvp_cap_free_pl(cap_entry->cap.kda_hkdf_cap->encodings);
                acvp_cap_free_nl(cap_entry->cap.kda_hkdf_cap->hmac_algs);
                acvp_cap_free_nl(cap_entry->cap.kda_hkdf_cap->mac_salt_methods);
                free(cap_entry->cap.kda_hkdf_cap);
                break;
            case ACVP_KTS_IFC_TYPE:
                acvp_cap_free_pl(cap_entry->cap.kts_ifc_cap->keygen_method);
                acvp_cap_free_pl(cap_entry->cap.kts_ifc_cap->functions);
                acvp_cap_free_sl(cap_entry->cap.kts_ifc_cap->modulo);
                free(cap_entry->cap.kts_ifc_cap->fixed_pub_exp);
                free(cap_entry->cap.kts_ifc_cap->iut_id);
                acvp_cap_free_kts_ifc_schemes(cap_entry);
                free(cap_entry->cap.kts_ifc_cap);
                break;
            case ACVP_RSA_KEYGEN_TYPE:
                acvp_cap_free_rsa_keygen_list(cap_entry);
                break;
            case ACVP_RSA_SIGGEN_TYPE:
                acvp_cap_free_rsa_sig_list(cap_entry);
                break;
            case ACVP_RSA_SIGVER_TYPE:
                acvp_cap_free_rsa_sig_list(cap_entry);
                break;
            case ACVP_RSA_PRIM_TYPE:
                if (cap_entry->cap.rsa_prim_cap->fixed_pub_exp) {
                    free(cap_entry->cap.rsa_prim_cap->fixed_pub_exp);
                }
                free(cap_entry->cap.rsa_prim_cap);
                break;
            case ACVP_ECDSA_KEYGEN_TYPE:
                acvp_cap_free_ec_alg_list(cap_entry->cap.ecdsa_keygen_cap->curves);
                acvp_cap_free_nl(cap_entry->cap.ecdsa_keygen_cap->secret_gen_modes);
                free(cap_entry->cap.ecdsa_keygen_cap);
                break;
            case ACVP_ECDSA_KEYVER_TYPE:
                acvp_cap_free_ec_alg_list(cap_entry->cap.ecdsa_keyver_cap->curves);
                acvp_cap_free_nl(cap_entry->cap.ecdsa_keyver_cap->secret_gen_modes);
                free(cap_entry->cap.ecdsa_keyver_cap);
                break;
            case ACVP_ECDSA_SIGGEN_TYPE:
                acvp_cap_free_ec_alg_list(cap_entry->cap.ecdsa_siggen_cap->curves);
                free(cap_entry->cap.ecdsa_siggen_cap);
                break;
            case ACVP_ECDSA_SIGVER_TYPE:
                acvp_cap_free_ec_alg_list(cap_entry->cap.ecdsa_sigver_cap->curves);
                free(cap_entry->cap.ecdsa_sigver_cap);
                break;
            case ACVP_KDF135_SRTP_TYPE:
                acvp_cap_free_sl(cap_entry->cap.kdf135_srtp_cap->aes_keylens);
                free(cap_entry->cap.kdf135_srtp_cap);
                break;
            case ACVP_KDF108_TYPE:
                acvp_cap_free_kdf108(cap_entry);
                break;
            case ACVP_KDF135_SNMP_TYPE:
                acvp_cap_free_sl(cap_entry->cap.kdf135_snmp_cap->pass_lens);
                acvp_cap_free_nl(cap_entry->cap.kdf135_snmp_cap->eng_ids);
                free(cap_entry->cap.kdf135_snmp_cap);
                break;
            case ACVP_KDF135_SSH_TYPE:
                free(cap_entry->cap.kdf135_ssh_cap);
                break;
            case ACVP_KDF135_IKEV2_TYPE:
                acvp_cap_free_nl(cap_entry->cap.kdf135_ikev2_cap->hash_algs);
                free(cap_entry->cap.kdf135_ikev2_cap);
                break;
            case ACVP_KDF135_IKEV1_TYPE:
                acvp_cap_free_nl(cap_entry->cap.kdf135_ikev1_cap->hash_algs);
                free(cap_entry->cap.kdf135_ikev1_cap);
                break;
            case ACVP_KDF135_X963_TYPE:
                acvp_cap_free_nl(cap_entry->cap.kdf135_x963_cap->hash_algs);
                acvp_cap_free_sl(cap_entry->cap.kdf135_x963_cap->shared_info_lengths);
                acvp_cap_free_sl(cap_entry->cap.kdf135_x963_cap->field_sizes);
                acvp_cap_free_sl(cap_entry->cap.kdf135_x963_cap->key_data_lengths);
                free(cap_entry->cap.kdf135_x963_cap);
                break;
            case ACVP_PBKDF_TYPE:
                acvp_cap_free_nl(cap_entry->cap.pbkdf_cap->hmac_algs);
                free(cap_entry->cap.pbkdf_cap);
                break;
            case ACVP_KDF_TLS13_TYPE:
                acvp_cap_free_nl(cap_entry->cap.kdf_tls13_cap->hmac_algs);
                acvp_cap_free_pl(cap_entry->cap.kdf_tls13_cap->running_mode);
                free(cap_entry->cap.kdf_tls13_cap);
                break;
            case ACVP_KDF_TLS12_TYPE:
                acvp_cap_free_nl(cap_entry->cap.kdf_tls12_cap->hash_algs);
                free(cap_entry->cap.kdf_tls12_cap);
                break;
            case ACVP_SAFE_PRIMES_KEYGEN_TYPE:
                if (cap_entry->cap.safe_primes_keygen_cap->mode->genmeth) {
                    acvp_cap_free_pl(cap_entry->cap.safe_primes_keygen_cap->mode->genmeth);
                }
                free(cap_entry->cap.safe_primes_keygen_cap->mode);
                free(cap_entry->cap.safe_primes_keygen_cap);
                break;
            case ACVP_SAFE_PRIMES_KEYVER_TYPE:
                if (cap_entry->cap.safe_primes_keyver_cap->mode->genmeth) {
                    acvp_cap_free_pl(cap_entry->cap.safe_primes_keyver_cap->mode->genmeth);
                }
                free(cap_entry->cap.safe_primes_keyver_cap->mode);
                free(cap_entry->cap.safe_primes_keyver_cap);
                break;
            case ACVP_KDF135_TPM_TYPE:
            default:
                return ACVP_INVALID_ARG;
            }
            free(cap_entry);
            cap_entry = cap_e2;
        }
    }

    /*
     * Free everything in the Operating Environment structs
     */
    acvp_oe_free_operating_env(ctx);

    /* Free the ACVP_CTX struct */
    free(ctx);

    return ACVP_SUCCESS;
}

/*
 * Simple utility function to free a supported length
 * list from the capabilities structure.
 */
static void acvp_cap_free_sl(ACVP_SL_LIST *list) {
    ACVP_SL_LIST *top = list;
    ACVP_SL_LIST *tmp;

    while (top) {
        tmp = top;
        top = top->next;
        free(tmp);
    }
}

/*
 * Simple utility function to free a supported param
 * list from the capabilities structure.
 */
static void acvp_cap_free_pl(ACVP_PARAM_LIST *list) {
    ACVP_PARAM_LIST *top = list;
    ACVP_PARAM_LIST *tmp;

    while (top) {
        tmp = top;
        top = top->next;
        free(tmp);
    }
}

/*
 * Simple utility function to free a name
 * list from the capabilities structure.
 */
static void acvp_cap_free_nl(ACVP_NAME_LIST *list) {
    ACVP_NAME_LIST *top = list;
    ACVP_NAME_LIST *tmp;

    while (top) {
        tmp = top;
        top = top->next;
        free(tmp);
    }
}

static void acvp_cap_free_hash_pairs(ACVP_RSA_HASH_PAIR_LIST *list) {
    ACVP_RSA_HASH_PAIR_LIST *top = list;
    ACVP_RSA_HASH_PAIR_LIST *tmp;

    while (top) {
        tmp = top;

        top = top->next;
        free(tmp);
    }
}

static void acvp_list_failing_algorithms(ACVP_CTX *ctx, ACVP_STRING_LIST **list) {
    if (!list || *list == NULL) {
        return;
    }
    ACVP_STRING_LIST *iterator = *list;
    if (!iterator || !iterator->string) {
        return;
    }
    ACVP_LOG_STATUS("Failing algorithms:");
    while (iterator && iterator->string) {
        ACVP_LOG_STATUS("    %s", iterator->string);
        iterator = iterator->next;
    }
}

/*
 * Allows application to load JSON kat vector file within context
 * to be read in and used for vector testing
 */
ACVP_RESULT acvp_load_kat_filename(ACVP_CTX *ctx, const char *kat_filename) {
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Array *reg_array;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!kat_filename) {
        ACVP_LOG_ERR("Must provide value for JSON filename");
        return ACVP_MISSING_ARG;
    }

    if (strnlen_s(kat_filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided kat_filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    val = json_parse_file(kat_filename);

    reg_array = json_value_get_array(val);
    obj = json_array_get_object(reg_array, 1);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        json_value_free(val);
        return ACVP_INVALID_ARG;
    }

    /* Process the kat vector(s) */
    rv  = acvp_dispatch_vector_set(ctx, obj);
    json_value_free(val);
    return rv;
}

/*
 * Allows application to load JSON vector file(req_filename) within context
 * to be read in and used for vector testing. The results are
 * then saved in a response file(rsp_filename).
 */
ACVP_RESULT acvp_run_vectors_from_file(ACVP_CTX *ctx, const char *req_filename, const char *rsp_filename) {
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;
    JSON_Array *reg_array;
    JSON_Value *file_val = NULL;
    JSON_Value *kat_val = NULL;
    JSON_Array *kat_array;
    JSON_Value *rsp_val = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;
    int n, i;
    ACVP_STRING_LIST *vs_entry;
    JSON_Array *vect_sets = NULL;
    const char *test_session_url = NULL;
    int vs_cnt = 0, isSample = 0;
    const char *jwt = NULL;
    char *json_result = NULL;

    ACVP_LOG_STATUS("Beginning offline processing of vector sets...");

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!req_filename || !rsp_filename) {
        ACVP_LOG_ERR("Must provide value for JSON filename");
        return ACVP_MISSING_ARG;
    }

    if (strnlen_s(req_filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided req_filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    val = json_parse_file(req_filename);

    n = 0;
    reg_array = json_value_get_array(val);
    obj = json_array_get_object(reg_array, n);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    /*
     * This is the identifiers provided by the server
     * for this specific test session!
     */
    test_session_url = json_object_get_string(obj, "url");
    if (test_session_url) {
        ctx->session_url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
        strcpy_s(ctx->session_url, ACVP_ATTR_URL_MAX + 1, test_session_url);
    } else {
        ACVP_LOG_WARN("Missing session URL, results will not be POSTed to server");
        goto end;
    }

    jwt = json_object_get_string(obj, "jwt");
    if (jwt) {
        ctx->jwt_token = calloc(ACVP_JWT_TOKEN_MAX + 1, sizeof(char));
        strcpy_s(ctx->jwt_token, ACVP_JWT_TOKEN_MAX + 1, jwt);
    } else {
        ACVP_LOG_WARN("Missing JWT, results will not be POSTed to server");
        goto end;
    }

    isSample = json_object_get_boolean(obj, "isSample");
    if (json_object_has_value(obj, "isSample")) {
        ctx->is_sample = isSample;
    } else {
        ACVP_LOG_WARN("Missing indication of whether tests are sample in file, continuing");
    }

    vect_sets = json_object_get_array(obj, "vectorSetUrls");
    vs_cnt = json_array_get_count(vect_sets);
    for (i = 0; i < vs_cnt; i++) {
        const char *vsid_url = json_array_get_string(vect_sets, i);

        if (!vsid_url) {
            ACVP_LOG_WARN("No vsId URL, results will not be POSTed to server");
            goto end;
        }

        rv = acvp_append_vsid_url(ctx, vsid_url);
        if (rv != ACVP_SUCCESS) goto end;
        ACVP_LOG_INFO("Received vsid_url=%s", vsid_url);
    }

    n++;        /* bump past the version or url, jwt, url sets */
    obj = json_array_get_object(reg_array, n);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    vs_entry = ctx->vsid_url_list;
    if (!vs_entry) {
        goto end;
    }

    while (obj) {
        if (!vs_entry) {
            goto end;
        }
        /* Process the kat vector(s) */
        rv  = acvp_dispatch_vector_set(ctx, obj);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("KAT dispatch error");
            goto end;
        }
        ACVP_LOG_STATUS("Writing vector set responses for vector set %d...", ctx->vs_id);

        /* 
         * Convert the JSON from a fully qualified to a value that can be 
         * added to the file. Kind of klumsy, but it works.
         */
        kat_array = json_value_get_array(ctx->kat_resp);
        kat_val = json_array_get_value(kat_array, 1);
        if (!kat_val) {
            ACVP_LOG_ERR("JSON val parse error");
            goto end;
        }
        json_result = json_serialize_to_string_pretty(kat_val, NULL);
        file_val = json_parse_string(json_result);
        json_free_serialized_string(json_result);

        /* track first vector set with file count */
        if (n == 1) {

            rsp_val = json_array_get_value(reg_array, 0);
            /* start the file with the '[' and identifiers array */
            rv = acvp_json_serialize_to_file_pretty_w(rsp_val, rsp_filename);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("File write error");
                json_value_free(file_val);
                goto end;
            }
        } 
        /* append vector sets */
        rv = acvp_json_serialize_to_file_pretty_a(file_val, rsp_filename);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("File write error");
            json_value_free(file_val);
            goto end;
        }

        json_value_free(file_val);
        file_val = NULL;
        n++;
        obj = json_array_get_object(reg_array, n);
        vs_entry = vs_entry->next;
    }
    /* append the final ']' to make the JSON work */ 
    rv = acvp_json_serialize_to_file_pretty_a(NULL, rsp_filename);
    ACVP_LOG_STATUS("Completed processing of vector sets. Responses saved in specified file.");
end:
    json_value_free(val);
    return rv;
}

/*
 * Allows application to read JSON vector responses from a file(rsp_filename)
 * and upload them to the server for verification.
 */
ACVP_RESULT acvp_upload_vectors_from_file(ACVP_CTX *ctx, const char *rsp_filename, int fips_validation) {
    JSON_Object *obj = NULL;
    JSON_Object *rsp_obj = NULL;
    JSON_Object *ver_obj = NULL;
    JSON_Value *vs_val = NULL;
    JSON_Value *new_val = NULL;
    JSON_Value *ver_val = NULL;
    JSON_Value *val = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Array *reg_array;
    int n, i;
    ACVP_STRING_LIST *vs_entry;
    JSON_Array *vect_sets = NULL;
    const char *test_session_url = NULL;
    int vs_cnt = 0, isSample = 0;
    const char *jwt = NULL;
    char *json_result = NULL;
    JSON_Array *vec_array = NULL;
    JSON_Value *vec_array_val = NULL;

    ACVP_LOG_STATUS("Uploading vectors from response file...");

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!rsp_filename) {
        ACVP_LOG_ERR("Must provide value for JSON filename");
        return ACVP_MISSING_ARG;
    }

    if (strnlen_s(rsp_filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided rsp_filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    val = json_parse_file(rsp_filename);
    if (!val) {
        ACVP_LOG_ERR("JSON val parse error");
        return ACVP_MALFORMED_JSON;
    }
    reg_array = json_value_get_array(val);
    obj = json_array_get_object(reg_array, 0);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        rv = ACVP_MALFORMED_JSON;
        goto end;
    }

    /*
     * This is the identifiers provided by the server
     * for this specific test session!
     */
    test_session_url = json_object_get_string(obj, "url");
    if (!test_session_url) {
        ACVP_LOG_ERR("Missing session URL");
        rv = ACVP_MALFORMED_JSON;
        goto end;
    }

    ctx->session_url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!ctx->session_url) {
        rv = ACVP_MALLOC_FAIL;
        goto end;
    }
    strcpy_s(ctx->session_url, ACVP_ATTR_URL_MAX + 1, test_session_url);

    jwt = json_object_get_string(obj, "jwt");
    if (!jwt) {
        rv = ACVP_MALFORMED_JSON;
        goto end;
    }
    ctx->jwt_token = calloc(ACVP_JWT_TOKEN_MAX + 1, sizeof(char));
    if (!ctx->jwt_token) {
        rv = ACVP_MALLOC_FAIL;
        goto end;
    }
    
    isSample = json_object_get_boolean(obj, "isSample");
    if (json_object_has_value(obj, "isSample")) {
        ctx->is_sample = isSample;
    } else {
        ACVP_LOG_WARN("Missing indication of whether tests are sample in file, continuing");
    }

    strcpy_s(ctx->jwt_token, ACVP_JWT_TOKEN_MAX + 1, jwt);

    vect_sets = json_object_get_array(obj, "vectorSetUrls");
    vs_cnt = json_array_get_count(vect_sets);
    for (i = 0; i < vs_cnt; i++) {
        const char *vsid_url = json_array_get_string(vect_sets, i);

        if (!vsid_url) {
            ACVP_LOG_ERR("No vsId URL, results will not be POSTed to server");
            rv = ACVP_MALFORMED_JSON;
            goto end;
        }

        rv = acvp_append_vsid_url(ctx, vsid_url);
        if (rv != ACVP_SUCCESS) goto end;
        ACVP_LOG_INFO("Received vsid_url=%s", vsid_url);
    }

    vs_entry = ctx->vsid_url_list;
    if (!vs_entry) {
        goto end;
    }

    if (fips_validation) {
        rv = acvp_verify_fips_validation_metadata(ctx);
        if (ACVP_SUCCESS != rv) {
            ACVP_LOG_ERR("Validation metadata not ready");
            goto end;
        }

        ctx->fips.do_validation = 1; /* Enable */
    } else {
        ctx->fips.do_validation = 0; /* Disable */
    }

    n = 1;    /* start with second array index */
    reg_array = json_value_get_array(val);
    vs_val = json_array_get_value(reg_array, n);

    while (vs_entry) {

        /* check vsId compared to vs URL */
        rsp_obj = json_array_get_object(reg_array, n);
        ctx->vs_id = json_object_get_number(rsp_obj, "vsId");

        vec_array_val = json_value_init_array();
        vec_array = json_array((const JSON_Value *)vec_array_val);

        ver_val = json_value_init_object();
        ver_obj = json_value_get_object(ver_val);

        json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
        json_array_append_value(vec_array, ver_val);

        json_result = json_serialize_to_string_pretty(vs_val, NULL);
        new_val = json_parse_string(json_result);
        json_free_serialized_string(json_result);

        json_array_append_value(vec_array, new_val);

        ctx->kat_resp = vec_array_val;

        json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
        if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
            printf("\n\n%s\n\n", json_result);
        } else {
            ACVP_LOG_INFO("\n\n%s\n\n", json_result);
        }
        json_free_serialized_string(json_result);
        ACVP_LOG_STATUS("Sending responses for vector set %d", ctx->vs_id);
        rv = acvp_submit_vector_responses(ctx, vs_entry->string);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to submit test results for vector set - skipping...");
        }

        json_value_free(vec_array_val);
        ctx->kat_resp = NULL;
        n++;
        vs_val = json_array_get_value(reg_array, n);
        vs_entry = vs_entry->next;
    }

    /*
     * Check the test results.
     */
    ACVP_LOG_STATUS("Tests complete, checking results...");
    rv = acvp_check_test_results(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to retrieve test results");
    }

    if (fips_validation) {
        /*
         * Tell the server to provision a FIPS certificate for this testSession.
         */
        rv = acvp_validate_test_session(ctx);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to perform Validation of testSession");
            goto end;
        }
    }
end:
    json_value_free(val);
    return rv;
}

/**
 * Allows application (with proper authentication) to connect to server and get results
 * of previous test session.
 */
ACVP_RESULT acvp_get_results_from_server(ACVP_CTX *ctx, const char *request_filename) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
  
    rv = acvp_parse_session_info_file(ctx, request_filename);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Error reading session info file, unable to get results");
        goto end;
    }

    rv = acvp_refresh(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to refresh login with ACVP server");
        goto end;
    }

    rv = acvp_check_test_results(ctx);
    
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to retrieve test results");
        goto end;
    }
    
end:
    return rv;
}

ACVP_RESULT acvp_get_expected_results(ACVP_CTX *ctx, const char *request_filename, const char *save_filename) {
    JSON_Value *val = NULL, *fw_val = NULL;
    JSON_Object *obj = NULL, *fw_obj = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    rv = acvp_parse_session_info_file(ctx, request_filename);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to parse session info file while trying to get expected results");
        goto end;
    }
    if (save_filename && strnlen_s(save_filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    if (!ctx->is_sample) {
        ACVP_LOG_ERR("Session not marked as sample");
        rv = ACVP_UNSUPPORTED_OP;
        goto end;
    }

    rv = acvp_refresh(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to refresh login with ACVP server");
        goto end;
    }

    rv = acvp_retrieve_vector_set_result(ctx, ctx->session_url);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Error retrieving vector set results!");
        goto end;
    }

    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        ACVP_LOG_ERR("Error while parsing json from server!");
        rv = ACVP_JSON_ERR;
        goto end;
    }
    obj = acvp_get_obj_from_rsp(ctx, val);
    if (!obj) {
        ACVP_LOG_ERR("Error while parsing json from server!");
        rv = ACVP_JSON_ERR;
        goto end;
    }

    JSON_Array *results = NULL;
    int count = 0, i = 0;
    JSON_Object *current = NULL;
    const char *vsid_url = NULL;

    results = json_object_get_array(obj, "results");
    if (!results) {
        ACVP_LOG_ERR("Error parsing status from server");
        rv = ACVP_JSON_ERR;
        goto end;
    }

    ACVP_LOG_STATUS("Beginning output of expected results...");
    ACVP_LOG_NEWLINE;

    if (save_filename) {
        //write the session URL and JWT to the file first
        fw_val = json_value_init_object();
        if (!fw_val) {
            ACVP_LOG_ERR("Error initializing JSON object");
            rv = ACVP_MALLOC_FAIL;
            goto end;
        }
        fw_obj = json_value_get_object(fw_val);
        if (!fw_obj) {
            ACVP_LOG_ERR("Error initializing JSON object");
            rv = ACVP_MALFORMED_JSON;
            goto end;
        }
        json_object_set_string(fw_obj, "jwt", ctx->jwt_token);
        json_object_set_string(fw_obj, "url", ctx->session_url);
        rv = acvp_json_serialize_to_file_pretty_w(fw_val, save_filename);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Error writing to provided file.");
            json_value_free(fw_val);
            goto end;
        }
        json_value_free(fw_val);
        fw_val = NULL;
        fw_obj = NULL;
    }

    count = (int)json_array_get_count(results);
    for (i = 0; i < count; i++) {
        current = json_array_get_object(results, i);
        if (!current) {
            ACVP_LOG_ERR("Error parsing status from server");
            rv = ACVP_JSON_ERR;
            goto end;
        }
        
        vsid_url = json_object_get_string(current, "vectorSetUrl");
        if (!vsid_url) {
            ACVP_LOG_ERR("Error parsing vector set URL from server");
            rv = ACVP_JSON_ERR;
            goto end;
        }
        if (strnlen_s(vsid_url, ACVP_ATTR_URL_MAX + 1) > ACVP_ATTR_URL_MAX) {
            ACVP_LOG_ERR("URL is too long. Cannot proceed.");
            rv = ACVP_TRANSPORT_FAIL;
            goto end;
        }

        rv = acvp_retrieve_expected_result(ctx, vsid_url);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Error retrieving expected results from server");
            goto end;
        }

        //If save_filename != null, we are saving to file, otherwise log it all
        if (save_filename) {
            fw_val = json_parse_string(ctx->curl_buf);
            if (!fw_val) {
                ACVP_LOG_ERR("Error parsing JSON from server response");
                rv = ACVP_TRANSPORT_FAIL;
                goto end;
            }
            /* append data */
            rv = acvp_json_serialize_to_file_pretty_a(fw_val, save_filename);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Error writing to file");
                goto end;
            }
            json_value_free(fw_val);
            fw_val = NULL;
        } else {
            printf("%s,\n", ctx->curl_buf);
        }
        vsid_url = NULL;
    }
    //append the final ']'
    rv = acvp_json_serialize_to_file_pretty_a(NULL, save_filename);
    ACVP_LOG_STATUS("Completed output of expected results.");
end:
   if (fw_val) json_value_free(fw_val);
   if (val) json_value_free(val);
   return rv;
}

/**
 * Allows application to continue a previous test session by checking which KAT responses the server is missing
 */
ACVP_RESULT acvp_resume_test_session(ACVP_CTX *ctx, const char *request_filename, int fips_validation) {
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;
    
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    
    ACVP_LOG_STATUS("Resuming session...");
    if (ctx->vector_req) {
        ACVP_LOG_STATUS("Restarting download of vector sets to file...");
    }

    rv = acvp_parse_session_info_file(ctx, request_filename);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to parse session info file to resume session");
        goto end;
    }

    rv = acvp_refresh(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to refresh login with ACVP server");
        goto end;
    }

    rv = acvp_retrieve_vector_set_result(ctx, ctx->session_url);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Error retrieving vector set results!");
        goto end;
    }

    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        ACVP_LOG_ERR("Error while parsing json from server!");
        rv = ACVP_JSON_ERR;
        goto end;
    }
    obj = acvp_get_obj_from_rsp(ctx, val);
    if (!obj) {
        ACVP_LOG_ERR("Error while parsing json from server!");
        rv = ACVP_JSON_ERR;
        goto end;
    }

    if (fips_validation) {
        rv = acvp_verify_fips_validation_metadata(ctx);
        if (ACVP_SUCCESS != rv) {
            ACVP_LOG_ERR("Validation metadata not ready");
            return ACVP_UNSUPPORTED_OP;
        }

        ctx->fips.do_validation = 1; /* Enable */
    } else {
        ctx->fips.do_validation = 0; /* Disable */
    }
    /*
     * Check for vector sets the server received no response to
     */

    JSON_Array *results = NULL;
    int count = 0, i = 0;

    results = json_object_get_array(obj, "results");
    if (!results) {
        ACVP_LOG_ERR("Error parsing status from server");
        rv = ACVP_JSON_ERR;
        goto end;
    }
    
    count = (int)json_array_get_count(results);
    JSON_Object *current = NULL;
    const char *vsid_url = NULL, *status = NULL;
    
    for (i = 0; i < count; i++) {
        int diff = 1;
        current = json_array_get_object(results, i);
        if (!current) {
            ACVP_LOG_ERR("Error parsing status from server");
            rv = ACVP_JSON_ERR;
            goto end;
        }
        
        status = json_object_get_string(current, "status");
        if (!status) {
            ACVP_LOG_ERR("Error parsing status from server");
            rv = ACVP_JSON_ERR;
            goto end;
        }
        vsid_url = json_object_get_string(current, "vectorSetUrl");
        if (!vsid_url) {
            ACVP_LOG_ERR("Error parsing status from server");
            rv = ACVP_JSON_ERR;
            goto end;
        }
        
        if (ctx->vector_req) {
            //If we are just saving to file, we don't need to check status, download all VS
            rv = acvp_append_vsid_url(ctx, vsid_url);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Error resuming session");
                goto end;
            }
        } else {
            strcmp_s("expired", 7, status, &diff);
            if (!diff) {
                ACVP_LOG_ERR("One or more vector sets has expired! Start a new session.");
                rv = ACVP_INVALID_ARG;
                goto end;
            }
            
            /*
             * If the result is unreceived, add it to the list of vsID urls
             */
            strcmp_s("unreceived", 10, status, &diff);
            if (!diff) {
                rv = acvp_append_vsid_url(ctx, vsid_url);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("Error resuming session");
                    goto end;
                }
            }
        }
    }

    if (!ctx->vsid_url_list) {
        ACVP_LOG_STATUS("All vector set results already uploaded. Nothing to resume.");
        goto end;
    } else {
        rv = acvp_process_tests(ctx);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to process vectors");
            goto end;
        }
        if (ctx->vector_req) {
            ACVP_LOG_STATUS("Successfully downloaded vector sets and saved to specified file.");
            return ACVP_SUCCESS;
        }

        /*
         * Check the test results.
         */
        ACVP_LOG_STATUS("Tests complete, checking results...");
        rv = acvp_check_test_results(ctx);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to retrieve test results");
            goto end;
        }

        if (fips_validation) {
            /*
             * Tell the server to provision a FIPS certificate for this testSession.
             */
            rv = acvp_validate_test_session(ctx);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Failed to perform Validation of testSession");
                goto end;
            }
        }

        if (ctx->put) {
           rv = acvp_put_data_from_ctx(ctx);
        }
    }
end:
    if (val) json_value_free(val);
    return rv;
}

/**
 * Allows application (with proper authentication) to connect to server and request
 * it cancel the session, halting processing and deleting related data
 */
ACVP_RESULT acvp_cancel_test_session(ACVP_CTX *ctx, const char *request_filename, const char *save_filename) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *val = NULL;
    int len = 0;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (save_filename) {
        len = strnlen_s(save_filename, ACVP_JSON_FILENAME_MAX + 1);
        if (len > ACVP_JSON_FILENAME_MAX || len <= 0) {
            ACVP_LOG_ERR("Provided save filename too long or too short");
            rv = ACVP_INVALID_ARG;
            goto end;
        }
    }

    rv = acvp_parse_session_info_file(ctx, request_filename);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Error reading session info file, unable to cancel session");
        goto end;
    }

    rv = acvp_refresh(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to refresh login with ACVP server");
        goto end;
    }

    rv = acvp_transport_delete(ctx, ctx->session_url);

    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to cancel test session");
        goto end;
    }
    if (save_filename) {
        ACVP_LOG_STATUS("Saving cancel request response to specified file...");
        val = json_parse_string(ctx->curl_buf);
        if (!val) {
            ACVP_LOG_ERR("Unable to parse JSON. printing output instead...");
        } else {
            rv = acvp_json_serialize_to_file_pretty_w(val, save_filename);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Failed to write file, printing instead...");
            } else {
                rv = acvp_json_serialize_to_file_pretty_a(NULL, save_filename);
                if (rv != ACVP_SUCCESS)
                    ACVP_LOG_WARN("Unable to append ending ] to write file");
                goto end;
            }
        }
    }
    ACVP_LOG_STATUS("DELETE Response:\n\n%s\n", ctx->curl_buf);

end:
    if (val) json_value_free(val);
    return rv;
}

/*
 * Allows application to set JSON filename within context
 * to be read in during registration
 */
ACVP_RESULT acvp_set_json_filename(ACVP_CTX *ctx, const char *json_filename) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!json_filename) {
        ACVP_LOG_ERR("Must provide value for JSON filename");
        return ACVP_MISSING_ARG;
    }
    if (!ctx->vector_req) {
        ACVP_LOG_ERR("The session must be request only to use a manual registraion");
        return ACVP_UNSUPPORTED_OP;
    }

    if (ctx->json_filename) { free(ctx->json_filename); }

    if (strnlen_s(json_filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided json_filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    ctx->json_filename = calloc(ACVP_JSON_FILENAME_MAX + 1, sizeof(char));
    if (!ctx->json_filename) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->json_filename, ACVP_JSON_FILENAME_MAX + 1, json_filename);

    ctx->use_json = 1;

    return ACVP_SUCCESS;
}

/*
 * This function is used by the application to specify the
 * ACVP server address and TCP port#.
 */
ACVP_RESULT acvp_set_server(ACVP_CTX *ctx, const char *server_name, int port) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!server_name || port < 1) {
        return ACVP_INVALID_ARG;
    }
    if (strnlen_s(server_name, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
        ACVP_LOG_ERR("Server name string(s) too long");
        return ACVP_INVALID_ARG;
    }
    if (ctx->server_name) {
        free(ctx->server_name);
    }
    ctx->server_name = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->server_name) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->server_name, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, server_name);

    ctx->server_port = port;

    if (!ctx->http_user_agent) {
        //generate user-agent string to send with HTTP requests
        acvp_http_user_agent_handler(ctx);
    }

    return ACVP_SUCCESS;
}

/*
 * This function is used by the application to specify the
 * ACVP server URI path segment prefix.
 */
ACVP_RESULT acvp_set_path_segment(ACVP_CTX *ctx, const char *path_segment) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!path_segment) {
        return ACVP_INVALID_ARG;
    }
    if (strnlen_s(path_segment, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
        ACVP_LOG_ERR("Path segment string(s) too long");
        return ACVP_INVALID_ARG;
    }
    if (ctx->path_segment) { free(ctx->path_segment); }
    ctx->path_segment = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->path_segment) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->path_segment, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, path_segment);

    return ACVP_SUCCESS;
}

/*
 * This function is used by the application to specify the
 * ACVP server URI path segment prefix.
 */
ACVP_RESULT acvp_set_api_context(ACVP_CTX *ctx, const char *api_context) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!api_context) {
        return ACVP_INVALID_ARG;
    }
    if (strnlen_s(api_context, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
        ACVP_LOG_ERR("API context string(s) too long");
        return ACVP_INVALID_ARG;
    }
    if (ctx->api_context) { free(ctx->api_context); }
    ctx->api_context = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->api_context) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->api_context, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, api_context);

    return ACVP_SUCCESS;
}

/*
 * This function allows the client to specify the location of the
 * PEM encoded CA certificates that will be used by Curl to verify
 * the ACVP server during the TLS handshake.  If this function is
 * not called by the application, then peer verification is not
 * enabled, which is not recommended (but provided as an operational
 * mode for testing).
 */
ACVP_RESULT acvp_set_cacerts(ACVP_CTX *ctx, const char *ca_file) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!ca_file) {
        return ACVP_MISSING_ARG;
    }

    if (strnlen_s(ca_file, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
        ACVP_LOG_ERR("CA filename is suspiciously long...");
        return ACVP_INVALID_ARG;
    }

    if (ctx->cacerts_file) { free(ctx->cacerts_file); }
    ctx->cacerts_file = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->cacerts_file) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->cacerts_file, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, ca_file);

    return ACVP_SUCCESS;
}

/*
 * This function is used to set the X509 certificate and private
 * key that will be used by libacvp during the TLS handshake to
 * identify itself to the server.  Some servers require TLS client
 * authentication, others do not.  This function is optional and
 * should only be used when the ACVP server supports TLS client
 * authentication.
 */
ACVP_RESULT acvp_set_certkey(ACVP_CTX *ctx, char *cert_file, char *key_file) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!cert_file || !key_file) {
        return ACVP_MISSING_ARG;
    }
    if (strnlen_s(cert_file, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX ||
        strnlen_s(key_file, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
        ACVP_LOG_ERR("CA filename is suspiciously long...");
        return ACVP_INVALID_ARG;
    }
    if (ctx->tls_cert) { free(ctx->tls_cert); }
    ctx->tls_cert = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->tls_cert) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->tls_cert, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, cert_file);

    if (ctx->tls_key) { free(ctx->tls_key); }
    ctx->tls_key = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->tls_key) {
        free(ctx->tls_cert);
        ctx->tls_cert = NULL;
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->tls_key, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, key_file);

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_mark_as_sample(ACVP_CTX *ctx) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    ctx->is_sample = 1;
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_mark_as_request_only(ACVP_CTX *ctx, char *filename) {
    if (!ctx) {
        return ACVP_NO_CTX;
    } 
    if (!filename) {
        return ACVP_MISSING_ARG;
    }
    if (strnlen_s(filename, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
         ACVP_LOG_ERR("Vector filename is suspiciously long...");
        return ACVP_INVALID_ARG;
    }

    if (ctx->vector_req_file) { free(ctx->vector_req_file); }
    ctx->vector_req_file = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->vector_req_file) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->vector_req_file, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, filename);
    ctx->vector_req = 1;
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_mark_as_get_only(ACVP_CTX *ctx, char *string) {
    if (!ctx) {
        return ACVP_NO_CTX;
    } 
    if (!string) {
        return ACVP_MISSING_ARG;
    }
    if (strnlen_s(string, ACVP_REQUEST_STR_LEN_MAX + 1) > ACVP_REQUEST_STR_LEN_MAX) {
         ACVP_LOG_ERR("Request string is suspiciously long...");
        return ACVP_INVALID_ARG;
    }

    if (ctx->get_string) { free(ctx->get_string); }
    ctx->get_string = calloc(ACVP_REQUEST_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->get_string) {
        return ACVP_MALLOC_FAIL;
    }

    strcpy_s(ctx->get_string, ACVP_REQUEST_STR_LEN_MAX + 1, string);
    ctx->get = 1;
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_set_get_save_file(ACVP_CTX *ctx, char *filename) {
    if (!ctx) {
        ACVP_LOG_ERR("No CTX given");
        return ACVP_NO_CTX;
    } 
    if (!filename) {
        ACVP_LOG_ERR("No filename given");
        return ACVP_MISSING_ARG;
    }
    if (!ctx->get) {
        ACVP_LOG_ERR("Session must be marked as get only to set a get save file");
        return ACVP_UNSUPPORTED_OP;
    }
    int filenameLen = 0;
    filenameLen = strnlen_s(filename, ACVP_JSON_FILENAME_MAX + 1);
    if (filenameLen > ACVP_JSON_FILENAME_MAX || filenameLen <= 0) {
        ACVP_LOG_ERR("Provided filename invalid");
        return ACVP_INVALID_ARG;
    }
    if (ctx->save_filename) { free(ctx->save_filename); }
    ctx->save_filename = calloc(filenameLen + 1, sizeof(char));
    if (!ctx->save_filename) {
        return ACVP_MALLOC_FAIL;
    }
    strncpy_s(ctx->save_filename, filenameLen + 1, filename, filenameLen);
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_mark_as_put_after_test(ACVP_CTX *ctx, char *filename) {
    if (!ctx) {
        return ACVP_NO_CTX;
    } 
    if (!filename) {
        return ACVP_MISSING_ARG;
    }
    if (strnlen_s(filename, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
         ACVP_LOG_ERR("Vector filename is suspiciously long...");
        return ACVP_INVALID_ARG;
    }

    if (ctx->put_filename) { free(ctx->put_filename); }
    ctx->put_filename = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->put_filename) {
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->put_filename, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, filename);
    ctx->put = 1;
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_mark_as_post_only(ACVP_CTX *ctx, char *filename) {

    if (!ctx) {
        return ACVP_NO_CTX;
    } 
    if (!filename) {
        return ACVP_MISSING_ARG;
    }
    if (strnlen_s(filename, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1) > ACVP_SESSION_PARAMS_STR_LEN_MAX) {
         ACVP_LOG_ERR("Request filename is suspiciously long...");
        return ACVP_INVALID_ARG;
    }

    if (ctx->post_filename) { free(ctx->post_filename); }
    ctx->post_filename = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->post_filename) {
        return ACVP_MALLOC_FAIL;
    }

    strcpy_s(ctx->post_filename, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, filename);
    ctx->post = 1;
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_mark_as_delete_only(ACVP_CTX *ctx, char *request_url) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!request_url) {
        return ACVP_MISSING_ARG;
    }
    int requestLen = strnlen_s(request_url, ACVP_REQUEST_STR_LEN_MAX + 1);
    if (requestLen > ACVP_REQUEST_STR_LEN_MAX || requestLen <= 0) {
        ACVP_LOG_ERR("Request URL is too long or too short");
        return ACVP_INVALID_ARG;
    }

    ctx->delete_string = calloc(ACVP_REQUEST_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->delete_string) {
        return ACVP_MALLOC_FAIL;
    }

    strcpy_s(ctx->delete_string, ACVP_REQUEST_STR_LEN_MAX + 1, request_url);
    ctx->delete = 1;
    return ACVP_SUCCESS;
}

/*
 * This function builds the JSON login message that
 * will be sent to the ACVP server. If enabled,
 * it will perform the second of the two-factor
 * authentications using a TOTP.
 */
static ACVP_RESULT acvp_build_login(ACVP_CTX *ctx, char **login, int *login_len, int refresh) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *reg_arry_val = NULL;
    JSON_Value *ver_val = NULL;
    JSON_Object *ver_obj = NULL;
    JSON_Value *pw_val = NULL;
    JSON_Object *pw_obj = NULL;
    JSON_Array *reg_arry = NULL;
    char *token = NULL;

    if (!login_len) return ACVP_INVALID_ARG;

    /*
     * Start the login array
     */
    reg_arry_val = json_value_init_array();
    reg_arry = json_array((const JSON_Value *)reg_arry_val);

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
    json_array_append_value(reg_arry, ver_val);

    if (ctx->totp_cb || refresh) {
        pw_val = json_value_init_object();
        pw_obj = json_value_get_object(pw_val);
    }

    if (ctx->totp_cb) {
        token = calloc(ACVP_TOTP_TOKEN_MAX + 1, sizeof(char));
        if (!token) return ACVP_MALLOC_FAIL;

        ctx->totp_cb(&token, ACVP_TOTP_TOKEN_MAX);
        if (strnlen_s(token, ACVP_TOTP_TOKEN_MAX + 1) > ACVP_TOTP_TOKEN_MAX) {
            ACVP_LOG_ERR("totp cb generated a token that is too long");
            json_value_free(pw_val);
            rv = ACVP_INVALID_ARG;
            goto err;
        }
        json_object_set_string(pw_obj, "password", token);
    }

    if (refresh) {
        json_object_set_string(pw_obj, "accessToken", ctx->jwt_token);
    }
    if (pw_val) json_array_append_value(reg_arry, pw_val);

err:
    *login = json_serialize_to_string(reg_arry_val, login_len);
    if (token) free(token);
    if (reg_arry_val) json_value_free(reg_arry_val);
    return rv;
}

/*
 * This function is used to register the DUT with the server.
 * Registration allows the DUT to advertise it's capabilities to
 * the server.  The server will respond with a set of vector set
 * identifiers that the client will need to process.
 */
static ACVP_RESULT acvp_register(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *reg = NULL;
    int reg_len = 0;
    JSON_Value *tmp_json_from_file = NULL;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Send the capabilities to the ACVP server and get the response,
     * which should be a list of vector set ID urls
     */
    if (ctx->use_json) {
        ACVP_LOG_STATUS("Reading capabilities registration file...");
        tmp_json_from_file = json_parse_file(ctx->json_filename);
        if (!tmp_json_from_file) {
            ACVP_LOG_ERR("Error reading capabilities file");
            rv = ACVP_JSON_ERR;
            goto end;
        }
        reg = json_serialize_to_string_pretty(tmp_json_from_file, &reg_len);
        if (!reg) {
            ACVP_LOG_ERR("Error loading capabilities file");
            rv = ACVP_JSON_ERR;
            goto end;
        }
    } else {
        ACVP_LOG_STATUS("Building registration of capabilities...");
        rv = acvp_build_test_session(ctx, &reg, &reg_len);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to build register message");
            goto end;
        }
    }

    ACVP_LOG_STATUS("Sending registration of capabilities...");
    ACVP_LOG_INFO("%s", reg);
    rv = acvp_send_test_session_registration(ctx, reg, reg_len);
    if (rv == ACVP_SUCCESS) {
        rv = acvp_parse_test_session_register(ctx);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to parse test session response");
            goto end;
        }
        ACVP_LOG_STATUS("Successfully sent registration and received list of vector set URLs");
        ACVP_LOG_STATUS("Test session URL: %s", ctx->session_url);
    } else {
        ACVP_LOG_ERR("Failed to send registration");
    }

end:
    if (tmp_json_from_file) json_value_free(tmp_json_from_file);
    if (reg) json_free_serialized_string(reg);
    return rv;
}

/*
 * Append a VS identifier to the list of VS identifiers
 * that will need to be downloaded and processed later.
 */
static ACVP_RESULT acvp_append_vsid_url(ACVP_CTX *ctx, const char *vsid_url) {
    ACVP_STRING_LIST *vs_entry, *vs_e2;


    if (!ctx || !vsid_url) {
        return ACVP_MISSING_ARG;
    }
    vs_entry = calloc(1, sizeof(ACVP_STRING_LIST));
    if (!vs_entry) {
        return ACVP_MALLOC_FAIL;
    }
    vs_entry->string = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!vs_entry->string) {
        free(vs_entry);
        return ACVP_MALLOC_FAIL;
    }
    strcpy_s(vs_entry->string, ACVP_ATTR_URL_MAX + 1, vsid_url);

    if (!ctx->vsid_url_list) {
        ctx->vsid_url_list = vs_entry;
    } else {
        vs_e2 = ctx->vsid_url_list;
        while (vs_e2->next) {
            vs_e2 = vs_e2->next;
        }
        vs_e2->next = vs_entry;
    }
    return ACVP_SUCCESS;
}

/*
 * This routine performs the JSON parsing of the login response
 * from the ACVP server.  The response should contain an initial
 * jwt which will be used once during registration.
 */
static ACVP_RESULT acvp_parse_login(ACVP_CTX *ctx) {
    JSON_Value *val;
    JSON_Object *obj = NULL;
    char *json_buf = ctx->curl_buf;
    const char *jwt;
#ifdef ACVP_DEPRECATED
    int large_required = 0;
#endif
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Parse the JSON
     */
    val = json_parse_string(json_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }

    obj = acvp_get_obj_from_rsp(ctx, val);
#ifdef ACVP_DEPRECATED
    large_required = json_object_get_boolean(obj, "largeEndpointRequired");

    if (large_required) {
        /* Grab the large submission sizeConstraint */
        ctx->post_size_constraint = json_object_get_number(obj, "sizeConstraint");
    }
#endif
    /*
     * Get the JWT assigned to this session by the server.  This will need
     * to be included when sending the vector responses back to the server
     * later.
     */
    jwt = json_object_get_string(obj, "accessToken");
    if (!jwt) {
        ACVP_LOG_ERR("No access_token provided in registration response");
        rv = ACVP_NO_TOKEN;
        goto end;
    } else {
        if (strnlen_s(jwt, ACVP_JWT_TOKEN_MAX + 1) > ACVP_JWT_TOKEN_MAX) {
            ACVP_LOG_ERR("access_token too large");
            rv = ACVP_NO_TOKEN;
            goto end;
        }

        ctx->jwt_token = calloc(ACVP_JWT_TOKEN_MAX + 1, sizeof(char));
        strcpy_s(ctx->jwt_token, ACVP_JWT_TOKEN_MAX + 1, jwt);
    }
end:
    json_value_free(val);
    return rv;
}

static ACVP_RESULT acvp_parse_validation(ACVP_CTX *ctx) {
    JSON_Value *val = NULL, *ts_val = NULL, *new_ts = NULL;
    JSON_Object *obj = NULL, *ts_obj = NULL;
    JSON_Array *ts_arr = NULL;
    const char *url = NULL, *status = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Parse the JSON
     */
    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }

    obj = acvp_get_obj_from_rsp(ctx, val);

    /*
     * Get the url of the 'request' status sent by server.
     */
    url = json_object_get_string(obj, "url");
    if (!url) {
        ACVP_LOG_ERR("Validation response JSON missing 'url'");
        rv = ACVP_JSON_ERR;
        goto end;
    }

    status = json_object_get_string(obj, "status");
    if (!status) {
        ACVP_LOG_ERR("Validation response JSON missing 'status'");
        rv = ACVP_JSON_ERR;
        goto end;
    }

    /* Print the request info to screen */
    ACVP_LOG_STATUS("Validation requested -- status %s -- url: %s", status, url);
    /* save the request URL to the test session info file, if it is saved in the CTX. */
    if (ctx->session_file_path) {
        ts_val = json_parse_file(ctx->session_file_path);
        if (!ts_val) {
            ACVP_LOG_WARN("Failed to save request URL to test session file. Make sure you save it from output!");
            goto end;
        }
        ts_arr = json_value_get_array(ts_val);
        if (!ts_arr) {
            ACVP_LOG_WARN("Failed to save request URL to test session file. Make sure you save it from output!");
            goto end;
        }
        ts_obj = json_array_get_object(ts_arr, 0);
        if (!ts_obj) {
            ACVP_LOG_WARN("Failed to save request URL to test session file. Make sure you save it from output!");
            goto end;
        }
        //Sanity check the object to make sure its valid
        if (!json_object_get_string(ts_obj, "url")) {
            ACVP_LOG_WARN("Saved testSession file seems invalid. Make sure you save request URL from output!");
            goto end;
        }
        json_object_set_string(ts_obj, "validationRequestUrl", url);
        new_ts = json_object_get_wrapping_value(ts_obj);
        if (!new_ts) {
            ACVP_LOG_WARN("Failed to save request URL to test session file. Make sure you save it from output!");
            goto end;  
        }
        rv = acvp_json_serialize_to_file_pretty_w(new_ts, ctx->session_file_path);
        if (rv) {
            ACVP_LOG_WARN("Failed to save request URL to test session file. Make sure you save it from output!");
            goto end;
        } else {
            acvp_json_serialize_to_file_pretty_a(NULL, ctx->session_file_path);
        }
    }


end:
    if (val) json_value_free(val);
    if (ts_val) json_value_free(ts_val);
    return rv;
}

#ifdef ACVP_DEPRECATED
ACVP_RESULT acvp_notify_large(ACVP_CTX *ctx,
                              const char *url,
                              char *large_url,
                              unsigned int data_len) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *arr_val = NULL, *val = NULL,
               *ver_val = NULL, *server_val = NULL;
    JSON_Object *obj = NULL, *ver_obj = NULL, *server_obj = NULL;
    JSON_Array *arr = NULL;
    char *substr = NULL;
    char snipped_url[ACVP_ATTR_URL_MAX + 1] = {0} ;
    char *large_notify = NULL;
    const char *jwt = NULL;
    int notify_len = 0;
    const char *large_url_str = NULL;

    if (!url) return ACVP_MISSING_ARG;
    if (!large_url) return ACVP_MISSING_ARG;
    if (!(data_len > ctx->post_size_constraint)) return ACVP_INVALID_ARG;

    arr_val = json_value_init_array();
    arr = json_array((const JSON_Value *)arr_val);

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
    json_array_append_value(arr, ver_val);

    /*
     * Start the large/ array
     */
    val = json_value_init_object();
    obj = json_value_get_object(val);

    /* 
     * Cut off the https://name:port/ prefix and /results suffix
     */
    strstr_s((char *)url, ACVP_ATTR_URL_MAX, "/acvp/v1", 8, &substr);
    strcpy_s(snipped_url, ACVP_ATTR_URL_MAX, substr);
    strstr_s(snipped_url, ACVP_ATTR_URL_MAX, "/results", 8, &substr);
    if (!substr) {
        rv = ACVP_INVALID_ARG;
        goto err;
    }
    *substr = '\0';

    json_object_set_string(obj, "vectorSetUrl", snipped_url);
    json_object_set_number(obj, "submissionSize", data_len);
    
    json_array_append_value(arr, val);

    large_notify = json_serialize_to_string(arr_val, &notify_len);

    ACVP_LOG_ERR("Notifying /large endpoint for this submission... %s", large_notify);
    rv = acvp_transport_post(ctx, "large", large_notify, notify_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to notify /large endpoint");
        goto err;
    }

    server_val = json_parse_string(ctx->curl_buf);
    if (!server_val) {
        ACVP_LOG_ERR("JSON parse error");
        rv = ACVP_JSON_ERR;
        goto err;
    }
    server_obj = acvp_get_obj_from_rsp(ctx, server_val);

    if (!server_obj) {
        ACVP_LOG_ERR("JSON parse error no server object");
        rv = ACVP_JSON_ERR;
        goto err;
    }

    /* Grab the full large/ endpoint URL */
    large_url_str = json_object_get_string(server_obj, "url");
    if (!large_url_str) {
        ACVP_LOG_ERR("JSON parse error no large URL object");
        rv = ACVP_JSON_ERR;
        goto err;
    }

    strcpy_s(large_url, ACVP_ATTR_URL_MAX, large_url_str);

    jwt = json_object_get_string(server_obj, "accessToken");
    if (jwt) {
        /*
         * A single-use JWT was given.
         */
        if (strnlen_s(jwt, ACVP_JWT_TOKEN_MAX + 1) > ACVP_JWT_TOKEN_MAX) {
            ACVP_LOG_ERR("access_token too large");
            rv = ACVP_NO_TOKEN;
            goto err;
        }

        if (ctx->tmp_jwt) {
            memzero_s(ctx->tmp_jwt, ACVP_JWT_TOKEN_MAX);
        } else {
            ctx->tmp_jwt = calloc(ACVP_JWT_TOKEN_MAX + 1, sizeof(char));
        }
        strcpy_s(ctx->tmp_jwt, ACVP_JWT_TOKEN_MAX + 1, jwt);

        ctx->use_tmp_jwt = 1;
    }

err:
    if (arr_val) json_value_free(arr_val);
    if (server_val) json_value_free(server_val);
    if (large_notify) json_free_serialized_string(large_notify);
    return rv;
}
#endif

/*
 * This routine performs the JSON parsing of the test session registration
 * from the server. It should contain a list of URLs for vector sets that
 * can be queried to get the test parameters.
 */
static ACVP_RESULT acvp_parse_test_session_register(ACVP_CTX *ctx) {
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    JSON_Array *vect_sets = NULL;
    const char *test_session_url = NULL, *access_token = NULL;
    int i = 0, vs_cnt = 0;
    ACVP_RESULT rv = 0;

    /*
     * Parse the JSON
     */
    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }
    obj = acvp_get_obj_from_rsp(ctx, val);

    /*
     * This is the identifiers provided by the server
     * for this specific test session!
     */
    test_session_url = json_object_get_string(obj, "url");
    if (!test_session_url) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }

    ctx->session_url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
    strcpy_s(ctx->session_url, ACVP_ATTR_URL_MAX + 1, test_session_url);

    /*
     * The accessToken needed for this specific test session.
     */
    access_token = json_object_get_string(obj, "accessToken");
    if (!access_token) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }
    if (strnlen_s(access_token, ACVP_JWT_TOKEN_MAX + 1) > ACVP_JWT_TOKEN_MAX) {
        ACVP_LOG_ERR("access_token too large");
        return ACVP_NO_TOKEN;
    }
    memzero_s(ctx->jwt_token, ACVP_JWT_TOKEN_MAX + 1);
    strcpy_s(ctx->jwt_token, ACVP_JWT_TOKEN_MAX + 1, access_token);

    /*
     * Identify the VS identifiers provided by the server, save them for
     * processing later.
     */
    vect_sets = json_object_get_array(obj, "vectorSetUrls");
    vs_cnt = json_array_get_count(vect_sets);
    for (i = 0; i < vs_cnt; i++) {
        const char *vsid_url = json_array_get_string(vect_sets, i);

        if (!vsid_url) {
            ACVP_LOG_ERR("No vsid_url");
            goto end;
        }

        rv = acvp_append_vsid_url(ctx, vsid_url);
        if (rv != ACVP_SUCCESS) goto end;
        ACVP_LOG_INFO("Received vsid_url=%s", vsid_url);
    }

end:
    if (val) json_value_free(val);
    return rv;
}

/**
 * Loads all of the data we need to process or view test session information
 * from the given file. used for non-continuous sessions.
 */
static ACVP_RESULT acvp_parse_session_info_file(ACVP_CTX *ctx, const char *filename) {
    JSON_Value *val = NULL;
    JSON_Array *reg_array;
    JSON_Object *obj = NULL;
    const char *test_session_url = NULL;
    const char *jwt = NULL;
    int isSample = 0;
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!filename) {
        ACVP_LOG_ERR("Must provide value for JSON filename");
        return ACVP_MISSING_ARG;
    }
    
    if (strnlen_s(filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }
    
    val = json_parse_file(filename);
    if (!val) {
        ACVP_LOG_ERR("JSON val parse error");
        return ACVP_MALFORMED_JSON;
    }
    reg_array = json_value_get_array(val);
    obj = json_array_get_object(reg_array, 0);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        rv = ACVP_MALFORMED_JSON;
        goto end;
    }

    test_session_url = json_object_get_string(obj, "url");
    if (!test_session_url) {
        ACVP_LOG_ERR("Missing session URL");
        rv = ACVP_MALFORMED_JSON;
        goto end;
    }

    ctx->session_url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!ctx->session_url) {
        rv = ACVP_MALLOC_FAIL;
        goto end;
    }
    strcpy_s(ctx->session_url, ACVP_ATTR_URL_MAX + 1, test_session_url);

    jwt = json_object_get_string(obj, "jwt");
    if (!jwt) {
        rv = ACVP_MALFORMED_JSON;
        goto end;
    }
    ctx->jwt_token = calloc(ACVP_JWT_TOKEN_MAX + 1, sizeof(char));
    if (!ctx->jwt_token) {
        rv = ACVP_MALLOC_FAIL;
        goto end;
    }
    strcpy_s(ctx->jwt_token, ACVP_JWT_TOKEN_MAX + 1, jwt);

    isSample = json_object_get_boolean(obj, "isSample");
    if (json_object_has_value(obj, "isSample")) {
        ctx->is_sample = isSample;
    } else {
        ACVP_LOG_WARN("Missing indication of whether tests are sample in file, continuing");
    }

end:
    if (val) json_value_free(val);
    return rv;
}

/*
 * This function is used by the application after registration
 * to commence the testing.  All the testing will be handled
 * by libacvp.  This function will block the caller.  Therefore,
 * it should be run on a separate thread if needed.
 */
ACVP_RESULT acvp_process_tests(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_STRING_LIST *vs_entry = NULL;
    int count = 0;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Iterate through the VS identifiers the server sent to us
     * in the test session register response.  Process each vector set and
     * return the results to the server.
     */
    vs_entry = ctx->vsid_url_list;
    if (!vs_entry) {
        return ACVP_MISSING_ARG;
    }
    while (vs_entry) {
        rv = acvp_process_vsid(ctx, vs_entry->string, count);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to process vector set! Error: %d", rv);
            return rv;
        }
        vs_entry = vs_entry->next;
        count++;
    }
    /* Need to add the ending ']' here */
    if (ctx->vector_req) {
        rv = acvp_json_serialize_to_file_pretty_a(NULL, ctx->vector_req_file);
    }
    return rv;
}

/*
 * This is a retry handler, which pauses for a specific time.
 * This allows the server time to generate the vectors on behalf of
 * the client and to process the vector responses. The caller of this function
 * can choose to implement a retry backoff using 'modifier'. Additionally, this
 * function will ensure that retry periods will sum to no longer than ACVP_MAX_WAIT_TIME.
 */
static ACVP_RESULT acvp_retry_handler(ACVP_CTX *ctx, int *retry_period, unsigned int *waited_so_far, int modifier, ACVP_WAITING_STATUS situation) {
    /* perform check at beginning of function call, so library can check one more time when max
     * time is reached to see if server status has changed */
    if (*waited_so_far >= ACVP_MAX_WAIT_TIME) {
        return ACVP_TRANSPORT_FAIL;
    }
    
    if (*waited_so_far + *retry_period > ACVP_MAX_WAIT_TIME) {
        *retry_period = ACVP_MAX_WAIT_TIME - *waited_so_far;
    }
    if (*retry_period <= ACVP_RETRY_TIME_MIN || *retry_period > ACVP_RETRY_TIME_MAX) {
        *retry_period = ACVP_RETRY_TIME_MAX;
        ACVP_LOG_WARN("retry_period not found, using max retry period!");
    }
    if (situation == ACVP_WAITING_FOR_TESTS) {
        ACVP_LOG_STATUS("200 OK KAT values not ready, server requests we wait %u seconds and try again...", *retry_period);
    } else if (situation == ACVP_WAITING_FOR_RESULTS) {
        ACVP_LOG_STATUS("200 OK results not ready, waiting %u seconds and trying again...", *retry_period);
    } else {
        ACVP_LOG_STATUS("200 OK, waiting %u seconds and trying again...", *retry_period);
    }

    #ifdef _WIN32
    /*
     * Windows uses milliseconds
     */
    Sleep(*retry_period * 1000);
    #else
    sleep(*retry_period);
    #endif

    /* ensure that all parameters are valid and that we do not wait longer than ACVP_MAX_WAIT_TIME */
    if (modifier < 1 || modifier > ACVP_RETRY_MODIFIER_MAX) {
        ACVP_LOG_WARN("retry modifier not valid, defaulting to 1 (no change)");
        modifier = 1;
    }
    if ((*retry_period *= modifier) > ACVP_RETRY_TIME_MAX) {
        *retry_period = ACVP_RETRY_TIME_MAX;
    }

    *waited_so_far += *retry_period;

    return ACVP_KAT_DOWNLOAD_RETRY;
}

/*
 * This routine will iterate through all the vector sets, requesting
 * the test result from the server for each set.
 */
ACVP_RESULT acvp_check_test_results(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    rv = acvp_get_result_test_session(ctx, ctx->session_url);
    return rv;
}

/***************************************************************************************************************
* Begin vector processing logic
***************************************************************************************************************/

static ACVP_RESULT acvp_login(ACVP_CTX *ctx, int refresh) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *login = NULL;
    int login_len = 0;

    ACVP_LOG_STATUS("Logging in...");
    rv = acvp_build_login(ctx, &login, &login_len, refresh);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to build login message");
        goto end;
    }

    /*
     * Send the login to the ACVP server and get the response,
     */
    rv = acvp_send_login(ctx, login, login_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_STATUS("Login Send Failed");
        goto end;
    }

    rv = acvp_parse_login(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_STATUS("Login Response Failed, %d", rv);
    } else {
        ACVP_LOG_STATUS("Login successful");
    }
end:
    if (login) free(login);
    return rv;
}

ACVP_RESULT acvp_refresh(ACVP_CTX *ctx) {
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    return acvp_login(ctx, 1);
}


/*
 * This function will process a single KAT vector set.  Each KAT
 * vector set has an identifier associated with it, called
 * the vs_id.  During registration, libacvp will receive the
 * list of vs_id's that need to be processed during the test
 * session.  This routine will execute the test flow for a single
 * vs_id.  The flow is:
 *    a) Download the KAT vector set from the server using the vs_id
 *    b) Parse the KAT vectors
 *    c) Process each test case in the KAT vector set
 *    d) Generate the response data
 *    e) Send the response data back to the ACVP server
 */
static ACVP_RESULT acvp_process_vsid(ACVP_CTX *ctx, char *vsid_url, int count) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *val = NULL;
    JSON_Value *alg_val = NULL;
    JSON_Array *alg_array = NULL;
    JSON_Array *url_arr = NULL;
    JSON_Value *ts_val = NULL;
    JSON_Object *ts_obj = NULL;
    JSON_Object *obj = NULL;
    ACVP_STRING_LIST *vs_entry = NULL;
    int retry_period = 0;
    int retry = 1;
    unsigned int time_waited_so_far = 0;
    while (retry) {
        /*
         * Get the KAT vector set
         */
        rv = acvp_retrieve_vector_set(ctx, vsid_url);
        if (rv != ACVP_SUCCESS) goto end;

        val = json_parse_string(ctx->curl_buf);
        if (!val) {
            ACVP_LOG_ERR("JSON parse error");
            rv = ACVP_JSON_ERR;
            goto end;
        }
        obj = acvp_get_obj_from_rsp(ctx, val);

        /*
         * Check if we received a retry response
         */
        retry_period = json_object_get_number(obj, "retry");
        if (retry_period) {
            /*
             * Wait and try again to retrieve the VectorSet
             */
            if (acvp_retry_handler(ctx, &retry_period, &time_waited_so_far, 1, ACVP_WAITING_FOR_TESTS) != ACVP_KAT_DOWNLOAD_RETRY) {
                ACVP_LOG_STATUS("Maximum wait time with server reached! (Max: %d seconds)", ACVP_MAX_WAIT_TIME);
                rv = ACVP_TRANSPORT_FAIL;
                goto end;
            };
            retry = 1;
        } else {
            /*
             * Save the KAT VectorSet to file
             */
            if (ctx->vector_req) {
                
                ACVP_LOG_STATUS("Saving vector set %s to file...", vsid_url);
                alg_array = json_value_get_array(val);
                alg_val = json_array_get_value(alg_array, 1);

                /* track first vector set with file count */
                if (count == 0) {
                    ts_val = json_value_init_object();
                    ts_obj = json_value_get_object(ts_val);

                    json_object_set_string(ts_obj, "jwt", ctx->jwt_token);
                    json_object_set_string(ts_obj, "url", ctx->session_url);
                    json_object_set_boolean(ts_obj, "isSample", ctx->is_sample);

                    json_object_set_value(ts_obj, "vectorSetUrls", json_value_init_array());
                    url_arr = json_object_get_array(ts_obj, "vectorSetUrls");

                    vs_entry = ctx->vsid_url_list;
                    while (vs_entry) {
                        json_array_append_string(url_arr, vs_entry->string);
                        vs_entry = vs_entry->next;
                    }
                    /* Start with identifiers */
                    rv = acvp_json_serialize_to_file_pretty_w(ts_val, ctx->vector_req_file);
                    if (rv != ACVP_SUCCESS) {
                        ACVP_LOG_ERR("File write error");
                        json_value_free(ts_val);
                        goto end;
                    }
                } 
                /* append vector set */
                rv = acvp_json_serialize_to_file_pretty_a(alg_val, ctx->vector_req_file);
                json_value_free(ts_val);
                goto end;
            }
            /*
             * Process the KAT VectorSet
             */
            rv = acvp_process_vector_set(ctx, obj);
            json_value_free(ts_val);
            retry = 0;
        }

        if (rv != ACVP_SUCCESS) goto end;
        json_value_free(val);
        val = NULL;
    }

    /*
     * Send the responses to the ACVP server
     */
    ACVP_LOG_STATUS("Posting vector set responses for vsId %d...", ctx->vs_id);
    rv = acvp_submit_vector_responses(ctx, vsid_url);

end:
    if (val) json_value_free(val);
    return rv;
}

/*
 * This function is used to invoke the appropriate handler function
 * for a given ACV operation.  The operation is specified in the
 * KAT vector set that was previously downloaded.  The handler function
 * is looked up in the alg_tbl[] and invoked here.
 */
static ACVP_RESULT acvp_dispatch_vector_set(ACVP_CTX *ctx, JSON_Object *obj) {
    int i;
    const char *alg = json_object_get_string(obj, "algorithm");
    const char *mode = json_object_get_string(obj, "mode");
    int vs_id = json_object_get_number(obj, "vsId");
    int diff = 1;

    ctx->vs_id = vs_id;
    ACVP_RESULT rv;

    if (!alg) {
        ACVP_LOG_ERR("JSON parse error: ACV algorithm not found");
        return ACVP_JSON_ERR;
    }

    ACVP_LOG_STATUS("Processing vector set: %d", vs_id);
    ACVP_LOG_STATUS("Algorithm: %s", alg);
    if (mode) {
        ACVP_LOG_STATUS("Mode: %s", mode);
    }
    for (i = 0; i < ACVP_ALG_MAX; i++) {
        strcmp_s(alg_tbl[i].name,
                 ACVP_ALG_NAME_MAX,
                 alg, &diff);
        if (!diff) {
            if (mode == NULL) {
                rv = (alg_tbl[i].handler)(ctx, obj);
                return rv;
            }

            if (alg_tbl[i].mode != NULL) {
                strcmp_s(alg_tbl[i].mode,
                        ACVP_ALG_MODE_MAX,
                        mode, &diff);
                if (!diff) {
                    rv = (alg_tbl[i].handler)(ctx, obj);
                    return rv;
                }
            }
        }
    }
    return ACVP_UNSUPPORTED_OP;
}

/*
 * This function is used to process the test cases for
 * a given KAT vector set.  This is invoked after the
 * KAT vector set has been downloaded from the server.  The
 * vectors are stored on the ACVP_CTX in one of the
 * transitory fields.  Therefore, the vs_id isn't needed
 * here to know which vectors need to be processed.
 *
 * The processing logic is:
 *    a) JSON parse the data
 *    b) Identify the ACVP operation to be performed (e.g. AES encrypt)
 *    c) Dispatch the vectors to the handler for the
 *       specified ACVP operation.
 */
static ACVP_RESULT acvp_process_vector_set(ACVP_CTX *ctx, JSON_Object *obj) {
    ACVP_RESULT rv;

    rv = acvp_dispatch_vector_set(ctx, obj);
    if (rv != ACVP_SUCCESS) {
        return rv;
    }

    ACVP_LOG_STATUS("Successfully processed vector set");
    return ACVP_SUCCESS;
}

/*
 * This function will get the test results for a test session by checking the results of each vector set
 */
static ACVP_RESULT acvp_get_result_test_session(ACVP_CTX *ctx, char *session_url) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *val = NULL;
    JSON_Value *val2 = NULL;
    JSON_Object *obj = NULL;
    JSON_Object *obj2 = NULL;
    int count = 0, i = 0, passed = 0;
    JSON_Array *results = NULL;
    JSON_Object *current = NULL;
    const char *status = NULL;

    unsigned int time_waited_so_far = 0;
    int retry_interval = ACVP_RETRY_TIME;
    //Maintains a list of names of algorithms that have failed
    ACVP_STRING_LIST *failedAlgList = NULL;
    /*
     * Maintains a list of the vector set URLs we have already looked up,
     * so we don't redownload failed vector sets every time a retry is done
     */
     ACVP_STRING_LIST *failedVsList = NULL;

    while (1) {
        int testsCompleted = 0;

        /*
         * Get the KAT vector set
         */
        rv = acvp_retrieve_vector_set_result(ctx, session_url);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Error retrieving vector set results!");
            goto end;
        }

        val = json_parse_string(ctx->curl_buf);
        if (!val) {
            ACVP_LOG_ERR("Error while parsing json from server!");
            rv = ACVP_JSON_ERR;
            goto end;
        }
        obj = acvp_get_obj_from_rsp(ctx, val);
        if (!obj) {
            ACVP_LOG_ERR("Error while parsing json from server!");
            rv = ACVP_JSON_ERR;
            goto end;
        }

        /*
         * Check the results for each vector set - flag if some are incomplete,
         * or name failed algorithms (even if others are still incomplete)
         */
        results = json_object_get_array(obj, "results");
        count = (int)json_array_get_count(results);
        for (i = 0; i < count; i++) {
            int diff = 1;
            current = json_array_get_object(results, i);
            status = json_object_get_string(current, "status");
            if (!status) {
                goto end;
            }
            strcmp_s("expired", 7, status, &diff);
            if (!diff) {
                ACVP_LOG_ERR("One or more vector sets expired before results were submitted. Please start a new test session.");
                goto end;
            }
            
            strcmp_s("unreceived", 10, status, &diff);
            if (!diff) {
                ACVP_LOG_ERR("Missing submissions for one or more vector sets. Please submit responses for all vector sets.");
                goto end;
            }
            /*
             * If the result is incomplete, set the flag so it keeps retrying
             */
            strcmp_s("incomplete", 10, status, &diff);
            if (!diff) {
                continue;
            }
            /*
             * If the result is fail, retrieve vector set, get algorithm name, add to list
             */
            strcmp_s("fail", 4, status, &diff);
            if (!diff) {
                const char *vsurl = json_object_get_string(current, "vectorSetUrl");
                if (!vsurl) {
                    ACVP_LOG_ERR("No vector set URL when generating failed algorithm list");
                    break;
                }
                if (!acvp_lookup_str_list(&failedVsList, vsurl)) {
                    //append the vsurl to the list so we dont download/check same one twice
                    rv = acvp_append_str_list(&failedVsList, vsurl);
                    if (rv != ACVP_SUCCESS) {
                        ACVP_LOG_ERR("Error appending failed algorithm name to list, skipping...");
                        continue;
                    }
                    //retrieve_vector_set expects a non-const string
                    char *vs_url = calloc(ACVP_REQUEST_STR_LEN_MAX + 1, sizeof(char));
                    if (!vs_url) {
                        ACVP_LOG_ERR("Unable to calloc when reporting failed algorithms, skipping...");
                        continue;                    
                    }
                    strncpy_s(vs_url, ACVP_REQUEST_STR_LEN_MAX + 1, vsurl, ACVP_REQUEST_STR_LEN_MAX);
                    rv = acvp_retrieve_vector_set(ctx, vs_url);
                    free(vs_url);
                    if (rv != ACVP_SUCCESS) {
                        ACVP_LOG_ERR("Unable to retrieve vector set while reporting failed algorithms, skipping...");
                        continue;
                    }

                    val2 = json_parse_string(ctx->curl_buf);
                    if (!val2) {
                        ACVP_LOG_ERR("JSON parse error while reporting failed algorithms, skipping...");
                        continue;
                    }
                    obj2 = acvp_get_obj_from_rsp(ctx, val2);
                    if (!obj2) {
                        json_value_free(val2);
                        ACVP_LOG_ERR("JSON parse error while reporting failed algorithms, skipping...");
                        continue;
                    }
                    const char *alg = json_object_get_string(obj2, "algorithm");
                    if (!alg) {
                        ACVP_LOG_ERR("JSON parse error while reporting failed algorithms, skipping...");
                        continue;
                    }
                    if (!acvp_lookup_str_list(&failedAlgList, alg)) {
                        rv = acvp_append_str_list(&failedAlgList, alg);
                        if (val2) json_value_free(val2);
                        val2 = NULL;
                        if (rv != ACVP_SUCCESS) {
                            ACVP_LOG_ERR("Error appending failed algorithm name to list, skipping...");
                            continue;
                        }
                    } else {
                        if (val2) json_value_free(val2);
                        val2 = NULL;
                    }
                }
            }
            testsCompleted++;
        }
        if (testsCompleted >= count) {
            passed = json_object_get_boolean(obj, "passed");
            if (passed == 1) {
                /*
                 * Pass, exit loop
                 */
                ACVP_LOG_STATUS("Passed all vectors in test session!");
                ctx->session_passed = 1;
                rv = ACVP_SUCCESS;
                goto end;
            } else {
                 /*
                  * Fail, continue with reporting results
                  */
                 ACVP_LOG_STATUS("Test session complete: some vectors failed, reporting results...");
                 ACVP_LOG_STATUS("Note: Use verbose-level logging to see results of each test case");
                 acvp_list_failing_algorithms(ctx, &failedAlgList);
             }
        } else {
              /*
             * If any tests are incomplete, retry, even if some have failed
             */
            acvp_list_failing_algorithms(ctx, &failedAlgList);
            ACVP_LOG_STATUS("TestSession results incomplete...");
            if (acvp_retry_handler(ctx, &retry_interval, &time_waited_so_far, 1, ACVP_WAITING_FOR_RESULTS) != ACVP_KAT_DOWNLOAD_RETRY) {
                ACVP_LOG_STATUS("Maximum wait time with server reached! (Max: %d seconds)", ACVP_MAX_WAIT_TIME);
                rv = ACVP_TRANSPORT_FAIL;
                goto end;
            }

            if (val) json_value_free(val);
            val = NULL;
            continue;
        }

        for (i = 0; i < count; i++) {
            int diff = 1;
            current = json_array_get_object(results, i);

            status = json_object_get_string(current, "status");
            if (!status) {
                goto end;
            }
            strcmp_s("fail", 4, status, &diff);
            if (diff)
                strcmp_s("error", 5, status, &diff);
            if (!diff) {
                const char *vs_url = json_object_get_string(current, "vectorSetUrl");
                if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
                    ACVP_LOG_STATUS("Getting details for failed Vector Set...");
                    rv = acvp_retrieve_vector_set_result(ctx, vs_url);
                    printf("\n%s\n", ctx->curl_buf);
                    if (rv != ACVP_SUCCESS) goto end;
                }
                /*
                 * Get the sample results if the user had requested them.
                 */
                if (ctx->is_sample) {
                    ACVP_LOG_STATUS("Getting expected results for failed Vector Set...");
                    rv = acvp_retrieve_expected_result(ctx, vs_url);
                    if (rv != ACVP_SUCCESS) {
                        ACVP_LOG_ERR("Expected results retrieval failed %d...", rv);
                        goto end;
                    }
                    /* always dump all of sample data */
                    printf("\n%s\n", ctx->curl_buf);
                }
            }
        }
        
        /* If we got here, the testSession failed, exit loop*/
        break;
    }

end:
    if (val) json_value_free(val);
    if (failedAlgList) {
        acvp_free_str_list(&failedAlgList);
    }
    if (failedVsList) {
        acvp_free_str_list(&failedVsList);
    }
    return rv;
}

static ACVP_RESULT acvp_validate_test_session(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *validation = NULL;
    int validation_len = 0;

    if (ctx == NULL) return ACVP_NO_CTX;

    if (ctx->session_passed != 1) {
        ACVP_LOG_ERR("This testSession cannot be certified. Required disposition == 'pass'.");
        return ACVP_SUCCESS; // Technically no error occurred
    }

    rv = acvp_build_validation(ctx, &validation, &validation_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to build Validation message");
        goto end;
    }

    /*
     * PUT the validation with the ACVP server and get the response,
     */
    rv = acvp_transport_put_validation(ctx, validation, validation_len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_STATUS("Validation send failed");
        goto end;
    }

    rv = acvp_parse_validation(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_STATUS("Failed to parse Validation response");
    }

end:
    if (validation) free(validation);

    return rv;
}


static
ACVP_RESULT acvp_post_data(ACVP_CTX *ctx, char *filename) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Array *data_array = NULL;
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;
    JSON_Value *post_val = NULL;
    JSON_Value *raw_val = NULL;
    const char *path = NULL;
    char *json_result = NULL;
    int len;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!filename) {
        ACVP_LOG_ERR("Must provide value for JSON filename");
        return ACVP_MISSING_ARG;
    }

    if (strnlen_s(filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    val = json_parse_file(filename);
    if (!val) {
        ACVP_LOG_ERR("JSON val parse error");
        return ACVP_MALFORMED_JSON;
    }

    data_array = json_value_get_array(val);
    obj = json_array_get_object(data_array, 0);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    path = json_object_get_string(obj, "url");
    if (!path) {
        ACVP_LOG_WARN("Missing path, POST aborted");
        goto end;
    }

    raw_val = json_array_get_value(data_array, 1);
    json_result = json_serialize_to_string_pretty(raw_val, NULL);
    post_val = json_parse_string(json_result);
    json_free_serialized_string(json_result);

    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    json_array_append_value(reg_arry, post_val);

    json_result = json_serialize_to_string_pretty(reg_arry_val, &len);
    ACVP_LOG_INFO("\nPOST Data: %s\n\n", json_result);
    json_value_free(reg_arry_val);

    rv = acvp_transport_post(ctx, path, json_result, len);
    ACVP_LOG_STATUS("POST response:\n\n%s\n", ctx->curl_buf);
    json_free_serialized_string(json_result);

end:
    json_value_free(val);
    return rv;

}

#define TEST_SESSION "testSessions/"

static ACVP_RESULT acvp_write_session_info(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *ts_val = NULL;
    JSON_Object *ts_obj = NULL;
    char *filename = NULL, *ptr = NULL, *path = NULL, *prefix = NULL;
    int diff;
    int pathLen = 0, allocedPrefix = 0;

    filename = calloc(ACVP_JSON_FILENAME_MAX + 1, sizeof(char));
    if (!filename) {
        return ACVP_MALLOC_FAIL;
    }

    ts_val = json_value_init_object();
    ts_obj = json_value_get_object(ts_val);

    json_object_set_string(ts_obj, "url", ctx->session_url);
    json_object_set_string(ts_obj, "jwt", ctx->jwt_token);
    json_object_set_boolean(ts_obj, "isSample", ctx->is_sample);
    json_object_set_value(ts_obj, "registration", json_value_deep_copy(ctx->registration));
    /* pull test session ID out of URL */
    ptr = ctx->session_url;
    while(*ptr != 0) {
        memcmp_s(ptr, strlen(TEST_SESSION), TEST_SESSION, strlen(TEST_SESSION), &diff);
        if (!diff) {
            break;
        }
        ptr++;
    }

    ptr+= strnlen_s(TEST_SESSION, ACVP_ATTR_URL_MAX);
    
    path = getenv("ACV_SESSION_SAVE_PATH");
    prefix = getenv("ACV_SESSION_SAVE_PREFIX");

    /*
     * Check the total length of our path, prefix, and total concatenated filename. 
     * Add 6 to checks for .json and the _ beteween prefix and session ID
     * If any lengths are too long, just use default prefix and location
     */
    if (path) {
        pathLen += strnlen_s(path, ACVP_JSON_FILENAME_MAX + 1);
    }
    if (prefix) {
        pathLen += strnlen_s(prefix, ACVP_JSON_FILENAME_MAX + 1);
    }
    pathLen += strnlen_s(ptr, ACVP_JSON_FILENAME_MAX + 1);
    
    if (pathLen > ACVP_JSON_FILENAME_MAX - 6) {
        ACVP_LOG_WARN("Provided ACV_SESSION_SAVE information too long (current max path len: %d). Using defaults", \
                      ACVP_JSON_FILENAME_MAX);
        path = NULL;
        prefix = NULL;
    }
    if (!prefix) {
        int len = strnlen_s(ACVP_SAVE_DEFAULT_PREFIX, ACVP_JSON_FILENAME_MAX);
        prefix = calloc(len + 1, sizeof(char));
        if (!prefix) {
            rv = ACVP_MALLOC_FAIL;
            goto end;
        }
        strncpy_s(prefix, len + 1, ACVP_SAVE_DEFAULT_PREFIX, len);
        allocedPrefix = 1;
    }

    //if we have a path, use it, otherwise use default (usually directory of parent application)
    if (path) {
        diff = snprintf(filename, ACVP_JSON_FILENAME_MAX, "%s/%s_%s.json", path, prefix, ptr);
    } else {
        diff = snprintf(filename, ACVP_JSON_FILENAME_MAX, "%s_%s.json", prefix, ptr);
    }
    if (diff < 0) {
        rv = ACVP_UNSUPPORTED_OP;
        goto end;
    }
    rv = acvp_json_serialize_to_file_pretty_w(ts_val, filename);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("File write error. Check that directory exists and allows writes.");
        goto end;
    }

    rv = acvp_json_serialize_to_file_pretty_a(NULL, filename);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("File write error. Check that directory exists and allows writes.");
        goto end;
    }

    if (ctx->session_file_path) {
        free(ctx->session_file_path);
    }
    ctx->session_file_path = calloc(ACVP_JSON_FILENAME_MAX + 1, sizeof(char));
    if (strncpy_s(ctx->session_file_path, ACVP_JSON_FILENAME_MAX + 1, filename, 
                  ACVP_JSON_FILENAME_MAX)) {
        ACVP_LOG_ERR("Buffer write error while trying to save session file path to CTX");
        rv = ACVP_UNSUPPORTED_OP;
        goto end;
    }

end:
    if (allocedPrefix && prefix) free(prefix);
    if (ts_val) json_value_free(ts_val);
    free(filename);
    return rv;
}



ACVP_RESULT acvp_run(ACVP_CTX *ctx, int fips_validation) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *val = NULL;

    if (ctx == NULL) return ACVP_NO_CTX;

    rv = acvp_login(ctx, 0);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to login with ACVP server");
        goto end;
    }


    if (ctx->get) { 
        rv = acvp_transport_get(ctx, ctx->get_string, NULL);
        if (ctx->save_filename) {
            ACVP_LOG_STATUS("Saving GET result to specified file...");
            val = json_parse_string(ctx->curl_buf);
            if (!val) {
                ACVP_LOG_ERR("Unable to parse JSON. printing output instead...");
            } else {
                rv = acvp_json_serialize_to_file_pretty_w(val, ctx->save_filename);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("Failed to write file, printing instead...");
                } else {
                    rv = acvp_json_serialize_to_file_pretty_a(NULL, ctx->save_filename);
                    if (rv != ACVP_SUCCESS)
                        ACVP_LOG_WARN("Unable to append ending ] to write file");
                    goto end;
                }
            }
        }
        if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
            printf("\n\n%s\n\n", ctx->curl_buf);
        } else {
            ACVP_LOG_STATUS("GET Response:\n\n%s\n", ctx->curl_buf);
        }
        goto end;
    }

    if (ctx->post) { 
        rv = acvp_post_data(ctx, ctx->post_filename);
        goto end;
    }

    if (ctx->delete) {
        rv = acvp_transport_delete(ctx, ctx->delete_string);
        if (ctx->save_filename) {
            ACVP_LOG_STATUS("Saving DELETE response to specified file...");
            val = json_parse_string(ctx->curl_buf);
            if (!val) {
                ACVP_LOG_ERR("Unable to parse JSON. printing output instead...");
            } else {
                rv = acvp_json_serialize_to_file_pretty_w(val, ctx->save_filename);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("Failed to write file, printing instead...");
                } else {
                    rv = acvp_json_serialize_to_file_pretty_a(NULL, ctx->save_filename);
                    if (rv != ACVP_SUCCESS)
                        ACVP_LOG_WARN("Unable to append ending ] to write file");
                    goto end;
                }
            }
        }
        if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
            printf("\n\n%s\n\n", ctx->curl_buf);
        } else {
            ACVP_LOG_STATUS("DELETE Response:\n\n%s\n", ctx->curl_buf);
        }
        goto end;
    }

    if (fips_validation) {
        rv = acvp_verify_fips_validation_metadata(ctx);
        if (ACVP_SUCCESS != rv) {
            ACVP_LOG_ERR("Issue(s) with validation metadata, not continuing with session.");
            return ACVP_UNSUPPORTED_OP;
        }

        ctx->fips.do_validation = 1; /* Enable */
    } else {
        ctx->fips.do_validation = 0; /* Disable */
    }

    /*
     * Register with the server to advertise our capabilities and receive
     * the vector sets identifiers.
     */
    rv = acvp_register(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to register with ACVP server");
        goto end;
    }
    
    //write session info so if we time out or lose connection waiting for results, we can recheck later on
    if (!ctx->put) {
        if (acvp_write_session_info(ctx) != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Error writing the session info file. Continuing, but session will not be able to be resumed or checked later on");
        }
    }

    ACVP_LOG_STATUS("Beginning to download and process vector sets...");

    /*
     * Now we process the test cases given to us during
     * registration earlier.
     */
    rv = acvp_process_tests(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to process vectors");
        goto end;
    }
    if (ctx->vector_req) {
        ACVP_LOG_STATUS("Successfully downloaded vector sets and saved to specified file.");
        return ACVP_SUCCESS;
    }

    /*
     * Check the test results.
     */
    ACVP_LOG_STATUS("Tests complete, checking results...");
    rv = acvp_check_test_results(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to retrieve test results");
        goto end;
    }

    if (fips_validation) {
        /*
         * Tell the server to provision a FIPS certificate for this testSession.
         */
        rv = acvp_validate_test_session(ctx);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to perform Validation of testSession");
            goto end;
        }
    }

   if (ctx->put) {
       rv = acvp_put_data_from_ctx(ctx);
   }
end:
    if (val) json_value_free(val);
    return rv;
}

const char *acvp_version(void) {
    return ACVP_LIBRARY_VERSION;
}

const char *acvp_protocol_version(void) {
    return ACVP_VERSION;
}

ACVP_RESULT acvp_put_data_from_file(ACVP_CTX *ctx, const char *put_filename) {
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;
    JSON_Value *meta_val = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Array *reg_array;
    const char *test_session_url = NULL;
    const char *jwt = NULL;
    JSON_Value *put_val = NULL;
    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;
    int len = 0;
    int validation = 0;
    char *json_result = NULL;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!put_filename) {
        ACVP_LOG_ERR("Must provide value for JSON filename");
        return ACVP_MISSING_ARG;
    }

    if (strnlen_s(put_filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided put_filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    val = json_parse_file(put_filename);
    if (!val) {
        ACVP_LOG_ERR("JSON val parse error");
        return ACVP_MALFORMED_JSON;
    }
    reg_array = json_value_get_array(val);
    obj = json_array_get_object(reg_array, 0);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        rv = ACVP_MALFORMED_JSON;
        goto end;
    }

    /*
     * This is the identifiers provided by the server
     * for this specific test session!
     */
    test_session_url = json_object_get_string(obj, "url");
    if (!test_session_url) {
        ACVP_LOG_ERR("Missing session URL");
        rv = ACVP_MALFORMED_JSON;
        goto end;
    }

    jwt = json_object_get_string(obj, "jwt");
    if (jwt) {
        ctx->jwt_token = calloc(ACVP_JWT_TOKEN_MAX + 1, sizeof(char));
        if (!ctx->jwt_token) {
            rv = ACVP_MALLOC_FAIL;
            goto end;
        }
        strcpy_s(ctx->jwt_token, ACVP_JWT_TOKEN_MAX + 1, jwt);
    } else {
        rv = acvp_login(ctx, 0);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to login with ACVP server");
            goto end;
        }
    }

    meta_val = json_array_get_value(reg_array, 1);
    obj = json_value_get_object(meta_val);
    if (!obj) {
        ACVP_LOG_ERR("JSON obj parse error");
        rv = ACVP_MALFORMED_JSON;
        goto end;
    }
    json_result = json_serialize_to_string(meta_val, &len);
    if (jwt && (json_object_has_value(obj, "oe") || json_object_has_value(obj, "oeUrl")) &&
        (json_object_has_value(obj, "module") || json_object_has_value(obj, "moduleUrl"))) {
        validation = 1;
    }

    put_val = json_parse_string(json_result);
    json_free_serialized_string(json_result);
    json_result = NULL;

    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_STATUS("Failed to create array");
        goto end;
    }
    json_array_append_value(reg_arry, put_val);
    json_result = json_serialize_to_string_pretty(reg_arry_val, &len);

    rv = acvp_transport_put(ctx, test_session_url, json_result, len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_STATUS("Failed to perform PUT");
        goto end;
    }

    /*
     * Check the test results.
     */
    if (validation) {
        ACVP_LOG_STATUS("Checking validation response...");
        rv = acvp_parse_validation(ctx);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_STATUS("Failed to parse Validation response");
        }
    } else {
        ACVP_LOG_STATUS("PUT response: \n%s", ctx->curl_buf);
    }
end:
    if (json_result) {json_free_serialized_string(json_result);}
    if (val) {json_value_free(val);}
    if (put_val) {json_value_free(put_val);}
    return rv;
}

static ACVP_RESULT acvp_put_data_from_ctx(ACVP_CTX *ctx) {

    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Array *reg_array;
    char *json_result = NULL;
    JSON_Value *val = NULL;
    JSON_Value *meta_val = NULL;
    JSON_Value *put_val = NULL;
    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;
    int len = 0;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (strnlen_s(ctx->put_filename, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided put_filename length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    val = json_parse_file(ctx->put_filename);
    if (!val) {
        ACVP_LOG_ERR("JSON val parse error");
        return ACVP_MALFORMED_JSON;
    }
    reg_array = json_value_get_array(val);

    meta_val = json_array_get_value(reg_array, 0);
    if (!val) {
        ACVP_LOG_ERR("JSON obj parse error");
        rv = ACVP_MALFORMED_JSON;
        goto end;
    }

    json_result = json_serialize_to_string(meta_val, &len);

    put_val = json_parse_string(json_result);
    json_free_serialized_string(json_result);
    json_result = NULL;

    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_STATUS("Failed to create array");
        goto end;
    }
    json_array_append_value(reg_arry, put_val);
    json_result = json_serialize_to_string_pretty(reg_arry_val, &len);

    rv = acvp_transport_put(ctx, ctx->session_url, json_result, len);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_STATUS("Failed to perform PUT");
        goto end;
    }

    /*
     * Check the test results.
     */
    ACVP_LOG_STATUS("Tests complete, checking results...");
    rv = acvp_parse_validation(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_STATUS("Failed to parse Validation response");
    }

end:
    if (json_result) {json_free_serialized_string(json_result);}
    if (put_val) {json_value_free(put_val);}
    if (val) {json_value_free(val);}
    return rv;
}

ACVP_SUB_CMAC acvp_get_cmac_alg(ACVP_CIPHER cipher)
{
    if ((cipher == ACVP_CIPHER_START) || (cipher >= ACVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.cmac);
}

ACVP_SUB_HASH acvp_get_hash_alg(ACVP_CIPHER cipher)
{
    if ((cipher == ACVP_CIPHER_START) || (cipher >= ACVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.hash);
}

ACVP_SUB_AES acvp_get_aes_alg(ACVP_CIPHER cipher)
{
    if ((cipher == ACVP_CIPHER_START) || (cipher >= ACVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.aes);
}

ACVP_SUB_TDES acvp_get_tdes_alg(ACVP_CIPHER cipher)
{
    if ((cipher == ACVP_CIPHER_START) || (cipher >= ACVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.tdes);
}

ACVP_SUB_HMAC acvp_get_hmac_alg(ACVP_CIPHER cipher)
{
    if ((cipher == ACVP_CIPHER_START) || (cipher >= ACVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.hmac);
}

ACVP_SUB_RSA acvp_get_rsa_alg(ACVP_CIPHER cipher)
{
    if ((cipher == ACVP_CIPHER_START) || (cipher >= ACVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.rsa);
}

ACVP_SUB_DSA acvp_get_dsa_alg(ACVP_CIPHER cipher)
{
    if ((cipher == ACVP_CIPHER_START) || (cipher >= ACVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.dsa);
}

ACVP_SUB_ECDSA acvp_get_ecdsa_alg(ACVP_CIPHER cipher)
{
    if ((cipher == ACVP_CIPHER_START) || (cipher >= ACVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.ecdsa);
}

ACVP_SUB_KDF acvp_get_kdf_alg(ACVP_CIPHER cipher)
{
    if ((cipher == ACVP_CIPHER_START) || (cipher >= ACVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.kdf);
}

ACVP_SUB_DRBG acvp_get_drbg_alg(ACVP_CIPHER cipher)
{
    if ((cipher == ACVP_CIPHER_START) || (cipher >= ACVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.drbg);
}

ACVP_SUB_KAS acvp_get_kas_alg(ACVP_CIPHER cipher)
{
    if ((cipher == ACVP_CIPHER_START) || (cipher >= ACVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.kas);
}
