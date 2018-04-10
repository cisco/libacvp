/** @file
 *  This is the public header file to be included by applications
 *  using libacvp.
 */
/*****************************************************************************
* Copyright (c) 2016-2017, Cisco Systems, Inc.
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

#ifndef acvp_h
#define acvp_h

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum acvp_log_lvl {
    ACVP_LOG_LVL_NONE = 0,
    ACVP_LOG_LVL_ERR,
    ACVP_LOG_LVL_WARN,
    ACVP_LOG_LVL_STATUS,
    ACVP_LOG_LVL_INFO,
    ACVP_LOG_LVL_VERBOSE,
} ACVP_LOG_LVL;

/*! @struct ACVP_CTX
 *  @brief This opaque structure is used to maintain the state of a test session
 *         with an ACVP server.  A single instance of this context
 *         represents a test session with the ACVP server.  This context
 *         is used by the application layer to perform the steps to
 *         conduct a test.  These steps are:
 *
 *         1. Create the context
 *         2. Specify the server hostname
 *         3. Specify the crypto algorithms to test
 *         4. Register with the ACVP server
 *         5. Commence the test with the server
 *         6. Check the test results
 *         7. Free the context
 */
typedef struct acvp_ctx_t ACVP_CTX;

/*! @struct ACVP_RESULT
 *  @brief This enum is used to indicate error conditions to the application
 *     layer. Most libacvp function will return a value from this enum.
 */
typedef enum acvp_result ACVP_RESULT;

/*
 * These are the available symmetric algorithms that libacvp supports.  The application
 * layer will need to register one or more of these based on the capabilities
 * of the crypto module being validated.
 *
 * **************** ALERT *****************
 * This enum must stay aligned with alg_tbl[] in acvp.c
 */
typedef enum acvp_sym_cipher {
    ACVP_CIPHER_START = 0,
    ACVP_AES_GCM,
    ACVP_AES_CCM,
    ACVP_AES_ECB,
    ACVP_AES_CBC,
    ACVP_AES_CFB1,
    ACVP_AES_CFB8,
    ACVP_AES_CFB128,
    ACVP_AES_OFB,
    ACVP_AES_CTR,
    ACVP_AES_XTS,
    ACVP_AES_KW,
    ACVP_AES_KWP,
    ACVP_TDES_ECB,
    ACVP_TDES_CBC,
    ACVP_TDES_CBCI,
    ACVP_TDES_OFB,
    ACVP_TDES_OFBI,
    ACVP_TDES_CFB1,
    ACVP_TDES_CFB8,
    ACVP_TDES_CFB64,
    ACVP_TDES_CFBP1,
    ACVP_TDES_CFBP8,
    ACVP_TDES_CFBP64,
    ACVP_TDES_CTR,
    ACVP_TDES_KW,
    ACVP_SHA1,
    ACVP_SHA224,
    ACVP_SHA256,
    ACVP_SHA384,
    ACVP_SHA512,
    ACVP_HASHDRBG,
    ACVP_HMACDRBG,
    ACVP_CTRDRBG,
    ACVP_HMAC_SHA1,
    ACVP_HMAC_SHA2_224,
    ACVP_HMAC_SHA2_256,
    ACVP_HMAC_SHA2_384,
    ACVP_HMAC_SHA2_512,
    ACVP_HMAC_SHA2_512_224,
    ACVP_HMAC_SHA2_512_256,
    ACVP_HMAC_SHA3_224,
    ACVP_HMAC_SHA3_256,
    ACVP_HMAC_SHA3_384,
    ACVP_HMAC_SHA3_512,
    ACVP_CMAC_AES,
    ACVP_CMAC_TDES,
    ACVP_DSA,
    ACVP_RSA_KEYGEN,
    ACVP_RSA_SIGGEN,
    ACVP_RSA_SIGVER,
    ACVP_ECDSA_KEYGEN,
    ACVP_ECDSA_KEYVER,
    ACVP_ECDSA_SIGGEN,
    ACVP_ECDSA_SIGVER,
    ACVP_KDF135_TLS,
    ACVP_KDF135_SNMP,
    ACVP_KDF135_SSH,
    ACVP_CIPHER_END
} ACVP_CIPHER;


typedef enum acvp_prereq_mode_t {
    ACVP_PREREQ_AES = 1,
    ACVP_PREREQ_TDES,
    ACVP_PREREQ_DRBG,
    ACVP_PREREQ_HMAC,
    ACVP_PREREQ_SHA
} ACVP_PREREQ_ALG;

#define ACVP_KDF135_SNMP_ENGID_MAX 32
#define ACVP_KDF135_SNMP_SKEY_MAX 32

/* these are bit flags */
typedef enum acvp_kdf135_tls_cap_parm {
    ACVP_KDF135_TLS_CAP_SHA256 = 1,
    ACVP_KDF135_TLS_CAP_SHA384,
    ACVP_KDF135_TLS_CAP_SHA512,
    ACVP_KDF135_TLS_CAP_MAX
} ACVP_KDF135_TLS_CAP_PARM;

/* these are bit flags */
typedef enum acvp_kdf135_ssh_cap_parm {
    ACVP_KDF135_SSH_CAP_MIN = 0,
    ACVP_KDF135_SSH_CAP_SHA256 = 1, //bin 001
    ACVP_KDF135_SSH_CAP_SHA384 = 2, //bin 010
    ACVP_KDF135_SSH_CAP_SHA512 = 4, //bin 100
} ACVP_KDF135_SSH_CAP_PARM;

typedef enum acvp_kdf135_ssh_method {
    ACVP_SSH_METH_TDES_CBC = 1,
    ACVP_SSH_METH_AES_128_CBC,
    ACVP_SSH_METH_AES_192_CBC,
    ACVP_SSH_METH_AES_256_CBC,
    ACVP_SSH_METH_MAX
} ACVP_KDF135_SSH_METHOD;

/*
 * Used to help manage capability structures
 */
typedef enum acvp_capability_type {
    ACVP_SYM_TYPE = 1,
    ACVP_HASH_TYPE,
    ACVP_DRBG_TYPE,
    ACVP_HMAC_TYPE,
    ACVP_CMAC_TYPE,
    ACVP_RSA_KEYGEN_TYPE,
    ACVP_RSA_SIGGEN_TYPE,
    ACVP_RSA_SIGVER_TYPE,
    ACVP_ECDSA_KEYGEN_TYPE,
    ACVP_ECDSA_KEYVER_TYPE,
    ACVP_ECDSA_SIGGEN_TYPE,
    ACVP_ECDSA_SIGVER_TYPE,
    ACVP_DSA_TYPE,
    ACVP_KDF135_TLS_TYPE,
    ACVP_KDF135_SNMP_TYPE,
    ACVP_KDF135_SSH_TYPE
} ACVP_CAP_TYPE;

typedef enum acvp_sym_cipher_keying_option {
    ACVP_KO_NA = 0,
    ACVP_KO_THREE,
    ACVP_KO_TWO,
    ACVP_KO_BOTH
} ACVP_SYM_CIPH_KO;

/*
 * The IV generation source for AEAD ciphers.
 * This can be internal, external, or not applicable.
 */
typedef enum acvp_sym_cipher_ivgen_source {
    ACVP_IVGEN_SRC_INT = 0,
    ACVP_IVGEN_SRC_EXT,
    ACVP_IVGEN_SRC_NA
} ACVP_SYM_CIPH_IVGEN_SRC;

/*
 * The IV generation mode.  It can comply with 8.2.1,
 * 8.2.2, or may not be applicable for some ciphers.
 */
typedef enum acvp_sym_cipher_ivgen_mode {
    ACVP_IVGEN_MODE_821 = 0,
    ACVP_IVGEN_MODE_822,
    ACVP_IVGEN_MODE_NA
} ACVP_SYM_CIPH_IVGEN_MODE;


/*
 * These are the algorithm direction suppported by libacvp.  These are used in
 * conjunction with ACVP_SYM_CIPH when registering the
 * crypto module capabilities with libacvp.
 */
typedef enum acvp_sym_cipher_direction {
    ACVP_DIR_ENCRYPT = 0,
    ACVP_DIR_DECRYPT,
    ACVP_DIR_BOTH
} ACVP_SYM_CIPH_DIR;

typedef enum acvp_kdf135_tls_method {
    ACVP_KDF135_TLS10_TLS11 = 1,
    ACVP_KDF135_TLS12
} ACVP_KDF135_TLS_METHOD;

// TODO: most of the specs are moving toward "SHA2..." but
// not all of them have been updated. The duplicates can
// be removed once all are updated.
#define ACVP_STR_SHA_1          "SHA-1"
#define ACVP_STR_SHA_224        "SHA-224"
#define ACVP_STR_SHA_256        "SHA-256"
#define ACVP_STR_SHA_384        "SHA-384"
#define ACVP_STR_SHA_512        "SHA-512"
#define ACVP_STR_SHA_512_224    "SHA-512/224"
#define ACVP_STR_SHA_512_256    "SHA-512/256"
#define ACVP_STR_SHA2_224       "SHA2-224"
#define ACVP_STR_SHA2_256       "SHA2-256"
#define ACVP_STR_SHA2_384       "SHA2-384"
#define ACVP_STR_SHA2_512       "SHA2-512"
#define ACVP_STR_SHA2_512_224   "SHA2-512/224"
#define ACVP_STR_SHA2_512_256   "SHA2-512/256"
typedef enum acvp_hash_param {
    ACVP_HASH_IN_BIT = 0,
    ACVP_HASH_IN_EMPTY
} ACVP_HASH_PARM;

/*
 * * **************** ALERT *****************
 * This enum must stay aligned with drbg_mode_tbl[] in acvp.c
 */
typedef enum acvp_drbg_mode {
    ACVP_DRBG_MODE_START = 0,
    ACVP_DRBG_SHA_1,
    ACVP_DRBG_SHA_224,
    ACVP_DRBG_SHA_256,
    ACVP_DRBG_SHA_384,
    ACVP_DRBG_SHA_512,
    ACVP_DRBG_SHA_512_224,
    ACVP_DRBG_SHA_512_256,
    ACVP_DRBG_3KEYTDEA,
    ACVP_DRBG_AES_128,
    ACVP_DRBG_AES_192,
    ACVP_DRBG_AES_256,
    ACVP_DRBG_MODE_END
} ACVP_DRBG_MODE;

typedef enum acvp_drbg_param {
    ACVP_DRBG_DER_FUNC_ENABLED = 0,
    ACVP_DRBG_PRED_RESIST_ENABLED,
    ACVP_DRBG_RESEED_ENABLED,
    ACVP_DRBG_ENTROPY_LEN,
    ACVP_DRBG_NONCE_LEN,
    ACVP_DRBG_PERSO_LEN,
    ACVP_DRBG_ADD_IN_LEN,
    ACVP_DRBG_RET_BITS_LEN,
    ACVP_DRBG_PRE_REQ_VALS
} ACVP_DRBG_PARM;

typedef enum acvp_rsa_param {
    ACVP_PUB_EXP_MODE = 0,
    ACVP_FIXED_PUB_EXP_VAL,
    ACVP_KEY_FORMAT_CRT,
    ACVP_RAND_PQ,
    ACVP_CAPS_PROV_PRIME,
    ACVP_CAPS_PROB_PRIME,
    ACVP_CAPS_PROV_PROB_PRIME,
    ACVP_RSA_INFO_GEN_BY_SERVER
} ACVP_RSA_PARM;

typedef enum acvp_ecdsa_param {
    ACVP_CURVE,
    ACVP_SECRET_GEN_MODE,
    ACVP_HASH_ALG
} ACVP_ECDSA_PARM;

#define RSA_SIG_TYPE_X931_NAME      "ansx9.31"
#define RSA_SIG_TYPE_PKCS1V15_NAME  "pkcs1v1.5"
#define RSA_SIG_TYPE_PKCS1PSS_NAME  "pss"

#define PRIME_TEST_TBLC2_NAME "tblC2"
#define PRIME_TEST_TBLC3_NAME "tblC3"

#define RSA_PUB_EXP_FIXED      1
#define RSA_PUB_EXP_RANDOM     0

typedef enum acvp_rsa_keygen_mode_t {
    ACVP_RSA_KEYGEN_START = 0,
    ACVP_RSA_KEYGEN_B32,
    ACVP_RSA_KEYGEN_B33,
    ACVP_RSA_KEYGEN_B34,
    ACVP_RSA_KEYGEN_B35,
    ACVP_RSA_KEYGEN_B36
} ACVP_RSA_KEYGEN_MODE;

typedef enum acvp_rsa_sig_type {
    RSA_SIG_TYPE_START = 0,
    RSA_SIG_TYPE_X931,
    RSA_SIG_TYPE_PKCS1V15,
    RSA_SIG_TYPE_PKCS1PSS
} ACVP_RSA_SIG_TYPE;

typedef enum acvp_sym_cipher_parameter {
    ACVP_SYM_CIPH_KEYLEN = 0,
    ACVP_SYM_CIPH_TAGLEN,
    ACVP_SYM_CIPH_IVLEN,
    ACVP_SYM_CIPH_PTLEN,
    ACVP_SYM_CIPH_TWEAK,
    ACVP_SYM_CIPH_AADLEN,
    ACVP_SYM_CIPH_KW_MODE,
} ACVP_SYM_CIPH_PARM;

typedef enum acvp_sym_xts_tweak_mode {
    ACVP_SYM_CIPH_TWEAK_HEX = 1,
    ACVP_SYM_CIPH_TWEAK_NUM,
    ACVP_SYM_CIPH_TWEAK_NONE
} ACVP_SYM_CIPH_TWEAK_MODE;

typedef enum acvp_sym_kw_mode {
    ACVP_SYM_KW_NONE = 0,
    ACVP_SYM_KW_CIPHER,
    ACVP_SYM_KW_INVERSE,
    ACVP_SYM_KW_MAX
} ACVP_SYM_KW_MODE;

typedef enum acvp_sym_cipher_testtype {
    ACVP_SYM_TEST_TYPE_NONE = 0,
    ACVP_SYM_TEST_TYPE_AFT,
    ACVP_SYM_TEST_TYPE_CTR,
    ACVP_SYM_TEST_TYPE_MCT
} ACVP_SYM_CIPH_TESTTYPE;


typedef enum acvp_hash_testtype {
    ACVP_HASH_TEST_TYPE_NONE = 0,
    ACVP_HASH_TEST_TYPE_AFT,
    ACVP_HASH_TEST_TYPE_MCT
} ACVP_HASH_TESTTYPE;

typedef enum acvp_hmac_parameter {
    ACVP_HMAC_KEYLEN_MIN = 0,
    ACVP_HMAC_KEYLEN_MAX,
    ACVP_HMAC_KEYBLOCK,
    ACVP_HMAC_MACLEN
} ACVP_HMAC_PARM;

typedef enum acvp_cmac_parameter {
    ACVP_CMAC_MACLEN,
    ACVP_CMAC_KEYLEN,
    ACVP_CMAC_KEYING_OPTION,
    ACVP_CMAC_DIRECTION_GEN,
    ACVP_CMAC_DIRECTION_VER,
    ACVP_CMAC_BLK_DIVISIBLE_1,
    ACVP_CMAC_BLK_DIVISIBLE_2,
    ACVP_CMAC_BLK_NOT_DIVISIBLE_1,
    ACVP_CMAC_BLK_NOT_DIVISIBLE_2,
    ACVP_CMAC_MSG_LEN_MAX
} ACVP_CMAC_PARM;

typedef enum acvp_cmac_msg_len_index {
    CMAC_BLK_DIVISIBLE_1 = 0,
    CMAC_BLK_DIVISIBLE_2,
    CMAC_BLK_NOT_DIVISIBLE_1,
    CMAC_BLK_NOT_DIVISIBLE_2,
    CMAC_MSG_LEN_MAX,
    CMAC_MSG_LEN_NUM_ITEMS
} ACVP_CMAC_MSG_LEN_INDEX;

/*
 * This struct holds data that represents a single test case for
 * a symmetric cipher, such as AES or DES.  This data is passed
 * between libacvp and the crypto module.  libacvp will parse the test
 * case parameters from the JSON encoded test vector, fill in this
 * structure, and pass the struct to the crypto module via the
 * handler that was registered with libacvp.  The crypto module will
 * then need to perform the crypto operation and fill in the remaining
 * items in the struct for the given test case.  The struct is then
 * passed back to libacvp, where it is then used to build the JSON
 * encoded vector response.
 */
typedef struct acvp_sym_cipher_tc_t {
    ACVP_CIPHER cipher;
    ACVP_SYM_CIPH_TESTTYPE test_type; /* KAT or MCT */
    ACVP_SYM_CIPH_DIR direction;   /* encrypt or decrypt */
    ACVP_SYM_CIPH_IVGEN_SRC ivgen_source;
    ACVP_SYM_CIPH_IVGEN_MODE ivgen_mode;
    unsigned int tc_id;    /* Test case id */
    unsigned char *key; /* Aes symmetric key */
    unsigned char *pt; /* Plaintext */
    unsigned char *aad; /* Additional Authenticated Data */
    unsigned char *iv; /* Initialization Vector */
    unsigned char *ct; /* Ciphertext */
    unsigned char *tag; /* Aead tag */
    unsigned char *iv_ret; /* updated IV used for TDES MCT */
    unsigned char *iv_ret_after; /* updated IV used for TDES MCT */
    unsigned int kwcipher;
    unsigned int key_len;
    unsigned int pt_len;
    unsigned int aad_len;
    unsigned int iv_len;
    unsigned int ct_len;
    unsigned int tag_len;
    unsigned int mct_index;  /* used to identify init vs. update */
} ACVP_SYM_CIPHER_TC;

/*
 * This struct holds data that represents a single test case
 * for an asymmetric cipher, such as RSA or ECDSA.  This data is
 * passed between libacvp and the crypto module.
 */
typedef struct acvp_asym_cipher_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /* Test case id */
} ACVP_ASYM_CIPHER_TC;

/*
 * This struct holds data that represents a single test case
 * for entropy testing.  This data is
 * passed between libacvp and the crypto module.
 */
typedef struct acvp_entropy_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /* Test case id */
    unsigned int entropy_len;
    unsigned char *entropy_data;
} ACVP_ENTROPY_TC;

/*
 * This struct holds data that represents a single test case
 * for hash testing.  This data is
 * passed between libacvp and the crypto module.
 */
typedef struct acvp_hash_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /* Test case id */
    ACVP_HASH_TESTTYPE test_type; /* KAT or MCT */
    unsigned char *msg;
    unsigned char *m1;
    unsigned char *m2;
    unsigned char *m3;
    unsigned int msg_len;
    unsigned char *md; /* The resulting digest calculated for the test case */
    unsigned int md_len;
} ACVP_HASH_TC;

/*
 * This struct holds data that represents a single test case
 * for kdf135 TLS testing.  This data is
 * passed between libacvp and the crypto module.
 */
typedef struct acvp_kdf135_tls_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /* Test case id */
    unsigned int method;
    unsigned int md;
    unsigned int pm_len;
    unsigned int kb_len;
    unsigned char *pm_secret;
    unsigned char *sh_rnd;
    unsigned char *ch_rnd;
    unsigned char *s_rnd;
    unsigned char *c_rnd;
    unsigned char *msecret1; /* The resulting data calculated for the test case */
    unsigned char *msecret2;
    unsigned char *kblock1;  /* The resulting data calculated for the test case */
    unsigned char *kblock2;
} ACVP_KDF135_TLS_TC;

/*
 * This struct holds data that represents a single test case
 * for kdf135 TLS testing.  This data is
 * passed between libacvp and the crypto module.
 */
typedef struct acvp_kdf135_snmp_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /* Test case id */
    const char *password;
    unsigned int p_len;
    unsigned char *s_key;
    unsigned int skey_len;
    unsigned char *engine_id;
} ACVP_KDF135_SNMP_TC;

/*
 * This struct holds data that represents a single test case
 * for kdf135 SSH testing.  This data is
 * passed between libacvp and the crypto module.
 */
typedef struct acvp_kdf135_ssh_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;        /* Test case id */
    unsigned int sha_type;
    unsigned int sh_sec_len;
    unsigned int iv_len;
    unsigned int key_len;
    char *shared_sec_k;
    char *hash_h;
    unsigned int hash_len;
    char *session_id;
    unsigned int session_len;
    //results
    unsigned char *cs_init_iv;
    unsigned char *sc_init_iv;
    unsigned char *cs_e_key;
    unsigned char *sc_e_key;
    unsigned char *cs_i_key;
    unsigned char *sc_i_key;
} ACVP_KDF135_SSH_TC;

/*
 * This struct holds data that represents a single test case
 * for hmac testing.  This data is
 * passed between libacvp and the crypto module.
 */
typedef struct acvp_hmac_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /* Test case id */
    unsigned char *msg;
    unsigned int msg_len;
    unsigned char *mac; /* The resulting digest calculated for the test case */
    unsigned int mac_len;
    unsigned int key_len;
    unsigned char *key;
} ACVP_HMAC_TC;

/*
 * This struct holds data that represents a single test case
 * for cmac testing.  This data is
 * passed between libacvp and the crypto module.
 */
typedef struct acvp_cmac_tc_t {
    ACVP_CIPHER cipher;
    char direction[3];
    char ver_disposition[4];
    unsigned int tc_id;    /* Test case id */
    unsigned char *msg;
    unsigned int msg_len;
    unsigned char *mac; /* The resulting digest calculated for the test case */
    unsigned int mac_len;
    unsigned int key_len;
    /* for CMAC-AES */
    unsigned char *key;
    /* for CMAC-TDES */
    unsigned char *key2;
    unsigned char *key3;
} ACVP_CMAC_TC;

/*
 * This struct holds data that represents a single test case
 * for RSA testing.  This data is
 * passed between libacvp and the crypto module.
 */
typedef struct acvp_rsa_keygen_tc_t {
    char *hash_alg;
    unsigned int tc_id;    /* Test case id */
    char *pub_exp;
    char *prime_test;
    char *prime_result;
    
    int rand_pq;
    int info_gen_by_server;
    char *pub_exp_mode;
    char *key_format;
    int modulo;

    unsigned char *e;
    unsigned char *p_rand;
    unsigned char *q_rand;

    unsigned char *xp1;
    unsigned char *xp2;
    unsigned char *xp;

    unsigned char *xq1;
    unsigned char *xq2;
    unsigned char *xq;
    
    unsigned char *dmp1;
    unsigned char *dmq1;
    unsigned char *iqmp;

    unsigned char *n;
    unsigned char *d;
    unsigned char *p;
    unsigned char *q;

    unsigned char *seed;
    int seed_len;
    int bitlen1;
    int bitlen2;
    int bitlen3;
    int bitlen4;
} ACVP_RSA_KEYGEN_TC;

/*
 * This struct holds data that represents a single test case
 * for ECDSA testing.  This data is
 * passed between libacvp and the crypto module.
 */
typedef struct acvp_ecdsa_tc_t {
    char *hash_alg;
    unsigned int tc_id;    /* Test case id */
    
    ACVP_CIPHER cipher;

    char *curve;
    char *secret_gen_mode;
    
    unsigned char *d;
    unsigned char *qy;
    unsigned char *qx;
    
    unsigned char *r;
    unsigned char *s;
    
    char *ver_disposition;
    unsigned char *message;

} ACVP_ECDSA_TC;

/*
 * This struct holds data that represents a single test case
 * for RSA testing.  This data is
 * passed between libacvp and the crypto module.
 */
typedef struct acvp_rsa_sig_tc_t {
    char *hash_alg;
    char *sig_type;
    unsigned int tc_id;    /* Test case id */
    unsigned int modulo;
    unsigned char *e;
    unsigned char *n;
    int salt_len;
    unsigned char *msg;
    int msg_len;
    unsigned char *signature;
    int sig_len;
    ACVP_CIPHER sig_mode;
    int ver_disposition;
} ACVP_RSA_SIG_TC;

typedef enum acvp_dsa_mode {
    ACVP_DSA_MODE_PQGGEN = 1
} ACVP_DSA_MODE;

/* These are used as bit flags */
typedef enum acvp_dsa_sha {
    ACVP_DSA_SHA1 = 1,
    ACVP_DSA_SHA224 = 2,
    ACVP_DSA_SHA256 = 4,
    ACVP_DSA_SHA384 = 8,
    ACVP_DSA_SHA512 = 16,
    ACVP_DSA_SHA512_224 = 32,
    ACVP_DSA_SHA512_256 = 64,
} ACVP_DSA_SHA;

typedef enum acvp_dsa_parm {
    ACVP_DSA_LN2048_224 = 1,
    ACVP_DSA_LN2048_256,
    ACVP_DSA_LN3072_256,
    ACVP_DSA_GENPQ,
    ACVP_DSA_GENG
} ACVP_DSA_PARM;

typedef enum acvp_dsa_gen_parm {
    ACVP_DSA_PROVABLE = 1,
    ACVP_DSA_PROBABLE,
    ACVP_DSA_CANONICAL,
    ACVP_DSA_UNVERIFIABLE
} ACVP_DSA_GEN_PARM;

/*
 * This struct holds data that represents a single test case
 * for DSA testing.  This data is
 * passed between libacvp and the crypto module.
 */
typedef struct acvp_dsa_pqggen_tc_t {
    int l;
    int n;
    int h;
    int sha;
    int gen_pq;
    int num;
    int index;
    int seedlen;
    unsigned char *p;
    unsigned char *q;
    unsigned char *g;
    unsigned char *seed;
    int counter;
} ACVP_DSA_PQGGEN_TC;

typedef struct acvp_dsa_tc_t {
    ACVP_CIPHER cipher;
    ACVP_DSA_MODE mode; // "pqgGen", "pqgVer", etc.
    union {
        ACVP_DSA_PQGGEN_TC *pqggen;
    } mode_tc;
} ACVP_DSA_TC;

/*
 * This struct holds data that represents a single test case
 * for DRBG testing.  This data is
 * passed between libacvp and the crypto module.
 */
typedef struct acvp_drbg_tc_t {
    ACVP_CIPHER cipher;
    ACVP_DRBG_MODE mode;
    unsigned int tc_id;    /* Test case id */

    unsigned char *additional_input;
    unsigned char *entropy_input_pr;
    unsigned char *additional_input_1;
    unsigned char *entropy_input_pr_1;
    unsigned char *perso_string;
    unsigned char *entropy;
    unsigned char *nonce;
    unsigned char *drb; /* The resulting pseudo random generated for the test case */

    unsigned int additional_input_len;
    unsigned int pred_resist_enabled;
    unsigned int perso_string_len;
    unsigned int der_func_enabled;
    unsigned int entropy_len;
    unsigned int nonce_len;
    unsigned int drb_len;
} ACVP_DRBG_TC;

/*
 * This is the abstracted test case representation used for
 * passing test case data to/from the crypto module. Because the
 * callback prototype is generic to all algorithms, we abstract
 * the various classes of test cases using a union.  This
 * struct is then used to pass a reference to the test case
 * between libacvp and the crypto module.
 */
typedef struct acvp_cipher_tc_t {
    union {
        ACVP_SYM_CIPHER_TC *symmetric;
        ACVP_ASYM_CIPHER_TC *asymmetric;
        ACVP_ENTROPY_TC *entropy;
        ACVP_HASH_TC *hash;
        ACVP_DRBG_TC *drbg;
        ACVP_DSA_TC *dsa;
        ACVP_HMAC_TC *hmac;
        ACVP_CMAC_TC *cmac;
        ACVP_RSA_KEYGEN_TC *rsa_keygen;
        ACVP_RSA_SIG_TC *rsa_sig;
        ACVP_ECDSA_TC *ecdsa;
        ACVP_KDF135_TLS_TC *kdf135_tls;
        ACVP_KDF135_SNMP_TC *kdf135_snmp;
        ACVP_KDF135_SSH_TC *kdf135_ssh;
    } tc;
} ACVP_TEST_CASE;

enum acvp_result {
    ACVP_SUCCESS = 0,
    ACVP_MALLOC_FAIL, /**< Error allocating memory */
    ACVP_NO_CTX, /**< No valid context */
    ACVP_TRANSPORT_FAIL, /**< Error exchanging data with server */
    ACVP_JSON_ERR,
    ACVP_UNSUPPORTED_OP,
    ACVP_CLEANUP_FAIL,
    ACVP_KAT_DOWNLOAD_RETRY,
    ACVP_INVALID_ARG,
    ACVP_CRYPTO_MODULE_FAIL,
    ACVP_CRYPTO_TAG_FAIL,
    ACVP_CRYPTO_WRAP_FAIL,
    ACVP_NO_TOKEN,
    ACVP_NO_CAP,
    ACVP_MALFORMED_JSON,
    ACVP_DATA_TOO_LARGE,
    ACVP_DUP_CIPHER,
    ACVP_RESULT_MAX,
};

/*! @brief acvp_enable_sym_cipher_cap() allows an application to specify a
       symmetric cipher capability to be tested by the ACVP server.

    This function should be called to enable crypto capabilities for
    symmetric ciphers that will be tested by the ACVP server.  This
    includes AES and 3DES.  This function may be called multiple times
    to specify more than one crypto capability, such as AES-CBC, AES-CTR,
    AES-GCM, etc.

    When the application enables a crypto capability, such as AES-GCM, it
    also needs to specify a callback function that will be used by libacvp
    when that crypto capability is needed during a test session.

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param dir ACVP_SYM_CIPH_DIR enum value identifying the crypto operation
       (e.g. encrypt or decrypt).
    @param keying_option ACVP_SYM_CIPH_KO enum value identifying the TDES keying options
    @param ivgen_source The source of the IV used by the crypto module
        (e.g. internal or external)
    @param ivgen_mode The IV generation mode
    @param crypto_handler Address of function implemented by application that
       is invoked by libacvp when the crypto capablity is needed during
       a test session.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_sym_cipher_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_SYM_CIPH_DIR dir,
        ACVP_SYM_CIPH_KO keying_options,
        ACVP_SYM_CIPH_IVGEN_SRC ivgen_source,
        ACVP_SYM_CIPH_IVGEN_MODE ivgen_mode,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case));

/*! @brief acvp_enable_sym_cipher_cap_parm() allows an application to specify
       non length-based operational parameters to be used for a given cipher
       during a test session with the ACVP server.

    This function should be called to enable crypto capabilities for
    symmetric ciphers that will be tested by the ACVP server.  This
    includes AES and 3DES.

    This function may be called multiple times to specify more than one
    crypto parameter value for the cipher. The ACVP_CIPHER value passed to
    this function should already have been setup by invoking
    acvp_enable_sym_cipher_cap() for that cipher earlier.

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param parm ACVP_SYM_CIPH_PARM enum value identifying the algorithm parameter
       that is being specified.  An example would be the supported key wrap values
   @param value The length value for the symmetric cipher parameter being set

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_sym_cipher_cap_value (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_SYM_CIPH_PARM param,
        int value);

/*! @brief acvp_enable_sym_cipher_cap_parm() allows an application to specify
       length-based operational parameters to be used for a given cipher during
       a test session with the ACVP server.

    This function should be called to enable crypto capabilities for
    symmetric ciphers that will be tested by the ACVP server.  This
    includes AES and 3DES.

    This function may be called multiple times to specify more than one
    crypto parameter value for the cipher.  For instance, if cipher supports
    plaintext lengths of 0, 128, and 136 bits, then this function would
    be called three times.  Once for 0, once for 128, and once again
    for 136. The ACVP_CIPHER value passed to this function should
    already have been setup by invoking acvp_enable_sym_cipher_cap() for
    that cipher earlier.

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param parm ACVP_SYM_CIPH_PARM enum value identifying the algorithm parameter
       that is being specified.  An example would be the supported plaintext
       length of the algorithm.
   @param length The length value for the symmetric cipher parameter being set

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_sym_cipher_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_SYM_CIPH_PARM parm,
        int length);

/*! @brief acvp_enable_hash_cap() allows an application to specify a
       hash capability to be tested by the ACVP server.

    This function should be called to enable crypto capabilities for
    hash algorithms that will be tested by the ACVP server.  This
    includes SHA-1, SHA-256, SHA-384, etc.  This function may be called
    multiple times to specify more than one crypto capability.

    When the application enables a crypto capability, such as SHA-1, it
    also needs to specify a callback function that will be used by libacvp
    when that crypto capability is needed during a test session.

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param crypto_handler Address of function implemented by application that
       is invoked by libacvp when the crypto capablity is needed during
       a test session.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_hash_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case));

/*! @brief acvp_enable_hash_cap_parm() allows an application to specify
       operational parameters to be used for a given hash alg during a
       test session with the ACVP server.

    This function should be called to enable crypto capabilities for
    hash capabilities that will be tested by the ACVP server.  This
    includes SHA-1, SHA-256, SHA-384, etc.

    This function may be called multiple times to specify more than one
    crypto parameter value for the hash algorithm. The ACVP_CIPHER value
    passed to this function should already have been setup by invoking
    acvp_enable_hash_cap().

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param param ACVP_HASH_PARM enum value identifying the algorithm parameter
       that is being specified.  An example would be a flag indicating if
       empty input values are allowed.
    @param value the value corresponding to the parameter being set

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_hash_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_HASH_PARM param,
        int value);

/*! @brief acvp_enable_drbg_cap() allows an application to specify a
       hash capability to be tested by the ACVP server.

    This function should be called to enable crypto capabilities for
    hash algorithms that will be tested by the ACVP server.  This
    includes HASHDRBG, HMACDRBG, CTRDRBG. This function may be called
    multiple times to specify more than one crypto capability.

    When the application enables a crypto capability, such as ACVP_HASHDRBG,
    it also needs to specify a callback function that will be used by libacvp
    when that crypto capability is needed during a test session.

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param crypto_handler Address of function implemented by application that
       is invoked by libacvp when the crypto capablity is needed during
       a test session.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_drbg_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case));

/*! @brief acvp_enable_drbg_cap_parm() allows an application to specify
       operational parameters to be used for a given DRBG alg during a
       test session with the ACVP server.

    This function should be called to enable crypto capabilities for
    hash capabilities that will be tested by the ACVP server.  This
    includes HASHDRBG, HMACDRBG, CTRDRBG. This function may be called
    multiple times to specify more than one crypto capability.

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param mode ACVP_DRBG_MODE enum value specifying mode. An example would be
        ACVP_DRBG_SHA_1
    @param param ACVP_DRBG_PARM enum value identifying the algorithm parameter
       that is being specified.  An example would be prediction resistance.
    @param value the value corresponding to the parameter being set

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_drbg_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_DRBG_MODE mode,
        ACVP_DRBG_PARM param,
        int value
);

/*! @brief acvp_enable_drbg_prereq_cap() allows an application to specify
        a prerequisite algorithm for a given DRBG during a test session
        with the ACVP server.

        This function should be called to enable a prerequisite for
        a DRBG capability that will be tested by the server.

   @param ctx Address of pointer to a previously allocated ACVP_CTX.
   @param cipher ACVP_CIPHER enum value identifying the crypto capability.
   @param mode ACVP_DRBG_MODE enum value specifying mode. An example would be
        ACVP_DRBG_SHA_1
   @param pre_req ACVP_PREREQ_ALG enum that the specified cipher/mode
        depends on
   @param value "same" or number

   @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_drbg_prereq_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_DRBG_MODE mode,
        ACVP_PREREQ_ALG pre_req,
        char *value
);

/*! @brief acvp_enable_drbg_length_cap() allows an application to register
        a DRBG capability length-based paramter.

        This function should be used to register a length-based parameter
        for a DRBG capability. An example would be entropy, nonce, perso
        where a minimum, step, and maximum can be specified.

   @param ctx Address of pointer to a previously allocated ACVP_CTX.
   @param cipher ACVP_CIPHER enum value identifying the crypto capability.
   @param mode ACVP_DRBG_MODE enum value specifying mode. An example would be
        ACVP_DRBG_SHA_1
   @param param ACVP_DRBG_PARM enum value specifying paramter. An example
        would be ACVP_DRBG_ENTROPY_LEN
   @param min minimum value
   @param step increment value
   @param max maximum value

   @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_drbg_length_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_DRBG_MODE mode,
        ACVP_DRBG_PARM param,
        int min,
        int step,
        int max);

/*! @brief acvp_enable_dsa_cap()

  This function should be used to enable DSA capabilities. Specific modes
  and parameters can use acvp_enable_rsa_cap_parm, acvp_enable_rsa_bignum_parm,
  acvp_enable_rsa_primes_parm depending on the need.

   When the application enables a crypto capability, such as RSA, it
   also needs to specify a callback function that will be used by libacvp
   when that crypto capability is needed during a test session.

   @param ctx Address of pointer to a previously allocated ACVP_CTX.
   @param cipher ACVP_CIPHER enum value identifying the crypto capability.
   @param crypto_handler Address of function implemented by application that
      is invoked by libacvp when the crypto capability is needed during
      a test session.

   @return ACVP_RESULT
*/
ACVP_RESULT acvp_enable_dsa_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case));

/*! @brief acvp_enable_dsa_cap_parm() allows an application to specify
       operational parameters to be used for a given hash alg during a
       test session with the ACVP server.

    This function should be called to enable crypto capabilities for
    hash capabilities that will be tested by the ACVP server.  This
    includes HASHDRBG, HMACDRBG, CTRDRBG. This function may be called
    multiple times to specify more than one crypto capability.

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param mode ACVP_DSA_MODE enum value specifying mode. An example would be
        ACVP_DSA_MODE_PQGGEN
    @param param ACVP_DSA_PARM enum value identifying the algorithm parameter
       that is being specified.  An example would be ACVP_DSA_GENPQ.
    @param value the value corresponding to the parameter being set

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_dsa_cap_parm (ACVP_CTX *ctx,
                                      ACVP_CIPHER cipher,
                                      ACVP_DSA_MODE mode,
                                      ACVP_DSA_PARM param,
                                      int value);

/*! @brief acvp_enable_rsa_cap()

  This function should be used to enable RSA capabilities. Specific modes
  and parameters can use acvp_enable_rsa_cap_parm, acvp_enable_rsa_bignum_parm,
  acvp_enable_rsa_primes_parm depending on the need.

   When the application enables a crypto capability, such as RSA, it
   also needs to specify a callback function that will be used by libacvp
   when that crypto capability is needed during a test session.

   @param ctx Address of pointer to a previously allocated ACVP_CTX.
   @param cipher ACVP_CIPHER enum value identifying the crypto capability.
   @param crypto_handler Address of function implemented by application that
      is invoked by libacvp when the crypto capablity is needed during
      a test session.

   @return ACVP_RESULT
*/
ACVP_RESULT acvp_enable_rsa_keygen_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case));

ACVP_RESULT acvp_enable_rsa_siggen_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case));

ACVP_RESULT acvp_enable_rsa_sigver_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case));

ACVP_RESULT acvp_enable_ecdsa_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case));

/*! @brief acvp_enable_rsa_*_cap_parm() allows an application to specify
       operational parameters to be used for a given RSA alg during a
       test session with the ACVP server.

    This function should be called to enable parameters for
    RSA capabilities that will be tested by the ACVP server. This function may be called
    multiple times to specify more than one crypto capability.

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param mode ACVP_RSA_MODE enum value specifying mode. An example would be
        ACVP_RSA_MODE_KEYGEN
    @param param ACVP_RSA_PARM enum value identifying the algorithm parameter
       that is being specified.  An example would be public exponent
    @param value the value corresponding to the parameter being set

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_rsa_keygen_cap_parm (
        ACVP_CTX *ctx,
        ACVP_RSA_PARM param,
        int value
);

ACVP_RESULT acvp_enable_rsa_siggen_cap_parm (
        ACVP_CTX *ctx,
        ACVP_RSA_PARM param,
        int value
);

ACVP_RESULT acvp_enable_rsa_sigver_cap_parm (
        ACVP_CTX *ctx,
        ACVP_RSA_PARM param,
        int value
);

ACVP_RESULT acvp_enable_rsa_keygen_mode (ACVP_CTX *ctx,
                                         ACVP_RSA_KEYGEN_MODE value);

ACVP_RESULT acvp_enable_rsa_siggen_type (ACVP_CTX *ctx,
                                         ACVP_RSA_SIG_TYPE type);

ACVP_RESULT acvp_enable_rsa_sigver_type (ACVP_CTX *ctx,
                                         ACVP_RSA_SIG_TYPE type);

ACVP_RESULT acvp_enable_rsa_siggen_caps_parm (ACVP_CTX *ctx,
                                              ACVP_RSA_SIG_TYPE sig_type,
                                              int mod,
                                              char *hash_name,
                                              int salt_len);

ACVP_RESULT acvp_enable_rsa_sigver_caps_parm (ACVP_CTX *ctx,
                                              ACVP_RSA_SIG_TYPE sig_type,
                                              int mod,
                                              char *hash_name,
                                              int salt_len);

ACVP_RESULT acvp_enable_ecdsa_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_ECDSA_PARM param,
        char *value
);

/*! @brief acvp_enable_rsa_bignum_parm() allows an application to specify
       BIGNUM operational parameters to be used for a given RSA alg during a
       test session with the ACVP server.

    This function behaves the same as acvp_enable_rsa_cap_parm() but instead
    allows the application to specify a BIGNUM parameter

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param mode ACVP_RSA_MODE enum value specifying mode. An example would be
        ACVP_RSA_MODE_KEYGEN
    @param param ACVP_RSA_PARM enum value identifying the algorithm parameter
       that is being specified.  An example would be public exponent
    @param value BIGNUM value corresponding to the parameter being set

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_rsa_keygen_exp_parm (ACVP_CTX *ctx,
                                             ACVP_RSA_PARM param,
                                             char *value
);
ACVP_RESULT acvp_enable_rsa_sigver_exp_parm (ACVP_CTX *ctx,
                                             ACVP_RSA_PARM param,
                                             char *value
);

/*! @brief acvp_enable_rsa_primes_parm() allows an application to specify
        RSA key generation provable or probable primes parameters for use
        during a test session with the ACVP server.

        The function behaves similarly to acvp_enable_rsa_cap_parm() and
        acvp_enable_rsa_*_exp_parm() but allows for a modulo and hash
        algorithm parameter to be specified alongside the provable or
        probable parameter.

   @param ctx Address of pointer to a previously allocated ACVP_CTX.
   @param cipher ACVP_CIPHER enum value identifying the crypto capability.
   @param mode ACVP_RSA_MODE enum value specifying mode. In this case it
       will always be ACVP_RSA_MODE_KEYGEN
   @param param ACVP_RSA_PARM enum value identifying the algorithm parameter
       being specified. Here, it will be one of: ACVP_CAPS_PROV_PRIME,
       ACVP_CAPS_PROB_PRIME, or ACVP_CAPS_PROV_PROB_PRIME
   @param mod Supported RSA modulo value for probable or provable prime
       generation
   @param hash The corresponding supported hash algorithm for probable
       or provable prime generation

   @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_rsa_keygen_primes_parm (ACVP_CTX *ctx,
                                                ACVP_RSA_KEYGEN_MODE mode,
                                                int mod,
                                                char *name
);

/*! @brief acvp_enable_hmac_cap() allows an application to specify an
       HMAC capability to be tested by the ACVP server.

    This function should be called to enable crypto capabilities for
    hmac algorithms that will be tested by the ACVP server.  This
    includes HMAC-SHA-1, HMAC-SHA2-256, HMAC-SHA2-384, etc.  This function may be called
    multiple times to specify more than one crypto capability.

    When the application enables a crypto capability, such as HMAC-SHA-1, it
    also needs to specify a callback function that will be used by libacvp
    when that crypto capability is needed during a test session.

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param crypto_handler Address of function implemented by application that
       is invoked by libacvp when the crypto capablity is needed during
       a test session.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_hmac_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case));

/*! @brief acvp_enable_hmac_cap_parm() allows an application to specify
        operational parameters for use during a test session with the
        ACVP server.

        This function allows the application to specify parameters for use
        when registering HMAC capability with the server.

   @param ctx Address of pointer to a previously allocated ACVP_CTX.
   @param cipher ACVP_CIPHER enum value identifying the crypto capability.
   @param parm ACVP_HMAC_PARM enum value specifying parameter
   @param value Supported value for the corresponding parameter

   @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_hmac_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_HMAC_PARM parm,
        int value);

/*! @brief acvp_enable_cmac_cap() allows an application to specify an
       CMAC capability to be tested by the ACVP server.

    This function should be called to enable crypto capabilities for
    cmac algorithms that will be tested by the ACVP server.  This
    includes CMAC-AES-128, CMAC-AES-192, CMAC-AES-256, etc.  This function may be called
    multiple times to specify more than one crypto capability.

    When the application enables a crypto capability, such as CMAC-AES-128, it
    also needs to specify a callback function that will be used by libacvp
    when that crypto capability is needed during a test session.

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param crypto_handler Address of function implemented by application that
       is invoked by libacvp when the crypto capablity is needed during
       a test session.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_cmac_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case));

/*! @brief acvp_enable_cmac_cap_parm() allows an application to specify
        operational parameters for use during a test session with the
        ACVP server.

        This function allows the application to specify parameters for use
        when registering CMAC capability with the server.

   @param ctx Address of pointer to a previously allocated ACVP_CTX.
   @param cipher ACVP_CIPHER enum value identifying the crypto capability.
   @param parm ACVP_CMAC_PARM enum value specifying parameter
   @param value Supported value for the corresponding parameter

   @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_cmac_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_CMAC_PARM parm,
        int value);

/*! @brief acvp_enable_kdf135_*_cap() allows an application to specify a
       kdf cipher capability to be tested by the ACVP server.

    When the application enables a crypto capability, such as KDF135_TLS, it
    also needs to specify a callback function that will be used by libacvp
    when that crypto capability is needed during a test session.

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param crypto_handler Address of function implemented by application that
       is invoked by libacvp when the crypto capablity is needed during
       a test session.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_kdf135_tls_cap (
        ACVP_CTX *ctx,
        ACVP_KDF135_TLS_METHOD method,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case));

ACVP_RESULT acvp_enable_kdf135_snmp_cap (
        ACVP_CTX *ctx,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case));

ACVP_RESULT acvp_enable_kdf135_ssh_cap (
        ACVP_CTX *ctx,
        ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case));

/*! @brief acvp_enable_kdf135_tls_cap_parm() allows an application to specify
        operational parameters to be used during a test session with the ACVP
        server.

        This function should be called after acvp_enable_kdf135_tls_cap() to
        specify the parameters for the corresponding KDF.

   @param ctx Address of pointer to a previously allocated ACVP_CTX.
   @param cap ACVP_CIPHER enum value identifying the crypto capability, here it
        will always be ACVP_KDF135_TLS
   @param method ACVP_KDF135_TLS_METHOD enum value specifying method type
   @param param ACVP_KDF135_TLS_CAP_PARM enum value

   @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_kdf135_tls_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER cap,
        ACVP_KDF135_TLS_METHOD method,
        ACVP_KDF135_TLS_CAP_PARM param);

/*! @brief acvp_enable_kdf135_ssh_cap_parm() allows an application to specify
        operational parameters to be used during a test session with the ACVP
        server.

        This function should be called after acvp_enable_kdf135_tls_cap() to
        specify the parameters for the corresponding KDF.

   @param ctx Address of pointer to a previously allocated ACVP_CTX.
   @param cap ACVP_CIPHER enum value identifying the crypto capability, here it
        will always be ACVP_KDF135_SSH
   @param method ACVP_KDF135_SSH_METHOD enum value specifying method type
   @param param ACVP_KDF135_SSH_CAP_PARM enum value

   @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_kdf135_ssh_cap_parm (
        ACVP_CTX *ctx,
        ACVP_CIPHER cap,
        ACVP_KDF135_SSH_METHOD method,
        ACVP_KDF135_SSH_CAP_PARM param);

/*! @brief acvp_enable_prereq_cap() allows an application to specify a
       prerequisite for a cipher capability that was previously registered.

    @param ctx Address of pointer to a previously allocated ACVP_CTX.
    @param cipher ACVP_CIPHER enum value identifying the crypto capability that has a prerequisite
    @param pre_req_alg ACVP_PREREQ_ALG enum identifying the prerequisite
    @param value value for specified prerequisite

    @return ACVP_RESULT
 */

ACVP_RESULT acvp_enable_prereq_cap (
        ACVP_CTX *ctx,
        ACVP_CIPHER cipher,
        ACVP_PREREQ_ALG pre_req_cap,
        char *value);

/*! @brief acvp_create_test_session() creates a context that can be used to
      commence a test session with an ACVP server.

    This function should be called first to create a context that is used
    to manage all the API calls into libacvp.  The context should be released
    after the test session has completed by invoking acvp_free_test_session().

    When creating a new test session, a function pointer can be provided
    to receive logging messages from libacvp.  The application can then
    forward the log messages to any logging service it desires, such as
    syslog.

    @param ctx Address of pointer to unallocated ACVP_CTX.
    @param progress_cb Address of function to receive log messages from libacvp.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_create_test_session (ACVP_CTX **ctx, ACVP_RESULT (*progress_cb) (char *msg),
                                      ACVP_LOG_LVL level);

/*! @brief acvp_free_test_session() releases the memory associated with
       an ACVP_CTX.

    This function will free an ACVP_CTX.  Failure to invoke this function
    will result in a memory leak in the application layer.  This function should
    be invoked after a test session has completed and a reference to the context
    is no longer needed.

    @param ctx Pointer to ACVP_CTX that was previously created by
        calling acvp_create_test_session.
    @param level Select the debug level, see ACVP_LOG_LVL

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_free_test_session (ACVP_CTX *ctx);

/*! @brief acvp_set_server() specifies the ACVP server and TCP port
       number to use when contacting the server.

    This function is used to specify the hostname or IP address of
    the ACVP server.  The TCP port number can also be specified if the
    server doesn't use port 443.

    @param ctx Pointer to ACVP_CTX that was previously created by
        calling acvp_create_test_session.
    @param server_name Name or IP address of the ACVP server.
    @param port TCP port number the server listens on.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_server (ACVP_CTX *ctx, char *server_name, int port);

/*! @brief acvp_set_path_segment() specifies the URI prefix used by
       the ACVP server.

    Some ACVP servers use a prefix in the URI for the path to the ACVP
    REST interface.  Calling this function allows the path segment
    prefix to be specified.  The value provided to this function is
    prepended to the path segment of the URI used for the ACVP
    REST calls.

    @param ctx Pointer to ACVP_CTX that was previously created by
        calling acvp_create_test_session.
    @param path_segment Value to embed in the URI path after the server name and
       before the ACVP well-known path.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_path_segment (ACVP_CTX *ctx, char *path_segment);

/*! @brief acvp_set_cacerts() specifies PEM encoded certificates to use
       as the root trust anchors for establishing the TLS session with
       the ACVP server.

    ACVP uses TLS as the transport.  In order to verify the identity of
    the ACVP server, the TLS stack requires one or more root certificates
    that can be used to verify the identify of the ACVP TLS certificate
    during the TLS handshake.  These root certificates are set using
    this function.  They must be PEM encoded and all contained in the
    same file.

    @param ctx Pointer to ACVP_CTX that was previously created by
        calling acvp_create_test_session.
    @param ca_file Name of file containing all the PEM encoded X.509 certificates used
       as trust anchors for the TLS session.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_cacerts (ACVP_CTX *ctx, char *ca_file);

/*! @brief acvp_set_certkey() specifies PEM encoded certificate and
       private key to use for establishing the TLS session with the
       ACVP server.

    ACVP uses TLS as the transport.  In order for the ACVP server to
    verify the identity the DUT using libacvp, a certificate needs to
    be presented during the TLS handshake.  The certificate used by libacvp
    needs to be trusted by the ACVP server.  Otherwise the TLS handshake
    will fail.

    @param ctx Pointer to ACVP_CTX that was previously created by
        calling acvp_create_test_session.
    @param cert_file Name of file containing the PEM encoded X.509 certificate to
       use as the client identity.
    @param key_file Name of file containing PEM encoded private key associated with
       the client certificate.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_certkey (ACVP_CTX *ctx, char *cert_file, char *key_file);

/*! @brief acvp_mark_as_sample() marks the registration as a sample.
 
    This function sets a flag that will allow the client to retrieve
    the correct answers later on, allowing for comparison and
    debugging.
    
    @param ctx Pointer to ACVP_CTX that was previously created by
        calling acvp_create_test_session.
 */
void acvp_mark_as_sample (ACVP_CTX *ctx);

/*! @brief acvp_register() registers the DUT with the ACVP server.

    This function is used to regitser the DUT with the server.
    Registration allows the DUT to advertise it's capabilities to
    the server.  The server will respond with a set of vector set
    identifiers that the client will need to process.

    @param ctx Pointer to ACVP_CTX that was previously created by
        calling acvp_create_test_session.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_register (ACVP_CTX *ctx);

/*! @brief acvp_process_tests() performs the ACVP testing procedures.

    This function will commence the test session after the DUT has
    been registered with the ACVP server.  This function should be
    invoked after acvp_register() finishes.  When invoked, this function
    will download the vector sets from the ACVP server, process the
    vectors, and upload the results to the server.

    @param ctx Pointer to ACVP_CTX that was previously created by
        calling acvp_create_test_session.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_process_tests (ACVP_CTX *ctx);

/*! @brief acvp_set_vendor_info() specifies the vendor attributes
    for the test session.

    @param ctx Pointer to ACVP_CTX that was previously created by
        calling acvp_create_test_session.
    @param vendor_name Name of the vendor that owns the crypto module.
    @param vendor_url The Vendor's URL.
    @param contact_name Name of contact at Vendor.
    @param contact_email Email of vendor contact.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_vendor_info (ACVP_CTX *ctx,
                                  const char *vendor_name,
                                  const char *vendor_url,
                                  const char *contact_name,
                                  const char *contact_email);

/*! @brief acvp_set_module_info() specifies the crypto module attributes
    for the test session.

    @param ctx Pointer to ACVP_CTX that was previously created by
        calling acvp_create_test_session.
    @param module_name Name of the crypto module under test.
    @param module_type The crypto module type: software, hardware, or hybrid.
    @param module_version The version# of the crypto module under test.
    @param module_description A brief description of the crypto module under test.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_module_info (ACVP_CTX *ctx,
                                  const char *module_name,
                                  const char *module_type,
                                  const char *module_version,
                                  const char *module_description);

/*! @brief acvp_check_test_results() allows the application to fetch vector
        set results from the server during a test session.

   @param ctx Address of pointer to a previously allocated ACVP_CTX.

   @return ACVP_RESULT
 */
ACVP_RESULT acvp_check_test_results (ACVP_CTX *ctx);

ACVP_RESULT acvp_bin_to_hexstr (const unsigned char *src, unsigned int src_len, unsigned char *dest);

void acvp_cleanup (void);

#ifdef __cplusplus
}
#endif

#endif
