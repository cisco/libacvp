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
#ifndef acvp_lcl_h
#define acvp_lcl_h

#include "parson.h"

#define ACVP_VERSION    "0.4"

#ifndef ACVP_LOG_INFO
#define ACVP_LOG_INFO(format, args ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_INFO, "***ACVP [INFO][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
} while (0)
#endif

#ifndef ACVP_LOG_ERR
#define ACVP_LOG_ERR(format, args ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_ERR, "***ACVP [ERR][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
} while (0)
#endif

#ifndef ACVP_LOG_STATUS
#define ACVP_LOG_STATUS(format, args ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_STATUS, "***ACVP [STATUS][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
} while (0)
#endif

#ifndef ACVP_LOG_WARN
#define ACVP_LOG_WARN(format, args ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_WARN, "***ACVP [WARN][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
} while (0)
#endif

#define ACVP_ALG_MAX 57  /* Used by alg_tbl[] */

#define ACVP_ALG_AES_ECB             "AES-ECB"
#define ACVP_ALG_AES_CBC             "AES-CBC"
#define ACVP_ALG_AES_CFB1            "AES-CFB1"
#define ACVP_ALG_AES_CFB8            "AES-CFB8"
#define ACVP_ALG_AES_CFB128          "AES-CFB128"
#define ACVP_ALG_AES_OFB             "AES-OFB"
#define ACVP_ALG_AES_CTR             "AES-CTR"
#define ACVP_ALG_AES_GCM             "AES-GCM"
#define ACVP_ALG_AES_CCM             "AES-CCM"
#define ACVP_ALG_AES_XTS             "AES-XTS"
#define ACVP_ALG_AES_KW              "AES-KW"
#define ACVP_ALG_AES_KWP             "AES-KWP"
#define ACVP_ALG_TDES_OFB            "TDES-OFB"
#define ACVP_ALG_TDES_OFBI           "TDES-OFBI"
#define ACVP_ALG_TDES_CFB1           "TDES-CFB1"
#define ACVP_ALG_TDES_CFB8           "TDES-CFB8"
#define ACVP_ALG_TDES_CFB64          "TDES-CFB64"
#define ACVP_ALG_TDES_CFBP1          "TDES-CFBP1"
#define ACVP_ALG_TDES_CFBP8          "TDES-CFBP8"
#define ACVP_ALG_TDES_CFBP64         "TDES-CFBP64"
#define ACVP_ALG_TDES_ECB            "TDES-ECB"
#define ACVP_ALG_TDES_CBC            "TDES-CBC"
#define ACVP_ALG_TDES_CBCI           "TDES-CBCI"
#define ACVP_ALG_TDES_CTR            "TDES-CTR"
#define ACVP_ALG_TDES_KW             "TDES-KW"
#define ACVP_ALG_SHA1                "SHA-1"
#define ACVP_ALG_SHA224              "SHA-224"
#define ACVP_ALG_SHA256              "SHA-256"
#define ACVP_ALG_SHA384              "SHA-384"
#define ACVP_ALG_SHA512              "SHA-512"
#define ACVP_ALG_HASHDRBG            "hashDRBG"
#define ACVP_ALG_HMACDRBG            "hmacDRBG"
#define ACVP_ALG_CTRDRBG             "ctrDRBG"
#define ACVP_ALG_HMAC_SHA1           "HMAC-SHA-1"
#define ACVP_ALG_HMAC_SHA2_224       "HMAC-SHA2-224"
#define ACVP_ALG_HMAC_SHA2_256       "HMAC-SHA2-256"
#define ACVP_ALG_HMAC_SHA2_384       "HMAC-SHA2-384"
#define ACVP_ALG_HMAC_SHA2_512       "HMAC-SHA2-512"
#define ACVP_ALG_HMAC_SHA2_512_224   "HMAC-SHA2-512/224"
#define ACVP_ALG_HMAC_SHA2_512_256   "HMAC-SHA2-512/256"
#define ACVP_ALG_HMAC_SHA3_224       "HMAC-SHA3-224"
#define ACVP_ALG_HMAC_SHA3_256       "HMAC-SHA3-256"
#define ACVP_ALG_HMAC_SHA3_384       "HMAC-SHA3-384"
#define ACVP_ALG_HMAC_SHA3_512       "HMAC-SHA3-512"

#define ACVP_ALG_CMAC_AES            "CMAC-AES"
#define ACVP_ALG_CMAC_TDES           "CMAC-TDES"

#define ACVP_ALG_DSA                 "DSA2"
#define ACVP_DSA_PQGGEN              "pqgGen"

#define ACVP_ALG_RSA_KEYGEN             "keyGen"
#define ACVP_ALG_RSA_SIGGEN             "sigGen"
#define ACVP_ALG_RSA_SIGVER             "sigVer"

#define ACVP_ALG_ECDSA_KEYGEN           "keyGen"
#define ACVP_ALG_ECDSA_KEYVER           "keyVer"
#define ACVP_ALG_ECDSA_SIGGEN           "sigGen"
#define ACVP_ALG_ECDSA_SIGVER           "sigVer"

#define ACVP_PREREQ_VAL_STR "valValue"
#define ACVP_PREREQ_OBJ_STR "prereqVals"

#define ACVP_DRBG_MODE_3KEYTDEA      "3KeyTDEA"
#define ACVP_DRBG_MODE_AES_128       "AES-128"
#define ACVP_DRBG_MODE_AES_192       "AES-192"
#define ACVP_DRBG_MODE_AES_256       "AES-256"

#define ACVP_ALG_KDF135_TLS	     "KDF-TLS"
#define ACVP_ALG_KDF135_SNMP     "KDF-SNMP"
#define ACVP_ALG_KDF135_SSH      "KDF-SSH"

/*
 * The values that are supplied
 * when a client application registers are in bits, as
 * the specs specify.
 *
 * All of these values are used to allocate memory for
 * and check lengths of the character arrays that the
 * library uses in sending/receiving JSON structs in
 * an ACVP interaction.
 */
#define ACVP_SYM_KEY_MAX    64       /**< 256 bits, 64 characters */
#define ACVP_SYM_PT_MAX     16384    /**< 65536 bits, 16384 characters */
#define ACVP_SYM_CT_MAX     16384    /**< 65536 bits, 16384 characters */
#define ACVP_SYM_IV_MAX     256      /**< 1024 bits, 256 characters */
#define ACVP_SYM_TAG_MAX    32       /**< 128 bits, 32 characters */
#define ACVP_SYM_AAD_MAX    16384    /**< 65536 bits, 16384 characters */

#define ACVP_DRB_MAX             4096
#define ACVP_DRBG_ENTPY_IN_MAX   256
#define ACVP_DRBG_NONCE_MAX      256
#define ACVP_DRBG_PER_SO_MAX     256
#define ACVP_DRBG_ADDI_IN_MAX    256

#define ACVP_HASH_MSG_MAX       1024*64
#define ACVP_HASH_MD_MAX        128     /**< 512 bits, 128 characters */
#define ACVP_HASH_MCT_INNER     1000
#define ACVP_HASH_MCT_OUTER     100
#define ACVP_AES_MCT_INNER      1000
#define ACVP_AES_MCT_OUTER      100
#define ACVP_DES_MCT_INNER      10000
#define ACVP_DES_MCT_OUTER      400

#define ACVP_KDF135_TLS_MSG_MAX 1024*4
#define ACVP_KDF135_SSH_MSG_MAX 1024

#define ACVP_HMAC_MSG_MAX       1024
#define ACVP_HMAC_MAC_MAX       128       /**< 512 bits, 128 characters */
#define ACVP_HMAC_KEY_MAX       131072    /**< 524288 bits, 131072 characters */

#define ACVP_CMAC_MSG_MAX       131072    /**< 524288 bits, 131072 characters */
#define ACVP_CMAC_MAC_MAX       128       /**< 512 bits, 128 characters */
#define ACVP_CMAC_KEY_MAX       64        /**< 256 bits, 64 characters */

#define ACVP_DSA_PQG_MAX        3072     /**< 3072 bits, 768 characters */
#define ACVP_DSA_SEED_MAX       128

#define ACVP_RSA_SEEDLEN_MAX    64
#define ACVP_RSA_MSGLEN_MAX     512
#define ACVP_RSA_SIGNATURE_MAX  1024
#define ACVP_RSA_RANDPQ32_STR   "B.3.2"
#define ACVP_RSA_RANDPQ33_STR   "B.3.3"
#define ACVP_RSA_RANDPQ34_STR   "B.3.4"
#define ACVP_RSA_RANDPQ35_STR   "B.3.5"
#define ACVP_RSA_RANDPQ36_STR   "B.3.6"
#define ACVP_RSA_SIG_TYPE_LEN_MAX    9
#define ACVP_RSA_HASH_ALG_LEN_MAX    12
#define ACVP_RSA_EXP_LEN_MAX         512  /**< 2048 bits max for n, 512 characters */

#define ACVP_KAT_BUF_MAX        1024*1024*4
#define ACVP_ANS_BUF_MAX        1024*1024*4
#define ACVP_REG_BUF_MAX        1024*128
#define ACVP_RETRY_TIME_MAX     60 /* seconds */
#define ACVP_JWT_TOKEN_MAX      1024

#define ACVP_PATH_SEGMENT_DEFAULT ""

#define ACVP_CFB1_BIT_MASK      0x80

typedef struct acvp_alg_handler_t ACVP_ALG_HANDLER;

struct acvp_alg_handler_t {
    ACVP_CIPHER cipher;

    ACVP_RESULT (*handler) (ACVP_CTX *ctx, JSON_Object *obj);

    char *name;
};

typedef struct acvp_vs_list_t {
    int vs_id;
    struct acvp_vs_list_t *next;
} ACVP_VS_LIST;

/*
 * Supported length list
 */
typedef struct acvp_sl_list_t {
    int length;
    struct acvp_sl_list_t *next;
} ACVP_SL_LIST;

typedef struct acvp_prereq_alg_val {
    ACVP_PREREQ_ALG alg;
    char *val;
} ACVP_PREREQ_ALG_VAL;

typedef struct acvp_prereq_list {
    ACVP_PREREQ_ALG_VAL prereq_alg_val;
    struct acvp_prereq_list *next;
} ACVP_PREREQ_LIST;

typedef struct acvp_sym_cipher_capability {
    ACVP_SYM_CIPH_DIR direction;
    ACVP_SYM_CIPH_KO keying_option;
    ACVP_SYM_CIPH_IVGEN_SRC ivgen_source;
    ACVP_SYM_CIPH_IVGEN_MODE ivgen_mode;
    ACVP_SL_LIST *keylen;
    ACVP_SL_LIST *ptlen;
    ACVP_SL_LIST *tweak;
    ACVP_SL_LIST *ivlen;
    ACVP_SL_LIST *aadlen;
    ACVP_SL_LIST *taglen;
    int kw_mode;
} ACVP_SYM_CIPHER_CAP;

typedef struct acvp_hash_capability {
    int in_bit;
    int in_empty;
} ACVP_HASH_CAP;

typedef struct acvp_kdf135_tls_capability {
    int method[2];
    int sha;
} ACVP_KDF135_TLS_CAP;

typedef struct acvp_kdf135_snmp_capability {

} ACVP_KDF135_SNMP_CAP;

typedef struct acvp_kdf135_ssh_capability {
    int method[4];
    int sha;
} ACVP_KDF135_SSH_CAP;

typedef struct acvp_hmac_capability {
    int key_len_min;      // 8-524288
    int key_len_max;      // 8-524288
    ACVP_SL_LIST *mac_len;         // 32-512
} ACVP_HMAC_CAP;

typedef struct acvp_cmac_capability {
    int direction_gen; // boolean
    int direction_ver; // boolean
    ACVP_SL_LIST *mac_len;
    ACVP_SL_LIST *key_len; // 128,192,256
    ACVP_SL_LIST *keying_option; // 1 or 2
    int msg_len[5];
} ACVP_CMAC_CAP;

typedef struct acvp_drbg_cap_mode {
    ACVP_DRBG_MODE mode;        //"3KeyTDEA",
    int der_func_enabled;       // boolean
    ACVP_PREREQ_LIST *prereq_vals;
    int pred_resist_enabled;    // boolean
    int reseed_implemented;     // boolean
    int entropy_input_len;      //":"112",
    int entropy_len_max;
    int entropy_len_min;
    int entropy_len_step;
    int nonce_len;              //":"56",
    int nonce_len_max;
    int nonce_len_min;
    int nonce_len_step;
    int perso_string_len;       //":"0",
    int perso_len_max;
    int perso_len_min;
    int perso_len_step;
    int additional_input_len;   //":"0",
    int additional_in_len_max;
    int additional_in_len_min;
    int additional_in_len_step;
    int returned_bits_len;      //":"256"
} ACVP_DRBG_CAP_MODE;

typedef struct acvp_cap_mode_list_t {
    ACVP_DRBG_CAP_MODE cap_mode;
    struct acvp_cap_mode_list_t *next;
} ACVP_DRBG_CAP_MODE_LIST;

typedef struct acvp_drbg_capability {
    ACVP_CIPHER cipher;
    ACVP_DRBG_CAP_MODE_LIST *drbg_cap_mode_list;
} ACVP_DRBG_CAP;

struct acvp_drbg_mode_name_t {
    ACVP_DRBG_MODE mode;
    char *name;
};

/*
 * list of strings to be used for supported algs,
 * prime_tests, etc.
 */
typedef struct acvp_name_list_t {
    char *name;
    struct acvp_name_list_t *next;
} ACVP_NAME_LIST;

typedef struct acvp_rsa_hash_pair_list {
    char *name;
    int salt;
    struct acvp_rsa_hash_pair_list *next;
} ACVP_RSA_HASH_PAIR_LIST;

typedef struct acvp_rsa_mode_caps_list {
    int modulo; // 2048, 3072, 4096 -- defined as macros
    int salt; // only valid for siggen mode
    ACVP_NAME_LIST *hash_algs;
    ACVP_RSA_HASH_PAIR_LIST *hash_pair;
    ACVP_NAME_LIST *prime_tests;
    struct acvp_rsa_mode_caps_list *next;
} ACVP_RSA_MODE_CAPS_LIST;

typedef struct acvp_rsa_keygen_capability_t {
    int key_format_crt;                     // if false, key format is assumed to be standard
    int pub_exp_mode;                             // 0 - random, 1 - fixed
    unsigned char *fixed_pub_exp;               // hex value of e
    ACVP_RSA_KEYGEN_MODE rand_pq;        // as defined in FIPS186-4
    char *rand_pq_str;
    int info_gen_by_server;                  // boolean
    ACVP_RSA_MODE_CAPS_LIST *mode_capabilities;
    struct acvp_rsa_keygen_capability_t *next; // to support multiple randPQ values
} ACVP_RSA_KEYGEN_CAP;

typedef enum acvp_ecdsa_curves {
    ACVP_ECDSA_CURVE_START = 0,
    ACVP_ECDSA_CURVE_P192,
    ACVP_ECDSA_CURVE_P224,
    ACVP_ECDSA_CURVE_P256,
    ACVP_ECDSA_CURVE_P384,
    ACVP_ECDSA_CURVE_P521,
    ACVP_ECDSA_CURVE_B163,
    ACVP_ECDSA_CURVE_B233,
    ACVP_ECDSA_CURVE_B283,
    ACVP_ECDSA_CURVE_B409,
    ACVP_ECDSA_CURVE_B571,
    ACVP_ECDSA_CURVE_K163,
    ACVP_ECDSA_CURVE_K233,
    ACVP_ECDSA_CURVE_K283,
    ACVP_ECDSA_CURVE_K409,
    ACVP_ECDSA_CURVE_K571,
    ACVP_ECDSA_CURVE_END
} ACVP_ECDSA_CURVE;

typedef struct acvp_ecdsa_capability_t {
    ACVP_NAME_LIST *curves;
    ACVP_NAME_LIST *secret_gen_modes;
    ACVP_NAME_LIST *hash_algs;
} ACVP_ECDSA_CAP;

typedef struct acvp_rsa_sig_capability_t {
    char *sig_type_str;
    int sig_type;
    int pub_exp_mode; // for sigVer only
    unsigned char *fixed_pub_exp; // hex value of e
    ACVP_RSA_MODE_CAPS_LIST *mode_capabilities; //holds modRSASigGen (int) and hashSigGen (list)
    struct acvp_rsa_sig_capability_t *next;
} ACVP_RSA_SIG_CAP;


typedef struct acvp_dsa_pqggen_attrs {
    int modulo;
    int sha;
    struct acvp_dsa_pqggen_attrs *next;
} ACVP_DSA_PQGGEN_ATTRS;

#define ACVP_DSA_MAX_MODES 5
typedef struct acvp_dsa_cap_mode_t {
    ACVP_DSA_MODE cap_mode;
    int gen_pq_prob;
    int gen_pq_prov;
    int gen_g_unv;
    int gen_g_can;
    union {
        ACVP_DSA_PQGGEN_ATTRS *pqggen;
    } cap_mode_attrs;
} ACVP_DSA_CAP_MODE;

typedef struct acvp_dsa_capability {
    ACVP_CIPHER cipher;
    ACVP_DSA_CAP_MODE *dsa_cap_mode;
} ACVP_DSA_CAP;

typedef struct acvp_caps_list_t {
    ACVP_CIPHER cipher;
    ACVP_CAP_TYPE cap_type;
    int has_prereq;    /* used to indicate algorithm can have prereqs */
    ACVP_PREREQ_LIST *prereq_vals;
    union {
        ACVP_SYM_CIPHER_CAP *sym_cap;
        ACVP_HASH_CAP *hash_cap;
        ACVP_DRBG_CAP *drbg_cap;
        ACVP_DSA_CAP *dsa_cap;
        ACVP_HMAC_CAP *hmac_cap;
        ACVP_CMAC_CAP *cmac_cap;
        ACVP_RSA_KEYGEN_CAP *rsa_keygen_cap;
        ACVP_RSA_SIG_CAP *rsa_siggen_cap;
        ACVP_RSA_SIG_CAP *rsa_sigver_cap;
        ACVP_ECDSA_CAP *ecdsa_keygen_cap;
        ACVP_ECDSA_CAP *ecdsa_keyver_cap;
        ACVP_ECDSA_CAP *ecdsa_siggen_cap;
        ACVP_ECDSA_CAP *ecdsa_sigver_cap;
        ACVP_KDF135_TLS_CAP *kdf135_tls_cap;
        ACVP_KDF135_SNMP_CAP *kdf135_snmp_cap;
        ACVP_KDF135_SSH_CAP *kdf135_ssh_cap;
    } cap;

    ACVP_RESULT (*crypto_handler) (ACVP_TEST_CASE *test_case);

    struct acvp_caps_list_t *next;
} ACVP_CAPS_LIST;

/*
 * This struct holds all the global data for a test session, such
 * as the server name, port#, etc.  Some of the values in this
 * struct are transitory and used during the JSON parsing and
 * vector processing logic.
 */
struct acvp_ctx_t {
    /* Global config values for the session */
    ACVP_LOG_LVL debug;
    char *server_name;
    char *path_segment;
    int server_port;
    char *cacerts_file;     /* Location of CA certificates Curl will use to verify peer */
    int verify_peer;        /* enables TLS peer verification via Curl */
    char *tls_cert;         /* Location of PEM encoded X509 cert to use for TLS client auth */
    char *tls_key;          /* Location of PEM encoded priv key to use for TLS client auth */
    char *vendor_name;
    char *vendor_url;
    char *contact_name;
    char *contact_email;
    char *module_name;
    char *module_type;
    char *module_version;
    char *module_desc;
    
    int is_sample;

    /* test session data */
    ACVP_VS_LIST *vs_list;
    char *jwt_token; /* access_token provided by server for authenticating REST calls */

    /* crypto module capabilities list */
    ACVP_CAPS_LIST *caps_list;

    /* application callbacks */
    ACVP_RESULT (*test_progress_cb) (char *msg);

    /* Transitory values */
    char *reg_buf;    /* holds the JSON registration response */
    char *kat_buf;    /* holds the current set of vectors being processed */
    char *upld_buf;   /* holds the HTTP response from server when uploading results */
    JSON_Value *kat_resp;   /* holds the current set of vector responses */
    int read_ctr;            /* used during curl processing */
    int vs_id;               /* vs_id currently being processed */
    char *ans_buf;    /* holds the queried answers on a sample registration */
};

ACVP_RESULT acvp_send_register (ACVP_CTX *ctx, char *reg);

ACVP_RESULT acvp_retrieve_sample_answers (ACVP_CTX *ctx, int vs_id);

ACVP_RESULT acvp_retrieve_vector_set (ACVP_CTX *ctx, int vs_id);

ACVP_RESULT acvp_retrieve_vector_set_result (ACVP_CTX *ctx, int vs_id);

ACVP_RESULT acvp_submit_vector_responses (ACVP_CTX *ctx);

void acvp_log_msg (ACVP_CTX *ctx, ACVP_LOG_LVL level, const char *format, ...);

ACVP_RESULT acvp_hexstr_to_bin (const unsigned char *src, unsigned char *dest, int dest_max);

ACVP_RESULT acvp_bin_to_bit (const unsigned char *in, int len, unsigned char *out);

ACVP_RESULT acvp_bit_to_bin (const unsigned char *in, int len, unsigned char *out);

/*
 * These are the handler routines for each KAT operation
 */
ACVP_RESULT acvp_retry_handler (ACVP_CTX *ctx, unsigned int retry_period);

ACVP_RESULT acvp_aes_kat_handler (ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_des_kat_handler (ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_entropy_handler (ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_hash_kat_handler (ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_drbg_kat_handler (ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_hmac_kat_handler (ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_cmac_kat_handler (ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_rsa_keygen_kat_handler (ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_ecdsa_kat_handler (ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_rsa_sig_kat_handler (ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kdf135_tls_kat_handler (ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kdf135_snmp_kat_handler (ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kdf135_ssh_kat_handler (ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_dsa_kat_handler (ACVP_CTX *ctx, JSON_Object *obj);

/*
 * ACVP utility functions used internally
 */
ACVP_CAPS_LIST *acvp_locate_cap_entry (ACVP_CTX *ctx, ACVP_CIPHER cipher);

char *acvp_lookup_cipher_name (ACVP_CIPHER alg);

ACVP_CIPHER acvp_lookup_cipher_index (const char *algorithm);

ACVP_DRBG_MODE acvp_lookup_drbg_mode_index (const char *mode);

ACVP_DRBG_CAP_MODE_LIST *acvp_locate_drbg_mode_entry (ACVP_CAPS_LIST *cap, ACVP_DRBG_MODE mode);

char *acvp_lookup_rsa_randpq_name (int value);

int acvp_lookup_rsa_randpq_index (char *value);

unsigned int yes_or_no (ACVP_CTX *ctx, const char *text);

ACVP_RESULT acvp_create_array (JSON_Object **obj, JSON_Value **val, JSON_Array **arry);

ACVP_RESULT is_valid_tf_param (unsigned int value);

ACVP_RESULT is_valid_hash_alg (char *value);

ACVP_RESULT is_valid_prime_test (char *value);

ACVP_RESULT is_valid_rsa_mod (int value);

void ctr64_inc(unsigned char *counter);
void ctr128_inc(unsigned char *counter);
#endif
