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

#define ACVP_VERSION    "0.5"
#define ACVP_LIBRARY_VERSION    "libacvp-1.0.0"

#ifndef ACVP_LOG_INFO
#ifdef WIN32
#define ACVP_LOG_INFO(format, ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_INFO, "***ACVP [INFO][%s:%d]--> " format "\n", \
                     __func__, __LINE__, __VA_ARGS__); \
} while (0)
#else
#define ACVP_LOG_INFO(format, args ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_INFO, "***ACVP [INFO][%s:%d]--> " format "\n", \
                     __func__, __LINE__, ##args); \
} while (0)
#endif
#endif

#ifndef ACVP_LOG_ERR
#ifdef WIN32
#define ACVP_LOG_ERR(format, ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_ERR, "***ACVP [ERR][%s:%d]--> " format "\n", \
                     __func__, __LINE__, __VA_ARGS__); \
} while (0)
#else
#define ACVP_LOG_ERR(format, args ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_ERR, "***ACVP [ERR][%s:%d]--> " format "\n", \
                     __func__, __LINE__, ##args); \
} while (0)
#endif
#endif

#ifndef ACVP_LOG_STATUS
#ifdef WIN32
#define ACVP_LOG_STATUS(format, ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_STATUS, "***ACVP [STATUS][%s:%d]--> " format "\n", \
                     __func__, __LINE__, __VA_ARGS__); \
} while (0)
#else
#define ACVP_LOG_STATUS(format, args ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_STATUS, "***ACVP [STATUS][%s:%d]--> " format "\n", \
                     __func__, __LINE__, ##args); \
} while (0)
#endif
#endif

#ifndef ACVP_LOG_WARN
#ifdef WIN32
#define ACVP_LOG_WARN(format, ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_WARN, "***ACVP [WARN][%s:%d]--> " format "\n", \
                     __func__, __LINE__, __VA_ARGS__); \
} while (0)
#else
#define ACVP_LOG_WARN(format, args ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_WARN, "***ACVP [WARN][%s:%d]--> " format "\n", \
                     __func__, __LINE__, ##args); \
} while (0)
#endif
#endif

#define ACVP_BIT2BYTE(x) ((x + 7) >> 3) /**< Convert bit length (x, of type integer) into byte length */

#define ACVP_ALG_MAX ACVP_CIPHER_END - 1  /* Used by alg_tbl[] */

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
#define ACVP_ALG_SHA224              "SHA2-224"
#define ACVP_ALG_SHA256              "SHA2-256"
#define ACVP_ALG_SHA384              "SHA2-384"
#define ACVP_ALG_SHA512              "SHA2-512"
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

#define ACVP_MODE_AES_128            "AES-128"
#define ACVP_MODE_TDES "TDES"
#define ACVP_MODE_AES_192 "AES-192"
#define ACVP_MODE_AES_256 "AES-256"

#define ACVP_ALG_CMAC_AES            "CMAC-AES"
#define ACVP_ALG_CMAC_AES_128        "CMAC-AES128"
#define ACVP_ALG_CMAC_AES_192        "CMAC-AES192"
#define ACVP_ALG_CMAC_AES_256        "CMAC-AES256"
#define ACVP_ALG_CMAC_TDES           "CMAC-TDES"

#define ACVP_ALG_DSA                 "DSA"
#define ACVP_ALG_DSA_PQGGEN          "pqgGen"
#define ACVP_ALG_DSA_PQGVER          "pqgVer"
#define ACVP_ALG_DSA_KEYGEN          "keyGen"
#define ACVP_ALG_DSA_SIGGEN          "sigGen"
#define ACVP_ALG_DSA_SIGVER          "sigVer"

#define ACVP_ALG_KAS_ECC_CDH         "CDH-Component"
#define ACVP_ALG_KAS_ECC_COMP        "Component"
#define ACVP_ALG_KAS_ECC_NOCOMP      ""

#define ACVP_ALG_KAS_ECC             "KAS-ECC"
#define ACVP_ALG_KAS_ECC_DPGEN       "dpGen"
#define ACVP_ALG_KAS_ECC_DPVAL       "dpVal"
#define ACVP_ALG_KAS_ECC_KEYPAIRGEN  "keyPairGen"
#define ACVP_ALG_KAS_ECC_FULLVAL     "fullVal"
#define ACVP_ALG_KAS_ECC_PARTIALVAL  "partialVal"
#define ACVP_ALG_KAS_ECC_KEYREGEN    "keyRegen"

#define ACVP_ALG_KAS_FFC_COMP        "Component"
#define ACVP_ALG_KAS_FFC_NOCOMP      ""

#define ACVP_ALG_KAS_FFC             "KAS-FFC"
#define ACVP_ALG_KAS_FFC_DPGEN       "dpGen"
#define ACVP_ALG_KAS_FFC_MQV2        "MQV2"
#define ACVP_ALG_KAS_FFC_KEYPAIRGEN  "keyPairGen"
#define ACVP_ALG_KAS_FFC_FULLVAL     "fullVal"
#define ACVP_ALG_KAS_FFC_KEYREGEN    "keyRegen"

#define ACVP_ECDSA_EXTRA_BITS_STR "extra bits"
#define ACVP_ECDSA_TESTING_CANDIDATES_STR "testing candidates"

#define ACVP_RSA_PRIME_TEST_TBLC2_STR "tblC2"
#define ACVP_RSA_PRIME_TEST_TBLC3_STR "tblC3"

#define ACVP_RSA_SIG_TYPE_X931_STR      "ansx9.31"
#define ACVP_RSA_SIG_TYPE_PKCS1V15_STR  "pkcs1v1.5"
#define ACVP_RSA_SIG_TYPE_PKCS1PSS_STR  "pss"

#define ACVP_ALG_RSA                "RSA"
#define ACVP_ALG_ECDSA              "ECDSA"

#define ACVP_MODE_KEYGEN            "keyGen"
#define ACVP_MODE_KEYVER            "keyVer"
#define ACVP_MODE_SIGGEN            "sigGen"
#define ACVP_MODE_SIGVER            "sigVer"
#define ACVP_MODE_COUNTER           "counter"
#define ACVP_MODE_FEEDBACK          "feedback"
#define ACVP_MODE_DPI               "double pipeline iteration"
#define ACVP_KDF135_ALG_STR         "kdf-components"

#define ACVP_AUTH_METHOD_DSA_STR "dsa"
#define ACVP_AUTH_METHOD_PSK_STR "psk"
#define ACVP_AUTH_METHOD_PKE_STR "pke"
#define ACVP_AUTH_METHOD_STR_MAX 3
#define ACVP_AUTH_METHOD_STR_MAX_PLUS 4

#define ACVP_FIXED_DATA_ORDER_AFTER_STR "after fixed data"
#define ACVP_FIXED_DATA_ORDER_BEFORE_STR "before fixed data"
#define ACVP_FIXED_DATA_ORDER_MIDDLE_STR "middle fixed data"
#define ACVP_FIXED_DATA_ORDER_NONE_STR "none"
#define ACVP_FIXED_DATA_ORDER_BEFORE_ITERATOR_STR "before iterator"

#define ACVP_PREREQ_VAL_STR "valValue"
#define ACVP_PREREQ_OBJ_STR "prereqVals"

#define ACVP_DRBG_MODE_3KEYTDEA      "3KeyTDEA"
#define ACVP_DRBG_MODE_AES_128       "AES-128"
#define ACVP_DRBG_MODE_AES_192       "AES-192"
#define ACVP_DRBG_MODE_AES_256       "AES-256"

#define ACVP_ALG_KDF135_TLS          "tls"
#define ACVP_ALG_KDF135_SNMP     "snmp"
#define ACVP_ALG_KDF135_SSH      "ssh"
#define ACVP_ALG_KDF135_SRTP     "srtp"
#define ACVP_ALG_KDF135_IKEV2    "ikev2"
#define ACVP_ALG_KDF135_IKEV1    "ikev1"
#define ACVP_ALG_KDF135_TPM      "KDF-TPM"
#define ACVP_ALG_KDF108          "KDF"
#define ACVP_ALG_KDF135_X963     "ansix9.63"

#define ACVP_CAPABILITY_STR_MAX 512 /**< Arbitrary string length limit */

/*
 *  Defines the key lengths and block lengths (in bytes)
 *  of symmetric block ciphers.
 */
#define ACVP_KEY_LEN_TDES 24
#define ACVP_KEY_LEN_AES128 16
#define ACVP_KEY_LEN_AES192 24
#define ACVP_KEY_LEN_AES256 32
#define ACVP_BLOCK_LEN_TDES 8
#define ACVP_BLOCK_LEN_AES128 16 /**< 16 byte block size regardless of mode */
#define ACVP_BLOCK_LEN_AES192 16 /**< 16 byte block size regardless of mode */
#define ACVP_BLOCK_LEN_AES256 16 /**< 16 byte block size regardless of mode */

/*
 * Hash algorithm output lengths (in bytes).
 */
#define ACVP_SHA1_BYTE_LEN 20
#define ACVP_SHA224_BYTE_LEN 28
#define ACVP_SHA256_BYTE_LEN 32
#define ACVP_SHA384_BYTE_LEN 48
#define ACVP_SHA512_BYTE_LEN 64

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
#define ACVP_SYM_KEY_MAX_STR 128
#define ACVP_SYM_KEY_MAX_BYTES 64       /**< 256 bits, 64 characters */
#define ACVP_SYM_KEY_MAX_BITS 256

#define ACVP_SYM_PT_BIT_MAX 131072                      /**< 131072 bits */
#define ACVP_SYM_PT_MAX (ACVP_SYM_PT_BIT_MAX >> 2)      /**< 32768 characters */
#define ACVP_SYM_PT_BYTE_MAX (ACVP_SYM_PT_BIT_MAX >> 3) /**< 16384 bytes */

#define ACVP_SYM_CT_BIT_MAX 131072                      /**< 131072 bits */
#define ACVP_SYM_CT_MAX (ACVP_SYM_CT_BIT_MAX >> 2)      /**< 32768 characters */
#define ACVP_SYM_CT_BYTE_MAX (ACVP_SYM_CT_BIT_MAX >> 3) /**< 16384 bytes */

#define ACVP_SYM_IV_BIT_MAX 1024                        /**< 1024 bits */
#define ACVP_SYM_IV_MAX (ACVP_SYM_IV_BIT_MAX >> 2)      /**< 256 characters */
#define ACVP_SYM_IV_BYTE_MAX (ACVP_SYM_IV_BIT_MAX >> 3) /**< 128 bytes */

#define ACVP_SYM_TAG_BIT_MIN 4                            /**< 128 bits */
#define ACVP_SYM_TAG_BIT_MAX 128                          /**< 128 bits */
#define ACVP_SYM_TAG_MAX (ACVP_SYM_TAG_BIT_MAX >> 2)      /**< 32 characters */
#define ACVP_SYM_TAG_BYTE_MAX (ACVP_SYM_TAG_BIT_MAX >> 3) /**< 16 bytes */

#define ACVP_SYM_AAD_BIT_MAX 65536                        /**< 65536 bits */
#define ACVP_SYM_AAD_MAX (ACVP_SYM_AAD_BIT_MAX >> 2)      /**< 16384 characters */
#define ACVP_SYM_AAD_BYTE_MAX (ACVP_SYM_AAD_BIT_MAX >> 3) /**< 8192 bytes */

/**
 * Accepted length ranges for DRBG.
 * https://github.com/usnistgov/ACVP/blob/master/artifacts/acvp_sub_drbg.txt
 */
#define ACVP_DRB_BIT_MAX 4096
#define ACVP_DRB_BYTE_MAX (ACVP_DRB_BIT_MAX >> 3)
#define ACVP_DRB_STR_MAX (ACVP_DRB_BIT_MAX >> 2)

#define ACVP_DRBG_ENTPY_IN_BIT_MIN 80
#define ACVP_DRBG_ENTPY_IN_BIT_MAX 1048576 /**< 2^20 library limit. Spec allows 2^35 */
#define ACVP_DRBG_ENTPY_IN_BYTE_MAX (ACVP_DRBG_ENTPY_IN_BIT_MAX >> 3)
#define ACVP_DRBG_ENTPY_IN_STR_MAX (ACVP_DRBG_ENTPY_IN_BIT_MAX >> 2)

#define ACVP_DRBG_NONCE_BIT_MIN 40
#define ACVP_DRBG_NONCE_BIT_MAX 512
#define ACVP_DRBG_NONCE_BYTE_MAX (ACVP_DRBG_NONCE_BIT_MAX >> 3)
#define ACVP_DRBG_NONCE_STR_MAX (ACVP_DRBG_NONCE_BIT_MAX >> 2)

#define ACVP_DRBG_PER_SO_BIT_MAX 1048576 /**< 2^20 library limit. Spec allows 2^35 */
#define ACVP_DRBG_PER_SO_BYTE_MAX (ACVP_DRBG_PER_SO_BIT_MAX >> 3)
#define ACVP_DRBG_PER_SO_STR_MAX (ACVP_DRBG_PER_SO_BIT_MAX >> 2)

#define ACVP_DRBG_ADDI_IN_BIT_MAX 1048576 /**< 2^20 library limit. Spec allows 2^35 */
#define ACVP_DRBG_ADDI_IN_BYTE_MAX (ACVP_DRBG_ADDI_IN_BIT_MAX >> 3)
#define ACVP_DRBG_ADDI_IN_STR_MAX (ACVP_DRBG_ADDI_IN_BIT_MAX >> 2)
/*
 * END DRBG
 */

#define ACVP_HASH_MSG_BIT_MAX 102400                        /**< 102400 bits */
#define ACVP_HASH_MSG_STR_MAX (ACVP_HASH_MSG_BIT_MAX >> 2)  /**< 25600 characters */
#define ACVP_HASH_MSG_BYTE_MAX (ACVP_HASH_MSG_BIT_MAX >> 3) /**< 12800 bytes */
#define ACVP_HASH_MD_BIT_MAX 512                            /**< 512 bits */
#define ACVP_HASH_MD_STR_MAX (ACVP_HASH_MD_BIT_MAX >> 2)    /**< 128 characters */
#define ACVP_HASH_MD_BYTE_MAX (ACVP_HASH_MD_BIT_MAX >> 3)   /**< 64 bytes */

#define ACVP_HASH_MCT_INNER     1000
#define ACVP_HASH_MCT_OUTER     100
#define ACVP_AES_MCT_INNER      1000
#define ACVP_AES_MCT_OUTER      100
#define ACVP_DES_MCT_INNER      10000
#define ACVP_DES_MCT_OUTER      400

#define ACVP_TDES_KEY_BIT_LEN 192                           /**< 192 bits */
#define ACVP_TDES_KEY_STR_LEN (ACVP_TDES_KEY_BIT_LEN >> 2)  /**< 48 characters */
#define ACVP_TDES_KEY_BYTE_LEN (ACVP_TDES_KEY_BIT_LEN >> 3) /**< 24 bytes */

#define ACVP_AES_CCM_IV_BIT_MIN 56   /**< 56 bits */
#define ACVP_AES_CCM_IV_BIT_MAX 104  /**< 104 bits */
#define ACVP_AES_GCM_IV_BIT_MIN 8    /**< 8 bits */
#define ACVP_AES_GCM_IV_BIT_MAX 1024 /**< 1024 bits */

#define ACVP_KDF135_TLS_MSG_MAX 1024 * 4
#define ACVP_KDF135_SSH_EKEY_MAX (ACVP_SHA512_BYTE_LEN)            /**< Encryption Key max.
                                                                        Be able to hold largest sha size, although
                                                                        actual key is a subset (up to 32 bytes).
                                                                        512 bits, 64 bytes */
#define ACVP_KDF135_SSH_IKEY_MAX (ACVP_SHA512_BYTE_LEN)            /**< Integrity Key max
                                                                        512 bits, 64 bytes */
#define ACVP_KDF135_SSH_IV_MAX (ACVP_SHA512_BYTE_LEN)              /**< Initial IV key max
                                                                        Be able to hold largest sha size, although
                                                                        actual IV is a subset (up to 16 bytes).
                                                                        512 bits, 64 bytes */
#define ACVP_KDF135_SSH_STR_OUT_MAX (ACVP_KDF135_SSH_IKEY_MAX * 2) /**< 128 characters */
#define ACVP_KDF135_SSH_STR_IN_MAX 4096                            /**< 4096 characters, needs to accomodate large shared_secret (K) */

/**
 * Accepted length ranges for KDF135_SRTP.
 * https://github.com/usnistgov/ACVP/blob/master/artifacts/acvp_sub_kdf135_srtp.txt
 */
#define ACVP_KDF135_SRTP_KDR_MAX 24
#define ACVP_KDF135_SRTP_KDR_STR_MAX 13
#define ACVP_KDF135_SRTP_MASTER_MAX 65
#define ACVP_KDF135_SRTP_INDEX_MAX 32
#define ACVP_KDF135_SRTP_OUTPUT_MAX 64

#define ACVP_KDF135_TLS_PMSECRET_BIT_MAX (384)
#define ACVP_KDF135_TLS_PMSECRET_BYTE_MAX (ACVP_KDF135_TLS_PMSECRET_BIT_MAX >> 3)
#define ACVP_KDF135_TLS_PMSECRET_STR_MAX (ACVP_KDF135_TLS_PMSECRET_BIT_MAX >> 2)

/**
 * Accepted length ranges for KDF135_X963.
 * https://github.com/usnistgov/ACVP/blob/master/artifacts/acvp_sub_kdf135_x963.txt
 */
#define ACVP_KDF135_X963_KEYDATA_MIN_BITS 128
#define ACVP_KDF135_X963_KEYDATA_MAX_BITS 4096
#define ACVP_KDF135_X963_KEYDATA_MAX_BYTES (ACVP_KDF135_X963_KEYDATA_MAX_BITS) / 8
#define ACVP_KDF135_X963_INPUT_MAX 1024 / 8
#define ACVP_KDF135_X963_FIELD_SIZE_224 224
#define ACVP_KDF135_X963_FIELD_SIZE_233 233
#define ACVP_KDF135_X963_FIELD_SIZE_256 256
#define ACVP_KDF135_X963_FIELD_SIZE_283 283
#define ACVP_KDF135_X963_FIELD_SIZE_384 384
#define ACVP_KDF135_X963_FIELD_SIZE_409 409
#define ACVP_KDF135_X963_FIELD_SIZE_521 521
#define ACVP_KDF135_X963_FIELD_SIZE_571 571
#define ACVP_KDF135_X963_SHARED_INFO_LEN_MAX 1024
#define ACVP_KDF135_X963_SHARED_INFO_LEN_MIN 0

/**
 * Accepted length ranges for KDF135_SNMP.
 * https://github.com/usnistgov/ACVP/blob/master/artifacts/acvp_sub_kdf135_snmp.txt
 */
#define ACVP_KDF135_SNMP_PASS_LEN_MIN 64
#define ACVP_KDF135_SNMP_PASS_LEN_MAX 8192

/**
 * Accepted length ranges for KDF135_IKEV1.
 * https://github.com/usnistgov/ACVP/blob/master/artifacts/acvp_sub_kdf135_ikev1.txt
 */
#define ACVP_KDF135_IKEV1_COOKIE_STR_MAX 32
#define ACVP_KDF135_IKEV1_COOKIE_BYTE_MAX (ACVP_KDF135_IKEV1_COOKIE_STR_MAX / 2)

#define ACVP_KDF135_IKEV1_SKEY_BYTE_MAX 64 /**< SHA512 byte length */
#define ACVP_KDF135_IKEV1_SKEY_STR_MAX 128 /**< SHA512 hex length */

#define ACVP_KDF135_IKEV1_INIT_NONCE_BIT_MIN 64
#define ACVP_KDF135_IKEV1_INIT_NONCE_BIT_MAX 2048
#define ACVP_KDF135_IKEV1_INIT_NONCE_BYTE_MAX (ACVP_KDF135_IKEV1_INIT_NONCE_BIT_MAX >> 3)
#define ACVP_KDF135_IKEV1_INIT_NONCE_STR_MAX (ACVP_KDF135_IKEV1_INIT_NONCE_BIT_MAX >> 2)

#define ACVP_KDF135_IKEV1_RESP_NONCE_BIT_MIN 64
#define ACVP_KDF135_IKEV1_RESP_NONCE_BIT_MAX 2048
#define ACVP_KDF135_IKEV1_RESP_NONCE_BYTE_MAX (ACVP_KDF135_IKEV1_RESP_NONCE_BIT_MAX >> 3)
#define ACVP_KDF135_IKEV1_RESP_NONCE_STR_MAX (ACVP_KDF135_IKEV1_RESP_NONCE_BIT_MAX >> 2)

#define ACVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MIN 224
#define ACVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MAX 8192
#define ACVP_KDF135_IKEV1_DH_SHARED_SECRET_BYTE_MAX (ACVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MAX >> 3)
#define ACVP_KDF135_IKEV1_DH_SHARED_SECRET_STR_MAX (ACVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MAX >> 2)

#define ACVP_KDF135_IKEV1_PSK_BIT_MIN 8
#define ACVP_KDF135_IKEV1_PSK_BIT_MAX 8192
#define ACVP_KDF135_IKEV1_PSK_BYTE_MAX (ACVP_KDF135_IKEV1_PSK_BIT_MAX >> 3)
#define ACVP_KDF135_IKEV1_PSK_STR_MAX (ACVP_KDF135_IKEV1_PSK_BIT_MAX >> 2)
/*
 * END KDF135_IKEV1
 */

/**
 * Accepted length ranges for KDF135_IKEV2.
 * https://github.com/usnistgov/ACVP/blob/master/artifacts/acvp_sub_kdf135_ikev2.txt
 */
#define ACVP_KDF135_IKEV2_SPI_STR_MAX 32
#define ACVP_KDF135_IKEV2_SPI_BYTE_MAX (ACVP_KDF135_IKEV2_SPI_STR_MAX / 2)

#define ACVP_KDF135_IKEV2_SKEY_SEED_BYTE_MAX 64 /**< SHA512 byte length */
#define ACVP_KDF135_IKEV2_SKEY_SEED_STR_MAX 128 /**< SHA512 hex length */

#define ACVP_KDF135_IKEV2_INIT_NONCE_BIT_MIN 64
#define ACVP_KDF135_IKEV2_INIT_NONCE_BIT_MAX 2048
#define ACVP_KDF135_IKEV2_INIT_NONCE_BYTE_MAX (ACVP_KDF135_IKEV2_INIT_NONCE_BIT_MAX >> 3)
#define ACVP_KDF135_IKEV2_INIT_NONCE_STR_MAX (ACVP_KDF135_IKEV2_INIT_NONCE_BIT_MAX >> 2)

#define ACVP_KDF135_IKEV2_RESP_NONCE_BIT_MIN 64
#define ACVP_KDF135_IKEV2_RESP_NONCE_BIT_MAX 2048
#define ACVP_KDF135_IKEV2_RESP_NONCE_BYTE_MAX (ACVP_KDF135_IKEV2_RESP_NONCE_BIT_MAX >> 3)
#define ACVP_KDF135_IKEV2_RESP_NONCE_STR_MAX (ACVP_KDF135_IKEV2_RESP_NONCE_BIT_MAX >> 2)

#define ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MIN 224
#define ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MAX 8192
#define ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BYTE_MAX (ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MAX >> 3)
#define ACVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX (ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MAX >> 2)

#define ACVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MIN 160
#define ACVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MAX 16384
#define ACVP_KDF135_IKEV2_DKEY_MATERIAL_BYTE_MAX (ACVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MAX >> 3)
#define ACVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX (ACVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MAX >> 2)
/*
 * END KDF135_IKEV2
 */

/**
 * Accepted length ranges for KDF108.
 * https://github.com/usnistgov/ACVP/blob/master/artifacts/acvp_sub_kdf108.txt
 */
#define ACVP_KDF108_KEYOUT_BIT_MIN 160 /**< SHA-1 */
#define ACVP_KDF108_KEYOUT_BIT_MAX 512 /**< SHA2-512 */
#define ACVP_KDF108_KEYOUT_BYTE_MAX (ACVP_KDF108_KEYOUT_BIT_MAX >> 3)
#define ACVP_KDF108_KEYOUT_STR_MAX (ACVP_KDF108_KEYOUT_BIT_MAX >> 2)

#define ACVP_KDF108_KEYIN_BIT_MAX 4096 /**< Based on supportedLengths */
#define ACVP_KDF108_KEYIN_BYTE_MAX (ACVP_KDF108_KEYIN_BIT_MAX >> 3)
#define ACVP_KDF108_KEYIN_STR_MAX (ACVP_KDF108_KEYIN_BIT_MAX >> 2)

#define ACVP_KDF108_IV_BIT_MAX 512 /**< SHA2-512 */
#define ACVP_KDF108_IV_BYTE_MAX (ACVP_KDF108_IV_BIT_MAX >> 3)
#define ACVP_KDF108_IV_STR_MAX (ACVP_KDF108_IV_BIT_MAX >> 2)

#define ACVP_KDF108_FIXED_DATA_BIT_MAX 512 /**< Arbitrary */
#define ACVP_KDF108_FIXED_DATA_BYTE_MAX (ACVP_KDF108_FIXED_DATA_BIT_MAX >> 3)
#define ACVP_KDF108_FIXED_DATA_STR_MAX (ACVP_KDF108_FIXED_DATA_BIT_MAX >> 2)
/*
 * END KDF108
 */

#define ACVP_HMAC_MSG_MAX       1024

#define ACVP_HMAC_MAC_BIT_MIN 32  /**< 32 bits */
#define ACVP_HMAC_MAC_BIT_MAX 512 /**< 512 bits */
#define ACVP_HMAC_MAC_BYTE_MAX (ACVP_HMAC_MAC_BIT_MAX >> 3)
#define ACVP_HMAC_MAC_STR_MAX (ACVP_HMAC_MAC_BIT_MAX >> 2)

#define ACVP_HMAC_KEY_BIT_MIN 8      /**< 8 bits */
#define ACVP_HMAC_KEY_BIT_MAX 524288 /**< 524288 bits */
#define ACVP_HMAC_KEY_BYTE_MAX (ACVP_HMAC_KEY_BIT_MAX >> 3)
#define ACVP_HMAC_KEY_STR_MAX (ACVP_HMAC_KEY_BIT_MAX >> 2)

#define ACVP_CMAC_MSGLEN_MAX_STR       131072    /**< 524288 bits, 131072 characters */
#define ACVP_CMAC_MSGLEN_MAX       524288
#define ACVP_CMAC_MSGLEN_MIN       0
#define ACVP_CMAC_MACLEN_MAX       128       /**< 512 bits, 128 characters */
#define ACVP_CMAC_MACLEN_MIN       32
#define ACVP_CMAC_KEY_MAX       64        /**< 256 bits, 64 characters */

#define ACVP_DSA_PQG_MAX        3072     /**< 3072 bits, 768 characters */
#define ACVP_DSA_PQG_MAX_BYTES  (ACVP_DSA_PQG_MAX / 2)
#define ACVP_DSA_SEED_MAX       1024
#define ACVP_DSA_SEED_MAX_BYTES (ACVP_DSA_SEED_MAX / 2)
#define ACVP_DSA_MAX_STRING     3072     /**< 3072 bytes */

#define ACVP_ECDSA_EXP_LEN_MAX       512
#define ACVP_ECDSA_MSGLEN_MAX 8192

#define ACVP_KAS_FFC_BIT_MAX 4096
#define ACVP_KAS_FFC_BYTE_MAX (ACVP_KAS_FFC_BIT_MAX >> 3)
#define ACVP_KAS_FFC_STR_MAX (ACVP_KAS_FFC_BIT_MAX >> 2)

#define ACVP_KAS_ECC_BIT_MAX 4096
#define ACVP_KAS_ECC_BYTE_MAX (ACVP_KAS_ECC_BIT_MAX >> 3)
#define ACVP_KAS_ECC_STR_MAX (ACVP_KAS_ECC_BIT_MAX >> 2)

/*
 * START RSA
 */
#define ACVP_RSA_SEEDLEN_MAX    64
#define ACVP_RSA_MSGLEN_MAX     1024
#define ACVP_RSA_SIGNATURE_MAX  2048
#define ACVP_RSA_PUB_EXP_MODE_FIXED_STR "fixed"
#define ACVP_RSA_PUB_EXP_MODE_RANDOM_STR "random"
#define ACVP_RSA_KEY_FORMAT_STD_STR "standard"
#define ACVP_RSA_KEY_FORMAT_CRT_STR "crt"
#define ACVP_RSA_RANDPQ32_STR   "B.3.2"
#define ACVP_RSA_RANDPQ33_STR   "B.3.3"
#define ACVP_RSA_RANDPQ34_STR   "B.3.4"
#define ACVP_RSA_RANDPQ35_STR   "B.3.5"
#define ACVP_RSA_RANDPQ36_STR   "B.3.6"
#define ACVP_RSA_SIG_TYPE_LEN_MAX    9

#define ACVP_RSA_EXP_BIT_MAX 4096 /**< 2048 bits max for n, 512 characters */
#define ACVP_RSA_EXP_LEN_MAX (ACVP_RSA_EXP_BIT_MAX >> 2)
#define ACVP_RSA_EXP_BYTE_MAX (ACVP_RSA_EXP_BIT_MAX >> 3)

/*
 * END RSA
 */

#define ACVP_KAT_BUF_MAX        1024 * 1024 * 4
#define ACVP_ANS_BUF_MAX        1024 * 1024 * 4
#define ACVP_REG_BUF_MAX        1024 * 128
#define ACVP_RETRY_TIME_MAX     60 /* seconds */
#define ACVP_JWT_TOKEN_MAX      1024
#define ACVP_ATTR_URL_MAX       2083 /* MS IE's limit - arbitrary */

#define ACVP_SESSION_PARAMS_STR_LEN_MAX 256
#define ACVP_PATH_SEGMENT_DEFAULT ""

#define ACVP_CFB1_BIT_MASK      0x80

typedef struct acvp_alg_handler_t ACVP_ALG_HANDLER;

struct acvp_alg_handler_t {
    ACVP_CIPHER cipher;

    ACVP_RESULT (*handler) (ACVP_CTX *ctx, JSON_Object *obj);

    char *name;
    char *mode; /** < Should be NULL unless using an asymmetric alg */
};

typedef struct acvp_vs_list_t {
    int vs_id;
    struct acvp_vs_list_t *next;
} ACVP_VS_LIST;

struct acvp_result_desc_t {
    ACVP_RESULT rv;
    char *desc;
};

struct acvp_hash_alg_info {
    ACVP_HASH_ALG id;
    char *name;
};

struct acvp_ec_curve_info {
    ACVP_EC_CURVE id;
    char *name;
};

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
    ACVP_KDF135_SSH_TYPE,
    ACVP_KDF135_SRTP_TYPE,
    ACVP_KDF135_IKEV2_TYPE,
    ACVP_KDF135_IKEV1_TYPE,
    ACVP_KDF135_X963_TYPE,
    ACVP_KDF135_TPM_TYPE,
    ACVP_KDF108_TYPE,
    ACVP_KAS_ECC_CDH_TYPE,
    ACVP_KAS_ECC_COMP_TYPE,
    ACVP_KAS_ECC_NOCOMP_TYPE,
    ACVP_KAS_FFC_COMP_TYPE,
    ACVP_KAS_FFC_NOCOMP_TYPE
} ACVP_CAP_TYPE;

/*
 * Supported length list
 */
typedef struct acvp_sl_list_t {
    int length;
    struct acvp_sl_list_t *next;
} ACVP_SL_LIST;

/*
 * Supported param list
 */
typedef struct acvp_param_list_t {
    int param;
    struct acvp_param_list_t *next;
} ACVP_PARAM_LIST;

/*
 * list of STATIC strings to be used for supported algs,
 * prime_tests, etc.
 */
typedef struct acvp_name_list_t {
    char *name;
    struct acvp_name_list_t *next;
} ACVP_NAME_LIST;

/*
 * list of CALLOC'd strings to be used for supported algs,
 * vsid_url etc.
 */
typedef struct acvp_string_list_t {
    char *string;
    struct acvp_string_list_t *next;
} ACVP_STRING_LIST;

typedef struct acvp_json_domain_obj_t {
    int min;
    int max;
    int increment;
    int value; // for single values
} ACVP_JSON_DOMAIN_OBJ;

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
    unsigned int ctr_incr;
    unsigned int ctr_ovrflw;
    ACVP_SL_LIST *keylen;
    ACVP_SL_LIST *ptlen;
    ACVP_SL_LIST *tweak;
    ACVP_SL_LIST *ivlen;
    ACVP_SL_LIST *aadlen;
    ACVP_SL_LIST *taglen;
    int kw_mode;
} ACVP_SYM_CIPHER_CAP;

typedef struct acvp_hash_capability {
    int in_bit;   /* defaults to false */
    int in_empty; /* defaults to false */
} ACVP_HASH_CAP;

typedef struct acvp_kdf135_tls_capability {
    int method[2];
    int sha;
} ACVP_KDF135_TLS_CAP;

typedef struct acvp_kdf135_snmp_capability {
    ACVP_SL_LIST *pass_lens;
    ACVP_NAME_LIST *eng_ids;
} ACVP_KDF135_SNMP_CAP;

typedef struct acvp_kdf108_mode_params {
    char *kdf_mode;
    ACVP_NAME_LIST *mac_mode;
    ACVP_JSON_DOMAIN_OBJ supported_lens;
    ACVP_NAME_LIST *data_order;
    ACVP_SL_LIST *counter_lens;
    int empty_iv_support;
} ACVP_KDF108_MODE_PARAMS;

typedef struct acvp_kdf108_capability {
    ACVP_KDF108_MODE_PARAMS counter_mode;
    ACVP_KDF108_MODE_PARAMS feedback_mode;
    ACVP_KDF108_MODE_PARAMS dpi_mode;
} ACVP_KDF108_CAP;

typedef struct acvp_kdf135_ssh_capability {
    int method[4];
    int sha;
} ACVP_KDF135_SSH_CAP;

typedef struct acvp_kdf135_srtp_capability {
    int supports_zero_kdr;
    int kdr_exp[ACVP_KDF135_SRTP_KDR_MAX];
    ACVP_SL_LIST *aes_keylens;
} ACVP_KDF135_SRTP_CAP;

typedef struct acvp_kdf135_ikev2_capability {
    ACVP_NAME_LIST *hash_algs;
    ACVP_JSON_DOMAIN_OBJ init_nonce_len_domain;
    ACVP_JSON_DOMAIN_OBJ respond_nonce_len_domain;
    ACVP_JSON_DOMAIN_OBJ dh_secret_len;
    ACVP_JSON_DOMAIN_OBJ key_material_len;
} ACVP_KDF135_IKEV2_CAP;

typedef struct acvp_kdf135_ikev1_capability {
    ACVP_NAME_LIST *hash_algs;
    char auth_method[ACVP_AUTH_METHOD_STR_MAX_PLUS];
    ACVP_JSON_DOMAIN_OBJ init_nonce_len_domain;
    ACVP_JSON_DOMAIN_OBJ respond_nonce_len_domain;
    ACVP_JSON_DOMAIN_OBJ dh_secret_len;
    ACVP_JSON_DOMAIN_OBJ psk_len;
} ACVP_KDF135_IKEV1_CAP;

typedef struct acvp_kdf135_x963_capability {
    ACVP_NAME_LIST *hash_algs;
    ACVP_SL_LIST *shared_info_lengths;
    ACVP_SL_LIST *field_sizes;
    ACVP_SL_LIST *key_data_lengths;
} ACVP_KDF135_X963_CAP;

typedef struct acvp_hmac_capability {
    ACVP_JSON_DOMAIN_OBJ key_len; // 8-524288
    ACVP_JSON_DOMAIN_OBJ mac_len; // 32-512
} ACVP_HMAC_CAP;

typedef struct acvp_cmac_capability {
    ACVP_JSON_DOMAIN_OBJ mac_len;
    ACVP_JSON_DOMAIN_OBJ msg_len;
    int direction_gen;
    int direction_ver;
    ACVP_SL_LIST *key_len;       // 128,192,256
    ACVP_SL_LIST *keying_option;
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

typedef struct acvp_rsa_hash_pair_list {
    char *name;
    int salt;
    struct acvp_rsa_hash_pair_list *next;
} ACVP_RSA_HASH_PAIR_LIST;

typedef struct acvp_rsa_mode_caps_list {
    int modulo; // 2048, 3072, 4096 -- defined as macros
    int salt;   // only valid for siggen mode
    ACVP_NAME_LIST *hash_algs;
    ACVP_RSA_HASH_PAIR_LIST *hash_pair;
    ACVP_NAME_LIST *prime_tests;
    struct acvp_rsa_mode_caps_list *next;
} ACVP_RSA_MODE_CAPS_LIST;

typedef struct acvp_rsa_keygen_capability_t {
    int key_format_crt;                     // if false, key format is assumed to be standard
    ACVP_RSA_PUB_EXP_MODE pub_exp_mode;
    char *fixed_pub_exp;               // hex value of e
    ACVP_RSA_KEYGEN_MODE rand_pq;      // as defined in FIPS186-4
    char *rand_pq_str;
    int info_gen_by_server;                  // boolean
    ACVP_RSA_MODE_CAPS_LIST *mode_capabilities;
    struct acvp_rsa_keygen_capability_t *next; // to support multiple randPQ values
} ACVP_RSA_KEYGEN_CAP;


typedef struct acvp_ecdsa_capability_t {
    ACVP_NAME_LIST *curves;
    ACVP_NAME_LIST *secret_gen_modes;
    ACVP_NAME_LIST *hash_algs;
} ACVP_ECDSA_CAP;

typedef struct acvp_rsa_sig_capability_t {
    char *sig_type_str;
    int sig_type;
    int pub_exp_mode;                           // for sigVer only
    char *fixed_pub_exp;                        // hex value of e
    ACVP_RSA_MODE_CAPS_LIST *mode_capabilities; //holds modRSASigGen (int) and hashSigGen (list)
    struct acvp_rsa_sig_capability_t *next;
} ACVP_RSA_SIG_CAP;


typedef struct acvp_dsa_attrs {
    int modulo;
    int sha;
    struct acvp_dsa_attrs *next;
} ACVP_DSA_ATTRS;

#define ACVP_DSA_MAX_MODES 5
typedef struct acvp_dsa_cap_mode_t {
    ACVP_DSA_MODE cap_mode;
    int defined;
    int gen_pq_prob;
    int gen_pq_prov;
    int gen_g_unv;
    int gen_g_can;
    ACVP_DSA_ATTRS *dsa_attrs;
} ACVP_DSA_CAP_MODE;

typedef struct acvp_dsa_capability {
    ACVP_CIPHER cipher;
    ACVP_DSA_CAP_MODE *dsa_cap_mode;
} ACVP_DSA_CAP;

typedef struct acvp_kas_ecc_mac {
    int alg;
    int curve;
    ACVP_PARAM_LIST *key;
    int nonce;
    int maclen;
    struct acvp_kas_ecc_mac *next;
} ACVP_KAS_ECC_MAC;

typedef struct acvp_kas_ecc_pset {
    int set;
    int curve;
    ACVP_PARAM_LIST *sha;
    ACVP_KAS_ECC_MAC *mac;
    struct acvp_kas_ecc_pset *next;
} ACVP_KAS_ECC_PSET;

typedef struct acvp_kas_ecc_scheme {
    ACVP_KAS_ECC_SCHEMES scheme;
    ACVP_KAS_ECC_SET kdf;
    ACVP_PARAM_LIST *role;
    ACVP_KAS_ECC_PSET *pset;
    struct acvp_kas_ecc_scheme *next;
} ACVP_KAS_ECC_SCHEME;


typedef struct acvp_kas_ecc_cap_mode_t {
    ACVP_KAS_ECC_MODE cap_mode;
    ACVP_PREREQ_LIST *prereq_vals;
    ACVP_PARAM_LIST *curve;    /* CDH mode only */
    ACVP_PARAM_LIST *function;
    ACVP_KAS_ECC_SCHEME *scheme; /* other modes use schemes */
} ACVP_KAS_ECC_CAP_MODE;

typedef struct acvp_kas_ecc_capability_t {
    ACVP_CIPHER cipher;
    ACVP_KAS_ECC_CAP_MODE *kas_ecc_mode;
} ACVP_KAS_ECC_CAP;

typedef struct acvp_kas_ffc_mac {
    int alg;
    int curve;
    ACVP_PARAM_LIST *key;
    int nonce;
    int maclen;
    struct acvp_kas_ffc_mac *next;
} ACVP_KAS_FFC_MAC;

typedef struct acvp_kas_ffc_pset {
    int set;
    ACVP_PARAM_LIST *sha;
    ACVP_KAS_FFC_MAC *mac;
    struct acvp_kas_ffc_pset *next;
} ACVP_KAS_FFC_PSET;

typedef struct acvp_kas_ffc_scheme {
    ACVP_KAS_FFC_SCHEMES scheme;
    ACVP_KAS_FFC_SET kdf;
    ACVP_PARAM_LIST *role;
    ACVP_KAS_FFC_PSET *pset;
    struct acvp_kas_ffc_scheme *next;
} ACVP_KAS_FFC_SCHEME;


typedef struct acvp_kas_ffc_cap_mode_t {
    ACVP_KAS_FFC_MODE cap_mode;
    ACVP_PREREQ_LIST *prereq_vals;
    ACVP_PARAM_LIST *function;
    ACVP_KAS_FFC_SCHEME *scheme; /* other modes use schemes */
} ACVP_KAS_FFC_CAP_MODE;

typedef struct acvp_kas_ffc_capability_t {
    ACVP_CIPHER cipher;
    ACVP_KAS_FFC_CAP_MODE *kas_ffc_mode;
} ACVP_KAS_FFC_CAP;

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
        ACVP_KDF135_SRTP_CAP *kdf135_srtp_cap;
        ACVP_KDF135_IKEV2_CAP *kdf135_ikev2_cap;
        ACVP_KDF135_IKEV1_CAP *kdf135_ikev1_cap;
        ACVP_KDF135_X963_CAP *kdf135_x963_cap;
        ACVP_KDF108_CAP *kdf108_cap;
        ACVP_KAS_ECC_CAP *kas_ecc_cap;
        ACVP_KAS_FFC_CAP *kas_ffc_cap;
    } cap;

    int (*crypto_handler)(ACVP_TEST_CASE *test_case);

    struct acvp_caps_list_t *next;
} ACVP_CAPS_LIST;

/*
 * to keep track of OEs with multiple dependencies
 * It includes a key/value list to be added as a flexible JSON obj
 * and the URL that the server returns once the dep is registered
 */
typedef struct acvp_dependency_list_t {
    ACVP_KV_LIST *attrs_list;
    char *url; /* returned from the server */
    struct acvp_dependency_list_t *next;
} ACVP_DEPENDENCY_LIST;

/*
 * This struct holds all the global data for a test session, such
 * as the server name, port#, etc.  Some of the values in this
 * struct are transitory and used during the JSON parsing and
 * vector processing logic.
 */
struct acvp_ctx_t {
    /* Global config values for the session */
    ACVP_LOG_LVL debug;
    int debug_request;
    char *server_name;
    char *path_segment;
    char *api_context;
    int server_port;
    char *cacerts_file;     /* Location of CA certificates Curl will use to verify peer */
    int verify_peer;        /* enables TLS peer verification via Curl */
    char *tls_cert;         /* Location of PEM encoded X509 cert to use for TLS client auth */
    char *tls_key;          /* Location of PEM encoded priv key to use for TLS client auth */
    char *vendor_name;
    char *vendor_website;
    char *contact_name;
    char *contact_email;
    char *module_name;
    char *module_type;
    char *module_version;
    char *module_desc;
    char *oe_name;
    ACVP_DEPENDENCY_LIST *dependency_list;
    ACVP_STRING_LIST *vsid_url_list;
    char *session_url;

    char *vendor_url; /*<< URL for vendor on validating server >>*/
    char *module_url;
    char *oe_url;

    char *json_filename;
    int use_json;

    int is_sample;

    /* test session data */
    ACVP_VS_LIST *vs_list;
    char *jwt_token; /* access_token provided by server for authenticating REST calls */

    /* crypto module capabilities list */
    ACVP_CAPS_LIST *caps_list;

    /* application callbacks */
    ACVP_RESULT (*test_progress_cb) (char *msg);

    /* Two-factor authentication callback */
    ACVP_RESULT (*totp_cb) (char **token);

    /* Transitory values */
    char *login_buf;      /* holds the 2-FA authentication response */
    char *reg_buf;        /* holds the JSON registration response */
    char *kat_buf;        /* holds the current set of vectors being processed */
    char *upld_buf;       /* holds the HTTP response from server when uploading results */
    JSON_Value *kat_resp; /* holds the current set of vector responses */
    int read_ctr;         /* used during curl processing */
    char *test_sess_buf;
    char *sample_buf;
    int vs_id;      /* vs_id currently being processed */
    char *vsid_url; /* vs currently being processed */
    char *ans_buf;  /* holds the queried answers on a sample registration */
};

ACVP_RESULT acvp_send_test_session_registration(ACVP_CTX *ctx, char *reg);

ACVP_RESULT acvp_send_vendor_registration(ACVP_CTX *ctx, char *reg);

ACVP_RESULT acvp_send_module_registration(ACVP_CTX *ctx, char *reg);

ACVP_RESULT acvp_send_oe_registration(ACVP_CTX *ctx, char *reg);

ACVP_RESULT acvp_send_dep_registration(ACVP_CTX *ctx, char *reg);

ACVP_RESULT acvp_send_login(ACVP_CTX *ctx, char *login);

ACVP_RESULT acvp_retrieve_vector_set(ACVP_CTX *ctx, char *vsid_url);

ACVP_RESULT acvp_retrieve_vector_set_result(ACVP_CTX *ctx, char *vsid_url);

ACVP_RESULT acvp_retrieve_result(ACVP_CTX *ctx, char *api_url);

ACVP_RESULT acvp_retrieve_expected_result(ACVP_CTX *ctx, char *api_url);

ACVP_RESULT acvp_submit_vector_responses(ACVP_CTX *ctx);

void acvp_log_msg(ACVP_CTX *ctx, ACVP_LOG_LVL level, const char *format, ...);

ACVP_RESULT acvp_hexstr_to_bin(const char *src, unsigned char *dest, int dest_max, int *converted_len);

ACVP_RESULT acvp_bin_to_bit(const unsigned char *in, int len, unsigned char *out);

ACVP_RESULT acvp_bit_to_bin(const unsigned char *in, int len, unsigned char *out);

/*
 * These are the handler routines for each KAT operation
 */
ACVP_RESULT acvp_aes_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_des_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_entropy_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_hash_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_drbg_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_hmac_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_cmac_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_rsa_keygen_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_rsa_siggen_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_rsa_sigver_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_ecdsa_keygen_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_ecdsa_keyver_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_ecdsa_siggen_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_ecdsa_sigver_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kdf135_tls_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kdf135_snmp_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kdf135_ssh_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kdf135_srtp_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kdf135_ikev2_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kdf135_ikev1_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kdf135_x963_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kdf108_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_dsa_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_dsa_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kas_ecc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kas_ffc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

/*
 * ACVP build registration functions used internally
 */
ACVP_RESULT acvp_build_vendors(ACVP_CTX *ctx, char **reg);

ACVP_RESULT acvp_build_modules(ACVP_CTX *ctx, char **reg);

ACVP_RESULT acvp_build_oes(ACVP_CTX *ctx, char **reg);

ACVP_RESULT acvp_build_test_session(ACVP_CTX *ctx, char **reg);

ACVP_RESULT acvp_build_dependency(ACVP_DEPENDENCY_LIST *dep, char **reg);

/*
 * ACVP utility functions used internally
 */
ACVP_CAPS_LIST *acvp_locate_cap_entry(ACVP_CTX *ctx, ACVP_CIPHER cipher);

char *acvp_lookup_cipher_name(ACVP_CIPHER alg);

ACVP_CIPHER acvp_lookup_cipher_index(const char *algorithm);

ACVP_DRBG_MODE acvp_lookup_drbg_mode_index(const char *mode);

ACVP_DRBG_CAP_MODE_LIST *acvp_locate_drbg_mode_entry(ACVP_CAPS_LIST *cap, ACVP_DRBG_MODE mode);

char *acvp_lookup_rsa_randpq_name(int value);

int acvp_lookup_rsa_randpq_index(const char *value);

ACVP_RESULT acvp_create_array(JSON_Object **obj, JSON_Value **val, JSON_Array **arry);

ACVP_RESULT is_valid_tf_param(int value);

char *acvp_lookup_rsa_prime_test_name(ACVP_RSA_PRIME_TEST_TYPE type);
ACVP_RESULT is_valid_prime_test(char *value);

ACVP_RESULT is_valid_rsa_mod(int value);

ACVP_HASH_ALG acvp_lookup_hash_alg(const char *name);
char *acvp_lookup_hash_alg_name(ACVP_HASH_ALG id);

ACVP_EC_CURVE acvp_lookup_ec_curve(ACVP_CIPHER cipher, const char *name);
char *acvp_lookup_ec_curve_name(ACVP_CIPHER cipher, ACVP_EC_CURVE id);

void ctr64_inc(unsigned char *counter);
void ctr128_inc(unsigned char *counter);
ACVP_RESULT acvp_refresh(ACVP_CTX *ctx);

ACVP_RESULT acvp_setup_json_rsp_group(ACVP_CTX **ctx,
                                      JSON_Value **outer_arr_val,
                                      JSON_Value **r_vs_val,
                                      JSON_Object **r_vs,
                                      const char *alg_str,
                                      JSON_Array **groups_arr);

void acvp_release_json(JSON_Value *r_vs_val,
                       JSON_Value *r_gval);
#endif
