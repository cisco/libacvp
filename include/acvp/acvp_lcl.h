/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#ifndef acvp_lcl_h
#define acvp_lcl_h

#include "parson.h"

#define ACVP_VERSION    "1.0"
#define ACVP_LIBRARY_VERSION    "libacvp_oss-1.1.3"


#ifndef ACVP_LOG_ERR
#ifdef _WIN32
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

#ifndef ACVP_LOG_WARN
#ifdef _WIN32
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

#ifndef ACVP_LOG_STATUS
#ifdef _WIN32
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

#ifndef ACVP_LOG_INFO
#ifdef _WIN32
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

#ifndef ACVP_LOG_VERBOSE
#ifdef _WIN32
#define ACVP_LOG_VERBOSE(format, ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_VERBOSE, "***ACVP [INFO][%s:%d]--> " format "\n", \
                     __func__, __LINE__, __VA_ARGS__); \
} while (0)
#else
#define ACVP_LOG_VERBOSE(format, args ...) do { \
        acvp_log_msg(ctx, ACVP_LOG_LVL_VERBOSE, "***ACVP [INFO][%s:%d]--> " format "\n", \
                     __func__, __LINE__, ##args); \
} while (0)
#endif
#endif
#define ACVP_LOG_NEWLINE do { \
        acvp_log_newline(ctx); \
} while (0)


#define ACVP_LOG_TRUNCATED_STR "...[truncated]\n"
//This MUST be the length of the above screen (want to avoid calculating at runtime frequently)
#define ACVP_LOG_TRUNCATED_STR_LEN 15
#define ACVP_LOG_MAX_MSG_LEN 2048

#define ACVP_BIT2BYTE(x) ((x + 7) >> 3) /**< Convert bit length (x, of type integer) into byte length */

#define ACVP_ALG_MAX ACVP_CIPHER_END - 1  /* Used by alg_tbl[] */

/********************************************************
 * ******************************************************
 * REVISIONS
 * ******************************************************
 ********************************************************
 */
#define ACVP_REVISION_LATEST "1.0"
#define ACVP_REVISION_FIPS186_4 "FIPS186-4"
#define ACVP_REVISION_SP800_56AR3 "Sp800-56Ar3"
#define ACVP_REVISION_SP800_56BR2 "Sp800-56Br2"

/* AES */
#define ACVP_REV_AES_ECB             ACVP_REVISION_LATEST
#define ACVP_REV_AES_CBC             ACVP_REVISION_LATEST
#define ACVP_REV_AES_CFB1            ACVP_REVISION_LATEST
#define ACVP_REV_AES_CFB8            ACVP_REVISION_LATEST
#define ACVP_REV_AES_CFB128          ACVP_REVISION_LATEST
#define ACVP_REV_AES_OFB             ACVP_REVISION_LATEST
#define ACVP_REV_AES_CTR             ACVP_REVISION_LATEST
#define ACVP_REV_AES_GCM             ACVP_REVISION_LATEST
#define ACVP_REV_AES_GCM_SIV         ACVP_REVISION_LATEST
#define ACVP_REV_AES_CCM             ACVP_REVISION_LATEST
#define ACVP_REV_AES_XTS             ACVP_REVISION_LATEST
#define ACVP_REV_AES_KW              ACVP_REVISION_LATEST
#define ACVP_REV_AES_KWP             ACVP_REVISION_LATEST
#define ACVP_REV_AES_GMAC            ACVP_REVISION_LATEST
#define ACVP_REV_AES_XPN             ACVP_REVISION_LATEST

/* TDES */
#define ACVP_REV_TDES_OFB            ACVP_REVISION_LATEST
#define ACVP_REV_TDES_OFBI           ACVP_REVISION_LATEST
#define ACVP_REV_TDES_CFB1           ACVP_REVISION_LATEST
#define ACVP_REV_TDES_CFB8           ACVP_REVISION_LATEST
#define ACVP_REV_TDES_CFB64          ACVP_REVISION_LATEST
#define ACVP_REV_TDES_CFBP1          ACVP_REVISION_LATEST
#define ACVP_REV_TDES_CFBP8          ACVP_REVISION_LATEST
#define ACVP_REV_TDES_CFBP64         ACVP_REVISION_LATEST
#define ACVP_REV_TDES_ECB            ACVP_REVISION_LATEST
#define ACVP_REV_TDES_CBC            ACVP_REVISION_LATEST
#define ACVP_REV_TDES_CBCI           ACVP_REVISION_LATEST
#define ACVP_REV_TDES_CTR            ACVP_REVISION_LATEST
#define ACVP_REV_TDES_KW             ACVP_REVISION_LATEST

/* SHA */
#define ACVP_REV_HASH_SHA1           ACVP_REVISION_LATEST
#define ACVP_REV_HASH_SHA224         ACVP_REVISION_LATEST
#define ACVP_REV_HASH_SHA256         ACVP_REVISION_LATEST
#define ACVP_REV_HASH_SHA384         ACVP_REVISION_LATEST
#define ACVP_REV_HASH_SHA512         ACVP_REVISION_LATEST
#define ACVP_REV_HASH_SHA512_224     ACVP_REVISION_LATEST
#define ACVP_REV_HASH_SHA512_256     ACVP_REVISION_LATEST
#define ACVP_REV_HASH_SHA3_224       ACVP_REVISION_LATEST
#define ACVP_REV_HASH_SHA3_256       ACVP_REVISION_LATEST
#define ACVP_REV_HASH_SHA3_384       ACVP_REVISION_LATEST
#define ACVP_REV_HASH_SHA3_512       ACVP_REVISION_LATEST
#define ACVP_REV_HASH_SHAKE_128      ACVP_REVISION_LATEST
#define ACVP_REV_HASH_SHAKE_256      ACVP_REVISION_LATEST

/* DRBG */
#define ACVP_REV_HASHDRBG            ACVP_REVISION_LATEST
#define ACVP_REV_HMACDRBG            ACVP_REVISION_LATEST
#define ACVP_REV_CTRDRBG             ACVP_REVISION_LATEST

/* HMAC */
#define ACVP_REV_HMAC_SHA1           ACVP_REVISION_LATEST
#define ACVP_REV_HMAC_SHA2_224       ACVP_REVISION_LATEST
#define ACVP_REV_HMAC_SHA2_256       ACVP_REVISION_LATEST
#define ACVP_REV_HMAC_SHA2_384       ACVP_REVISION_LATEST
#define ACVP_REV_HMAC_SHA2_512       ACVP_REVISION_LATEST
#define ACVP_REV_HMAC_SHA2_512_224   ACVP_REVISION_LATEST
#define ACVP_REV_HMAC_SHA2_512_256   ACVP_REVISION_LATEST
#define ACVP_REV_HMAC_SHA3_224       ACVP_REVISION_LATEST
#define ACVP_REV_HMAC_SHA3_256       ACVP_REVISION_LATEST
#define ACVP_REV_HMAC_SHA3_384       ACVP_REVISION_LATEST
#define ACVP_REV_HMAC_SHA3_512       ACVP_REVISION_LATEST

/* CMAC */
#define ACVP_REV_CMAC_AES            ACVP_REVISION_LATEST
#define ACVP_REV_CMAC_TDES           ACVP_REVISION_LATEST

/* DSA */
#define ACVP_REV_DSA                 ACVP_REVISION_LATEST

/* RSA */
#define ACVP_REV_RSA                 ACVP_REVISION_FIPS186_4
#define ACVP_REV_RSA_PRIM            ACVP_REVISION_LATEST

/* ECDSA */
#define ACVP_REV_ECDSA               ACVP_REVISION_LATEST

/* KAS_ECC */
#define ACVP_REV_KAS_ECC             ACVP_REVISION_LATEST
#define ACVP_REV_KAS_ECC_SSC         ACVP_REVISION_SP800_56AR3

/* KAS_FFC */
#define ACVP_REV_KAS_FFC             ACVP_REVISION_LATEST
#define ACVP_REV_KAS_FFC_SSC         ACVP_REVISION_SP800_56AR3

/* KAS_IFC */
#define ACVP_REV_KAS_IFC_SSC         ACVP_REVISION_SP800_56BR2

/* KTS_IFC */
#define ACVP_REV_KTS_IFC             ACVP_REVISION_SP800_56BR2

/* KDF */
#define ACVP_REV_KDF135_TLS          ACVP_REVISION_LATEST
#define ACVP_REV_KDF135_SNMP         ACVP_REVISION_LATEST
#define ACVP_REV_KDF135_SSH          ACVP_REVISION_LATEST
#define ACVP_REV_KDF135_SRTP         ACVP_REVISION_LATEST
#define ACVP_REV_KDF135_IKEV2        ACVP_REVISION_LATEST
#define ACVP_REV_KDF135_IKEV1        ACVP_REVISION_LATEST
#define ACVP_REV_KDF135_TPM          ACVP_REVISION_LATEST
#define ACVP_REV_KDF135_X963         ACVP_REVISION_LATEST
#define ACVP_REV_KDF108              ACVP_REVISION_LATEST
#define ACVP_REV_PBKDF               ACVP_REVISION_LATEST


/********************************************************
 * ******************************************************
 * ALGORITHM STRINGS
 * ******************************************************
 ********************************************************
 */
#define ACVP_ALG_NAME_MAX 18 /**< Always make sure this is >= the length of ACVP_ALG* strings */
#define ACVP_ALG_MODE_MAX 26 /**< Always make sure this is >= the length of ACVP_MODE* strings */

#define ACVP_ALG_AES_ECB             "ACVP-AES-ECB"
#define ACVP_ALG_AES_CBC             "ACVP-AES-CBC"
#define ACVP_ALG_AES_CFB1            "ACVP-AES-CFB1"
#define ACVP_ALG_AES_CFB8            "ACVP-AES-CFB8"
#define ACVP_ALG_AES_CFB128          "ACVP-AES-CFB128"
#define ACVP_ALG_AES_OFB             "ACVP-AES-OFB"
#define ACVP_ALG_AES_CTR             "ACVP-AES-CTR"
#define ACVP_ALG_AES_GCM             "ACVP-AES-GCM"
#define ACVP_ALG_AES_GCM_SIV         "ACVP-AES-GCM-SIV"
#define ACVP_ALG_AES_CCM             "ACVP-AES-CCM"
#define ACVP_ALG_AES_XTS             "ACVP-AES-XTS"
#define ACVP_ALG_AES_KW              "ACVP-AES-KW"
#define ACVP_ALG_AES_KWP             "ACVP-AES-KWP"
#define ACVP_ALG_AES_GMAC            "ACVP-AES-GMAC"
#define ACVP_ALG_AES_XPN             "ACVP-AES-XPN"
#define ACVP_ALG_TDES_OFB            "ACVP-TDES-OFB"
#define ACVP_ALG_TDES_OFBI           "ACVP-TDES-OFBI"
#define ACVP_ALG_TDES_CFB1           "ACVP-TDES-CFB1"
#define ACVP_ALG_TDES_CFB8           "ACVP-TDES-CFB8"
#define ACVP_ALG_TDES_CFB64          "ACVP-TDES-CFB64"
#define ACVP_ALG_TDES_CFBP1          "ACVP-TDES-CFBP1"
#define ACVP_ALG_TDES_CFBP8          "ACVP-TDES-CFBP8"
#define ACVP_ALG_TDES_CFBP64         "ACVP-TDES-CFBP64"
#define ACVP_ALG_TDES_ECB            "ACVP-TDES-ECB"
#define ACVP_ALG_TDES_CBC            "ACVP-TDES-CBC"
#define ACVP_ALG_TDES_CBCI           "ACVP-TDES-CBCI"
#define ACVP_ALG_TDES_CTR            "ACVP-TDES-CTR"
#define ACVP_ALG_TDES_KW             "ACVP-TDES-KW"
#define ACVP_ALG_SHA1                "SHA-1"
#define ACVP_ALG_SHA224              "SHA2-224"
#define ACVP_ALG_SHA256              "SHA2-256"
#define ACVP_ALG_SHA384              "SHA2-384"
#define ACVP_ALG_SHA512              "SHA2-512"
#define ACVP_ALG_SHA512_224          "SHA2-512/224"
#define ACVP_ALG_SHA512_256          "SHA2-512/256"
#define ACVP_ALG_SHA3_224            "SHA3-224"
#define ACVP_ALG_SHA3_256            "SHA3-256"
#define ACVP_ALG_SHA3_384            "SHA3-384"
#define ACVP_ALG_SHA3_512            "SHA3-512"
#define ACVP_ALG_SHAKE_128           "SHAKE-128"
#define ACVP_ALG_SHAKE_256           "SHAKE-256"
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
#define ACVP_MODE_DECPRIM            "decryptionPrimitive"
#define ACVP_MODE_SIGPRIM            "signaturePrimitive"

#define ACVP_ALG_KAS_ECC_CDH         "CDH-Component"
#define ACVP_ALG_KAS_ECC_COMP        "Component"
#define ACVP_ALG_KAS_ECC_NOCOMP      ""


#define ACVP_ALG_KAS_ECC_SSC         "KAS-ECC-SSC"
#define ACVP_ALG_KAS_ECC             "KAS-ECC"
#define ACVP_ALG_KAS_ECC_DPGEN       "dpGen"
#define ACVP_ALG_KAS_ECC_DPVAL       "dpVal"
#define ACVP_ALG_KAS_ECC_KEYPAIRGEN  "keyPairGen"
#define ACVP_ALG_KAS_ECC_FULLVAL     "fullVal"
#define ACVP_ALG_KAS_ECC_PARTIALVAL  "partialVal"
#define ACVP_ALG_KAS_ECC_KEYREGEN    "keyRegen"

#define ACVP_ALG_KAS_FFC_COMP        "Component"
#define ACVP_ALG_KAS_FFC_NOCOMP      ""

#define ACVP_ALG_KAS_FFC_SSC         "KAS-FFC-SSC"
#define ACVP_ALG_KAS_FFC             "KAS-FFC"
#define ACVP_ALG_KAS_FFC_DPGEN       "dpGen"
#define ACVP_ALG_KAS_FFC_MQV2        "MQV2"
#define ACVP_ALG_KAS_FFC_KEYPAIRGEN  "keyPairGen"
#define ACVP_ALG_KAS_FFC_FULLVAL     "fullVal"
#define ACVP_ALG_KAS_FFC_KEYREGEN    "keyRegen"

#define ACVP_ALG_KAS_IFC_SSC         "KAS-IFC-SSC"
#define ACVP_ALG_KAS_IFC_COMP        ""

#define ACVP_ALG_KTS_IFC             "KTS-IFC"
#define ACVP_ALG_KTS_IFC_COMP        ""

#define ACVP_ECDSA_EXTRA_BITS_STR "extra bits"
#define ACVP_ECDSA_EXTRA_BITS_STR_LEN 10
#define ACVP_ECDSA_TESTING_CANDIDATES_STR "testing candidates"
#define ACVP_ECDSA_TESTING_CANDIDATES_STR_LEN 18

#define ACVP_RSA_PRIME_TEST_TBLC2_STR "tblC2"
#define ACVP_RSA_PRIME_TEST_TBLC2_STR_LEN 5
#define ACVP_RSA_PRIME_TEST_TBLC3_STR "tblC3"
#define ACVP_RSA_PRIME_TEST_TBLC3_STR_LEN 5

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

#define ACVP_DRBG_MODE_TDES          "TDES"
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
#define ACVP_ALG_PBKDF           "PBKDF"

#define ACVP_CAPABILITY_STR_MAX 512 /**< Arbitrary string length limit */

#define ACVP_HEXSTR_MAX (ACVP_DRBG_ENTPY_IN_BIT_MAX >> 2) /**< Represents the largest hexstr that the client will accept.
                                                               Should always be set the the highest hexstr (i.e. bit length)
                                                               the the client will accept from server JSON string field */

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
#define ACVP_AES_GCM_SIV_IVLEN 96
#define ACVP_AES_XPN_IVLEN 96

#define ACVP_SYM_TAG_BIT_MIN 4                            /**< 128 bits */
#define ACVP_SYM_TAG_BIT_MAX 128                          /**< 128 bits */
#define ACVP_SYM_TAG_MAX (ACVP_SYM_TAG_BIT_MAX >> 2)      /**< 32 characters */
#define ACVP_SYM_TAG_BYTE_MAX (ACVP_SYM_TAG_BIT_MAX >> 3) /**< 16 bytes */
#define ACVP_AES_GCM_SIV_TAGLEN 128

#define ACVP_SYM_AAD_BIT_MAX 65536                        /**< 65536 bits */
#define ACVP_SYM_AAD_MAX (ACVP_SYM_AAD_BIT_MAX >> 2)      /**< 16384 characters */
#define ACVP_SYM_AAD_BYTE_MAX (ACVP_SYM_AAD_BIT_MAX >> 3) /**< 8192 bytes */

#define ACVP_AES_XPN_SALTLEN 96

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

#define ACVP_HASH_SHA1_SHA2_MSG_BIT_MAX 65535               /**< 65535 bits */
#define ACVP_HASH_MSG_BIT_MIN 0                             /**< 0 bits */
#define ACVP_HASH_MSG_BIT_MAX 140000                        /**< 140000 bits */
#define ACVP_HASH_MSG_STR_MAX (ACVP_HASH_MSG_BIT_MAX >> 2)  /**< 35000 characters */
#define ACVP_HASH_MSG_BYTE_MAX (ACVP_HASH_MSG_BIT_MAX >> 3) /**< 17500 bytes */
#define ACVP_HASH_MD_BIT_MAX 512                            /**< 512 bits */
#define ACVP_HASH_MD_STR_MAX (ACVP_HASH_MD_BIT_MAX >> 2)    /**< 128 characters */
#define ACVP_HASH_MD_BYTE_MAX (ACVP_HASH_MD_BIT_MAX >> 3)   /**< 64 bytes */

#define ACVP_HASH_XOF_MD_BIT_MIN 16 /**< XOF (extendable output format) outLength minimum (in bits) */
#define ACVP_HASH_XOF_MD_BIT_MAX 65536 /**< XOF (extendable output format) outLength maximum (in bits) */
#define ACVP_HASH_XOF_MD_STR_MAX (ACVP_HASH_XOF_MD_BIT_MAX >> 2) /**< 16,384 characters */
#define ACVP_HASH_XOF_MD_BYTE_MAX (ACVP_HASH_XOF_MD_BIT_MAX >> 3) /**< 8,192 bytes */

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
#define ACVP_KDF135_SNMP_ENGID_MAX_BYTES 32
#define ACVP_KDF135_SNMP_ENGID_MAX_STR 64
#define ACVP_KDF135_SNMP_SKEY_MAX 64

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

/**
 * Accepted length ranges for PBKDF.
 */
#define ACVP_PBKDF_ITERATION_MIN 1
#define ACVP_PBKDF_ITERATION_MAX 10000000

#define ACVP_PBKDF_KEY_BIT_MIN 112
#define ACVP_PBKDF_KEY_BIT_MAX 4096
#define ACVP_PBKDF_KEY_BYTE_MIN (ACVP_PBKDF_KEY_BIT_MIN >> 3)
#define ACVP_PBKDF_KEY_STR_MIN (ACVP_PBKDF_KEY_BIT_MIN >> 2)
#define ACVP_PBKDF_KEY_BYTE_MAX (ACVP_PBKDF_KEY_BIT_MAX >> 3)
#define ACVP_PBKDF_KEY_STR_MAX (ACVP_PBKDF_KEY_BIT_MAX >> 2)

#define ACVP_PBKDF_PASS_LEN_MIN 8 //in chars
#define ACVP_PBKDF_PASS_LEN_MAX 128 //in chars

#define ACVP_PBKDF_SALT_LEN_BIT_MIN 128
#define ACVP_PBKDF_SALT_LEN_BIT_MAX 4096
#define ACVP_PBKDF_SALT_LEN_BYTE_MIN (ACVP_PBKDF_SALT_LEN_BIT_MIN >> 3)
#define ACVP_PBKDF_SALT_LEN_STR_MIN (ACVP_PBKDF_SALT_LEN_BIT_MIN >> 2)
#define ACVP_PBKDF_SALT_LEN_BYTE_MAX (ACVP_PBKDF_SALT_LEN_BIT_MAX >> 3)
#define ACVP_PBKDF_SALT_LEN_STR_MAX (ACVP_PBKDF_SALT_LEN_BIT_MAX >> 2)
/*
 * END PBKDF
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

#define ACVP_KAS_IFC_BIT_MAX 4096
#define ACVP_KAS_IFC_BYTE_MAX (ACVP_KAS_IFC_BIT_MAX >> 3)
#define ACVP_KAS_IFC_STR_MAX (ACVP_KAS_IFC_BIT_MAX >> 2)

#define ACVP_KTS_IFC_BIT_MAX 4096
#define ACVP_KTS_IFC_BYTE_MAX (ACVP_KTS_IFC_BIT_MAX >> 3)
#define ACVP_KTS_IFC_STR_MAX (ACVP_KTS_IFC_BIT_MAX >> 2)

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
#define ACVP_RSA_PUB_EXP_MODE_FIXED_STR_LEN 5
#define ACVP_RSA_PUB_EXP_MODE_RANDOM_STR "random"
#define ACVP_RSA_PUB_EXP_MODE_RANDOM_STR_LEN 6
#define ACVP_RSA_KEY_FORMAT_STD_STR "standard"
#define ACVP_RSA_KEY_FORMAT_STD_STR_LEN 9
#define ACVP_RSA_KEY_FORMAT_CRT_STR "crt"
#define ACVP_RSA_KEY_FORMAT_CRT_STR_LEN 3
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

#define ACVP_CURL_BUF_MAX       (1024 * 1024 * 32) /**< 32 MB */
#define ACVP_RETRY_TIME_MIN     5 /* seconds */
#define ACVP_RETRY_TIME_MAX     300 
#define ACVP_MAX_WAIT_TIME      7200
#define ACVP_RETRY_TIME         30
#define ACVP_RETRY_MODIFIER_MAX 10
#define ACVP_JWT_TOKEN_MAX      2048
#define ACVP_ATTR_URL_MAX       2083 /* MS IE's limit - arbitrary */

#define ACVP_SESSION_PARAMS_STR_LEN_MAX 256
#define ACVP_REQUEST_STR_LEN_MAX 128
#define ACVP_OE_STR_MAX 256
#define ACVP_PATH_SEGMENT_DEFAULT ""
#define ACVP_JSON_FILENAME_MAX 128

/* 
 * This should NOT be made longer than ACVP_JSON_FILENAME_MAX - 15
 * (accounting for _ character, ".json", and 9 digits for testSession ID)
 */
#define ACVP_SAVE_DEFAULT_PREFIX "testSession"

#define ACVP_CFB1_BIT_MASK      0x80


#define ACVP_USER_AGENT_STR_MAX 255
//char cannot exist in any string for http user agent for parsing reasons
#define ACVP_USER_AGENT_DELIMITER ';'
#define ACVP_USER_AGENT_CHAR_REPLACEMENT '_';

/*
 * Max lengths for different values in the HTTP user-agent string, arbitrarily selected
 */
#define ACVP_USER_AGENT_ACVP_STR_MAX 16
#define ACVP_USER_AGENT_OSNAME_STR_MAX 32
#define ACVP_USER_AGENT_OSVER_STR_MAX 64
#define ACVP_USER_AGENT_ARCH_STR_MAX 16
#define ACVP_USER_AGENT_PROC_STR_MAX 64
#define ACVP_USER_AGENT_COMP_STR_MAX 32

#define ACVP_STRING_LIST_MAX_LEN 256 //arbitrary max character count for a string in ACVP_STRING_LIST

/*
 * If library cannot detect hardware or software info for HTTP user-agent string, we can check for them
 * in environmental variables, which are defined here
 */
#define ACVP_USER_AGENT_OSNAME_ENV "ACV_OE_OSNAME"
#define ACVP_USER_AGENT_OSVER_ENV "ACV_OE_OSVERSION"
#define ACVP_USER_AGENT_ARCH_ENV "ACV_OE_ARCHITECTURE"
#define ACVP_USER_AGENT_PROC_ENV "ACV_OE_PROCESSOR"
#define ACVP_USER_AGENT_COMP_ENV "ACV_OE_COMPILER"

typedef struct acvp_alg_handler_t ACVP_ALG_HANDLER;

struct acvp_alg_handler_t {
    ACVP_CIPHER cipher;

    ACVP_RESULT (*handler) (ACVP_CTX *ctx, JSON_Object *obj);

    const char *name;
    const char *mode; /** < Should be NULL unless using an asymmetric alg */
    const char *revision;
};

typedef struct acvp_vs_list_t {
    int vs_id;
    struct acvp_vs_list_t *next;
} ACVP_VS_LIST;

struct acvp_result_desc_t {
    ACVP_RESULT rv;
    const char *desc;
};

struct acvp_hash_alg_info {
    ACVP_HASH_ALG id;
    const char *name;
};

struct acvp_ec_curve_info {
    ACVP_EC_CURVE id;
    const char *name;
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
    ACVP_RSA_PRIM_TYPE,
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
    ACVP_PBKDF_TYPE,
    ACVP_KAS_ECC_CDH_TYPE,
    ACVP_KAS_ECC_COMP_TYPE,
    ACVP_KAS_ECC_NOCOMP_TYPE,
    ACVP_KAS_ECC_SSC_TYPE,
    ACVP_KAS_FFC_COMP_TYPE,
    ACVP_KAS_FFC_SSC_TYPE,
    ACVP_KAS_FFC_NOCOMP_TYPE,
    ACVP_KAS_IFC_TYPE,
    ACVP_KTS_IFC_TYPE
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
    const char *name;
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

/**
 * @struct ACVP_KV_LIST
 * @brief This struct is a list of key/value pairs.
 *
 */
typedef struct acvp_kv_list_t {
    char *key;
    char *value;
    struct acvp_kv_list_t *next;
} ACVP_KV_LIST;

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
    ACVP_SYM_CIPH_SALT_SRC salt_source;
    int perform_ctr_tests;
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
    int out_bit; /**< 1 for true, 0 for false
                      Defaults to false.
                      Only for ACVP_HASH_SHAKE_* */
    ACVP_JSON_DOMAIN_OBJ out_len; /**< Required for ACVP_HASH_SHAKE_* */
    ACVP_JSON_DOMAIN_OBJ msg_length;
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
    const char *kdf_mode;
    ACVP_NAME_LIST *mac_mode;
    ACVP_JSON_DOMAIN_OBJ supported_lens;
    ACVP_NAME_LIST *data_order;
    ACVP_SL_LIST *counter_lens;
    int empty_iv_support;
    int requires_empty_iv;
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

typedef struct acvp_pbkdf_capability {
    ACVP_NAME_LIST *hmac_algs;
    ACVP_JSON_DOMAIN_OBJ iteration_count_domain;
    ACVP_JSON_DOMAIN_OBJ key_len_domain;
    ACVP_JSON_DOMAIN_OBJ password_len_domain;
    ACVP_JSON_DOMAIN_OBJ salt_len_domain;
} ACVP_PBKDF_CAP;

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
    const char *name;
};

typedef struct acvp_rsa_hash_pair_list {
    const char *name;
    int salt;
    struct acvp_rsa_hash_pair_list *next;
} ACVP_RSA_HASH_PAIR_LIST;

typedef struct acvp_rsa_mode_caps_list {
    unsigned int modulo; // 2048, 3072, 4096 -- defined as macros
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
    const char *rand_pq_str;
    int info_gen_by_server;                  // boolean
    ACVP_RSA_MODE_CAPS_LIST *mode_capabilities;
    struct acvp_rsa_keygen_capability_t *next; // to support multiple randPQ values
} ACVP_RSA_KEYGEN_CAP;

typedef struct acvp_rsa_prim_capability_t {
    unsigned int prim_type;
    int key_format_crt;                     // if false, key format is assumed to be standard
    ACVP_RSA_PUB_EXP_MODE pub_exp_mode;
    char *fixed_pub_exp;               // hex value of e
    struct acvp_rsa_prim_capability_t *next; // to support multiple randPQ values
} ACVP_RSA_PRIM_CAP;


typedef struct acvp_ecdsa_capability_t {
    ACVP_NAME_LIST *curves;
    ACVP_NAME_LIST *secret_gen_modes;
    ACVP_NAME_LIST *hash_algs;
} ACVP_ECDSA_CAP;

typedef struct acvp_rsa_sig_capability_t {
    const char *sig_type_str;
    unsigned int sig_type;
    int pub_exp_mode;                           // for sigVer only
    char *fixed_pub_exp;                        // hex value of e
    ACVP_RSA_MODE_CAPS_LIST *mode_capabilities; //holds modRSASigGen (int) and hashSigGen (list)
    struct acvp_rsa_sig_capability_t *next;
} ACVP_RSA_SIG_CAP;


typedef struct acvp_dsa_attrs {
    unsigned int modulo;
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
    unsigned int set;
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
    int hash;     /* only a single sha for KAS-ECC-SSC */
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
    unsigned int set;
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
    ACVP_PARAM_LIST *genmeth;
    int hash;
    ACVP_KAS_FFC_SCHEME *scheme; /* other modes use schemes */
} ACVP_KAS_FFC_CAP_MODE;

typedef struct acvp_kas_ffc_capability_t {
    ACVP_CIPHER cipher;
    ACVP_KAS_FFC_CAP_MODE *kas_ffc_mode;
} ACVP_KAS_FFC_CAP;


typedef struct acvp_kas_ifc_capability_t {
    ACVP_CIPHER cipher;
    int hash;
    char *fixed_pub_exp;
    ACVP_PARAM_LIST *kas1_roles;
    ACVP_PARAM_LIST *kas2_roles;
    ACVP_PARAM_LIST *keygen_method;
    ACVP_SL_LIST *modulo;
} ACVP_KAS_IFC_CAP;


typedef struct acvp_kts_ifc_macs_t {
    ACVP_CIPHER cipher;
    int key_length;
    int mac_length;
    struct acvp_kts_ifc_macs_t *next;
} ACVP_KTS_IFC_MACS;

typedef struct acvp_kts_ifc_schemes_t {
    ACVP_KTS_IFC_SCHEME_TYPE scheme;
    int l;
    ACVP_PARAM_LIST *roles;
    ACVP_KTS_IFC_MACS *macs;  /* not yet supported */
    ACVP_PARAM_LIST *hash;
    int null_assoc_data;
    char *assoc_data_pattern;
    char *encodings;      /* may need to change to SL_LIST */
    struct acvp_kts_ifc_schemes_t *next;
} ACVP_KTS_IFC_SCHEMES;


typedef struct acvp_kts_ifc_capability_t {
    ACVP_CIPHER cipher;
    char *fixed_pub_exp;
    char *iut_id;
    ACVP_PARAM_LIST *functions;
    ACVP_KTS_IFC_SCHEMES *schemes;
    ACVP_PARAM_LIST *keygen_method;
    ACVP_SL_LIST *modulo;
} ACVP_KTS_IFC_CAP;

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
        ACVP_RSA_PRIM_CAP *rsa_prim_cap;
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
        ACVP_PBKDF_CAP *pbkdf_cap;
        ACVP_KAS_ECC_CAP *kas_ecc_cap;
        ACVP_KAS_FFC_CAP *kas_ffc_cap;
        ACVP_KAS_IFC_CAP *kas_ifc_cap;
        ACVP_KTS_IFC_CAP *kts_ifc_cap;
    } cap;

    int (*crypto_handler)(ACVP_TEST_CASE *test_case);

    struct acvp_caps_list_t *next;
} ACVP_CAPS_LIST;

typedef struct acvp_vendor_address_t {
    char *street_1;
    char *street_2;
    char *street_3;
    char *locality;
    char *region;
    char *country;
    char *postal_code;
    char *url; /**< ID URL returned from the server */
} ACVP_VENDOR_ADDRESS;

typedef struct acvp_oe_phone_list_t {
    char *number;
    char *type;
    struct acvp_oe_phone_list_t *next;
} ACVP_OE_PHONE_LIST;

typedef struct acvp_person_t {
    char *url; /**< ID URL returned from the server */
    char *full_name;
    ACVP_OE_PHONE_LIST *phone_numbers;
    ACVP_STRING_LIST *emails;
} ACVP_PERSON;

#define LIBACVP_PERSONS_MAX 8
typedef struct acvp_persons_t {
    ACVP_PERSON person[LIBACVP_PERSONS_MAX];
    int count;
} ACVP_PERSONS;

typedef struct acvp_vendor_t {
    unsigned int id; /**< For library tracking purposes */
    char *url; /**< ID URL returned from the server */
    char *name;
    char *website;
    ACVP_OE_PHONE_LIST *phone_numbers;
    ACVP_STRING_LIST *emails;
    ACVP_VENDOR_ADDRESS address;
    ACVP_PERSONS persons;
} ACVP_VENDOR;

#define LIBACVP_VENDORS_MAX 8
typedef struct acvp_vendors_t {
    ACVP_VENDOR v[LIBACVP_VENDORS_MAX];
    int count;
} ACVP_VENDORS;

typedef struct acvp_module_t {
    unsigned int id; /**< For library tracking purposes */
    char *name;
    char *type;
    char *version;
    char *description;
    char *url; /**< ID URL returned from the server */
    ACVP_VENDOR *vendor; /**< Pointer to the Vendor to use */
} ACVP_MODULE;

#define LIBACVP_MODULES_MAX 32
typedef struct acvp_modules_t {
    ACVP_MODULE module[LIBACVP_MODULES_MAX];
    int count;
} ACVP_MODULES;

typedef struct acvp_dependency_t {
    unsigned int id; /**< For library tracking purposes */
    char *url; /**< Returned from the server */
    char *type;
    char *name;
    char *description;
    char *series;
    char *family;
    char *version;
    char *manufacturer;
} ACVP_DEPENDENCY;

#define LIBACVP_DEPENDENCIES_MAX 64
typedef struct acvp_dependencies_t {
    ACVP_DEPENDENCY deps[LIBACVP_DEPENDENCIES_MAX];
    unsigned int count;
} ACVP_DEPENDENCIES;

typedef enum acvp_resource_status {
    ACVP_RESOURCE_STATUS_COMPLETE = 1,
    ACVP_RESOURCE_STATUS_PARTIAL,
    ACVP_RESOURCE_STATUS_INCOMPLETE,
} ACVP_RESOURCE_STATUS;

typedef enum acvp_waiting_status {
    ACVP_WAITING_FOR_TESTS = 1,
    ACVP_WAITING_FOR_RESULTS,
} ACVP_WAITING_STATUS;

typedef struct acvp_oe_dependencies_t {
    ACVP_DEPENDENCY *deps[LIBACVP_DEPENDENCIES_MAX]; /* Array to pointers of linked dependencies */
    unsigned int count;
    ACVP_RESOURCE_STATUS status; /**< PARTIAL indicates that at least one of the linked Dependencies does not
                                      exist. INCOMPLETE indicates all of the 'url' are missing */
} ACVP_OE_DEPENDENCIES;

typedef struct acvp_oe_t {
    unsigned int id; /**< For library tracking purposes */
    char *name; /**< Name of the Operating Environment */
    char *url; /**< ID URL returned from the server */
    ACVP_OE_DEPENDENCIES dependencies; /**< Pointers to attached dependencies */
} ACVP_OE;

#define LIBACVP_OES_MAX 8
typedef struct acvp_oes_t {
    ACVP_OE oe[LIBACVP_OES_MAX];
    int count;
} ACVP_OES;

typedef struct acvp_operating_env_t {
    ACVP_VENDORS vendors; /**< Vendors */
    ACVP_MODULES modules; /**< Modules */
    ACVP_DEPENDENCIES dependencies; /** Dependencies */
    ACVP_OES oes; /**< Operating Environments */
} ACVP_OPERATING_ENV;

typedef struct acvp_fips_t {
    int do_validation; /* Flag indicating whether a FIPS validation
                          should be performed on this testSession. 1 for yes */
    int metadata_loaded; /* Flag indicating whether the metadata necessary for
                           a FIPS validation was successfully loaded into memory. 1 for yes */
    int metadata_ready; /* Flag indicating whether the metadata necessary for
                           a FIPS validation has passed all stages (loaded and verified). 1 for yes */
    ACVP_MODULE *module; /* Pointer to the Module to use for this validation */
    ACVP_OE *oe; /* Pointer to the Operating Environment to use for this validation */
} ACVP_FIPS;

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
    char *api_context;
    int server_port;
    char *cacerts_file;     /* Location of CA certificates Curl will use to verify peer */
    int verify_peer;        /* enables TLS peer verification via Curl */
    char *tls_cert;         /* Location of PEM encoded X509 cert to use for TLS client auth */
    char *tls_key;          /* Location of PEM encoded priv key to use for TLS client auth */

    char *http_user_agent;   /* String containing info to be sent with HTTP requests, currently OE info */
    
    ACVP_OPERATING_ENV op_env; /**< The Operating Environment resources available */
    ACVP_STRING_LIST *vsid_url_list;
    char *session_url;
    int session_passed;

    char *json_filename;    /* filename of registration JSON */
    int use_json;           /* flag to indicate a JSON file is being used for registration */
    int is_sample;          /* flag to idicate that we are requesting sample vector responses */
    char *vector_req_file;  /* filename to use to store vector request JSON */
    int vector_req;         /* flag to indicate we are storing vector request JSON in a file */
    int vector_rsp;         /* flag to indicate we are storing vector responses JSON in a file */
    int get;                /* flag to indicate we are only getting status or metadata */
    char *get_string;       /* string used for get request */
    char *get_filename;     /* string used for file to save GET requests to */
    int post;               /* flag to indicate we are only posting metadata */
    char *post_filename;    /* string used for post */
    int put;                /* flag to indicate we are only putting metadata  for post test validation*/
    char *put_filename;     /* string used for put */

    ACVP_FIPS fips; /* Information related to a FIPS validation */

    /* test session data */
    ACVP_VS_LIST *vs_list;
    char *jwt_token; /* access_token provided by server for authenticating REST calls */
    char *tmp_jwt; /* access_token provided by server for authenticating a single REST call */
    int use_tmp_jwt; /* 1 if the tmp_jwt should be used */

    /* crypto module capabilities list */
    ACVP_CAPS_LIST *caps_list;

    /* application callbacks */
    ACVP_RESULT (*test_progress_cb) (char *msg);

    /* Two-factor authentication callback */
    ACVP_RESULT (*totp_cb) (char **token, int token_max);

    /* Transitory values */
    int vs_id;      /* vs_id currently being processed */

    JSON_Value *kat_resp; /* holds the current set of vector responses */

    char *curl_buf;       /**< Data buffer for inbound Curl messages */
    int curl_read_ctr;    /**< Total number of bytes written to the curl_buf */
    int post_size_constraint;  /**< The number of bytes that the body of an HTTP POST may contain
                                    without requiring the use of the /large endpoint. If the POST body
                                    is larger than this value, then use of the /large endpoint is necessary */

};

ACVP_RESULT acvp_check_test_results(ACVP_CTX *ctx);

ACVP_RESULT acvp_process_tests(ACVP_CTX *ctx);

ACVP_RESULT acvp_send_test_session_registration(ACVP_CTX *ctx, char *reg, int len);

ACVP_RESULT acvp_send_login(ACVP_CTX *ctx, char *login, int len);

ACVP_RESULT acvp_transport_put_validation(ACVP_CTX *ctx, const char *data, int data_len);

ACVP_RESULT acvp_transport_get(ACVP_CTX *ctx, const char *url, const ACVP_KV_LIST *parameters);

ACVP_RESULT acvp_transport_post(ACVP_CTX *ctx, const char *uri, char *data, int data_len);

ACVP_RESULT acvp_transport_put(ACVP_CTX *ctx, const char *endpoint, const char *data, int data_len);

ACVP_RESULT acvp_retrieve_vector_set(ACVP_CTX *ctx, char *vsid_url);

ACVP_RESULT acvp_retrieve_vector_set_result(ACVP_CTX *ctx, const char *vsid_url);

ACVP_RESULT acvp_retrieve_expected_result(ACVP_CTX *ctx, const char *api_url);

ACVP_RESULT acvp_submit_vector_responses(ACVP_CTX *ctx, char *vsid_url);

#ifdef _WIN32
void acvp_log_msg(ACVP_CTX *ctx, ACVP_LOG_LVL level, const char *format, ...);
#else
void acvp_log_msg(ACVP_CTX *ctx, ACVP_LOG_LVL level, const char *format, ...) __attribute__ ((format (gnu_printf, 3, 4)));
#endif
void acvp_log_newline(ACVP_CTX *ctx);
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

ACVP_RESULT acvp_rsa_decprim_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_rsa_sigprim_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

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

ACVP_RESULT acvp_pbkdf_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_dsa_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kas_ecc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kas_ecc_ssc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kas_ffc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kas_ffc_ssc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kas_ifc_ssc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

ACVP_RESULT acvp_kts_ifc_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);

/*
 * ACVP build registration functions used internally
 */
ACVP_RESULT acvp_build_test_session(ACVP_CTX *ctx, char **reg, int *out_len);

ACVP_RESULT acvp_build_validation(ACVP_CTX *ctx, char **out, int *out_len);

/*
 * Operating Environment functions
 */
void acvp_oe_free_operating_env(ACVP_CTX *ctx);

ACVP_RESULT acvp_oe_verify_fips_operating_env(ACVP_CTX *ctx);

ACVP_RESULT acvp_notify_large(ACVP_CTX *ctx,
                              const char *url,
                              char *large_url,
                              unsigned int data_len);

/*
 * ACVP utility functions used internally
 */
ACVP_CAPS_LIST *acvp_locate_cap_entry(ACVP_CTX *ctx, ACVP_CIPHER cipher);

const char *acvp_lookup_cipher_name(ACVP_CIPHER alg);

ACVP_CIPHER acvp_lookup_cipher_index(const char *algorithm);

ACVP_CIPHER acvp_lookup_cipher_w_mode_index(const char *algorithm,
                                            const char *mode);

const char *acvp_lookup_cipher_revision(ACVP_CIPHER alg);

ACVP_DRBG_MODE acvp_lookup_drbg_mode_index(const char *mode);

ACVP_DRBG_CAP_MODE_LIST *acvp_locate_drbg_mode_entry(ACVP_CAPS_LIST *cap, ACVP_DRBG_MODE mode);

const char *acvp_lookup_rsa_randpq_name(int value);

int acvp_lookup_rsa_randpq_index(const char *value);

ACVP_RESULT acvp_create_array(JSON_Object **obj, JSON_Value **val, JSON_Array **arry);

ACVP_RESULT is_valid_tf_param(int value);

const char *acvp_lookup_rsa_prime_test_name(ACVP_RSA_PRIME_TEST_TYPE type);
ACVP_RESULT is_valid_prime_test(const char *value);

ACVP_RESULT is_valid_rsa_mod(int value);

ACVP_HASH_ALG acvp_lookup_hash_alg(const char *name);
const char *acvp_lookup_hash_alg_name(ACVP_HASH_ALG id);

ACVP_EC_CURVE acvp_lookup_ec_curve(ACVP_CIPHER cipher, const char *name);
const char *acvp_lookup_ec_curve_name(ACVP_CIPHER cipher, ACVP_EC_CURVE id);

ACVP_RESULT acvp_refresh(ACVP_CTX *ctx);

void acvp_http_user_agent_handler(ACVP_CTX *ctx);

ACVP_RESULT acvp_setup_json_rsp_group(ACVP_CTX **ctx,
                                      JSON_Value **outer_arr_val,
                                      JSON_Value **r_vs_val,
                                      JSON_Object **r_vs,
                                      const char *alg_str,
                                      JSON_Array **groups_arr);

void acvp_release_json(JSON_Value *r_vs_val,
                       JSON_Value *r_gval);

JSON_Object *acvp_get_obj_from_rsp(ACVP_CTX *ctx, JSON_Value *arry_val);

int string_fits(const char *string, unsigned int max_allowed);

ACVP_RESULT acvp_kv_list_append(ACVP_KV_LIST **kv_list,
                                const char *key,
                                const char *value);

void acvp_kv_list_free(ACVP_KV_LIST *kv_list);

void acvp_free_str_list(ACVP_STRING_LIST **list);
ACVP_RESULT acvp_append_str_list(ACVP_STRING_LIST **list, const char *string);
int acvp_lookup_str_list(ACVP_STRING_LIST **list, const char *string);

ACVP_RESULT acvp_json_serialize_to_file_pretty_a(const JSON_Value *value, const char *filename);
ACVP_RESULT acvp_json_serialize_to_file_pretty_w(const JSON_Value *value, const char *filename);


#endif
