/**
 * @file
 * @brief This is the public header file to be included by applications
 *        using libacvp.
 */

/*
 * Copyright (c) 2023, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#ifndef acvp_h
#define acvp_h

#ifdef __cplusplus
extern "C"
{
#endif

#define ACVP_TOTP_LENGTH 8
#define ACVP_TOTP_TOKEN_MAX 128

#define ACVP_HASH_MCT_INNER     1000
#define ACVP_HASH_MCT_OUTER     100
#define ACVP_AES_MCT_INNER      1000
#define ACVP_AES_MCT_OUTER      100
#define ACVP_DES_MCT_INNER      10000
#define ACVP_DES_MCT_OUTER      400

/**
 * @enum ACVP_LOG_LVL
 * @brief This enum defines the different log levels for
 *        the ACVP client library. Each level also contains
 *        the logging for the level below it.
 *        Error level logging will only create output in case of failures.
 *        Warning level logging will create output for situations where the user may want to intervene,
 *        but are not neccessarily issues and running will continue.
 *        Status level logging is the default and will include high-level information about the progress
 *        of the test session and status of processing.
 *        Info level logging contains more info about network activity, metadata processing, and login.
 *        Verbose level logging is extensive and contains info about test groups and cases being run,
 *        more network activity, and other information. This is excessive for most users.
 */
typedef enum acvp_log_lvl {
    ACVP_LOG_LVL_NONE = 0,
    ACVP_LOG_LVL_ERR,
    ACVP_LOG_LVL_WARN,
    ACVP_LOG_LVL_STATUS,
    ACVP_LOG_LVL_INFO,
    ACVP_LOG_LVL_VERBOSE,
    ACVP_LOG_LVL_DEBUG,
    ACVP_LOG_LVL_MAX
} ACVP_LOG_LVL;

/**
 * @struct ACVP_CTX
 * @brief This opaque structure is used to maintain the state of a session with an ACVP server.
 *        A single instance of this context represents a session with the ACVP server. A session
 *        can consist of a regular test session, or various types of requests (like requesting a
 *        metadata listing.) Largely, This context is used by the application layer to perform the
 *        steps to conduct a test session. These steps are:
 *
 *        1. Create the context
 *        2. Specify the server hostname
 *        3. Specify the crypto algorithms to test
 *        4. Register with the ACVP server
 *        5. Commence the test with the server
 *        6. Check the test results
 *        7. Free the context
 */
typedef struct acvp_ctx_t ACVP_CTX;

/**
 * @enum ACVP_RESULT
 * @brief This enum is used to indicate error conditions to the application
 *        layer. Most libacvp function will return a value from this enum.
 */
typedef enum acvp_result {
    ACVP_SUCCESS = 0,
    ACVP_MALLOC_FAIL,        /**< Error allocating memory */
    ACVP_NO_CTX,             /**< An initalized context was expected but not present */
    ACVP_TRANSPORT_FAIL,     /**< Error exchanging data with server */
    ACVP_NO_DATA,            /**< Required data for operation is missing */
    ACVP_UNSUPPORTED_OP,     /**< An operation has been requested that is not supported. This can
                                  either be because parameters are not valid or because the library
                                  does not support something at the time */
    ACVP_CLEANUP_FAIL,       /**< Failure when cleaning up (e.g. freeing memory) after operations */
    ACVP_KAT_DOWNLOAD_RETRY, /**< Does not neccessarily indicate an error, but that data requested
                                  from server is not yet ready to be accessed */
    ACVP_INVALID_ARG,        /**< A provided argument or parameter is not valid for the given operation */
    ACVP_MISSING_ARG,        /**< A required argument or parameter is not provided/null/0 */
    ACVP_CRYPTO_MODULE_FAIL, /**< A non-zero return code was provided by the application callback 
                                  for test case processin; this should indicate that the application
                                  failed to process the test case*/
    ACVP_NO_CAP,             /**< A registered capability object for the given algorithm does not exist. This
                                  usually means an operation is being requested for an algorithm that is not yet
                                  registered */
    ACVP_MALFORMED_JSON,     /**< The given JSON is not properly formatted/readable JSON */
    ACVP_JSON_ERR,           /**< Error occured attempting to parse JSON into data stuctures */
    ACVP_TC_MISSING_DATA,    /**< Data is missing from test case JSON */
    ACVP_TC_INVALID_DATA,    /**< Test case JSON is formatted properly, but the data is bad, does not
                                  match the registration, or does not match the spec */
    ACVP_DATA_TOO_LARGE,     /**< The given parameter larger than the library allows. This can apply to strings,
                                  server responses, files, etc */
    ACVP_CONVERT_DATA_ERR,   /**< Error converting data between hexidecimal and binary (either direction) */
    ACVP_DUP_CIPHER,         /**< The client is attempting to register an algorithm that has already been registered */
    ACVP_TOTP_FAIL,          /**< A failure occured attempting to generate a TOTP */
    ACVP_CTX_NOT_EMPTY,      /**< Occurs specifically when an attempt is made to initialize a CTX that is already initialized */
    ACVP_JWT_MISSING,        /**< A JSON web token is missing from a file or from memory but was expected */
    ACVP_JWT_EXPIRED,        /**< The provided JWT was not accepted by the server because it is expired */
    ACVP_JWT_INVALID,        /**< A provided JSON web token is invalid due to its size, encoding, or contents */
    ACVP_INTERNAL_ERR,       /**< An unexpected error occuring internally to libacvp */
    ACVP_RESULT_MAX
} ACVP_RESULT;

/**
 * These are the available algorithms that libacvp supports. The application layer will need to
 * register one or more of these based on the capabilities of the crypto module being validated.
 * Libacvp may not support every desired algorithm; the list of all algorithms supported by the
 * protocol itself can be found in the ACVP specification.
 *
 * **************** ALERT *****************
 * This enum must stay aligned with alg_tbl[] in acvp.c
 */
/**
 * @enum ACVP_CIPHER
 * @brief This enum lists the various algorithms supported by the ACVP
 *        library
 */
typedef enum acvp_cipher {
    ACVP_CIPHER_START = 0,
    ACVP_AES_GCM,
    ACVP_AES_GCM_SIV,
    ACVP_AES_CCM,
    ACVP_AES_ECB,
    ACVP_AES_CBC,
    ACVP_AES_CBC_CS1,
    ACVP_AES_CBC_CS2,
    ACVP_AES_CBC_CS3,
    ACVP_AES_CFB1,
    ACVP_AES_CFB8,
    ACVP_AES_CFB128,
    ACVP_AES_OFB,
    ACVP_AES_CTR,
    ACVP_AES_XTS,
    ACVP_AES_KW,
    ACVP_AES_KWP,
    ACVP_AES_GMAC,
    ACVP_AES_XPN,
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
    ACVP_HASH_SHA1,
    ACVP_HASH_SHA224,
    ACVP_HASH_SHA256,
    ACVP_HASH_SHA384,
    ACVP_HASH_SHA512,
    ACVP_HASH_SHA512_224,
    ACVP_HASH_SHA512_256,
    ACVP_HASH_SHA3_224,
    ACVP_HASH_SHA3_256,
    ACVP_HASH_SHA3_384,
    ACVP_HASH_SHA3_512,
    ACVP_HASH_SHAKE_128,
    ACVP_HASH_SHAKE_256,
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
    ACVP_KMAC_128,
    ACVP_KMAC_256,
    ACVP_DSA_KEYGEN,
    ACVP_DSA_PQGGEN,
    ACVP_DSA_PQGVER,
    ACVP_DSA_SIGGEN,
    ACVP_DSA_SIGVER,
    ACVP_RSA_KEYGEN,
    ACVP_RSA_SIGGEN,
    ACVP_RSA_SIGVER,
    ACVP_RSA_DECPRIM,
    ACVP_RSA_SIGPRIM,
    ACVP_ECDSA_KEYGEN,
    ACVP_ECDSA_KEYVER,
    ACVP_ECDSA_SIGGEN,
    ACVP_ECDSA_SIGVER,
    ACVP_KDF135_SNMP,
    ACVP_KDF135_SSH,
    ACVP_KDF135_SRTP,
    ACVP_KDF135_IKEV2,
    ACVP_KDF135_IKEV1,
    ACVP_KDF135_X942,
    ACVP_KDF135_X963,
    ACVP_KDF108,
    ACVP_PBKDF,
    ACVP_KDF_TLS12,
    ACVP_KDF_TLS13,
    ACVP_KAS_ECC_CDH,
    ACVP_KAS_ECC_COMP,
    ACVP_KAS_ECC_NOCOMP,
    ACVP_KAS_ECC_SSC,
    ACVP_KAS_FFC_COMP,
    ACVP_KAS_FFC_NOCOMP,
    ACVP_KAS_FFC_SSC,
    ACVP_KAS_IFC_SSC,
    ACVP_KDA_ONESTEP,
    ACVP_KDA_TWOSTEP,
    ACVP_KDA_HKDF,
    ACVP_KTS_IFC,
    ACVP_SAFE_PRIMES_KEYGEN,
    ACVP_SAFE_PRIMES_KEYVER,
    ACVP_LMS_KEYGEN,
    ACVP_LMS_SIGGEN,
    ACVP_LMS_SIGVER,
    ACVP_CIPHER_END
} ACVP_CIPHER;


/**
 * The following are sub-type algorithms which can be used within
 * algorithm specific code to avoid having to include all the
 * above enums in the case statements.
 *
 * To get the sub-type enum call the algorithm specific functions
 * in acvp.c such as acvp_get_aes_alg(CIPHER).
 *
 * These enums MUST maintain the same values as the CIPHER enum
 * above thus ordering is of the utmost importance.
 */
typedef enum acvp_alg_type_aes {
    ACVP_SUB_AES_GCM = ACVP_AES_GCM,
    ACVP_SUB_AES_GCM_SIV,
    ACVP_SUB_AES_CCM,
    ACVP_SUB_AES_ECB,
    ACVP_SUB_AES_CBC,
    ACVP_SUB_AES_CBC_CS1,
    ACVP_SUB_AES_CBC_CS2,
    ACVP_SUB_AES_CBC_CS3,
    ACVP_SUB_AES_CFB1,
    ACVP_SUB_AES_CFB8,
    ACVP_SUB_AES_CFB128,
    ACVP_SUB_AES_OFB,
    ACVP_SUB_AES_CTR,
    ACVP_SUB_AES_XTS,
    ACVP_SUB_AES_XPN,
    ACVP_SUB_AES_KW,
    ACVP_SUB_AES_KWP,
    ACVP_SUB_AES_GMAC
} ACVP_SUB_AES;

/** @enum ACVP_SUB_TDES */
typedef enum acvp_alg_type_tdes {
    ACVP_SUB_TDES_ECB = ACVP_TDES_ECB,
    ACVP_SUB_TDES_CBC,
    ACVP_SUB_TDES_CBCI,
    ACVP_SUB_TDES_OFB,
    ACVP_SUB_TDES_OFBI,
    ACVP_SUB_TDES_CFB1,
    ACVP_SUB_TDES_CFB8,
    ACVP_SUB_TDES_CFB64,
    ACVP_SUB_TDES_CFBP1,
    ACVP_SUB_TDES_CFBP8,
    ACVP_SUB_TDES_CFBP64,
    ACVP_SUB_TDES_CTR,
    ACVP_SUB_TDES_KW
} ACVP_SUB_TDES;

/** @enum ACVP_SUB_CMAC */
typedef enum acvp_alg_type_cmac {
    ACVP_SUB_CMAC_AES = ACVP_CMAC_AES,
    ACVP_SUB_CMAC_TDES
} ACVP_SUB_CMAC;

/** @enum ACVP_SUB_KMAC */
typedef enum acvp_alg_type_kmac {
    ACVP_SUB_KMAC_128 = ACVP_KMAC_128,
    ACVP_SUB_KMAC_256
} ACVP_SUB_KMAC;

/** @enum ACVP_SUB_HMAC */
typedef enum acvp_alg_type_hmac {
    ACVP_SUB_HMAC_SHA1 = ACVP_HMAC_SHA1,
    ACVP_SUB_HMAC_SHA2_224,
    ACVP_SUB_HMAC_SHA2_256,
    ACVP_SUB_HMAC_SHA2_384,
    ACVP_SUB_HMAC_SHA2_512,
    ACVP_SUB_HMAC_SHA2_512_224,
    ACVP_SUB_HMAC_SHA2_512_256,
    ACVP_SUB_HMAC_SHA3_224,
    ACVP_SUB_HMAC_SHA3_256,
    ACVP_SUB_HMAC_SHA3_384,
    ACVP_SUB_HMAC_SHA3_512
} ACVP_SUB_HMAC;

/** @enum ACVP_SUB_HASH */
typedef enum acvp_alg_type_hash {
    ACVP_SUB_HASH_SHA1 = ACVP_HASH_SHA1,
    ACVP_SUB_HASH_SHA2_224,
    ACVP_SUB_HASH_SHA2_256,
    ACVP_SUB_HASH_SHA2_384,
    ACVP_SUB_HASH_SHA2_512,
    ACVP_SUB_HASH_SHA2_512_224,
    ACVP_SUB_HASH_SHA2_512_256,
    ACVP_SUB_HASH_SHA3_224,
    ACVP_SUB_HASH_SHA3_256,
    ACVP_SUB_HASH_SHA3_384,
    ACVP_SUB_HASH_SHA3_512,
    ACVP_SUB_HASH_SHAKE_128,
    ACVP_SUB_HASH_SHAKE_256
} ACVP_SUB_HASH;

/** @enum ACVP_SUB_DSA */
typedef enum acvp_alg_type_dsa {
    ACVP_SUB_DSA_KEYGEN = ACVP_DSA_KEYGEN,
    ACVP_SUB_DSA_PQGGEN,
    ACVP_SUB_DSA_PQGVER,
    ACVP_SUB_DSA_SIGGEN,
    ACVP_SUB_DSA_SIGVER,
} ACVP_SUB_DSA;

/** @enum ACVP_SUB_RSA */
typedef enum acvp_alg_type_rsa {
    ACVP_SUB_RSA_KEYGEN = ACVP_RSA_KEYGEN,
    ACVP_SUB_RSA_SIGGEN,
    ACVP_SUB_RSA_SIGVER,
    ACVP_SUB_RSA_DECPRIM,
    ACVP_SUB_RSA_SIGPRIM
} ACVP_SUB_RSA;

/** @enum ACVP_SUB_ECDSA */
typedef enum acvp_alg_type_ecdsa {
    ACVP_SUB_ECDSA_KEYGEN = ACVP_ECDSA_KEYGEN,
    ACVP_SUB_ECDSA_KEYVER,
    ACVP_SUB_ECDSA_SIGGEN,
    ACVP_SUB_ECDSA_SIGVER
} ACVP_SUB_ECDSA;

/** @enum ACVP_SUB_DRBG */
typedef enum acvp_alg_type_drbg {
    ACVP_SUB_DRBG_HASH = ACVP_HASHDRBG,
    ACVP_SUB_DRBG_HMAC,
    ACVP_SUB_DRBG_CTR
} ACVP_SUB_DRBG;

/** @enum ACVP_SUB_KAS */
typedef enum acvp_alg_type_kas {
    ACVP_SUB_KAS_ECC_CDH = ACVP_KAS_ECC_CDH,
    ACVP_SUB_KAS_ECC_COMP,
    ACVP_SUB_KAS_ECC_NOCOMP,
    ACVP_SUB_KAS_ECC_SSC,
    ACVP_SUB_KAS_FFC_COMP,
    ACVP_SUB_KAS_FFC_SSC,
    ACVP_SUB_KAS_FFC_NOCOMP,
    ACVP_SUB_KAS_IFC_SSC,
    ACVP_SUB_KTS_IFC,
    ACVP_SUB_KDA_ONESTEP,
    ACVP_SUB_KDA_TWOSTEP,
    ACVP_SUB_KDA_HKDF,
    ACVP_SUB_SAFE_PRIMES_KEYGEN,
    ACVP_SUB_SAFE_PRIMES_KEYVER
} ACVP_SUB_KAS;

/** @enum ACVP_SUB_KDF */
typedef enum acvp_alg_type_kdf {
    ACVP_SUB_KDF_SNMP = ACVP_KDF135_SNMP,
    ACVP_SUB_KDF_SSH,
    ACVP_SUB_KDF_SRTP,
    ACVP_SUB_KDF_IKEV2,
    ACVP_SUB_KDF_IKEV1,
    ACVP_SUB_KDF_X942,
    ACVP_SUB_KDF_X963,
    ACVP_SUB_KDF_108,
    ACVP_SUB_KDF_PBKDF,
    ACVP_SUB_KDF_TLS12,
    ACVP_SUB_KDF_TLS13
} ACVP_SUB_KDF;

/** @enum ACVP_SUB_LMS */
typedef enum acvp_alg_type_lms {
    ACVP_SUB_LMS_KEYGEN = ACVP_LMS_KEYGEN,
    ACVP_SUB_LMS_SIGGEN,
    ACVP_SUB_LMS_SIGVER
} ACVP_SUB_LMS;

#define CIPHER_TO_ALG(alg2) (alg_tbl[cipher].alg.alg2)

/**
 * @enum ACVP_PREREQ_ALG
 * @brief This enum lists the prerequisities that are available
 *        to the library during registration. Whereas an ACVP_CIPHER may
 *        specify a certain mode or key size, the prereqs are more
 *        generic.
 */
typedef enum acvp_prereq_mode_t {
    ACVP_PREREQ_AES = 1,
    ACVP_PREREQ_CCM,
    ACVP_PREREQ_CMAC,
    ACVP_PREREQ_DRBG,
    ACVP_PREREQ_DSA,
    ACVP_PREREQ_ECDSA,
    ACVP_PREREQ_HMAC,
    ACVP_PREREQ_KAS,
    ACVP_PREREQ_RSA,
    ACVP_PREREQ_RSADP,
    ACVP_PREREQ_SAFE_PRIMES,
    ACVP_PREREQ_SHA,
    ACVP_PREREQ_TDES,
    ACVP_PREREQ_KMAC
} ACVP_PREREQ_ALG;

/**
 * @enum ACVP_CONFORMANCE
 * @brief this enum lists different conformances that can be claimed in libacvp. These are largely
 *        algorithm specific.
 */
typedef enum acvp_conformance_t {
    ACVP_CONFORMANCE_DEFAULT = 0,
    ACVP_CONFORMANCE_RFC3686,
    ACVP_CONFORMANCE_MAX
} ACVP_CONFORMANCE;

/**
 * @enum ACVP_REVISION
 * @brief this enum lists revisions that may be claimed for ciphers alternative to the default ones
 *        used by libacvp. This may grow over time. Because one revision may apply to multiple
 *        algorithms, this list is universal and the library determines which ones revisions are
 *        allowed for which algorihms.
 */
typedef enum acvp_revision_t {
    ACVP_REVISION_DEFAULT = 0,
    ACVP_REVISION_SP800_56CR1,
    ACVP_REVISION_SP800_56AR3,
    ACVP_REVISION_MAX
} ACVP_REVISION;

/**
 * @enum ACVP_HASH_ALG
 * @brief Represents the general hash algorithms. Can be used as bit flags.
 */
typedef enum acvp_hash_alg {
    ACVP_NO_SHA = 0,
    ACVP_SHA1 = 1,
    ACVP_SHA224 = 2,
    ACVP_SHA256 = 4,
    ACVP_SHA384 = 8,
    ACVP_SHA512 = 16,
    ACVP_SHA512_224 = 32,
    ACVP_SHA512_256 = 64,
    ACVP_SHA3_224 = 128,
    ACVP_SHA3_256 = 256,
    ACVP_SHA3_384 = 512,
    ACVP_SHA3_512 = 1024,
    ACVP_HASH_ALG_MAX = 2048
} ACVP_HASH_ALG;

/**
 * @enum ACVP_TEST_DISPOSITION
 * @brief These values are used to indicate the pass/fail status of a test session
 */
typedef enum acvp_test_disposition {
    ACVP_TEST_DISPOSITION_FAIL = 0,
    ACVP_TEST_DISPOSITION_PASS = 1
} ACVP_TEST_DISPOSITION;

/**
 * The following enumerators are used to track the capabiltiies that the application
 * registers with the library and are used in data fields for some test cases.
 */

/** @enum ACVP_KDF135_SSH_METHOD */
typedef enum acvp_kdf135_ssh_method {
    ACVP_SSH_METH_TDES_CBC = 1,
    ACVP_SSH_METH_AES_128_CBC,
    ACVP_SSH_METH_AES_192_CBC,
    ACVP_SSH_METH_AES_256_CBC,
    ACVP_SSH_METH_MAX
} ACVP_KDF135_SSH_METHOD;

/** @enum ACVP_KDF135_IKEV1_AUTH_METHOD */
typedef enum acvp_kdf135_ikev1_auth_method {
    ACVP_KDF135_IKEV1_AMETH_DSA = 1,
    ACVP_KDF135_IKEV1_AMETH_PSK,
    ACVP_KDF135_IKEV1_AMETH_PKE,
    ACVP_KDF135_IKEV1_AMETH_MAX
} ACVP_KDF135_IKEV1_AUTH_METHOD;

/** @enum ACVP_KDF135_SRTP_PARAM */
typedef enum acvp_kdf135_srtp_param {
    ACVP_SRTP_AES_KEYLEN = 1,
    ACVP_SRTP_SUPPORT_ZERO_KDR,
    ACVP_SRTP_KDF_EXPONENT
} ACVP_KDF135_SRTP_PARAM;

#define ACVP_KDF108_KEYOUT_MAX 64     /**< SHA2-512 */
#define ACVP_KDF108_FIXED_DATA_MAX 64 /**< SHA2-512 */

/** @enum ACVP_KDF108_MODE */
typedef enum acvp_kdf108_mode {
    ACVP_KDF108_MODE_COUNTER = 1,
    ACVP_KDF108_MODE_FEEDBACK,
    ACVP_KDF108_MODE_DPI
} ACVP_KDF108_MODE;

/** @enum ACVP_KDF108_MAC_MODE_VAL */
typedef enum acvp_kdf108_mac_mode_val {
    ACVP_KDF108_MAC_MODE_MIN,
    ACVP_KDF108_MAC_MODE_CMAC_AES128,
    ACVP_KDF108_MAC_MODE_CMAC_AES192,
    ACVP_KDF108_MAC_MODE_CMAC_AES256,
    ACVP_KDF108_MAC_MODE_CMAC_TDES,
    ACVP_KDF108_MAC_MODE_HMAC_SHA1,
    ACVP_KDF108_MAC_MODE_HMAC_SHA224,
    ACVP_KDF108_MAC_MODE_HMAC_SHA256,
    ACVP_KDF108_MAC_MODE_HMAC_SHA384,
    ACVP_KDF108_MAC_MODE_HMAC_SHA512,
    ACVP_KDF108_MAC_MODE_HMAC_SHA512_224,
    ACVP_KDF108_MAC_MODE_HMAC_SHA512_256,
    ACVP_KDF108_MAC_MODE_HMAC_SHA3_224,
    ACVP_KDF108_MAC_MODE_HMAC_SHA3_256,
    ACVP_KDF108_MAC_MODE_HMAC_SHA3_384,
    ACVP_KDF108_MAC_MODE_HMAC_SHA3_512,
    ACVP_KDF108_MAC_MODE_MAX
} ACVP_KDF108_MAC_MODE_VAL;

/** @enum ACVP_KDF108_FIXED_DATA_ORDER_VAL */
typedef enum acvp_kdf108_fixed_data_order_val {
    ACVP_KDF108_FIXED_DATA_ORDER_MIN,
    ACVP_KDF108_FIXED_DATA_ORDER_NONE,
    ACVP_KDF108_FIXED_DATA_ORDER_AFTER,
    ACVP_KDF108_FIXED_DATA_ORDER_BEFORE,
    ACVP_KDF108_FIXED_DATA_ORDER_MIDDLE,
    ACVP_KDF108_FIXED_DATA_ORDER_BEFORE_ITERATOR,
    ACVP_KDF108_FIXED_DATA_ORDER_MAX
} ACVP_KDF108_FIXED_DATA_ORDER_VAL;

/** @enum ACVP_SYM_CIPH_KO */
typedef enum acvp_sym_cipher_keying_option {
    ACVP_SYM_CIPH_KO_NA = 0,
    ACVP_SYM_CIPH_KO_ONE,
    ACVP_SYM_CIPH_KO_THREE, /**< This is outdated and will eventually be removed */
    ACVP_SYM_CIPH_KO_TWO,
    ACVP_SYM_CIPH_KO_BOTH,
    ACVP_SYM_CIPH_KO_MAX
} ACVP_SYM_CIPH_KO;

/**
 * @enum ACVP_SYM_CIPH_IVGEN_SRC
 * @brief The IV generation source for AEAD ciphers. This can be internal, external, or not applicable.
 */
typedef enum acvp_sym_cipher_ivgen_source {
    ACVP_SYM_CIPH_IVGEN_SRC_INT = 1,
    ACVP_SYM_CIPH_IVGEN_SRC_EXT,
    ACVP_SYM_CIPH_IVGEN_SRC_EITHER,
    ACVP_SYM_CIPH_IVGEN_SRC_NA,
    ACVP_SYM_CIPH_IVGEN_SRC_MAX
} ACVP_SYM_CIPH_IVGEN_SRC;


/**
 * @enum ACVP_SYM_CIPH_SALT_SRC
 * @brief The IV generation source for AES_XPN. This can be internal, external, or not applicable.
 */
typedef enum acvp_sym_cipher_salt_source {
    ACVP_SYM_CIPH_SALT_SRC_INT = 1,
    ACVP_SYM_CIPH_SALT_SRC_EXT,
    ACVP_SYM_CIPH_SALT_SRC_NA,
    ACVP_SYM_CIPH_SALT_SRC_MAX
} ACVP_SYM_CIPH_SALT_SRC;

/**
 * @enum ACVP_SYM_CIPH_IVGEN_MODE
 * @brief The IV generation mode. It can comply with 8.2.1, 8.2.2, or may not be applicable for some ciphers.
 */
typedef enum acvp_sym_cipher_ivgen_mode {
    ACVP_SYM_CIPH_IVGEN_MODE_821 = 1,
    ACVP_SYM_CIPH_IVGEN_MODE_822,
    ACVP_SYM_CIPH_IVGEN_MODE_NA,
    ACVP_SYM_CIPH_IVGEN_MODE_MAX
} ACVP_SYM_CIPH_IVGEN_MODE;


/**
 * @enum ACVP_SYM_CIPH_DIR
 * @brief These are the algorithm direction suppported by libacvp. These are used in conjunction
 *        with ACVP_SYM_CIPH when registering the crypto module capabilities with libacvp.
 */
typedef enum acvp_sym_cipher_direction {
    ACVP_SYM_CIPH_DIR_ENCRYPT = 1,
    ACVP_SYM_CIPH_DIR_DECRYPT,
    ACVP_SYM_CIPH_DIR_BOTH,
    ACVP_SYM_CIPH_DIR_MAX
} ACVP_SYM_CIPH_DIR;

/** @enum ACVP_KDF135_SNMP_PARAM */
typedef enum acvp_kdf135_snmp_param {
    ACVP_KDF135_SNMP_PASS_LEN,
    ACVP_KDF135_SNMP_ENGID
} ACVP_KDF135_SNMP_PARAM;

#define ACVP_STR_SHA_1          "SHA-1"
#define ACVP_STR_SHA2_224       "SHA2-224"
#define ACVP_STR_SHA2_256       "SHA2-256"
#define ACVP_STR_SHA2_384       "SHA2-384"
#define ACVP_STR_SHA2_512       "SHA2-512"
#define ACVP_STR_SHA2_512_224   "SHA2-512/224"
#define ACVP_STR_SHA2_512_256   "SHA2-512/256"
#define ACVP_STR_SHA3_224       "SHA3-224"
#define ACVP_STR_SHA3_256       "SHA3-256"
#define ACVP_STR_SHA3_384       "SHA3-384"
#define ACVP_STR_SHA3_512       "SHA3-512"
#define ACVP_STR_SHA_MAX        12

/** @enum ACVP_HASH_PARM */
typedef enum acvp_hash_param {
    ACVP_HASH_IN_BIT = 1,
    ACVP_HASH_IN_EMPTY,
    ACVP_HASH_OUT_BIT, /**< Used for ACVP_HASH_SHAKE_128, ACVP_HASH_SHAKE_256 */
    ACVP_HASH_OUT_LENGTH, /**< Used for ACVP_HASH_SHAKE_128, ACVP_HASH_SHAKE_256 */
    ACVP_HASH_MESSAGE_LEN
} ACVP_HASH_PARM;

/**
 * ****************** ALERT *****************
 * This enum must stay aligned with drbg_mode_tbl[] in acvp_util.c
 */
/** @enum ACVP_DRBG_MODE */
typedef enum acvp_drbg_mode {
    ACVP_DRBG_SHA_1 = 1,
    ACVP_DRBG_SHA_224,
    ACVP_DRBG_SHA_256,
    ACVP_DRBG_SHA_384,
    ACVP_DRBG_SHA_512,
    ACVP_DRBG_SHA_512_224,
    ACVP_DRBG_SHA_512_256,
    ACVP_DRBG_TDES,
    ACVP_DRBG_AES_128,
    ACVP_DRBG_AES_192,
    ACVP_DRBG_AES_256
} ACVP_DRBG_MODE;

/** @enum ACVP_DRBG_PARM */
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

/** @enum ACVP_RSA_PARM */
typedef enum acvp_rsa_param {
    ACVP_RSA_PARM_PUB_EXP_MODE = 1,
    ACVP_RSA_PARM_FIXED_PUB_EXP_VAL,
    ACVP_RSA_PARM_KEY_FORMAT_CRT,
    ACVP_RSA_PARM_RAND_PQ,
    ACVP_RSA_PARM_INFO_GEN_BY_SERVER,
} ACVP_RSA_PARM;

/** @enum ACVP_RSA_PRIME_PARAM */
typedef enum acvp_rsa_prime_param {
    ACVP_RSA_PRIME_HASH_ALG = 1,
    ACVP_RSA_PRIME_TEST,
} ACVP_RSA_PRIME_PARAM;

/** @enum ACVP_ECDSA_PARM */
typedef enum acvp_ecdsa_param {
    ACVP_ECDSA_CURVE,
    ACVP_ECDSA_SECRET_GEN,
    ACVP_ECDSA_HASH_ALG,
    ACVP_ECDSA_COMPONENT_TEST
} ACVP_ECDSA_PARM;

/** @enum ACVP_ECDSA_SECRET_GEN_MODE */
typedef enum acvp_ecdsa_secret_gen_mode {
    ACVP_ECDSA_SECRET_GEN_EXTRA_BITS = 1,
    ACVP_ECDSA_SECRET_GEN_TEST_CAND
} ACVP_ECDSA_SECRET_GEN_MODE;

/** @enum ACVP_EC_CURVE */
typedef enum acvp_ec_curve {
    ACVP_EC_CURVE_START = 0,
    ACVP_EC_CURVE_P192,
    ACVP_EC_CURVE_P224,
    ACVP_EC_CURVE_P256,
    ACVP_EC_CURVE_P384,
    ACVP_EC_CURVE_P521,
    ACVP_EC_CURVE_B163,
    ACVP_EC_CURVE_B233,
    ACVP_EC_CURVE_B283,
    ACVP_EC_CURVE_B409,
    ACVP_EC_CURVE_B571,
    ACVP_EC_CURVE_K163,
    ACVP_EC_CURVE_K233,
    ACVP_EC_CURVE_K283,
    ACVP_EC_CURVE_K409,
    ACVP_EC_CURVE_K571,
    ACVP_EC_CURVE_END
} ACVP_EC_CURVE;

/** @enum ACVP_ECDSA_COMPONENT_MODE */
typedef enum acvp_ecdsa_component_mode {
    ACVP_ECDSA_COMPONENT_MODE_NO,
    ACVP_ECDSA_COMPONENT_MODE_YES,
    ACVP_ECDSA_COMPONENT_MODE_BOTH
} ACVP_ECDSA_COMPONENT_MODE;

/** @enum ACVP_KDF135_IKEV2_PARM */
typedef enum acvp_kdf135_ikev2_param {
    ACVP_KDF_HASH_ALG,
    ACVP_INIT_NONCE_LEN,
    ACVP_RESPOND_NONCE_LEN,
    ACVP_DH_SECRET_LEN,
    ACVP_KEY_MATERIAL_LEN
} ACVP_KDF135_IKEV2_PARM;

/** @enum ACVP_KDF135_IKEV1_PARM */
typedef enum acvp_kdf135_ikev1_param {
    ACVP_KDF_IKEv1_HASH_ALG,
    ACVP_KDF_IKEv1_AUTH_METHOD,
    ACVP_KDF_IKEv1_INIT_NONCE_LEN,
    ACVP_KDF_IKEv1_RESPOND_NONCE_LEN,
    ACVP_KDF_IKEv1_DH_SECRET_LEN,
    ACVP_KDF_IKEv1_PSK_LEN
} ACVP_KDF135_IKEV1_PARM;

/** @enum ACVP_KDF135_X942_TYPE */
typedef enum acvp_kdf_x942_type {
    ACVP_KDF_X942_KDF_TYPE_DER,
    ACVP_KDF_X942_KDF_TYPE_CONCAT,
    ACVP_KDF_X942_KDF_TYPE_BOTH
} ACVP_KDF_X942_TYPE;

/** @enum ACVP_KDF135_X942_OID */
typedef enum acvp_kdf135_x942_oid {
    ACVP_KDF_X942_OID_TDES,
    ACVP_KDF_X942_OID_AES128KW,
    ACVP_KDF_X942_OID_AES192KW,
    ACVP_KDF_X942_OID_AES256KW
} ACVP_KDF135_X942_OID;

/** @enum ACVP_KDF135_X942_PARM */
typedef enum acvp_kdf135_x942_param {
    ACVP_KDF_X942_KDF_TYPE,
    ACVP_KDF_X942_KEY_LEN,
    ACVP_KDF_X942_OTHER_INFO_LEN,
    ACVP_KDF_X942_SUPP_INFO_LEN,
    ACVP_KDF_X942_ZZ_LEN,
    ACVP_KDF_X942_OID,
    ACVP_KDF_X942_HASH_ALG
} ACVP_KDF135_X942_PARM;


/** @enum ACVP_KDF135_X963_PARM */
typedef enum acvp_kdf135_x963_param {
    ACVP_KDF_X963_HASH_ALG,
    ACVP_KDF_X963_KEY_DATA_LEN,
    ACVP_KDF_X963_FIELD_SIZE,
    ACVP_KDF_X963_SHARED_INFO_LEN
} ACVP_KDF135_X963_PARM;

/** @enum ACVP_KDF108_PARM */
typedef enum acvp_kdf108_param {
    ACVP_KDF108_PARAM_MIN,
    ACVP_KDF108_KDF_MODE,
    ACVP_KDF108_MAC_MODE,
    ACVP_KDF108_SUPPORTED_LEN,
    ACVP_KDF108_FIXED_DATA_ORDER,
    ACVP_KDF108_COUNTER_LEN,
    ACVP_KDF108_SUPPORTS_EMPTY_IV,
    ACVP_KDF108_REQUIRES_EMPTY_IV,
    ACVP_KDF108_PARAM_MAX
} ACVP_KDF108_PARM;

/** @enum ACVP_PBKDF_PARM */
typedef enum acvp_pbkdf_param {
    ACVP_PBKDF_PARAM_MIN,
    ACVP_PBKDF_ITERATION_COUNT,
    ACVP_PBKDF_KEY_LEN,
    ACVP_PBKDF_PASSWORD_LEN,
    ACVP_PBKDF_SALT_LEN,
    ACVP_PBKDF_HMAC_ALG
} ACVP_PBKDF_PARM;

/** @enum ACVP_KDF_TLS12_PARM */
typedef enum acvp_kdf_tls12_param {
    ACVP_KDF_TLS12_PARAM_MIN,
    ACVP_KDF_TLS12_HASH_ALG /**< HMAC algorithms supported by TLS 1.2 imeplementation */
} ACVP_KDF_TLS12_PARM;

/** @enum ACVP_KDF_TLS13_RUN_MODE */
typedef enum acvp_kdf_tls13_running_mode {
    ACVP_KDF_TLS13_RUN_MODE_MIN,
    ACVP_KDF_TLS13_RUN_MODE_PSK,
    ACVP_KDF_TLS13_RUN_MODE_DHE,
    ACVP_KDF_TLS13_RUN_MODE_PSK_DHE,
    ACVP_KDF_TLS13_RUN_MODE_MAX
} ACVP_KDF_TLS13_RUN_MODE;

/** @enum ACVP_KDF_TLS13_PARM */
typedef enum acvp_kdf_tls13_param {
    ACVP_KDF_TLS13_PARAM_MIN,
    ACVP_KDF_TLS13_HMAC_ALG,
    ACVP_KDF_TLS13_RUNNING_MODE
} ACVP_KDF_TLS13_PARM;

/** @enum ACVP_RSA_TESTTYPE */
typedef enum acvp_rsa_test_type {
    ACVP_RSA_TESTTYPE_KAT = 1, /**< Known Answer Test */
    ACVP_RSA_TESTTYPE_AFT,     /**< Algorithm Functional Test */
    ACVP_RSA_TESTTYPE_GDT      /**< Generated Data Test */
} ACVP_RSA_TESTTYPE;

/** @enum ACVP_RSA_KEY_FORMAT */
typedef enum acvp_rsa_key_format {
    ACVP_RSA_KEY_FORMAT_STANDARD = 1, /**< Standard */
    ACVP_RSA_KEY_FORMAT_CRT           /**< Chinese Remainder Theorem */
} ACVP_RSA_KEY_FORMAT;

/** @enum ACVP_RSA_PUB_EXP_MODE */
typedef enum acvp_rsa_pub_exp_mode {
    ACVP_RSA_PUB_EXP_MODE_FIXED = 1,
    ACVP_RSA_PUB_EXP_MODE_RANDOM
} ACVP_RSA_PUB_EXP_MODE;

/** @enum ACVP_RSA_PRIME_TEST_TYPE */
typedef enum acvp_rsa_prime_test_type {
    ACVP_RSA_PRIME_TEST_TBLC2 = 1,
    ACVP_RSA_PRIME_TEST_TBLC3
} ACVP_RSA_PRIME_TEST_TYPE;

/** @enum ACVP_RSA_KEYGEN_MODE */
typedef enum acvp_rsa_keygen_mode_t {
    ACVP_RSA_KEYGEN_B32 = 1,
    ACVP_RSA_KEYGEN_B33,
    ACVP_RSA_KEYGEN_B34,
    ACVP_RSA_KEYGEN_B35,
    ACVP_RSA_KEYGEN_B36
} ACVP_RSA_KEYGEN_MODE;

/** @enum ACVP_RSA_SIG_TYPE */
typedef enum acvp_rsa_sig_type {
    ACVP_RSA_SIG_TYPE_X931 = 1,
    ACVP_RSA_SIG_TYPE_PKCS1V15,
    ACVP_RSA_SIG_TYPE_PKCS1PSS
} ACVP_RSA_SIG_TYPE;

/** @enum ACVP_RSA_PRIM_KEYFORMAT */
typedef enum acvp_rsa_prim_keyformat {
    ACVP_RSA_PRIM_KEYFORMAT_STANDARD = 1,
    ACVP_RSA_PRIM_KEYFORMAT_CRT
} ACVP_RSA_PRIM_KEYFORMAT;

/**
 * @struct ACVP_RSA_PRIM_TC
 * @brief This struct holds data that represents a single test case for a RSA primitive cipher.
 *        This data is passed between libacvp and the crypto module. libacvp will parse the test
 *        case parameters from the JSON encoded test vector, fill in this structure, and pass the
 *        struct to the crypto module via the handler that was registered with libacvp. The crypto
 *        module will then need to perform the crypto operation and fill in the remaining tems in
 *        the struct for the given test case. The struct is then passed back to libacvp, where it
 *        is then used to build the JSON encoded vector response.

 */
typedef struct acvp_rsa_prim_tc_t {
    unsigned int tc_id;    /**< Test case id */
    unsigned char *cipher;
    int cipher_len;
    unsigned char *msg;
    int msg_len;
    unsigned char *signature;
    int sig_len;
    char *plaintext;
    int deferred;
    int modulo;
    unsigned int fail;
    unsigned int pass;
    int key_format;
    unsigned char *n;
    unsigned char *e;
    unsigned char *d;
    unsigned char *p;
    unsigned char *q;
    unsigned char *dmp1;
    unsigned char *dmq1;
    unsigned char *iqmp;
    unsigned char *pt;

    int n_len;
    int e_len;
    int d_len;
    int p_len;
    int q_len;
    int dmp1_len;
    int dmq1_len;
    int iqmp_len;
    int pt_len;
    int disposition;
} ACVP_RSA_PRIM_TC;


/** @enum ACVP_SYM_CIPH_PARM */
typedef enum acvp_sym_cipher_parameter {
    ACVP_SYM_CIPH_KEYLEN = 1,
    ACVP_SYM_CIPH_TAGLEN,
    ACVP_SYM_CIPH_IVLEN,
    ACVP_SYM_CIPH_PTLEN,
    ACVP_SYM_CIPH_TWEAK,
    ACVP_SYM_CIPH_AADLEN,
    ACVP_SYM_CIPH_KW_MODE,
    ACVP_SYM_CIPH_PARM_DIR,
    ACVP_SYM_CIPH_PARM_KO,
    ACVP_SYM_CIPH_PARM_PERFORM_CTR,
    ACVP_SYM_CIPH_PARM_CTR_INCR,
    ACVP_SYM_CIPH_PARM_CTR_OVRFLW,
    ACVP_SYM_CIPH_PARM_IVGEN_MODE,
    ACVP_SYM_CIPH_PARM_IVGEN_SRC,
    ACVP_SYM_CIPH_PARM_SALT_SRC,
    ACVP_SYM_CIPH_PARM_CONFORMANCE,
    ACVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN
} ACVP_SYM_CIPH_PARM;


/** @enum ACVP_SYM_CIPH_DOMAIN_PARM */
typedef enum acvp_sym_cipher_domain_parameter {
    ACVP_SYM_CIPH_DOMAIN_IVLEN = 1,
    ACVP_SYM_CIPH_DOMAIN_PTLEN,
    ACVP_SYM_CIPH_DOMAIN_AADLEN,
    ACVP_SYM_CIPH_DOMAIN_DULEN
} ACVP_SYM_CIPH_DOMAIN_PARM;

/** @enum ACVP_SYM_CIPH_TWEAK_MODE */
typedef enum acvp_sym_xts_tweak_mode {
    ACVP_SYM_CIPH_TWEAK_HEX = 1,
    ACVP_SYM_CIPH_TWEAK_NUM,
    ACVP_SYM_CIPH_TWEAK_NONE
} ACVP_SYM_CIPH_TWEAK_MODE;

/** @enum ACVP_SYM_KW_MODE */
typedef enum acvp_sym_kw_mode {
    ACVP_SYM_KW_NONE = 0,
    ACVP_SYM_KW_CIPHER,
    ACVP_SYM_KW_INVERSE,
    ACVP_SYM_KW_MAX
} ACVP_SYM_KW_MODE;

/** @enum ACVP_SYM_CIPH_TESTTYPE */
typedef enum acvp_sym_cipher_testtype {
    ACVP_SYM_TEST_TYPE_NONE = 0,
    ACVP_SYM_TEST_TYPE_AFT,
    ACVP_SYM_TEST_TYPE_CTR,
    ACVP_SYM_TEST_TYPE_MCT
} ACVP_SYM_CIPH_TESTTYPE;

/** @enum ACVP_HASH_TESTTYPE */
typedef enum acvp_hash_testtype {
    ACVP_HASH_TEST_TYPE_NONE = 0,
    ACVP_HASH_TEST_TYPE_AFT,
    ACVP_HASH_TEST_TYPE_MCT,
    ACVP_HASH_TEST_TYPE_VOT
} ACVP_HASH_TESTTYPE;

/** @enum ACVP_CMAC_TESTTYPE */
typedef enum acvp_cmac_testtype {
    ACVP_CMAC_TEST_TYPE_NONE = 0,
    ACVP_CMAC_TEST_TYPE_AFT
} ACVP_CMAC_TESTTYPE;

/** @enum ACVP_KMAC_TESTTYPE */
typedef enum acvp_kmac_testtype {
    ACVP_KMAC_TEST_TYPE_NONE = 0,
    ACVP_KMAC_TEST_TYPE_AFT,
    ACVP_KMAC_TEST_TYPE_MVT
} ACVP_KMAC_TESTTYPE;

/** @enum ACVP_PBKDF_TESTTYPE */
typedef enum acvp_pbkdf_testtype {
    ACVP_PBKDF_TEST_TYPE_NONE = 0,
    ACVP_PBKDF_TEST_TYPE_AFT
} ACVP_PBKDF_TESTTYPE;

/** @enum ACVP_KDF_TLS13_TESTTYPE */
typedef enum acvp_kdf_tls13_testtype {
    ACVP_KDF_TLS13_TEST_TYPE_NONE = 0,
    ACVP_KDF_TLS13_TEST_TYPE_AFT
} ACVP_KDF_TLS13_TESTTYPE;

/** @enum ACVP_HMAC_PARM */
typedef enum acvp_hmac_parameter {
    ACVP_HMAC_KEYLEN = 1,
    ACVP_HMAC_KEYBLOCK,
    ACVP_HMAC_MACLEN
} ACVP_HMAC_PARM;

/** @enum ACVP_CMAC_PARM */
typedef enum acvp_cmac_parameter {
    ACVP_CMAC_MACLEN,
    ACVP_CMAC_MSGLEN,
    ACVP_CMAC_KEYLEN,
    ACVP_CMAC_KEYING_OPTION,
    ACVP_CMAC_DIRECTION_GEN,
    ACVP_CMAC_DIRECTION_VER
} ACVP_CMAC_PARM;

/** @enum ACVP_KMAC_PARM */
typedef enum acvp_kmac_parameter {
    ACVP_KMAC_MACLEN,
    ACVP_KMAC_MSGLEN,
    ACVP_KMAC_KEYLEN,
    ACVP_KMAC_XOF_SUPPORT,
    ACVP_KMAC_HEX_CUSTOM_SUPPORT
} ACVP_KMAC_PARM;

/** @enum ACVP_CMAC_KEY_ATTR */
typedef enum acvp_cmac_keylen {
    ACVP_CMAC_KEYING_OPTION_1 = 1,
    ACVP_CMAC_KEYING_OPTION_2 = 2,
    ACVP_CMAC_KEYLEN_128 = 128,
    ACVP_CMAC_KEYLEN_192 = 192,
    ACVP_CMAC_KEYLEN_256 = 256
} ACVP_CMAC_KEY_ATTR;

/** @enum ACVP_CMAC_TDES_KEYING_OPTION */
typedef enum acvp_cmac_tdes_keying_option {
    ACVP_CMAC_TDES_KEYING_OPTION_MIN = 0,
    ACVP_CMAC_TDES_KEYING_OPTION_1,
    ACVP_CMAC_TDES_KEYING_OPTION_2,
    ACVP_CMAC_TDES_KEYING_OPTION_MAX
} ACVP_CMAC_TDES_KEYING_OPTION;

/** @enum ACVP_CMAC_MSG_LEN_INDEX */
typedef enum acvp_cmac_msg_len_index {
    CMAC_BLK_DIVISIBLE_1 = 0,
    CMAC_BLK_DIVISIBLE_2,
    CMAC_BLK_NOT_DIVISIBLE_1,
    CMAC_BLK_NOT_DIVISIBLE_2,
    CMAC_MSG_LEN_MAX,
    CMAC_MSG_LEN_NUM_ITEMS
} ACVP_CMAC_MSG_LEN_INDEX;

/** @enum ACVP_XOF_SUPPORT_OPTION */
typedef enum acvp_xof_support_option {
    ACVP_XOF_SUPPORT_FALSE = 0,
    ACVP_XOF_SUPPORT_TRUE,
    ACVP_XOF_SUPPORT_BOTH
} ACVP_XOF_SUPPORT_OPTION;

/**
 * @struct ACVP_SYM_CIPHER_TC
 * @brief This struct holds data that represents a single test case for a symmetric cipher, such as
 *        AES or DES. This data is passed between libacvp and the crypto module. libacvp will
 *        parse the test case parameters from the JSON encoded test vector, fill in this structure,
 *        and pass the struct to the crypto module via the handler that was registered with
 *        libacvp. The crypto module will then need to perform the crypto operation and fill in
 *        the remaining items in the struct for the given test case. The struct is then passed back
 *        to libacvp, where it is then used to build the JSON encoded vector response.
 */
typedef struct acvp_sym_cipher_tc_t {
    ACVP_CIPHER cipher;
    ACVP_CONFORMANCE conformance;
    ACVP_SYM_CIPH_TESTTYPE test_type; /**< KAT or MCT */
    ACVP_SYM_CIPH_DIR direction;      /**< encrypt or decrypt */
    ACVP_SYM_CIPH_IVGEN_SRC ivgen_source;
    ACVP_SYM_CIPH_IVGEN_MODE ivgen_mode;
    ACVP_SYM_CIPH_SALT_SRC salt_source; /**< for AES-XPN */
    unsigned int tc_id;          /**< Test case id */
    unsigned char *key;          /**< Aes symmetric key */
    unsigned char *pt;           /**< Plaintext */
    unsigned char *aad;          /**< Additional Authenticated Data */
    unsigned char *iv;           /**< Initialization Vector */
    unsigned char *ct;           /**< Ciphertext */
    unsigned char *tag;          /**< Aead tag */
    unsigned char *iv_ret;       /**< updated IV used for TDES MCT */
    unsigned char *iv_ret_after; /**< updated IV used for TDES MCT */
    unsigned char *salt;         /**< For use with AES-XPN */
    ACVP_SYM_KW_MODE kwcipher;
    ACVP_SYM_CIPH_TWEAK_MODE tw_mode;
    unsigned int seq_num;
    unsigned int key_len;
    unsigned int pt_len;
    unsigned int data_len;
    unsigned int aad_len;
    unsigned int iv_len;
    unsigned int ct_len;
    unsigned int tag_len;
    unsigned int salt_len;
    unsigned int mct_index;  /**< used to identify init vs. update */
    unsigned int incr_ctr;
    unsigned int ovrflw_ctr;
    unsigned int keyingOption; /**< For some TDES, indicates keyingOption. 
                                 * 1 is 3 key TDES. 2 is 2-key TDES, supported
                                 * for decrypt only. 0 indicates is not applicable */
    unsigned int data_unit_len; /**< for AES-XTS rev 2.0, the amount of data that can be
                                 * processed at once may be lower than the total payload
                                 * size. By default it will = payloadLen. */
} ACVP_SYM_CIPHER_TC;

/**
 * @struct ACVP_HASH_TC
 * @brief This struct holds data that represents a single test case for hash testing. This data is
 *        passed between libacvp and the crypto module.
 */
typedef struct acvp_hash_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;           /**< Test case id */
    ACVP_HASH_TESTTYPE test_type; /**< KAT or MCT or VOT */
    unsigned char *msg; /**< Message input */
    unsigned char *m1; /**< Mesage input #1
                            Provided when \ref ACVP_HASH_TC.test_type is MCT */
    unsigned char *m2; /**< Mesage input #2
                            Provided when \ref ACVP_HASH_TC.test_type is MCT */
    unsigned char *m3; /**< Mesage input #3
                            Provided when \ref ACVP_HASH_TC.test_type is MCT */
    unsigned int msg_len; /**< Length (in bytes) of...
                               \ref ACVP_HASH_TC.msg , \ref ACVP_HASH_TC.m1 ,
                               \ref ACVP_HASH_TC.m2 , \ref ACVP_HASH_TC.m3 */
    unsigned int xof_len; /**< XOF (extendable output format) length
                               The expected length (in bytes) of \ref ACVP_HASH_TC.md
                               Only provided when \ref ACVP_HASH_TC.test_type is VOT */
    unsigned int xof_bit_len; /**< XOF (extendable output format) length
                                   The expected length (in bits) of \ref ACVP_HASH_TC.md
                                   Only provided when \ref ACVP_HASH_TC.test_type is VOT */
    unsigned char *md; /**< The resulting digest calculated for the test case.
                            SUPPLIED BY USER */
    unsigned int md_len; /**< The length (in bytes) of \ref ACVP_HASH_TC.md
                              SUPPLIED BY USER */
} ACVP_HASH_TC;

/**
 * @struct ACVP_KDF135_IKEV2_TC
 * @brief This struct holds data that represents a single test case for kdf135 IKEV2 testing. This
 *        data is passed between libacvp and the crypto module.
 */
typedef struct acvp_kdf135_ikev2_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /**< Test case id */
    ACVP_HASH_ALG hash_alg;
    int init_nonce_len;
    int resp_nonce_len;
    int gir_len;
    int gir_new_len;
    int init_spi_len;
    int resp_spi_len;
    int dh_secret_len;
    int keying_material_len; /**< Keying material length (in bytes) */
    unsigned char *init_nonce;
    unsigned char *resp_nonce;
    unsigned char *init_spi;
    unsigned char *resp_spi;
    unsigned char *gir;
    unsigned char *gir_new;
    unsigned char *s_key_seed;
    unsigned char *s_key_seed_rekey;
    unsigned char *derived_keying_material;
    unsigned char *derived_keying_material_child;
    unsigned char *derived_keying_material_child_dh;
    int key_out_len;
} ACVP_KDF135_IKEV2_TC;

/**
 * @struct ACVP_KDF135_IKEV1_TC
 * @brief This struct holds data that represents a single test case for kdf135 IKEV1 testing. This
 *        data is passed between libacvp and the crypto module.
 */
typedef struct acvp_kdf135_ikev1_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id; /**< Test case id */
    ACVP_HASH_ALG hash_alg;
    ACVP_KDF135_IKEV1_AUTH_METHOD auth_method;
    int init_nonce_len; /**< Initiator nonce length (in bytes) */
    int resp_nonce_len; /**< Responder nonce length (in bytes) */
    int dh_secret_len;  /**< Diffie-Hellman Secret length (in bytes) */
    int psk_len;        /**< Preshared Key length (in bytes) */
    unsigned char *init_nonce;
    unsigned char *resp_nonce;
    unsigned char *init_ckey;
    unsigned char *resp_ckey;
    unsigned char *gxy;
    unsigned char *psk;

    unsigned char *s_key_id;
    int s_key_id_len;
    unsigned char *s_key_id_d;
    int s_key_id_d_len;
    unsigned char *s_key_id_a;
    int s_key_id_a_len;
    unsigned char *s_key_id_e;
    int s_key_id_e_len;
} ACVP_KDF135_IKEV1_TC;

/**
 * @struct ACVP_KDF135_SNMP_TC
 * @brief This struct holds data that represents a single test case for kdf135 SNMP testing. This
 *        data is passed between libacvp and the crypto module.
 */
typedef struct acvp_kdf135_snmp_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /**< Test case id */
    unsigned char *engine_id;
    unsigned int engine_id_len;
    const char *password;
    unsigned int p_len;
    unsigned char *s_key;
    unsigned int skey_len;
} ACVP_KDF135_SNMP_TC;


/**
 * @struct ACVP_KDF135_X942_TC
 * @brief This struct holds data that represents a single test case for kdf135-x942 testing. This
 *        data is passed between libacvp and the crypto module.
 */
typedef struct acvp_kdf135_x942_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /**< Test case id */
    ACVP_HASH_ALG hash_alg;
    ACVP_KDF_X942_TYPE type;

    unsigned char *oid; /**< OID is a unique identifier (bit string) of the cipher using the DKM.
                         * These are fixed, specific values in ANSI X9.42 */
    unsigned char *zz;
    unsigned char *party_u_info;
    unsigned char *party_v_info;
    unsigned char *supp_pub_info;
    unsigned char *supp_priv_info;
    unsigned char *dkm; /**< Buffer for the output DKM */

    int key_len;
    int oid_len;
    int zz_len;
    int party_u_len;
    int party_v_len;
    int supp_pub_len;
    int supp_priv_len;
    int dkm_len;
} ACVP_KDF135_X942_TC;


/**
 * @struct ACVP_KDF135_X963_TC
 * @brief This struct holds data that represents a single test case for kdf135 TPM testing. This
 *        data is passed between libacvp and the crypto module.
 */
typedef struct acvp_kdf135_x963_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /**< Test case id */
    ACVP_HASH_ALG hash_alg;
    int field_size;
    int key_data_len;
    int shared_info_len;
    int z_len;
    unsigned char *z;
    unsigned char *shared_info;
    unsigned char *key_data;
} ACVP_KDF135_X963_TC;


/**
 * @struct ACVP_KDF108_TC
 * @brief This struct holds data that represents a single test case for kdf108 testing. This
 *        data is passed between libacvp and the crypto module.
 */
typedef struct acvp_kdf108_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /**< Test case id */
    ACVP_KDF108_MODE mode;
    ACVP_KDF108_MAC_MODE_VAL mac_mode;
    ACVP_KDF108_FIXED_DATA_ORDER_VAL counter_location;
    unsigned char *key_in;
    unsigned char *key_out;
    unsigned char *fixed_data;
    unsigned char *iv;
    int key_in_len;             /**< Length of key_in (in bytes) */
    int key_out_len;            /**< Length of key_out (in bytes) */
    int iv_len;                 /**< Length of iv (in bytes) */
    int fixed_data_len;         /**< Length of fixed_data (in bytes).
                                     --- User supplied ---
                                     Must be <= ACVP_KDF108_FIXED_DATA_MAX */
    int counter_len;
    int deferred;
} ACVP_KDF108_TC;

/**
 * @struct ACVP_KDF135_SRTP_TC
 * @brief This struct holds data that represents a single test case for kdf135 SRTP testing. This
 *        data is passed between libacvp and the crypto module.
 */
typedef struct acvp_kdf135_srtp_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /**< Test case id */
    unsigned char *kdr;
    int kdr_len;
    int aes_keylen;
    char *master_key;
    char *master_salt;
    char *idx;
    char *srtcp_idx;

    unsigned char *srtp_ke;
    unsigned char *srtp_ka;
    unsigned char *srtp_ks;
    unsigned char *srtcp_ke;
    unsigned char *srtcp_ka;
    unsigned char *srtcp_ks;
} ACVP_KDF135_SRTP_TC;

/**
 * @struct ACVP_KDF135_SSH_TC
 * @brief This struct holds data that represents a single test case for kdf135 SSH testing. This
 *        data is passed between libacvp and the crypto module.
 */
typedef struct acvp_kdf135_ssh_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;              /**< Test case id */
    ACVP_HASH_ALG sha_type;          /**< SHA algorithm type */
    unsigned int shared_secret_len;  /**< Length of shared_secret (in bytes) */
    unsigned int hash_len;           /**< Length of hash (in bytes) */
    unsigned int session_id_len;     /**< Length of session_id (in bytes) */
    unsigned int e_key_len;          /**< Expected length of encrypt keys (in bytes) */
    unsigned int i_key_len;          /**< Expected length of integrity keys (in bytes) */
    unsigned int iv_len;             /**< Expected length of initial IV (in bytes) */
    char *shared_secret_k;           /**< Shared secret (K) */
    char *hash_h;                    /**< Provided hash (H) */
    char *session_id;                /**< Session ID */
    unsigned char *cs_init_iv;       /**< Initial IV, client to server
                                          ---User supplied--- */
    unsigned char *sc_init_iv;       /**< Initial IV, server to client,
                                          ---User supplied--- */
    unsigned char *cs_encrypt_key;   /**< Encryption Key, client to server
                                          ---User supplied--- */
    unsigned char *sc_encrypt_key;   /**< Encryption Key, server to client
                                          ---User supplied--- */
    unsigned char *cs_integrity_key; /**< Integrity Key, client to server
                                          ---User supplied--- */
    unsigned char *sc_integrity_key; /**< Integrity Key, server to client
                                          ---User supplied--- */
} ACVP_KDF135_SSH_TC;

/**
 * @struct ACVP_PBKDF_TC
 * @brief This struct holds data that represents a single test case for pbkdf testing. This data is
 *        passed between libacvp and the crypto module.
 */
typedef struct acvp_pbkdf_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;              /**< Test case id */
    ACVP_HASH_ALG hmac_type;         /**< HMAC algorithm type */
    ACVP_PBKDF_TESTTYPE test_type;   /**< Test type */
    unsigned int key_len;            /**< Length of key to be generated (in bytes) */
    unsigned char *salt;
    unsigned int salt_len;           /**< the length of the given salt (in bytes) */
    char *password;
    unsigned int pw_len;            /**< The length of the given password (in chars) */
    unsigned int iterationCount;
    unsigned char *key;       /**< The output derived key
                                           ---User supplied--- */
} ACVP_PBKDF_TC;

/**
 * @struct ACVP_KDF_TLS12_TC
 * @brief This struct holds data that represents a single test case for TLS 1.2 KDF testing. This
 *        data is passed between libacvp and the crypto module.
 */
typedef struct acvp_kdf_tls12_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /**< Test case id */
    ACVP_HASH_ALG md;
    unsigned int pm_len;
    unsigned int kb_len;
    unsigned char *pm_secret;
    unsigned char *session_hash;
    unsigned char *s_rnd;
    unsigned char *c_rnd;
    unsigned char *msecret; /**< The resulting data calculated for the test case */
    unsigned char *kblock;  /**< The resulting data calculated for the test case */
    int session_hash_len;
    int s_rnd_len;
    int c_rnd_len;
} ACVP_KDF_TLS12_TC;

/**
 * @struct ACVP_KDF_TLS13_TC
 * @brief This struct holds data that represents a single test case for TLS 1.3 KDF testing. This
 *        data is passed between libacvp and the crypto module.
 */
typedef struct acvp_kdf_tls13_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;              /**< Test case id */

    //test params:
    ACVP_KDF_TLS13_TESTTYPE test_type;   /**< Test type */
    ACVP_HASH_ALG hmac_alg;         /**< HMAC algorithm type */
    ACVP_KDF_TLS13_RUN_MODE running_mode; /**< DHE, PSK, or PSK-DHE */
    unsigned char *psk; /**< pre shared key, populated for PSK or PSK-DHE */
    unsigned char *dhe; /**< diffie hellman secret, populated for DHE or PSK-DHE */
    unsigned char *s_hello_rand; /**< server hello random value */
    unsigned char *c_hello_rand; /**< client hello random value */
    unsigned char *fin_s_hello_rand; /**< finished server hello random value */
    unsigned char *fin_c_hello_rand; /**< finished client hello random value */
    //test param lengths:
    int psk_len;
    int dhe_len;
    int s_hello_rand_len;
    int c_hello_rand_len;
    int fin_s_hello_rand_len;
    int fin_c_hello_rand_len;

    //user supplied (vars are self descriptive):
    unsigned char *c_early_traffic_secret;
    unsigned char *early_expt_master_secret;
    unsigned char *c_hs_traffic_secret;
    unsigned char *s_hs_traffic_secret;
    unsigned char *c_app_traffic_secret;
    unsigned char *s_app_traffic_secret;
    unsigned char *expt_master_secret;
    unsigned char *resume_master_secret;
    //user supplied lengths of above values in bytes:
    int cets_len;
    int eems_len;
    int chts_len;
    int shts_len;
    int cats_len;
    int sats_len;
    int ems_len;
    int rms_len;

} ACVP_KDF_TLS13_TC;

/**
 * @struct ACVP_HMAC_TC
 * @brief This struct holds data that represents a single test case for HMAC testing. This data is
 *        passed between libacvp and the crypto module.
 */
typedef struct acvp_hmac_tc_t {
    ACVP_CIPHER cipher;
    unsigned int tc_id;    /**< Test case id */
    unsigned char *msg;
    unsigned int msg_len;
    unsigned char *mac; /**< The resulting digest calculated for the test case */
    unsigned int mac_len;
    unsigned int key_len;
    unsigned char *key;
} ACVP_HMAC_TC;

/**
 * @struct ACVP_CMAC_TC
 * @brief This struct holds data that represents a single test case for CMAC testing. This data is
 *        passed between libacvp and the crypto module.
 */
typedef struct acvp_cmac_tc_t {
    ACVP_CIPHER cipher;
    ACVP_CMAC_TESTTYPE test_type;
    int verify;                            /**< 1 indicates verify. 0 indicates generate. */
    ACVP_TEST_DISPOSITION ver_disposition; /**< Indicates pass/fail (only in "verify" direction)*/
    unsigned int tc_id;                    /**< Test case id */
    unsigned char *msg;
    unsigned int msg_len;
    unsigned char *mac; /**< The resulting digest calculated for the test case */
    unsigned int mac_len;
    unsigned int key_len;
    unsigned char *key; /**< for CMAC-AES */
    unsigned char *key2; /**< for CMAC-TDES */
    unsigned char *key3; /**< for CMAC-TDES */
} ACVP_CMAC_TC;

/**
 * @struct ACVP_KMAC_TC
 * @brief This struct holds data that represents a single test case for KMAC testing. This data is
 *        passed between libacvp and the crypto module.
 */
typedef struct acvp_kmac_tc_t {
    ACVP_CIPHER cipher;
    ACVP_KMAC_TESTTYPE test_type;
    ACVP_TEST_DISPOSITION disposition; /**< Indicates pass/fail when running verification */
    int tc_id; /**< Test case id */
    int xof;
    int hex_customization;

    unsigned char *msg;
    unsigned char *mac; /**< The resulting digest calculated for the test case, or provided when verifying */
    unsigned char *key;
    unsigned char *custom_hex;
    char *custom;

    int msg_len;
    int mac_len;
    int key_len;
    int custom_len;
} ACVP_KMAC_TC;

/**
 * @struct ACVP_RSA_KEYGEN_TC
 * @brief This struct holds data that represents a single test case for RSA keygen testing. The
 *        other modes of RSA have their own respective structs. This data is passed between
 *        libacvp and the crypto module.
 */
typedef struct acvp_rsa_keygen_tc_t {
    unsigned int tc_id;    /**< Test case id */
    ACVP_HASH_ALG hash_alg;
    ACVP_RSA_TESTTYPE test_type;
    ACVP_RSA_PRIME_TEST_TYPE prime_test;
    char *prime_result;
    char *pub_exp;

    ACVP_RSA_KEYGEN_MODE rand_pq;
    ACVP_RSA_PUB_EXP_MODE pub_exp_mode;
    ACVP_RSA_KEY_FORMAT key_format;
    int info_gen_by_server;
    int test_disposition;
    unsigned int modulo;

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

    int e_len;
    int n_len;
    int d_len;
    int p_len;
    int q_len;
    int xq_len;
    int xq1_len;
    int xq2_len;
    int xp_len;
    int xp1_len;
    int xp2_len;
} ACVP_RSA_KEYGEN_TC;

/**
 * @struct ACVP_ECDSA_TC
 * @brief This struct holds data that represents a single test case for ECDSA testing. This data is
 *        passed between libacvp and the crypto module.
 */
typedef struct acvp_ecdsa_tc_t {
    unsigned int tc_id;    /**< Test case id */
    int tg_id;
    int is_component;
    ACVP_HASH_ALG hash_alg;

    ACVP_CIPHER cipher;

    ACVP_EC_CURVE curve;
    ACVP_ECDSA_SECRET_GEN_MODE secret_gen_mode;

    unsigned char *d;
    int d_len;
    unsigned char *qy;
    int qx_len;
    unsigned char *qx;
    int qy_len;

    unsigned char *r;
    int r_len;
    unsigned char *s;
    int s_len;

    ACVP_TEST_DISPOSITION ver_disposition; /**< Indicates pass/fail (only in "verify" direction)*/
    unsigned char *message;
    int msg_len;
} ACVP_ECDSA_TC;

/**
 * @struct ACVP_RSA_SIG_TC
 * @brief This struct holds data that represents a single test case for RSA signature testing. Both
 *        siggen and sigver use this struct in their testing. This data is  passed between libacvp
 *        and the crypto module.
 */
typedef struct acvp_rsa_sig_tc_t {
    unsigned int tc_id; /**< Test case id */
    int tg_id;          /**< needed to keep e,n state */
    char *group_e;
    char *group_n;
    ACVP_HASH_ALG hash_alg;
    ACVP_RSA_SIG_TYPE sig_type;
    unsigned int modulo;
    unsigned char *e;
    int e_len;
    unsigned char *n;
    int n_len;
    char *salt;
    int salt_len;
    unsigned char *msg;
    int msg_len;
    unsigned char *signature;
    int sig_len;
    ACVP_CIPHER sig_mode;
    ACVP_TEST_DISPOSITION ver_disposition; /**< Indicates pass/fail (only in "verify" direction)*/
} ACVP_RSA_SIG_TC;

/** @enum ACVP_DSA_MODE */
typedef enum acvp_dsa_mode {
    ACVP_DSA_MODE_KEYGEN = 1,
    ACVP_DSA_MODE_PQGGEN,
    ACVP_DSA_MODE_PQGVER,
    ACVP_DSA_MODE_SIGGEN,
    ACVP_DSA_MODE_SIGVER
} ACVP_DSA_MODE;

/** @enum ACVP_DSA_PARM */
typedef enum acvp_dsa_parm {
    ACVP_DSA_LN1024_160 = 1,
    ACVP_DSA_LN2048_224,
    ACVP_DSA_LN2048_256,
    ACVP_DSA_LN3072_256,
    ACVP_DSA_GENPQ,
    ACVP_DSA_GENG
} ACVP_DSA_PARM;

/** @enum ACVP_DSA_GEN_PARM */
typedef enum acvp_dsa_gen_parm {
    ACVP_DSA_PROVABLE = 1,
    ACVP_DSA_PROBABLE,
    ACVP_DSA_CANONICAL,
    ACVP_DSA_UNVERIFIABLE
} ACVP_DSA_GEN_PARM;

/**
 * @struct ACVP_DSA_TC
 * @brief This struct holds data that represents a single test case for DSA testing. This data is
 *        passed between libacvp and the crypto module.
 */
typedef struct acvp_dsa_tc_t {
    int tg_id;
    int tc_id;
    ACVP_CIPHER cipher;
    ACVP_DSA_MODE mode; /**< "pqgGen", "pqgVer", etc. */
    ACVP_HASH_ALG sha;
    int l;
    int n;
    int h;
    int c;
    int pqg;
    int gen_pq;
    int num;
    int index;
    int seedlen;
    int msglen;
    int result;
    int counter;
    unsigned char *p;
    int p_len;
    unsigned char *q;
    int q_len;
    unsigned char *g;
    int g_len;
    unsigned char *y;
    int y_len;
    unsigned char *x;
    int x_len;
    unsigned char *r;
    int r_len;
    unsigned char *s;
    int s_len;
    unsigned char *seed;
    unsigned char *msg;
} ACVP_DSA_TC;

/** @enum ACVP_KAS_ECC_MODE */
typedef enum acvp_kas_ecc_mode {
    ACVP_KAS_ECC_MODE_COMPONENT = 1,
    ACVP_KAS_ECC_MODE_CDH,
    ACVP_KAS_ECC_MODE_NOCOMP,
    ACVP_KAS_ECC_MODE_NONE,
    ACVP_KAS_ECC_MAX_MODES
} ACVP_KAS_ECC_MODE;

/** @enum ACVP_KAS_ECC_FUNC */
typedef enum acvp_kas_ecc_func {
    ACVP_KAS_ECC_FUNC_PARTIAL = 1,
    ACVP_KAS_ECC_FUNC_DPGEN,
    ACVP_KAS_ECC_FUNC_DPVAL,
    ACVP_KAS_ECC_FUNC_KEYPAIR,
    ACVP_KAS_ECC_FUNC_KEYREGEN,
    ACVP_KAS_ECC_FUNC_FULL,
    ACVP_KAS_ECC_MAX_FUNCS
} ACVP_KAS_ECC_FUNC;

/** @enum ACVP_KAS_ECC_PARAM */
typedef enum acvp_kas_ecc_param {
    ACVP_KAS_ECC_FUNCTION = 1,
    ACVP_KAS_ECC_REVISION,
    ACVP_KAS_ECC_CURVE,
    ACVP_KAS_ECC_ROLE,
    ACVP_KAS_ECC_KDF,
    ACVP_KAS_ECC_EB,
    ACVP_KAS_ECC_EC,
    ACVP_KAS_ECC_ED,
    ACVP_KAS_ECC_EE,
    ACVP_KAS_ECC_HASH,
    ACVP_KAS_ECC_NONE
} ACVP_KAS_ECC_PARAM;

/** @enum ACVP_KAS_ECC_ROLES */
typedef enum acvp_kas_ecc_roles {
    ACVP_KAS_ECC_ROLE_INITIATOR = 1,
    ACVP_KAS_ECC_ROLE_RESPONDER
} ACVP_KAS_ECC_ROLES;

/** @enum ACVP_KAS_ECC_SET */
typedef enum acvp_kas_ecc_set {
    ACVP_KAS_ECC_NOKDFNOKC = 1,
    ACVP_KAS_ECC_KDFNOKC,
    ACVP_KAS_ECC_KDFKC,
    ACVP_KAS_ECC_PARMSET
} ACVP_KAS_ECC_SET;

/** @enum ACVP_KAS_ECC_SCHEMES */
typedef enum acvp_kas_ecc_schemes {
    ACVP_KAS_ECC_EPHEMERAL_UNIFIED = 1,
    ACVP_KAS_ECC_FULL_MQV,
    ACVP_KAS_ECC_FULL_UNIFIED,
    ACVP_KAS_ECC_ONEPASS_DH,
    ACVP_KAS_ECC_ONEPASS_MQV,
    ACVP_KAS_ECC_ONEPASS_UNIFIED,
    ACVP_KAS_ECC_STATIC_UNIFIED,
    ACVP_KAS_ECC_SCHEMES_MAX
} ACVP_KAS_ECC_SCHEMES;

/** @enum ACVP_KAS_ECC_TEST_TYPE */
typedef enum acvp_kas_ecc_test_type {
    ACVP_KAS_ECC_TT_AFT = 1,
    ACVP_KAS_ECC_TT_VAL
} ACVP_KAS_ECC_TEST_TYPE;

/**
 * @struct ACVP_KAS_ECC_TC
 * @brief This struct holds data that represents a single test case for KAS-ECC testing. This data
 *        is passed between libacvp and the crypto module.
 */
typedef struct acvp_kas_ecc_tc_t {
    ACVP_CIPHER cipher;
    ACVP_KAS_ECC_FUNC func;
    ACVP_KAS_ECC_TEST_TYPE test_type;
    ACVP_KAS_ECC_MODE mode;
    ACVP_EC_CURVE curve;
    ACVP_HASH_ALG md;
    unsigned char *psx;
    unsigned char *psy;
    unsigned char *pix;
    unsigned char *piy;
    unsigned char *d;
    unsigned char *z;
    unsigned char *chash;
    int psxlen;
    int psylen;
    int pixlen;
    int piylen;
    int dlen;
    int zlen;
    int chashlen;
} ACVP_KAS_ECC_TC;

/** @enum ACVP_KAS_FFC_MODE */
typedef enum acvp_kas_ffc_mode {
    ACVP_KAS_FFC_MODE_COMPONENT = 1,
    ACVP_KAS_FFC_MODE_NOCOMP,
    ACVP_KAS_FFC_MODE_NONE,
    ACVP_KAS_FFC_MAX_MODES
} ACVP_KAS_FFC_MODE;

/** @enum ACVP_KAS_FFC_SCHEMES */
typedef enum acvp_kas_ffc_schemes {
    ACVP_KAS_FFC_DH_EPHEMERAL = 1,
    ACVP_KAS_FFC_DH_HYBRID1,
    ACVP_KAS_FFC_FULL_MQV1,
    ACVP_KAS_FFC_FULL_MQV2,
    ACVP_KAS_FFC_DH_HYBRID_ONEFLOW,
    ACVP_KAS_FFC_DH_ONEFLOW,
    ACVP_KAS_FFC_DH_STATIC,
    ACVP_KAS_FFC_MAX_SCHEMES
} ACVP_KAS_FFC_SCHEMES;

/** @enum ACVP_KAS_FFC_FUNC */
typedef enum acvp_kas_ffc_func {
    ACVP_KAS_FFC_FUNC_DPGEN = 1,
    ACVP_KAS_FFC_FUNC_DPVAL,
    ACVP_KAS_FFC_FUNC_KEYPAIR,
    ACVP_KAS_FFC_FUNC_KEYREGEN,
    ACVP_KAS_FFC_FUNC_FULL,
    ACVP_KAS_FFC_MAX_FUNCS
} ACVP_KAS_FFC_FUNC;

/** @enum ACVP_KAS_FFC_PARAM */
typedef enum acvp_kas_ffc_param {
    ACVP_KAS_FFC_FUNCTION = 1,
    ACVP_KAS_FFC_CURVE,
    ACVP_KAS_FFC_ROLE,
    ACVP_KAS_FFC_HASH,
    ACVP_KAS_FFC_GEN_METH,
    ACVP_KAS_FFC_KDF,
    ACVP_KAS_FFC_FB,
    ACVP_KAS_FFC_FC,
    ACVP_KAS_FFC_MODP2048,
    ACVP_KAS_FFC_MODP3072,
    ACVP_KAS_FFC_MODP4096,
    ACVP_KAS_FFC_MODP6144,
    ACVP_KAS_FFC_MODP8192,
    ACVP_KAS_FFC_FFDHE2048,
    ACVP_KAS_FFC_FFDHE3072,
    ACVP_KAS_FFC_FFDHE4096,
    ACVP_KAS_FFC_FFDHE6144,
    ACVP_KAS_FFC_FFDHE8192
} ACVP_KAS_FFC_PARAM;

/** @enum ACVP_KAS_FFC_ROLES */
typedef enum acvp_kas_ffc_roles {
    ACVP_KAS_FFC_ROLE_INITIATOR = 1,
    ACVP_KAS_FFC_ROLE_RESPONDER
} ACVP_KAS_FFC_ROLES;

/** @enum ACVP_KAS_FFC_SET */
typedef enum acvp_kas_ffc_set {
    ACVP_KAS_FFC_NOKDFNOKC = 1,
    ACVP_KAS_FFC_KDFNOKC,
    ACVP_KAS_FFC_KDFKC,
    ACVP_KAS_FFC_PARMSET
} ACVP_KAS_FFC_SET;

/** @enum ACVP_KAS_FFC_TEST_TYPE */
typedef enum acvp_kas_ffc_test_type {
    ACVP_KAS_FFC_TT_AFT = 1,
    ACVP_KAS_FFC_TT_VAL
} ACVP_KAS_FFC_TEST_TYPE;

/**
 * @struct ACVP_KAS_FFC_TC
 * @brief This struct holds data that represents a single test case for KAS-FFC testing. This data
 *        is passed between libacvp and the crypto module.
 */
#define DGM_STR_MAX 9

typedef struct acvp_kas_ffc_tc_t {
    ACVP_CIPHER cipher;
    ACVP_KAS_FFC_TEST_TYPE test_type;
    ACVP_HASH_ALG md;
    ACVP_KAS_FFC_MODE mode;
    ACVP_KAS_FFC_PARAM dgm;
    unsigned char *p;
    unsigned char *q;
    unsigned char *g;
    unsigned char *d;
    unsigned char *eps;
    unsigned char *epri;
    unsigned char *epui;
    unsigned char *z;
    unsigned char *chash;
    unsigned char *piut;
    int plen;
    int qlen;
    int glen;
    int dlen;
    int zlen;
    int epslen;
    int eprilen;
    int epuilen;
    int chashlen;
    int piutlen;
} ACVP_KAS_FFC_TC;

/** @enum ACVP_SAFE_PRIMES_PARAM */
typedef enum acvp_safe_primes_param {
    ACVP_SAFE_PRIMES_GENMETH = 1,
} ACVP_SAFE_PRIMES_PARAM;

/** @enum ACVP_SAFE_PRIMES_MODE */
typedef enum acvp_safe_primes_mode {
    ACVP_SAFE_PRIMES_MODP2048 = 1,
    ACVP_SAFE_PRIMES_MODP3072,
    ACVP_SAFE_PRIMES_MODP4096,
    ACVP_SAFE_PRIMES_MODP6144,
    ACVP_SAFE_PRIMES_MODP8192,
    ACVP_SAFE_PRIMES_FFDHE2048,
    ACVP_SAFE_PRIMES_FFDHE3072,
    ACVP_SAFE_PRIMES_FFDHE4096,
    ACVP_SAFE_PRIMES_FFDHE6144,
    ACVP_SAFE_PRIMES_FFDHE8192
} ACVP_SAFE_PRIMES_MODE;

/** @enum ACVP_SAFE_PRIMES_TEST_TYPE */
typedef enum acvp_safe_primes_test_type {
    ACVP_SAFE_PRIMES_TT_AFT = 1,
    ACVP_SAFE_PRIMES_TT_VAL
} ACVP_SAFE_PRIMES_TEST_TYPE;

/**
 * @struct ACVP_SAFE_PRIMES_TC
 * @brief This struct holds data that represents a single test case for safe primes testing. This
 *        data is passed between libacvp and the crypto module.
 */
typedef struct acvp_safe_primes_tc_t {
    int tg_id;
    int tc_id;
    unsigned char *x;
    unsigned char *y;
    int xlen;
    int ylen;
    int result;
    ACVP_SAFE_PRIMES_TEST_TYPE test_type;
    ACVP_CIPHER cipher;
    ACVP_SAFE_PRIMES_MODE dgm;
} ACVP_SAFE_PRIMES_TC;

/** @enum ACVP_KAS_IFC_PARAM */
typedef enum acvp_kas_ifc_param {
    ACVP_KAS_IFC_KEYGEN_METHOD = 1,
    ACVP_KAS_IFC_MODULO,
    ACVP_KAS_IFC_HASH,
    ACVP_KAS_IFC_KAS1,
    ACVP_KAS_IFC_KAS2,
    ACVP_KAS_IFC_FIXEDPUBEXP
} ACVP_KAS_IFC_PARAM;

/** @enum ACVP_KAS_IFC_KEYGEN */
typedef enum acvp_kas_ifc_keygen {
    ACVP_KAS_IFC_RSAKPG1_BASIC = 1,
    ACVP_KAS_IFC_RSAKPG1_PRIME_FACTOR,
    ACVP_KAS_IFC_RSAKPG1_CRT,
    ACVP_KAS_IFC_RSAKPG2_BASIC,
    ACVP_KAS_IFC_RSAKPG2_PRIME_FACTOR,
    ACVP_KAS_IFC_RSAKPG2_CRT
} ACVP_KAS_IFC_KEYGEN;

/** @enum ACVP_KAS_IFC_ROLES */
typedef enum acvp_kas_ifc_roles {
    ACVP_KAS_IFC_INITIATOR = 1,
    ACVP_KAS_IFC_RESPONDER
} ACVP_KAS_IFC_ROLES;

/** @enum ACVP_KAS_IFC_TEST_TYPE */
typedef enum acvp_kas_ifc_test_type {
    ACVP_KAS_IFC_TT_AFT = 1,
    ACVP_KAS_IFC_TT_VAL
} ACVP_KAS_IFC_TEST_TYPE;

/**
 * @struct ACVP_KAS_IFC_TC
 * @brief This struct holds data that represents a single test case for KAS-IFC testing. This data
 *        is passed between libacvp and the crypto module.
 */
typedef struct acvp_kas_ifc_tc_t {
    ACVP_CIPHER cipher;
    ACVP_KAS_IFC_TEST_TYPE test_type;
    ACVP_KAS_IFC_KEYGEN key_gen;
    ACVP_HASH_ALG md;
    ACVP_KAS_IFC_PARAM scheme;
    ACVP_KAS_IFC_ROLES kas_role;

    /* Key parameters */
    unsigned char *server_n;
    unsigned char *server_e;
    unsigned char *p;
    unsigned char *q;
    unsigned char *d;
    unsigned char *n;
    unsigned char *e;
    /* CRT parameters */
    unsigned char *dmp1;
    unsigned char *dmq1;
    unsigned char *iqmp;

    unsigned char *iut_pt_z;
    unsigned char *iut_ct_z;
    unsigned char *provided_pt_z; /**< For VAL tests. Could either be plain Z or hashZ */
    unsigned char *provided_ct_z; /**< for VAL tests */
    unsigned char *server_pt_z;
    unsigned char *server_ct_z;
    unsigned char *provided_kas2_z; /* The server-provided combined Z for KAS2 cases */
    int server_nlen;
    int server_elen;
    int plen;
    int qlen;
    int nlen;
    int dlen;
    int elen;
    int dmp1_len;
    int dmq1_len;
    int iqmp_len;
    int iut_pt_z_len;
    int iut_ct_z_len;
    int provided_pt_z_len;
    int provided_ct_z_len;
    int server_pt_z_len;
    int server_ct_z_len;
    int provided_kas2_z_len;
    unsigned int modulo;
} ACVP_KAS_IFC_TC;

/** @enum ACVP_KDA_ENCODING */
typedef enum acvp_kda_encoding {
    ACVP_KDA_ENCODING_NONE = 0,
    ACVP_KDA_ENCODING_CONCAT,
    ACVP_KDA_ENCODING_MAX
} ACVP_KDA_ENCODING;

/** @enum ACVP_KDA_PATTERN_CANDIDATE */
typedef enum acvp_kda_pattern_candidate {
    ACVP_KDA_PATTERN_NONE = 0,
    ACVP_KDA_PATTERN_LITERAL,
    ACVP_KDA_PATTERN_UPARTYINFO,
    ACVP_KDA_PATTERN_VPARTYINFO,
    ACVP_KDA_PATTERN_CONTEXT,
    ACVP_KDA_PATTERN_ALGID,
    ACVP_KDA_PATTERN_LABEL,
    ACVP_KDA_PATTERN_L,
    ACVP_KDA_PATTERN_T,
    ACVP_KDA_PATTERN_MAX
} ACVP_KDA_PATTERN_CANDIDATE;

/** @enum ACVP_KDA_MAC_SALT_METHOD */
typedef enum acvp_kda_mac_salt_method {
    ACVP_KDA_MAC_SALT_METHOD_NONE = 0,
    ACVP_KDA_MAC_SALT_METHOD_DEFAULT,
    ACVP_KDA_MAC_SALT_METHOD_RANDOM,
    ACVP_KDA_MAC_SALT_METHOD_MAX
} ACVP_KDA_MAC_SALT_METHOD;

/** @enum ACVP_KDA_TEST_TYPE */
typedef enum acvp_kda_test_type {
    ACVP_KDA_TT_NONE = 0,
    ACVP_KDA_TT_AFT,
    ACVP_KDA_TT_VAL,
    ACVP_KDA_TT_MAX
} ACVP_KDA_TEST_TYPE;

/** @enum ACVP_KDA_PARM */
typedef enum acvp_kda_param {
    ACVP_KDA_PATTERN = 1,
    ACVP_KDA_REVISION,
    ACVP_KDA_ENCODING_TYPE,
    ACVP_KDA_Z,
    ACVP_KDA_L,
    ACVP_KDA_MAC_SALT,
    ACVP_KDA_PERFORM_MULTIEXPANSION_TESTS,
    ACVP_KDA_MAC_ALG,
    ACVP_KDA_USE_HYBRID_SECRET,
    ACVP_KDA_ONESTEP_AUX_FUNCTION,
    ACVP_KDA_TWOSTEP_SUPPORTED_LEN,
    ACVP_KDA_TWOSTEP_FIXED_DATA_ORDER,
    ACVP_KDA_TWOSTEP_COUNTER_LEN,
    ACVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV,
    ACVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV
} ACVP_KDA_PARM;

/**
 * @struct ACVP_KDA_ONESTEP_TC
 * @brief This struct holds data that represents a single test case for KDA onestep testing.
 *        This data is passed between libacvp and the crypto module.
 */
typedef struct acvp_kda_onestep_tc_t {
    ACVP_CIPHER cipher;
    ACVP_KDA_TEST_TYPE type;
    //Incrementing through the array, each element represents a pattern candidate until we reach a 0
    ACVP_KDA_PATTERN_CANDIDATE fixedInfoPattern[ACVP_KDA_PATTERN_MAX];
    ACVP_KDA_ENCODING encoding;
    ACVP_CIPHER aux_function;
    ACVP_KDA_MAC_SALT_METHOD saltMethod;
    unsigned int tc_id;
    unsigned char *salt;
    unsigned char *z;
    unsigned char *t;
    int l;
    int saltLen;
    int zLen;
    int tLen;
    int uPartyIdLen;
    int uEphemeralLen;
    int vPartyIdLen;
    int vEphemeralLen;
    int algIdLen;
    int labelLen;
    int contextLen;
    int literalLen;
    unsigned char *literalCandidate;
    unsigned char *algorithmId;
    unsigned char *label;
    unsigned char *context;
    unsigned char *uPartyId;
    unsigned char *uEphemeralData;
    unsigned char *vPartyId;
    unsigned char *vEphemeralData;
    unsigned char *providedDkm;
    unsigned char *outputDkm;
} ACVP_KDA_ONESTEP_TC;

/**
 * @struct ACVP_KDA_TWOSTEP_TC
 * @brief This struct holds data that represents a single test case for KDA twostep testing.
 *        This data is passed between libacvp and the crypto module.
 */
typedef struct acvp_kda_twostep_tc_t {
    ACVP_CIPHER cipher;
    ACVP_KDA_TEST_TYPE type;
    //Incrementing through the array, each element represents a pattern candidate until we reach a 0
    ACVP_KDA_PATTERN_CANDIDATE fixedInfoPattern[ACVP_KDA_PATTERN_MAX];
    ACVP_KDA_ENCODING encoding;
    ACVP_KDF108_MODE kdfMode;
    ACVP_KDF108_MAC_MODE_VAL macFunction; /**< we re-use the SP800-108 KDF MAC list here, since its part of twostep. */
    ACVP_KDF108_FIXED_DATA_ORDER_VAL counterLocation;
    ACVP_KDA_MAC_SALT_METHOD saltMethod;
    unsigned int tc_id;
    int uses_hybrid_secret;
    unsigned char *salt;
    unsigned char *iv;
    unsigned char *z;
    unsigned char *t;
    int l;
    int saltLen;
    int ivLen;
    int zLen;
    int tLen;
    int uPartyIdLen;
    int uEphemeralLen;
    int vPartyIdLen;
    int vEphemeralLen;
    int algIdLen;
    int labelLen;
    int contextLen;
    int literalLen;
    int counterLen;
    unsigned char *literalCandidate;
    unsigned char *algorithmId;
    unsigned char *label;
    unsigned char *context;
    unsigned char *uPartyId;
    unsigned char *uEphemeralData;
    unsigned char *vPartyId;
    unsigned char *vEphemeralData;
    unsigned char *providedDkm;
    unsigned char *outputDkm;
} ACVP_KDA_TWOSTEP_TC;

/**
 * @struct ACVP_KDA_HKDF_TC
 * @brief This struct holds data that represents a single test case for KDA HKDF testing. This data
 *        is passed between libacvp and the crypto module.
 */
typedef struct acvp_kda_hkdf_tc_t {
    ACVP_CIPHER cipher;
    ACVP_KDA_TEST_TYPE type;
    //Incrementing through the array, each element represents a pattern candidate until we reach a 0
    ACVP_KDA_PATTERN_CANDIDATE fixedInfoPattern[ACVP_KDA_PATTERN_MAX];
    ACVP_KDA_ENCODING encoding;
    ACVP_HASH_ALG hmacAlg;
    ACVP_KDA_MAC_SALT_METHOD saltMethod;
    unsigned int tc_id;
    unsigned char *salt;
    unsigned char *z;
    unsigned char *t;
    int uses_hybrid_secret;
    int l;
    int saltLen;
    int zLen;
    int tLen;
    int uPartyIdLen;
    int uEphemeralLen;
    int vPartyIdLen;
    int vEphemeralLen;
    int algIdLen;
    int labelLen;
    int contextLen;
    int literalLen;
    unsigned char *literalCandidate;
    unsigned char *algorithmId;
    unsigned char *label;
    unsigned char *context;
    unsigned char *uPartyId;
    unsigned char *uEphemeralData;
    unsigned char *vPartyId;
    unsigned char *vEphemeralData;
    unsigned char *providedDkm;
    unsigned char *outputDkm;
} ACVP_KDA_HKDF_TC;

/** @enum ACVP_KTS_IFC_PARAM */
typedef enum acvp_kts_ifc_param {
    ACVP_KTS_IFC_KEYGEN_METHOD = 1,
    ACVP_KTS_IFC_SCHEME,
    ACVP_KTS_IFC_FUNCTION,
    ACVP_KTS_IFC_MODULO,
    ACVP_KTS_IFC_IUT_ID,
    ACVP_KTS_IFC_KEYPAIR_GEN,
    ACVP_KTS_IFC_PARTIAL_VAL,
    ACVP_KTS_IFC_FIXEDPUBEXP
} ACVP_KTS_IFC_PARAM;

/** @enum ACVP_KTS_IFC_KEYGEN */
typedef enum acvp_kts_ifc_keygen {
    ACVP_KTS_IFC_RSAKPG1_BASIC = 1,
    ACVP_KTS_IFC_RSAKPG1_PRIME_FACTOR,
    ACVP_KTS_IFC_RSAKPG1_CRT,
    ACVP_KTS_IFC_RSAKPG2_BASIC,
    ACVP_KTS_IFC_RSAKPG2_PRIME_FACTOR,
    ACVP_KTS_IFC_RSAKPG2_CRT
} ACVP_KTS_IFC_KEYGEN;

/** @enum ACVP_KTS_IFC_ROLES */
typedef enum acvp_kts_ifc_roles {
    ACVP_KTS_IFC_INITIATOR = 1,
    ACVP_KTS_IFC_RESPONDER
} ACVP_KTS_IFC_ROLES;

/** @enum ACVP_KTS_IFC_SCHEME_PARAM */
typedef enum acvp_kts_ifc_scheme_param {
    ACVP_KTS_IFC_NULL_ASSOC_DATA = 1,
    ACVP_KTS_IFC_AD_PATTERN,
    ACVP_KTS_IFC_ENCODING,
    ACVP_KTS_IFC_HASH,
    ACVP_KTS_IFC_ROLE,
    ACVP_KTS_IFC_L,
    ACVP_KTS_IFC_MAC_METHODS
} ACVP_KTS_IFC_SCHEME_PARAM;

/** @enum ACVP_KTS_IFC_SCHEME_TYPE */
typedef enum acvp_kts_ifc_scheme_type {
    ACVP_KTS_IFC_KAS1_BASIC = 1,
    ACVP_KTS_IFC_KAS1_PARTYV,
    ACVP_KTS_IFC_KAS2_BASIC,
    ACVP_KTS_IFC_KAS2_BILATERAL,
    ACVP_KTS_IFC_KAS2_PARTYU,
    ACVP_KTS_IFC_KAS2_PARTYV
} ACVP_KTS_IFC_SCHEME_TYPE;

#define ACVP_KAS_IFC_CONCAT 2
/** @enum ACVP_KTS_IFC_TEST_TYPE */
typedef enum acvp_kts_ifc_test_type {
    ACVP_KTS_IFC_TT_AFT = 1,
    ACVP_KTS_IFC_TT_VAL
} ACVP_KTS_IFC_TEST_TYPE;



/**
 * @struct ACVP_KTS_IFC_TC
 * @brief This struct holds data that represents a single test case for KTS-IFC testing. This data
 *        is passed between libacvp and the crypto module.
 */
typedef struct acvp_kts_ifc_tc_t {
    ACVP_CIPHER cipher;
    ACVP_KTS_IFC_TEST_TYPE test_type;
    ACVP_KTS_IFC_KEYGEN key_gen;
    ACVP_HASH_ALG md;
    ACVP_KTS_IFC_ROLES kts_role;
    ACVP_KTS_IFC_SCHEME_TYPE scheme;
    unsigned char *p;
    unsigned char *q;
    unsigned char *d;
    unsigned char *n;
    unsigned char *e;
    unsigned char *dmp1;
    unsigned char *dmq1;
    unsigned char *iqmp;
    unsigned char *ct;
    unsigned char *pt;
    int llen;
    int plen;
    int qlen;
    int nlen;
    int dlen;
    int elen;
    int dmp1_len;
    int dmq1_len;
    int iqmp_len;
    int ct_len;
    int pt_len;
    int modulo;
} ACVP_KTS_IFC_TC;

/**
 * @struct ACVP_DRBG_TC
 * @brief  This struct holds data that represents a single test case for DRBG testing. This data is
 *         passed between libacvp and the crypto module.
 */
typedef struct acvp_drbg_tc_t {
    ACVP_CIPHER cipher;
    ACVP_DRBG_MODE mode;
    unsigned int tc_id;    /**< Test case id */

    unsigned char *additional_input_0;
    unsigned char *entropy_input_pr_0;
    unsigned char *additional_input_1;
    unsigned char *entropy_input_pr_1;
    unsigned char *additional_input_2;
    unsigned char *entropy_input_pr_2;
    unsigned int pr1_len;
    unsigned int pr2_len;
    unsigned char *perso_string;
    unsigned char *entropy;
    unsigned char *nonce;
    unsigned char *drb; /**< The resulting pseudo random generated for the test case */

    unsigned int der_func_enabled;
    unsigned int pred_resist_enabled;
    unsigned int reseed;
    unsigned int additional_input_len; /**< Additional Input length (in bytes) */
    unsigned int perso_string_len;     /**< Personalization String length (in bytes) */
    unsigned int entropy_len;          /**< Entropy length (in bytes) */
    unsigned int nonce_len;            /**< Nonce length (in bytes) */
    unsigned int drb_len;              /**< Expected drb length (in bytes) */
} ACVP_DRBG_TC;

/** @enum ACVP_LMS_PARAM */
typedef enum acvp_lms_param {
    ACVP_LMS_PARAM_LMS_MODE = 1,
    ACVP_LMS_PARAM_LMOTS_MODE
} ACVP_LMS_PARAM;

/** @enum ACVP_LMS_MODE */
typedef enum acvp_lms_mode {
    ACVP_LMS_MODE_NONE = 0,
    ACVP_LMS_MODE_SHA256_M24_H5,
    ACVP_LMS_MODE_SHA256_M24_H10,
    ACVP_LMS_MODE_SHA256_M24_H15,
    ACVP_LMS_MODE_SHA256_M24_H20,
    ACVP_LMS_MODE_SHA256_M24_H25,
    ACVP_LMS_MODE_SHA256_M32_H5,
    ACVP_LMS_MODE_SHA256_M32_H10,
    ACVP_LMS_MODE_SHA256_M32_H15,
    ACVP_LMS_MODE_SHA256_M32_H20,
    ACVP_LMS_MODE_SHA256_M32_H25,
    ACVP_LMS_MODE_SHAKE_M24_H5,
    ACVP_LMS_MODE_SHAKE_M24_H10,
    ACVP_LMS_MODE_SHAKE_M24_H15,
    ACVP_LMS_MODE_SHAKE_M24_H20,
    ACVP_LMS_MODE_SHAKE_M24_H25,
    ACVP_LMS_MODE_SHAKE_M32_H5,
    ACVP_LMS_MODE_SHAKE_M32_H10,
    ACVP_LMS_MODE_SHAKE_M32_H15,
    ACVP_LMS_MODE_SHAKE_M32_H20,
    ACVP_LMS_MODE_SHAKE_M32_H25,
    ACVP_LMS_MODE_MAX
} ACVP_LMS_MODE;

/** @enum ACVP_LMOTS_MODE */
typedef enum acvp_lmots_mode {
    ACVP_LMOTS_MODE_NONE = 0,
    ACVP_LMOTS_MODE_SHA256_N24_W1,
    ACVP_LMOTS_MODE_SHA256_N24_W2,
    ACVP_LMOTS_MODE_SHA256_N24_W4,
    ACVP_LMOTS_MODE_SHA256_N24_W8,
    ACVP_LMOTS_MODE_SHA256_N32_W1,
    ACVP_LMOTS_MODE_SHA256_N32_W2,
    ACVP_LMOTS_MODE_SHA256_N32_W4,
    ACVP_LMOTS_MODE_SHA256_N32_W8,
    ACVP_LMOTS_MODE_SHAKE_N24_W1,
    ACVP_LMOTS_MODE_SHAKE_N24_W2,
    ACVP_LMOTS_MODE_SHAKE_N24_W4,
    ACVP_LMOTS_MODE_SHAKE_N24_W8,
    ACVP_LMOTS_MODE_SHAKE_N32_W1,
    ACVP_LMOTS_MODE_SHAKE_N32_W2,
    ACVP_LMOTS_MODE_SHAKE_N32_W4,
    ACVP_LMOTS_MODE_SHAKE_N32_W8,
    ACVP_LMOTS_MODE_MAX
} ACVP_LMOTS_MODE;

/** enum ACVP_LMS_TESTTYPE */
typedef enum acvp_lms_testtype {
    ACVP_LMS_TESTTYPE_NONE = 0,
    ACVP_LMS_TESTTYPE_AFT
} ACVP_LMS_TESTTYPE;
/**
 * @struct ACVP_LMS_TC
 * @brief This struct holds data that represents a single test case for LMS testing. This data is
 *        passed between libacvp and the crypto module.
 */
typedef struct acvp_lms_tc_t {
    unsigned int tc_id;    /**< Test case id */
    unsigned int tg_id; /**< Test group id; needed by sigver */

    ACVP_CIPHER cipher;
    ACVP_LMS_TESTTYPE type;

    ACVP_LMS_MODE lms_mode;
    ACVP_LMOTS_MODE lmots_mode;

    unsigned char *pub_key;
    int pub_key_len;

    /* Keygen values */
    unsigned char *i;
    unsigned char *seed;
    int i_len;
    int seed_len;

    /* Signature values */
    unsigned char *msg;
    unsigned char *sig;
    int msg_len;
    int sig_len;
    ACVP_TEST_DISPOSITION ver_disposition;

} ACVP_LMS_TC;

/**
 * @struct ACVP_TEST_CASE
 * @brief This is the abstracted test case representation used for passing test case data to/from
 *        the crypto module. Because the callback prototype is generic to all algorithms, we
 *        abstract the various classes of test cases using a union. This struct is then used to
 *        pass a reference to the test case between libacvp and the crypto module.
 */
typedef struct acvp_test_case_t {
    union {
        ACVP_SYM_CIPHER_TC *symmetric;
        ACVP_HASH_TC *hash;
        ACVP_DRBG_TC *drbg;
        ACVP_DSA_TC *dsa;
        ACVP_HMAC_TC *hmac;
        ACVP_CMAC_TC *cmac;
        ACVP_KMAC_TC *kmac;
        ACVP_RSA_KEYGEN_TC *rsa_keygen;
        ACVP_RSA_SIG_TC *rsa_sig;
        ACVP_RSA_PRIM_TC *rsa_prim;
        ACVP_ECDSA_TC *ecdsa;
        ACVP_KDF135_SNMP_TC *kdf135_snmp;
        ACVP_KDF135_SSH_TC *kdf135_ssh;
        ACVP_KDF135_SRTP_TC *kdf135_srtp;
        ACVP_KDF135_IKEV2_TC *kdf135_ikev2;
        ACVP_KDF135_IKEV1_TC *kdf135_ikev1;
        ACVP_KDF135_X942_TC *kdf135_x942;
        ACVP_KDF135_X963_TC *kdf135_x963;
        ACVP_KDF108_TC *kdf108;
        ACVP_PBKDF_TC *pbkdf;
        ACVP_KDF_TLS12_TC *kdf_tls12;
        ACVP_KDF_TLS13_TC *kdf_tls13;
        ACVP_KAS_ECC_TC *kas_ecc;
        ACVP_KAS_FFC_TC *kas_ffc;
        ACVP_KAS_IFC_TC *kas_ifc;
        ACVP_KDA_ONESTEP_TC *kda_onestep;
        ACVP_KDA_TWOSTEP_TC *kda_twostep;
        ACVP_KDA_HKDF_TC *kda_hkdf;
        ACVP_KTS_IFC_TC *kts_ifc;
        ACVP_SAFE_PRIMES_TC *safe_primes;
        ACVP_LMS_TC *lms;
    } tc; /**< the union abstracting the test case for passing to the user application */
} ACVP_TEST_CASE;



/** @defgroup APIs Public APIs for libacvp
 *  @brief this section describes APIs for libacvp.
 */
/** @internal ALL APIS SHOULD BE ADDED UNDER THE INGORUP BLOCK. */
/** @ingroup APIs
 * @{
 */

/**
 * @brief Allows an application to specify a symmetric cipher capability to be tested by the ACVP
 *        server.
 *        This function should be called to enable crypto capabilities for symmetric ciphers that
 *        will be tested by the ACVP server. This includes AES and 3DES. This function may be
 *        called multiple times to specify more than one crypto capability, such as AES-CBC,
 *        AES-CTR, AES-GCM, etc.
 *        When the application enables a crypto capability, such as AES-GCM, it also needs to
 *        specify a callback function that will be used by libacvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_sym_cipher_enable(ACVP_CTX *ctx,
                                       ACVP_CIPHER cipher,
                                       int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_sym_cipher_set_parm() allows an application to specify length-based
 *        operational parameters to be used for a given cipher during a test session with the ACVP
 *        server.
 *
 *        This function should be called to enable crypto capabilities for symmetric ciphers that
 *        will be tested by the ACVP server. This includes AES and 3DES.
 *
 *        This function may be called multiple times to specify more than one crypto parameter
 *        value for the cipher. For instance, if cipher supports key lengths of 128, 192, and 256
 *        bits, then this function would be called three times. Once for 128, once for 192, and
 *        once again for 256. The ACVP_CIPHER value passed to this function should already have
 *        been setup by invoking acvp_enable_sym_cipher_cap() for that cipher earlier.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param parm ACVP_SYM_CIPH_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be the supported plaintext length of the algorithm.
 * @param length The length value for the symmetric cipher parameter being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_sym_cipher_set_parm(ACVP_CTX *ctx,
                                         ACVP_CIPHER cipher,
                                         ACVP_SYM_CIPH_PARM parm,
                                         int length);

/**
 * @brief acvp_cap_sym_cipher_set_domain allow an application to specify length-based operational
 *        parameters to be used for a given cipher during a test session with the ACVP server.
 *
 *        The user should call this to specify the supported key PT lengths, AAD lengths, and IV
 *        lengths This is called multiple times, for different parms.
 *
 *        The ACVP_CIPHER value passed to this function should already have been setup by invoking
 *        acvp_enable_sym_cipher_cap() for that cipher earlier.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param parm ACVP_SYM_CIPH_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be the supported key length of the algorithm.
 * @param min the minimum value of the domain (range of possible values) being set
 * @param max the maximum value of the domain being set
 * @param increment the increment of the domain being set. Should evenly divide into the other
 *        values.
 *
 * @return ACVP_RESULT
*/
ACVP_RESULT acvp_cap_sym_cipher_set_domain(ACVP_CTX *ctx,
                                           ACVP_CIPHER cipher,
                                           ACVP_SYM_CIPH_DOMAIN_PARM parm,
                                           int min,
                                           int max,
                                           int increment);

/**
 * @brief acvp_cap_hash_enable() allows an application to specify a hash capability to be tested
 *        by the ACVP server.
 *
 *        This function should be called to enable crypto capabilities for hash algorithms that
 *        will be tested by the ACVP server. This includes SHA-1, SHA-256, SHA-384, etc. This
 *        function may be called multiple times to specify more than one crypto capability.
 *
 *        When the application enables a crypto capability, such as SHA-1, it also needs to specify
 *        a callback function that will be used by libacvp when that crypto capability is needed
 *        during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_hash_enable(ACVP_CTX *ctx,
                                 ACVP_CIPHER cipher,
                                 int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_hash_set_parm() allows an application to specify operational parameters to be
 *        used for a given hash alg during a test session with the ACVP server.
 *
 *        This function should be called to enable crypto capabilities for hash capabilities that
 *        will be tested by the ACVP server. This includes SHA-1, SHA-256, SHA-384, etc.
 *
 *        This function may be called multiple times to specify more than one crypto parameter
 *        value for the hash algorithm. The ACVP_CIPHER value passed to this function should
 *        already have been setup by invoking acvp_enable_hash_cap().
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param param ACVP_HASH_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be a flag indicating if empty input values are allowed.
 * @param value the value corresponding to the parameter being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_hash_set_parm(ACVP_CTX *ctx,
                                   ACVP_CIPHER cipher,
                                   ACVP_HASH_PARM param,
                                   int value);

/**
 * @brief acvp_cap_hash_set_domain() functions similarly to @ref acvp_cap_hash_set_parm() but uses
 *        a range of values for certain parameters instead of a single value.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param parm ACVP_HASH_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be message length.
 * @param min the lower value of the supported range of values
 * @param max the maximum supported value for the given parameter
 * @param increment the supported increment for every value in between min and max
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_hash_set_domain(ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     ACVP_HASH_PARM parm,
                                     int min,
                                     int max,
                                     int increment);

/**
 * @brief acvp_enable_drbg_cap() allows an application to specify a hash capability to be tested by
 *        the ACVP server.
 *
 *        This function should be called to enable crypto capabilities for drbg algorithms that
 *        will be tested by the ACVP server. This includes HASHDRBG, HMACDRBG, CTRDRBG. This
 *        function may be called multiple times to specify more than one crypto capability.
 *
 *        When the application enables a crypto capability, such as ACVP_HASHDRBG, it also needs to
 *        specify a callback function that will be used by libacvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_drbg_enable(ACVP_CTX *ctx,
                                 ACVP_CIPHER cipher,
                                 int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_drbg_set_parm() allows an application to specify operational parameters to be
 *        used for a given DRBG alg during a test session with the ACVP server.
 *
 *        This function should be called to enable crypto capabilities for hash capabilities that
 *        will be tested by the ACVP server. This includes HASHDRBG, HMACDRBG, CTRDRBG. This
 *        function may be called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param mode ACVP_DRBG_MODE enum value specifying mode. An example would be ACVP_DRBG_SHA_1
 * @param group The group of capabilities for the given ACVP DRBG modes. Different groups can be
 *        defined for different capabilities; e.g. different lengths can be supported with and
 *        without derivation function support. Groups must be used in a linear fashion (group 0
 *        must be defined before you can define group 1, group 1 before group 2, etc)
 * @param param ACVP_DRBG_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be prediction resistance.
 * @param value the value corresponding to the parameter being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_drbg_set_parm(ACVP_CTX *ctx,
                                   ACVP_CIPHER cipher,
                                   ACVP_DRBG_MODE mode,
                                   int group,
                                   ACVP_DRBG_PARM param,
                                   int value);

/**
 * @brief acvp_enable_drbg_length_cap() allows an application to register a DRBG capability
 *        length-based paramter.
 *
 *        This function should be used to register a length-based parameter for a DRBG capability.
 *        An example would be entropy, nonce, perso where a minimum, step, and maximum can be
 *        specified.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param mode ACVP_DRBG_MODE enum value specifying mode. An example would be ACVP_DRBG_SHA_1
 * @param group The group of capabilities for the given ACVP DRBG modes. Different groups can be
 *        defined for different capabilities; e.g. different lengths can be supported with and
 *        without derivation function support. Groups must be used in a linear fashion (group 0
 *        must be defined before you can define group 1, group 1 before group 2, etc)
 * @param param ACVP_DRBG_PARM enum value specifying paramter. An example would be
 *        ACVP_DRBG_ENTROPY_LEN
 * @param min minimum value
 * @param step increment value
 * @param max maximum value
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_drbg_set_length(ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     ACVP_DRBG_MODE mode,
                                     int group,
                                     ACVP_DRBG_PARM param,
                                     int min,
                                     int step,
                                     int max);

/**
 * @brief acvp_enable_dsa_cap()
 *        This function should be used to enable DSA capabilities. Specific modes and parameters
 *        can use acvp_cap_dsa_set_parm.
 *
 *        When the application enables a crypto capability, such as DSA, it also needs to specify a
 *        callback function that will be used by libacvp when that crypto capability is needed
 *        during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_dsa_enable(ACVP_CTX *ctx,
                                ACVP_CIPHER cipher,
                                int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_dsa_set_parm() allows an application to specify operational parameters to be
 *        used for a given dsa alg during a test session with the ACVP server. This function
 *        should be called to enable crypto capabilities for DSA modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param mode ACVP_DSA_MODE enum value specifying mode. An example would be ACVP_DSA_MODE_PQGGEN
 * @param param ACVP_DSA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_DSA_GENPQ.
 * @param value the value corresponding to the parameter being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_dsa_set_parm(ACVP_CTX *ctx,
                                  ACVP_CIPHER cipher,
                                  ACVP_DSA_MODE mode,
                                  ACVP_DSA_PARM param,
                                  int value);

/**
 * @brief acvp_enable_kas_ecc_cap()
 *        This function should be used to enable KAS-ECC capabilities. Specific modes and
 *        parameters can use acvp_cap_kas_ecc_set_parm.
 *
 *        When the application enables a crypto capability, such as KAS-ECC, it also needs to
 *        specify a callback function that will be used by libacvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kas_ecc_enable(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_enable_kas_ecc_prereq_cap() allows an application to specify a prerequisite
 *        algorithm for a given KAS-ECC mode during a test session with the ACVP server. This
 *        function should be called to enable a prerequisite for an KAS-ECC mode capability that
 *        will be tested by the server.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param mode ACVP_KAS_ECC_MODE enum value specifying mode. An example would be
 *        ACVP_KAS_ECC_MODE_PARTIAL
 * @param pre_req ACVP_PREREQ_ALG enum that the specified cipher/mode depends on
 * @param value "same" or number
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kas_ecc_set_prereq(ACVP_CTX *ctx,
                                        ACVP_CIPHER cipher,
                                        ACVP_KAS_ECC_MODE mode,
                                        ACVP_PREREQ_ALG pre_req,
                                        char *value);

/**
 * @brief acvp_cap_kas_ecc_set_parm() allows an application to specify operational parameters to
 *        be used for a given kas-ecc alg during a test session with the ACVP server. This function
 *        should be called to enable crypto capabilities for KAS-ECC modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param mode ACVP_KAS_ECC_MODE enum value specifying mode. An example would be
 *        ACVP_KAS_ECC_MODE_PARTIALVAL
 * @param param ACVP_KAS_ECC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_KAS_ECC_????
 * @param value the value corresponding to the parameter being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kas_ecc_set_parm(ACVP_CTX *ctx,
                                      ACVP_CIPHER cipher,
                                      ACVP_KAS_ECC_MODE mode,
                                      ACVP_KAS_ECC_PARAM param,
                                      int value);

/**
 * @brief acvp_cap_kas_ecc_set_scheme() allows an application to specify operational parameters to
 *        be used for a given kas-ecc alg during a test session with the ACVP server  This function
 *        should be called to enable crypto capabilities for KAS-ECC modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param mode ACVP_KAS_ECC_MODE enum value specifying mode. An example would be
 *        ACVP_KAS_ECC_MODE_CDH
 * @param scheme The ACVP_KAS_ECC_SCHEMES value specifying the desired scheme
 * @param param ACVP_KAS_ECC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_KAS_ECC_????
 * @param option the value for some schemes which require an additional option to be set
 * @param value the value corresponding to the parameter being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kas_ecc_set_scheme(ACVP_CTX *ctx,
                                        ACVP_CIPHER cipher,
                                        ACVP_KAS_ECC_MODE mode,
                                        ACVP_KAS_ECC_SCHEMES scheme,
                                        ACVP_KAS_ECC_PARAM param,
                                        int option,
                                        int value);


/**
 * @brief acvp_cap_kas_ifc_enable()
 *        This function should be used to enable KAS-IFC capabilities. Specific modes and
 *        parameters can use acvp_cap_kas_ifc_set_parm.
 *
 *        When the application enables a crypto capability, such as KAS-IFC, it also needs to
 *        specify a callback function that will be used by libacvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that
 *        is invoked by libacvp when the crypto capability is needed during a test session. This
 *        crypto_handler function is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kas_ifc_enable(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    int (*crypto_handler)(ACVP_TEST_CASE *test_case));


/**
 * @brief acvp_cap_kas_ifc_set_parm() allows an application to specify operational parameters to be
 *        used for a given alg during a test session with the ACVP server. This function should be
 *        called to enable crypto capabilities for KAS-IFC modes and functions. It may be called
 *        multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param param ACVP_KAS_IFC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_KAS_IFC_????
 * @param value the value corresponding to the parameter being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kas_ifc_set_parm(ACVP_CTX *ctx,
                                      ACVP_CIPHER cipher,
                                      ACVP_KAS_IFC_PARAM param,
                                      int value);

/**
 * @brief acvp_cap_kas_ifc_set_exponent() allows an application to specify public exponent to be
 *        used for a given alg during a test session with the ACVP server.  This function should be
 *        called to enable crypto capabilities for KAS-IFC modes and functions. It may be called
 *        multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param param ACVP_KAS_IFC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_KAS_IFC_????
 * @param value the string value corresponding to the public exponent being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kas_ifc_set_exponent(ACVP_CTX *ctx,
                                          ACVP_CIPHER cipher,
                                          ACVP_KAS_IFC_PARAM param,
                                          char *value);


/**
 * @brief acvp_cap_kts_ifc_enable()
 *        This function should be used to enable KTS-IFC capabilities. Specific modes and
 *        parameters can use acvp_enable_kts_ifc_set_parm, acvp_cap_kts_ifc_set_param_string and
 *        acvp_cap_kts_ifc_set_scheme_string.
 *
 *        When the application enables a crypto capability, such as KTS-IFC, it also needs to
 *        specify a callback function that will be used by libacvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kts_ifc_enable(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    int (*crypto_handler)(ACVP_TEST_CASE *test_case));


/**
 * @brief acvp_cap_kts_ifc_set_parm() allows an application to specify operational parameters to be
 *        used for a given alg during a test session with the ACVP server. This function should be
 *        called to enable crypto capabilities for KTS-IFC modes and functions. It may be called
 *        multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param param ACVP_KTS_IFC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_KTS_IFC_????
 * @param value the value corresponding to the parameter being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kts_ifc_set_parm(ACVP_CTX *ctx,
                                      ACVP_CIPHER cipher,
                                      ACVP_KTS_IFC_PARAM param,
                                      int value);

/**
 * @brief acvp_cap_kts_ifc_set_scheme_parm() allows an application to specify operational
 *        parameters to be used for KTS-IFC scheme parameters  during a test session with the ACVP
 *        server. This function should be called to enable crypto capabilities for KTS-IFC modes
 *        and functions. It may be called  multiple times to specify more than one crypto
 *        capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param scheme ACVP_KTS_IFC_SCHEME enum value identifying the scheme type that is being specified.
 *        An example would be ACVP_KTS_IFC_KAS1_BASIC
 * @param param ACVP_KTS_IFC_SCHEME_PARAM enum value identifying the scheme option that is being
 *        specified. An example would be ACVP_KTS_IFC_ROLE
 * @param value the value corresponding to the parameter being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kts_ifc_set_scheme_parm(ACVP_CTX *ctx,
                                             ACVP_CIPHER cipher,
                                             ACVP_KTS_IFC_SCHEME_TYPE scheme,
                                             ACVP_KTS_IFC_SCHEME_PARAM param,
                                             int value);

/**
 * @brief acvp_cap_kts_ifc_set_param_string() allows an application to specify
 *     string based params to be used for a given alg during a
 *      test session with the ACVP server.
 *     This function should be called to enable crypto capabilities for
 *    KTS-IFC modes and functions. It may be called  multiple times to specify
 *   more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param param ACVP_KTS_IFC_PARAM enum value identifying the algorithm parameter
 *        that is being specified. An example would be ACVP_KTS_IFC_FIXEDPUBEXP
 * @param value the string value corresponding to the public exponent being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kts_ifc_set_param_string(ACVP_CTX *ctx,
                                             ACVP_CIPHER cipher,
                                             ACVP_KTS_IFC_PARAM param,
                                             char *value);

/**
 * @brief acvp_cap_kts_ifc_set_scheme_string() allows an application to specify string based params
 *        to be used for a given alg during a test session with the ACVP server. This function
 *        should be called to enable crypto capabilities for KTS-IFC modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param scheme ACVP_KTS_IFC_SCHEME enum value identifying the scheme type that is being specified.
 *        An example would be ACVP_KTS_IFC_KAS1_BASIC
 * @param param ACVP_KTS_IFC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_KTS_IFC_ENCODING
 * @param value the string value corresponding to the public exponent being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kts_ifc_set_scheme_string(ACVP_CTX *ctx,
                                               ACVP_CIPHER cipher,
                                               ACVP_KTS_IFC_SCHEME_TYPE scheme,
                                               ACVP_KTS_IFC_SCHEME_PARAM param,
                                               char *value);

/**
 * @brief acvp_enable_kas_ffc_cap()
 *        This function should be used to enable KAS-FFC capabilities. Specific modes and
 *        parameters can use acvp_cap_kas_ffc_set_parm.
 *
 *        When the application enables a crypto capability, such as KAS-FFC, it also needs to
 *        specify a callback function that will be used by libacvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */

ACVP_RESULT acvp_cap_kas_ffc_enable(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_enable_kas_ffc_prereq_cap() allows an application to specify a prerequisite
 *        algorithm for a given KAS-FFC mode during a test session with the ACVP server. This
 *        function should be called to enable a prerequisite for an KAS-FFC mode capability that
 *        will be tested by the server.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param mode ACVP_KAS_FFC_MODE enum value specifying mode. An example would be
 *        ACVP_KAS_FFC_MODE_PARTIAL
 * @param pre_req ACVP_PREREQ_ALG enum that the specified cipher/mode depends on
 * @param value "same" or number
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kas_ffc_set_prereq(ACVP_CTX *ctx,
                                        ACVP_CIPHER cipher,
                                        ACVP_KAS_FFC_MODE mode,
                                        ACVP_PREREQ_ALG pre_req,
                                        char *value);

/**
 * @brief acvp_cap_kas_ffc_set_parm() allows an application to specify operational parameters to
 *        be used for a given alg during a test session with the ACVP server. This function should
 *        be called to enable crypto capabilities for KAS-FFC modes and functions. It may be called
 *        multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param mode ACVP_KAS_FFC_MODE enum value specifying mode. An example would be
 *        ACVP_KAS_FFC_MODE_DPGEN
 * @param param ACVP_KAS_FFC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_KAS_FFC_????
 * @param value the value corresponding to the parameter being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kas_ffc_set_parm(ACVP_CTX *ctx,
                                      ACVP_CIPHER cipher,
                                      ACVP_KAS_FFC_MODE mode,
                                      ACVP_KAS_FFC_PARAM param,
                                      int value);


/**
 * @brief acvp_enable_kas_ffc_cap_scheme() allows an application to specify scheme parameters to be
 *        used for a given alg during a test session with the ACVP server. This function should be
 *        called to enable crypto capabilities for KAS-FFC modes and functions. It may be called
 *        multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param mode ACVP_KAS_FFC_MODE enum value specifying mode. An example would be
 *        ACVP_KAS_FFC_MODE_COMPONENT
 * @param scheme ACVP_KAS_FFC_SCHEME enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_KAS_FFC_DH_EPHEMERAL
 * @param param ACVP_KAS_FFC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_KAS_FFC_KDF
 * @param value the value corresponding to the parameter being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kas_ffc_set_scheme(ACVP_CTX *ctx,
                                        ACVP_CIPHER cipher,
                                        ACVP_KAS_FFC_MODE mode,
                                        ACVP_KAS_FFC_SCHEMES scheme,
                                        ACVP_KAS_FFC_PARAM param,
                                        int value);

/**
 * @brief acvp_enable_kda_set_domain() allows an application to specify operational parameters
 *        to be used for a given alg during a test session with the ACVP server. This function
 *        should be called to enable crypto capabilities for KDA modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param param ACVP_KDA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_KDA_HKDF_???
 * @param min Minumum supported value for the corresponding parameter
 * @param max Maximum supported value for the corresponding parameter
 * @param increment Increment value supported
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kda_set_domain(ACVP_CTX *ctx,
                                       ACVP_CIPHER cipher,
                                       ACVP_KDA_PARM param,
                                       int min,
                                       int max,
                                       int increment);

/**
 * @brief acvp_enable_kda_twostep_set_domain() allows an application to specify operational parameters
 *        to be used for a given alg during a test session with the ACVP server. This function
 *        should be called to enable crypto capabilities for KDA modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_KDA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_KDA_HKDF_???
 * @param min Minumum supported value for the corresponding parameter
 * @param max Maximum supported value for the corresponding parameter
 * @param increment Increment value supported
 * @param kdf_mode The kdf mode being set - counter, feedback, or double pipeline iteration
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kda_twostep_set_domain(ACVP_CTX *ctx,
                                       ACVP_KDA_PARM param,
                                       int min,
                                       int max,
                                       int increment,
                                       int kdf_mode);


/**
 * @brief acvp_enable_kda_set_parm() allows an application to specify operational parameters
 *        to be used for a given alg during a test session with the ACVP server. This function
 *        should be called to enable crypto capabilities for KDA modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param param ACVP_KDA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_KDA_HKDF_???
 * @param value the value corresponding to the parameter being set
 * @param string a constant string value required by some parameters, will return an error if
 *        incorrectly used with wrong parameters
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kda_set_parm(ACVP_CTX *ctx,
                                      ACVP_CIPHER cipher,
                                      ACVP_KDA_PARM param,
                                      int value,
                                      const char* string);

/**
 * @brief acvp_cap_kda_twostep_set_parm() allows an application to specify operational parameters
 *        to be used for a given alg during a test session with the ACVP server. This function
 *        should be called to enable crypto capabilities for KDA modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_KDA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be ACVP_KDA_TWOSTEP_??
 * @param value the value corresponding to the parameter being set
 * @param kdf_mode The kdf mode being set - counter, feedback, or double pipeline iteration
 * @param string a constant string value required by some parameters, will return an error if
 *        incorrectly used with wrong parameters
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kda_twostep_set_parm(ACVP_CTX *ctx, 
                                          ACVP_KDA_PARM param,
                                          int value, 
                                          int kdf_mode, 
                                          const char* string);

/**
 * @brief acvp_enable_kda_enable()
 *        This function should be used to enable KDA functions. Parameters are set using
 *        acvp_cap_kda_set_parm().
 *
 *        When the application enables a crypto capability, such as KDA-HKDF, it also needs to
 *        specify a callback function that will be used by libacvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kda_enable(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_enable_rsa_*_cap()
 *        This function should be used to enable RSA capabilities. Specific modes and parameters
 *        can use acvp_cap_rsa_parm, acvp_enable_rsa_bignum_set_parm,
 *        acvp_enable_rsa_primes_parm depending on the need.
 *
 *        When the application enables a crypto capability, such as RSA, it also needs to specify a
 *        callback function that will be used by libacvp when that crypto capability is needed
 *        during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_rsa_keygen_enable(ACVP_CTX *ctx,
                                       ACVP_CIPHER cipher,
                                       int (*crypto_handler)(ACVP_TEST_CASE *test_case));

ACVP_RESULT acvp_cap_rsa_sig_enable(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    int (*crypto_handler)(ACVP_TEST_CASE *test_case));

ACVP_RESULT acvp_cap_rsa_prim_enable(ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     int (*crypto_handler)(ACVP_TEST_CASE *test_case));

ACVP_RESULT acvp_cap_ecdsa_enable(ACVP_CTX *ctx,
                                  ACVP_CIPHER cipher,
                                  int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_rsa_*_set_parm() allows an application to specify operational parameters to
 *        be used for a given RSA alg during a test session with the ACVP server. This function
 *        should be called to enable parameters for RSA capabilities that will be tested by the
 *        ACVP server. This function may be called multiple times to specify more than one crypto
 *        capability.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_RSA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be public exponent
 * @param value the value corresponding to the parameter being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_rsa_keygen_set_parm(ACVP_CTX *ctx,
                                         ACVP_RSA_PARM param,
                                         int value);

ACVP_RESULT acvp_cap_rsa_sigver_set_parm(ACVP_CTX *ctx,
                                         ACVP_RSA_PARM param,
                                         int value);

ACVP_RESULT acvp_cap_rsa_keygen_set_mode(ACVP_CTX *ctx,
                                         ACVP_RSA_KEYGEN_MODE value);

ACVP_RESULT acvp_cap_rsa_prim_set_parm(ACVP_CTX *ctx,
                                       ACVP_RSA_PARM prim_type,
                                       int value);

ACVP_RESULT acvp_cap_rsa_prim_set_exponent(ACVP_CTX *ctx,
                                           ACVP_RSA_PARM param,
                                           char *value);

ACVP_RESULT acvp_cap_rsa_siggen_set_type(ACVP_CTX *ctx,
                                         ACVP_RSA_SIG_TYPE type);

ACVP_RESULT acvp_cap_rsa_sigver_set_type(ACVP_CTX *ctx,
                                         ACVP_RSA_SIG_TYPE type);

ACVP_RESULT acvp_cap_rsa_siggen_set_mod_parm(ACVP_CTX *ctx,
                                             ACVP_RSA_SIG_TYPE sig_type,
                                             unsigned int mod,
                                             int hash_alg,
                                             int salt_len);

ACVP_RESULT acvp_cap_rsa_sigver_set_mod_parm(ACVP_CTX *ctx,
                                             ACVP_RSA_SIG_TYPE sig_type,
                                             unsigned int mod,
                                             int hash_alg,
                                             int salt_len);

ACVP_RESULT acvp_cap_ecdsa_set_parm(ACVP_CTX *ctx,
                                    ACVP_CIPHER cipher,
                                    ACVP_ECDSA_PARM param,
                                    int value);

ACVP_RESULT acvp_cap_ecdsa_set_curve_hash_alg(ACVP_CTX *ctx,
                                              ACVP_CIPHER cipher,
                                              ACVP_EC_CURVE curve,
                                              ACVP_HASH_ALG alg);


/**
 * @brief acvp_enable_rsa_bignum_parm() allows an application to specify BIGNUM operational
 *        parameters to be used for a given RSA alg during a test session with the ACVP server.
 *        This function behaves the same as acvp_cap_rsa_set_parm() but instead allows the
 *        application to specify a BIGNUM parameter
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_RSA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be public exponent
 * @param value BIGNUM value corresponding to the parameter being set
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_rsa_keygen_set_exponent(ACVP_CTX *ctx,
                                             ACVP_RSA_PARM param,
                                             char *value);
ACVP_RESULT acvp_cap_rsa_sigver_set_exponent(ACVP_CTX *ctx,
                                             ACVP_RSA_PARM param,
                                             char *value);

/**
 * @brief acvp_cap_rsa_keygen_set_primes() allows an application to specify RSA key generation
 *        provable or probable primes parameters for use during a test session with the ACVP
 *        server. The function behaves similarly to acvp_cap_rsa_set_parm() and
 *        acvp_enable_rsa_*_exp_parm() but allows for a modulo and hash algorithm parameter to be
 *        specified alongside the provable or probable parameter.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param mode ACVP_RSA_MODE enum value specifying mode. In this case it will always be
 *        ACVP_RSA_MODE_KEYGEN
 * @param mod Supported RSA modulo value for probable or provable prime generation
 * @param param ACVP_RSA_PRIME_PARAM enum value identifying the parameter that will be given for
 *              the \p value. One of: ACVP_RSA_PRIME_HASH_ALG, ACVP_RSA_PRIME_TEST
 * @param value Integer value corresponding to the specified \p param.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_rsa_keygen_set_primes(ACVP_CTX *ctx,
                                           ACVP_RSA_KEYGEN_MODE mode,
                                           unsigned int mod,
                                           ACVP_RSA_PRIME_PARAM param,
                                           int value);

/**
 * @brief acvp_enable_hmac_cap() allows an application to specify an HMAC capability to be tested
 *        by the ACVP server. This function should be called to enable crypto capabilities for hmac
 *        algorithms that will be tested by the ACVP server. This includes HMAC-SHA-1,
 *        HMAC-SHA2-256, HMAC-SHA2-384, etc. This function may be called multiple times to specify
 *        more than one crypto capability.
 *
 *        When the application enables a crypto capability, such as HMAC-SHA-1, it also needs to
 *        specify a callback function that will be used by libacvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_hmac_enable(ACVP_CTX *ctx,
                                 ACVP_CIPHER cipher,
                                 int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_hmac_set_parm() allows an application to specify operational parameters for
 *        use during a test session with the ACVP server. This function allows the application to
 *        specify parameters for use when registering HMAC capability with the server.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param parm ACVP_HMAC_PARM enum value specifying parameter
 * @param value Supported value for the corresponding parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_hmac_set_parm(ACVP_CTX *ctx,
                                   ACVP_CIPHER cipher,
                                   ACVP_HMAC_PARM parm,
                                   int value);

/**
 * @brief Allows an application to specify operational parameters for use during a test session
 *        with the ACVP server.This function allows the application to specify parameters for use
 *        when registering HMAC capability with the server.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param parm ACVP_HMAC_PARM enum value specifying parameter
 * @param min Minumum supported value for the corresponding parameter
 * @param max Maximum supported value for the corresponding parameter
 * @param increment Increment value supported
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_hmac_set_domain(ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     ACVP_HMAC_PARM parm,
                                     int min,
                                     int max,
                                     int increment);

/**
 * @brief acvp_enable_cmac_cap() allows an application to specify an CMAC capability to be tested
 *         by the ACVP server. This function should be called to enable crypto capabilities for
 *         cmac algorithms that will be tested by the ACVP server. This includes CMAC-AES-128,
 *         CMAC-AES-192, CMAC-AES-256, etc. This function may be called multiple times to specify
 *         more than one crypto capability.
 *
 *         When the application enables a crypto capability, such as CMAC-AES-128, it also needs to
 *         specify a callback function that will be used by libacvp when that crypto capability is
 *         needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_cmac_enable(ACVP_CTX *ctx,
                                 ACVP_CIPHER cipher,
                                 int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_cmac_set_parm() allows an application to specify operational parameters for
 *        use during a test session with the ACVP server. This function allows the application to
 *        specify parameters for use when registering CMAC capability with the server.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param parm ACVP_CMAC_PARM enum value specifying parameter
 * @param value Supported value for the corresponding parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_cmac_set_parm(ACVP_CTX *ctx,
                                   ACVP_CIPHER cipher,
                                   ACVP_CMAC_PARM parm,
                                   int value);

/**
 * @brief acvp_cap_cmac_set_domain() allows an application to specify operational parameters for
 *        use during a test session with the ACVP server. This function allows the application to
 *        specify parameters for use when registering CMAC capability with the server.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param parm ACVP_CMAC_PARM enum value specifying parameter
 * @param min Minumum supported value for the corresponding parameter
 * @param max Maximum supported value for the corresponding parameter
 * @param increment Increment value supported
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_cmac_set_domain(ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     ACVP_CMAC_PARM parm,
                                     int min,
                                     int max,
                                     int increment);

/**
 * @brief acvp_cap_kmac_enable() allows an application to specify an KMAC capability to be tested
 *         by the ACVP server. This function should be called to enable crypto capabilities for
 *         kmac algorithms that will be tested by the ACVP server. This includes KMAC-128 and
 *         KMAC-256. This function may be called multiple times to specify
 *         more than one crypto capability.
 *
 *         When the application enables a crypto capability, such as KMAC-128, it also needs to
 *         specify a callback function that will be used by libacvp when that crypto capability is
 *         needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kmac_enable(ACVP_CTX *ctx,
                                 ACVP_CIPHER cipher,
                                 int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_kmac_set_parm() allows an application to specify operational parameters for
 *        use during a test session with the ACVP server. This function allows the application to
 *        specify parameters for use when registering KMAC capability with the server.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param parm ACVP_KMAC_PARM enum value specifying parameter
 * @param value Supported value for the corresponding parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kmac_set_parm(ACVP_CTX *ctx,
                                   ACVP_CIPHER cipher,
                                   ACVP_KMAC_PARM parm,
                                   int value);

/**
 * @brief acvp_cap_kmac_set_domain() allows an application to specify operational parameters for
 *        use during a test session with the ACVP server. This function allows the application to
 *        specify parameters for use when registering KMAC capability with the server.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param parm ACVP_KMAC_PARM enum value specifying parameter
 * @param min Minumum supported value for the corresponding parameter
 * @param max Maximum supported value for the corresponding parameter
 * @param increment Increment value supported
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kmac_set_domain(ACVP_CTX *ctx,
                                     ACVP_CIPHER cipher,
                                     ACVP_KMAC_PARM parm,
                                     int min,
                                     int max,
                                     int increment);


/**
 * @brief acvp_cap_kdf135_*_enable() allows an application to specify a kdf cipher capability to be
 *        tested by the ACVP server. When the application enables a crypto capability, such as
 *        KDF135_SNMP, it also needs to specify a callback function that will be used by libacvp
 *        when that crypto capability is needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_snmp_enable(ACVP_CTX *ctx,
                                        int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief see @ref acvp_cap_kdf135_snmp_enable()
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_ssh_enable(ACVP_CTX *ctx,
                                       int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief see @ref acvp_cap_kdf135_snmp_enable()
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_srtp_enable(ACVP_CTX *ctx,
                                        int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief see @ref acvp_cap_kdf135_snmp_enable()
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_ikev2_enable(ACVP_CTX *ctx,
                                         int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief see @ref acvp_cap_kdf135_snmp_enable()
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_ikev1_enable(ACVP_CTX *ctx,
                                         int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief see @ref acvp_cap_kdf135_snmp_enable()
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_x942_enable(ACVP_CTX *ctx,
                                        int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief see @ref acvp_cap_kdf135_snmp_enable()
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_x963_enable(ACVP_CTX *ctx,
                                        int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_kdf108_enable() allows an application to specify a kdf cipher capability to be
 *        tested by the ACVP server. When the application enables a crypto capability, it also
 *        needs to specify a callback function that will be used by libacvp  when that crypto
 *        capability is needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf108_enable(ACVP_CTX *ctx,
                                   int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_pbkdf_enable() allows an application to specify a kdf cipher capability to be
 *        tested by the ACVP server. When the application enables a crypto capability, it also
 *        needs to specify a callback function that will be used by libacvp  when that crypto
 *        capability is needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_pbkdf_enable(ACVP_CTX *ctx,
                                  int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_kdf_tls12_enable() allows an application to specify a kdf cipher capability to
 *        be tested by the ACVP server. When the application enables a crypto capability, it also
 *        needs to specify a callback function that will be used by libacvp  when that crypto
 *        capability is needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf_tls12_enable(ACVP_CTX *ctx,
                                  int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_kdf_tls13_enable() allows an application to specify a kdf cipher capability to
 *        be tested by the ACVP server. When the application enables a crypto capability, it also
 *        needs to specify a callback function that will be used by libacvp  when that crypto
 *        capability is needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param crypto_handler Address of function implemented by application that is invoked by libacvp
 *        when the crypto capability is needed during a test session. This crypto_handler function
 *        is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf_tls13_enable(ACVP_CTX *ctx,
                                  int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_kdf135_ssh_set_parm() allows an application to specify operational parameters
 *        to be used during a test session with the ACVP server. This function should be called
 *        after acvp_enable_kdf135_ssh_cap() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cap ACVP_CIPHER enum value identifying the crypto capability, here it will always be
 *        ACVP_KDF135_SSH
 * @param method ACVP_KDF135_SSH_METHOD enum value specifying method type
 * @param param ACVP_HASH_ALG enum value
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_ssh_set_parm(ACVP_CTX *ctx,
                                         ACVP_CIPHER cap,
                                         ACVP_KDF135_SSH_METHOD method,
                                         ACVP_HASH_ALG param);


/**
 * @brief acvp_cap_kdf135_srtp_set_parm() allows an application to specify operational
 *        parameters to be used during a test session with the ACVP server. This function should be
 *        called after acvp_enable_kdf135_srtp_cap() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cap ACVP_CIPHER enum value identifying the crypto capability, here it will always be
 *        ACVP_KDF135_SRTP
 * @param param acvp_cap_kdf135_srtp_set_parm enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_srtp_set_parm(ACVP_CTX *ctx,
                                          ACVP_CIPHER cap,
                                          ACVP_KDF135_SRTP_PARAM param,
                                          int value);

/**
 * @brief acvp_cap_kdf108_set_parm() allows an application to specify operational parameters to
 *        be used during a test session with the ACVP server. This function should be called after
 *        acvp_enable_kdf108_cap() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param mode ACVP_KDF108_MODE enum value identifying the kdf108 mode
 * @param param ACVP_KDF108_PARM enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf108_set_parm(ACVP_CTX *ctx,
                                     ACVP_KDF108_MODE mode,
                                     ACVP_KDF108_PARM param,
                                     int value);

/**
 * @brief acvp_cap_kdf135_x942_set_parm() allows an application to specify operational
 *        parameters to be used during a test session with the ACVP server. This function should be
 *        called after acvp_cap_kdf135_x942_enable() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_KDF135_X942_PARM enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_x942_set_parm(ACVP_CTX *ctx,
                                          ACVP_KDF135_X942_PARM param,
                                          int value);

/**
 * @brief acvp_cap_kdf135_x942_set_domain() allows an application to specify operational
 *        parameters to be used during a test session with the ACVP server. This function should be
 *        called after acvp_cap_kdf135_x942_enable() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_KDF135_X942_PARM enum value identifying the X9.42 parameter
 * @param min integer minimum for domain parameter
 * @param max integer maximum for domain parameter
 * @param increment integer increment for domain parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_x942_set_domain(ACVP_CTX *ctx,
                                             ACVP_KDF135_X942_PARM param,
                                             int min,
                                             int max,
                                             int increment);

/**
 * @brief acvp_enable_kdf135_x963_cap_param() allows an application to specify operational
 *        parameters to be used during a test session with the ACVP server. This function should be
 *        called after acvp_enable_kdf135_srtp_cap() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_KDF135_X963_PARM enum value specifying parameter
 * @param value integer value for parameter. The acceptable hash algs are defined in an enum
 *        ACVP_KDF135_X963_HASH_VALS in the library
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_x963_set_parm(ACVP_CTX *ctx,
                                          ACVP_KDF135_X963_PARM param,
                                          int value);

/**
 * @brief acvp_cap_kdf135_snmp_set_parm() allows an application to specify operational
 *        parameters to be used during a test session with the ACVP server.  This function should
 *        be called after acvp_enable_kdf135_srtp_cap() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param kcap ACVP_CIPHER enum value specifying parameter
 * @param param ACVP_KDF135_SNMP_PARAM enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_snmp_set_parm(ACVP_CTX *ctx,
                                          ACVP_CIPHER kcap,
                                          ACVP_KDF135_SNMP_PARAM param,
                                          int value);

/**
 * @brief acvp_enable_kdf135_snmp_engid_parm() allows an application to specify a custom engid to
 *        be used during a test session with the ACVP server. This function should be called after
 *        acvp_enable_kdf135_snmp_cap() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param kcap ACVP_CIPHER enum value specifying parameter
 * @param engid a hexadecimal string representing engine ID
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_snmp_set_engid(ACVP_CTX *ctx,
                                           ACVP_CIPHER kcap,
                                           const char *engid);

/**
 * @brief acvp_enable_kdf135_ikev2_cap_param() allows an application to specify operational
 *        parameters to be used during a test session with the ACVP server.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_KDF135_IKEV2_PARM enum specifying parameter to enable. Here it is always
 *        ACVP_KDF_HASH_ALG. Other params should be enabled with
 *        acvp_enable_kdf135_ikev2_domain_param
 * @param value String value for parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_ikev2_set_parm(ACVP_CTX *ctx,
                                           ACVP_KDF135_IKEV2_PARM param,
                                           int value);

/**
 * @brief acvp_enable_kdf135_ikev1_cap_param() allows an application to specify operational
 *        parameters to be used during a test session with the ACVP server.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_KDF135_IKEV1_PARM enum specifying parameter to enable. Here it is
 *        ACVP_KDF_HASH_ALG or ACVP_KDF_IKEv1_AUTH_METHOD. Other params should be enabled with
 *        acvp_enable_kdf135_ikev1_domain_param
 * @param value String value for parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_ikev1_set_parm(ACVP_CTX *ctx,
                                           ACVP_KDF135_IKEV1_PARM param,
                                           int value);

/**
 * @brief acvp_enable_kdf135_ikev2_cap_len_param() allows an application to specify operational
 *        lengths to be used during a test session with the ACVP server.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_KDF135_IKEV2_PARM enum specifying parameter to enable.
 * @param value length
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_ikev2_set_length(ACVP_CTX *ctx,
                                             ACVP_KDF135_IKEV2_PARM param,
                                             int value);

/**
 * @brief acvp_enable_kdf135_ikev2_domain_param() allows an application to specify operational
 *        parameters to be used during a test session with the ACVP server. This function should be
 *        called after acvp_enable_kdf135_ikev2_cap() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_KDF135_IKEV2_PARM enum value identifying the IKEv2 parameter
 * @param min integer minimum for domain parameter
 * @param max integer maximum for domain parameter
 * @param increment integer increment for domain parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf135_ikev2_set_domain(ACVP_CTX *ctx,
                                             ACVP_KDF135_IKEV2_PARM param,
                                             int min,
                                             int max,
                                             int increment);

/**
 * @brief acvp_enable_kdf135_ikev1_set_domain() allows an application to specify operational
 *        parameters to be used during a test session with the ACVP server. This function should be
 *        called after acvp_cap_kdf135_ikev1_enable() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_KDF135_IKEV1_PARM enum value identifying the IKEv1 parameter
 * @param min integer minimum for domain parameter
 * @param max integer maximum for domain parameter
 * @param increment integer increment for domain parameter
 *
 * @return ACVP_RESULT
 */

ACVP_RESULT acvp_cap_kdf135_ikev1_set_domain(ACVP_CTX *ctx,
                                             ACVP_KDF135_IKEV1_PARM param,
                                             int min,
                                             int max,
                                             int increment);

/**
 * @brief acvp_enable_kdf108_set_domain() allows an application to specify operational parameters
 *        to be used during a test session with the ACVP server. This function should be called
 *        after acvp_cap_kdf108_enable() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param mode ACVP_KDF108_MODE enum value identifying the KDF108 mode
 * @param param ACVP_KDF108_PARM enum value identifying the KDF108 parameter
 * @param min integer minimum for domain parameter
 * @param max integer maximum for domain parameter
 * @param increment integer increment for domain parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf108_set_domain(ACVP_CTX *ctx,
                                       ACVP_KDF108_MODE mode,
                                       ACVP_KDF108_PARM param,
                                       int min,
                                       int max,
                                       int increment);

/**
 * @brief acvp_enable_pbkdf_set_domain() allows an application to specify operational parameters to
 *        be used during a test session with the ACVP server. This function should be called after
 *        acvp_cap_pbkdf_enable() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_PBKDF_PARM enum value identifying the PBKDF parameter
 * @param min integer minimum for domain parameter
 * @param max integer maximum for domain parameter
 * @param increment integer increment for domain parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_pbkdf_set_domain(ACVP_CTX *ctx,
                                      ACVP_PBKDF_PARM param,
                                      int min, int max,
                                      int increment);

/**
 * @brief acvp_cap_pbkdf_set_parm() allows an application to specify operational parameters to be
 *        used during a test session with the ACVP server. This function should be called after
 *        acvp_cap_pbkdf_enable() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_PBKDF_PARM enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_pbkdf_set_parm(ACVP_CTX *ctx,
                                    ACVP_PBKDF_PARM param,
                                    int value);

/**
 * @brief acvp_cap_kdf_tls12_set_parm() allows an application to specify operational parameters to
 *        be used during a test session with the ACVP server. This function should be called after
 *        acvp_cap_kdf_tls12_enable() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_KDF_TLS12_PARM enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf_tls12_set_parm(ACVP_CTX *ctx,
                                        ACVP_KDF_TLS12_PARM param,
                                        int value);

/**
 * @brief acvp_cap_kdf_tls13_set_parm() allows an application to specify operational parameters to
 *        be used during a test session with the ACVP server. This function should be called after
 *        acvp_cap_kdf_tls13_enable() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param param ACVP_KDF_TLS13_PARM enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_kdf_tls13_set_parm(ACVP_CTX *ctx,
                                        ACVP_KDF_TLS13_PARM param,
                                        int value);

ACVP_RESULT acvp_cap_safe_primes_enable(ACVP_CTX *ctx,
                                        ACVP_CIPHER cipher,
                                        int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_safe_primes_set_parm() allows an application to specify operational
 *        parameters to be used for a given safe_primes alg during a test session with the ACVP
 *        server. This function should be called to enable crypto capabilities for safe_primes
 *        capabilities that will be tested by the ACVP server. This includes KEYGEN and KEYVER.
 *
 *        This function may be called multiple times to specify more than one crypto parameter
 *        value for the safe_primes algorithm. The ACVP_CIPHER value passed to this function should
 *        already have been setup by invoking acvp_cap_safe_primes_enable().
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param param ACVP_SAFE_PRIMES_PARAM enum value identifying the algorithm parameter that is being
 *        specified.
 * @param mode the value corresponding to the parameter being set, at present only generation mode
 *        is supported.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_safe_primes_set_parm(ACVP_CTX *ctx,
                                          ACVP_CIPHER cipher,
                                          ACVP_SAFE_PRIMES_PARAM param,
                                          ACVP_SAFE_PRIMES_MODE mode);


/**
 * @brief acvp_cap_lms_enable() should be used to enable LMS capabilities. Specific modes and
 *        parameters can use acvp_cap_lms_set_parm.
 *
 *        When the application enables a crypto capability, such as LMS, it also needs to
 *        specify a callback function that will be used by libacvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param crypto_handler Address of function implemented by application that
 *        is invoked by libacvp when the crypto capability is needed during a test session. This
 *        crypto_handler function is expected to return 0 on success and 1 for failure.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_lms_enable(ACVP_CTX *ctx,
                                ACVP_CIPHER cipher,
                                int (*crypto_handler)(ACVP_TEST_CASE *test_case));

/**
 * @brief acvp_cap_lms_set_parm() allows an application to specify operational
 *        parameters to be used for a given LMS alg during a test session with the ACVP
 *        server. This function should be called to enable crypto capabilities for LMS
 *        capabilities that will be tested by the ACVP server. This includes KEYGEN and KEYVER.
 *
 *        This function may be called multiple times to specify more than one crypto parameter
 *        value for the LMS algorithm. The ACVP_CIPHER value passed to this function should
 *        already have been setup by invoking acvp_cap_lms_enable().
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param param ACVP_LMS_PARAM enum value identifying the algorithm parameter that is being
 *        specified.
 * @param value the value corresponding to the parameter being set, at present only generation mode
 *        is supported.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_lms_set_parm(ACVP_CTX *ctx,
                                  ACVP_CIPHER cipher,
                                  ACVP_LMS_PARAM param, int value);

/**
 * @brief acvp_cap_lms_set_mode_compatability pair allows an application to specify specific compatible pairs
 * of LMS and LMOTS modes, in the case where a IuT does not support an LMS or LMOTS mode universally. 
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability.
 * @param lms_mode ACVP_LMS_MODE for the LMS mode of the pair
 * @param lmots_mode ACVP_LMOTS_MODE for the LMOTS mode of the pair
 *
 * @return ACVP_RESULT 
 */
ACVP_RESULT acvp_cap_lms_set_mode_compatability_pair(ACVP_CTX *ctx,
                                                     ACVP_CIPHER cipher,
                                                     ACVP_LMS_MODE lms_mode,
                                                     ACVP_LMOTS_MODE lmots_mode);
/**
 * @brief acvp_enable_prereq_cap() allows an application to specify a prerequisite for a cipher
 *        capability that was previously registered.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cipher ACVP_CIPHER enum value identifying the crypto capability that has a prerequisite
 * @param pre_req_cap ACVP_PREREQ_ALG enum identifying the prerequisite
 * @param value value for specified prerequisite
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cap_set_prereq(ACVP_CTX *ctx,
                                ACVP_CIPHER cipher,
                                ACVP_PREREQ_ALG pre_req_cap,
                                char *value);

/**
 * @brief acvp_create_test_session() creates a context that can be used to commence a test session
 *        with an ACVP server. This function should be called first to create a context that is
 *        used to manage all the API calls into libacvp. The context should be released after the
 *        test session has completed by invoking acvp_free_test_session().
 *
 *        When creating a new test session, a function pointer can be provided to receive logging
 *        messages from libacvp. The application can then forward the log messages to any logging
 *        service it desires, such as syslog.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param progress_cb Address of function to receive log messages from libacvp.
 * @param level The level of detail to use in logging, as defined by ACVP_LOG_LVL.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_create_test_session(ACVP_CTX **ctx,
                                     ACVP_RESULT (*progress_cb)(char *msg, ACVP_LOG_LVL level),
                                     ACVP_LOG_LVL level);

/**
 * @brief acvp_free_test_session() releases the memory associated withan ACVP_CTX. This function
 *        will free an ACVP_CTX. Failure to invoke this function will result in a memory leak in
 *        the application layer. This function should be invoked after a test session has completed
 *        and a reference to the context is no longer needed.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_free_test_session(ACVP_CTX *ctx);

/**
 * @brief acvp_set_server() specifies the ACVP server and TCP port number to use when contacting
 *        the server. This function is used to specify the hostname or IP address of the ACVP
 *        server. The TCP port number can also be specified if the server doesn't use port 443.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param server_name Name or IP address of the ACVP server.
 * @param port TCP port number the server listens on.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_server(ACVP_CTX *ctx, const char *server_name, int port);

/**
 * @brief acvp_set_path_segment() specifies the URI prefix used by the ACVP server. Some ACVP
 *        servers use a prefix in the URI for the path to the ACVP REST interface. Calling this
 *        function allows the path segment prefix to be specified. The value provided to this
 *        function is prepended to the path segment of the URI used for the ACVP REST calls.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param path_segment Value to embed in the URI path after the server name and before the ACVP
 *        well-known path.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_path_segment(ACVP_CTX *ctx, const char *path_segment);

/**
 * @brief acvp_set_api_context() specifies the URI prefix used by the ACVP server. Some ACVP
 *        servers use a context string in the URI for the path to the REST interface. Calling this
 *        function allows the API context prefix to be specified. The value provided to this
 *        function is prepended to the path segment of the URI used for the ACVP REST calls.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param api_context Value to embed in the URI path after the server name and before the ACVP
 *        well-known path.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_api_context(ACVP_CTX *ctx, const char *api_context);

/**
 * @brief acvp_set_cacerts() specifies PEM encoded certificates to use as the root trust anchors
 *        for establishing the TLS session with the ACVP server. ACVP uses TLS as the transport. In
 *        order to verify the identity of the ACVP server, the TLS stack requires one or more root
 *        certificates that can be used to verify the identify of the ACVP TLS certificate during
 *        the TLS handshake. These root certificates are set using this function. They must be PEM
 *        encoded and all contained in the same file.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param ca_file Name of file containing all the PEM encoded X.509 certificates used as trust
 *        anchors for the TLS session.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_cacerts(ACVP_CTX *ctx, const char *ca_file);

/**
 * @brief acvp_set_certkey() specifies PEM encoded certificate and private key to use for
 *        establishing the TLS session with the ACVP server. ACVP uses TLS as the transport. In
 *        order for the ACVP server to verify the identity the DUT using libacvp, a certificate
 *        needs to be presented during the TLS handshake. The certificate used by libacvp needs to
 *        be trusted by the ACVP server. Otherwise the TLS handshake will fail.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param cert_file Name of file containing the PEM encoded X.509 certificate to use as the client
 *        identity.
 * @param key_file Name of file containing PEM encoded private key associated with the client
 *        certificate.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_certkey(ACVP_CTX *ctx, char *cert_file, char *key_file);

/**
 * @brief acvp_mark_as_sample() marks the registration as a sample. This function sets a flag that
 *        will allow the client to retrieve the correct answers later on, allowing for comparison
 *        and debugging.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_mark_as_sample(ACVP_CTX *ctx);

/**
 * @brief acvp_mark_as_request_only() marks the registration as a request only. This function sets
 *         a flag that will allow the client to retrieve the vectors from the server and store them
 *         in a file for later use.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param filename Name of the file to be used for the request vectors
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_mark_as_request_only(ACVP_CTX *ctx, char *filename);

/**
 * @brief acvp_mark_as_get_only() marks the operation as a GET only. This function will take the
 *        string parameter and perform a GET to check the get of a specific request. The request ID
 *        must be part of the string.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param string used for the get, such as '/acvp/v1/requests/383'
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_mark_as_get_only(ACVP_CTX *ctx, char *string);

/**
 * @brief acvp_set_get_save_file() indicates a file to save get requests to. This function will
 *        only work if acvp_mark_as_get_only() has already been successfully called. It will take a
 *        string parameter for the location to save the results from the GET request indicated in
 *        acvp_mark_as_get_only() to as a file.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param filename location to save the GET results to (assumes data in JSON format)
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_get_save_file(ACVP_CTX *ctx, char *filename);

/**
 * @brief acvp_mark_as_post_only() marks the operation as a POST only. This function will take the
 *        filename and perform a POST of the data in the file to the URL
 *        /acvp/v1/(first field in file)
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param filename file containing URL and content to POST
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_mark_as_post_only(ACVP_CTX *ctx, char *filename);

/**
 * @brief acvp_mark_as_delete only() marks the operation as a DELETE only. This function will
 *        perform an HTTP DELETE call on the resource at the givenURL.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param request_url url of resource to delete
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_mark_as_delete_only(ACVP_CTX *ctx, char *request_url);

/**
 * @brief acvp_mark_as_put_after_test() will attempt to PUT the given file (with the URL inside)
 *        at the conclusion of a test session run with the given CTX.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param filename the path to the file to PUT after the test session
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_mark_as_put_after_test(ACVP_CTX *ctx, char *filename);

/**
 * @brief acvp_get_vector_set_count will return the number of vector sets that are expected based on the current
 * registration. This should be seen as a close estimate not an exact number, as different ACVP servers could
 * possibly have different behaviors.
 *
 * @param ctx Pointer to ACVP_CTX with registered algorithms
 *
 * @return Count of expected vector sets
 */
int acvp_get_vector_set_count(ACVP_CTX *ctx);

/**
 * @brief Performs the ACVP testing procedures.
 *        This function will do the following actions:
 *          1. Verify the provided metadata if user has specified \p fips_validation.
 *          2. Register a new testSession with the ACVP server with the capabilities attached to
 *             the \p ctx.
 *          3. Communicate with the ACVP server to acquire the test vectors, calculate the results
 *             and upload the results to the server.
 *          4. Check the results of each vector associated with the testSession. The success or
 *             failure information will be printed to stderr.
 *          5. Request that the ACVP server perform a FIPS validation (if \p fips_validation == 1
 *             and testSession is passed).
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param fips_validation A flag to indicate whether a fips validation is being performed on the
 *        test session
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_run(ACVP_CTX *ctx, int fips_validation);

ACVP_RESULT acvp_oe_ingest_metadata(ACVP_CTX *ctx, const char *metadata_file);

ACVP_RESULT acvp_oe_set_fips_validation_metadata(ACVP_CTX *ctx,
                                                 unsigned int module_id,
                                                 unsigned int oe_id);

ACVP_RESULT acvp_oe_module_new(ACVP_CTX *ctx,
                               unsigned int id,
                               const char *name);

ACVP_RESULT acvp_oe_module_set_type_version_desc(ACVP_CTX *ctx,
                                                 unsigned int id,
                                                 const char *type,
                                                 const char *version,
                                                 const char *description);

ACVP_RESULT acvp_oe_dependency_new(ACVP_CTX *ctx, unsigned int id);

ACVP_RESULT acvp_oe_oe_new(ACVP_CTX *ctx,
                           unsigned int id,
                           const char *oe_name);

ACVP_RESULT acvp_oe_oe_set_dependency(ACVP_CTX *ctx,
                                      unsigned int oe_id,
                                      unsigned int dependency_id);

/**
 * @brief acvp_set_json_filename specifies JSON registration file to be used during registration.
 *        This allows the app to skip the acvp_enable_* API calls
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param json_filename Name of the file that contains the JSON registration
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_json_filename(ACVP_CTX *ctx, const char *json_filename);

/**
 * @brief acvp_get_current_registration returns a string form of the currently registered set of capabilities. If a test
 * session has already begun it will use the session's submitted registration. If it has not yet begun, only the capabilities
 * registered thus far will be returrned.
 *
 * @param ctx The ctx to retrieve registration from
 * @param len An optional pointer to an integer for saving the length of the returned string
 * @return The string (char*) form of the current registration. The string must be later freed by the user.
 */
char *acvp_get_current_registration(ACVP_CTX *ctx, int *len);

/**
 * @brief acvp_load_kat_filename loads and processes JSON kat vector file This option will not
 *        communicate with the server at all.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param kat_filename Name of the file that contains the JSON kat vectors
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_load_kat_filename(ACVP_CTX *ctx, const char *kat_filename);

/**
 * @brief Uploads a set of vector set responses that were processed from an offline vector set JSON
 *        file.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param rsp_filename Name of the file that contains the completed vector set results
 * @param fips_validation Should be != 0 in case of fips validation (metadata must be provided)
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_upload_vectors_from_file(ACVP_CTX *ctx, const char *rsp_filename, int fips_validation);

/**
 * @brief Runs a set of tests from vector sets that were saved to a file and saves the results in a
 *        different file.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param req_filename Name of the file that contains the unprocessed vector sets
 * @param rsp_filename Name of the file to save vector set test results to
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_run_vectors_from_file(ACVP_CTX *ctx, const char *req_filename, const char *rsp_filename);

/**
 * @brief performs an HTTP PUT on a given libacvp JSON file to the ACV server
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param put_filename name of the file to PUT to the ACV server
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_put_data_from_file(ACVP_CTX *ctx, const char *put_filename);

/**
 * @brief Retrieves the results of an already-completed test session
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param request_filename File containing the session info created by libacvp
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_get_results_from_server(ACVP_CTX *ctx, const char *request_filename);

/**
 * @brief Gets the expected test results for test sessions marked as samples
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param request_filename File containing the session info created by libacvp
 * @param save_filename path/name for file to save the expected results too. OPTIONAL. If null,
 *        will print expected results to log.
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_get_expected_results(ACVP_CTX *ctx, const char *request_filename, const char *save_filename);

/**
 * @brief Queries the server for any vector sets that have not received a response (e.x. in case of
 *        lose of connectivity during testing), downloads those vector sets, and continues to
 *        process them
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param request_filename File containing the session info created by libacvp
 * @param fips_validation Should be != 0 in case of fips validation (metadata must be provided)
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_resume_test_session(ACVP_CTX *ctx, const char *request_filename, int fips_validation);


/**
 * @brief Requests the server to cancel a test session and delete associated data
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param request_filename File containing the session info created by libacvp
 * @param save_filename OPTIONAL arugment indicated a file the server response can be saved to.
 *        Leave NULL if not applicable
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_cancel_test_session(ACVP_CTX *ctx, const char *request_filename, const char *save_filename);

/**
 * @brief acvp_set_2fa_callback() sets a callback function which will create or obtain a TOTP
 *        password for the second part of the two-factor authentication.
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 * @param totp_cb Function that will get the TOTP password
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_set_2fa_callback(ACVP_CTX *ctx, ACVP_RESULT (*totp_cb)(char **token, int token_max));

/**
 * @brief acvp_bin_to_hexstr() Converts a binary string to hex
 *
 * @param src Pointer to the binary source string
 * @param src_len Length of source sting in bytes
 * @param dest Length of destination hex string
 * @param dest_max Maximum length allowed for destination
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_bin_to_hexstr(const unsigned char *src, int src_len, char *dest, int dest_max);

/**
 * @brief acvp_hexstr_to_bin() Converts a hex string to binary
 *
 * @param src Pointer to the hex source string
 * @param dest Length of destination binary string
 * @param dest_max Maximum length allowed for destination
 * @param converted_len the number of bytes converted (output length)
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_hexstr_to_bin(const char *src, unsigned char *dest, int dest_max, int *converted_len);

/**
 * @brief acvp_lookup_error_string() is a utility that returns a more descriptive string for an ACVP_RESULT
 *        error code
 *
 * @param rv ACVP_RESULT error code
 *
 * @return (char *) error string
 */
const char *acvp_lookup_error_string(ACVP_RESULT rv);

/**
 * @brief acvp_cleanup() extends the curl_global_cleanup function to applications using libacvp to
 *        perform cleanup of curl resources
 *
 * @param ctx Pointer to ACVP_CTX that was previously created by calling acvp_create_test_session.
 *
 * @return ACVP_RESULT
 *
 */
ACVP_RESULT acvp_cleanup(ACVP_CTX *ctx);

/**
 * @brief acvp_version() fetch the library version string
 *
 * @return (char *) library string, formatted like: libacvp_oss-1.0.0
 */
const char *acvp_version(void);

/**
 * @brief acvp_protocol_version() fetch the protocol version string
 *
 * @return (char *) protocol version, formated like: 0.5
 */
const char *acvp_protocol_version(void);

ACVP_SUB_CMAC acvp_get_cmac_alg(ACVP_CIPHER cipher);
ACVP_SUB_KMAC acvp_get_kmac_alg(ACVP_CIPHER cipher);
ACVP_SUB_HASH acvp_get_hash_alg(ACVP_CIPHER cipher);
ACVP_SUB_AES acvp_get_aes_alg(ACVP_CIPHER cipher);
ACVP_SUB_TDES acvp_get_tdes_alg(ACVP_CIPHER cipher);
ACVP_SUB_HMAC acvp_get_hmac_alg(ACVP_CIPHER cipher);
ACVP_SUB_ECDSA acvp_get_ecdsa_alg(ACVP_CIPHER cipher);
ACVP_SUB_RSA acvp_get_rsa_alg(ACVP_CIPHER cipher);
ACVP_SUB_DSA acvp_get_dsa_alg(ACVP_CIPHER cipher);
ACVP_SUB_KDF acvp_get_kdf_alg(ACVP_CIPHER cipher);
ACVP_SUB_DRBG acvp_get_drbg_alg(ACVP_CIPHER cipher);
ACVP_SUB_KAS acvp_get_kas_alg(ACVP_CIPHER cipher);
ACVP_SUB_LMS acvp_get_lms_alg(ACVP_CIPHER cipher);

/** @} */
/** @internal ALL APIS SHOULD BE ADDED ABOVE THESE BLOCKS */

#ifdef __cplusplus
}
#endif
#endif
