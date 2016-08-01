/** @file 
 *  This is the public header file to be included by applications
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
#ifndef acvp_h
#define acvp_h

#ifdef __cplusplus
extern "C"
{
#endif

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
 *  @brief This enum is used to indicate error conditions to the appplication
 *     layer. Most libacvp function will return a value from this enum. 
 *
 *     TODO: document all the error codes
 */
typedef enum acvp_result ACVP_RESULT;

/*
 * These are the available algorithms that libacvp supports.  The application
 * layer will need to register one or more of these based on the capabilities
 * of the crypto module being validated.
 */
typedef enum acvp_cipher {
    ACVP_AES = 0,
    ACVP_DES,
    ACVP_RSA,
    ACVP_DSA,
    ACVP_ECDSA,
    ACVP_SHA,
    ACVP_SHA2_256,
    ACVP_SHA2_384,
    ACVP_SHA2_512,
    ACVP_DH,
    ACVP_ECDH,
    ACVP_ENTROPY
} ACVP_CIPHER;

/*
 * These are the cipher modes used with symmetric ciphers.
 */
typedef enum acvp_cipher_mode {
    ACVP_GCM = 0,
    ACVP_CCM,
    ACVP_CBC,
    ACVP_EBC,
    ACVP_CTR,
    ACVP_NA  /* Not applicable */
} ACVP_CIPHER_MODE;

/*
 * These are the algorithm operations supported by libacvp.  These are used in
 * conjunction with ACVP_CIPHER and ACVP_CIPHER_MODE when registering the
 * crypto module capabilities with libacvp.
 */
typedef enum acvp_cipher_op {
    ACVP_ENCRYPT = 0,
    ACVP_DECRYPT,
    ACVP_SIGN,
    ACVP_VERIFY,
    ACVP_COMPUTE, /* Diffie-Hellman */
    ACVP_GENERATE /* keygen, entropy, random data */
} ACVP_CIPHER_OP;

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
    ACVP_CIPHER_MODE mode;
    ACVP_CIPHER_OP direction;   /* encrypt or decrypt */
    unsigned int tc_id;    /* Test case id */
    unsigned char   *key; /* Aes symmetric key */
    unsigned char   *pt; /* Plaintext */
    unsigned char   *aad; /* Additional Authenticated Data */
    unsigned char   *iv; /* Initialization Vector */
    unsigned char   *ct; /* Ciphertext */
    unsigned char   *tag; /* Aead tag */
    unsigned int key_len;
    unsigned int pt_len;
    unsigned int aad_len;
    unsigned int iv_len;
    unsigned int ct_len;
    unsigned int tag_len;
} ACVP_SYM_CIPHER_TC;

/*
 * This struct holds data that represents a single test case
 * for an asymmetric cipher, such as RSA or ECDSA.  This data is
 * passed between libacvp and the crypto module.
 *
 * TODO: libacvp currently supports no asymmetric ciphers, this
 *       is only a placeholder.
 */
typedef struct acvp_asym_cipher_tc_t {
    ACVP_CIPHER cipher;
    ACVP_CIPHER_MODE mode;
    ACVP_CIPHER_OP direction;   /* encrypt or decrypt */
    unsigned int tc_id;    /* Test case id */
    //TODO: need to add support for RSA, ECDSA, etc.
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
 * This is the abstracted test case representation used for
 * passing test case data to/from the crypto module. Because the
 * callback prototype is generic to all algorithms, we abstract
 * the various classes of test cases using a union.  This
 * struct is then used to pass a reference to the test case
 * between libacvp and the crypto module.
 */
typedef struct acvp_cipher_tc_t {
    union {
        ACVP_SYM_CIPHER_TC  *symmetric;
        ACVP_ASYM_CIPHER_TC *asymmetric;
        ACVP_ENTROPY_TC     *entropy;
        //TODO: need more types for hashes, DRBG, etc.
    } tc;
} ACVP_CIPHER_TC;

enum acvp_result {
    ACVP_SUCCESS = 0,
    ACVP_MALLOC_FAIL,
    ACVP_NO_CTX,
    ACVP_TRANSPORT_FAIL,
    ACVP_JSON_ERR,
    ACVP_UNSUPPORTED_OP,
    ACVP_CLEANUP_FAIL,
    ACVP_KAT_DOWNLOAD_RETRY,
    ACVP_INVALID_ARG,
    ACVP_CRYPTO_MODULE_FAIL,
    ACVP_NO_TOKEN,
    ACVP_RESULT_MAX,
};

/*! @brief acvp_enable_capability() allows an application to specify the 
       crypto algorithms it supports and would like to validate with the
       ACVP server. 

    This function should be called to enable crypto capabilities that will
    be tested by the ACVP server.  At least one crypto capability needs to
    be specified to register a new test session.  This function should be
    called at least one time prior to invoking acvp_register().  

    This function may be called multiple times to specify more than one
    crypto capability.  Crytpo capabilities include symmetric algorithms,
    asymmetric algorithms, hash algorithms, random number generators,
    and more.  

    When the application enables a crypto capability, such as AES-GCM, it
    also needs to specify a callback function that will be used by libacvp
    when that crypto capability is needed during a test session.  

    Note: It is anticipated that this API will be changing as the ACVP
          specification evolves.

    @param ctx Address of pointer to a previously allocated ACVP_CTX. 
    @param cipher ACVP_CIPHER enum value identifying the crypto capability.
    @param mode ACVP_CIPHER_MODE enum value identifying the cipher mode.
    @param op ACVP_CIPHER_OP enum value identifying the crypto operation
       (e.g. encrypt, decrypt, sign, verify).
    @param crypto_handler Address of function implemented by application that
       is invoked by libacvp when the crypto capablity is needed during
       a test session.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_enable_capability(ACVP_CTX *ctx, ACVP_CIPHER cipher, ACVP_CIPHER_MODE mode, ACVP_CIPHER_OP op,
                                   ACVP_RESULT (*crypto_handler)(ACVP_CIPHER_TC *test_case));

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
ACVP_RESULT acvp_create_test_session(ACVP_CTX **ctx, ACVP_RESULT (*progress_cb)(char *msg));

/*! @brief acvp_free_test_session() releases the memory associated with
       an ACVP_CTX.  

    This function will free an ACVP_CTX.  Failure to invoke this function
    will result in a memory leak in the application layer.  This function should
    be invoked after a test session has completed and a reference to the context
    is no longer needed. 

    @param ctx Pointer to ACVP_CTX that was previously created by
        calling acvp_create_test_session.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_free_test_session(ACVP_CTX *ctx);

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
ACVP_RESULT acvp_set_server(ACVP_CTX *ctx, char *server_name, int port);

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
ACVP_RESULT acvp_set_path_segment(ACVP_CTX *ctx, char *path_segment);

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
ACVP_RESULT acvp_set_cacerts(ACVP_CTX *ctx, char *ca_file);

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
ACVP_RESULT acvp_set_certkey(ACVP_CTX *ctx, char *cert_file, char *key_file);

/*! @brief acvp_register() registers the DUT with the ACVP server.

    This function is used to regitser the DUT with the server.
    Registration allows the DUT to advertise it's capabilities to
    the server.  The server will respond with a set of vector set
    identifiers that the client will need to process.

    @param ctx Pointer to ACVP_CTX that was previously created by
        calling acvp_create_test_session.

    @return ACVP_RESULT
 */
ACVP_RESULT acvp_register(ACVP_CTX *ctx);

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
ACVP_RESULT acvp_process_tests(ACVP_CTX *ctx);

ACVP_RESULT acvp_check_test_results(ACVP_CTX *ctx);
void acvp_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
