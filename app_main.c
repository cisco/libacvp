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
/*
 * This module is not part of libacvp.  Rather, it's a simple app that
 * demonstrates how to use libacvp. Software that use libacvp
 * will need to implement a similar module.
 *
 * It will default to 127.0.0.1 port 443 if no arguments are given.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "acvp.h"
#ifdef USE_MURL
#include <murl/murl.h>
#else
#include <curl/curl.h>
#endif
#ifndef USE_LIBGCRYPT
# include <openssl/evp.h>
#else
# include <gcrypt.h>
#endif

static ACVP_RESULT app_aes_handler(ACVP_CIPHER_TC *test_case);

#define DEFAULT_SERVER "127.0.0.1"
#define DEFAULT_PORT 443
#define DEFAULT_CA_CHAIN "certs/acvp-private-root-ca.crt.pem"
#define DEFAULT_CERT "certs/sto-labsrv2-client-cert.pem"
#define DEFAULT_KEY "certs/sto-labsrv2-client-key.pem"
char *server;
int port;
char *ca_chain_file;
char *cert_file;
char *key_file;
char *path_segment;

#define CHECK_ENABLE_CAP_RV(rv) \
    if (rv != ACVP_SUCCESS) { \
        printf("Failed to register AES GCM capability with libacvp (rv=%d)\n", rv); \
        exit(1); \
    }


/*
 * Read the operational parameters from the various environment
 * variables.
 */
static void setup_session_parameters()
{
    char *tmp;

    server = getenv("ACV_SERVER");
    if (!server) server = DEFAULT_SERVER;

    tmp = getenv("ACV_PORT");
    if (tmp) port = atoi(tmp);
    if (!port) port = DEFAULT_PORT;

    path_segment = getenv("ACV_URI_PREFIX");
    if (!path_segment) path_segment = "";

    ca_chain_file = getenv("ACV_CA_FILE");
    if (!ca_chain_file) ca_chain_file = DEFAULT_CA_CHAIN;

    cert_file = getenv("ACV_CERT_FILE");
    if (!cert_file) cert_file = DEFAULT_CERT;

    key_file = getenv("ACV_KEY_FILE");
    if (!key_file) key_file = DEFAULT_KEY;

    printf("Using the following parameters:\n\n");
    printf("    ACV_SERVER:     %s\n", server);
    printf("    ACV_PORT:       %d\n", port);
    printf("    ACV_URI_PREFIX: %s\n", path_segment);
    printf("    ACV_CA_FILE:    %s\n", ca_chain_file);
    printf("    ACV_CERT_FILE:  %s\n", cert_file);
    printf("    ACV_KEY_FILE:   %s\n\n", key_file);
}

/*
 * This is a minimal and rudimentary logging handler.
 * libacvp calls this function to for debugs, warnings,
 * and errors.
 */
ACVP_RESULT progress(char *msg)
{
    printf("ACVP Log: %s\n", msg);
    return ACVP_SUCCESS;
}

static void print_usage(void)
{
    printf("\nInvalid usage...\n");
    printf("acvp_app does not require any arguments.  Options are passed to acvp_app\n");
    printf("using environment variables.  The following variables can be set:\n\n");
    printf("    ACV_SERVER (when not set, defaults to %s)\n", DEFAULT_SERVER);
    printf("    ACV_PORT (when not set, defaults to %d)\n", DEFAULT_PORT);
    printf("    ACV_URI_PREFIX (when not set, defaults to null)\n");
    printf("    ACV_CA_FILE (when not set, defaults to %s)\n", DEFAULT_CA_CHAIN);
    printf("    ACV_CERT_FILE (when not set, defaults to %s)\n", DEFAULT_CERT);
    printf("    ACV_KEY_FILE (when not set, defaults to %s)\n\n", DEFAULT_KEY);
    printf("The CA certificates, cert and key should be PEM encoded. There should be no\n");
    printf("password on the key file.\n");
}

int main(int argc, char **argv)
{
    ACVP_RESULT rv;
    ACVP_CTX *ctx;

    if (argc != 1) {
        print_usage();
        return 1;
    }

    setup_session_parameters();

    /*
     * We begin the libacvp usage flow here.
     * First, we create a test session context.
     */
    rv = acvp_create_test_session(&ctx, &progress);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to create ACVP context\n");
        exit(1);
    }

    /*
     * Next we specify the ACVP server address
     */
    rv = acvp_set_server(ctx, server, port);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set server/port\n");
        exit(1);
    }

    /*
     * Set the path segment prefix if needed
     */
     if (strnlen(path_segment, 255) > 0) {
        rv = acvp_set_path_segment(ctx, path_segment);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set URI prefix\n");
            exit(1);
        }
     }

    /*
     * Next we provide the CA certs to be used by libacvp
     * to verify the ACVP TLS certificate.
     */
    rv = acvp_set_cacerts(ctx, ca_chain_file);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set CA certs\n");
        exit(1);
    }

    /*
     * Specify the certificate and private key the client should used
     * for TLS client auth.
     */
    rv = acvp_set_certkey(ctx, cert_file, key_file);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set TLS cert/key\n");
        exit(1);
    }

    /*
     * We need to register all the crypto module capabilities that will be
     * validated.  For now we just register AES-GCM mode for encrypt using
     * a handful of key sizes and plaintext lengths.
     */
    rv = acvp_enable_sym_cipher_cap(ctx, ACVP_AES_GCM, ACVP_DIR_BOTH, ACVP_IVGEN_SRC_INT, ACVP_IVGEN_MODE_821, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_IVLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 136);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 136);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_enable_sym_cipher_cap_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    /*
     * Now that we have a test session, we register with
     * the server to advertise our capabilities and receive
     * the KAT vector sets the server demands that we process.
     */
    rv = acvp_register(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to register with ACVP server (rv=%d)\n", rv);
        exit(1);
    }

    /*
     * Now we process the test cases given to us during
     * registration earlier.
     */
    rv = acvp_process_tests(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to process vectors (%d)\n", rv);
        exit(1);
    }

    /*
     * Finally, we free the test session context and cleanup
     */
    rv = acvp_free_test_session(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to free ACVP context\n");
        exit(1);
    }
    acvp_cleanup();

    return (0);
}

#ifndef USE_LIBGCRYPT
/*
 * This fuction is invoked by libacvp when an AES crypto
 * operation is needed from the crypto module being
 * validated.  This is a callback provided to libacvp when
 * acvp_enable_capability() is invoked to register the
 * AES-GCM capabilitiy with libacvp.  libacvp will in turn
 * invoke this function when it needs to process an AES-GCM
 * test case.
 */
//TODO: I have mixed feelings on returing ACVP_RESULT.  This is
//      application layer code outside of libacvp.  Should we
//      return a simple pass/fail?  Should we provide a separate
//      enum that applications can use?
static ACVP_RESULT app_aes_handler(ACVP_CIPHER_TC *test_case)
{
    ACVP_SYM_CIPHER_TC      *tc;
    EVP_CIPHER_CTX cipher_ctx;
    const EVP_CIPHER        *cipher;
    unsigned char iv_fixed[4] = {1,2,3,4};
    int rv;

    if (!test_case) {
        return ACVP_INVALID_ARG;
    }

    tc = test_case->tc.symmetric;

    printf("%s: enter (tc_id=%d)\n", __FUNCTION__, tc->tc_id);

    /* Validate key length */
    switch (tc->key_len) {
    case 128:
        cipher = EVP_aes_128_gcm();
        break;
    case 192:
        cipher = EVP_aes_192_gcm();
        break;
    case 256:
        cipher = EVP_aes_256_gcm();
        break;
    default:
        printf("Unsupported AES-GCM key length\n");
        return ACVP_UNSUPPORTED_OP;
        break;
    }

    /* Begin encrypt code section */
    EVP_CIPHER_CTX_init(&cipher_ctx);

    if (tc->direction == ACVP_DIR_ENCRYPT) {
	EVP_CipherInit(&cipher_ctx, cipher, NULL, NULL, 1);
	EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, tc->iv_len, 0);
	EVP_CipherInit(&cipher_ctx, NULL, tc->key, NULL, 1);
	/* TODO: there are new rules for IV generation with GCM mode, this needs another look */
	EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_SET_IV_FIXED, 4, iv_fixed);
	if (!EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_IV_GEN, 0, tc->iv)) {
	    printf("acvp_aes_encrypt: iv gen error\n");
	    return ACVP_CRYPTO_MODULE_FAIL;
	}
	if (tc->aad_len) {
	    EVP_Cipher(&cipher_ctx, NULL, tc->aad, tc->aad_len);
	}
        EVP_Cipher(&cipher_ctx, tc->ct, tc->pt, tc->pt_len);
	EVP_Cipher(&cipher_ctx, NULL, NULL, 0);
	EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_GET_TAG, tc->tag_len, tc->tag);
    } else if (tc->direction == ACVP_DIR_DECRYPT) {
	EVP_CipherInit_ex(&cipher_ctx, cipher, NULL, tc->key, NULL, 0);
	EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, tc->iv_len, 0);
	EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_SET_IV_FIXED, -1, tc->iv);
	if(!EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_IV_GEN, 0, tc->iv)) {
	    printf("\nFailed to set IV");;
	    return ACVP_CRYPTO_MODULE_FAIL;
	}        
	if (tc->aad_len) {
	    /*
	     * Set dummy tag before processing AAD.  Otherwise the AAD can
	     * not be processed.  
	     */
	    EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_SET_TAG, tc->tag_len, tc->tag);
	    EVP_Cipher(&cipher_ctx, NULL, tc->aad, tc->aad_len);
	}
	/*
	 * Set the tag when decrypting 
	 */
	EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_SET_TAG, tc->tag_len, tc->tag);
	
	/*
	 * Decrypt the CT
	 */
	EVP_Cipher(&cipher_ctx, tc->pt, tc->ct, tc->pt_len);
	/*
	 * Check the tag
	 */
	rv = EVP_Cipher(&cipher_ctx, NULL, NULL, 0);
	if (rv) {
	    printf("\nGCM decrypt failed due to tag mismatch (%d)\n", rv); 
	    return ACVP_CRYPTO_MODULE_FAIL;
	}
    } else {
        printf("Unsupported direction\n");
        return ACVP_UNSUPPORTED_OP;
    }

    EVP_CIPHER_CTX_cleanup(&cipher_ctx);

    return ACVP_SUCCESS;
}
#else
/*
 * This flavor of the handler uses libgcrypt instead of OpenSSL, which was used
 * for testing TASM-264.  This code is here for demonstration only.  This
 * function lacks proper error handling.
 */
static ACVP_RESULT app_aes_handler(ACVP_CIPHER_TC *test_case)
{
    gcry_cipher_hd_t hd;
    int algo = -1;
    ACVP_SYM_CIPHER_TC      *tc;
    unsigned char iv[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

    printf("************************ Using gcrypt...\n");

    tc = test_case->tc.symmetric;

    /* Validate key length */
    switch (tc->key_len) {
    case 128:
        algo = gcry_cipher_map_name("aes128");
        break;
    case 192:
        algo = gcry_cipher_map_name("aes192");
        break;
    case 256:
        algo = gcry_cipher_map_name("aes256");
        break;
    default:
        printf("Unsupported AES-GCM key length\n");
        return ACVP_UNSUPPORTED_OP;
        break;
    }

    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_GCM, 0);
    gcry_cipher_setkey(hd, tc->key, tc->key_len/8);
    gcry_cipher_setiv(hd, iv, tc->iv_len);
    gcry_cipher_authenticate(hd, tc->aad, tc->aad_len);

    if (tc->pt_len > 0) {
        gcry_cipher_encrypt(hd, tc->ct, tc->ct_len, tc->pt, tc->pt_len);
    }

    gcry_cipher_gettag(hd, tc->tag, tc->tag_len);

    /*
       WARNING: The IV source is hardcoded above and uses length of only 16.
                This may lead to test case failures.
     */
    memcpy(tc->iv, iv, tc->iv_len);

    gcry_cipher_close(hd);
    return ACVP_SUCCESS;
}
#endif
