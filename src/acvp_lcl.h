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
#ifndef acvp_lcl_h
#define acvp_lcl_h

#include "parson.h"

#define ACVP_VERSION    "0.3"

#define ACVP_ALG_MAX 12  /* Used by alg_tbl[] */

#define ACVP_ALG_AES_ECB             "AES-ECB"
#define ACVP_ALG_AES_CBC             "AES-CBC"
#define ACVP_ALG_AES_CTR             "AES-CTR"
#define ACVP_ALG_AES_GCM             "AES-GCM"
#define ACVP_ALG_AES_CCM             "AES-CCM"
#define ACVP_ALG_AES_XTS             "AES-XTS"
#define ACVP_ALG_AES_KW              "AES-KW"
#define ACVP_ALG_AES_KWP             "AES-KWP"
#define ACVP_ALG_TDES_OFB            "TDES-OFB"
#define ACVP_ALG_TDES_CFB1           "TDES-CFB1"
#define ACVP_ALG_TDES_CFB8           "TDES-CFB8"
#define ACVP_ALG_TDES_CFB64          "TDES-CFB64"
#define ACVP_ALG_TDES_ECB            "TDES-ECB"
#define ACVP_ALG_TDES_CBC            "TDES-CBC"
#define ACVP_ALG_TDES_CTR            "TDES-CTR"
#define ACVP_ALG_TDES_KW             "TDES-KW"

#define ACVP_SYM_KEY_MAX    64
#define ACVP_SYM_PT_MAX     1024
#define ACVP_SYM_CT_MAX     1024
#define ACVP_SYM_IV_MAX     64
#define ACVP_SYM_TAG_MAX    64
#define ACVP_SYM_AAD_MAX    128

#define ACVP_KAT_BUF_MAX        1024*1024
#define ACVP_REG_BUF_MAX        1024*65
#define ACVP_RETRY_TIME_MAX         60 /* seconds */
#define ACVP_JWT_TOKEN_MAX      1024

#define ACVP_PATH_SEGMENT_DEFAULT ""

typedef struct acvp_alg_handler_t ACVP_ALG_HANDLER;

struct acvp_alg_handler_t {
    ACVP_SYM_CIPHER        cipher;
    ACVP_RESULT (*handler)(ACVP_CTX *ctx, JSON_Object *obj);
    char		   *name;
};

typedef struct acvp_vs_list_t {
    int vs_id;
    struct acvp_vs_list_t   *next;
} ACVP_VS_LIST;

/*
 * Supported length list
 */
typedef struct acvp_sl_list_t {
    int length;
    struct acvp_sl_list_t *next;
} ACVP_SL_LIST;

typedef struct acvp_sym_cipher_capability {
    ACVP_SYM_CIPHER cipher;
    ACVP_SYM_CIPH_DIR direction;
    ACVP_SYM_CIPH_IVGEN_SRC ivgen_source;
    ACVP_SYM_CIPH_IVGEN_MODE ivgen_mode;
    ACVP_SL_LIST *keylen;
    ACVP_SL_LIST *ptlen;
    ACVP_SL_LIST *ivlen;
    ACVP_SL_LIST *aadlen;
    ACVP_SL_LIST *taglen;
} ACVP_SYM_CIPHER_CAP;

typedef struct acvp_caps_list_t {
    union {
	ACVP_SYM_CIPHER_CAP *sym_cap;
	//TODO: add other cipher types: asymmetric, DRBG, hash, etc.
    } cap;
    ACVP_RESULT (*crypto_handler)(ACVP_CIPHER_TC *test_case);
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
    char        *server_name;
    char        *path_segment;
    int server_port;
    char        *cacerts_file; /* Location of CA certificates Curl will use to verify peer */
    int verify_peer;           /* enables TLS peer verification via Curl */
    char        *tls_cert;     /* Location of PEM encoded X509 cert to use for TLS client auth */
    char        *tls_key;      /* Location of PEM encoded priv key to use for TLS client auth */

    /* test session data */
    ACVP_VS_LIST    *vs_list;
    char            *jwt_token; /* access_token provided by server for authenticating REST calls */

    /* crypto module capabilities list */
    ACVP_CAPS_LIST  *caps_list;

    /* application callbacks */
    ACVP_RESULT (*test_progress_cb)(char *msg);

    /* Transitory values */
    char        *reg_buf;    /* holds the JSON registration response */
    char        *kat_buf;    /* holds the current set of vectors being processed */
    char        *upld_buf;   /* holds the HTTP response from server when uploading results */
    JSON_Value      *kat_resp;   /* holds the current set of vector responses */
    int read_ctr;            /* used during curl processing */
    int vs_id;               /* vs_id currently being processed */
};

ACVP_RESULT acvp_send_register(ACVP_CTX *ctx, char *reg);
ACVP_RESULT acvp_retrieve_vector_set(ACVP_CTX *ctx, int vs_id);
ACVP_RESULT acvp_retrieve_vector_set_result(ACVP_CTX *ctx, int vs_id);
ACVP_RESULT acvp_submit_vector_responses(ACVP_CTX *ctx);
void acvp_log_msg (ACVP_CTX *ctx, const char *format, ...);
ACVP_RESULT acvp_hexstr_to_bin(const unsigned char *src, unsigned char *dest);
ACVP_RESULT acvp_bin_to_hexstr(const unsigned char *src, unsigned int src_len, unsigned char *dest);

/*
 * These are the handler routines for each KAT operation
 */
ACVP_RESULT acvp_retry_handler(ACVP_CTX *ctx, unsigned int retry_period);
ACVP_RESULT acvp_aes_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);
ACVP_RESULT acvp_des_kat_handler(ACVP_CTX *ctx, JSON_Object *obj);
ACVP_RESULT acvp_entropy_handler(ACVP_CTX *ctx, JSON_Object *obj);

/*
 * ACVP utility functions used internally
 */
ACVP_CAPS_LIST* acvp_locate_cap_entry(ACVP_CTX *ctx, ACVP_SYM_CIPHER cipher);
char * acvp_lookup_sym_cipher_name(ACVP_SYM_CIPHER alg);
ACVP_SYM_CIPHER acvp_lookup_sym_cipher_index(const char *algorithm);
#endif
