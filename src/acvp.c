/** @file */
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"

/*
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_parse_register(ACVP_CTX *ctx);
static ACVP_RESULT acvp_process_vsid(ACVP_CTX *ctx, int vs_id);
static ACVP_RESULT acvp_process_vector_set(ACVP_CTX *ctx, JSON_Object *obj);
static ACVP_RESULT acvp_dispatch_vector_set(ACVP_CTX *ctx, JSON_Object *obj);
static ACVP_RESULT acvp_append_sym_cipher_caps_entry(
    ACVP_CTX *ctx,
    ACVP_SYM_CIPHER_CAP *cap,
    ACVP_CIPHER cipher,
    ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case));
static ACVP_RESULT acvp_append_hash_caps_entry(
    ACVP_CTX *ctx,
    ACVP_HASH_CAP *cap,
    ACVP_CIPHER cipher,
    ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case));
static ACVP_RESULT acvp_append_drbg_caps_entry(
	ACVP_CTX *ctx,
	ACVP_DRBG_CAP *cap,
	ACVP_CIPHER cipher,
	ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case));
static ACVP_RESULT acvp_append_dsa_caps_entry(
	ACVP_CTX *ctx,
	ACVP_DSA_CAP *cap,
	ACVP_CIPHER cipher,
	ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case));
static ACVP_RESULT acvp_append_rsa_caps_entry(
	ACVP_CTX *ctx,
	ACVP_RSA_CAP *cap,
	ACVP_CIPHER cipher,
	ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case));
static ACVP_RESULT acvp_append_hmac_caps_entry(
	ACVP_CTX *ctx,
	ACVP_HMAC_CAP *cap,
	ACVP_CIPHER cipher,
	ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case));
static ACVP_RESULT acvp_append_cmac_caps_entry(
	ACVP_CTX *ctx,
	ACVP_CMAC_CAP *cap,
	ACVP_CIPHER cipher,
	ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case));
static ACVP_RESULT acvp_append_kdf135_tls_caps_entry(
    ACVP_CTX *ctx,
    ACVP_KDF135_TLS_CAP *cap,
    ACVP_KDF135_TLS_METHOD method,
    ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case));
static void acvp_cap_free_sl(ACVP_SL_LIST *list);
static ACVP_RESULT acvp_get_result_vsid(ACVP_CTX *ctx, int vs_id);
static ACVP_RESULT acvp_add_prereq_val(ACVP_CIPHER cipher,
                    ACVP_CAPS_LIST *caps_list,
                    ACVP_PREREQ_ALG pre_req, char *value);





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
    {ACVP_AES_GCM,         &acvp_aes_kat_handler,   ACVP_ALG_AES_GCM},
    {ACVP_AES_CCM,         &acvp_aes_kat_handler,   ACVP_ALG_AES_CCM},
    {ACVP_AES_ECB,         &acvp_aes_kat_handler,   ACVP_ALG_AES_ECB},
    {ACVP_AES_CBC,         &acvp_aes_kat_handler,   ACVP_ALG_AES_CBC},
    {ACVP_AES_CFB1,        &acvp_aes_kat_handler,   ACVP_ALG_AES_CFB1},
    {ACVP_AES_CFB8,        &acvp_aes_kat_handler,   ACVP_ALG_AES_CFB8},
    {ACVP_AES_CFB128,      &acvp_aes_kat_handler,   ACVP_ALG_AES_CFB128},
    {ACVP_AES_OFB,         &acvp_aes_kat_handler,   ACVP_ALG_AES_OFB},
    {ACVP_AES_CTR,         &acvp_aes_kat_handler,   ACVP_ALG_AES_CTR},
    {ACVP_AES_XTS,         &acvp_aes_kat_handler,   ACVP_ALG_AES_XTS},
    {ACVP_AES_KW,          &acvp_aes_kat_handler,   ACVP_ALG_AES_KW},
    {ACVP_AES_KWP,         &acvp_aes_kat_handler,   ACVP_ALG_AES_KWP},
    {ACVP_TDES_ECB,        &acvp_des_kat_handler,   ACVP_ALG_TDES_ECB},
    {ACVP_TDES_CBC,        &acvp_des_kat_handler,   ACVP_ALG_TDES_CBC},
    {ACVP_TDES_CBCI,       &acvp_des_kat_handler,   ACVP_ALG_TDES_CBCI},
    {ACVP_TDES_OFB,        &acvp_des_kat_handler,   ACVP_ALG_TDES_OFB},
    {ACVP_TDES_OFBI,       &acvp_des_kat_handler,   ACVP_ALG_TDES_OFBI},
    {ACVP_TDES_CFB1,       &acvp_des_kat_handler,   ACVP_ALG_TDES_CFB1},
    {ACVP_TDES_CFB8,       &acvp_des_kat_handler,   ACVP_ALG_TDES_CFB8},
    {ACVP_TDES_CFB64,      &acvp_des_kat_handler,   ACVP_ALG_TDES_CFB64},
    {ACVP_TDES_CFBP1,      &acvp_des_kat_handler,   ACVP_ALG_TDES_CFBP1},
    {ACVP_TDES_CFBP8,      &acvp_des_kat_handler,   ACVP_ALG_TDES_CFBP8},
    {ACVP_TDES_CFBP64,     &acvp_des_kat_handler,   ACVP_ALG_TDES_CFBP64},
    {ACVP_TDES_CTR,        &acvp_des_kat_handler,   ACVP_ALG_TDES_CTR},
    {ACVP_TDES_KW,         &acvp_des_kat_handler,   ACVP_ALG_TDES_KW},
    {ACVP_SHA1,            &acvp_hash_kat_handler,  ACVP_ALG_SHA1},
    {ACVP_SHA224,          &acvp_hash_kat_handler,  ACVP_ALG_SHA224},
    {ACVP_SHA256,          &acvp_hash_kat_handler,  ACVP_ALG_SHA256},
    {ACVP_SHA384,          &acvp_hash_kat_handler,  ACVP_ALG_SHA384},
    {ACVP_SHA512,          &acvp_hash_kat_handler,  ACVP_ALG_SHA512},
    {ACVP_HASHDRBG,        &acvp_drbg_kat_handler,  ACVP_ALG_HASHDRBG},
    {ACVP_HMACDRBG,        &acvp_drbg_kat_handler,  ACVP_ALG_HMACDRBG},
    {ACVP_CTRDRBG,         &acvp_drbg_kat_handler,  ACVP_ALG_CTRDRBG},
    {ACVP_HMAC_SHA1,       &acvp_hmac_kat_handler,  ACVP_ALG_HMAC_SHA1},
    {ACVP_HMAC_SHA2_224,   &acvp_hmac_kat_handler,  ACVP_ALG_HMAC_SHA2_224},
    {ACVP_HMAC_SHA2_256,   &acvp_hmac_kat_handler,  ACVP_ALG_HMAC_SHA2_256},
    {ACVP_HMAC_SHA2_384,   &acvp_hmac_kat_handler,  ACVP_ALG_HMAC_SHA2_384},
    {ACVP_HMAC_SHA2_512,   &acvp_hmac_kat_handler,  ACVP_ALG_HMAC_SHA2_512},
    {ACVP_HMAC_SHA2_512_224, &acvp_hmac_kat_handler, ACVP_ALG_HMAC_SHA2_512_224},
    {ACVP_HMAC_SHA2_512_256, &acvp_hmac_kat_handler, ACVP_ALG_HMAC_SHA2_512_256},
    {ACVP_HMAC_SHA3_224,   &acvp_hmac_kat_handler,  ACVP_ALG_HMAC_SHA3_224},
    {ACVP_HMAC_SHA3_256,   &acvp_hmac_kat_handler,  ACVP_ALG_HMAC_SHA3_256},
    {ACVP_HMAC_SHA3_384,   &acvp_hmac_kat_handler,  ACVP_ALG_HMAC_SHA3_384},
    {ACVP_HMAC_SHA3_512,   &acvp_hmac_kat_handler,  ACVP_ALG_HMAC_SHA3_512},
    {ACVP_CMAC_AES_128,    &acvp_cmac_kat_handler,  ACVP_ALG_CMAC_AES_128},
    {ACVP_CMAC_AES_192,    &acvp_cmac_kat_handler,  ACVP_ALG_CMAC_AES_192},
    {ACVP_CMAC_AES_256,    &acvp_cmac_kat_handler,  ACVP_ALG_CMAC_AES_256},
    {ACVP_CMAC_TDES,       &acvp_cmac_kat_handler,  ACVP_ALG_CMAC_TDES},
    {ACVP_DSA,             &acvp_dsa_kat_handler,   ACVP_ALG_DSA},
    {ACVP_RSA,             &acvp_rsa_kat_handler,   ACVP_ALG_RSA},
    {ACVP_KDF135_TLS,      &acvp_kdf135_tls_kat_handler,  ACVP_ALG_KDF135_TLS},
    {ACVP_KDF135_SNMP,     &acvp_kdf135_snmp_kat_handler, ACVP_ALG_KDF135_SNMP},
    {ACVP_KDF135_SSH ,     &acvp_kdf135_ssh_kat_handler, ACVP_ALG_KDF135_SSH}
};

#define ACVP_NUM_PREREQS 5
struct acvp_prereqs_mode_name_t acvp_prereqs_tbl[ACVP_NUM_PREREQS] = {
    {ACVP_PREREQ_AES, "AES"},
    {ACVP_PREREQ_DRBG, "DRBG"},
    {ACVP_PREREQ_HMAC, "HMAC"},
    {ACVP_PREREQ_SHA, "SHA"},
    {ACVP_PREREQ_TDES, "TDES"}
};


/*
 * This is the first function the user should invoke to allocate
 * a new context to be used for the test session.
 */
ACVP_RESULT acvp_create_test_session(ACVP_CTX **ctx,
                                     ACVP_RESULT (*progress_cb)(char *msg),
				     ACVP_LOG_LVL level)
{
    *ctx = calloc(1, sizeof(ACVP_CTX));
    if (!*ctx) {
        return ACVP_MALLOC_FAIL;
    }
    (*ctx)->path_segment = strdup(ACVP_PATH_SEGMENT_DEFAULT);

    if (progress_cb) {
        (*ctx)->test_progress_cb = progress_cb;
    }

    (*ctx)->debug = level;

    return ACVP_SUCCESS;
}


/*
 * Free Internal memory for DRBG Data struct
 */
static void acvp_free_drbg_struct(ACVP_CAPS_LIST* cap_list)
{
    ACVP_DRBG_CAP       *drbg_cap = cap_list->cap.drbg_cap;
    if (drbg_cap) {
        ACVP_DRBG_CAP_MODE_LIST *mode_list = drbg_cap->drbg_cap_mode_list;
        ACVP_DRBG_CAP_MODE_LIST *next_mode_list;
        ACVP_PREREQ_LIST   *current_pre_req_vals;
        ACVP_PREREQ_LIST   *next_pre_req_vals;

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

static void acvp_free_prereqs(ACVP_CAPS_LIST* cap_list) {
      while (cap_list->prereq_vals) {
          ACVP_PREREQ_LIST *temp_ptr;
          temp_ptr = cap_list->prereq_vals;
          cap_list->prereq_vals = cap_list->prereq_vals->next;
          free(temp_ptr);
      }
}

/*
 * The application will invoke this to free the ACVP context
 * when the test session is finished.
 */
ACVP_RESULT acvp_free_test_session(ACVP_CTX *ctx)
{
    ACVP_VS_LIST *vs_entry, *vs_e2;
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    if (ctx) {
        if (ctx->reg_buf) free(ctx->reg_buf);
        if (ctx->kat_buf) free(ctx->kat_buf);
        if (ctx->upld_buf) free(ctx->upld_buf);
        if (ctx->kat_resp) json_value_free(ctx->kat_resp);
        if (ctx->server_name) free(ctx->server_name);
        if (ctx->vendor_name) free(ctx->vendor_name);
        if (ctx->vendor_url) free(ctx->vendor_url);
        if (ctx->contact_name) free(ctx->contact_name);
        if (ctx->contact_email) free(ctx->contact_email);
        if (ctx->module_name) free(ctx->module_name);
        if (ctx->module_version) free(ctx->module_version);
        if (ctx->module_type) free(ctx->module_type);
        if (ctx->module_desc) free(ctx->module_desc);
        if (ctx->path_segment) free(ctx->path_segment);
        if (ctx->cacerts_file) free(ctx->cacerts_file);
        if (ctx->tls_cert) free(ctx->tls_cert);
        if (ctx->tls_key) free(ctx->tls_key);
        if (ctx->vs_list) {
            vs_entry = ctx->vs_list;
            while (vs_entry) {
                vs_e2 = vs_entry->next;
                free(vs_entry);
                vs_entry = vs_e2;
            }
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
                    free(cap_entry->cap.sym_cap);
                    free(cap_entry);
                    cap_entry = cap_e2;
                    break;
                case ACVP_HASH_TYPE:
                    free(cap_entry->cap.hash_cap);
                    free(cap_entry);
                    cap_entry = cap_e2;
                    break;
                case ACVP_DRBG_TYPE:
                    acvp_free_drbg_struct(cap_entry);
                    free(cap_entry);
                    cap_entry = cap_e2;
                    break;
                case ACVP_HMAC_TYPE:
                    acvp_cap_free_sl(cap_entry->cap.hmac_cap->mac_len);
                    free(cap_entry->cap.hmac_cap);
                    free(cap_entry);
                    cap_entry = cap_e2;
                    break;
                case ACVP_CMAC_TYPE:
                    acvp_cap_free_sl(cap_entry->cap.cmac_cap->mac_len);
                    free(cap_entry->cap.cmac_cap);
                    free(cap_entry);
                    cap_entry = cap_e2;
                    break;
                default:
                    break;
                }
            }
        }
        if (ctx->jwt_token) free(ctx->jwt_token);
        free(ctx);
    }
    return ACVP_SUCCESS;
}

/*
 * Adds the length provided to the linked list of
 * supported lengths.
 */
static ACVP_RESULT acvp_cap_add_length(ACVP_SL_LIST **list, int len)
{
    ACVP_SL_LIST *l = *list;
    ACVP_SL_LIST *new;

    /*
     * Allocate some space for the new entry
     */
    new = calloc(1, sizeof(ACVP_SL_LIST));
    if (!new) {
      return ACVP_MALLOC_FAIL;
    }
    new->length = len;

    /*
     * See if we need to create the list first
     */
    if (!l) {
      *list = new;
    } else {
      /*
       * Find the end of the list and add the new entry there
       */
      while (l->next) {
          l = l->next;
      }
      l->next = new;
    }
    return ACVP_SUCCESS;
}

/*
 * Simple utility function to free a supported length
 * list from the capabilities structure.
 */
static void acvp_cap_free_sl(ACVP_SL_LIST *list)
{
    ACVP_SL_LIST *top = list;
    ACVP_SL_LIST *tmp;

    while(top) {
        tmp = top;
        top = top->next;
        free(tmp);
    }
}

/*
 * This function is called by the application to register a crypto
 * capability for symmetric ciphers, along with a handler that the
 * application implements when that particular crypto operation is
 * needed by libacvp.
 *
 * This function should be called one or more times for each crypto
 * capability supported by the crypto module being validated.  This
 * needs to be called after acvp_create_test_session() and prior to
 * calling acvp_register().
 *
 */
ACVP_RESULT acvp_enable_sym_cipher_cap(
	ACVP_CTX *ctx,
	ACVP_CIPHER cipher,
	ACVP_SYM_CIPH_DIR dir,
	ACVP_SYM_CIPH_KO keying_option,
	ACVP_SYM_CIPH_IVGEN_SRC ivgen_source,
	ACVP_SYM_CIPH_IVGEN_MODE ivgen_mode,
        ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_SYM_CIPHER_CAP *cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }

    cap = calloc(1, sizeof(ACVP_SYM_CIPHER_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }

    //TODO: need to validate that cipher, mode, etc. are valid values
    //      we also need to make sure we're not adding a duplicate
    cap->direction = dir;
    cap->keying_option = keying_option;
    cap->ivgen_source = ivgen_source;
    cap->ivgen_mode = ivgen_mode;

    return (acvp_append_sym_cipher_caps_entry(ctx, cap, cipher, crypto_handler));
}

ACVP_RESULT acvp_validate_sym_cipher_parm_value(ACVP_SYM_CIPH_PARM parm, int value) {
  ACVP_RESULT retval = ACVP_INVALID_ARG;

  switch(parm){
    case ACVP_SYM_CIPH_KEYLEN:
      if (value == 128 || value == 168 || value == 192 || value == 256) {
        retval = ACVP_SUCCESS;
      }
      break;
    case ACVP_SYM_CIPH_TAGLEN:
      if (value >= 4 && value <= 128) {
        retval = ACVP_SUCCESS;
      }
      break;
    case ACVP_SYM_CIPH_IVLEN:
      if (value >= 8 && value <= 1024) {
        retval = ACVP_SUCCESS;
      }
      break;
    case ACVP_SYM_CIPH_AADLEN:
    case ACVP_SYM_CIPH_PTLEN:
      if (value >= 0 && value <= 65536) {
        retval = ACVP_SUCCESS;
      }
      break;
    default:
      break;
  }

  return retval;
}

/*
 * The user should call this after invoking acvp_enable_sym_cipher_cap()
 * to specify the supported key lengths, PT lengths, AAD lengths, IV
 * lengths, and tag lengths.  This is called by the user multiple times,
 * once for each length supported.
 */
ACVP_RESULT acvp_enable_sym_cipher_cap_parm(
	ACVP_CTX *ctx,
	ACVP_CIPHER cipher,
	ACVP_SYM_CIPH_PARM parm,
	int length) {

    ACVP_CAPS_LIST *cap;

    /*
     * Locate this cipher in the caps array
     */
    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        ACVP_LOG_ERR("Cap entry not found, use acvp_enable_sym_cipher_cap() first.");
	return ACVP_NO_CAP;
    }

    if (acvp_validate_sym_cipher_parm_value(parm, length) != ACVP_SUCCESS) {
      return ACVP_INVALID_ARG;
    }

    switch (parm) {
    case ACVP_SYM_CIPH_KEYLEN:
      acvp_cap_add_length(&cap->cap.sym_cap->keylen, length);
      break;
    case ACVP_SYM_CIPH_TAGLEN:
      acvp_cap_add_length(&cap->cap.sym_cap->taglen, length);
      break;
    case ACVP_SYM_CIPH_IVLEN:
      acvp_cap_add_length(&cap->cap.sym_cap->ivlen, length);
      break;
    case ACVP_SYM_CIPH_PTLEN:
      acvp_cap_add_length(&cap->cap.sym_cap->ptlen, length);
      break;
    case ACVP_SYM_CIPH_AADLEN:
      acvp_cap_add_length(&cap->cap.sym_cap->aadlen, length);
      break;
    default:
      return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}


ACVP_RESULT acvp_enable_prereq_cap(ACVP_CTX *ctx,
                                       ACVP_CIPHER      cipher,
                                    ACVP_PREREQ_ALG pre_req_cap,
                             	       char              *value)
{
    ACVP_CAPS_LIST          *cap_list;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    cap_list->has_prereq = 1;     /* make sure this is set */
    /*
     * Add the value to the cap
     */
    return (acvp_add_prereq_val(cipher, cap_list, pre_req_cap, value));
}

ACVP_RESULT acvp_enable_hash_cap(
	ACVP_CTX *ctx,
	ACVP_CIPHER cipher,
	ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_HASH_CAP *cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }

    cap = calloc(1, sizeof(ACVP_HASH_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }

    //TODO: need to validate that cipher, mode, etc. are valid values
    //      we also need to make sure we're not adding a duplicate

    return (acvp_append_hash_caps_entry(ctx, cap, cipher, crypto_handler));
}

ACVP_RESULT acvp_validate_hash_parm_value(ACVP_HASH_PARM parm, int value) {
  ACVP_RESULT retval = ACVP_INVALID_ARG;

  switch(parm){
    case ACVP_HASH_IN_BIT:
    case ACVP_HASH_IN_EMPTY:
        retval = is_valid_tf_param(value);
        break;
    default:
      break;
  }

  return retval;
}

/*
 * Add HASH(SHA) parameters
 */
ACVP_RESULT acvp_enable_hash_cap_parm (
		   ACVP_CTX *ctx,
		   ACVP_CIPHER cipher,
                   ACVP_HASH_PARM       param,
                   int                  value
                   )
{
    ACVP_CAPS_LIST *cap;
    ACVP_HASH_CAP *hash_cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    hash_cap = cap->cap.hash_cap;
    if (!hash_cap) {
        return ACVP_NO_CAP;
    }

    if (acvp_validate_hash_parm_value(param, value) != ACVP_SUCCESS) {
      return ACVP_INVALID_ARG;
    }

    switch (cipher) {
    case ACVP_SHA1:
    case ACVP_SHA224:
    case ACVP_SHA256:
    case ACVP_SHA384:
    case ACVP_SHA512:
        switch (param) {
        case ACVP_HASH_IN_BIT:
            hash_cap->in_bit = value;
            break;
        case ACVP_HASH_IN_EMPTY:
            hash_cap->in_empty = value;
	    break;
        default:
            return ACVP_INVALID_ARG;
            break;
        }
        break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_validate_hmac_parm_value(ACVP_CIPHER cipher,
                                          ACVP_HMAC_PARM parm,
                                          int value) {
  ACVP_RESULT retval = ACVP_INVALID_ARG;
  int max_val = 0;

  switch(parm){
    case ACVP_HMAC_KEYLEN_MIN:
    case ACVP_HMAC_KEYLEN_MAX:
      if (value >= 8 && value <= 524288) {
        retval = ACVP_SUCCESS;
      }
      break;
    case ACVP_HMAC_MACLEN:
      switch(cipher){
        case ACVP_HMAC_SHA1:
          max_val = 160;
          break;
        case ACVP_HMAC_SHA2_224:
        case ACVP_HMAC_SHA2_512_224:
        case ACVP_HMAC_SHA3_224:
          max_val = 224;
          break;
        case ACVP_HMAC_SHA2_256:
        case ACVP_HMAC_SHA2_512_256:
        case ACVP_HMAC_SHA3_256:
          max_val = 256;
          break;
        case ACVP_HMAC_SHA2_384:
        case ACVP_HMAC_SHA3_384:
          max_val = 384;
          break;
        case ACVP_HMAC_SHA2_512:
        case ACVP_HMAC_SHA3_512:
          max_val = 512;
          break;
        default:
          break;
      }
      if (value >= 32 && value <= max_val) {
        retval = ACVP_SUCCESS;
      }
      break;
    default:
      break;
  }

  return retval;
}

ACVP_RESULT acvp_enable_hmac_cap(
          ACVP_CTX *ctx,
          ACVP_CIPHER cipher,
          ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_HMAC_CAP *cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }

    cap = calloc(1, sizeof(ACVP_HMAC_CAP));
    if (!cap) {
      return ACVP_MALLOC_FAIL;
    }

    return (acvp_append_hmac_caps_entry(ctx, cap, cipher, crypto_handler));
}

/*
 * The user should call this after invoking acvp_enable_hmac_cap()
 * to specify the supported key ranges, keyblock value, and
 * suuported mac lengths. This is called by the user multiple times,
 * once for each length supported.
 */
ACVP_RESULT acvp_enable_hmac_cap_parm(
                          ACVP_CTX *ctx,
                          ACVP_CIPHER cipher,
                          ACVP_HMAC_PARM parm,
                          int value) {

    ACVP_CAPS_LIST *cap;

    /*
     * Locate this cipher in the caps array
     */
    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        ACVP_LOG_ERR("Cap entry not found, use acvp_enable_hmac_cipher_cap() first.");
        return ACVP_NO_CAP;
    }

    if (acvp_validate_hmac_parm_value(cipher, parm, value) != ACVP_SUCCESS) {
      return ACVP_INVALID_ARG;
    }

    switch (parm) {
    case ACVP_HMAC_KEYLEN_MIN:
      cap->cap.hmac_cap->key_len_min = value;
      break;
    case ACVP_HMAC_KEYLEN_MAX:
      cap->cap.hmac_cap->key_len_max = value;
      break;
    case ACVP_HMAC_MACLEN:
      acvp_cap_add_length(&cap->cap.hmac_cap->mac_len, value);
      break;
    default:
      return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_validate_cmac_parm_value(ACVP_CMAC_PARM parm, int value) {
  ACVP_RESULT retval = ACVP_INVALID_ARG;

  switch(parm){
    case ACVP_CMAC_BLK_DIVISIBLE_1:
    case ACVP_CMAC_BLK_DIVISIBLE_2:
    case ACVP_CMAC_BLK_NOT_DIVISIBLE_1:
    case ACVP_CMAC_BLK_NOT_DIVISIBLE_2:
    case ACVP_CMAC_MSG_LEN_MAX:
        if (value >= 0 && value <= 524288 && value % 8 == 0) {
          retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_CMAC_MACLEN:
        if (value >= 8 && value <= 524288 && value % 8 == 0) {
          retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_CMAC_DIRECTION_GEN:
    case ACVP_CMAC_DIRECTION_VER:
        retval = is_valid_tf_param(value);
        break;
    default:
        break;
  }

  return retval;
}

ACVP_RESULT acvp_enable_cmac_cap(
          ACVP_CTX *ctx,
          ACVP_CIPHER cipher,
          ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_CMAC_CAP *cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }

    cap = calloc(1, sizeof(ACVP_CMAC_CAP));
    if (!cap) {
      return ACVP_MALLOC_FAIL;
    }

    return (acvp_append_cmac_caps_entry(ctx, cap, cipher, crypto_handler));
}

/*
 * The user should call this after invoking acvp_enable_cmac_cap()
 * to specify the supported msg lengths, mac lengths, and diretion.
 * This is called by the user multiple times,
 * once for each length supported.
 */
ACVP_RESULT acvp_enable_cmac_cap_parm(
                          ACVP_CTX *ctx,
                          ACVP_CIPHER cipher,
                          ACVP_CMAC_PARM parm,
                          int value) {

    ACVP_CAPS_LIST *cap;

    /*
     * Locate this cipher in the caps array
     */
    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        ACVP_LOG_ERR("Cap entry not found, use acvp_enable_cmac_cipher_cap() first.");
        return ACVP_NO_CAP;
    }

    if (acvp_validate_cmac_parm_value(parm, value) != ACVP_SUCCESS) {
      return ACVP_INVALID_ARG;
    }

    switch (parm) {
    case ACVP_CMAC_BLK_DIVISIBLE_1:
      cap->cap.cmac_cap->msg_len[CMAC_BLK_DIVISIBLE_1] = value;
      break;
    case ACVP_CMAC_BLK_DIVISIBLE_2:
      cap->cap.cmac_cap->msg_len[CMAC_BLK_DIVISIBLE_2] = value;
      break;
    case ACVP_CMAC_BLK_NOT_DIVISIBLE_1:
      cap->cap.cmac_cap->msg_len[CMAC_BLK_NOT_DIVISIBLE_1] = value;
      break;
    case ACVP_CMAC_BLK_NOT_DIVISIBLE_2:
      cap->cap.cmac_cap->msg_len[CMAC_BLK_NOT_DIVISIBLE_2] = value;
      break;
    case ACVP_CMAC_MSG_LEN_MAX:
      cap->cap.cmac_cap->msg_len[CMAC_MSG_LEN_MAX] = value;
      break;
    case ACVP_CMAC_DIRECTION_GEN:
      cap->cap.cmac_cap->direction_gen = value;
      break;
    case ACVP_CMAC_DIRECTION_VER:
      cap->cap.cmac_cap->direction_ver = value;
      break;
    case ACVP_CMAC_MACLEN:
      acvp_cap_add_length(&cap->cap.cmac_cap->mac_len, value);
      break;
    default:
      return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}


ACVP_RESULT acvp_validate_drbg_parm_value(ACVP_DRBG_PARM parm, int value) {
  ACVP_RESULT retval = ACVP_INVALID_ARG;

  switch(parm){
    case ACVP_DRBG_DER_FUNC_ENABLED:
    case ACVP_DRBG_PRED_RESIST_ENABLED:
    case ACVP_DRBG_RESEED_ENABLED:
      retval = is_valid_tf_param(value);
      break;
    case ACVP_DRBG_ENTROPY_LEN:
    case ACVP_DRBG_NONCE_LEN:
    case ACVP_DRBG_PERSO_LEN:
    case ACVP_DRBG_ADD_IN_LEN:
    case ACVP_DRBG_RET_BITS_LEN:
    case ACVP_DRBG_PRE_REQ_VALS:
      // TODO: add proper validation for these parameters
      retval = ACVP_SUCCESS;
      break;
    default:
      break;
  }

  return retval;
}

/*
 * Add CTR DRBG parameters
 */
static ACVP_RESULT acvp_add_ctr_drbg_cap_parm (
                             ACVP_DRBG_CAP_MODE  *drbg_cap_mode,
                             ACVP_DRBG_MODE       mode,
                             ACVP_DRBG_PARM       param,
                             int value
                             )
{
    if (!drbg_cap_mode) {
        return ACVP_INVALID_ARG;
    }

    if (acvp_validate_drbg_parm_value(param, value) != ACVP_SUCCESS) {
      return ACVP_INVALID_ARG;
    }

    switch (mode) {
    case ACVP_DRBG_3KEYTDEA:
    case ACVP_DRBG_AES_128:
    case ACVP_DRBG_AES_192:
    case ACVP_DRBG_AES_256:
        drbg_cap_mode->mode = mode;
        switch (param) {
        case ACVP_DRBG_DER_FUNC_ENABLED:
            drbg_cap_mode->der_func_enabled = value;
            break;
        case ACVP_DRBG_PRED_RESIST_ENABLED:
            drbg_cap_mode->pred_resist_enabled = value;
            break;
        case ACVP_DRBG_RESEED_ENABLED:
            drbg_cap_mode->reseed_implemented = value;
            break;
        case ACVP_DRBG_ENTROPY_LEN:
            drbg_cap_mode->entropy_input_len = value;
            break;
        case ACVP_DRBG_NONCE_LEN:
            drbg_cap_mode->nonce_len = value;
            break;
        case ACVP_DRBG_PERSO_LEN:
            drbg_cap_mode->perso_string_len = value;
            break;
        case ACVP_DRBG_ADD_IN_LEN:
            drbg_cap_mode->additional_input_len = value;
            break;
        case ACVP_DRBG_RET_BITS_LEN:
            drbg_cap_mode->returned_bits_len = value;
            break;
        case ACVP_DRBG_PRE_REQ_VALS:
        default:
            break;
        }
        break;


    default:
        return ACVP_INVALID_ARG;
        break;
    }

    return ACVP_SUCCESS;
}

/*
 * Add HASH DRBG parameters
 */
static ACVP_RESULT acvp_add_hash_drbg_cap_parm (
                             ACVP_DRBG_CAP_MODE  *drbg_cap_mode,
                             ACVP_DRBG_MODE       mode,
                             ACVP_DRBG_PARM       param,
                             int                  value
                             )
{
    switch (mode) {
    case ACVP_DRBG_SHA_1:
    case ACVP_DRBG_SHA_224:
    case ACVP_DRBG_SHA_256:
    case ACVP_DRBG_SHA_384:
    case ACVP_DRBG_SHA_512:
        drbg_cap_mode->mode = mode;
        switch (param) {
        case ACVP_DRBG_DER_FUNC_ENABLED:
            drbg_cap_mode->der_func_enabled = value;
            break;
        case ACVP_DRBG_PRED_RESIST_ENABLED:
            drbg_cap_mode->pred_resist_enabled = value;
            break;
        case ACVP_DRBG_RESEED_ENABLED:
            drbg_cap_mode->reseed_implemented = value;
            break;
        case ACVP_DRBG_ENTROPY_LEN:
            drbg_cap_mode->entropy_input_len = value;
            break;
        case ACVP_DRBG_NONCE_LEN:
            drbg_cap_mode->nonce_len = value;
            break;
        case ACVP_DRBG_PERSO_LEN:
            drbg_cap_mode->perso_string_len = value;
            break;
        case ACVP_DRBG_ADD_IN_LEN:
            drbg_cap_mode->additional_input_len = value;
            break;
        case ACVP_DRBG_RET_BITS_LEN:
            drbg_cap_mode->returned_bits_len = value;
            break;
        case ACVP_DRBG_PRE_REQ_VALS:
        default:
            return ACVP_INVALID_ARG;
            break;
        }
        break;
    case ACVP_DRBG_SHA_512_224:
    case ACVP_DRBG_SHA_512_256:
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}

/*
 * Add HMAC DRBG parameters
 */
static ACVP_RESULT acvp_add_hmac_drbg_cap_parm (
                             ACVP_DRBG_CAP_MODE  *drbg_cap_mode,
                             ACVP_DRBG_MODE       mode,
                             ACVP_DRBG_PARM       param,
                             int                  value
                             )
{
    switch (mode) {
    case ACVP_DRBG_SHA_1:
    case ACVP_DRBG_SHA_224:
    case ACVP_DRBG_SHA_256:
    case ACVP_DRBG_SHA_384:
    case ACVP_DRBG_SHA_512:
        drbg_cap_mode->mode = mode;
        switch (param) {
        case ACVP_DRBG_DER_FUNC_ENABLED:
            drbg_cap_mode->der_func_enabled = value;
            break;
        case ACVP_DRBG_PRED_RESIST_ENABLED:
            drbg_cap_mode->pred_resist_enabled = value;
            break;
        case ACVP_DRBG_RESEED_ENABLED:
            drbg_cap_mode->reseed_implemented = value;
            break;
        case ACVP_DRBG_ENTROPY_LEN:
            drbg_cap_mode->entropy_input_len = value;
            break;
        case ACVP_DRBG_NONCE_LEN:
            drbg_cap_mode->nonce_len = value;
            break;
        case ACVP_DRBG_PERSO_LEN:
            drbg_cap_mode->perso_string_len = value;
            break;
        case ACVP_DRBG_ADD_IN_LEN:
            drbg_cap_mode->additional_input_len = value;
            break;
        case ACVP_DRBG_RET_BITS_LEN:
            drbg_cap_mode->returned_bits_len = value;
            break;
        case ACVP_DRBG_PRE_REQ_VALS:
        default:
            return ACVP_INVALID_ARG;
        }
        break;

    case ACVP_DRBG_SHA_512_224:
    case ACVP_DRBG_SHA_512_256:
    default:
        return ACVP_INVALID_ARG;
        break;
    }

    return ACVP_SUCCESS;
}

/*
 * Append a DRBG pre req val to the
 */
static ACVP_RESULT acvp_add_drbg_prereq_val(ACVP_DRBG_CAP_MODE *drbg_cap_mode,
                   ACVP_DRBG_MODE mode, ACVP_PREREQ_ALG pre_req, char *value)
{
    ACVP_PREREQ_LIST *prereq_entry, *prereq_entry_2;

    prereq_entry = calloc(1, sizeof(ACVP_PREREQ_LIST));
    if (!prereq_entry) {
        return ACVP_MALLOC_FAIL;
    }
    prereq_entry->prereq_alg_val.alg = pre_req;
    prereq_entry->prereq_alg_val.val = value;

    /*
     * 1st entry
     */
    if (!drbg_cap_mode->prereq_vals) {
        drbg_cap_mode->prereq_vals= prereq_entry;
    } else {
        /*
         * append to the last in the list
         */
        prereq_entry_2 = drbg_cap_mode->prereq_vals;
        while (prereq_entry_2->next) {
            prereq_entry_2 = prereq_entry_2->next;
        }
        prereq_entry_2->next = prereq_entry;
    }
    return (ACVP_SUCCESS);
}

static ACVP_RESULT acvp_validate_prereq_val(ACVP_CIPHER cipher, ACVP_PREREQ_ALG pre_req) {
    switch(cipher) {
    case ACVP_AES_GCM:
    case ACVP_AES_CCM:
    case ACVP_AES_ECB:
    case ACVP_AES_CFB1:
    case ACVP_AES_CFB8:
    case ACVP_AES_CFB128:
    case ACVP_AES_OFB:
    case ACVP_AES_CBC:
    case ACVP_AES_KW:
    case ACVP_AES_CTR:
    case ACVP_TDES_ECB:
    case ACVP_TDES_CBC:
    case ACVP_TDES_OFB:
    case ACVP_TDES_CFB64:
    case ACVP_TDES_CFB8:
    case ACVP_TDES_CFB1:
        if (pre_req == ACVP_PREREQ_AES ||
            pre_req == ACVP_PREREQ_DRBG)
            return ACVP_SUCCESS;
        break;
    case ACVP_SHA1:
    case ACVP_SHA224:
    case ACVP_SHA256:
    case ACVP_SHA384:
    case ACVP_SHA512:
        return ACVP_INVALID_ARG;
        break;
    case ACVP_HASHDRBG:
    case ACVP_HMACDRBG:
    case ACVP_CTRDRBG:
        if (pre_req == ACVP_PREREQ_AES ||
            pre_req == ACVP_PREREQ_DRBG ||
            pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_TDES)
            return ACVP_SUCCESS;
        break;
    case ACVP_HMAC_SHA1:
    case ACVP_HMAC_SHA2_224:
    case ACVP_HMAC_SHA2_256:
    case ACVP_HMAC_SHA2_384:
    case ACVP_HMAC_SHA2_512:
        if (pre_req == ACVP_PREREQ_SHA)
            return ACVP_SUCCESS;
        break;
    case ACVP_CMAC_AES_128:
    case ACVP_CMAC_AES_192:
    case ACVP_CMAC_AES_256:
    case ACVP_CMAC_TDES:
        if (pre_req == ACVP_PREREQ_AES)
            return ACVP_SUCCESS;
        break;
    case ACVP_DSA:
        if (pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_DRBG)
            return ACVP_SUCCESS;
        break;
    case ACVP_RSA:
        if (pre_req == ACVP_PREREQ_SHA ||
        	pre_req == ACVP_PREREQ_DRBG)
            return ACVP_SUCCESS;
        break;
    case ACVP_KDF135_TLS:
    case ACVP_KDF135_SNMP:
        if (pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_HMAC)
            return ACVP_SUCCESS;
        break;
    case ACVP_KDF135_SSH:
        if (pre_req == ACVP_PREREQ_SHA ||
            pre_req == ACVP_PREREQ_TDES ||
            pre_req == ACVP_PREREQ_AES)
            return ACVP_SUCCESS;
        break;

    default:
        break;
    }

    return ACVP_INVALID_ARG;
}

/*
 * Add RSA siggen parameter sigType
 */
static ACVP_RESULT acvp_add_rsa_siggen_parm (
                             ACVP_RSA_CAP_MODE_LIST  *rsa_cap_mode_list,
                             ACVP_RSA_PARM       param,
                             ACVP_RSA_SIG_TYPE   value
                             )
{

    // TODO: NEED TO ADD VALIDATION here

    switch (param) {
    case ACVP_SIG_TYPE:
    	switch (value) {
    	case RSA_SIG_TYPE_X931:
    		rsa_cap_mode_list->cap_mode_attrs.siggen->sig_type = RSA_SIG_TYPE_X931_NAME;
    		break;
    	case RSA_SIG_TYPE_PKCS1V15:
			rsa_cap_mode_list->cap_mode_attrs.siggen->sig_type = RSA_SIG_TYPE_PKCS1V15_NAME;
			break;
    	case RSA_SIG_TYPE_PKCS1PSS:
			rsa_cap_mode_list->cap_mode_attrs.siggen->sig_type = RSA_SIG_TYPE_PKCS1PSS_NAME;
			break;
		default:
            break;
        }
        break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}

/*
 * Add RSA siggen parameter sigType
 */
static ACVP_RESULT acvp_add_rsa_sigver_parm (
                             ACVP_RSA_CAP_MODE_LIST  *rsa_cap_mode_list,
                             ACVP_RSA_PARM       param,
                             ACVP_RSA_SIG_TYPE   value
                             )
{

    // TODO: NEED TO ADD VALIDATION here

    switch (param) {
    case ACVP_SIG_TYPE:
        switch (value) {
        case RSA_SIG_TYPE_X931:
            rsa_cap_mode_list->cap_mode_attrs.sigver->sig_type = RSA_SIG_TYPE_X931_NAME;
            break;
        case RSA_SIG_TYPE_PKCS1V15:
            rsa_cap_mode_list->cap_mode_attrs.sigver->sig_type = RSA_SIG_TYPE_PKCS1V15_NAME;
            break;
        case RSA_SIG_TYPE_PKCS1PSS:
            rsa_cap_mode_list->cap_mode_attrs.sigver->sig_type = RSA_SIG_TYPE_PKCS1PSS_NAME;
            break;
        default:
            break;
        }
        break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}

/*
 * Append a RSA pre req val to the list of prereqs
 */
static ACVP_RESULT acvp_add_prereq_val(ACVP_CIPHER cipher,
                    ACVP_CAPS_LIST *cap_list,
                    ACVP_PREREQ_ALG pre_req, char *value)
{
    ACVP_PREREQ_LIST *prereq_entry, *prereq_entry_2;
    ACVP_RESULT result;

    prereq_entry = calloc(1, sizeof(ACVP_PREREQ_LIST));
    if (!prereq_entry) {
        return ACVP_MALLOC_FAIL;
    }
    prereq_entry->prereq_alg_val.alg = pre_req;
    prereq_entry->prereq_alg_val.val = value;

    result = acvp_validate_prereq_val(cipher, pre_req);
    if (result != ACVP_SUCCESS) return result;
    /*
     * 1st entry
     */
    if (!cap_list->prereq_vals) {
        cap_list->prereq_vals = prereq_entry;
    } else {
        /*
         * append to the last in the list
         */
        prereq_entry_2 = cap_list->prereq_vals;
        while (prereq_entry_2->next) {
            prereq_entry_2 = prereq_entry_2->next;
        }
        prereq_entry_2->next = prereq_entry;
    }
    return (ACVP_SUCCESS);
}




/*
 * Add top level RSA keygen parameters
 */
static ACVP_RESULT acvp_add_rsa_keygen_parm (
                             ACVP_RSA_CAP_MODE_LIST  *rsa_cap_mode_list,
                             ACVP_RSA_PARM       param,
                             int                  value
                             )
{
    switch (param) {
    case ACVP_PUB_EXP:
        rsa_cap_mode_list->cap_mode_attrs.keygen->pub_exp = value;
        break;
    case ACVP_RAND_PQ:
        rsa_cap_mode_list->cap_mode_attrs.keygen->rand_pq = value;
        break;
    case ACVP_RSA_INFO_GEN_BY_SERVER:
        rsa_cap_mode_list->cap_mode_attrs.keygen->info_gen_by_server = value;
        break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_rsa_prepare_to_add_param(ACVP_CTX *ctx, ACVP_CIPHER cipher,
                                          ACVP_RSA_MODE mode,
                                          ACVP_CAPS_LIST **cap_list,
                                          ACVP_RSA_CAP_MODE_LIST      **rsa_cap_mode_list) {

    ACVP_RSA_CAP_MODE_LIST *current_rsa_cap_list;

    /*
     * Validate input
     */
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (cipher != ACVP_RSA) return ACVP_INVALID_ARG;

    /*
     * Locate this cipher in the caps array
     */
    *cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!*cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     * if the mode does not exist yet then create it.
     */
    if (!(*cap_list)->cap.rsa_cap) {
        ACVP_LOG_ERR("RSA Cap entry not found.");
        return ACVP_NO_CAP;
    }

    *rsa_cap_mode_list = acvp_locate_rsa_mode_entry(*cap_list, mode);
    if (!*rsa_cap_mode_list) {
        *rsa_cap_mode_list = calloc(1, sizeof(ACVP_RSA_CAP_MODE_LIST));
        if (!*rsa_cap_mode_list) {
            ACVP_LOG_ERR("Malloc Failed -- RSA cap mode list entry");
            return ACVP_MALLOC_FAIL;
        }

        (*rsa_cap_mode_list)->cap_mode = mode;

        switch(mode) {
        case ACVP_RSA_MODE_KEYGEN:
            (*rsa_cap_mode_list)->cap_mode_attrs.keygen = calloc(1, sizeof(ACVP_RSA_KEYGEN_ATTRS));
            if (!(*rsa_cap_mode_list)->cap_mode_attrs.keygen) {
                ACVP_LOG_ERR("Malloc Failed -- RSA KeyGen cap attributes");
                return ACVP_MALLOC_FAIL;
            }
            (*rsa_cap_mode_list)->cap_mode_attrs.keygen->rand_pq = 0;
            break;
        case ACVP_RSA_MODE_SIGGEN:
			(*rsa_cap_mode_list)->cap_mode_attrs.siggen = calloc(1, sizeof(ACVP_RSA_SIGGEN_ATTRS));
			if (!(*rsa_cap_mode_list)->cap_mode_attrs.siggen) {
				ACVP_LOG_ERR("Malloc Failed -- RSA SigGen cap attributes");
				return ACVP_MALLOC_FAIL;
			}
			break;
        case ACVP_RSA_MODE_SIGVER:
                    (*rsa_cap_mode_list)->cap_mode_attrs.sigver = calloc(1, sizeof(ACVP_RSA_SIGVER_ATTRS));
                    if (!(*rsa_cap_mode_list)->cap_mode_attrs.sigver) {
                        ACVP_LOG_ERR("Malloc Failed -- RSA SigVer cap attributes");
                        return ACVP_MALLOC_FAIL;
                    }
                    break;
        default:
            break;
        }

        current_rsa_cap_list = (*cap_list)->cap.rsa_cap->rsa_cap_mode_list;
        if (!current_rsa_cap_list) (*cap_list)->cap.rsa_cap->rsa_cap_mode_list = *rsa_cap_mode_list;
        else {
            while (current_rsa_cap_list->next) {
                current_rsa_cap_list = current_rsa_cap_list->next;
            }
            current_rsa_cap_list->next = *rsa_cap_mode_list;
        }

    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_validate_rsa_parm_value(ACVP_RSA_PARM parm, int value,
                                         ACVP_RSA_CAP_MODE_LIST *rsa_cap_mode_list)
{
  ACVP_RESULT retval = ACVP_INVALID_ARG;

  switch(parm){
    case ACVP_PUB_EXP:
    case ACVP_RSA_INFO_GEN_BY_SERVER:
        retval = is_valid_tf_param(value);
        break;
    case ACVP_RAND_PQ:
        if (value >= RSA_RAND_PQ_B32 && value <= RSA_RAND_PQ_B36) {
            retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_CAPS_PROV_PRIME:
        if (rsa_cap_mode_list->cap_mode_attrs.keygen->rand_pq == RSA_RAND_PQ_B32 ||
            rsa_cap_mode_list->cap_mode_attrs.keygen->rand_pq == RSA_RAND_PQ_B34) {
              retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_CAPS_PROB_PRIME:
        if (rsa_cap_mode_list->cap_mode_attrs.keygen->rand_pq == RSA_RAND_PQ_B33 ||
            rsa_cap_mode_list->cap_mode_attrs.keygen->rand_pq == RSA_RAND_PQ_B36) {
              retval = ACVP_SUCCESS;
        }
        break;
    case ACVP_CAPS_PROV_PROB_PRIME:
        if (rsa_cap_mode_list->cap_mode_attrs.keygen->rand_pq == RSA_RAND_PQ_B35) {
              retval = ACVP_SUCCESS;
        }
        break;

    case ACVP_SIG_TYPE:
    	switch (value) {
		case RSA_SIG_TYPE_X931:
		case RSA_SIG_TYPE_PKCS1V15:
		case RSA_SIG_TYPE_PKCS1PSS:
			retval = ACVP_SUCCESS;
		}
		break;
    default:
      break;
  }

  return retval;
}

ACVP_RESULT acvp_validate_rsa_primes_parm(ACVP_RSA_PARM parm, int mod, char *name,
                                          ACVP_RSA_CAP_MODE_LIST *rsa_cap_mode_list)
{
    ACVP_RESULT retval = ACVP_INVALID_ARG;
    retval = is_valid_rsa_mod(mod);
    if (retval != ACVP_SUCCESS) return retval;

    switch(parm){
    case ACVP_CAPS_PROV_PRIME:
        if (rsa_cap_mode_list->cap_mode_attrs.keygen->rand_pq == RSA_RAND_PQ_B32 ||
            rsa_cap_mode_list->cap_mode_attrs.keygen->rand_pq == RSA_RAND_PQ_B34) {
                retval = is_valid_hash_alg(name);
        }
        break;
    case ACVP_CAPS_PROB_PRIME:
        if (rsa_cap_mode_list->cap_mode_attrs.keygen->rand_pq == RSA_RAND_PQ_B33 ||
            rsa_cap_mode_list->cap_mode_attrs.keygen->rand_pq == RSA_RAND_PQ_B36) {
                retval = is_valid_prime_test(name);
        }
        break;
    case ACVP_CAPS_PROV_PROB_PRIME:
        if (rsa_cap_mode_list->cap_mode_attrs.keygen->rand_pq == RSA_RAND_PQ_B35) {
              if (is_valid_hash_alg(name) == ACVP_SUCCESS ||
                  is_valid_prime_test(name) == ACVP_SUCCESS) {
                      retval = ACVP_SUCCESS;
              }
        }
        break;
    default:
      break;
    }

    return retval;
}

/*
 * The user should call this after invoking acvp_enable_rsa_cap_parm().
 */
ACVP_RESULT acvp_enable_rsa_cap_parm (ACVP_CTX *ctx,
                             ACVP_CIPHER cipher,
                             ACVP_RSA_MODE mode,
                             ACVP_RSA_PARM param,
                             int value
                             )
{
    ACVP_RSA_CAP_MODE_LIST *rsa_cap_mode_list;
    ACVP_CAPS_LIST *cap_list;
    ACVP_RESULT result;

    /*
     * Add the value to the cap
     */
    result = acvp_rsa_prepare_to_add_param(ctx, cipher, mode, &cap_list,
            &rsa_cap_mode_list);
    if (result != ACVP_SUCCESS)
        return result;
    if (acvp_validate_rsa_parm_value(param, value, rsa_cap_mode_list)
                != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Invalid value for specified RSA param");
            return ACVP_INVALID_ARG;
        }
    switch (mode) {
    case ACVP_RSA_MODE_KEYGEN:

        result = acvp_add_rsa_keygen_parm(rsa_cap_mode_list, param, value);
        if (result != ACVP_SUCCESS)
            ACVP_LOG_ERR(
                    "Invalid param to enable_rsa_cap_parm. If registering primes, use enable_rsa_primes instead");
        break;
    case ACVP_RSA_MODE_SIGGEN:
        if (rsa_cap_mode_list->cap_mode_attrs.siggen->sig_type) {
            rsa_cap_mode_list= acvp_locate_rsa_sig_type_entry(ctx, cap_list, mode,
                                            value);
            if (!rsa_cap_mode_list) {
                return ACVP_INVALID_ARG;
            }
        }
        result = acvp_add_rsa_siggen_parm(rsa_cap_mode_list, param, value);
        break;
    case ACVP_RSA_MODE_SIGVER:
        if (rsa_cap_mode_list->cap_mode_attrs.sigver->sig_type) {
            rsa_cap_mode_list = acvp_locate_rsa_sig_type_entry(ctx, cap_list, mode,
        	                    value);
            if (!rsa_cap_mode_list) {
                return ACVP_INVALID_ARG;
            }
        }
        result = acvp_add_rsa_sigver_parm(rsa_cap_mode_list, param, value);
        break;
    default:
        ACVP_LOG_ERR("RSA Mode Type Not Found - RSA mode %d is not supported.",mode);
        return ACVP_INVALID_ARG;
    }

    return result;
}

/*
 * The user should call this after invoking acvp_enable_rsa_cap_parm().
 */
ACVP_RESULT acvp_enable_rsa_cap_sig_type_parm (ACVP_CTX *ctx,
                             ACVP_CIPHER cipher,
                             ACVP_RSA_MODE mode,
                             ACVP_RSA_SIG_TYPE sig_type,
                             int mod,
                             char *hash
                             )
{
    ACVP_RSA_CAP_MODE_LIST      *rsa_cap_mode_list;
    ACVP_CAPS_LIST              *cap_list;

    /*
     * Validate input
     */
    if (!ctx) {
        return ACVP_INVALID_ARG;
    }

    switch (cipher) {
    case ACVP_RSA:
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     * if the mode does not exist yet then create it.
     */
    if (!cap_list->cap.rsa_cap) {
        ACVP_LOG_ERR("RSA Cap entry not found.");
        return ACVP_NO_CAP;
    }
    rsa_cap_mode_list = acvp_locate_rsa_sig_type_entry(ctx, cap_list, mode, sig_type);
    if (!rsa_cap_mode_list) {
        return ACVP_INVALID_ARG;
    }
    // TODO CHECK PARAMS BEFORE DOING ALL THIS LOOKUP
    int found = 0;
    ACVP_RSA_CAP_SIG_TYPE *current_cap_sig_type = NULL;
    if(mode==ACVP_RSA_MODE_SIGGEN)
    {
        if(!rsa_cap_mode_list->cap_mode_attrs.siggen->cap_sig_type) {
          rsa_cap_mode_list->cap_mode_attrs.siggen->cap_sig_type = calloc(1, sizeof(ACVP_RSA_CAP_SIG_TYPE));
          if(!rsa_cap_mode_list->cap_mode_attrs.siggen->cap_sig_type) {
              ACVP_LOG_ERR("Malloc Failed -- RSA SigGen cap sig type entry");
              return ACVP_MALLOC_FAIL;
          }
          rsa_cap_mode_list->cap_mode_attrs.siggen->cap_sig_type->mod_rsa_sig = mod;
          current_cap_sig_type = rsa_cap_mode_list->cap_mode_attrs.siggen->cap_sig_type;

        } else {
            current_cap_sig_type = rsa_cap_mode_list->cap_mode_attrs.siggen->cap_sig_type;

            int found = 0;
            do {
                if(current_cap_sig_type->mod_rsa_sig != mod) {
                    if(current_cap_sig_type->next == NULL) {
                        current_cap_sig_type->next = calloc(1, sizeof(ACVP_RSA_CAP_SIG_TYPE));
                        if(!current_cap_sig_type->next) {
                            ACVP_LOG_ERR("Malloc Failed -- RSA SigGen cap sig type entry");
                            return ACVP_MALLOC_FAIL;
                        }
                        current_cap_sig_type = current_cap_sig_type->next;
                        current_cap_sig_type->mod_rsa_sig = mod;
                        found = 1;
                    } else {
                        current_cap_sig_type = current_cap_sig_type->next;
                    }
                } else {
                    found = 1;
                }
            } while (!found);
        }

        ACVP_NAME_LIST *current_hash = NULL;
        if(!current_cap_sig_type->compatible_hashes_sig) {
            current_cap_sig_type->compatible_hashes_sig = calloc(1, sizeof(ACVP_NAME_LIST));
            if(!current_cap_sig_type->compatible_hashes_sig) {
                ACVP_LOG_ERR("Malloc Failed -- RSA SigGen compatible hashes entry");
                return ACVP_MALLOC_FAIL;
            }
            current_cap_sig_type->compatible_hashes_sig->name = hash;
        } else {
            current_hash = current_cap_sig_type->compatible_hashes_sig;
            while(current_hash->next != NULL) {
                current_hash = current_hash->next;
            }
            current_hash->next = calloc(1, sizeof(ACVP_NAME_LIST));
            if(!current_hash->next) {
                ACVP_LOG_ERR("Malloc Failed -- RSA SigGen compatible hashes entry");
                return ACVP_MALLOC_FAIL;
            }
            current_hash->next->name = hash;
        }
    }
    else if (mode == ACVP_RSA_MODE_SIGVER)
    {
        if(!rsa_cap_mode_list->cap_mode_attrs.sigver->cap_sig_type) {
              rsa_cap_mode_list->cap_mode_attrs.sigver->cap_sig_type = calloc(1, sizeof(ACVP_RSA_CAP_SIG_TYPE));
              if(!rsa_cap_mode_list->cap_mode_attrs.sigver->cap_sig_type) {
                  ACVP_LOG_ERR("Malloc Failed -- RSA SigVer cap sig type entry");
                  return ACVP_MALLOC_FAIL;
              }
              rsa_cap_mode_list->cap_mode_attrs.sigver->cap_sig_type->mod_rsa_sig = mod;
              current_cap_sig_type = rsa_cap_mode_list->cap_mode_attrs.sigver->cap_sig_type;

            } else {
                current_cap_sig_type = rsa_cap_mode_list->cap_mode_attrs.sigver->cap_sig_type;

                int found = 0;
                do {
                    if(current_cap_sig_type->mod_rsa_sig != mod) {
                        if(current_cap_sig_type->next == NULL) {
                            current_cap_sig_type->next = calloc(1, sizeof(ACVP_RSA_CAP_SIG_TYPE));
                            if(!current_cap_sig_type->next) {
                                ACVP_LOG_ERR("Malloc Failed -- RSA SigVer cap sig type entry");
                                return ACVP_MALLOC_FAIL;
                            }
                            current_cap_sig_type = current_cap_sig_type->next;
                            current_cap_sig_type->mod_rsa_sig = mod;
                            found = 1;
                        } else {
                            current_cap_sig_type = current_cap_sig_type->next;
                        }
                    } else {
                        found = 1;
                    }
                } while (!found);
            }

            ACVP_NAME_LIST *current_hash = NULL;
            if(!current_cap_sig_type->compatible_hashes_sig) {
                current_cap_sig_type->compatible_hashes_sig = calloc(1, sizeof(ACVP_NAME_LIST));
                if(!current_cap_sig_type->compatible_hashes_sig) {
                    ACVP_LOG_ERR("Malloc Failed -- RSA SigVer compatible hashes entry");
                    return ACVP_MALLOC_FAIL;
                }
                current_cap_sig_type->compatible_hashes_sig->name = hash;
            } else {
                current_hash = current_cap_sig_type->compatible_hashes_sig;
                while(current_hash->next != NULL) {
                    current_hash = current_hash->next;
                }
                current_hash->next = calloc(1, sizeof(ACVP_NAME_LIST));
                if(!current_hash->next) {
                    ACVP_LOG_ERR("Malloc Failed -- RSA SigVer compatible hashes entry");
                    return ACVP_MALLOC_FAIL;
                }
                current_hash->next->name = hash;
            }
    }
    else
    {
        return (ACVP_INVALID_ARG);
    }
    return (ACVP_SUCCESS);
}

/*
 * The user should call this after invoking acvp_enable_rsa_cap_parm().
 */
ACVP_RESULT acvp_enable_rsa_cap_sig_type_salt_parm (ACVP_CTX *ctx,
                             ACVP_CIPHER cipher,
                             ACVP_RSA_MODE mode,
                             ACVP_RSA_SIG_TYPE sig_type,
                             int mod,
                             char *hash,
							 int salt
                             )
{
    ACVP_RSA_CAP_MODE_LIST      *rsa_cap_mode_list;
    ACVP_CAPS_LIST              *cap_list;

    /*
     * Validate input
     */
    if (!ctx) {
        return ACVP_INVALID_ARG;
    }

    switch (cipher) {
    case ACVP_RSA:
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     * if the mode does not exist yet then create it.
     */
    if (!cap_list->cap.rsa_cap) {
        ACVP_LOG_ERR("RSA Cap entry not found.");
        return ACVP_NO_CAP;
    }
    rsa_cap_mode_list = acvp_locate_rsa_sig_type_entry(ctx, cap_list, mode, sig_type);
    if (!rsa_cap_mode_list) {
        return ACVP_INVALID_ARG;
    }

    // TODO CHECK PARAMS BEFORE DOING ALL THIS LOOKUP
    int found = 0;
    ACVP_RSA_CAP_SIG_TYPE *current_cap_sig_type = NULL;
    if (mode == ACVP_RSA_MODE_SIGGEN) {
        if (!rsa_cap_mode_list->cap_mode_attrs.siggen->cap_sig_type) {
            rsa_cap_mode_list->cap_mode_attrs.siggen->cap_sig_type = calloc(1,
                    sizeof(ACVP_RSA_CAP_SIG_TYPE));
            if (!rsa_cap_mode_list->cap_mode_attrs.siggen->cap_sig_type) {
                ACVP_LOG_ERR("Malloc Failed -- RSA SigGen cap sig type entry");
                return ACVP_MALLOC_FAIL;
            }
            rsa_cap_mode_list->cap_mode_attrs.siggen->cap_sig_type->mod_rsa_sig =
                    mod;
            current_cap_sig_type =
                    rsa_cap_mode_list->cap_mode_attrs.siggen->cap_sig_type;

        } else {
            current_cap_sig_type =
                    rsa_cap_mode_list->cap_mode_attrs.siggen->cap_sig_type;

            int found = 0;
            do {
                if (current_cap_sig_type->mod_rsa_sig != mod) {
                    if (current_cap_sig_type->next == NULL) {
                        current_cap_sig_type->next = calloc(1,
                                sizeof(ACVP_RSA_CAP_SIG_TYPE));
                        if (!current_cap_sig_type->next) {
                            ACVP_LOG_ERR(
                                    "Malloc Failed -- RSA SigGen cap sig type entry");
                            return ACVP_MALLOC_FAIL;
                        }
                        current_cap_sig_type = current_cap_sig_type->next;
                        current_cap_sig_type->mod_rsa_sig = mod;
                        found = 1;
                    } else {
                        current_cap_sig_type = current_cap_sig_type->next;
                    }
                } else {
                    found = 1;
                }
            } while (!found);
        }

        ACVP_NAME_LIST *current_hash = NULL;
        if (!current_cap_sig_type->compatible_hashes_sig) {
            current_cap_sig_type->compatible_hashes_sig = calloc(1,
                    sizeof(ACVP_NAME_LIST));
            if (!current_cap_sig_type->compatible_hashes_sig) {
                ACVP_LOG_ERR("Malloc Failed -- RSA SigGen compatible hashes entry");
                return ACVP_MALLOC_FAIL;
            }
            current_cap_sig_type->compatible_hashes_sig->name = hash;
        } else {
            current_hash = current_cap_sig_type->compatible_hashes_sig;
            while (current_hash->next != NULL) {
                current_hash = current_hash->next;
            }
            current_hash->next = calloc(1, sizeof(ACVP_NAME_LIST));
            if (!current_hash->next) {
                ACVP_LOG_ERR("Malloc Failed -- RSA SigGen compatible hashes entry");
                return ACVP_MALLOC_FAIL;
            }
            current_hash->next->name = hash;
        }

        // checks that sigType is "PKCS1PSS" before creating salt array
        // this check should be unnecessary, since this function should only be called when sigType is "PKCS1PSS"
        if (strncmp(rsa_cap_mode_list->cap_mode_attrs.siggen->sig_type,
                RSA_SIG_TYPE_PKCS1PSS_NAME, RSA_SIG_TYPE_MAX_LEN) == 0) {
            ACVP_SALT_SIZES *current_salt = NULL;
            if (!current_cap_sig_type->salt_sig) {
                current_cap_sig_type->salt_sig = calloc(1,
                        sizeof(ACVP_SALT_SIZES));
                if (!current_cap_sig_type->salt_sig) {
                    ACVP_LOG_ERR("Malloc Failed -- RSA SigGen salt size entry");
                    return ACVP_MALLOC_FAIL;
                }
                current_cap_sig_type->salt_sig->saltVal = salt;
            } else {
                current_salt = current_cap_sig_type->salt_sig;
                while (current_salt->next != NULL) {
                    current_salt = current_salt->next;
                }
                current_salt->next = calloc(1, sizeof(ACVP_SALT_SIZES));
                if (!current_salt->next) {
                    ACVP_LOG_ERR("Malloc Failed -- RSA SigGen salt size entry");
                    return ACVP_MALLOC_FAIL;
                }
                current_salt->next->saltVal = salt;
            }
        }
    } else if (mode == ACVP_RSA_MODE_SIGVER) {
        if (!rsa_cap_mode_list->cap_mode_attrs.sigver->cap_sig_type) {
                    rsa_cap_mode_list->cap_mode_attrs.sigver->cap_sig_type = calloc(1,
                            sizeof(ACVP_RSA_CAP_SIG_TYPE));
                    if (!rsa_cap_mode_list->cap_mode_attrs.sigver->cap_sig_type) {
                        ACVP_LOG_ERR("Malloc Failed -- RSA SigVer cap sig type entry");
                        return ACVP_MALLOC_FAIL;
                    }
                    rsa_cap_mode_list->cap_mode_attrs.siggen->cap_sig_type->mod_rsa_sig =
                            mod;
                    current_cap_sig_type =
                            rsa_cap_mode_list->cap_mode_attrs.sigver->cap_sig_type;

                } else {
                    current_cap_sig_type =
                            rsa_cap_mode_list->cap_mode_attrs.sigver->cap_sig_type;

                    int found = 0;
                    do {
                        if (current_cap_sig_type->mod_rsa_sig != mod) {
                            if (current_cap_sig_type->next == NULL) {
                                current_cap_sig_type->next = calloc(1,
                                        sizeof(ACVP_RSA_CAP_SIG_TYPE));
                                if (!current_cap_sig_type->next) {
                                    ACVP_LOG_ERR(
                                            "Malloc Failed -- RSA SigVer cap sig type entry");
                                    return ACVP_MALLOC_FAIL;
                                }
                                current_cap_sig_type = current_cap_sig_type->next;
                                current_cap_sig_type->mod_rsa_sig = mod;
                                found = 1;
                            } else {
                                current_cap_sig_type = current_cap_sig_type->next;
                            }
                        } else {
                            found = 1;
                        }
                    } while (!found);
                }

                ACVP_NAME_LIST *current_hash = NULL;
                if (!current_cap_sig_type->compatible_hashes_sig) {
                    current_cap_sig_type->compatible_hashes_sig = calloc(1,
                            sizeof(ACVP_NAME_LIST));
                    if (!current_cap_sig_type->compatible_hashes_sig) {
                        ACVP_LOG_ERR("Malloc Failed -- RSA SigVer compatible hashes entry");
                        return ACVP_MALLOC_FAIL;
                    }
                    current_cap_sig_type->compatible_hashes_sig->name = hash;
                } else {
                    current_hash = current_cap_sig_type->compatible_hashes_sig;
                    while (current_hash->next != NULL) {
                        current_hash = current_hash->next;
                    }
                    current_hash->next = calloc(1, sizeof(ACVP_NAME_LIST));
                    if (!current_hash->next) {
                        ACVP_LOG_ERR("Malloc Failed -- RSA SigVer compatible hashes entry");
                        return ACVP_MALLOC_FAIL;
                    }
                    current_hash->next->name = hash;
                }

                // checks that sigType is "PKCS1PSS" before creating salt array
                // this check should be unnecessary, since this function should only be called when sigType is "PKCS1PSS"
                if (strncmp(rsa_cap_mode_list->cap_mode_attrs.sigver->sig_type,
                        RSA_SIG_TYPE_PKCS1PSS_NAME, RSA_SIG_TYPE_MAX_LEN) == 0) {
                    ACVP_SALT_SIZES *current_salt = NULL;
                    if (!current_cap_sig_type->salt_sig) {
                        current_cap_sig_type->salt_sig = calloc(1,
                                sizeof(ACVP_SALT_SIZES));
                        if (!current_cap_sig_type->salt_sig) {
                            ACVP_LOG_ERR("Malloc Failed -- RSA SigVer salt size entry");
                            return ACVP_MALLOC_FAIL;
                        }
                        current_cap_sig_type->salt_sig->saltVal = salt;
                    } else {
                        current_salt = current_cap_sig_type->salt_sig;
                        while (current_salt->next != NULL) {
                            current_salt = current_salt->next;
                        }
                        current_salt->next = calloc(1, sizeof(ACVP_SALT_SIZES));
                        if (!current_salt->next) {
                            ACVP_LOG_ERR("Malloc Failed -- RSA SigVer salt size entry");
                            return ACVP_MALLOC_FAIL;
                        }
                        current_salt->next->saltVal = salt;
                    }
                }
    } else {
        return (ACVP_INVALID_ARG);
    }
    return (ACVP_SUCCESS);
}

/*
 * The user should call this after invoking acvp_enable_rsa_cap_parm().
 */
ACVP_RESULT acvp_enable_rsa_bignum_parm (ACVP_CTX *ctx,
                             ACVP_CIPHER cipher,
                             ACVP_RSA_MODE mode,
                             ACVP_RSA_PARM param,
                             BIGNUM *value
                             )
{
    ACVP_RSA_CAP_MODE_LIST      *rsa_cap_mode_list;
    ACVP_CAPS_LIST              *cap_list;
    ACVP_RESULT                 result;

    result = acvp_rsa_prepare_to_add_param(ctx, cipher, mode, &cap_list,
                                           &rsa_cap_mode_list);
    if(result != ACVP_SUCCESS) return result;

    /*
     * Add the value to the cap
     */
    switch (mode) {
    case ACVP_RSA_MODE_KEYGEN:
        switch(param) {
        case ACVP_FIXED_PUB_EXP_VAL:
            if (rsa_cap_mode_list->cap_mode_attrs.keygen->pub_exp == RSA_PUB_EXP_FIXED)
                rsa_cap_mode_list->cap_mode_attrs.keygen->fixed_pub_exp_val = value;
            break;
        default:
            return ACVP_INVALID_ARG;
            break;
        }
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}

/*
 * The user should call this after invoking acvp_enable_rsa_cap_parm()
 * and setting the randPQ value.
 */
ACVP_RESULT acvp_enable_rsa_primes_parm (ACVP_CTX *ctx,
                             ACVP_CIPHER cipher,
                             ACVP_RSA_MODE mode,
                             ACVP_RSA_PARM param,
                             int mod,
                             char *name
                             )
{
    ACVP_RSA_CAP_MODE_LIST      *rsa_cap_mode_list;
    ACVP_CAPS_LIST              *cap_list;
    ACVP_RESULT                 result;
    int found;

    result = acvp_rsa_prepare_to_add_param(ctx, cipher, mode, &cap_list,
                                           &rsa_cap_mode_list);
    if (result != ACVP_SUCCESS) return result;

    result = acvp_validate_rsa_primes_parm(param, mod, name, rsa_cap_mode_list);
    if (result != ACVP_SUCCESS) {
        ACVP_LOG_ERR("RSA primes param validation failed, invalid values");
        return result;
    }

    ACVP_RSA_PRIMES_LIST *current_prime = NULL;
    if(!rsa_cap_mode_list->cap_mode_attrs.keygen->cap_primes_list) {
      rsa_cap_mode_list->cap_mode_attrs.keygen->cap_primes_list = calloc(1, sizeof(ACVP_RSA_PRIMES_LIST));
      if(!rsa_cap_mode_list->cap_mode_attrs.keygen->cap_primes_list) {
          ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
          return ACVP_MALLOC_FAIL;
      }
      rsa_cap_mode_list->cap_mode_attrs.keygen->cap_primes_list->modulo = mod;
      current_prime = rsa_cap_mode_list->cap_mode_attrs.keygen->cap_primes_list;

    } else {
        current_prime = rsa_cap_mode_list->cap_mode_attrs.keygen->cap_primes_list;

        found = 0;
        do {
            if(current_prime->modulo != mod) {
                if(current_prime->next == NULL) {
                    current_prime->next = calloc(1, sizeof(ACVP_RSA_PRIMES_LIST));
                    if(!current_prime->next) {
                        ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                        return ACVP_MALLOC_FAIL;
                    }
                    current_prime = current_prime->next;
                    current_prime->modulo = mod;
                    found = 1;
                } else {
                    current_prime = current_prime->next;
                }
            } else {
                found = 1;
            }
        } while (!found);
    }

    if (param == ACVP_CAPS_PROV_PRIME || param == ACVP_CAPS_PROV_PROB_PRIME) {
        ACVP_NAME_LIST *current_hash = NULL;
        if(!current_prime->hash_algs) {
            current_prime->hash_algs = calloc(1, sizeof(ACVP_NAME_LIST));
            if(!current_prime->hash_algs) {
                ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                return ACVP_MALLOC_FAIL;
            }
            current_prime->hash_algs->name = name;
        } else {
            current_hash = current_prime->hash_algs;
            while(current_hash->next != NULL) {
                current_hash = current_hash->next;
            }
            current_hash->next = calloc(1, sizeof(ACVP_NAME_LIST));
            if(!current_hash->next) {
                ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                return ACVP_MALLOC_FAIL;
            }
            current_hash->next->name = name;
        }
    }

    if (param == ACVP_CAPS_PROB_PRIME || param == ACVP_CAPS_PROV_PROB_PRIME) {
        ACVP_NAME_LIST *current_prime_test = NULL;
        if(!current_prime->prime_tests) {
            current_prime->prime_tests = calloc(1, sizeof(ACVP_NAME_LIST));
            if(!current_prime->prime_tests) {
                ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                return ACVP_MALLOC_FAIL;
            }
            current_prime->prime_tests->name = name;
        } else {
            current_prime_test = current_prime->prime_tests;
            while(current_prime_test->next != NULL) {
                current_prime_test = current_prime_test->next;
            }
            current_prime_test->next = calloc(1, sizeof(ACVP_NAME_LIST));
            if(!current_prime_test->next) {
                ACVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                return ACVP_MALLOC_FAIL;
            }
            current_prime_test->next->name = name;
        }
    }

    return (ACVP_SUCCESS);
}

/*
 * Add DRBG Length Range
 */
static ACVP_RESULT acvp_add_drbg_length_range (
                             ACVP_DRBG_CAP_MODE  *drbg_cap_mode,
                             ACVP_DRBG_PARM       param,
                             int                  min,
                             int                  step,
                             int                  max
                             )
{
    if (!drbg_cap_mode) {
        return ACVP_INVALID_ARG;
    }

    switch (param) {
    case ACVP_DRBG_ENTROPY_LEN:
        drbg_cap_mode->entropy_len_min  = min;
        drbg_cap_mode->entropy_len_step = step;
        drbg_cap_mode->entropy_len_max  = max;
        break;
    case ACVP_DRBG_NONCE_LEN:
        drbg_cap_mode->nonce_len_min  = min;
        drbg_cap_mode->nonce_len_step = step;
        drbg_cap_mode->nonce_len_max  = max;
        break;
    case ACVP_DRBG_PERSO_LEN:
        drbg_cap_mode->perso_len_min  = min;
        drbg_cap_mode->perso_len_step = step;
        drbg_cap_mode->perso_len_max  = max;
        break;
    case ACVP_DRBG_ADD_IN_LEN:
        drbg_cap_mode->additional_in_len_min = min;
        drbg_cap_mode->additional_in_len_step = step;
        drbg_cap_mode->additional_in_len_max = max;
        break;
    case ACVP_DRBG_RET_BITS_LEN:
    case ACVP_DRBG_PRE_REQ_VALS:
    case ACVP_DRBG_DER_FUNC_ENABLED:
    case ACVP_DRBG_PRED_RESIST_ENABLED:
    case ACVP_DRBG_RESEED_ENABLED:
    default:
        return ACVP_INVALID_ARG;
        break;
    }

    return ACVP_SUCCESS;
}



/*
 * The user should call this after invoking acvp_enable_drbg_cap_parm().
 */
ACVP_RESULT acvp_enable_drbg_cap_parm (ACVP_CTX *ctx,
                             ACVP_CIPHER cipher,
                             ACVP_DRBG_MODE mode,
                             ACVP_DRBG_PARM param,
                             int value
                             )
{
    ACVP_DRBG_CAP_MODE_LIST *drbg_cap_mode_list;
    ACVP_CAPS_LIST          *cap_list;
    ACVP_RESULT              result;

    /*
     * Validate input
     */
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    switch (cipher) {
    case ACVP_HASHDRBG:
    case ACVP_HMACDRBG:
    case ACVP_CTRDRBG:
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     * if the mode does not exist yet then create it.
     */
    if (!cap_list->cap.drbg_cap) {
        ACVP_LOG_ERR("DRBG Cap entry not found.");
        return ACVP_NO_CAP;
    }

    drbg_cap_mode_list = acvp_locate_drbg_mode_entry(cap_list, mode);
    if (!drbg_cap_mode_list) {
        drbg_cap_mode_list = calloc(1, sizeof(ACVP_DRBG_CAP_MODE_LIST));
        if (!drbg_cap_mode_list) {
            ACVP_LOG_ERR("Malloc Failed.");
            return ACVP_MALLOC_FAIL;
        }

        drbg_cap_mode_list->cap_mode.mode = mode;
        cap_list->cap.drbg_cap->drbg_cap_mode_list = drbg_cap_mode_list;
    }

    /*
     * Add the value to the cap
     */
    switch (cipher) {
    case ACVP_HASHDRBG:
        result = acvp_add_hash_drbg_cap_parm(&drbg_cap_mode_list->cap_mode, mode, param, value);
        break;
    case ACVP_HMACDRBG:
        result = acvp_add_hmac_drbg_cap_parm(&drbg_cap_mode_list->cap_mode, mode, param, value);
        break;
    case ACVP_CTRDRBG:
        result = acvp_add_ctr_drbg_cap_parm(&drbg_cap_mode_list->cap_mode, mode, param, value);
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    return (result);
}

ACVP_RESULT acvp_enable_drbg_prereq_cap(ACVP_CTX          *ctx,
                             ACVP_CIPHER       cipher,
                             ACVP_DRBG_MODE    mode,
                             ACVP_PREREQ_ALG pre_req,
                             char              *value)
{
    ACVP_DRBG_CAP_MODE_LIST *drbg_cap_mode_list;
    ACVP_CAPS_LIST          *cap_list;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     * if the mode does not exist yet then create it.
     */
    drbg_cap_mode_list = acvp_locate_drbg_mode_entry(cap_list, mode);
    if (!drbg_cap_mode_list) {
        drbg_cap_mode_list = calloc(1, sizeof(ACVP_DRBG_CAP_MODE_LIST));
        if (!drbg_cap_mode_list) {
            ACVP_LOG_ERR("Malloc Failed.");
            return ACVP_MALLOC_FAIL;
        }
        drbg_cap_mode_list->cap_mode.mode = mode;
        cap_list->cap.drbg_cap->drbg_cap_mode_list = drbg_cap_mode_list;
    }

    /*
     * Add the value to the cap
     */
    return (acvp_add_drbg_prereq_val(&drbg_cap_mode_list->cap_mode, mode, pre_req, value));
}

ACVP_RESULT acvp_enable_drbg_length_cap(ACVP_CTX            *ctx,
                                        ACVP_CIPHER          cipher,
                                        ACVP_DRBG_MODE       mode,
                                        ACVP_DRBG_PARM       param,
                                        int                  min,
                                        int                  step,
                                        int                  max)
{
    ACVP_DRBG_CAP_MODE_LIST *drbg_cap_mode_list;
    ACVP_CAPS_LIST          *cap_list;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     * if the mode does not exist yet then create it.
     */
    drbg_cap_mode_list = acvp_locate_drbg_mode_entry(cap_list, mode);
    if (!drbg_cap_mode_list) {
        drbg_cap_mode_list = calloc(1, sizeof(ACVP_DRBG_CAP_MODE_LIST));
        if (!drbg_cap_mode_list) {
            ACVP_LOG_ERR("Malloc Failed.");
            return ACVP_MALLOC_FAIL;
        }
        drbg_cap_mode_list->cap_mode.mode = mode;
        cap_list->cap.drbg_cap->drbg_cap_mode_list = drbg_cap_mode_list;
    }

    /*
     * Add the length range to the cap
     */
    return(acvp_add_drbg_length_range(&drbg_cap_mode_list->cap_mode,
           param, min, step, max));
}

ACVP_RESULT acvp_enable_drbg_cap(
     ACVP_CTX *ctx,
     ACVP_CIPHER cipher,
     ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_DRBG_CAP *drbg_cap;
    ACVP_RESULT result;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }

    //Check for duplicate entry
    if (acvp_locate_cap_entry(ctx, cipher)) {
        return ACVP_DUP_CIPHER;
    }

    drbg_cap = calloc(1, sizeof(ACVP_DRBG_CAP));
    if (!drbg_cap) {
        return ACVP_MALLOC_FAIL;
    }

    drbg_cap->cipher = cipher;
    result = acvp_append_drbg_caps_entry(ctx, drbg_cap, cipher, crypto_handler);
    if (result != ACVP_SUCCESS) {
        free(drbg_cap);
        drbg_cap = NULL;
    }
    return result;
}

ACVP_RESULT acvp_enable_rsa_cap(
     ACVP_CTX *ctx,
     ACVP_CIPHER cipher,
     ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_RSA_CAP *rsa_cap;
    ACVP_RESULT result;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }

    /*
     * Check for duplicate entry
     */
    if (acvp_locate_cap_entry(ctx, cipher)) {
        return ACVP_DUP_CIPHER;
    }

    rsa_cap = calloc(1, sizeof(ACVP_RSA_CAP));
    if (!rsa_cap) {
        return ACVP_MALLOC_FAIL;
    }

    result = acvp_append_rsa_caps_entry(ctx, rsa_cap, cipher, crypto_handler);
    if (result != ACVP_SUCCESS) {
        free(rsa_cap);
        rsa_cap = NULL;
    }
    return result;
}

/*
 * Allows application to specify the vendor attributes for
 * the test session.
 */
ACVP_RESULT acvp_set_vendor_info(ACVP_CTX *ctx,
				 const char *vendor_name,
				 const char *vendor_url,
				 const char *contact_name,
				 const char *contact_email)
{
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (ctx->vendor_name) free (ctx->vendor_name);
    if (ctx->vendor_url) free (ctx->vendor_url);
    if (ctx->contact_name) free (ctx->contact_name);
    if (ctx->contact_email) free (ctx->contact_email);

    ctx->vendor_name = strdup(vendor_name);
    ctx->vendor_url = strdup(vendor_url);
    ctx->contact_name = strdup(contact_name);
    ctx->contact_email = strdup(contact_email);

    return ACVP_SUCCESS;
}

/*
 * Allows application to specify the crypto module attributes for
 * the test session.
 */
ACVP_RESULT acvp_set_module_info(ACVP_CTX *ctx,
				 const char *module_name,
				 const char *module_type,
				 const char *module_version,
				 const char *module_description)
{
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (ctx->module_name) free (ctx->module_name);
    if (ctx->module_type) free (ctx->module_type);
    if (ctx->module_version) free (ctx->module_version);
    if (ctx->module_desc) free (ctx->module_desc);

    ctx->module_name = strdup(module_name);
    ctx->module_type = strdup(module_type);
    ctx->module_version = strdup(module_version);
    ctx->module_desc = strdup(module_description);

    return ACVP_SUCCESS;
}

/*
 * This function is used by the application to specify the
 * ACVP server address and TCP port#.
 */
ACVP_RESULT acvp_set_server(ACVP_CTX *ctx, char *server_name, int port)
{
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (ctx->server_name) free (ctx->server_name);
    ctx->server_name = strdup(server_name);
    ctx->server_port = port;

    return ACVP_SUCCESS;
}

/*
 * This function is used by the application to specify the
 * ACVP server URI path segment prefix.
 */
ACVP_RESULT acvp_set_path_segment(ACVP_CTX *ctx, char *path_segment)
{
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!path_segment) {
        return ACVP_INVALID_ARG;
    }
    if (ctx->path_segment) free (ctx->path_segment);
    ctx->path_segment = strdup(path_segment);

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
ACVP_RESULT acvp_set_cacerts(ACVP_CTX *ctx, char *ca_file)
{
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (ctx->cacerts_file) free (ctx->cacerts_file);
    ctx->cacerts_file = strdup(ca_file);

    /*
     * Enable peer verification when CA certs are provided.
     */
    ctx->verify_peer = 1;

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
ACVP_RESULT acvp_set_certkey(ACVP_CTX *ctx, char *cert_file, char *key_file)
{
    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (ctx->tls_cert) free (ctx->tls_cert);
    ctx->tls_cert = strdup(cert_file);
    if (ctx->tls_key) free (ctx->tls_key);
    ctx->tls_key = strdup(key_file);

    return ACVP_SUCCESS;
}


static ACVP_RESULT acvp_lookup_prereqVals (JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry)
{
    JSON_Array *prereq_array = NULL;
    ACVP_PREREQ_LIST *prereq_vals, *next_pre_req;
    ACVP_PREREQ_ALG_VAL *pre_req;
    char *alg_str;
    int i = 0;

    if(!cap_entry) return ACVP_INVALID_ARG;

    if (!cap_entry->has_prereq) return ACVP_SUCCESS;
    /*
     * Init json array
     */
    json_object_set_value(cap_obj, "prereqVals", json_value_init_array());
    prereq_array = json_object_get_array(cap_obj, "prereqVals");

    /*
     * return OK if nothing present
     */
     prereq_vals = cap_entry->prereq_vals;

     while (prereq_vals) {
        JSON_Value *val = NULL;
        JSON_Object *obj = NULL;
        val = json_value_init_object();
        obj = json_value_get_object(val);
        pre_req = &prereq_vals->prereq_alg_val;

        for (i = 0; i < ACVP_NUM_PREREQS; i++) {
            if (acvp_prereqs_tbl[i].alg == pre_req->alg) {
                alg_str = acvp_prereqs_tbl[i].name;
                json_object_set_string(obj, "algorithm", alg_str);
                json_object_set_string(obj, "value", pre_req->val);
                break;
            }
        }

        json_array_append_value(prereq_array, val);
        next_pre_req = prereq_vals->next;
        prereq_vals = next_pre_req;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_hash_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry)
{
    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
    json_object_set_boolean(cap_obj, "inBit", cap_entry->cap.hash_cap->in_bit);
    json_object_set_boolean(cap_obj, "inEmpty", cap_entry->cap.hash_cap->in_empty);

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_hmac_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry)
{
    JSON_Array *temp_arr = NULL;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    ACVP_SL_LIST *sl_list;
    ACVP_RESULT result;

    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) return result;

    json_object_set_value(cap_obj, "keyLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "keyLen");

    val = json_value_init_object();
    obj = json_value_get_object(val);

    json_object_set_number(obj, "min", cap_entry->cap.hmac_cap->key_len_min);
    json_object_set_number(obj, "max", cap_entry->cap.hmac_cap->key_len_max);
    json_object_set_number(obj, "increment", 8);

    json_array_append_value(temp_arr, val);
    /*
     * Set the supported mac lengths
     */
    json_object_set_value(cap_obj, "macLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "macLen");
    sl_list = cap_entry->cap.hmac_cap->mac_len;
    while (sl_list) {
      json_array_append_number(temp_arr, sl_list->length);
      sl_list = sl_list->next;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_cmac_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry)
{
    JSON_Array *temp_arr = NULL;
    ACVP_SL_LIST *sl_list;
    int i;
    ACVP_RESULT result;

    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if(result != ACVP_SUCCESS) return result;

    json_object_set_value(cap_obj, "direction", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "direction");
    if (cap_entry->cap.cmac_cap->direction_gen) json_array_append_string(temp_arr, "gen");
    if (cap_entry->cap.cmac_cap->direction_ver) json_array_append_string(temp_arr, "ver");

    json_object_set_value(cap_obj, "msgLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "msgLen");
    for (i = 0; i < CMAC_MSG_LEN_NUM_ITEMS; i++) {
      json_array_append_number(temp_arr, cap_entry->cap.cmac_cap->msg_len[i]);
    }

    /*
     * Set the supported mac lengths
     */
    json_object_set_value(cap_obj, "macLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "macLen");
    sl_list = cap_entry->cap.cmac_cap->mac_len;
    while (sl_list) {
      json_array_append_number(temp_arr, sl_list->length);
      sl_list = sl_list->next;
    }

    return ACVP_SUCCESS;
}


static ACVP_RESULT acvp_build_sym_cipher_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry)
{
    JSON_Array *mode_arr = NULL;
    JSON_Array *opts_arr = NULL;
    ACVP_SL_LIST *sl_list;
    ACVP_RESULT result;
    ACVP_SYM_CIPHER_CAP *sym_cap;

    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));

    sym_cap = cap_entry->cap.sym_cap;
    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) return result;

    /*
     * Set the direction capability
     */
    json_object_set_value(cap_obj, "direction", json_value_init_array());
    mode_arr = json_object_get_array(cap_obj, "direction");
    if (sym_cap->direction == ACVP_DIR_ENCRYPT ||
        sym_cap->direction == ACVP_DIR_BOTH) {
        json_array_append_string(mode_arr, "encrypt");
    }
    if (sym_cap->direction == ACVP_DIR_DECRYPT ||
        sym_cap->direction == ACVP_DIR_BOTH) {
        json_array_append_string(mode_arr, "decrypt");
    }

    /*
     * Set the IV generation source if applicable
     */
    switch(sym_cap->ivgen_source) {
    case ACVP_IVGEN_SRC_INT:
        json_object_set_string(cap_obj, "ivGen", "internal");
        break;
    case ACVP_IVGEN_SRC_EXT:
        json_object_set_string(cap_obj, "ivGen", "external");
        break;
    default:
        /* do nothing, this is an optional capability */
        break;
    }

    /*
     * Set the IV generation mode if applicable
     */
    switch(sym_cap->ivgen_mode) {
    case ACVP_IVGEN_MODE_821:
        json_object_set_string(cap_obj, "ivGenMode", "8.2.1");
        break;
    case ACVP_IVGEN_MODE_822:
        json_object_set_string(cap_obj, "ivGenMode", "8.2.2");
        break;
    default:
        /* do nothing, this is an optional capability */
        break;
    }

    /*
     * Set the TDES keyingOptions  if applicable
     */
    if (sym_cap->keying_option != ACVP_KO_NA) {
        json_object_set_value(cap_obj, "keyingOption", json_value_init_array());
      	opts_arr = json_object_get_array(cap_obj, "keyingOption");
        if (sym_cap->keying_option == ACVP_KO_THREE ||
            sym_cap->keying_option == ACVP_KO_BOTH) {
            json_array_append_number(opts_arr, 1);
        }
    	if (sym_cap->keying_option == ACVP_KO_TWO ||
            sym_cap->keying_option == ACVP_KO_BOTH) {
            json_array_append_number(opts_arr, 2);
        }
    }
    /*
     * Set the supported key lengths
     */
    json_object_set_value(cap_obj, "keyLen", json_value_init_array());
    opts_arr = json_object_get_array(cap_obj, "keyLen");
    sl_list = sym_cap->keylen;
    while (sl_list) {
        json_array_append_number(opts_arr, sl_list->length);
        sl_list = sl_list->next;
    }

    /*
     * Set the supported tag lengths (for AEAD ciphers)
     */
    if ((cap_entry->cipher == ACVP_AES_GCM) || (cap_entry->cipher == ACVP_AES_CCM)) {
        json_object_set_value(cap_obj, "tagLen", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "tagLen");
        sl_list = sym_cap->taglen;
        while (sl_list) {
           json_array_append_number(opts_arr, sl_list->length);
           sl_list = sl_list->next;
        }
    }

    /*
     * Set the supported IV lengths
     */
    switch (cap_entry->cipher)
    {
    case ACVP_TDES_ECB:
    case ACVP_TDES_CBC:
    case ACVP_TDES_CBCI:
    case ACVP_TDES_OFB:
    case ACVP_TDES_OFBI:
    case ACVP_TDES_CFB1:
    case ACVP_TDES_CFB8:
    case ACVP_TDES_CFB64:
    case ACVP_TDES_CFBP1:
    case ACVP_TDES_CFBP8:
    case ACVP_TDES_CFBP64:
    case ACVP_TDES_CTR:
    case ACVP_TDES_KW:
    case ACVP_AES_ECB:
    case ACVP_AES_CFB1:
    case ACVP_AES_CFB8:
    case ACVP_AES_CFB128:
    case ACVP_AES_OFB:
    case ACVP_AES_CBC:
    case ACVP_AES_KW:
    case ACVP_AES_CTR:
        break;
    default:
        json_object_set_value(cap_obj, "ivLen", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "ivLen");
        sl_list = sym_cap->ivlen;
        while (sl_list) {
            json_array_append_number(opts_arr, sl_list->length);
            sl_list = sl_list->next;
        }
    }
    /*
     * Set the supported plaintext lengths
     */
    json_object_set_value(cap_obj, "ptLen", json_value_init_array());
    opts_arr = json_object_get_array(cap_obj, "ptLen");
    sl_list = sym_cap->ptlen;
    while (sl_list) {
        json_array_append_number(opts_arr, sl_list->length);
        sl_list = sl_list->next;
    }

    /*
     * Set the supported AAD lengths (for AEAD ciphers)
     */
    if ((cap_entry->cipher == ACVP_AES_GCM) || (cap_entry->cipher == ACVP_AES_CCM)) {
        json_object_set_value(cap_obj, "aadLen", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "aadLen");
        sl_list = sym_cap->aadlen;
        while (sl_list) {
            json_array_append_number(opts_arr, sl_list->length);
            sl_list = sl_list->next;
        }
    }
    return ACVP_SUCCESS;
}


static char *acvp_lookup_drbg_mode_string (ACVP_CAPS_LIST *cap_entry)
{
    char *mode_str = NULL;
    if(!cap_entry) return NULL;
    if(!cap_entry->cap.drbg_cap) return NULL;
    if(!cap_entry->cap.drbg_cap->drbg_cap_mode_list) return NULL;

    switch (cap_entry->cap.drbg_cap->drbg_cap_mode_list->cap_mode.mode) {
    case ACVP_DRBG_SHA_1:
        mode_str = ACVP_DRBG_MODE_SHA_1;
        break;
    case ACVP_DRBG_SHA_224:
        mode_str = ACVP_DRBG_MODE_SHA_224;
        break;
    case ACVP_DRBG_SHA_256:
        mode_str = ACVP_DRBG_MODE_SHA_256;
        break;
    case ACVP_DRBG_SHA_384:
        mode_str = ACVP_DRBG_MODE_SHA_384;
        break;
    case ACVP_DRBG_SHA_512:
        mode_str = ACVP_DRBG_MODE_SHA_512;
        break;
    case ACVP_DRBG_SHA_512_224:
        mode_str = ACVP_DRBG_MODE_SHA_512_224;
        break;
    case ACVP_DRBG_SHA_512_256:
        mode_str = ACVP_DRBG_MODE_SHA_512_256;
        break;
    case ACVP_DRBG_3KEYTDEA:
        mode_str = ACVP_DRBG_MODE_3KEYTDEA;
        break;
    case ACVP_DRBG_AES_128:
        mode_str = ACVP_DRBG_MODE_AES_128;
        break;
    case ACVP_DRBG_AES_192:
        mode_str = ACVP_DRBG_MODE_AES_192;
        break;
    case ACVP_DRBG_AES_256:
        mode_str = ACVP_DRBG_MODE_AES_256;
        break;
    default:
        return NULL;
    }
    return mode_str;
}

static ACVP_RESULT acvp_lookup_drbg_prereqVals (JSON_Object *cap_obj, ACVP_DRBG_CAP_MODE *drbg_cap_mode)
{
    JSON_Array *prereq_array = NULL;
    ACVP_PREREQ_LIST *prereq_vals, *next_pre_req;
    ACVP_PREREQ_ALG_VAL *pre_req;
    char *alg_str;
    int i;

    if(!drbg_cap_mode) return ACVP_INVALID_ARG;

    /*
     * Init json array
     */
    json_object_set_value(cap_obj, "prereqVals", json_value_init_array());
    prereq_array = json_object_get_array(cap_obj, "prereqVals");

    /*
     * return OK if nothing present
     */
    prereq_vals = drbg_cap_mode->prereq_vals;
    if(!prereq_vals) {
        return ACVP_SUCCESS;
    }


    while (prereq_vals) {
        JSON_Value *val = NULL;
        JSON_Object *obj = NULL;
        val = json_value_init_object();
        obj = json_value_get_object(val);
        pre_req = &prereq_vals->prereq_alg_val;

        for (i = 0; i < ACVP_NUM_PREREQS; i++) {
            if (acvp_prereqs_tbl[i].alg == pre_req->alg) {
                alg_str = acvp_prereqs_tbl[i].name;
                json_object_set_string(obj, "algorithm", alg_str);
                json_object_set_string(obj, "value", pre_req->val);
                break;
            }
        }

        json_array_append_value(prereq_array, val);
        next_pre_req = prereq_vals->next;
        prereq_vals = next_pre_req;
    }
    return ACVP_SUCCESS;
}



static ACVP_RESULT acvp_build_drbg_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry)
{
    ACVP_RESULT result;
    ACVP_DRBG_CAP_MODE *drbg_cap_mode = NULL;
    JSON_Object *len_obj = NULL;
    JSON_Value  *len_val = NULL;

    char *mode_str = acvp_lookup_drbg_mode_string(cap_entry);
    if (!mode_str) return ACVP_INVALID_ARG;

    drbg_cap_mode = &cap_entry->cap.drbg_cap->drbg_cap_mode_list->cap_mode;
    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
    json_object_set_string(cap_obj, "mode", mode_str);
    json_object_set_boolean(cap_obj, "derFuncEnabled", drbg_cap_mode->der_func_enabled);

    result = acvp_lookup_drbg_prereqVals(cap_obj, drbg_cap_mode);
    if (result != ACVP_SUCCESS) return result;

    json_object_set_boolean(cap_obj, "predResistanceEnabled", drbg_cap_mode->pred_resist_enabled);
    json_object_set_boolean(cap_obj, "reseedImplemented",     drbg_cap_mode->reseed_implemented);

    //Set entropy range
    len_val = json_value_init_object();
    len_obj = json_value_get_object(len_val);
    json_object_set_number(len_obj, "max", drbg_cap_mode->entropy_len_max);
    json_object_set_number(len_obj, "min", drbg_cap_mode->entropy_len_min);
    json_object_set_number(len_obj, "step", drbg_cap_mode->entropy_len_step);
    json_object_set_value(cap_obj, "entropyInputRange", len_val);

    //Set nonce range
    len_val = json_value_init_object();
    len_obj = json_value_get_object(len_val);
    json_object_set_number(len_obj, "max", drbg_cap_mode->nonce_len_max);
    json_object_set_number(len_obj, "min", drbg_cap_mode->nonce_len_min);
    json_object_set_number(len_obj, "step", drbg_cap_mode->nonce_len_step);
    json_object_set_value(cap_obj, "nonceLenRange", len_val);

    //Set persoString range
    len_val = json_value_init_object();
    len_obj = json_value_get_object(len_val);
    json_object_set_number(len_obj, "max", drbg_cap_mode->perso_len_max);
    json_object_set_number(len_obj, "min", drbg_cap_mode->perso_len_min);
    json_object_set_number(len_obj, "step", drbg_cap_mode->perso_len_step);
    json_object_set_value(cap_obj, "persoStringLenRange", len_val);

    //Set additionalInputLen Range
    len_val = json_value_init_object();
    len_obj = json_value_get_object(len_val);
    json_object_set_number(len_obj, "max", drbg_cap_mode->additional_in_len_max);
    json_object_set_number(len_obj, "min", drbg_cap_mode->additional_in_len_min);
    json_object_set_number(len_obj, "step", drbg_cap_mode->additional_in_len_step);
    json_object_set_value(cap_obj, "additionalInputLenRange", len_val);

    //Set DRBG Length
    json_object_set_number(cap_obj, "returnedBitsLen", drbg_cap_mode->returned_bits_len);
    return ACVP_SUCCESS;
}

/*
 * Builds the JSON object for RSA keygen primes
 */
static ACVP_RESULT acvp_lookup_rsa_primes(JSON_Object *cap_obj, ACVP_RSA_CAP *rsa_cap)
{
    JSON_Array *primes_array = NULL, *hash_array = NULL, *prime_test_array = NULL;

    ACVP_RSA_PRIMES_LIST *primes, *next_prime;
    ACVP_NAME_LIST *comp_name, *next_name;

    if(!rsa_cap) return ACVP_INVALID_ARG;
    unsigned int rand_pq_val = rsa_cap->rsa_cap_mode_list->cap_mode_attrs.keygen->rand_pq;

    /*
     * Init json array
     */
    switch (rand_pq_val) {
        case RSA_RAND_PQ_B32:
        case RSA_RAND_PQ_B34:
            json_object_set_value(cap_obj, "capProvPrimes", json_value_init_array());
            primes_array = json_object_get_array(cap_obj, "capProvPrimes");
            break;
        case RSA_RAND_PQ_B33:
        case RSA_RAND_PQ_B36:
            json_object_set_value(cap_obj, "capProbPrime", json_value_init_array());
            primes_array = json_object_get_array(cap_obj, "capProbPrime");
            break;
        case RSA_RAND_PQ_B35:
            json_object_set_value(cap_obj, "capsProvProbPrimes", json_value_init_array());
            primes_array = json_object_get_array(cap_obj, "capsProvProbPrimes");
            break;
        default:
            break;
    }

    /*
     * return OK if nothing present
     */
    primes = rsa_cap->rsa_cap_mode_list->cap_mode_attrs.keygen->cap_primes_list;
    if(!rsa_cap->rsa_cap_mode_list->cap_mode_attrs.keygen->cap_primes_list) {
        return ACVP_SUCCESS;
    }

    while (primes) {
        JSON_Value *val = NULL;
        JSON_Object *obj = NULL;
        val = json_value_init_object();
        obj = json_value_get_object(val);

        json_object_set_number(obj, "modulo", primes->modulo);

        if (rand_pq_val == RSA_RAND_PQ_B32 ||
            rand_pq_val == RSA_RAND_PQ_B34 ||
            rand_pq_val == RSA_RAND_PQ_B35)
        {
            json_object_set_value(obj, "hashAlg", json_value_init_array());
            hash_array = json_object_get_array(obj, "hashAlg");
            comp_name = primes->hash_algs;

            while(comp_name) {
                if (is_valid_hash_alg(comp_name->name) == ACVP_SUCCESS)
                    json_array_append_string(hash_array, comp_name->name);
                next_name = comp_name->next;
                comp_name = next_name;
            }
        }
        if (rand_pq_val == RSA_RAND_PQ_B33 ||
            rand_pq_val == RSA_RAND_PQ_B36 ||
            rand_pq_val == RSA_RAND_PQ_B35)
        {
            json_object_set_value(obj, "primeTest", json_value_init_array());
            prime_test_array = json_object_get_array(obj, "primeTest");
            comp_name = primes->prime_tests;

            while(comp_name) {
                if (is_valid_prime_test(comp_name->name) == ACVP_SUCCESS)
                    json_array_append_string(prime_test_array, comp_name->name);
                next_name = comp_name->next;
                comp_name = next_name;
            }
        }

        json_array_append_value(primes_array, val);
        next_prime = primes->next;
        primes = next_prime;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_lookup_rsa_cap_sig_type(JSON_Object *cap_obj, ACVP_RSA_CAP_MODE_LIST *mode_list)
{
    JSON_Array *mod_rsa_sig_array = NULL, *hash_sig_array = NULL;

    ACVP_RSA_CAP_SIG_TYPE *type, *next_type;
    ACVP_NAME_LIST *comp_hash, *next_hash;

    if(!mode_list) return ACVP_INVALID_ARG;

    /*
     * Init json array
     */
    if(mode_list->cap_mode==ACVP_RSA_MODE_SIGGEN)
    {
        json_object_set_value(cap_obj, "capSigType", json_value_init_array());
        mod_rsa_sig_array = json_object_get_array(cap_obj, "capSigType");

        /*
         * return OK if nothing present
         */
        type = mode_list->cap_mode_attrs.siggen->cap_sig_type;
        if(!mode_list->cap_mode_attrs.siggen->cap_sig_type) {
            return ACVP_SUCCESS;
        }


        while (type) {
            JSON_Value *val = NULL;
            JSON_Object *obj = NULL;
            val = json_value_init_object();
            obj = json_value_get_object(val);

            json_object_set_number(obj, "modulo", type->mod_rsa_sig);
            json_object_set_value(obj, ACVP_RSA_HASHALG_OBJ_NAME, json_value_init_array());
            hash_sig_array = json_object_get_array(obj, ACVP_RSA_HASHALG_OBJ_NAME);
            comp_hash = type->compatible_hashes_sig;

            while(comp_hash) {
                json_array_append_string(hash_sig_array, comp_hash->name);
                next_hash = comp_hash->next;
                comp_hash = next_hash;
            }

            // only print saltSigGen if sigType is "PKCS1PSS"
            if(strncmp(mode_list->cap_mode_attrs.siggen->sig_type, RSA_SIG_TYPE_PKCS1PSS_NAME, RSA_SIG_TYPE_MAX_LEN ) == 0 ) {
                ACVP_SALT_SIZES *salt, *next_salt;
                JSON_Array *salt_sig_array = NULL;

                json_object_set_value(obj, ACVP_RSA_SALTLEN_OBJ_NAME, json_value_init_array());
                salt_sig_array = json_object_get_array(obj, ACVP_RSA_SALTLEN_OBJ_NAME);
                salt = type->salt_sig;

                while(salt) {
                    json_array_append_number(salt_sig_array, salt->saltVal);
                    next_salt = salt->next;
                    salt = next_salt;
                }

            }
            json_array_append_value(mod_rsa_sig_array, val);
            next_type = type->next;
            type = next_type;
        }
    }
    else if(mode_list->cap_mode==ACVP_RSA_MODE_SIGVER)
    {
        json_object_set_value(cap_obj, "capSigType", json_value_init_array());
        mod_rsa_sig_array = json_object_get_array(cap_obj, "capSigType");

        /*
         * return OK if nothing present
         */
        type = mode_list->cap_mode_attrs.sigver->cap_sig_type;
        if(!mode_list->cap_mode_attrs.sigver->cap_sig_type) {
            return ACVP_SUCCESS;
        }


        while (type) {
            JSON_Value *val = NULL;
            JSON_Object *obj = NULL;
            val = json_value_init_object();
            obj = json_value_get_object(val);

            json_object_set_number(obj, "modulo", type->mod_rsa_sig);
            json_object_set_value(obj, ACVP_RSA_HASHALG_OBJ_NAME, json_value_init_array());
            hash_sig_array = json_object_get_array(obj, ACVP_RSA_HASHALG_OBJ_NAME);
            comp_hash = type->compatible_hashes_sig;

            while(comp_hash) {
                json_array_append_string(hash_sig_array, comp_hash->name);
                next_hash = comp_hash->next;
                comp_hash = next_hash;
            }

            // only print saltSigVer if sigType is "PKCS1PSS"
            if(strncmp(mode_list->cap_mode_attrs.sigver->sig_type, RSA_SIG_TYPE_PKCS1PSS_NAME, RSA_SIG_TYPE_MAX_LEN ) == 0 ) {
                ACVP_SALT_SIZES *salt, *next_salt;
                JSON_Array *salt_sig_array = NULL;

                json_object_set_value(obj, ACVP_RSA_SALTLEN_OBJ_NAME, json_value_init_array());
                salt_sig_array = json_object_get_array(obj, ACVP_RSA_SALTLEN_OBJ_NAME);
                salt = type->salt_sig;

                while(salt) {
                    json_array_append_number(salt_sig_array, salt->saltVal);
                    next_salt = salt->next;
                    salt = next_salt;
                }

            }
            json_array_append_value(mod_rsa_sig_array, val);
            next_type = type->next;
            type = next_type;
        }
    }
    return ACVP_SUCCESS;
}

static char *acvp_lookup_rsa_mode_string (ACVP_RSA_MODE mode)
{
    char *mode_str = NULL;
    switch(mode) {
    case ACVP_RSA_MODE_KEYGEN:
        mode_str = ACVP_RSA_KEYGEN;
        break;
    case ACVP_RSA_MODE_SIGGEN:
		mode_str = ACVP_RSA_SIGGEN;
		break;
    case ACVP_RSA_MODE_SIGVER:
            mode_str = ACVP_RSA_SIGVER;
            break;
    default:
        return NULL;
    }
    return mode_str;
}

static ACVP_RESULT acvp_build_rsa_keygen_register(JSON_Object **cap_specs_obj, ACVP_CAPS_LIST *cap_entry) {
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_RSA_KEYGEN_ATTRS *rsa_cap_mode = NULL;

    rsa_cap_mode = cap_entry->cap.rsa_cap->rsa_cap_mode_list->cap_mode_attrs.keygen;

    json_object_set_string(*cap_specs_obj, "pubExp", rsa_cap_mode->pub_exp == RSA_PUB_EXP_FIXED ? "fixed" : "random");

    if (rsa_cap_mode->pub_exp == RSA_PUB_EXP_FIXED) {
        json_object_set_string(*cap_specs_obj, "fixedPubExpVal", BN_bn2hex(rsa_cap_mode->fixed_pub_exp_val));
    }

    json_object_set_boolean(*cap_specs_obj, "infoGeneratedByServer", rsa_cap_mode->info_gen_by_server);
    json_object_set_string(*cap_specs_obj, "randPQ", acvp_lookup_rsa_randpq_name(rsa_cap_mode->rand_pq));
    result = acvp_lookup_rsa_primes(*cap_specs_obj, cap_entry->cap.rsa_cap);

    return result;
}

static ACVP_RESULT acvp_build_rsa_siggen_register(JSON_Object **cap_specs_obj, ACVP_RSA_CAP_MODE_LIST *mode_list) {
    ACVP_RSA_SIGGEN_ATTRS *rsa_cap_mode = NULL;
    rsa_cap_mode = mode_list->cap_mode_attrs.siggen;
    json_object_set_string(*cap_specs_obj, "sigType", rsa_cap_mode->sig_type);

    return acvp_lookup_rsa_cap_sig_type(*cap_specs_obj, mode_list);
}

static ACVP_RESULT acvp_build_rsa_sigver_register(JSON_Object **cap_specs_obj, ACVP_RSA_CAP_MODE_LIST *mode_list) {
    ACVP_RSA_SIGVER_ATTRS *rsa_cap_mode = NULL;
    rsa_cap_mode = mode_list->cap_mode_attrs.sigver;
    json_object_set_string(*cap_specs_obj, "sigType", rsa_cap_mode->sig_type);

    return acvp_lookup_rsa_cap_sig_type(*cap_specs_obj, mode_list);
}

static ACVP_RESULT acvp_build_rsa_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry)
{
	ACVP_RESULT result;
	ACVP_RSA_MODE mode;

	JSON_Array *specs_array = NULL;
	JSON_Value *mode_specs_val = NULL, *cap_specs_val = NULL, *mode_val = NULL;
	JSON_Object *mode_specs_obj = NULL, *cap_specs_obj = NULL, *mode_obj = NULL;

	json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
	result = acvp_lookup_prereqVals(cap_obj, cap_entry);
	if (result != ACVP_SUCCESS) return result;

	json_object_set_value(cap_obj, "algSpecs", json_value_init_array());
	specs_array = json_object_get_array(cap_obj, "algSpecs");

	ACVP_RSA_CAP_MODE_LIST *mode_list = cap_entry->cap.rsa_cap->rsa_cap_mode_list;
	while(mode_list)
	{
	    mode = mode_list->cap_mode;
	    char *mode_str = acvp_lookup_rsa_mode_string(mode);
        if (!mode_str)
            return ACVP_INVALID_ARG;

	    mode_specs_val = json_value_init_object();
        mode_specs_obj = json_value_get_object(mode_specs_val);

        mode_val = json_value_init_object();
        mode_obj = json_value_get_object(mode_val);

	    cap_specs_val = json_value_init_object();
	    cap_specs_obj = json_value_get_object(cap_specs_val);

	    switch(mode) {
	    case ACVP_RSA_MODE_KEYGEN:
	        result = acvp_build_rsa_keygen_register(&cap_specs_obj, cap_entry);
	        if (result != ACVP_SUCCESS) return result;
	        break;
	    case ACVP_RSA_MODE_SIGGEN:
	        result = acvp_build_rsa_siggen_register(&cap_specs_obj, mode_list);
	        if (result != ACVP_SUCCESS) return result;
	        break;
	    case ACVP_RSA_MODE_SIGVER:
	        result = acvp_build_rsa_sigver_register(&cap_specs_obj, mode_list);
	        if (result != ACVP_SUCCESS) return result;
	        break;
	    default:
            return ACVP_INVALID_ARG;
	    }

	    json_object_set_string(mode_obj, "mode", mode_str);
	    json_object_set_value(mode_obj, "capSpecs", cap_specs_val);
	    json_object_set_value(mode_specs_obj, "modeSpecs", mode_val);
	    json_array_append_value(specs_array, mode_specs_val);
	    mode_list = mode_list->next;
	}
	return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kdf135_tls_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry)
{
    JSON_Array *temp_arr = NULL;
    ACVP_RESULT result;

    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
    json_object_set_value(cap_obj, "methods", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "methods");
    if (cap_entry->cap.kdf135_tls_cap->method[0] == ACVP_KDF135_TLS10_TLS11)
        json_array_append_string(temp_arr, "TLS1.0-1.1");
    else if (cap_entry->cap.kdf135_tls_cap->method[0] == ACVP_KDF135_TLS12)
        json_array_append_string(temp_arr, "TLS1.2");

    if (cap_entry->cap.kdf135_tls_cap->method[1] == ACVP_KDF135_TLS10_TLS11)
        json_array_append_string(temp_arr, "TLS1.0-1.1");
    else if (cap_entry->cap.kdf135_tls_cap->method[1] == ACVP_KDF135_TLS12)
        json_array_append_string(temp_arr, "TLS1.2");

    json_object_set_value(cap_obj, "sha", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "sha");
    if (cap_entry->cap.kdf135_tls_cap->sha || ACVP_KDF135_TLS_CAP_SHA256)
        json_array_append_string(temp_arr, "SHA-256");
    if (cap_entry->cap.kdf135_tls_cap->sha || ACVP_KDF135_TLS_CAP_SHA384)
        json_array_append_string(temp_arr, "SHA-384");
    if (cap_entry->cap.kdf135_tls_cap->sha || ACVP_KDF135_TLS_CAP_SHA512)
        json_array_append_string(temp_arr, "SHA-512");

    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if(result != ACVP_SUCCESS) return result;

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kdf135_snmp_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry)
{
    ACVP_RESULT result;
    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));

    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if(result != ACVP_SUCCESS) return result;

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kdf135_ssh_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry)
{
    JSON_Array *temp_arr = NULL;
    ACVP_RESULT result;

    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
    json_object_set_value(cap_obj, "methods", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "methods");
    if (cap_entry->cap.kdf135_ssh_cap->method[0] == ACVP_SSH_METH_TDES_CBC)
        json_array_append_string(temp_arr, "TDES-CBC");

    if (cap_entry->cap.kdf135_ssh_cap->method[1] == ACVP_SSH_METH_AES_128_CBC)
        json_array_append_string(temp_arr, "AES-128-CBC");

    if (cap_entry->cap.kdf135_ssh_cap->method[2] == ACVP_SSH_METH_AES_192_CBC)
        json_array_append_string(temp_arr, "AES-192-CBC");

    if (cap_entry->cap.kdf135_ssh_cap->method[3] == ACVP_SSH_METH_AES_256_CBC)
        json_array_append_string(temp_arr, "AES-256-CBC");

    json_object_set_value(cap_obj, "sha", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "sha");
    if (cap_entry->cap.kdf135_ssh_cap->sha & ACVP_KDF135_SSH_CAP_SHA256)
        json_array_append_string(temp_arr, "SHA-256");
    if (cap_entry->cap.kdf135_ssh_cap->sha & ACVP_KDF135_SSH_CAP_SHA384)
        json_array_append_string(temp_arr, "SHA-384");
    if (cap_entry->cap.kdf135_ssh_cap->sha & ACVP_KDF135_SSH_CAP_SHA512)
        json_array_append_string(temp_arr, "SHA-512");

    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if(result != ACVP_SUCCESS) return result;

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_dsa_pqggen_register(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_DSA_PQGGEN_ATTRS *pqggen = NULL;
    ACVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    JSON_Array *temp_arr = NULL;
    JSON_Array *sha_arr = NULL;
    JSON_Value *ln_val = NULL;
    JSON_Object *ln_obj = NULL;
    JSON_Value *sha_val = NULL;
    JSON_Object *sha_obj = NULL;

    dsa_cap_mode = cap_entry->cap.dsa_cap->dsa_cap_mode;
    pqggen = dsa_cap_mode->cap_mode_attrs.pqggen;

    json_object_set_value(cap_obj, "genPQ", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "genPQ");
    if (dsa_cap_mode->gen_pq_prob) {
        json_array_append_string(temp_arr, "probable");
    }
    if (dsa_cap_mode->gen_pq_prov) {
        json_array_append_string(temp_arr, "provable");
    }

    json_object_set_value(cap_obj, "genG", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "genG");
    if (dsa_cap_mode->gen_g_unv) {
        json_array_append_string(temp_arr, "unverifiable");
    }
    if (dsa_cap_mode->gen_g_can) {
        json_array_append_string(temp_arr, "canonical");
    }

    json_object_set_value(cap_obj, "lnInfo", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "lnInfo");
    while (pqggen) {
    switch (pqggen->modulo)
    {
        case ACVP_DSA_LN2048_224:
            ln_val = json_value_init_object();
            ln_obj = json_value_get_object(ln_val);
            json_object_set_string(ln_obj, "ln", "2048-224");
	    break;
        case ACVP_DSA_LN2048_256:
            ln_val = json_value_init_object();
            ln_obj = json_value_get_object(ln_val);
            json_object_set_string(ln_obj, "ln", "2048-256");
	    break;
        case ACVP_DSA_LN3072_256:
            ln_val = json_value_init_object();
            ln_obj = json_value_get_object(ln_val);
            json_object_set_string(ln_obj, "ln", "3072-256");
	    break;
        default:
	    return ACVP_INVALID_ARG;
    }
    json_array_append_value(temp_arr, ln_val);

    sha_val = json_value_init_object();
    sha_obj = json_value_get_object(sha_val);
    json_object_set_value(sha_obj, "sha", json_value_init_array());
    sha_arr = json_object_get_array(sha_obj, "sha");
    if (pqggen->sha & ACVP_DSA_SHA1)
        json_array_append_string(sha_arr, "SHA-1");
    if (pqggen->sha & ACVP_DSA_SHA224)
        json_array_append_string(sha_arr, "SHA-224");
    if (pqggen->sha & ACVP_DSA_SHA256)
        json_array_append_string(sha_arr, "SHA-256");
    if (pqggen->sha & ACVP_DSA_SHA384)
        json_array_append_string(sha_arr, "SHA-384");
    if (pqggen->sha & ACVP_DSA_SHA512)
        json_array_append_string(sha_arr, "SHA-512");
    if (pqggen->sha & ACVP_DSA_SHA512_224)
        json_array_append_string(sha_arr, "SHA-512-224");
    if (pqggen->sha & ACVP_DSA_SHA512_256)
        json_array_append_string(sha_arr, "SHA-512-256");
    pqggen = pqggen->next;

    json_array_append_value(temp_arr, sha_val);
    }

    return result;
}

static ACVP_RESULT acvp_build_dsa_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry)
{
    ACVP_RESULT result;
    ACVP_RSA_MODE mode;

    JSON_Array *meth_array = NULL;
    JSON_Value *cap_meth_val = NULL;
    JSON_Object *cap_meth_obj = NULL;

    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) return result;

    json_object_set_value(cap_obj, "methods", json_value_init_array());
    meth_array = json_object_get_array(cap_obj, "methods");

    cap_meth_val = json_value_init_object();
    cap_meth_obj = json_value_get_object(cap_meth_val);

    mode = cap_entry->cap.dsa_cap->dsa_cap_mode->cap_mode;

    switch(mode) {
    case ACVP_DSA_MODE_PQGGEN:
        json_object_set_string(cap_meth_obj, "type", "pqgGen");
        result = acvp_build_dsa_pqggen_register(cap_meth_obj, cap_entry);
        if (result != ACVP_SUCCESS) return result;
        break;
    default:
        break;
    }

    json_array_append_value(meth_array, cap_meth_val);

    return ACVP_SUCCESS;
}


/*
 * This function builds the JSON register message that
 * will be sent to the ACVP server to advertised the crypto
 * capabilities of the module under test.
 */
static ACVP_RESULT acvp_build_register(ACVP_CTX *ctx, char **reg)
{
    ACVP_CAPS_LIST *cap_entry;

    JSON_Value *reg_arry_val  = NULL;
    JSON_Value *ver_val  = NULL;
    JSON_Object *ver_obj = NULL;

    JSON_Array *reg_arry = NULL;

    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    JSON_Value *oe_val = NULL;
    JSON_Object *oe_obj = NULL;
    JSON_Value *oee_val = NULL;
    JSON_Object *oee_obj = NULL;
    JSON_Array *caps_arr = NULL;
    JSON_Value *caps_val = NULL;
    JSON_Object *caps_obj = NULL;
    JSON_Value *cap_val = NULL;
    JSON_Object *cap_obj = NULL;
    JSON_Value *vendor_val = NULL;
    JSON_Object *vendor_obj = NULL;
    JSON_Array *con_array_val  = NULL;
    JSON_Array *dep_array_val  = NULL;
    JSON_Value *mod_val  = NULL;
    JSON_Object *mod_obj = NULL;
    JSON_Value *dep_val  = NULL;
    JSON_Object *dep_obj = NULL;
    JSON_Value *con_val  = NULL;
    JSON_Object *con_obj = NULL;

    /*
     * Start the registration array
     */
    reg_arry_val = json_value_init_array();
    reg_arry = json_array  ((const JSON_Value *)reg_arry_val);

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
    json_array_append_value(reg_arry, ver_val);

    val = json_value_init_object();
    obj = json_value_get_object(val);

    /* TODO: Type of request are under construction, hardcoded for now
     * will need a function acvp_set_request_info() to init
     */
    json_object_set_string(obj, "operation", "register");
    json_object_set_string(obj, "certificateRequest", "yes");
    json_object_set_string(obj, "debugRequest", "no");
    json_object_set_string(obj, "production", "no");
    json_object_set_string(obj, "encryptAtRest", "yes");

    oe_val = json_value_init_object();
    oe_obj = json_value_get_object(oe_val);

    vendor_val = json_value_init_object();
    vendor_obj = json_value_get_object(vendor_val);

    json_object_set_string(vendor_obj, "name", ctx->vendor_name);
    json_object_set_string(vendor_obj, "website", ctx->vendor_url);


    json_object_set_value(vendor_obj, "contact", json_value_init_array());
    con_array_val = json_object_get_array(vendor_obj, "contact");

    con_val = json_value_init_object();
    con_obj = json_value_get_object(con_val);

    json_object_set_string(con_obj, "name", ctx->contact_name);
    json_object_set_string(con_obj, "email", ctx->contact_email);
    json_array_append_value(con_array_val, con_val);

    json_object_set_value(oe_obj, "vendor", vendor_val);

    mod_val = json_value_init_object();
    mod_obj = json_value_get_object(mod_val);

    json_object_set_string(mod_obj, "name", ctx->module_name);
    json_object_set_string(mod_obj, "version", ctx->module_version);
    json_object_set_string(mod_obj, "type", ctx->module_type);
    json_object_set_value(oe_obj, "module", mod_val);

    oee_val = json_value_init_object();
    oee_obj = json_value_get_object(oee_val);

    /* TODO: dependencies are under construction, hardcoded for now
     * will need a function acvp_set_depedency_info() to init
     */
    json_object_set_value(oee_obj, "dependencies", json_value_init_array());
    dep_array_val = json_object_get_array(oee_obj, "dependencies");

    dep_val = json_value_init_object();
    dep_obj = json_value_get_object(dep_val);

    /* TODO: some of this stuff could be pulled from the processor(/proc/cpuinfo) and
     * O/S internals (uname -a) and then populated - maybe an API to the DUT to
     * return some of the environment info.  Needs to be moved to app code ?
     */

    json_object_set_string(dep_obj, "type", "software");
    json_object_set_string(dep_obj, "name", "Linux 3.1");
    json_object_set_string(dep_obj, "cpe", "cpe-2.3:o:ubuntu:linux:3.1");
    json_array_append_value(dep_array_val, dep_val);

    dep_val = json_value_init_object();
    dep_obj = json_value_get_object(dep_val);
    json_object_set_string(dep_obj, "type", "processor");
    json_object_set_string(dep_obj, "manufacturer", "Intel");
    json_object_set_string(dep_obj, "family", "ARK");
    json_object_set_string(dep_obj, "name", "Xeon");
    json_object_set_string(dep_obj, "series", "5100");
    json_array_append_value(dep_array_val, dep_val);

    dep_val = json_value_init_object();
    dep_obj = json_value_get_object(dep_val);

    json_object_set_value(oe_obj, "operationalEnvironment", oee_val);

    json_object_set_string(oe_obj, "implementationDescription", ctx->module_desc);
    json_object_set_value(obj, "oeInformation", oe_val);

    /*
     * Start the capabilities advertisement
     */
    caps_val = json_value_init_object();
    caps_obj = json_value_get_object(caps_val);
    json_object_set_value(caps_obj, "algorithms", json_value_init_array());
    caps_arr = json_object_get_array(caps_obj, "algorithms");

    /*
     * Iterate through all the capabilities the user has enabled
     * TODO: This logic is written for the symmetric cipher sub-spec.
     *       This will need rework when implementing the other
     *       sub-specifications.
     */
    if (ctx->caps_list) {
        cap_entry = ctx->caps_list;
        while (cap_entry) {
            /*
             * Create a new capability to be advertised in the JSON
             * registration message
             */
            cap_val = json_value_init_object();
            cap_obj = json_value_get_object(cap_val);

            /*
             * Build up the capability JSON based on the cipher type
             */
            switch(cap_entry->cipher) {
            case ACVP_AES_GCM:
            case ACVP_AES_CCM:
            case ACVP_AES_ECB:
            case ACVP_AES_CFB1:
            case ACVP_AES_CFB8:
            case ACVP_AES_CFB128:
            case ACVP_AES_OFB:
            case ACVP_AES_CBC:
            case ACVP_AES_KW:
            case ACVP_AES_CTR:
            case ACVP_TDES_ECB:
            case ACVP_TDES_CBC:
            case ACVP_TDES_OFB:
            case ACVP_TDES_CFB64:
            case ACVP_TDES_CFB8:
            case ACVP_TDES_CFB1:
                acvp_build_sym_cipher_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_SHA1:
            case ACVP_SHA224:
            case ACVP_SHA256:
            case ACVP_SHA384:
            case ACVP_SHA512:
                acvp_build_hash_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_HASHDRBG:
            case ACVP_HMACDRBG:
            case ACVP_CTRDRBG:
                acvp_build_drbg_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_HMAC_SHA1:
            case ACVP_HMAC_SHA2_224:
            case ACVP_HMAC_SHA2_256:
            case ACVP_HMAC_SHA2_384:
            case ACVP_HMAC_SHA2_512:
                acvp_build_hmac_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_CMAC_AES_128:
            case ACVP_CMAC_AES_192:
            case ACVP_CMAC_AES_256:
            case ACVP_CMAC_TDES:
                acvp_build_cmac_register_cap(cap_obj, cap_entry);
                break;
	    case ACVP_DSA:
                acvp_build_dsa_register_cap(cap_obj, cap_entry);
	        break;
            case ACVP_RSA:
                acvp_build_rsa_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_KDF135_TLS:
                acvp_build_kdf135_tls_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_KDF135_SNMP:
                acvp_build_kdf135_snmp_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_KDF135_SSH:
                acvp_build_kdf135_ssh_register_cap(cap_obj, cap_entry);
                break;
            default:
                ACVP_LOG_ERR("Cap entry not found, %d.", cap_entry->cipher);
                return ACVP_NO_CAP;
            }

            /*
             * Now that we've built up the JSON for this capability,
             * add it to the array of capabilities on the register message.
             */
            json_array_append_value(caps_arr, cap_val);

            /* Advance to next cap entry */
            cap_entry = cap_entry->next;
        }
    }

    /*
     * Add the entire caps exchange section to the top object
     */
    json_object_set_value(obj, "capabilityExchange", caps_val);

    json_array_append_value(reg_arry, val);
    *reg = json_serialize_to_string_pretty(reg_arry_val);
    json_value_free(reg_arry_val);
    json_value_free(dep_val);

    return ACVP_SUCCESS;
}

/*
 * This function is used to regitser the DUT with the server.
 * Registration allows the DUT to advertise it's capabilities to
 * the server.  The server will respond with a set of vector set
 * identifiers that the client will need to process.
 */
ACVP_RESULT acvp_register(ACVP_CTX *ctx)
{
    ACVP_RESULT rv;
    char *reg;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Construct the registration message based on the capabilities
     * the user has enabled.
     */
    rv = acvp_build_register(ctx, &reg);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to build register message");
        return rv;
    }

    if (ctx->debug >= ACVP_LOG_LVL_STATUS) {
        printf("\nPOST %s\n", reg);
    } else {
        ACVP_LOG_INFO("POST %s", reg);
    }
    /*
     * Send the capabilities to the ACVP server and get the response,
     * which should be a list of VS identifiers that will need
     * to be downloaded and processed.
     */
    rv = acvp_send_register(ctx, reg);
    if (rv == ACVP_SUCCESS) {
        ACVP_LOG_STATUS("200 OK %s", ctx->reg_buf);
        rv = acvp_parse_register(ctx);
    }

    json_free_serialized_string(reg);

    return (rv);
}

/*
 * Append a symmetric cipher capabilitiy to the
 * capabilities list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_sym_cipher_caps_entry(
	ACVP_CTX *ctx,
	ACVP_SYM_CIPHER_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.sym_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_SYM_TYPE;

    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

/*
 * Append a hash capabilitiy to the
 * capabilities list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_hash_caps_entry(
	ACVP_CTX *ctx,
	ACVP_HASH_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.hash_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_HASH_TYPE;

    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}


/*
 * Append a DRBG capability to the
 * capabilities list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_drbg_caps_entry(
        ACVP_CTX *ctx,
        ACVP_DRBG_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.drbg_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_DRBG_TYPE;

    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}


/*
 * Append an RSA capability to the
 * capabilities list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_rsa_caps_entry(
        ACVP_CTX *ctx,
        ACVP_RSA_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.rsa_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_RSA_TYPE;

    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

/*
 * Append hmac capability to the capabilities
 * list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_hmac_caps_entry(
        ACVP_CTX *ctx,
        ACVP_HMAC_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.hmac_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_HMAC_TYPE;

    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

/*
 * Append cmac capability to the capabilities
 * list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_cmac_caps_entry(
        ACVP_CTX *ctx,
        ACVP_CMAC_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.cmac_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_CMAC_TYPE;

    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

/*
 * Append a VS identifier to the list of VS identifiers
 * that will need to be downloaded and processed later.
 */
static ACVP_RESULT acvp_append_vs_entry(ACVP_CTX *ctx, int vs_id)
{
    ACVP_VS_LIST *vs_entry, *vs_e2;

    vs_entry = calloc(1, sizeof(ACVP_VS_LIST));
    if (!vs_entry) {
        return ACVP_MALLOC_FAIL;
    }
    vs_entry->vs_id = vs_id;

    if (!ctx->vs_list) {
        ctx->vs_list = vs_entry;
    } else {
        vs_e2 = ctx->vs_list;
        while (vs_e2->next) {
            vs_e2 = vs_e2->next;
        }
        vs_e2->next = vs_entry;
    }
    return (ACVP_SUCCESS);
}

/*
 * get version from response
 */
static char* acvp_get_version_from_rsp(JSON_Value *arry_val)
{
    char *version = NULL;
    JSON_Object *ver_obj = NULL;

    JSON_Array  *reg_array;

    reg_array = json_value_get_array(arry_val);
    ver_obj = json_array_get_object(reg_array, 0);
    version = (char *)json_object_get_string(ver_obj, "acvVersion");
    if (version == NULL) {
        return NULL;
    }

    return(version);
}

/*
 * get JASON Object from response
 */
static JSON_Object* acvp_get_obj_from_rsp(JSON_Value *arry_val)
{
    JSON_Object *obj = NULL;
    JSON_Array  *reg_array;
    char        *ver = NULL;

    reg_array = json_value_get_array(arry_val);
    ver = acvp_get_version_from_rsp(arry_val);
    if (ver == NULL) {
        return NULL;
    }

    obj = json_array_get_object(reg_array, 1);
    return(obj);
}

/*
 * This routine performs the JSON parsing of the registration response
 * from the ACVP server.  The response should contain a list of vector
 * set (VS) identifiers that will need to be downloaded and processed
 * by the DUT.
 */
static ACVP_RESULT acvp_parse_register(ACVP_CTX *ctx)
{
    JSON_Value *val;
    JSON_Object *obj = NULL;
    JSON_Object *cap_obj = NULL;
    ACVP_RESULT rv;
    char *json_buf = ctx->reg_buf;
    JSON_Array *vect_sets;
    JSON_Value *vs_val;
    JSON_Object *vs_obj;
    int i, vs_cnt;
    int vs_id;
    const char *jwt;

    /*
     * Parse the JSON
     */
    val = json_parse_string_with_comments(json_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }

    obj = acvp_get_obj_from_rsp(val);

    /*
     * Get the JWT assigned to this session by the server.  This will need
     * to be included when sending the vector responses back to the server
     * later.
     */
    jwt = json_object_get_string(obj, "accessToken");
    if (!jwt) {
        json_value_free(val);
        ACVP_LOG_ERR("No access_token provided in registration response");
        return ACVP_NO_TOKEN;
    } else {
        i = strnlen(jwt, ACVP_JWT_TOKEN_MAX+1);
        if (i > ACVP_JWT_TOKEN_MAX) {
            json_value_free(val);
            ACVP_LOG_ERR("access_token too large");
            return ACVP_NO_TOKEN;
        }
        ctx->jwt_token = calloc(1, i+1);
        strncpy(ctx->jwt_token, jwt, i);
        ctx->jwt_token[i] = 0;
        ACVP_LOG_STATUS("JWT: %s", ctx->jwt_token);
    }

    /*
     * Identify the VS identifiers provided by the server, save them for
     * processing later.
     */
    cap_obj = json_object_get_object(obj, "capabilityResponse");
    vect_sets = json_object_get_array(cap_obj, "vectorSets");
    vs_cnt = json_array_get_count(vect_sets);
    for (i = 0; i < vs_cnt; i++) {
        vs_val = json_array_get_value(vect_sets, i);
        vs_obj = json_value_get_object(vs_val);
        vs_id = json_object_get_number(vs_obj, "vsId");

        rv = acvp_append_vs_entry(ctx, vs_id);
        if (rv != ACVP_SUCCESS) {
            json_value_free(val);
            return rv;
        }
        ACVP_LOG_INFO("Received vs_id=%d", vs_id);
    }

    json_value_free(val);

    ACVP_LOG_INFO("Successfully processed registration response from server");

    return ACVP_SUCCESS;

}

/*
 * This function is used by the application after registration
 * to commence the testing.  All the testing will be handled
 * by libacvp.  This function will block the caller.  Therefore,
 * it should be run on a separate thread if needed.
 */
ACVP_RESULT acvp_process_tests(ACVP_CTX *ctx)
{
    ACVP_RESULT rv;
    ACVP_VS_LIST *vs_entry;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Iterate through the VS identifiers the server sent to us
     * in the regisration response.  Process each vector set and
     * return the results to the server.
     */
    vs_entry = ctx->vs_list;
    while (vs_entry) {
        rv = acvp_process_vsid(ctx, vs_entry->vs_id);
        vs_entry = vs_entry->next;
    }

    return (rv);
}

/*
 * This is a minimal retry handler, which pauses for a specific time.
 * This allows the server time to generate the vectors on behalf of
 * the client.
 */
ACVP_RESULT acvp_retry_handler(ACVP_CTX *ctx, unsigned int retry_period)
{
    ACVP_LOG_STATUS("200 OK KAT values not ready, server requests we wait and try again...");
    if (retry_period <= 0 || retry_period > ACVP_RETRY_TIME_MAX) {
        retry_period = ACVP_RETRY_TIME_MAX;
        ACVP_LOG_WARN("retry_period not found, using max retry period!");
    }
    sleep(retry_period);

    return ACVP_KAT_DOWNLOAD_RETRY;
}


/*
 * This routine will iterate through all the vector sets, requesting
 * the test result from the server for each set.
 */
ACVP_RESULT acvp_check_test_results(ACVP_CTX *ctx)
{
    ACVP_RESULT rv;
    ACVP_VS_LIST *vs_entry;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    /*
     * Iterate through the VS identifiers the server sent to us
     * in the regisration response.  Attempt to download the result
     * for each vector set.
     */
    vs_entry = ctx->vs_list;
    while (vs_entry) {
        rv = acvp_get_result_vsid(ctx, vs_entry->vs_id);
        vs_entry = vs_entry->next;
    }

    return (rv);
}



/***************************************************************************************************************
* Begin vector processing logic.  This code should probably go into another module.
***************************************************************************************************************/


/*
 * This function will process a single KAT vector set.  Each KAT
 * vector set has an identifier associated with it, called
 * the vs_id.  During registration, libacvp will receive the
 * list of vs_id's that need to be processed during the test
 * session.  This routine will execute the test flow for a single
 * vs_id.  The flow is:
 *	a) Download the KAT vector set from the server using the vs_id
 *	b) Parse the KAT vectors
 *	c) Process each test case in the KAT vector set
 *	d) Generate the response data
 *	e) Send the response data back to the ACVP server
 */
static ACVP_RESULT acvp_process_vsid(ACVP_CTX *ctx, int vs_id)
{
    ACVP_RESULT rv;
    JSON_Value *val;
    JSON_Object *obj = NULL;
    char *json_buf;
    int retry = 1;

    //TODO: do we want to limit the number of retries?
    while (retry) {
        /*
         * Get the KAT vector set
         */
        rv = acvp_retrieve_vector_set(ctx, vs_id);
        if (rv != ACVP_SUCCESS) {
            return (rv);
        }
        json_buf = ctx->kat_buf;
    	if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
            printf("\n200 OK %s\n", ctx->kat_buf);
        } else {
            ACVP_LOG_STATUS("200 OK %s\n", ctx->kat_buf);
        }
        val = json_parse_string_with_comments(json_buf);
        if (!val) {
            ACVP_LOG_ERR("JSON parse error");
            return ACVP_JSON_ERR;
        }
        obj = acvp_get_obj_from_rsp(val);
        ctx->vs_id = vs_id;

        /*
         * Check if we received a retry response
         */
        unsigned int retry_period = json_object_get_number(obj, "retry");
        if (retry_period) {
            rv = acvp_retry_handler(ctx, retry_period);
        } else {
            /*
             * Process the KAT vectors
             */
            rv = acvp_process_vector_set(ctx, obj);
        }
        json_value_free(val);

        /*
         * Check if we need to retry the download because
         * the KAT values were not ready
         */
        if (ACVP_KAT_DOWNLOAD_RETRY == rv) {
            retry = 1;
        } else if (rv != ACVP_SUCCESS) {
            return (rv);
        } else {
            retry = 0;
        }
    }

    /*
     * Send the responses to the ACVP server
     */
    ACVP_LOG_STATUS("POST vector set response vsId: %d", vs_id);
    rv = acvp_submit_vector_responses(ctx);
    if (rv != ACVP_SUCCESS) {
        return (rv);
    }

    return ACVP_SUCCESS;
}

/*
 * This function is used to invoke the appropriate handler function
 * for a given ACV operation.  The operation is specified in the
 * KAT vector set that was previously downloaded.  The handler function
 * is looked up in the alg_tbl[] and invoked here.
 */
static ACVP_RESULT acvp_dispatch_vector_set(ACVP_CTX *ctx, JSON_Object *obj)
{
    int i;
    const char *alg = json_object_get_string(obj, "algorithm");
    const char *dir = json_object_get_string(obj, "direction");
    int vs_id = json_object_get_number(obj, "vsId");
    ACVP_RESULT rv;

    if (!alg) {
        ACVP_LOG_ERR("JSON parse error: ACV algorithm not found");
        return ACVP_JSON_ERR;
    }

    ACVP_LOG_STATUS("vsId: %d", vs_id);
    ACVP_LOG_STATUS("ACV Operation: %s", alg);
    ACVP_LOG_INFO("ACV Direction: %s", dir);
    ACVP_LOG_INFO("ACV version: %s", json_object_get_string(obj, "acvVersion"));

    for (i = 0; i < ACVP_ALG_MAX; i++) {
        if (!strncmp(alg, alg_tbl[i].name, strlen(alg_tbl[i].name))) {
            rv = (alg_tbl[i].handler)(ctx, obj);
            return rv;
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
 *	a) JSON parse the data
 *	b) Identify the ACVP operation to be performed (e.g. AES encrypt)
 *	c) Dispatch the vectors to the handler for the
 *	   specified ACVP operation.
 */
static ACVP_RESULT acvp_process_vector_set(ACVP_CTX *ctx, JSON_Object *obj)
{
    ACVP_RESULT rv;

    rv = acvp_dispatch_vector_set(ctx, obj);
    if (rv != ACVP_SUCCESS) {
        return rv;
    }

    ACVP_LOG_STATUS("Successfully processed KAT vector set");

    return ACVP_SUCCESS;

}


/*
 * This function will get the test results for a single KAT vector set.
 */
static ACVP_RESULT acvp_get_result_vsid(ACVP_CTX *ctx, int vs_id)
{
    ACVP_RESULT rv;
    JSON_Value *val;
    JSON_Object *obj = NULL;
    char *json_buf;
    int retry_count = 900; /* 15 minutes*/
    int retry = 1;

    while (retry && (retry_count > 0)) {
        /*
         * Get the KAT vector set
         */
        rv = acvp_retrieve_vector_set_result(ctx, vs_id);
        if (rv != ACVP_SUCCESS) {
            return (rv);
        }
        json_buf = ctx->kat_buf;

    	if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
            printf("\n%s\n", ctx->kat_buf);
    	} else {
            ACVP_LOG_ERR("%s", ctx->kat_buf);
        }
        val = json_parse_string_with_comments(json_buf);
        if (!val) {
            ACVP_LOG_ERR("JSON parse error");
            return ACVP_JSON_ERR;
        }
        obj = acvp_get_obj_from_rsp(val);
        ctx->vs_id = vs_id;

        /*
         * Check if we received a retry response
         */
        unsigned int retry_period = json_object_get_number(obj, "retry");
        if (retry_period) {
            rv = acvp_retry_handler(ctx, retry_period);
    	    retry_count -= retry_period;
        } else {
	    /*
	     * Parse the JSON response from the server, if the vector set failed,
	     * then pull out the reason code and log it.
	     */
	    //TODO
        }
        json_value_free(val);

        /*
         * Check if we need to retry the download because
         * the KAT values were not ready
         */
        if (ACVP_KAT_DOWNLOAD_RETRY == rv) {
            retry = 1;
        } else if (rv != ACVP_SUCCESS) {
            return (rv);
        } else {
            retry = 0;
        }
    }

    return ACVP_SUCCESS;
}

static
ACVP_RESULT acvp_validate_kdf135_tls_param_value(ACVP_KDF135_TLS_METHOD method, ACVP_KDF135_TLS_CAP_PARM param) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;

    switch (method){

      case ACVP_KDF135_TLS12:
          if ((param < ACVP_KDF135_TLS_CAP_MAX) && (param > 0)) {
              retval = ACVP_SUCCESS;
          }
	  break;
      case ACVP_KDF135_TLS10_TLS11:
          if (param == 0) {
              retval = ACVP_SUCCESS;
	  }
	  break;
      default:
          break;
    }

    return retval;
}

static ACVP_RESULT acvp_append_kdf135_tls_caps_entry(
       ACVP_CTX *ctx,
       ACVP_KDF135_TLS_CAP *cap,
       ACVP_KDF135_TLS_METHOD method,
       ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = method;
    cap_entry->cap.kdf135_tls_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_KDF135_TLS;

    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_kdf135_tls_cap(
          ACVP_CTX *ctx,
          ACVP_KDF135_TLS_METHOD method,
          ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_KDF135_TLS_CAP *cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }

    cap = calloc(1, sizeof(ACVP_KDF135_TLS_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }

    return (acvp_append_kdf135_tls_caps_entry(ctx, cap, method, crypto_handler));
}

/*
 * The user should call this after invoking acvp_enable_kdf135_tls_cap()
 * to specify the kdf parameters.
 */
ACVP_RESULT acvp_enable_kdf135_tls_cap_parm(
                          ACVP_CTX *ctx,
                          ACVP_CIPHER kcap,
                          ACVP_KDF135_TLS_METHOD method,
			  ACVP_KDF135_TLS_CAP_PARM param) {

    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_TLS_CAP *kdf135_tls_cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, kcap);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kdf135_tls_cap = cap->cap.kdf135_tls_cap;
    if (!kdf135_tls_cap) {
        return ACVP_NO_CAP;
    }

    if (acvp_validate_kdf135_tls_param_value(method, param) != ACVP_SUCCESS) {
        return ACVP_INVALID_ARG;
    }

    /* only support two method types so just use whichever is available */
    if (!kdf135_tls_cap->method[0]) {
        kdf135_tls_cap->method[0] = method;
    } else {
        kdf135_tls_cap->method[1] = method;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_append_kdf135_snmp_caps_entry(
       ACVP_CTX *ctx,
       ACVP_KDF135_SNMP_CAP *cap,
       ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cap.kdf135_snmp_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cipher = ACVP_KDF135_SNMP;
    cap_entry->cap_type = ACVP_KDF135_SNMP_TYPE;

    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_kdf135_snmp_cap(
          ACVP_CTX *ctx,
          ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_KDF135_SNMP_CAP *cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }

    cap = calloc(1, sizeof(ACVP_KDF135_SNMP_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }

    return (acvp_append_kdf135_snmp_caps_entry(ctx, cap, crypto_handler));
}

static ACVP_RESULT acvp_append_kdf135_ssh_caps_entry(
       ACVP_CTX *ctx,
       ACVP_KDF135_SSH_CAP *cap,
       ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = ACVP_KDF135_SSH;
    cap_entry->cap.kdf135_ssh_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_KDF135_SSH_TYPE;

    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_enable_kdf135_ssh_cap(
          ACVP_CTX *ctx,
          ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_KDF135_SSH_CAP *cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }

    cap = calloc(1, sizeof(ACVP_KDF135_SSH_CAP));
    if (!cap) {
        return ACVP_MALLOC_FAIL;
    }

    return (acvp_append_kdf135_ssh_caps_entry(ctx, cap, crypto_handler));
}

static
ACVP_RESULT acvp_validate_kdf135_ssh_param_value(ACVP_KDF135_SSH_METHOD method, ACVP_KDF135_SSH_CAP_PARM param) {
    ACVP_RESULT retval = ACVP_INVALID_ARG;

    if ((method < ACVP_SSH_METH_MAX) && (method > 0)) {
        if ((param & ACVP_KDF135_SSH_CAP_SHA256) ||
            (param & ACVP_KDF135_SSH_CAP_SHA384) ||
            (param & ACVP_KDF135_SSH_CAP_SHA512) ) {
            retval = ACVP_SUCCESS;
        }
    }
    return retval;
}

/*
 * The user should call this after invoking acvp_enable_kdf135_ssh_cap()
 * to specify the kdf parameters.
 */
ACVP_RESULT acvp_enable_kdf135_ssh_cap_parm(
                          ACVP_CTX *ctx,
                          ACVP_CIPHER kcap,
                          ACVP_KDF135_SSH_METHOD method,
                          ACVP_KDF135_SSH_CAP_PARM param) {

    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_SSH_CAP *kdf135_ssh_cap;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    cap = acvp_locate_cap_entry(ctx, kcap);
    if (!cap) {
        return ACVP_NO_CAP;
    }

    kdf135_ssh_cap = cap->cap.kdf135_ssh_cap;
    if (!kdf135_ssh_cap) {
        return ACVP_NO_CAP;
    }

    if (acvp_validate_kdf135_ssh_param_value(method, param) != ACVP_SUCCESS) {
        return ACVP_INVALID_ARG;
    }

    /* only support two method types so just use whichever is available */
    switch(method) {
    case ACVP_SSH_METH_TDES_CBC:
        kdf135_ssh_cap->method[0] = ACVP_SSH_METH_TDES_CBC;
        break;
    case ACVP_SSH_METH_AES_128_CBC:
        kdf135_ssh_cap->method[1] = ACVP_SSH_METH_AES_128_CBC;
        break;
    case ACVP_SSH_METH_AES_192_CBC:
        kdf135_ssh_cap->method[2] = ACVP_SSH_METH_AES_192_CBC;
        break;
    case ACVP_SSH_METH_AES_256_CBC:
        kdf135_ssh_cap->method[3] = ACVP_SSH_METH_AES_256_CBC;
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    kdf135_ssh_cap->sha = kdf135_ssh_cap->sha | param;

    return ACVP_SUCCESS;
}

/*
 * Append an DSA capability to the
 * capabilities list.  This list is later used to build
 * the register message.
 */
static ACVP_RESULT acvp_append_dsa_caps_entry(
        ACVP_CTX *ctx,
        ACVP_DSA_CAP *cap,
        ACVP_CIPHER cipher,
        ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cipher = cipher;
    cap_entry->cap.dsa_cap = cap;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = ACVP_DSA_TYPE;

    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }
    return (ACVP_SUCCESS);
}

ACVP_RESULT acvp_enable_dsa_cap(ACVP_CTX *ctx,
     ACVP_CIPHER cipher,
     ACVP_RESULT (*crypto_handler)(ACVP_TEST_CASE *test_case))
{
    ACVP_DSA_CAP *dsa_cap;
    ACVP_RESULT result;
    void *dsa_modes;
    int i;

    if (!ctx) {
        return ACVP_NO_CTX;
    }
    if (!crypto_handler) {
        return ACVP_INVALID_ARG;
    }

    /*
     * Check for duplicate entry
     */
    if (acvp_locate_cap_entry(ctx, cipher)) {
        return ACVP_DUP_CIPHER;
    }

    dsa_cap = calloc(1, sizeof(ACVP_DSA_CAP));
    if (!dsa_cap) {
        return ACVP_MALLOC_FAIL;
    }

    dsa_cap->cipher = cipher;

    dsa_modes = calloc(1, sizeof(ACVP_DSA_MAX_MODES) * sizeof(ACVP_DSA_CAP_MODE));
    if (!dsa_modes) {
        free(dsa_cap);
        return ACVP_MALLOC_FAIL;
    }

    dsa_cap->dsa_cap_mode = dsa_modes;
    for (i=1; i <= ACVP_DSA_MAX_MODES; i++) {
        dsa_cap->dsa_cap_mode[i-1].cap_mode = i;
    }

    result = acvp_append_dsa_caps_entry(ctx, dsa_cap, cipher, crypto_handler);
    if (result != ACVP_SUCCESS) {
        free(dsa_cap);
        free(dsa_modes);
        dsa_cap = NULL;
    }
    return result;
}

static ACVP_RESULT acvp_dsa_set_modulo (ACVP_DSA_CAP_MODE  *dsa_cap_mode,
                                        ACVP_DSA_PARM       param,
                                        ACVP_DSA_SHA value)
{
    ACVP_DSA_PQGGEN_ATTRS *pqggen;

    if (!dsa_cap_mode) {
        return ACVP_NO_CTX;
    }

    pqggen = dsa_cap_mode->cap_mode_attrs.pqggen;
    if (!pqggen) {
        pqggen = calloc(1, sizeof(ACVP_DSA_PQGGEN_ATTRS));
        if (!pqggen) {
            return ACVP_MALLOC_FAIL;
        }
        dsa_cap_mode->cap_mode_attrs.pqggen = pqggen;
        pqggen->modulo = param;
        pqggen->next = NULL;
    }
    /* TODO check range of modulo and value */
    while (1) {
        if (pqggen->modulo == param) {
            pqggen->sha |= value;
            return ACVP_SUCCESS;
        }
        if (pqggen->next == NULL)
	    break;
        pqggen = pqggen->next;
    }
    pqggen->next = calloc(1, sizeof(ACVP_DSA_PQGGEN_ATTRS));
    if (!pqggen->next) {
        return ACVP_MALLOC_FAIL;
    }
    pqggen = pqggen->next;
    pqggen->modulo = param;
    pqggen->sha |= value;
    pqggen->next = NULL;
    return ACVP_SUCCESS;
}

/*
 * Add DSA per modulo parameters
 */
static ACVP_RESULT acvp_add_dsa_mode_parm (ACVP_CTX *ctx,
       		   	     ACVP_DSA_CAP_MODE *dsa_cap_mode,
                             ACVP_DSA_PARM       param,
                             ACVP_DSA_SHA        value
                             )
{
    ACVP_RESULT rv;

    /*
     * Validate input
     */
    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!dsa_cap_mode) {
        return ACVP_NO_CTX;
    }

    rv = acvp_dsa_set_modulo(dsa_cap_mode, param, value);
    if (rv != ACVP_SUCCESS) {
        return rv;
    }

    return ACVP_SUCCESS;
}

/*
 * Add top level DSA pqggen parameters
 */
static ACVP_RESULT acvp_add_dsa_pqggen_parm (ACVP_CTX *ctx,
                             ACVP_DSA_CAP_MODE  *dsa_cap_mode,
                             ACVP_DSA_PARM       param,
                             int                 value
                             )
{
    switch (param) {
    case ACVP_DSA_GENPQ:
        switch (value) {
	case ACVP_DSA_PROVABLE:
	   dsa_cap_mode->gen_pq_prov = 1;
	   break;
	case ACVP_DSA_PROBABLE:
	   dsa_cap_mode->gen_pq_prob = 1;
	   break;
	default:
            return ACVP_INVALID_ARG;
            break;
        }
	break;
    case ACVP_DSA_GENG:
        switch (value) {
	case ACVP_DSA_CANONICAL:
	   dsa_cap_mode->gen_g_can = 1;
	   break;
	case ACVP_DSA_UNVERIFIABLE:
	   dsa_cap_mode->gen_g_unv = 1;
	   break;
	default:
            return ACVP_INVALID_ARG;
            break;
        }
	break;
    case ACVP_DSA_LN2048_224:
        return (acvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value));
	break;
    case ACVP_DSA_LN2048_256:
        return (acvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value));
	break;
    case ACVP_DSA_LN3072_256:
        return (acvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value));
	break;
    default:
        return ACVP_INVALID_ARG;
        break;
    }

    return ACVP_SUCCESS;
}


/*
 * The user should call this after invoking acvp_enable_dsa_cap().
 */
ACVP_RESULT acvp_enable_dsa_cap_parm (ACVP_CTX *ctx,
                             ACVP_CIPHER cipher,
                             ACVP_DSA_MODE mode,
                             ACVP_DSA_PARM param,
                             int value
                             )
{
    ACVP_DSA_CAP_MODE           *dsa_cap_mode;
    ACVP_DSA_CAP                *dsa_cap;
    ACVP_CAPS_LIST              *cap_list;
    ACVP_RESULT                 result;


    /*
     * Locate this cipher in the caps array
     */
    cap_list = acvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        ACVP_LOG_ERR("Cap entry not found.");
        return ACVP_NO_CAP;
    }
    dsa_cap = cap_list->cap.dsa_cap;

    /* range check mode */
    dsa_cap_mode = &dsa_cap->dsa_cap_mode[mode-1];
    /*
     * Add the value to the cap
     */
    switch (mode) {
    case ACVP_DSA_MODE_PQGGEN:
        result = acvp_add_dsa_pqggen_parm(ctx, dsa_cap_mode, param, value);
        if (result != ACVP_SUCCESS)
            ACVP_LOG_ERR("Invalid param to enable_dsa_cap_parm.");
        break;
    default:
        return ACVP_INVALID_ARG;
    }

    return (result);
}
