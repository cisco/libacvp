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
 * **************** ALERT *****************
 * This array must stay aligned with ACVP_SYM_CIPHER in acvp.h
 */
char *sym_ciph_name[] = {
    ACVP_ALG_AES_ECB,
    ACVP_ALG_AES_CBC,
    ACVP_ALG_AES_CTR,
    ACVP_ALG_AES_GCM,
    ACVP_ALG_AES_CCM,
    ACVP_ALG_AES_XTS,
    ACVP_ALG_AES_KW,
    ACVP_ALG_AES_KWP,
    ACVP_ALG_TDES_ECB,
    ACVP_ALG_TDES_CBC,
    ACVP_ALG_TDES_CTR
};
    
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
    ACVP_RESULT (*crypto_handler)(ACVP_CIPHER_TC *test_case));
static void acvp_cap_free_sl(ACVP_SL_LIST *list); 


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
#define ACVP_ALG_MAX 5
static ACVP_ALG_HANDLER alg_tbl[ACVP_ALG_MAX] = {
    {ACVP_AES_GCM,         &acvp_aes_kat_handler},
    {ACVP_AES_CCM,         &acvp_aes_kat_handler},
    {ACVP_AES_ECB,         &acvp_aes_kat_handler},
    {ACVP_AES_CBC,         &acvp_aes_kat_handler},
    {ACVP_AES_CTR,         &acvp_aes_kat_handler},
};



/*
 * This is the first function the user should invoke to allocate
 * a new context to be used for the test session.
 */
ACVP_RESULT acvp_create_test_session(ACVP_CTX **ctx,
                                     ACVP_RESULT (*progress_cb)(char *msg))
{
    *ctx = malloc(sizeof(ACVP_CTX));
    if (!*ctx) {
        return ACVP_MALLOC_FAIL;
    }
    memset(*ctx, 0x0, sizeof(ACVP_CTX));
    (*ctx)->path_segment = strdup(ACVP_PATH_SEGMENT_DEFAULT);

    if (progress_cb) {
        (*ctx)->test_progress_cb = progress_cb;
    }

    return ACVP_SUCCESS;
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
        if (ctx->kat_resp) json_value_free(ctx->kat_resp);
        if (ctx->server_name) free(ctx->server_name);
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
		free(cap_entry->cap.sym_cap);
		acvp_cap_free_sl(cap_entry->cap.sym_cap->keylen);
		acvp_cap_free_sl(cap_entry->cap.sym_cap->ptlen);
		acvp_cap_free_sl(cap_entry->cap.sym_cap->ivlen);
		acvp_cap_free_sl(cap_entry->cap.sym_cap->aadlen);
		acvp_cap_free_sl(cap_entry->cap.sym_cap->taglen);
                free(cap_entry);
                cap_entry = cap_e2;
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
	ACVP_SYM_CIPHER cipher, 
	ACVP_SYM_CIPH_DIR dir,
	ACVP_SYM_CIPH_IVGEN_SRC ivgen_source,
	ACVP_SYM_CIPH_IVGEN_MODE ivgen_mode,
        ACVP_RESULT (*crypto_handler)(ACVP_CIPHER_TC *test_case))
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
    cap->cipher = cipher;
    cap->direction = dir;
    cap->ivgen_source = ivgen_source;
    cap->ivgen_mode = ivgen_mode;

    return (acvp_append_sym_cipher_caps_entry(ctx, cap, crypto_handler));
}

/*
 * The user should call this after invoking acvp_enable_sym_cipher_cap()
 * to specify the supported key lengths, PT lengths, AAD lengths, IV
 * lengths, and tag lengths.  This is call multipe times, once for each
 * length supported.
 */
ACVP_RESULT acvp_enable_sym_cipher_cap_parm(
	ACVP_CTX *ctx, 
	ACVP_SYM_CIPHER cipher, 
	ACVP_SYM_CIPH_PARM parm,
	int length) {

    ACVP_CAPS_LIST *cap;

    /*
     * Locate this cipher in the caps array
     */
    cap = acvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        acvp_log_msg(ctx, "Cap entry not found, use acvp_enable_sym_cipher_cap() first.");
	return ACVP_NO_CAP;
    }

    /*
     * Add the length to the cap
     */
    //TODO: need to add validation logic to verify incoming length
    //      is within range for each length type
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

/*
 * This function is used by the application to specify the
 * ACVP server address and port#.
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

static ACVP_RESULT acvp_build_register(ACVP_CTX *ctx, char **reg)
{
    ACVP_CAPS_LIST *cap_entry;
    ACVP_SL_LIST *sl_list;

    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    JSON_Value *oe_val = NULL;
    JSON_Object *oe_obj = NULL;
    JSON_Value *oee_val = NULL;
    JSON_Object *oee_obj = NULL;
    JSON_Array *caps_arr = NULL;
    JSON_Array *opts_arr = NULL;
    JSON_Array *mode_arr = NULL;
    JSON_Value *caps_val = NULL;
    JSON_Object *caps_obj = NULL;
    JSON_Value *cap_val = NULL;
    JSON_Object *cap_obj = NULL;

    val = json_value_init_object();
    obj = json_value_get_object(val);
    json_object_set_string(obj, "acv_version", "0.2");

    oe_val = json_value_init_object();
    oe_obj = json_value_get_object(oe_val);
    //TODO: need public API to allow app to specify some of these values
    json_object_set_string(oe_obj, "vendor_name", "VendorName");
    json_object_set_string(oe_obj, "vendor_url", "www.vendor.org");
    json_object_set_string(oe_obj, "contact", "John Doe");
    json_object_set_string(oe_obj, "contact_email", "jdoe@vendor.org");
    json_object_set_string(oe_obj, "module_name", "Crypto Module 1.0");
    json_object_set_string(oe_obj, "module_type", "Software");

    oee_val = json_value_init_object();
    oee_obj = json_value_get_object(oee_val);
    json_object_set_string(oee_obj, "module_version", "1.0");
    json_object_set_string(oee_obj, "processor", "Intel Woodcrest");
    json_object_set_string(oee_obj, "operating_system", "Linux 3.1");
    json_object_set_value(oe_obj, "operational_environment", oee_val);

    json_object_set_string(oe_obj, "implementation_description", "Sample crypto module for demonstrating ACV protocol.");
    json_object_set_value(obj, "oe_information", oe_val);

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
	    cap_val = json_value_init_object();
	    cap_obj = json_value_get_object(cap_val);

	    json_object_set_string(cap_obj, "algorithm", sym_ciph_name[cap_entry->cap.sym_cap->cipher]);

	    /*
	     * Set the direction capability
	     */
	    json_object_set_value(cap_obj, "direction", json_value_init_array());
	    mode_arr = json_object_get_array(cap_obj, "direction");
	    if (cap_entry->cap.sym_cap->direction == ACVP_DIR_ENCRYPT ||
	        cap_entry->cap.sym_cap->direction == ACVP_DIR_BOTH) {
		json_array_append_string(mode_arr, "encrypt");
	    }
	    if (cap_entry->cap.sym_cap->direction == ACVP_DIR_DECRYPT ||
	        cap_entry->cap.sym_cap->direction == ACVP_DIR_BOTH) {
		json_array_append_string(mode_arr, "decrypt");
	    }

	    /*
	     * Set the IV generation source if applicable 
	     */
	    switch(cap_entry->cap.sym_cap->ivgen_source) {
	    case ACVP_IVGEN_SRC_INT:
		json_object_set_string(cap_obj, "ivgen", "internal");
		break;
	    case ACVP_IVGEN_SRC_EXT:
		json_object_set_string(cap_obj, "ivgen", "external");
		break;
	    default:
		/* do nothing, this is an optional capability */
		break;
	    }

	    /*
	     * Set the IV generation mode if applicable
	     */
	    switch(cap_entry->cap.sym_cap->ivgen_mode) {
	    case ACVP_IVGEN_MODE_821:
		json_object_set_string(cap_obj, "ivgenmode", "8.2.1");
		break;
	    case ACVP_IVGEN_MODE_822:
		json_object_set_string(cap_obj, "ivgenmode", "8.2.2");
		break;
	    default:
		/* do nothing, this is an optional capability */
		break;
	    }

	    /*
	     * Set the supported key lengths
	     */
	    json_object_set_value(cap_obj, "keylen", json_value_init_array());
	    opts_arr = json_object_get_array(cap_obj, "keylen");
	    sl_list = cap_entry->cap.sym_cap->keylen;
	    while (sl_list) {
		json_array_append_number(opts_arr, sl_list->length);
		sl_list = sl_list->next;
	    }

	    /*
	     * Set the supported tag lengths (for AEAD ciphers)
	     */
	    json_object_set_value(cap_obj, "taglen", json_value_init_array());
	    opts_arr = json_object_get_array(cap_obj, "taglen");
	    sl_list = cap_entry->cap.sym_cap->taglen;
	    while (sl_list) {
		json_array_append_number(opts_arr, sl_list->length);
		sl_list = sl_list->next;
	    }


	    /*
	     * Set the supported IV lengths
	     */
	    json_object_set_value(cap_obj, "ivlen", json_value_init_array());
	    opts_arr = json_object_get_array(cap_obj, "ivlen");
	    sl_list = cap_entry->cap.sym_cap->ivlen;
	    while (sl_list) {
		json_array_append_number(opts_arr, sl_list->length);
		sl_list = sl_list->next;
	    }

	    /*
	     * Set the supported plaintext lengths
	     */
	    json_object_set_value(cap_obj, "ptlen", json_value_init_array());
	    opts_arr = json_object_get_array(cap_obj, "ptlen");
	    sl_list = cap_entry->cap.sym_cap->ptlen;
	    while (sl_list) {
		json_array_append_number(opts_arr, sl_list->length);
		sl_list = sl_list->next;
	    }

	    /*
	     * Set the supported AAD lengths (for AEAD ciphers)
	     */
	    json_object_set_value(cap_obj, "aadlen", json_value_init_array());
	    opts_arr = json_object_get_array(cap_obj, "aadlen");
	    sl_list = cap_entry->cap.sym_cap->aadlen;
	    while (sl_list) {
		json_array_append_number(opts_arr, sl_list->length);
		sl_list = sl_list->next;
	    }

	    json_array_append_value(caps_arr, cap_val);
	    
	    /* Advance to next cap entry */
            cap_entry = cap_entry->next;
        }
    } 

    /*
     * Add the entire caps exchange section to the top object
     */
    json_object_set_value(obj, "capability_exchange", caps_val);

    //*reg = json_serialize_to_string(val);
    *reg = json_serialize_to_string_pretty(val);
    json_value_free(val);
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

    rv = acvp_build_register(ctx, &reg);
    if (rv != ACVP_SUCCESS) {
        acvp_log_msg(ctx, "Unable to build register message");
        return rv;
    }

    //FIXME
    printf("%s\n", reg);

    rv = acvp_send_register(ctx, reg);
    if (rv == ACVP_SUCCESS) {
        printf("\n%s\n", ctx->reg_buf);
        rv = acvp_parse_register(ctx);
    }

    json_free_serialized_string(reg);

    return (rv);
}

static ACVP_RESULT acvp_append_sym_cipher_caps_entry(
	ACVP_CTX *ctx,
	ACVP_SYM_CIPHER_CAP *cap,
        ACVP_RESULT (*crypto_handler)(ACVP_CIPHER_TC *test_case))
{
    ACVP_CAPS_LIST *cap_entry, *cap_e2;

    cap_entry = calloc(1, sizeof(ACVP_CAPS_LIST));
    if (!cap_entry) {
        return ACVP_MALLOC_FAIL;
    }
    cap_entry->cap.sym_cap = cap;
    cap_entry->crypto_handler = crypto_handler;

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

static ACVP_RESULT acvp_append_vs_entry(ACVP_CTX *ctx, int vs_id)
{
    ACVP_VS_LIST *vs_entry, *vs_e2;

    vs_entry = malloc(sizeof(ACVP_VS_LIST));
    if (!vs_entry) {
        return ACVP_MALLOC_FAIL;
    }
    memset(vs_entry, 0x0, sizeof(ACVP_VS_LIST));
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

    val = json_parse_string_with_comments(json_buf);
    if (!val) {
        acvp_log_msg(ctx, "JSON parse error");
        return ACVP_JSON_ERR;
    }
    obj = json_value_get_object(val);

    jwt = json_object_get_string(obj, "access_token");
    if (!jwt) {
        json_value_free(val);
        acvp_log_msg(ctx, "No access_token provided in registration response");
        return ACVP_NO_TOKEN;
    } else {
        i = strnlen(jwt, ACVP_JWT_TOKEN_MAX+1);
        if (i > ACVP_JWT_TOKEN_MAX) {
            json_value_free(val);
            acvp_log_msg(ctx, "access_token too large");
            return ACVP_NO_TOKEN;
        }
        ctx->jwt_token = malloc(i+1);
        strncpy(ctx->jwt_token, jwt, i);
        ctx->jwt_token[i] = 0;
        acvp_log_msg(ctx, "JWT: %s", ctx->jwt_token);
    }

    cap_obj = json_object_get_object(obj, "capability_response");
    //const char *op = json_object_get_string(obj, "operation");
    vect_sets = json_object_get_array(cap_obj, "vector_sets");
    vs_cnt = json_array_get_count(vect_sets);
    for (i = 0; i < vs_cnt; i++) {
        vs_val = json_array_get_value(vect_sets, i);
        vs_obj = json_value_get_object(vs_val);
        vs_id = json_object_get_number(vs_obj, "vs_id");

        rv = acvp_append_vs_entry(ctx, vs_id);
        if (rv != ACVP_SUCCESS) {
            json_value_free(val);
            return rv;
        }
        acvp_log_msg(ctx, "Received vs_id=%d", vs_id);
    }

    json_value_free(val);

    acvp_log_msg(ctx, "Successfully processed registration response from server");

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

    vs_entry = ctx->vs_list;
    while (vs_entry) {
        rv = acvp_process_vsid(ctx, vs_entry->vs_id);
        vs_entry = vs_entry->next;
    }

    return (rv);
}

ACVP_RESULT acvp_retry_handler(ACVP_CTX *ctx, unsigned int retry_period)
{
    acvp_log_msg(ctx, "KAT values not ready, server requests we wait and try again...");
    if (retry_period <= 0 || retry_period > ACVP_RETRY_TIME_MAX) {
        retry_period = ACVP_RETRY_TIME_MAX;
        acvp_log_msg(ctx, "Warning: retry_period not found, using max retry period!");
    }
    sleep(retry_period);

    return ACVP_KAT_DOWNLOAD_RETRY;
}


//TODO
//ACVP_RESULT acvp_check_test_results(ACVP_CTX *ctx);



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
        printf("\n%s\n", ctx->kat_buf);
        val = json_parse_string_with_comments(json_buf);
        if (!val) {
            acvp_log_msg(ctx, "JSON parse error");
            return ACVP_JSON_ERR;
        }
        obj = json_value_get_object(val);
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
    const char *mode = json_object_get_string(obj, "mode"); //TODO: not using this yet
    ACVP_RESULT rv;

    if (!alg) {
        acvp_log_msg(ctx, "JSON parse error: ACV algorithm not found");
        return ACVP_JSON_ERR;
    }

    acvp_log_msg(ctx, "ACV Operation: %s", alg);
    acvp_log_msg(ctx, "ACV Mode: %s", mode);
    acvp_log_msg(ctx, "ACV version: %s", json_object_get_string(obj, "acvp_version_string"));

    for (i = 0; i < ACVP_ALG_MAX; i++) {
        if (!strncmp(alg, sym_ciph_name[alg_tbl[i].cipher], strlen(sym_ciph_name[alg_tbl[i].cipher]))) {
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

    acvp_log_msg(ctx, "Successfully processed KAT vector set");

    return ACVP_SUCCESS;

}
