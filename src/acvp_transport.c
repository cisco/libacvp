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
#ifdef USE_MURL
# include <murl/murl.h>
#else
# include <curl/curl.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "acvp.h"
#include "acvp_lcl.h"

#define HTTP_OK    200

#define MAX_TOKEN_LEN 512 
static struct curl_slist* acvp_add_auth_hdr (ACVP_CTX *ctx, struct curl_slist *slist)
{
    int bearer_size;
    char *bearer;

    /*
     * Create the Authorzation header if needed
     */
    if (ctx->jwt_token) {
    	bearer_size = strnlen(ctx->jwt_token, MAX_TOKEN_LEN) + 23;
    	bearer = calloc(1, bearer_size);
	if (!bearer) {
	    ACVP_LOG_ERR("unable to allocate memory.");
	    return slist;
	}
        snprintf(bearer, bearer_size + 1, "Authorization: Bearer %s", ctx->jwt_token);
        slist = curl_slist_append(slist, bearer);
        free(bearer);
    }
    return slist;
}


/*
 * This routine will log the TLS peer certificate chain, which
 * allows auditing the peer identity by inspecting the logs.
 */
static void acvp_curl_log_peer_cert (ACVP_CTX *ctx, CURL *hnd) 
{
    int rv; 
    union {
        struct curl_slist    *to_info;
        struct curl_certinfo *to_certinfo;
    } ptr;
    int i;
    struct curl_slist *slist;
 
    ptr.to_info = NULL;
 
    rv = curl_easy_getinfo(hnd, CURLINFO_CERTINFO, &ptr.to_info);
 
    if(!rv && ptr.to_info) {
	ACVP_LOG_INFO("TLS peer presented the following %d certificates...", ptr.to_certinfo->num_of_certs);
        for(i = 0; i < ptr.to_certinfo->num_of_certs; i++) {
            for(slist = ptr.to_certinfo->certinfo[i]; slist; slist = slist->next) {
		ACVP_LOG_INFO("%s", slist->data);
	    }
        }
    }
}

/*
 * This function uses libcurl to send a simple HTTP GET
 * request with no Content-Type header.
 * TLS peer verification is enabled, but not HTTP authentication.
 * The parameters are:
 *
 * ctx: Ptr to ACVP_CTX, which contains the server name
 * url: URL to use for the GET request
 * writefunc: Function pointer to handle writing the data
 *            from the HTTP body received from the server.
 *
 * Return value is the HTTP status value from the server
 *	    (e.g. 200 for HTTP OK)
 */
static long acvp_curl_http_get (ACVP_CTX *ctx, char *url, void *writefunc)
{
    long http_code = 0;
    CURL *hnd;
    struct curl_slist *slist;

    slist = NULL;
    /*
     * Create the Authorzation header if needed
     */
    slist = acvp_add_auth_hdr(ctx, slist);

    ctx->read_ctr = 0;

    /*
     * Setup Curl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, url);
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.27.0");
    if (slist) {
        curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
    }
    if (ctx->verify_peer && ctx->cacerts_file) {
        curl_easy_setopt(hnd, CURLOPT_CAINFO, ctx->cacerts_file);
        curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(hnd, CURLOPT_CERTINFO, 1L);
    } else {
        curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
        ACVP_LOG_WARN("TLS peer verification has not been enabled.\n");
    }
    curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    if (ctx->tls_cert && ctx->tls_key) {
        curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt(hnd, CURLOPT_SSLCERT, ctx->tls_cert);
        curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
        curl_easy_setopt(hnd, CURLOPT_SSLKEY, ctx->tls_key);
    }
    /*
     * If the caller wants the HTTP data from the server
     * set the callback function
     */
    if (writefunc) {
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, ctx);
        curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, writefunc);
    }

    /*
     * Send the HTTP GET request
     */
    curl_easy_perform(hnd);

    /*
     * Get the cert info from the TLS peer
     */
    if (ctx->verify_peer) {
	acvp_curl_log_peer_cert(ctx, hnd); 
    }

    /*
     * Get the HTTP reponse status code from the server
     */
    curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != HTTP_OK) {
	ACVP_LOG_ERR("HTTP response: %d\n", (int)http_code);
    } 

    curl_easy_cleanup(hnd);
    hnd = NULL;
    if (slist) {
        curl_slist_free_all(slist);
        slist = NULL;
    }

    return (http_code);
}

/*
 * This function uses libcurl to send a simple HTTP POST
 * request with no Content-Type header.
 * TLS peer verification is enabled, but not HTTP authentication.
 * The parameters are:
 *
 * ctx: Ptr to ACVP_CTX, which contains the server name
 * url: URL to use for the GET request
 * data: data to POST to the server
 * writefunc: Function pointer to handle writing the data
 *            from the HTTP body received from the server.
 *
 * Return value is the HTTP status value from the server
 *	    (e.g. 200 for HTTP OK)
 */
static long acvp_curl_http_post (ACVP_CTX *ctx, char *url, char *data, void *writefunc)
{
    long http_code = 0;
    CURL *hnd;
    CURLcode crv;
    struct curl_slist *slist;

    /*
     * Set the Content-Type header in the HTTP request
     */
    slist = NULL;
    slist = curl_slist_append(slist, "Content-Type:application/octet-stream");
    //FIXME: v0.2 spec says to use application/json
    //slist = curl_slist_append(slist, "Content-Type:application/json");
    
    /*
     * Create the Authorzation header if needed
     */
    slist = acvp_add_auth_hdr(ctx, slist);

    ctx->read_ctr = 0;

    /*
     * Setup Curl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, url);
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "libacvp");
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_POST, 1L);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(data));
    //FIXME: we should always to TLS peer auth
    if (ctx->verify_peer && ctx->cacerts_file) {
        curl_easy_setopt(hnd, CURLOPT_CAINFO, ctx->cacerts_file);
        curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(hnd, CURLOPT_CERTINFO, 1L);
    } else {
        curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
        ACVP_LOG_WARN("TLS peer verification has not been enabled.");
    }
    curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    if (ctx->tls_cert && ctx->tls_key) {
        curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt(hnd, CURLOPT_SSLCERT, ctx->tls_cert);
        curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
        curl_easy_setopt(hnd, CURLOPT_SSLKEY, ctx->tls_key);
    }

    /*
     * If the caller wants the HTTP data from the server
     * set the callback function
     */
    if (writefunc) {
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, ctx);
        curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, writefunc);
    }

    /*
     * Send the HTTP POST request
     */
    crv = curl_easy_perform(hnd);
    if (crv != CURLE_OK) {
        ACVP_LOG_ERR("Curl failed with code %d (%s)\n", crv, curl_easy_strerror(crv));
    }

    /*
     * Get the cert info from the TLS peer
     */
    if (ctx->verify_peer) {
	acvp_curl_log_peer_cert(ctx, hnd); 
    }

    /*
     * Get the HTTP reponse status code from the server
     */
    curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != HTTP_OK) {
	ACVP_LOG_ERR("HTTP response: %d\n", (int)http_code);
    }

    curl_easy_cleanup(hnd);
    hnd = NULL;
    curl_slist_free_all(slist);
    slist = NULL;

    return (http_code);
}

/*
 * This is a callback used by curl to send the HTTP body
 * to the application (us).  We will store the HTTP body
 * on the ACVP_CTX in one of the transitory fields.
 */
static size_t acvp_curl_write_upld_func(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    ACVP_CTX *ctx = (ACVP_CTX*)userdata;
    char *http_buf;

    if (size != 1) {
        fprintf(stderr, "\ncurl size not 1\n");
        return 0;
    }

    if (!ctx->upld_buf) {
        ctx->upld_buf = calloc(1, ACVP_KAT_BUF_MAX);
        if (!ctx->upld_buf) {
            fprintf(stderr, "\nmalloc failed in curl write upld func\n");
            return 0;
        }
    }
    http_buf = ctx->upld_buf;

    if ((ctx->read_ctr + nmemb) > ACVP_KAT_BUF_MAX) {
        fprintf(stderr, "\nKAT is too large\n");
        return 0;
    }

    memcpy(&http_buf[ctx->read_ctr], ptr, nmemb);
    http_buf[ctx->read_ctr+nmemb] = 0;
    ctx->read_ctr += nmemb;

    return nmemb;
}


/*
 * This is a callback used by curl to send the HTTP body
 * to the application (us).  We will store the HTTP body
 * on the ACVP_CTX in one of the transitory fields.
 */
static size_t acvp_curl_write_kat_func(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    ACVP_CTX *ctx = (ACVP_CTX*)userdata;
    char *json_buf;

    if (size != 1) {
        fprintf(stderr, "\ncurl size not 1\n");
        return 0;
    }

    if (!ctx->kat_buf) {
        ctx->kat_buf = calloc(1, ACVP_KAT_BUF_MAX);
        if (!ctx->kat_buf) {
            fprintf(stderr, "\nmalloc failed in curl write kat func\n");
            return 0;
        }
    }
    json_buf = ctx->kat_buf;

    if ((ctx->read_ctr + nmemb) > ACVP_KAT_BUF_MAX) {
        fprintf(stderr, "\nKAT is too large\n");
        return 0;
    }

    memcpy(&json_buf[ctx->read_ctr], ptr, nmemb);
    json_buf[ctx->read_ctr+nmemb] = 0;
    ctx->read_ctr += nmemb;

    return nmemb;
}

/*
 * This is a callback used by curl to send the HTTP body
 * to the application (us).  We will store the HTTP body
 * on the ACVP_CTX in one of the transitory fields.
 */
static size_t acvp_curl_write_register_func(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    ACVP_CTX *ctx = (ACVP_CTX*)userdata;
    char *json_buf;

    if (size != 1) {
        fprintf(stderr, "\ncurl size not 1\n");
        return 0;
    }

    if (!ctx->reg_buf) {
        ctx->reg_buf = calloc(1, ACVP_REG_BUF_MAX);
        if (!ctx->reg_buf) {
            fprintf(stderr, "\nmalloc failed in curl write reg func\n");
            return 0;
        }
    }
    json_buf = ctx->reg_buf;

    if ((ctx->read_ctr + nmemb) > ACVP_REG_BUF_MAX) {
        fprintf(stderr, "\nRegister response is too large\n");
        return 0;
    }

    memcpy(&json_buf[ctx->read_ctr], ptr, nmemb);
    json_buf[ctx->read_ctr+nmemb] = 0;
    ctx->read_ctr += nmemb;

    return nmemb;
}


/*
 * This is the transport function used within libacvp to register
 * the DUT with the ACVP server.
 *
 * The reg parameter is the JSON encoded registration message that
 * will be sent to the server.
 */
ACVP_RESULT acvp_send_register(ACVP_CTX *ctx, char *reg)
{
    int rv;
    char url[512]; //TODO: 512 is an arbitrary limit

    memset(url, 0x0, 512);
    snprintf(url, 511, "https://%s:%d/%svalidation/acvp/register", ctx->server_name, ctx->server_port, ctx->path_segment);

    rv = acvp_curl_http_post(ctx, url, reg, &acvp_curl_write_register_func);
    if (rv != HTTP_OK) {
        ACVP_LOG_ERR("Unable to register with ACVP server. curl rv=%d\n", rv);
	ACVP_LOG_ERR("%s\n", ctx->reg_buf);
        return ACVP_TRANSPORT_FAIL;
    }

    /*
     * Update user with status
     */ 
    ACVP_LOG_STATUS("Successfully received registration response from ACVP server");

    return ACVP_SUCCESS;
}

/*
 * This is the top level function used within libacvp to retrieve
 * a KAT vector set from the ACVP server.
 */
ACVP_RESULT acvp_retrieve_vector_set(ACVP_CTX *ctx, int vs_id)
{
    int rv;
    char url[512]; //TODO: 512 is an arbitrary limit

    memset(url, 0x0, 512);
    snprintf(url, 511, "https://%s:%d/%svalidation/acvp/vectors?vsId=%d", ctx->server_name, ctx->server_port, ctx->path_segment, vs_id);

    ACVP_LOG_STATUS("GET acvp/validation/acvp/vectors?vsId=%d", vs_id);
    if (ctx->kat_buf) {
        memset(ctx->kat_buf, 0x0, ACVP_KAT_BUF_MAX);
    }
    rv = acvp_curl_http_get(ctx, url, &acvp_curl_write_kat_func);
    if (rv != HTTP_OK) {
        ACVP_LOG_ERR("Unable to get vectors from server. curl rv=%d\n", rv);
	ACVP_LOG_ERR("%s\n", ctx->kat_buf);
        return ACVP_TRANSPORT_FAIL;
    }

    /*
     * Update user with status
     */
    ACVP_LOG_STATUS("KAT vector set response received");

    return ACVP_SUCCESS;
}


/*
 * This function is used to submit a vector set response
 * to the ACV server.
 */
ACVP_RESULT acvp_submit_vector_responses(ACVP_CTX *ctx)
{
    int rv;
    char url[512]; //TODO: 512 is an arbitrary limit
    char *resp;

    memset(url, 0x0, 512);
    snprintf(url, 511, "https://%s:%d/%svalidation/acvp/vectors?vsId=%d", ctx->server_name, ctx->server_port, ctx->path_segment, ctx->vs_id);

    resp = json_serialize_to_string_pretty(ctx->kat_resp);
    rv = acvp_curl_http_post(ctx, url, resp, &acvp_curl_write_upld_func);
    json_value_free(ctx->kat_resp);
    ctx->kat_resp = NULL;
    json_free_serialized_string(resp);
    if (rv != HTTP_OK) {
        ACVP_LOG_ERR("Unable to upload vector set to ACVP server. curl rv=%d\n", rv);
	ACVP_LOG_ERR("%s\n", ctx->upld_buf);
        return ACVP_TRANSPORT_FAIL;
    }

    ACVP_LOG_STATUS("Successfully submitted KAT vector responses");
    return ACVP_SUCCESS;
}

/*
 * This is the top level function used within libacvp to retrieve
 * the test result for a given KAT vector set from the ACVP server.
 */
ACVP_RESULT acvp_retrieve_vector_set_result(ACVP_CTX *ctx, int vs_id)
{
    int rv;
    char url[512]; //TODO: 512 is an arbitrary limit

    memset(url, 0x0, 512);
    snprintf(url, 511, "https://%s:%d/%svalidation/acvp/results?vsId=%d", ctx->server_name, ctx->server_port, ctx->path_segment, vs_id);

    if (ctx->kat_buf) {
        memset(ctx->kat_buf, 0x0, ACVP_KAT_BUF_MAX);
    }
    rv = acvp_curl_http_get(ctx, url, &acvp_curl_write_kat_func);
    if (rv != HTTP_OK) {
        ACVP_LOG_ERR("Unable to get vector result from server. curl rv=%d\n", rv);
	ACVP_LOG_ERR("%s\n", ctx->kat_buf);
        return ACVP_TRANSPORT_FAIL;
    }

    /*
     * Update user with status
     */
    ACVP_LOG_STATUS("Successfully retrieved KAT vector set response");

    return ACVP_SUCCESS;
}


