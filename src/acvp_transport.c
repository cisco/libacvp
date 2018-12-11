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
#define HTTP_UNAUTH    401

#define ACVP_AUTH_BEARER_TITLE_LEN 23

typedef enum acvp_net_action {
    ACVP_NET_ACTION_GET_RESULT = 1,
    ACVP_NET_ACTION_GET_VECTOR_SET,
    ACVP_NET_ACTION_GET_SAMPLE,
    ACVP_NET_ACTION_POST_VECTOR_RESP
} ACVP_NET_ACTION;

static struct curl_slist *acvp_add_auth_hdr(ACVP_CTX *ctx, struct curl_slist *slist) {
    int bearer_size;
    char *bearer;

    /*
     * Create the Authorzation header if needed
     */
    if (ctx->jwt_token) {
        bearer_size = strnlen(ctx->jwt_token, ACVP_JWT_TOKEN_MAX) + ACVP_AUTH_BEARER_TITLE_LEN;
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
static void acvp_curl_log_peer_cert(ACVP_CTX *ctx, CURL *hnd) {
    int rv;

    union {
        struct curl_slist *to_info;
        struct curl_certinfo *to_certinfo;
    } ptr;
    int i;
    struct curl_slist *slist;

    ptr.to_certinfo = NULL;

    rv = curl_easy_getinfo(hnd, CURLINFO_CERTINFO, &ptr.to_certinfo);

    if (!rv && ptr.to_certinfo) {
        ACVP_LOG_INFO("TLS peer presented the following %d certificates...", ptr.to_certinfo->num_of_certs);
        for (i = 0; i < ptr.to_certinfo->num_of_certs; i++) {
            for (slist = ptr.to_certinfo->certinfo[i]; slist; slist = slist->next) {
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
static long acvp_curl_http_get(ACVP_CTX *ctx, char *url, void *writefunc) {
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
    curl_easy_setopt(hnd, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
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
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != HTTP_OK) {
        ACVP_LOG_ERR("HTTP response: %d\n", (int)http_code);
    }

    curl_easy_cleanup(hnd);
    hnd = NULL;
    if (slist) {
        curl_slist_free_all(slist);
        slist = NULL;
    }

    return http_code;
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
static long acvp_curl_http_post(ACVP_CTX *ctx, char *url, char *data, void *writefunc) {
    long http_code = 0;
    CURL *hnd;
    CURLcode crv;
    struct curl_slist *slist;

    /*
     * Set the Content-Type header in the HTTP request
     */
    slist = NULL;
    slist = curl_slist_append(slist, "Content-Type:application/json");

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
    curl_easy_setopt(hnd, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
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
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != HTTP_OK) {
        ACVP_LOG_ERR("HTTP response: %d\n", (int)http_code);
    }

    curl_easy_cleanup(hnd);
    hnd = NULL;
    curl_slist_free_all(slist);
    slist = NULL;

    return http_code;
}

/*
 * This is a callback used by curl to send the HTTP body
 * to the application (us).  We will store the HTTP body
 * on the ACVP_CTX in one of the transitory fields.
 */
static size_t acvp_curl_write_upld_func(void *ptr, size_t size, size_t nmemb, void *userdata) {
    ACVP_CTX *ctx = (ACVP_CTX *)userdata;
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
    http_buf[ctx->read_ctr + nmemb] = 0;
    ctx->read_ctr += nmemb;

    return nmemb;
}

/*
 * This is a callback used by curl to send the HTTP body
 * to the application (us).  We will store the HTTP body
 * on the ACVP_CTX in one of the transitory fields.
 */
static size_t acvp_curl_write_vs_func(void *ptr, size_t size, size_t nmemb, void *userdata) {
    ACVP_CTX *ctx = (ACVP_CTX *)userdata;
    char *json_buf;

    if (size != 1) {
        fprintf(stderr, "\ncurl size not 1\n");
        return 0;
    }

    if (!ctx->test_sess_buf) {
        ctx->test_sess_buf = calloc(1, ACVP_ANS_BUF_MAX);
        if (!ctx->test_sess_buf) {
            fprintf(stderr, "\nmalloc failed in curl write ans func\n");
            return 0;
        }
    }
    json_buf = ctx->test_sess_buf;

    if ((ctx->read_ctr + nmemb) > ACVP_ANS_BUF_MAX) {
        fprintf(stderr, "\nAnswer response is too large\n");
        return 0;
    }

    memcpy(&json_buf[ctx->read_ctr], ptr, nmemb);
    json_buf[ctx->read_ctr + nmemb] = 0;
    ctx->read_ctr += nmemb;

    return nmemb;
}

/*
 * This is a callback used by curl to send the HTTP body
 * to the application (us).  We will store the HTTP body
 * on the ACVP_CTX in one of the transitory fields.
 */
static size_t acvp_curl_write_sample_func(void *ptr, size_t size, size_t nmemb, void *userdata) {
    ACVP_CTX *ctx = (ACVP_CTX *)userdata;
    char *json_buf;

    if (size != 1) {
        fprintf(stderr, "\ncurl size not 1\n");
        return 0;
    }

    if (!ctx->sample_buf) {
        ctx->sample_buf = calloc(1, ACVP_ANS_BUF_MAX);
        if (!ctx->sample_buf) {
            fprintf(stderr, "\nmalloc failed in curl write ans func\n");
            return 0;
        }
    }
    json_buf = ctx->sample_buf;

    if ((ctx->read_ctr + nmemb) > ACVP_ANS_BUF_MAX) {
        fprintf(stderr, "\nAnswer response is too large\n");
        return 0;
    }

    memcpy(&json_buf[ctx->read_ctr], ptr, nmemb);
    json_buf[ctx->read_ctr + nmemb] = 0;
    ctx->read_ctr += nmemb;

    return nmemb;
}

/*
 * This is a callback used by curl to send the HTTP body
 * to the application (us).  We will store the HTTP body
 * on the ACVP_CTX in one of the transitory fields.
 */
static size_t acvp_curl_write_kat_func(void *ptr, size_t size, size_t nmemb, void *userdata) {
    ACVP_CTX *ctx = (ACVP_CTX *)userdata;
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
    json_buf[ctx->read_ctr + nmemb] = 0;
    ctx->read_ctr += nmemb;

    return nmemb;
}

/*
 * This is a callback used by curl to send the HTTP body
 * to the application (us).  We will store the HTTP body
 * on the ACVP_CTX in one of the transitory fields.
 */
static size_t acvp_curl_write_register_func(void *ptr, size_t size, size_t nmemb, void *userdata) {
    ACVP_CTX *ctx = (ACVP_CTX *)userdata;
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
    json_buf[ctx->read_ctr + nmemb] = 0;
    ctx->read_ctr += nmemb;

    return nmemb;
}

/*
 * This is the internal send function that takes the URI as an extra
 * parameter. This removes repeated code without having to change the
 * API that the library uses to send registrations
 */
static ACVP_RESULT acvp_send_internal(ACVP_CTX *ctx, char *data, char *uri) {
    int rv;
    char url[ACVP_ATTR_URL_MAX];

    if (!ctx) {
        ACVP_LOG_ERR("No CTX to send");
        return ACVP_NO_CTX;
    }

    if (!ctx->server_port || !ctx->server_name) {
        ACVP_LOG_ERR("Call acvp_set_server to fill in server name and port");
        return ACVP_MISSING_ARG;
    }

    if (!data) {
        ACVP_LOG_ERR("No data to send");
        return ACVP_NO_DATA;
    }

    memset(url, 0x0, ACVP_ATTR_URL_MAX);
    snprintf(url, ACVP_ATTR_URL_MAX - 1, "https://%s:%d/%s%s%s", ctx->server_name, ctx->server_port,
             ctx->api_context, ctx->path_segment, uri);

    /*
     * only need to clear jwt if logging in
     */
    if (strncmp(uri, "login", 5) == 0) {
        if (ctx->jwt_token) {
            free(ctx->jwt_token);
        }
        ctx->jwt_token = NULL;
    }

    rv = acvp_curl_http_post(ctx, url, data, &acvp_curl_write_register_func);
    if (rv != HTTP_OK) {
        ACVP_LOG_ERR("Unable to register |%s| with ACVP server. curl rv=%d\n", url, rv);
        printf("%s", ctx->reg_buf);
        return ACVP_TRANSPORT_FAIL;
    }

    /*
     * Update user with status
     */
    ACVP_LOG_STATUS("Successfully received response from ACVP server");

    return ACVP_SUCCESS;
}

/*
 * This is the transport function used within libacvp to register
 * the DUT attributes with the ACVP server.
 *
 * The reg parameter is the JSON encoded registration message that
 * will be sent to the server.
 */
#define ACVP_VENDORS_URI "vendors"
ACVP_RESULT acvp_send_vendor_registration(ACVP_CTX *ctx, char *reg) {
    return acvp_send_internal(ctx, reg, ACVP_VENDORS_URI);
}

/*
 * This is the transport function used within libacvp to register
 * the DUT attributes with the ACVP server.
 *
 * The reg parameter is the JSON encoded registration message that
 * will be sent to the server.
 */
#define ACVP_MODULES_URI "modules"
ACVP_RESULT acvp_send_module_registration(ACVP_CTX *ctx, char *reg) {
    return acvp_send_internal(ctx, reg, ACVP_MODULES_URI);
}

/*
 * This is the transport function used within libacvp to register
 * the DUT attributes with the ACVP server.
 *
 * The reg parameter is the JSON encoded registration message that
 * will be sent to the server.
 */
#define ACVP_DEPS_URI "dependencies"
ACVP_RESULT acvp_send_dep_registration(ACVP_CTX *ctx, char *reg) {
    return acvp_send_internal(ctx, reg, ACVP_DEPS_URI);
}

/*
 * This is the transport function used within libacvp to register
 * the DUT attributes with the ACVP server.
 *
 * The reg parameter is the JSON encoded registration message that
 * will be sent to the server.
 */
#define ACVP_OES_URI "oes"
ACVP_RESULT acvp_send_oe_registration(ACVP_CTX *ctx, char *reg) {
    return acvp_send_internal(ctx, reg, ACVP_OES_URI);
}

/*
 * This is the transport function used within libacvp to register
 * the DUT attributes with the ACVP server.
 *
 * The reg parameter is the JSON encoded registration message that
 * will be sent to the server.
 */
#define ACVP_TEST_SESSIONS_URI "testSessions"
ACVP_RESULT acvp_send_test_session_registration(ACVP_CTX *ctx, char *reg) {
    return acvp_send_internal(ctx, reg, ACVP_TEST_SESSIONS_URI);
}

/*
 * This is the transport function used within libacvp to login before
 * it is able to register parameters with the server
 *
 * The reg parameter is the JSON encoded registration message that
 * will be sent to the server.
 */
#define ACVP_LOGIN_URI "login"
ACVP_RESULT acvp_send_login(ACVP_CTX *ctx, char *login) {
    return acvp_send_internal(ctx, login, ACVP_LOGIN_URI);
}

#define JWT_EXPIRED_STR "JWT expired"
#define JWT_EXPIRED_STR_LEN 11
#define JWT_INVALID_STR "JWT signature does not match"
#define JWT_INVALID_STR_LEN 28
static ACVP_RESULT inspect_http_code(ACVP_CTX *ctx, int code) {
    ACVP_RESULT result = ACVP_TRANSPORT_FAIL; /* Generic failure */
    JSON_Value *root_value = NULL;
    const JSON_Object *obj = NULL;
    const char *err_str = NULL;

    if (code == HTTP_OK) {
        /* 200 */
        return ACVP_SUCCESS;
    }

    if (code == HTTP_UNAUTH) {
        if (ctx->sample_buf) {
            root_value = json_parse_string(ctx->sample_buf);
        } else if (ctx->kat_buf) {
            root_value = json_parse_string(ctx->kat_buf);
        }

        obj = json_value_get_object(root_value);
        if (!obj) {
            ACVP_LOG_ERR("HTTP body doesn't contain top-level JSON object");
            goto end;
        }

        err_str = json_object_get_string(obj, "error");
        if (!err_str) {
            ACVP_LOG_ERR("JSON object doesn't contain 'error'");
            goto end;
        }

        if (strncmp(err_str, JWT_EXPIRED_STR, JWT_EXPIRED_STR_LEN) == 0) {
            result = ACVP_JWT_EXPIRED;
            goto end;
        } else if (strncmp(err_str, JWT_INVALID_STR, JWT_INVALID_STR_LEN) == 0) {
            result = ACVP_JWT_INVALID;
            goto end;
        }
    }

end:
    if (root_value) json_value_free(root_value);

    return result;
}

static ACVP_RESULT execute_network_action(ACVP_CTX *ctx,
                                          ACVP_NET_ACTION action,
                                          char *url,
                                          void *curl_callback) {
    ACVP_RESULT result = ACVP_TRANSPORT_FAIL;
    char *resp = NULL;
    int rc = 0;

    switch(action) {
    case ACVP_NET_ACTION_GET_RESULT:
    case ACVP_NET_ACTION_GET_VECTOR_SET:
    case ACVP_NET_ACTION_GET_SAMPLE:
        rc = acvp_curl_http_get(ctx, url, curl_callback);
        break;
    case ACVP_NET_ACTION_POST_VECTOR_RESP:
        resp = json_serialize_to_string_pretty(ctx->kat_resp);

        rc = acvp_curl_http_post(ctx, url, resp, curl_callback);
        json_value_free(ctx->kat_resp);
        ctx->kat_resp = NULL;
        break;
    default:
        ACVP_LOG_ERR("Unknown ACVP_NET_ACTION");
        return ACVP_INVALID_ARG;
    }

    /* Peek at the HTTP code */
    result = inspect_http_code(ctx, rc);

    if (result != ACVP_SUCCESS) {
        if (result == ACVP_JWT_EXPIRED) {
            /*
             * Expired JWT
              * We are going to refresh the session
              * and try to obtain a new JWT!
              */
            ACVP_LOG_ERR("JWT authorization has timed out, curl rc=%d.\n"
                         "Refreshing session...", rc);

            result = acvp_refresh(ctx);
            if (result != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JWT refresh failed.");
                goto end;
            }

            /* Try action again after the refresh */
            switch(action) {
            case ACVP_NET_ACTION_GET_RESULT:
            case ACVP_NET_ACTION_GET_VECTOR_SET:
            case ACVP_NET_ACTION_GET_SAMPLE:
                rc = acvp_curl_http_get(ctx, url, curl_callback);
                break;
            case ACVP_NET_ACTION_POST_VECTOR_RESP:
                rc = acvp_curl_http_post(ctx, url, resp, curl_callback);
                break;
            }

            result = inspect_http_code(ctx, rc);
            if (result != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Refreshed + retried, HTTP transport fails. curl rc=%d\n", rc);
                goto end;
            }
        } else if (result == ACVP_JWT_INVALID) {
            /*
             * Invalid JWT
             */
            ACVP_LOG_ERR("JWT invalid. curl rc=%d.\n", rc);
            goto end;
        }

        /* Generic error */
        goto end;
    }

    result = ACVP_SUCCESS;

end:
    /* Log any errors */
    switch(action) {
    case ACVP_NET_ACTION_GET_RESULT:
        if (result != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to get vector result from server. curl rc=%d\n", rc);
            ACVP_LOG_ERR("%s\n", ctx->kat_buf);
        }
        break;
    case ACVP_NET_ACTION_GET_VECTOR_SET:
        if (result != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to get vector set from ACVP server. curl rc=%d\n", rc);
            ACVP_LOG_ERR("%s\n", ctx->kat_buf);
        }
        break;
    case ACVP_NET_ACTION_GET_SAMPLE:
        if (result != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to get vector result samples from server. curl rc=%d\n", rc);
            ACVP_LOG_ERR("%s\n", ctx->sample_buf);
        }
        break;
    case ACVP_NET_ACTION_POST_VECTOR_RESP:
        if (result != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to submit vector set responses. curl rc=%d\n", rc);
            ACVP_LOG_ERR("%s\n", ctx->kat_buf);
        }
        break;
    }

    if (resp) json_free_serialized_string(resp);

    return result;
}

/*
 * This is the top level function used within libacvp to retrieve
 * a KAT vector set from the ACVP server.
 */
ACVP_RESULT acvp_retrieve_vector_set(ACVP_CTX *ctx, char *vsid_url) {
    char url[ACVP_ATTR_URL_MAX];
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!ctx->server_name || !ctx->server_port) {
        ACVP_LOG_ERR("Missing server/port details; call acvp_set_server first");
        return ACVP_MISSING_ARG;
    }

    if (!vsid_url) {
        ACVP_LOG_ERR("Missing vsid_url from retrieve vector set");
        return ACVP_MISSING_ARG;
    }

    memset(url, 0x0, ACVP_ATTR_URL_MAX);
    snprintf(url, ACVP_ATTR_URL_MAX - 1, "https://%s:%d/%s%s", ctx->server_name, ctx->server_port,
             ctx->api_context, vsid_url);

    ACVP_LOG_STATUS("GET %s", url);

    if (ctx->kat_buf) {
        memset(ctx->kat_buf, 0x0, ACVP_KAT_BUF_MAX);
    }

    result = execute_network_action(ctx, ACVP_NET_ACTION_GET_VECTOR_SET,
                                    url, &acvp_curl_write_kat_func);
    if (result != ACVP_SUCCESS) {
        /* Failed to transport */
        ACVP_LOG_ERR("Transport failure.");
        return result;
    }

    ACVP_LOG_STATUS("KAT vector set response received");

    return ACVP_SUCCESS;
}

/*
 * This function is used to submit a vector set response
 * to the ACV server.
 */
ACVP_RESULT acvp_submit_vector_responses(ACVP_CTX *ctx) {
    char url[ACVP_ATTR_URL_MAX];
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!ctx->server_name || !ctx->server_port) {
        ACVP_LOG_ERR("Missing server/port details; call acvp_set_server first");
        return ACVP_MISSING_ARG;
    }

    if (!ctx->vs_id) {
        ACVP_LOG_ERR("Missing vs_id when trying to submit responses");
        return ACVP_MISSING_ARG;
    }

    memset(url, 0x0, ACVP_ATTR_URL_MAX);
    snprintf(url, ACVP_ATTR_URL_MAX - 1, "https://%s:%d/%s%s/results", ctx->server_name, ctx->server_port,
             ctx->api_context, ctx->vsid_url);

    ACVP_LOG_STATUS("Submitting vector responses to %s", url);

    result = execute_network_action(ctx, ACVP_NET_ACTION_POST_VECTOR_RESP,
                                    url, &acvp_curl_write_upld_func);
    if (result != ACVP_SUCCESS) {
        /* Failed to transport */
        ACVP_LOG_ERR("Transport failure.");
        return result;
    }

    ACVP_LOG_STATUS("Finished POSTing KAT vector responses");
    return ACVP_SUCCESS;
}

/*
 * This is the top level function used within libacvp to retrieve
 * the test result for a given KAT vector set from the ACVP server.
 * It can be used to get the results for an entire session, or
 * more specifically for a vectorSet
 */
ACVP_RESULT acvp_retrieve_result(ACVP_CTX *ctx, char *api_url) {
    char url[ACVP_ATTR_URL_MAX];
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!ctx->server_name || !ctx->server_port) {
        ACVP_LOG_ERR("Missing server/port details; call acvp_set_server first");
        return ACVP_MISSING_ARG;
    }

    if (!api_url) {
        ACVP_LOG_ERR("Missing vs_id from retrieve vector set");
        return ACVP_MISSING_ARG;
    }

    memset(url, 0x0, ACVP_ATTR_URL_MAX);
    snprintf(url, ACVP_ATTR_URL_MAX - 1, "https://%s:%d/%s%s/results", ctx->server_name, ctx->server_port,
             ctx->api_context, api_url);

    if (ctx->kat_buf) {
        memset(ctx->kat_buf, 0x0, ACVP_KAT_BUF_MAX);
    }

    result = execute_network_action(ctx, ACVP_NET_ACTION_GET_RESULT,
                                    url, &acvp_curl_write_vs_func);
    if (result != ACVP_SUCCESS) {
        /* Failed to transport */
        ACVP_LOG_ERR("Transport failure.");
        return result;
    }

    ACVP_LOG_STATUS("Successfully retrieved KAT vector set response");

    return ACVP_SUCCESS;
}

/*
 * This is the top level function used within libacvp to retrieve
 * the test result for a given KAT vector set from the ACVP server.
 * It can be used to get the results for an entire session, or
 * more specifically for a vectorSet
 */
ACVP_RESULT acvp_retrieve_expected_result(ACVP_CTX *ctx, char *api_url) {
    char url[ACVP_ATTR_URL_MAX];
    ACVP_RESULT result = ACVP_SUCCESS;

    if (!ctx) {
        return ACVP_NO_CTX;
    }

    if (!ctx->server_name || !ctx->server_port) {
        ACVP_LOG_ERR("Missing server/port details; call acvp_set_server first");
        return ACVP_MISSING_ARG;
    }

    if (!api_url) {
        ACVP_LOG_ERR("Missing vs_id from retrieve vector set");
        return ACVP_MISSING_ARG;
    }

    memset(url, 0x0, ACVP_ATTR_URL_MAX);
    snprintf(url, ACVP_ATTR_URL_MAX - 1, "https://%s:%d/%s%s/expected", ctx->server_name, ctx->server_port,
             ctx->api_context, api_url);

    if (ctx->sample_buf) {
        memset(ctx->sample_buf, 0x0, ACVP_KAT_BUF_MAX);
    }

    result = execute_network_action(ctx, ACVP_NET_ACTION_GET_SAMPLE,
                                    url, &acvp_curl_write_sample_func);
    if (result != ACVP_SUCCESS) {
        /* Failed to transport */
        ACVP_LOG_ERR("Transport failure.");
        return result;
    }

    ACVP_LOG_STATUS("Successfully retrieved sample results");

    return ACVP_SUCCESS;
}
