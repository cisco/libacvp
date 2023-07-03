/*
   Copyright (c) 2018, Cisco Systems, Inc.
   All rights reserved.

   Redistribution and use in source and binary forms, with or without modification,
   are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
   USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/***************************************************************************
* Some of this code is derived from Curl.  The Curl license is retained
* here...
*
* Copyright (C) 1998 - 2008, Daniel Stenberg, <daniel@haxx.se>, et al.
*
* This software is licensed as described in the file COPYING, which
* you should have received as part of this distribution. The terms
* are also available at http://curl.haxx.se/docs/copyright.html.
*
* You may opt to use, copy, modify, merge, publish, distribute and/or sell
* copies of the Software, and permit persons to whom the Software is
* furnished to do so, under the terms of the COPYING file.
*
* This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
* KIND, either express or implied.
*
***************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include "murl.h"
#include "murl_lcl.h"

static unsigned int initialized = 0;
#define DEBUGF(x) do { } while (0)

void curl_free(void *p)
{
  free(p);
}

/**
 * Global SSL init
 *
 * @retval 0 error initializing SSL
 * @retval 1 SSL initialized successfully
 */
static int Curl_ossl_init(void)
{
    ENGINE_load_builtin_engines();

   OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
                        | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
   if (!OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN
                         | OPENSSL_INIT_LOAD_CONFIG, NULL))
        return 0;

    return 1;
}

/**
 * curl_global_init() globally initializes cURL given a bitwise set of the
 * different features of what to initialize.
 */
static CURLcode curl_global_init()
{
    if (initialized++)
        return CURLE_OK;

    if (!Curl_ossl_init()) {
        DEBUGF(fprintf(stderr, "Error: Curl_ssl_init failed\n"));
        return CURLE_FAILED_INIT;
    }

    return CURLE_OK;
}

/*
 * curl_easy_init() is the external interface to alloc, setup and init an
 * easy handle that is returned. If anything goes wrong, NULL is returned.
 */
CURL *curl_easy_init(void)
{
    CURLcode result;
    SessionHandle *data;

    /* Make sure we inited the global SSL stuff */
    if (!initialized) {
        result = curl_global_init();
        if (result) {
            /* something in the global init failed, return nothing */
            DEBUGF(fprintf(stderr, "Error: curl_global_init failed\n"));
            return NULL;
        }
    }

    /* We use curl_open() with undefined URL so far */
    data = calloc(1, sizeof(SessionHandle));
    if (!data) {
        DEBUGF(fprintf(stderr, "Error: calloc failed\n"));
        return NULL;
    }
    data->server_port = 443; /* default to HTTPS port */
    data->ssl_verify_hostname = 1; /* default to verify server hostname */

    return data;
}

static CURLcode setstropt(char **charp, char *s)
{
    /* Release the previous storage at `charp' and replace by a dynamic storage
       copy of `s'. Return CURLE_OK or CURLE_OUT_OF_MEMORY. */

    if (*charp) free(*charp);

    if (s) {
        s = strdup(s);
        if (!s)
            return CURLE_OUT_OF_MEMORY;

        *charp = s;
    }

    return CURLE_OK;
}



CURLcode Curl_setopt(CURL *ctx, CURLoption option, va_list param)
{
    CURLcode result = CURLE_OK;
    SessionHandle *data = (SessionHandle*)ctx;

    switch (option) {
    case CURLOPT_USERAGENT:
        /*
         * String to use in the HTTP User-Agent field
         */
        result = setstropt(&data->user_agent, va_arg(param, char *));
        break;
    case CURLOPT_URL:
        /*
         * The URL to fetch.
         */
        result = setstropt(&data->url, va_arg(param, char *));
        break;
    case CURLOPT_HTTPHEADER:
        /*
         * Set a list with HTTP headers to use (or replace internals with)
         */
        data->headers = va_arg(param, struct curl_slist *);
        break;
    case CURLOPT_POSTFIELDS:
        data->http_post = 1;
        result = setstropt(&data->post_fields, va_arg(param, char *));
        break;
    case CURLOPT_POSTFIELDSIZE_LARGE:
        /*
         * The size of the POSTFIELD data to prevent libcurl to do strlen() to
         * figure it out. Enables binary posts.
         */
        data->post_field_size = va_arg(param, long);
        break;
    case CURLOPT_CAINFO:
        /*
         * Set CA info for SSL connection. Specify file name of the CA certificate
         */
        result = setstropt(&data->ca_file, va_arg(param, char *));
        break;
    case CURLOPT_SSL_VERIFYPEER:
        /*
         * Enable peer SSL verifying.
         */
        data->ssl_verify_peer = (0 != va_arg(param, long)) ? 1 : 0;
        break;
    case CURLOPT_CERTINFO:
        /*
         * Enable certification info logging.
         */
        data->ssl_certinfo = (0 != va_arg(param, long)) ? 1 : 0;
        break;
    case CURLOPT_SSLCERT:
        /*
         * String that holds file name of the SSL certificate to use
         */
        result = setstropt(&data->ssl_cert_file, va_arg(param, char *));
        break;
    case CURLOPT_SSLCERTTYPE:
        /*
         * String that holds file type of the SSL certificate to use
         */
        result = setstropt(&data->ssl_cert_type, va_arg(param, char *));
        break;
    case CURLOPT_SSLKEY:
        /*
         * String that holds file name of the SSL key to use
         */
        result = setstropt(&data->ssl_key_file, va_arg(param, char *));
        break;
    case CURLOPT_SSLKEYTYPE:
        /*
         * String that holds file type of the SSL key to use
         */
        result = setstropt(&data->ssl_key_type, va_arg(param, char *));
        break;
    case CURLOPT_WRITEDATA:
        data->write_ctx = va_arg(param, void *);
        break;
    case CURLOPT_WRITEFUNCTION:
        data->write_func = va_arg(param, curl_write_callback);
        break;
    case CURLOPT_SSL_VERIFY_HOSTNAME:
        /*
         * Enable peer hostname verification.
         */
        data->ssl_verify_hostname = (0 != va_arg(param, long)) ? 1 : 0;
        break;
    default:
        /* Silent failure since we don't support most Curl options */
        DEBUGF(fprintf(stderr, "Warning: unsupported Curl option requested from Murl\n"));
        break;
    }
    return result;
}


CURLcode curl_easy_setopt(CURL *curl, CURLoption tag, ...)
{
    va_list arg;
    struct SessionHandle *data = curl;
    CURLcode result;

    if (!curl)
        return CURLE_BAD_FUNCTION_ARGUMENT;

    va_start(arg, tag);

    result = Curl_setopt(data, tag, arg);

    va_end(arg);
    return result;
}

/*
 * This function simply opens a TCP connection using
 * the BIO interface. Returns the file descriptor for
 * the socket.
 */
static BIO *create_connection(char *server, int port)
{
    BIO *b = NULL;
    char pbuf[64];

    b = BIO_new_connect(server);
    if (b == NULL) {
        printf("IP connection failed\n");
        return NULL;
    }
    sprintf(pbuf, "%d", port);
    BIO_set_conn_port(b, pbuf);

    if (BIO_do_connect(b) <= 0) {
        printf("TCP connect failed\n");
        BIO_free_all(b);
        return NULL;
    }
    return b;
}

/*
 * This function simply opens a TCP connection given an
 * IPv6 address.  The address should be enclosed in square
 * brackets. Example:
 *	[2001:db8:85a3:8d3:1319:8a2e:370:7348]
 */
#define IPV6_ADDRESS_MAX    41
static BIO *create_connection_v6(char *address, int port)
{
    BIO		    *conn = NULL;
    struct sockaddr_in6 si6;
    char	    *host = &address[1];  /* Removes first square bracket */
    int		    rc;
    int		    sock;

    /*
     * Strip off trailing bracket 
     */
    host[strnlen(host, IPV6_ADDRESS_MAX)-1] = 0;

    /*
     * Setup destination address/port 
     */
    memset((char *) &si6, 0, sizeof(si6));
    si6.sin6_flowinfo = 0;
    si6.sin6_family = AF_INET6;    
    si6.sin6_port = htons(port);
    rc = inet_pton(AF_INET6, host, &si6.sin6_addr);
    if (rc != 1) {
	fprintf(stderr, "Unable to resolve v6 address: %s\n", host);
	return(NULL);
    }

    /*
     * Create and connect to the socket
     */
    if ((sock = socket(AF_INET6, SOCK_STREAM, 0)) < 0 ) {
	fprintf(stderr, "Unable to create v6 socket for address: %s\n", host);
	return(NULL);
    }
    if (connect(sock, (struct sockaddr *) &si6, sizeof(si6)) < 0 ) {
	fprintf(stderr, "Unable to connect v6 socket to address: %s  [%s]\n", host, strerror(errno));
	close(sock);
	return(NULL);
    }

    /*
     * Pass the socket to the BIO interface, which OpenSSL uses
     * to create the TLS session.
     */
    conn = BIO_new_socket(sock, BIO_CLOSE);
    if (conn == NULL) {
        fprintf(stderr, "OpenSSL error creating IP socket\n");
        //ossl_dump_ssl_errors();
        return(NULL);
    }        

    return(conn);
}

/*
 * Parse URL and fill in the relevant members of the connection struct.
 * This code was adapted from Curl.  It now only supports HTTPS with
 * either a hostname, IPv4 address or IPv6 address in the URI.
 *
 * This code was taken from Curl's parseurlandfillconn()
 */
#define MURL_URI_MAX	512
static CURLcode parseurl(SessionHandle *data)
{
    char *at;
    char *fragment;
    char *path = data->path_segment;
    char *host_name = data->host_name;
    char *query;
    int rc;
    char protobuf[16] = "";
    const char *protop = "";
    int rebuild_url = 0;


    /* We might pass the entire URL into the request so we need to make sure
     * there are no bad characters in there.*/
    if (strpbrk(data->url, "\r\n")) {
        fprintf(stderr, "Illegal characters found in URL");
        return CURLE_URL_MALFORMAT;
    }

    /*************************************************************
     * Parse the URL.
     *
     * We need to parse the url even when using the proxy, because we will need
     * the hostname and port in case we are trying to SSL connect through the
     * proxy -- and we don't know if we will need to use SSL until we parse the
     * url ...
     ************************************************************/
    /* clear path */
    path[0] = 0;

    if (2 > sscanf(data->url,
                   "%15[^\n:]://%[^\n/?]%[^\n]",
                   protobuf, host_name, path)) {

        /*
         * The URL was badly formatted, let's try the browser-style _without_
         * protocol specified like 'http://'.
         */
        rc = sscanf(data->url, "%[^\n/?]%[^\n]", host_name, path);
        if (1 > rc) {
            /*
             * We couldn't even get this format.
             * djgpp 2.04 has a sscanf() bug where 'conn->host.name' is
             * assigned, but the return value is EOF!
             */
#if defined(__DJGPP__) && (DJGPP_MINOR == 4)
            if (!(rc == -1 && *host_name))
#endif
            {
                fprintf(stderr, "<url> malformed");
                return CURLE_URL_MALFORMAT;
            }
        }
    }
    /*
     * Murl only supports http
     */
    protop = "https";

    /* We search for '?' in the host name (but only on the right side of a
     * @-letter to allow ?-letters in username and password) to handle things
     * like http://example.com?param= (notice the missing '/').
     */
    at = strchr(host_name, '@');
    if (at)
        query = strchr(at+1, '?');
    else
        query = strchr(host_name, '?');

    if (query) {
        /* We must insert a slash before the '?'-letter in the URL. If the URL had
           a slash after the '?', that is where the path currently begins and the
           '?string' is still part of the host name.

           We must move the trailing part from the host name and put it first in
           the path. And have it all prefixed with a slash.
         */

        size_t hostlen = strnlen(query, MURL_URI_MAX);
        size_t pathlen = strnlen(path, MURL_URI_MAX);

        /* move the existing path plus the zero byte forward, to make room for
           the host-name part */
        memmove(path+hostlen+1, path, pathlen+1);

        /* now copy the trailing host part in front of the existing path */
        memcpy(path+1, query, hostlen);

        path[0] = '/'; /* prepend the missing slash */
        rebuild_url = 1;

        *query = 0; /* now cut off the hostname at the ? */
    }
    else if (!path[0]) {
        /* if there's no path set, use a single slash */
        strcpy(path, "/");
        rebuild_url = 1;
    }

    /* If the URL is malformatted (missing a '/' after hostname before path) we
     * insert a slash here. The only letter except '/' we accept to start a path
     * is '?'.
     */
    if (path[0] == '?') {
        /* We need this function to deal with overlapping memory areas. We know
           that the memory area 'path' points to is 'urllen' bytes big and that
           is bigger than the path. Use +1 to move the zero byte too. */
        memmove(&path[1], path, strnlen(path, MURL_URI_MAX)+1);
        path[0] = '/';
        rebuild_url = 1;
    }

    /*
     * "rebuild_url" means that one or more URL components have been modified so
     * we need to generate an updated full version.  We need the corrected URL
     * when communicating over HTTP proxy and we don't know at this point if
     * we're using a proxy or not.
     */
    if (rebuild_url) {
        char *reurl;

        size_t plen = strnlen(path, MURL_URI_MAX); /* new path, should be 1 byte longer than
                                       the original */
        size_t urllen = strnlen(data->url, MURL_URI_MAX); /* original URL length */

        size_t prefixlen = strnlen(host_name, MURL_URI_MAX);

        prefixlen += strlen(protop) + strlen("://");

        reurl = malloc(urllen + 2); /* 2 for zerobyte + slash */
        if (!reurl)
            return CURLE_OUT_OF_MEMORY;

        /* copy the prefix */
        memcpy(reurl, data->url, prefixlen);

        /* append the trailing piece + zerobyte */
        memcpy(&reurl[prefixlen], path, plen + 1);

	if (data->url) free(data->url);
	data->url = reurl;
    }

#if 0
    //TODO: do we want to support login credentials in the URL?
    /*
     * Parse the login details from the URL and strip them out of
     * the host name
     */
    result = parse_url_login(data, conn, userp, passwdp, optionsp);
    if (result)
        return result;
#endif

    /*
     * Check for an IPv6 address as the host name
     */
    if (host_name[0] == '[') {
	data->use_ipv6 = 1;
#if 0
	//TODO: libmurl currently doesn't support IPv6 scopes
        /* This looks like an IPv6 address literal.  See if there is an address
           scope if there is no location header */
        char *percent = strchr(host_name, '%');
        if (percent) {
            unsigned int identifier_offset = 3;
            char *endp;
            unsigned long scope;
            if (strncmp("%25", percent, 3) != 0) {
                fprintf(stderr, "Please URL encode %% as %%25, see RFC 6874.\n");
                identifier_offset = 1;
            }
            scope = strtoul(percent + identifier_offset, &endp, 10);
            if (*endp == ']') {
                /* The address scope was well formed.  Knock it out of the
                   hostname. */
                memmove(percent, endp, strlen(endp)+1);
                conn->scope_id = (unsigned int)scope;
            }
            else {
                /* Zone identifier is not numeric */
#if defined(HAVE_NET_IF_H) && defined(IFNAMSIZ) && defined(HAVE_IF_NAMETOINDEX)
                char ifname[IFNAMSIZ + 2];
                char *square_bracket;
                unsigned int scopeidx = 0;
                strncpy(ifname, percent + identifier_offset, IFNAMSIZ + 2);
                /* Ensure nullbyte termination */
                ifname[IFNAMSIZ + 1] = '\0';
                square_bracket = strchr(ifname, ']');
                if (square_bracket) {
                    /* Remove ']' */
                    *square_bracket = '\0';
                    scopeidx = if_nametoindex(ifname);
                    if (scopeidx == 0) {
                        fprintf(stderr, "Invalid network interface: %s; %s\n", ifname, strerror(errno));
                    }
                }
                if (scopeidx > 0) {
                    char *p = percent + identifier_offset + strlen(ifname);

                    /* Remove zone identifier from hostname */
                    memmove(percent, p, strlen(p) + 1);
                }
                else
#endif /* HAVE_NET_IF_H && IFNAMSIZ */
                fprintf(stderr, "Invalid IPv6 address format\n");
            }
        }
#endif
	/*
	 * Finally, check if the host_name has a TCP port number
	 */
	at = strrchr(host_name, ':');
    } else {
	/*
	 * Finally, check if the host_name has a TCP port number
	 */
	at = strchr(host_name, ':');
    }


    /* Remove the fragment part of the path. Per RFC 2396, this is always the
       last part of the URI. We are looking for the first '#' so that we deal
       gracefully with non conformant URI such as http://example.com#foo#bar. */
    fragment = strchr(path, '#');
    if (fragment) {
        *fragment = 0;

        /* we know the path part ended with a fragment, so we know the full URL
           string does too and we need to cut it off from there so it isn't used
           over proxy */
        fragment = strchr(data->url, '#');
        if (fragment)
            *fragment = 0;
    }

    /*
     * So if the URL was A://B/C#D,
     *   protop is A
     *   host_name is B
     *   path is /C
     */
    if (at) {
	/*
	 * The port number needs to be stripped off
	 */
	data->server_port = atoi(at+1);
	*at = 0;
    }


    return CURLE_OK;
}

/*
 * This function will log the X509 distinguished name of the TLS
 * peer certificate.
 */
static void murl_log_peer_cert(SSL *ssl)
{
    X509 *cert;
    X509_NAME *subject;
    BIO *out = NULL;
    BUF_MEM *bptr = NULL;

    cert = SSL_get_peer_certificate(ssl);
    if (cert) {
	subject = X509_get_subject_name(cert);
	if (subject) {
	    out = BIO_new(BIO_s_mem());
	    if (!out) {
		fprintf(stderr, "Unable to allocation OpenSSL BIO\n");
		return;
	    }
	    X509_NAME_print(out, subject, 0);
	    (void)BIO_flush(out);
	    BIO_get_mem_ptr(out, &bptr);
	    //fprintf(stdout, "TLS peer subject name: %s\n", bptr->data); 
	    BIO_free_all(out);
	}
    }
}


#define TBUF_MAX 1024
#define READ_CHUNK_SZ 16384
CURLcode curl_easy_perform(CURL *curl)
{
    BIO *conn;
    int rv;
    int ssl_err;
    int read_cnt = 0;
    char *rbuf = NULL;
    char tbuf[TBUF_MAX];
    SSL *ssl = NULL;
    SSL_CTX *ssl_ctx = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    int cl;
    SessionHandle *ctx = (SessionHandle*)curl;
    struct curl_slist *hdrs;
    unsigned long ossl_err;
    CURLcode crv;

    if (!ctx) {
	return CURLE_UNKNOWN_OPTION;
    }

    /*
     * Allocate some space to build the HTTP request
     */
    if (ctx->http_post && ctx->post_field_size) {
        cl = ctx->post_field_size; 
    } else if (ctx->http_post && ctx->post_fields) {
        cl = strlen(ctx->post_fields); //FIXME: this is not safe
    } else {
        cl = 0;
    }
    if (cl > MURL_POST_MAX) {
	fprintf(stderr, "POST data exceeds %d byte limit\n", MURL_POST_MAX);
	return CURLE_FILESIZE_EXCEEDED;
    }
    rbuf = calloc(1, cl+MURL_HDR_MAX);
    if (!rbuf) {
        fprintf(stderr, "calloc failed.\n");
        return CURLE_OUT_OF_MEMORY;
    }

    /*
     * Split the URL into it's parts
     */
    crv = parseurl(ctx);
    if (crv != CURLE_OK) goto easy_perform_cleanup;

    /*
     * Setup OpenSSL API
     */
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ssl_ctx) {
        fprintf(stderr, "Failed to create SSL context.\n");
        ERR_print_errors_fp(stderr);
        crv = CURLE_SSL_CONNECT_ERROR;
	goto easy_perform_cleanup;
    }
    /*
     * This is optional.
     * Since we'll be using blocking sockets, set the
     * SSL read/write mode to auto-retry.  This simplifies
     * the error handling required when reading/writing to
     * the SSL socket.
     */
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);


    /*
     * Enable TLS peer verification if requested and CA certs were provided
     */
    if (ctx->ssl_verify_peer && ctx->ca_file) {
        if (!SSL_CTX_load_verify_locations(ssl_ctx, ctx->ca_file, NULL)) {
            fprintf(stderr, "Failed to set trust anchors.\n");
            ERR_print_errors_fp(stderr);
            crv = CURLE_SSL_CACERT_BADFILE;
	    goto easy_perform_cleanup;
        }
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }

    vpm = X509_VERIFY_PARAM_new();
    if (vpm == NULL) {
        fprintf(stderr, "Unable to allocate a verify parameter structure.\n");
        ERR_print_errors_fp(stderr);
        crv = CURLE_SSL_CONNECT_ERROR;
	goto easy_perform_cleanup;
    }
#if 0
    /* TODO: Enable CRL checks */
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK |
                                X509_V_FLAG_CRL_CHECK_ALL);
#endif
    X509_VERIFY_PARAM_set_depth(vpm, 7);
    X509_VERIFY_PARAM_set_purpose(vpm, X509_PURPOSE_SSL_SERVER);
    if (ctx->ssl_verify_hostname) {
	X509_VERIFY_PARAM_set1_host(vpm, ctx->host_name, strnlen(ctx->host_name, MURL_HOSTNAME_MAX));
    }
    SSL_CTX_set1_param(ssl_ctx, vpm);
    X509_VERIFY_PARAM_free(vpm);

    if (ctx->ssl_cert_file && ctx->ssl_key_file) {
        if (SSL_CTX_use_certificate_chain_file(ssl_ctx, ctx->ssl_cert_file) != 1) {
            fprintf(stderr,"Failed to load client certificate\n");
            ERR_print_errors_fp(stderr);
            crv = CURLE_SSL_CERTPROBLEM;
	    goto easy_perform_cleanup;
        }
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, ctx->ssl_key_file, SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "Failed to load client private key\n");
            ERR_print_errors_fp(stderr);
            crv = CURLE_SSL_CERTPROBLEM;
	    goto easy_perform_cleanup;
        }
    }

    /*
     * Open TCP connection with server
     */
    if (ctx->use_ipv6) {
	conn = create_connection_v6(ctx->host_name, ctx->server_port);
    } else {
	conn = create_connection(ctx->host_name, ctx->server_port);
    }
    //FIXME: do we need to free conn, or is this handled by SSL_free?
    if (conn == NULL) {
        fprintf(stderr, "Unable to open socket with server.\n");
        crv = CURLE_COULDNT_CONNECT;
	goto easy_perform_cleanup;
    }
    ssl = SSL_new(ssl_ctx);
    if (!SSL_set_tlsext_host_name(ssl, ctx->host_name)) {
        fprintf(stderr, "Warning: SNI extension not set.\n");
    }
    SSL_set_bio(ssl, conn, conn);
    rv = SSL_connect(ssl);
    if (rv <= 0) {
        fprintf(stderr, "TLS handshake failed.\n");
        ERR_print_errors_fp(stderr);
        crv = CURLE_SSL_CONNECT_ERROR;
	goto easy_perform_cleanup;
    }

    /*
     * PSB requires we log the X509 distinguished name of the peer
     */
    if (ctx->ssl_verify_peer) {
	murl_log_peer_cert(ssl);
    }

    /*
     * Build HTTP request
     */
    memset(tbuf, 0, sizeof(tbuf));
    snprintf(tbuf, TBUF_MAX, "%s %s HTTP/1.0\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: %s\r\n",
            (ctx->http_post ? "POST" : "GET"),
            ctx->path_segment, ctx->host_name, ctx->server_port,
            (ctx->user_agent ? ctx->user_agent : "Murl"));
    strcat(rbuf, tbuf); //FIXME: safe string handling needed

    /*
     * Add any custom headers requested by the user
     */
    if (ctx->headers) {
        hdrs = ctx->headers;
        while (hdrs) {
            memset(tbuf, 0, sizeof(tbuf));
            snprintf(tbuf, TBUF_MAX, "%s\r\n", hdrs->data);
            strcat(rbuf, tbuf); //FIXME: safe string handling needed
            hdrs = hdrs->next;
        }
    }

    /*
     * Set the Content-length header
     */
    memset(tbuf, 0, sizeof(tbuf));
    snprintf(tbuf, TBUF_MAX, "Content-Length: %d\r\n" "Accept: */*\r\n\r\n", cl);
    strcat(rbuf, tbuf); //FIXME: safe string handling needed

    /*
     * Send the HTTP request
     */
    SSL_write(ssl, rbuf, strlen(rbuf));
    SSL_write(ssl, ctx->post_fields, cl);

    ERR_clear_error();
    free(rbuf);
    rbuf = NULL;

    /*
     * Read the HTTP response
     */
    rv = 1;
    while (rv) {
	/*
	 * Allocate some space to receive the response from the server
	 */
	rbuf = realloc(rbuf, read_cnt + READ_CHUNK_SZ);
	if (!rbuf) {
	    fprintf(stderr, "realloc failed (%s).\n", __FUNCTION__);
	    crv = CURLE_OUT_OF_MEMORY;
	    goto easy_perform_cleanup;
	}
	memset(rbuf+read_cnt, 0x0, READ_CHUNK_SZ);
	
	/*
	 * Read the next chunk from the server
	 */
        rv = SSL_read(ssl, rbuf+read_cnt, READ_CHUNK_SZ);
        if (rv <= 0) {
            ssl_err = SSL_get_error(ssl, rv);
            switch (ssl_err) {
            case SSL_ERROR_NONE:
            case SSL_ERROR_ZERO_RETURN:
                //fprintf(stderr, "SSL_read finished\n");
                break;
            default:
                ossl_err = ERR_get_error();
                if ((rv < 0) || ossl_err) {
                    fprintf(stderr, "SSL_read failed, rv=%d ssl_err=%d ossl_err=%d.\n",
                            rv, ssl_err, (int)ossl_err);
                    ERR_print_errors_fp(stderr);
                    crv = CURLE_USE_SSL_FAILED;
	            goto easy_perform_cleanup;
                }
                break;
            }
        }
        read_cnt += rv;
	
	/*
	 * Make sure we're not receving too much data from the server.
	 */
	if (read_cnt > MURL_RCV_MAX) {
	    crv = CURLE_FILESIZE_EXCEEDED;
	    goto easy_perform_cleanup;
	}
    }

    /*
     * make sure the data is null terminated
     */
    rbuf[read_cnt] = 0;

    /*
     * Parse the HTTP response
     */
    if (murl_http_parse_response(ctx, rbuf)) {
        crv = CURLE_HTTP2;
	goto easy_perform_cleanup;
    }

    /*
     * Send the data back to the user
     */
    if (ctx->write_func) {
        (ctx->write_func)(ctx->recv_buf, 1, ctx->recv_ctr, ctx->write_ctx);
    }

    crv = CURLE_OK;
easy_perform_cleanup:
    if (ssl) {
	SSL_shutdown(ssl);
	SSL_free(ssl);
    }
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    if (rbuf) free(rbuf);
    return crv;
}

static CURLcode getinfo_long(SessionHandle *data, CURLINFO info, long *param_longp)
{
    switch (info) {
    case CURLINFO_RESPONSE_CODE:
        *param_longp = data->http_status_code;
        break;
    default:
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    return CURLE_OK;
}


static CURLcode Curl_getinfo(SessionHandle *data, CURLINFO info, ...)
{
    va_list arg;
    long *param_longp = NULL;
    //double *param_doublep = NULL;
    //char **param_charp = NULL;
    //struct curl_slist **param_slistp = NULL;
    int type;
    /* default return code is to error out! */
    CURLcode result = CURLE_BAD_FUNCTION_ARGUMENT;

    if (!data)
        return result;

    va_start(arg, info);

    type = CURLINFO_TYPEMASK & (int)info;
    switch (type) {
#if 0
    case CURLINFO_STRING:
        param_charp = va_arg(arg, char **);
        if (param_charp)
            result = getinfo_char(data, info, param_charp);
        break;
#endif
    case CURLINFO_LONG:
        param_longp = va_arg(arg, long *);
        if (param_longp)
            result = getinfo_long(data, info, param_longp);
        break;
#if 0
    case CURLINFO_DOUBLE:
        param_doublep = va_arg(arg, double *);
        if (param_doublep)
            result = getinfo_double(data, info, param_doublep);
        break;
    case CURLINFO_SLIST:
        param_slistp = va_arg(arg, struct curl_slist **);
        if (param_slistp)
            result = getinfo_slist(data, info, param_slistp);
        break;
#endif
    default:
        break;
    }

    va_end(arg);

    return result;
}

CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...)
{
    va_list arg;
    void *paramp;
    CURLcode result;
    SessionHandle *data = (SessionHandle *)curl;

    va_start(arg, info);
    paramp = va_arg(arg, void *);

    result = Curl_getinfo(data, info, paramp);

    va_end(arg);
    return result;
}

/* returns last node in linked list */
static struct curl_slist *slist_get_last(struct curl_slist *list)
{
    struct curl_slist     *item;

    /* if caller passed us a NULL, return now */
    if (!list)
        return NULL;

    /* loop through to find the last item */
    item = list;
    while (item->next) {
        item = item->next;
    }
    return item;
}

/*
 * Curl_slist_append_nodup() appends a string to the linked list. Rather than
 * copying the string in dynamic storage, it takes its ownership. The string
 * should have been malloc()ated. Curl_slist_append_nodup always returns
 * the address of the first record, so that you can use this function as an
 * initialization function as well as an append function.
 * If an error occurs, NULL is returned and the string argument is NOT
 * released.
 */
static struct curl_slist *Curl_slist_append_nodup(struct curl_slist *list, char *data)
{
    struct curl_slist     *last;
    struct curl_slist     *new_item;

    new_item = calloc(1, sizeof(struct curl_slist));
    if (!new_item)
        return NULL;

    new_item->next = NULL;
    new_item->data = data;

    /* if this is the first item, then new_item *is* the list */
    if (!list)
        return new_item;

    last = slist_get_last(list);
    last->next = new_item;
    return list;
}

/*
 * curl_slist_append() appends a string to the linked list. It always returns
 * the address of the first record, so that you can use this function as an
 * initialization function as well as an append function. If you find this
 * bothersome, then simply create a separate _init function and call it
 * appropriately from within the program.
 */
struct curl_slist *curl_slist_append(struct curl_slist *list,
                                     const char *data)
{
    char *dupdata = strdup(data);

    if (!dupdata)
        return NULL;

    list = Curl_slist_append_nodup(list, dupdata);
    if (!list)
        free(dupdata);

    return list;
}

/* be nice and clean up resources */
void curl_slist_free_all(struct curl_slist *list)
{
    struct curl_slist     *next;
    struct curl_slist     *item;

    if (!list)
        return;

    item = list;
    do {
        next = item->next;
        if (item->data) {
            free(item->data);
            item->data = NULL;
        }
        free(item);
        item = next;
    } while (next);
}

static void Curl_ossl_cleanup(void)
{
    /* Free thread local error state, destroying hash upon zero refcount */
    ERR_remove_thread_state(NULL);
    ERR_remove_state(0);
}

void curl_easy_cleanup(CURL *curl)
{
    SessionHandle *data = (SessionHandle*)curl;

    if (data->user_agent) free(data->user_agent);
    if (data->url) free(data->url);
    if (data->post_fields) free(data->post_fields);
    if (data->ca_file) free(data->ca_file);
    if (data->ssl_cert_file) free(data->ssl_cert_file);
    if (data->ssl_cert_type) free(data->ssl_cert_type);
    if (data->ssl_key_file) free(data->ssl_key_file);
    if (data->ssl_key_type) free(data->ssl_key_type);
    if (data->recv_buf) free(data->recv_buf);
    //if (data->headers) curl_slist_free_all(data->headers);

    free(data);
}

void curl_global_cleanup(void)
{
    Curl_ossl_cleanup();
}

const char * curl_easy_strerror(CURLcode error)
{
#ifndef CURL_DISABLE_VERBOSE_STRINGS
    switch (error) {
    case CURLE_OK:
        return "No error";

    case CURLE_UNSUPPORTED_PROTOCOL:
        return "Unsupported protocol";

    case CURLE_FAILED_INIT:
        return "Failed initialization";

    case CURLE_URL_MALFORMAT:
        return "URL using bad/illegal format or missing URL";

    case CURLE_NOT_BUILT_IN:
        return "A requested feature, protocol or option was not found built-in in"
               " this libcurl due to a build-time decision.";

    case CURLE_COULDNT_RESOLVE_PROXY:
        return "Couldn't resolve proxy name";

    case CURLE_COULDNT_RESOLVE_HOST:
        return "Couldn't resolve host name";

    case CURLE_COULDNT_CONNECT:
        return "Couldn't connect to server";

    case CURLE_FTP_WEIRD_SERVER_REPLY:
        return "FTP: weird server reply";

    case CURLE_REMOTE_ACCESS_DENIED:
        return "Access denied to remote resource";

    case CURLE_FTP_ACCEPT_FAILED:
        return "FTP: The server failed to connect to data port";

    case CURLE_FTP_ACCEPT_TIMEOUT:
        return "FTP: Accepting server connect has timed out";

    case CURLE_FTP_PRET_FAILED:
        return "FTP: The server did not accept the PRET command.";

    case CURLE_FTP_WEIRD_PASS_REPLY:
        return "FTP: unknown PASS reply";

    case CURLE_FTP_WEIRD_PASV_REPLY:
        return "FTP: unknown PASV reply";

    case CURLE_FTP_WEIRD_227_FORMAT:
        return "FTP: unknown 227 response format";

    case CURLE_FTP_CANT_GET_HOST:
        return "FTP: can't figure out the host in the PASV response";

    case CURLE_HTTP2:
        return "Error in the HTTP2 framing layer";

    case CURLE_FTP_COULDNT_SET_TYPE:
        return "FTP: couldn't set file type";

    case CURLE_PARTIAL_FILE:
        return "Transferred a partial file";

    case CURLE_FTP_COULDNT_RETR_FILE:
        return "FTP: couldn't retrieve (RETR failed) the specified file";

    case CURLE_QUOTE_ERROR:
        return "Quote command returned error";

    case CURLE_HTTP_RETURNED_ERROR:
        return "HTTP response code said error";

    case CURLE_WRITE_ERROR:
        return "Failed writing received data to disk/application";

    case CURLE_UPLOAD_FAILED:
        return "Upload failed (at start/before it took off)";

    case CURLE_READ_ERROR:
        return "Failed to open/read local data from file/application";

    case CURLE_OUT_OF_MEMORY:
        return "Out of memory";

    case CURLE_OPERATION_TIMEDOUT:
        return "Timeout was reached";

    case CURLE_FTP_PORT_FAILED:
        return "FTP: command PORT failed";

    case CURLE_FTP_COULDNT_USE_REST:
        return "FTP: command REST failed";

    case CURLE_RANGE_ERROR:
        return "Requested range was not delivered by the server";

    case CURLE_HTTP_POST_ERROR:
        return "Internal problem setting up the POST";

    case CURLE_SSL_CONNECT_ERROR:
        return "SSL connect error";

    case CURLE_BAD_DOWNLOAD_RESUME:
        return "Couldn't resume download";

    case CURLE_FILE_COULDNT_READ_FILE:
        return "Couldn't read a file:// file";

    case CURLE_LDAP_CANNOT_BIND:
        return "LDAP: cannot bind";

    case CURLE_LDAP_SEARCH_FAILED:
        return "LDAP: search failed";

    case CURLE_FUNCTION_NOT_FOUND:
        return "A required function in the library was not found";

    case CURLE_ABORTED_BY_CALLBACK:
        return "Operation was aborted by an application callback";

    case CURLE_BAD_FUNCTION_ARGUMENT:
        return "A libcurl function was given a bad argument";

    case CURLE_INTERFACE_FAILED:
        return "Failed binding local connection end";

    case CURLE_TOO_MANY_REDIRECTS:
        return "Number of redirects hit maximum amount";

    case CURLE_UNKNOWN_OPTION:
        return "An unknown option was passed in to libcurl";

    case CURLE_TELNET_OPTION_SYNTAX:
        return "Malformed telnet option";

    case CURLE_PEER_FAILED_VERIFICATION:
        return "SSL peer certificate or SSH remote key was not OK";

    case CURLE_GOT_NOTHING:
        return "Server returned nothing (no headers, no data)";

    case CURLE_SSL_ENGINE_NOTFOUND:
        return "SSL crypto engine not found";

    case CURLE_SSL_ENGINE_SETFAILED:
        return "Can not set SSL crypto engine as default";

    case CURLE_SSL_ENGINE_INITFAILED:
        return "Failed to initialise SSL crypto engine";

    case CURLE_SEND_ERROR:
        return "Failed sending data to the peer";

    case CURLE_RECV_ERROR:
        return "Failure when receiving data from the peer";

    case CURLE_SSL_CERTPROBLEM:
        return "Problem with the local SSL certificate";

    case CURLE_SSL_CIPHER:
        return "Couldn't use specified SSL cipher";

    case CURLE_SSL_CACERT:
        return "Peer certificate cannot be authenticated with given CA "
               "certificates";

    case CURLE_SSL_CACERT_BADFILE:
        return "Problem with the SSL CA cert (path? access rights?)";

    case CURLE_BAD_CONTENT_ENCODING:
        return "Unrecognized or bad HTTP Content or Transfer-Encoding";

    case CURLE_LDAP_INVALID_URL:
        return "Invalid LDAP URL";

    case CURLE_FILESIZE_EXCEEDED:
        return "Maximum file size exceeded";

    case CURLE_USE_SSL_FAILED:
        return "Requested SSL level failed";

    case CURLE_SSL_SHUTDOWN_FAILED:
        return "Failed to shut down the SSL connection";

    case CURLE_SSL_CRL_BADFILE:
        return "Failed to load CRL file (path? access rights?, format?)";

    case CURLE_SSL_ISSUER_ERROR:
        return "Issuer check against peer certificate failed";

    case CURLE_SEND_FAIL_REWIND:
        return "Send failed since rewinding of the data stream failed";

    case CURLE_LOGIN_DENIED:
        return "Login denied";

    case CURLE_TFTP_NOTFOUND:
        return "TFTP: File Not Found";

    case CURLE_TFTP_PERM:
        return "TFTP: Access Violation";

    case CURLE_REMOTE_DISK_FULL:
        return "Disk full or allocation exceeded";

    case CURLE_TFTP_ILLEGAL:
        return "TFTP: Illegal operation";

    case CURLE_TFTP_UNKNOWNID:
        return "TFTP: Unknown transfer ID";

    case CURLE_REMOTE_FILE_EXISTS:
        return "Remote file already exists";

    case CURLE_TFTP_NOSUCHUSER:
        return "TFTP: No such user";

    case CURLE_CONV_FAILED:
        return "Conversion failed";

    case CURLE_CONV_REQD:
        return "Caller must register CURLOPT_CONV_ callback options";

    case CURLE_REMOTE_FILE_NOT_FOUND:
        return "Remote file not found";

    case CURLE_SSH:
        return "Error in the SSH layer";

    case CURLE_AGAIN:
        return "Socket not ready for send/recv";

    case CURLE_RTSP_CSEQ_ERROR:
        return "RTSP CSeq mismatch or invalid CSeq";

    case CURLE_RTSP_SESSION_ERROR:
        return "RTSP session error";

    case CURLE_FTP_BAD_FILE_LIST:
        return "Unable to parse FTP file list";

    case CURLE_CHUNK_FAILED:
        return "Chunk callback failed";

    case CURLE_NO_CONNECTION_AVAILABLE:
        return "The max connection limit is reached";

    case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
        return "SSL public key does not match pinned public key";

    case CURLE_SSL_INVALIDCERTSTATUS:
        return "SSL server certificate status verification FAILED";

    /* error codes not used by current libcurl */
    case CURLE_OBSOLETE20:
    case CURLE_OBSOLETE24:
    case CURLE_OBSOLETE29:
    case CURLE_OBSOLETE32:
    case CURLE_OBSOLETE40:
    case CURLE_OBSOLETE44:
    case CURLE_OBSOLETE46:
    case CURLE_OBSOLETE50:
    case CURLE_OBSOLETE57:
    case CURL_LAST:
        break;
    }
    /*
     * By using a switch, gcc -Wall will complain about enum values
     * which do not appear, helping keep this function up-to-date.
     * By using gcc -Wall -Werror, you can't forget.
     *
     * A table would not have the same benefit.  Most compilers will
     * generate code very similar to a table in any case, so there
     * is little performance gain from a table.  And something is broken
     * for the user's application, anyways, so does it matter how fast
     * it _doesn't_ work?
     *
     * The line number for the error will be near this comment, which
     * is why it is here, and not at the start of the switch.
     */
    return "Unknown error";
#else
    if (!error)
        return "No error";
    else
        return "Error";
#endif
}

