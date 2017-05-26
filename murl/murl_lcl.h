/*
Copyright (c) 2016, Cisco Systems, Inc.
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
#ifndef __MURL_LCL_H
#define __MURL_LCL_H
#ifdef  __cplusplus
extern "C" {
#endif

#include <openssl/ssl.h>
#include "murl.h"

/* Maximum size of data that can be in HTTP POST */
#define MURL_POST_MAX	64*1024*1024
/* Maximum size of HTTP request, minus the POST data */
#define MURL_HDR_MAX	64*1024
#define MURL_RCV_MAX	MURL_POST_MAX

#define MURL_HOSTNAME_MAX   256

/*
 * Local murl context for a session
 */
typedef struct SessionHandle_ {
    char		    *url;
    int                     use_ipv6;
    char		    *user_agent;
    int			    http_post; /* 1 to do POST, zero for GET */
    char		    *post_fields;
    int			    post_field_size;
    char		    *ca_file;
    int			    ssl_verify_peer; /* 1 to verify, zero to skip verification at SSL layer */
    int			    ssl_verify_hostname; /* 1 to verify server hostname against certfication */
    int			    ssl_certinfo; /* 1 to collect TLS peer certificate info */
    char		    *ssl_cert_file;
    char		    *ssl_cert_type;  /* "PEM" and "DER" are valid values */
    char		    *ssl_key_file;
    char		    *ssl_key_type;  /* "PEM" and "DER" are valid values */
    void		    *write_ctx;
    struct curl_slist	    *headers;
    curl_write_callback	    write_func;

    SSL	*ssl;

    /* The following members are for HTTP parsing */
    int			http_status_code;  /* HTTP response from server */
    char		*recv_buf;
    int			recv_ctr;
    char		path_segment[256]; //FIXME: use a pointer
    char		host_name[MURL_HOSTNAME_MAX]; //FIXME: use a pointer
    int			server_port;
} SessionHandle;

int murl_http_parse_response(SessionHandle *ctx, const char *buf);

#ifdef  __cplusplus
}
#endif

#endif
