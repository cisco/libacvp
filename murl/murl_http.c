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
/*
 * Since some of this code is derived from http-parser, their copyright
 * is retained here....
 *
 * Copyright 2009,2010 Ryan Dahl <ry@tinyclouds.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "murl_lcl.h"
#include "http_parser.h"

//FIXME: these are arbitrary values for now.  we're wasting memory since
//       the query string, request path, etc. doesn't need to be this large.
//       but the body size may need to be this large for ACVP, if not larger.
//       we'll need to rethink how to allocate this memory for the various
//       use cases.
#define MAX_HEADERS 13
#define MAX_ELEMENT_SIZE 64*1024
#define MAX_BODY_SIZE 64*1024*1024

/*
 * Using this global variable to track when all the HTTP data has been 
 * parsed.  This will need to be addressed if/when thread-safety is
 * desired.
 */
static int currently_parsing_eof;

typedef struct message {
    const char *name; // for debugging purposes
    const char *raw;
    enum http_parser_type type;
    enum http_method method;
    int status_code;
    char request_path[MAX_ELEMENT_SIZE];
    char request_url[MAX_ELEMENT_SIZE];
    char fragment[MAX_ELEMENT_SIZE];
    char query_string[MAX_ELEMENT_SIZE];
    char body[MAX_BODY_SIZE];
    size_t body_size;
    int num_headers;
    enum { NONE=0, FIELD, VALUE } last_header_element;
    char headers[MAX_HEADERS][2][MAX_ELEMENT_SIZE];
    int should_keep_alive;

    int upgrade;

    unsigned short http_major;
    unsigned short http_minor;

    int message_begin_cb_called;
    int headers_complete_cb_called;
    int message_complete_cb_called;
    int message_complete_on_eof;
} http_msg;

int request_path_cb (http_parser *p, const char *buf, size_t len)
{
    http_msg *msg = p->data;

    //FIXME: check for buffer overflow prior to strncat
    strncat(msg->request_path, buf, len);
    return 0;
}

int request_url_cb (http_parser *p, const char *buf, size_t len)
{
    http_msg *msg = p->data;

    //FIXME: check for buffer overflow prior to strncat
    strncat(msg->request_url, buf, len);
    return 0;
}

int query_string_cb (http_parser *p, const char *buf, size_t len)
{
    http_msg *msg = p->data;

    //FIXME: check for buffer overflow prior to strncat
    strncat(msg->query_string, buf, len);
    return 0;
}

int fragment_cb (http_parser *p, const char *buf, size_t len)
{
    http_msg *msg = p->data;

    //FIXME: check for buffer overflow prior to strncat
    strncat(msg->fragment, buf, len);
    return 0;
}

int header_field_cb (http_parser *p, const char *buf, size_t len)
{
    http_msg *msg = p->data;

    if (msg->last_header_element != FIELD)
        msg->num_headers++;

    //FIXME: check for buffer overflow prior to strncat
    strncat(msg->headers[msg->num_headers-1][0], buf, len);

    msg->last_header_element = FIELD;

    return 0;
}

int header_value_cb (http_parser *p, const char *buf, size_t len)
{
    http_msg *msg = p->data;

    //FIXME: check for buffer overflow prior to strncat
    strncat(msg->headers[msg->num_headers-1][1], buf, len);

    msg->last_header_element = VALUE;

    return 0;
}

int body_cb (http_parser *p, const char *buf, size_t len)
{
    http_msg *msg = p->data;

    if (msg->body_size + len >= MAX_BODY_SIZE) {
        fprintf(stderr, "Maximum HTTP body size exceeded\n");
        return -1;
    }
    strncat(msg->body, buf, len);
    msg->body_size += len;
    return 0;
}

int count_body_cb (http_parser *p, const char *buf, size_t len)
{
    http_msg *msg = p->data;

    msg->body_size += len;
    return 0;
}

int message_begin_cb (http_parser *p)
{
    http_msg *msg = p->data;

    msg->message_begin_cb_called = 1;
    return 0;
}

int headers_complete_cb (http_parser *p)
{
    http_msg *msg = p->data;

    msg->method = p->method;
    msg->status_code = p->status_code;
    msg->http_major = p->http_major;
    msg->http_minor = p->http_minor;
    msg->headers_complete_cb_called = 1;
    msg->should_keep_alive = http_should_keep_alive(p);
    return 0;
}

int message_complete_cb (http_parser *p)
{
    http_msg *msg = p->data;

    if (msg->should_keep_alive != http_should_keep_alive(p))
    {
        fprintf(stderr, "\n\n *** Error http_should_keep_alive() should have same "
                "value in both on_message_complete and on_headers_complete "
                "but it doesn't! ***\n\n");
        return 1;
    }
    msg->message_complete_cb_called = 1;

    msg->message_complete_on_eof = currently_parsing_eof;

    return 0;
}




static http_parser_settings settings =
{.on_message_begin = message_begin_cb
 ,.on_header_field = header_field_cb
 ,.on_header_value = header_value_cb
 ,.on_path = request_path_cb
 ,.on_url = request_url_cb
 ,.on_fragment = fragment_cb
 ,.on_query_string = query_string_cb
 ,.on_body = body_cb
 ,.on_headers_complete = headers_complete_cb
 ,.on_message_complete = message_complete_cb};

http_parser * murl_http_parser_init (enum http_parser_type type, http_msg *msg)
{
    http_parser *parser;

    parser = calloc(1, sizeof(http_parser));
    if (!parser) {
        fprintf(stderr, "malloc failed (%s)\n", __FUNCTION__);
	return NULL;
    }
    http_parser_init(parser, type);
    parser->data = msg;

    return parser;
}

void murl_http_parser_free (http_parser *parser)
{
    free(parser);
}

size_t murl_http_parse (http_parser *parser, const char *buf, size_t len)
{
    size_t nparsed;
    currently_parsing_eof = (len == 0);
    nparsed = http_parser_execute(parser, &settings, buf, len);
    return nparsed;
}

/*
 * This routine will perform HTTP parsing on the data provided.
 *
 * Returns 0 on success, non-zero on error.
 */
int murl_http_parse_response (SessionHandle *ctx, const char *buf)
{
    size_t parsed;
    int rv;
    int len;
    http_parser *parser;
    http_msg *msg;

    msg = calloc(1, sizeof(http_msg));
    if (!msg) {
        fprintf(stderr, "malloc failed (%s)\n", __FUNCTION__);
	return 1;
    }

    /*
     * Initialize the parser
     */
    parser = murl_http_parser_init(HTTP_RESPONSE, msg);
    if (!parser) {
        fprintf(stderr, "murl_http_parser_init failed (%s)\n", __FUNCTION__);
	free(msg);
	return 1;
    }

    /*
     * Parse the data
     */
    parsed = murl_http_parse(parser, buf, strlen(buf));

    /*
     * check that all of it was parsed
     */
    rv = (parsed == strlen(buf));
    parsed = murl_http_parse(parser, NULL, 0);
    rv &= (parsed == 0);

    /*
     * Save the HTTP status code sent by the server
     */
    ctx->http_status_code = parser->status_code;
    murl_http_parser_free(parser);

    if (!rv) {
        fprintf(stderr, "HTTP parsing failed\n");
	free(msg);
        return 1;
    }

    len = msg->body_size;
    if (ctx->recv_buf) {
	free(ctx->recv_buf); 
	ctx->recv_buf = NULL;
	ctx->recv_ctr = 0;
    }
    ctx->recv_buf = calloc(1, len+1);
    if (!ctx->recv_buf) {
        fprintf(stderr, "\nmalloc failed in curl write reg func\n");
	free(msg);
        return 1;
    }

    /*
     * Copy the data to the Murl context
     */
    memcpy(ctx->recv_buf, msg->body, len);
    ctx->recv_buf[len] = 0;
    ctx->recv_ctr += len;
    free(msg);

    return 0;
}




