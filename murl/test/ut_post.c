/*
Copyright (c) 2016, Cisco Systems, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <string.h>
#include <murl/murl.h>
#include "parson.h"
#include "ut_lcl.h"


/*
 * For now we'll just use a global variable to stash the HTTP response
 * from the server for all test cases.
 */
static char *http_response = NULL;

static size_t test_murl_post_body_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    if (size != 1) {
        fprintf(stderr, "ERROR: murl size not 1 (%s)\n", __FUNCTION__);
        return 0;
    }

    if (http_response) free(http_response);
    http_response = calloc(1, nmemb);
    if (!http_response) {
	fprintf(stderr, "malloc failed (%s)\n", __FUNCTION__);
	exit(1);
    }

    memcpy(http_response, ptr, nmemb);

    //printf("%s", (char *)ptr);

    return nmemb;
}


/*
 * This function performs an HTTP POST using libmurl.
 * The return value is the HTTP status code from the
 * server.
 */
static int test_murl_post_http_post(char *url, char *post_data)
{
    long http_code = 0;
    CURL *hnd;

    printf("\tPOST URL: %s\n", url);

    /*
     * Setup Murl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, url);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "murl");
    curl_easy_setopt(hnd, CURLOPT_CAINFO, PUBLIC_ROOTS);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_POST, 1L);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(post_data));
    /*
     * If the caller wants the HTTP data from the server
     * set the callback function
     */
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, &test_murl_post_body_cb);

    /*
     * Send the HTTP GET request
     */
    curl_easy_perform(hnd);

    /*
     * Get the HTTP reponse status code from the server
     */
    curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);

    curl_easy_cleanup(hnd);
    hnd = NULL;

    printf("HTTP status from server: %d\n", (int)http_code);

    return http_code;
}

/*
 * This routine will parse the http_reponse value that was recieved
 * from the HTTPS test server.  It will compare the POSTed data
 * received from the server with the POST data we sent to the
 * server.  If they match, this routine returns zero. Otherwise
 * it fails.
 *
 * Arguments:
 *
 *  *match   Value to match against the received response from the server
 *
 * returns 0 on success, non-zero on failure
 */
static int test_murl_parse_http_response (char *match)
{
    JSON_Value *val;
    JSON_Object *obj = NULL;
    JSON_Object *hdr_obj = NULL;
    const char *data;
    const char *content_len;
    int cl;
    int rv = 1;

    val = json_parse_string(http_response);
    if (!val) {
        fprintf(stderr, "JSON parse error in %s", __FUNCTION__);
        return rv;
    }
    obj = json_value_get_object(val);
    data = json_object_get_string(obj, "data");
    if (!data) {
	fprintf(stderr, "No data in JSON object in %s\n", __FUNCTION__);
	rv = 1;
	goto json_parse_cleanup;
    }

    hdr_obj = json_object_get_object(obj, "headers");
    if (!hdr_obj) {
	fprintf(stderr, "No headers in JSON object in %s\n", __FUNCTION__);
	rv = 1;
	goto json_parse_cleanup;
    }
    content_len = json_object_get_string(hdr_obj, "Content-Length");
    if (!content_len) {
	fprintf(stderr, "No Content-Length in JSON header object (%s)\n", __FUNCTION__);
	rv = 1;
	goto json_parse_cleanup;
    }
    cl = atoi(content_len);
    printf("Returned Content-Length is %d\n", cl);

    if (memcmp(data, match, cl)) {
	fprintf(stderr, "POST data response from server did not match\n");
	rv = 1;
    } else {
	rv = 0;
    }
json_parse_cleanup:
    json_value_free(val);
    return rv;
}

/*
 * Performs a simple HTTP POST operation.
 * 
 * returns 0 on success, non-zero on failure.
 */
#define TEST_POST_VALUE1 "value1=1,value2=two"
static int test_murl_simple_post ()
{
    int http_resp;
    int rv = 1;

    printf("Starting simple HTTP POST test...\n");
    
    http_resp = test_murl_post_http_post("https://httpbin.org/post", TEST_POST_VALUE1);

    if (http_resp != 200) {
	printf("HTTP post failed with response %d\n", http_resp);
	return rv;
    }

    /*
     * JSON parse the response from the server and extract the POST data.
     * It should match what we originally sent to the server.
     */
    rv = test_murl_parse_http_response(TEST_POST_VALUE1);

    if (!rv) {
	printf("Simple HTTP POST test passed\n");
    } else {
	printf("Simple HTTP POST test failed.  Reponse from server:\n%s\n", http_response);
    }

    return rv;
}

/*
 * Performs a HTTP POST operation with large data.
 * 
 * returns 0 on success, non-zero on failure.
 */
//httpbin.org appears to support large POST, we'll limit to 1MB for now to avoid
//abusing their server.
#define LARGE_DATA_SZ	1024*1024//*63
static int test_murl_large_post ()
{
    int http_resp;
    char *data = NULL;
    int i;
    int rv = 1;

    printf("Starting large HTTP POST test (%d bytes)...\n", LARGE_DATA_SZ);
    /*
     * Create a blob to POST do the server
     */
    data = malloc(LARGE_DATA_SZ+1);
    if (!data) {
	printf("malloc failed in %s\n", __FUNCTION__);
	goto large_post_cleanup;
    }
    for (i=0; i<LARGE_DATA_SZ; i++) {
	data[i] = 65+(i%26);
    }
    data[LARGE_DATA_SZ] = 0;

    /*
     * POST the data to the server and collect the response
     */
    http_resp = test_murl_post_http_post("https://httpbin.org/post", data);


    if (http_resp != 200) {
	printf("HTTP post failed with response %d\n", http_resp);
	goto large_post_cleanup; 
    }
 
    /*
     * JSON parse the response from the server and extract the POST data.
     * It should match what we originally sent to the server.
     */
    rv = test_murl_parse_http_response(data);

    if (!rv) {
	printf("Large HTTP POST test passed\n");
    } else {
	printf("Large HTTP POST test failed.  Reponse from server:\n%s\n", http_response);
    }
large_post_cleanup:
    if (data) free(data);
    return rv;
}

/*
 * This is the main entry point into the HTTPS POST
 * test suite.
 *
 * Returns zero on success, non-zero on any test
 * failure.
 */
int test_murl_post (void)
{
    int rv;
    int any_failures = 0;

    /*
     * First test case is a simple HTTP POST
     */
    rv = test_murl_simple_post();
    if (rv) any_failures = 1;

    /*
     * Next test case is a HTTP POST of a large amount of data
     */
    rv = test_murl_large_post();
    if (rv) any_failures = 1;

    if (http_response) free(http_response);

    return any_failures;
}

