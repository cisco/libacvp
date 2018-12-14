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


#define MAX_ARG_LEN 16
typedef struct test_args {
    char    arg_name[MAX_ARG_LEN];
    char    arg_val[MAX_ARG_LEN];
} TEST_ARGS;
#define TEST_ARG_CNT	8
static TEST_ARGS test_args[TEST_ARG_CNT] = {
    { "arg1", "arg1value" },
    { "argument2", "arg2value" },
    { "testarg3", "arg3test" },
    { "t4", "t4value" },
    { "anotherarg5", "yetanothervalue" },
    { "arg", "textarg" },
    { "z", "zvalue" },
    { "last8", "8lastvalue" },
};

/*
 * For now we'll just use a global variable to stash the HTTP response
 * from the server for all test cases.
 */
static char *http_response = NULL;
static int dumby_ctx = 0;
#define DUMBY_CTX_TEST_VAL 12311999


static size_t test_murl_get_body_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    int *usr_ctx = (int *)userdata;

    /*
     * Set the user context to a non-zero value.  Later this is checked to
     * confirm the userdata facility is working.
     */
    *usr_ctx = DUMBY_CTX_TEST_VAL;

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
 *
 * Returns 200 on success
 */
static int test_murl_http_get(char *url)
{
    long http_code = 0;
    CURL *hnd;
    int i;
    char *new_url = NULL;
    char tmp[128];

    new_url = malloc(strlen(url) + (TEST_ARG_CNT*(2*MAX_ARG_LEN+2)) + 2);
    if (!new_url) {
	fprintf(stderr, "malloc failed in %s\n", __FUNCTION__);
	return 1;
    }
    sprintf(new_url, "%s\?", url);

    /*
     * Add the test arguments to the URL
     */
    for (i=0; i<TEST_ARG_CNT; i++) {
	sprintf(tmp, "%s=%s&", test_args[i].arg_name, test_args[i].arg_val); 
	new_url = strcat(new_url, tmp);  
    }

    printf("\tGET URL: %s\n", new_url);

    /*
     * Setup Murl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, new_url);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "murl");
    curl_easy_setopt(hnd, CURLOPT_CAINFO, PUBLIC_ROOTS);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
    /*
     * If the caller wants the HTTP data from the server
     * set the callback function
     */
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &dumby_ctx);
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, &test_murl_get_body_cb);

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

    if (new_url) free(new_url);

    /*
     * Verify dumby context was set by the Murl handler
     */
    if (dumby_ctx != DUMBY_CTX_TEST_VAL) {
	fprintf(stderr, "CURLOPT_WRITEDATA facility failed (%s)\n", __FUNCTION__);
	return -1;
    }

    return http_code;
}

/*
 * This routine will parse the http_reponse value that was recieved
 * from the HTTPS test server.  It will compare the POSTed data
 * received from the server with the POST data we sent to the
 * server.  If they match, this routine returns zero. Otherwise
 * it fails.
 *
 * returns 0 on success, non-zero on failure
 */
static int test_murl_parse_http_response ()
{
    JSON_Value *val;
    JSON_Object *obj = NULL;
    JSON_Object *args_obj = NULL;
    const char *arg;
    int rv = 1;
    int i;

    val = json_parse_string(http_response);
    if (!val) {
        fprintf(stderr, "JSON parse error in %s", __FUNCTION__);
        return rv;
    }
    obj = json_value_get_object(val);
    args_obj = json_object_get_object(obj, "args");
    if (!args_obj) {
	fprintf(stderr, "No args in JSON object in %s\n", __FUNCTION__);
	rv = 1;
	goto json_parse_cleanup;
    }

    for (i=0; i<TEST_ARG_CNT; i++) {
	arg = json_object_get_string(args_obj, test_args[i].arg_name);
	if (!arg) {
	    fprintf(stderr, "Unable to find arg %s in HTTP response (%s)\n", test_args[i].arg_name, __FUNCTION__);
	    rv = 1;
	    goto json_parse_cleanup;
	}
	if (strcmp(arg, test_args[i].arg_val)) {
	    fprintf(stderr, "%s is mismatched value for arg %s in HTTP response (%s)\n", arg, test_args[i].arg_name, __FUNCTION__);
	    rv = 1;
	    goto json_parse_cleanup;
	}
    }
    rv = 0;

json_parse_cleanup:
    json_value_free(val);
    return rv;
}

/*
 * Performs a simple HTTP GET operation.
 * 
 * returns 0 on success, non-zero on failure.
 */
static int test_murl_simple_get ()
{
    int http_resp;
    int rv = 1;

    printf("Starting simple HTTP GET test...\n");
    
    http_resp = test_murl_http_get("https://httpbin.org/get");

    if (http_resp != 200) {
	printf("HTTP GET failed with response %d\n", http_resp);
	return rv;
    }

    /*
     * JSON parse the response from the server and extract the GET data.
     * It should match what we originally sent to the server.
     */
    rv = test_murl_parse_http_response();

    if (!rv) {
	printf("Simple HTTP GET test passed\n");
    } else {
	printf("Simple HTTP GET test failed.  Reponse from server:\n%s\n", http_response);
    }

    if (http_response) {
	free(http_response);
	http_response = NULL;
    }
    return rv;
}

/*
 * Performs a simple HTTP GET operation with
 * custom headers.
 * 
 * returns 0 on success, non-zero on failure.
 */
static int test_murl_headers_get()
{
    int rv = 1;
    long http_code = 0;
    CURL *hnd;
    struct curl_slist *slist = NULL;

    printf("\nStarting HTTP headers GET test...\n");

    slist = curl_slist_append(slist, "Content-Type: text/html");
    slist = curl_slist_append(slist, "Authorization: Bearer");

    /*
     * Setup Murl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, "https://httpbin.org/headers");
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "murl");
    curl_easy_setopt(hnd, CURLOPT_CAINFO, PUBLIC_ROOTS);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
    //Note: the httpbin.org server doesn't support POST using the /headers URI
    //curl_easy_setopt(hnd, CURLOPT_POST, 1L);
    //curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, TEST_POST_VALUE1);
    //curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(TEST_POST_VALUE1));
    /*
     * If the caller wants the HTTP data from the server
     * set the callback function
     */
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &dumby_ctx);
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, &test_murl_get_body_cb);

    /*
     * Send the HTTP GET request
     */
    curl_easy_perform(hnd);

    /*
     * Get the HTTP reponse status code from the server
     */
    curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);
    printf("HTTP status from server: %d\n", (int)http_code);

    /*
     * Check the response from the server
     */
    if (http_code == 200) {
	printf("%s", http_response);
	/*
	 * See if our headers are in the server response
	 */
	if (strstr(http_response, "Authorization") &&
	    strstr(http_response, "Bearer") &&
	    strstr(http_response, "Content-Type") &&
	    strstr(http_response, "text/html")) {
	    /*
	     * Signal success for this test
	     */
	    rv = 0;
	}
    }

    curl_easy_cleanup(hnd);
    hnd = NULL;
    if (slist) {
        curl_slist_free_all(slist);
        slist = NULL;
    }
    if (http_response) {
	free(http_response);
	http_response = NULL;
    }

    if (rv) {
	printf("HTTP headers GET test failed\n");
    } else {
	printf("HTTP headers GET test passed\n");
    }

    return rv;
}

/*
 * This function performs an HTTP GET using httpbin.org 
 * while omitting the trailing slash on the URL.
 * This improves code coverage of the URL parser in libmurl. 
 *
 * Returns zero on success, non-zero on failure
 */
static int test_murl_missing_slash(void)
{
    CURL *hnd;
    int rv = -1;
    CURLcode crv;
    long http_code = 0;

    printf("\nTesting Murl with omitted trailing slash in URL...\n");

    /*
     * Setup Murl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, "https://httpbin.org");
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "murl");
    curl_easy_setopt(hnd, CURLOPT_CAINFO, PUBLIC_ROOTS);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);

    /*
     * Send the HTTP GET request
     */
    crv = curl_easy_perform(hnd);
    if (crv == CURLE_OK) {
	rv = 0;
    } else {
	printf("test failed, crv=%d\n", crv);
    }

    /*
     * Get the HTTP reponse status code from the server
     */
    curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
	printf("Invalid HTTP response from server: %d\n", (int)http_code);
	rv = -1;
    }

    curl_easy_cleanup(hnd);
    hnd = NULL;

    LOG_RESULT(rv);
    return rv;
}


/*
 * This is the main entry point into the HTTPS GET
 * test suite.
 *
 * Returns zero on success, non-zero on any test
 * failure.
 */
int test_murl_get (void)
{
    int rv;
    int any_failures = 0;

    /*
     * First test case is a simple HTTP GET
     */
    rv = test_murl_simple_get();
    if (rv) any_failures = 1;

    rv = test_murl_headers_get();
    if (rv) any_failures = 1;

    /*
     * Test missing trailing slash in URL
     */
    rv = test_murl_missing_slash();
    if (rv) any_failures = 1;

    return any_failures;
}

