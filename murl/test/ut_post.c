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

//TODO: this assumes the unit test will be run from the 
//      top level murl directory
#define PUBLIC_ROOTS "../certs/mozzila_trust_anchors.pem"

static size_t test_murl_post_body_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    if (size != 1) {
        fprintf(stderr, "\nmurl size not 1\n");
        return 0;
    }

    //TODO: need to save the HTTP response from the server so
    //      we can json parse it and verify the data sent
    //      back from the server
    printf("%s", (char *)ptr);

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

    printf("\nHTTP status from server: %d\n", (int)http_code);

    return http_code;
}

/*
 * Performs a simple HTTP POST operation.
 * 
 * returns 0 on success, non-zero on failure.
 */
static int test_murl_simple_post ()
{
    int http_resp;
    
    http_resp = test_murl_post_http_post("https://httpbin.org/post", "value1=1,value2=two");

    if (http_resp == 200) {
	return 0;
    } else {
	printf("HTTP post failed with response %d\n", http_resp);
	return 1;
    }
}

/*
 * Performs a HTTP POST operation with large data.
 * 
 * returns 0 on success, non-zero on failure.
 */
//TODO: need to identify the max POST size allowed by httpbin.org
#define LARGE_DATA_SZ	10*1024 //*1024
static int test_murl_large_post ()
{
    int http_resp;
    char *data;
    int i;

    data = malloc(LARGE_DATA_SZ+1);
    if (!data) {
	printf("malloc failed in %s\n", __FUNCTION__);
	return 1;
    }
    for (i=0; i<LARGE_DATA_SZ; i++) {
	data[i] = 65+(i%26);
    }
    data[LARGE_DATA_SZ] = 0;
    
    http_resp = test_murl_post_http_post("https://httpbin.org/post", data);

    free(data);

    if (http_resp == 200) {
	return 0;
    } else {
	printf("HTTP post failed with response %d\n", http_resp);
	return 1;
    }

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

#if 0
    /*
     * Next test case is a HTTP POST of a large amount of data
     */
    rv = test_murl_large_post();
    if (rv) any_failures = 1;
#endif

    return any_failures;
}

