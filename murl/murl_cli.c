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
#include <stdio.h>
#include <murl/murl.h>

static size_t http_body_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    if (size != 1) {
        fprintf(stderr, "\nmurl size not 1\n");
        return 0;
    }

    printf("%s", (char *)ptr);

    return nmemb;
}

/*
 * Sample test app that shows how to use Murl
 */
int main(int argc, char **argv)
{
    long http_code = 0;
    CURL *hnd;

    if (argc != 3) {
	fprintf(stderr, "\nUsage: murl <pem_cacert_file> <url>\n\n");
	exit(1);
    }

    /*
     * Setup Murl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, argv[2]);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "murl");
    curl_easy_setopt(hnd, CURLOPT_CAINFO, argv[1]);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);

    /*
     * If the caller wants the HTTP data from the server
     * set the callback function
     */
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, &http_body_cb);

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
    curl_global_cleanup();

    return (http_code==200?0:1);
}
