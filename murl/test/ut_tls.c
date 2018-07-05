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
#include <pthread.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <murl/murl.h>
#include "parson.h"
#include "ut_lcl.h"
#include <sys/types.h> 
#include <sys/socket.h>
#include <netdb.h>

#define SERVER_IP   "127.0.0.1"
#define SERVER_PORT 29516

#define COMMON_ROOT "test/certs/rootcert.pem"
#define SERVER_CERT_LVL1 "test/certs/server1.pem"
#define SERVER_KEY_LVL1 "test/certs/key1.pem"
#define SERVER_CERT_BADUSAGE "test/certs/server-bu.pem"
#define SERVER_KEY_BADUSAGE "test/certs/key-bu.pem"
#define SERVER_CERT_BADNAME "test/certs/server-bname.pem"
#define SERVER_KEY_BADNAME "test/certs/key-bname.pem"
#define SERVER_CERT_LVL7 "test/certs/server7chain.pem"
#define SERVER_KEY_LVL7 "test/certs/key7.pem"
#define TEST_GET_URL "https://httpbin.org/get"
#define TEST_LOCAL_URL "https://127.0.0.1:29516/index.html"
#define SELFSIGN_CERT "../certs/acvp.nist.gov.crt"


/*
 * Some globals for our little internal TLS server that's used
 * for some test cases.  We can only handle a single incoming
 * connection at any time, limiting test cases to be 
 * done sequentially. 
 */
static int server_running;
static char *server_cert;
static char *server_key;
static int server_sock;
static int server_ip_family = AF_INET;



static int create_server_connection()
{
    struct sockaddr *addr;
    struct addrinfo hints, *ai, *aiptr;
    char portstr[12];
    int on = 1;
    int rc;
    int new;
    int unsigned len;

    /*
     * Lookup the local address we'll use to bind too
     */
    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_family = server_ip_family; 
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; 
    snprintf(portstr, sizeof(portstr), "%u", SERVER_PORT);
    rc = getaddrinfo(NULL, portstr, &hints, &aiptr);
    if (rc) {
        printf("\ngetaddrinfo call failed\n");
	printf("getaddrinfo(): %s\n", gai_strerror(rc));
        exit(1);
    }
    for (ai = aiptr; ai; ai = ai->ai_next) {
        server_sock = socket(server_ip_family, SOCK_STREAM, IPPROTO_TCP);
        if (server_sock == -1) {
	    /* If we can't create a socket using this address, then
	     * try the next address */
	    continue;
        }
	/*
	 * Set some socket options for our server
	 */
        if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on))) {
            printf("\nsetsockopt REUSEADDR call failed\n");
            exit(1);
        }
        if (setsockopt(server_sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on))) {
            printf("\nsetsockopt KEEPALIAVE call failed\n");
            exit(1);
        }
	/*
	 * Bind to the socket 
	 */
        rc = bind(server_sock, ai->ai_addr, ai->ai_addrlen);
        if (rc == -1) {
            printf("\nbind call failed\n");
            exit(1);
        }
	break;
    }
    if (ai) {
	addr = ai->ai_addr;
	listen(server_sock, 1);
    } else {
        printf("\nNo address info found\n");
        exit(1);
    }
    freeaddrinfo(aiptr);

    len = sizeof(struct sockaddr);
    server_running = 1;
    new = accept(server_sock, (struct sockaddr*)addr, &len);
    return new;
}

static void destroy_server_connection()
{
    close(server_sock);
}


#define SERVER_RESP "HTTP/1.1 404 Not Found\r\nServer: murltest\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\nContent-Length: 38\r\nContent-Type: text/html\r\n\r\n<HTML><BODY>None</BODY></HTML>/r/n/r/n"

/*
 * This function runs a very simple TLS server to be used
 * with the various test cases.
 */
static void* tls_server_thread (void *arg)
{
    int conn;
    SSL *ssl;
    SSL_CTX *ssl_ctx = NULL;
    int rv;
    char buf[1024];
    /*
     * Create a TLS server context.  Here we use the SSLv23 method.
     * This method will attempt to negotiate the highest TLS version
     * supported by both the client and the server.  
     * If you want to enforce a specific TLS version, then use one
     * of the other methods, such as TLSv12_server_method().
     */
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx) {
	printf("Failed to create SSL context\n");
	ERR_print_errors_fp(stderr);
	exit(1);
    }
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    /*
     * Specify the certificate chain the server will send during the 
     * TLS handshake. 
     */
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, server_cert) != 1) {
	printf("Failed to load server certificate chain\n");
	ERR_print_errors_fp(stderr);
	exit(1);
    }
    /*
     * Specify the private key associated with the server's cert
     */
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, server_key, SSL_FILETYPE_PEM) != 1) {
	printf("Failed to load server private key\n");
	ERR_print_errors_fp(stderr);
	exit(1);
    }
#if 0
    /*
     * The following is optional, but required when doing TLS
     * client authentication.  This specifies the trusted root certificates 
     * that will be used for verifying the TLS peer.  
     */
    if (!SSL_CTX_load_verify_locations(ssl_ctx, CACERTS, NULL)) {
	printf("Failed to load trusted root certs\n");
	ERR_print_errors_fp(stderr);
	exit(1);
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, cert_chain_verify_cb);
#endif
    /*
     * Now that the SSL context is ready, open a socket
     * with the server and bind that socket to the context.
     */
    conn = create_server_connection();
    if (conn < 0) {
	printf("Unable to create a connection\n");
	exit(1);
    }
    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, conn);

    /*
     * Now that we have everything ready, let's start waiting for
     * a client to contact us.  Normally we might using a pthread
     * or some other construct to avoid blocking on the main 
     * thread while waiting for an incoming connection.  This
     * code is simply a contrived example, we will wait on the
     * main thread for an incoming connection.
     */
    rv = SSL_accept(ssl);
    if (rv <= 0) {
	printf("Failed to complete TLS handshake\n");
	ERR_print_errors_fp(stderr);
	goto cleanup;
    }

    /*
     * At this point the handshake has completed and the
     * peer has been verified.  You can use SSL_write and SSL_read
     * to send and receive data.
     */
    rv = SSL_read(ssl, buf, sizeof(buf));
    if (rv > 0) {
	/*
	 * make sure the data is null terminated 
	 */
	buf[rv] = 0;
	printf("Received text: %s\n", buf);

	/*
	 * Just blindly send back a 404 not found response
	 */
	SSL_write(ssl, SERVER_RESP, strlen(SERVER_RESP));
    } else {
	printf("Error while reading data\n");
	ERR_print_errors_fp(stderr);
	exit(1);
    }

    /*
     * When your application is done with the TLS session, 
     * invoke SSL_shutdown to close the session.  Also be
     * sure to free any resources you allocated for the context.
     */
cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(conn);
    destroy_server_connection();
    //BIO_free_all(listener);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ERR_remove_thread_state(NULL);
#endif

    server_running = 0;
    return NULL;
}

/*
 * This routine will spin up a new pthread and run
 * a TLS server on that thread.  This server is used with
 * the various test cases in this module.
 *
 * family parameter should be AF_INET or AF_INET6
 *
 * returns zero on success, non-zero on failure
 */
static int test_murl_start_server(char *cert, char *key, int family)
{
    pthread_t thread;

    if (server_running) {
	printf("TLS test server is already running!!!\n");
	return -1;
    }

    server_ip_family = family;
    server_cert = cert;
    server_key = key;

    pthread_create(&thread, NULL, tls_server_thread, NULL);
    return 0;
}

static void test_murl_stop_server(void)
{
    server_running = 0;
}

/*
 * This function performs an HTTP GET using root certs
 * not bound to the server certificate.  It is expected 
 * that the TLS connectino will fail.
 *
 * Returns zero on success, non-zero on failure
 */
static int test_murl_untrusted_server(void)
{
    CURL *hnd;
    int rv = -1;
    CURLcode crv;

    printf("\nTesting untrusted server cert fails TLS connection...\n");

    printf("\tGET URL: %s\n", TEST_GET_URL);

    /*
     * Setup Murl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, TEST_GET_URL);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "murl");
    curl_easy_setopt(hnd, CURLOPT_CAINFO, SELFSIGN_CERT);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);

    /*
     * Send the HTTP GET request
     */
    crv = curl_easy_perform(hnd);
    if (crv == CURLE_SSL_CONNECT_ERROR) {
	rv = 0;
    } else {
	printf("test failed, crv=%d\n", crv);
    }

    curl_easy_cleanup(hnd);
    hnd = NULL;

    LOG_RESULT(rv);
    return rv;
}

/*
 * This function performs an HTTP GET using a server that
 * doesn't have the key usage set properly in it's 
 * certificate.  Murl should fail the TLS connection.
 *
 * Returns zero on success, non-zero on failure
 */
static int test_murl_key_usage(void)
{
    CURL *hnd;
    int rv = -1;
    CURLcode crv;

    printf("\nTesting Murl checks server certificate key usage...\n");

    /*
     * start the simple test server
     */
    if (test_murl_start_server(SERVER_CERT_BADUSAGE, SERVER_KEY_BADUSAGE, AF_INET)) {
	printf("Unable to start test server, test case failed!\n");
	return rv;
    }
    while (!server_running) {
	printf("waiting for TLS server startup...\n");
	sleep(1);
    }

    printf("\tGET URL: %s\n", TEST_LOCAL_URL);

    /*
     * Setup Murl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, TEST_LOCAL_URL);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "murl");
    curl_easy_setopt(hnd, CURLOPT_CAINFO, COMMON_ROOT);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);

    /*
     * Send the HTTP GET request
     */
    crv = curl_easy_perform(hnd);
    if (crv == CURLE_SSL_CONNECT_ERROR) {
	rv = 0;
    } else {
	printf("test failed, crv=%d\n", crv);
    }

    /*
     * Stop the test server
     */
    test_murl_stop_server();

    curl_easy_cleanup(hnd);
    hnd = NULL;

    LOG_RESULT(rv);
    return rv;
}

/*
 * This function performs an HTTP GET using a server that
 * doesn't uses the wrong hostname in the CN of the server
 * certificate.  Murl should fail the TLS connection.
 *
 * Returns zero on success, non-zero on failure
 */
static int test_murl_rfc6125(void)
{
    CURL *hnd;
    int rv = -1;
    CURLcode crv;

    printf("\nTesting Murl checks server certificate hostname (RFC6125)...\n");

    /*
     * start the simple test server
     */
    if (test_murl_start_server(SERVER_CERT_BADNAME, SERVER_KEY_BADNAME, AF_INET)) {
	printf("Unable to start test server, test case failed!\n");
	return rv;
    }
    while (!server_running) {
	printf("waiting for TLS server startup...\n");
	sleep(1);
    }

    printf("\tGET URL: %s\n", TEST_LOCAL_URL);

    /*
     * Setup Murl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, TEST_LOCAL_URL);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "murl");
    curl_easy_setopt(hnd, CURLOPT_CAINFO, COMMON_ROOT);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);

    /*
     * Send the HTTP GET request
     */
    crv = curl_easy_perform(hnd);
    if (crv == CURLE_SSL_CONNECT_ERROR) {
	rv = 0;
    } else {
	printf("test failed, crv=%d\n", crv);
    }

    /*
     * Stop the test server
     */
    test_murl_stop_server();

    curl_easy_cleanup(hnd);
    hnd = NULL;

    LOG_RESULT(rv);
    return rv;
}


/*
 * This function performs an HTTP GET using a server that
 * uses a cert that's signed by a cert chain with more
 * than certifcate authorities.  The handshake should
 * fail since Murl limits the chain depth of 7.
 *
 * Returns zero on success, non-zero on failure
 */
static int test_murl_chain_depth(void)
{
    CURL *hnd;
    int rv = -1;
    CURLcode crv;

    printf("\nTesting Murl checks certificate chain depth limit...\n");

    /*
     * start the simple test server
     */
    if (test_murl_start_server(SERVER_CERT_LVL7, SERVER_KEY_LVL7, AF_INET)) {
	printf("Unable to start test server, test case failed!\n");
	return rv;
    }
    while (!server_running) {
	printf("waiting for TLS server startup...\n");
	sleep(1);
    }

    printf("\tGET URL: %s\n", TEST_LOCAL_URL);

    /*
     * Setup Murl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, TEST_LOCAL_URL);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "murl");
    curl_easy_setopt(hnd, CURLOPT_CAINFO, COMMON_ROOT);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);

    /*
     * Send the HTTP GET request
     */
    crv = curl_easy_perform(hnd);
    if (crv == CURLE_SSL_CONNECT_ERROR) {
	rv = 0;
    } else {
	printf("test failed, crv=%d\n", crv);
    }

    /*
     * Stop the test server
     */
    test_murl_stop_server();

    curl_easy_cleanup(hnd);
    hnd = NULL;

    LOG_RESULT(rv);
    return rv;
}

/*
 * This function performs an HTTP GET using a local server 
 * listening on an IPv6 address. 
 *
 * Returns zero on success, non-zero on failure
 */
static int test_murl_ipv6_address(void)
{
    CURL *hnd;
    int rv = -1;
    CURLcode crv;
    char v6_addr[50];
    char uri[250];
    long http_code = 0;

    printf("\nTesting Murl with IPv6 address...\n");
    if (test_murl_locate_ipv6_address (v6_addr, 50)) {
	printf("No IPv6 interfaces found, test skipped.\n");
	return 0;
    }

    /*
     * start the simple test server
     */
    if (test_murl_start_server(SERVER_CERT_LVL1, SERVER_KEY_LVL1, AF_INET6)) {
	printf("Unable to start test server, test case failed!\n");
	return rv;
    }
    while (!server_running) {
	printf("waiting for TLS server startup...\n");
	sleep(1);
    }

    /*
     * Build the URL with the v6 address
     */
    sprintf(uri, "https://[%s]:%d/index.html", v6_addr, SERVER_PORT);
    printf("\tGET URL: %s\n", uri);

    /*
     * Setup Murl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, uri);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "murl");
    curl_easy_setopt(hnd, CURLOPT_CAINFO, COMMON_ROOT);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);

    /*
     * Disable hostname check since the certs only have IPv4 addresses
     */
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFY_HOSTNAME, 0L);

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
     * Our little dummy server should always return a 404.
     */
    curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 404) {
	printf("Invalid HTTP response from server: %d\n", (int)http_code);
	rv = -1;
    }

    /*
     * Stop the test server
     */
    test_murl_stop_server();

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
int test_murl_tls (void)
{
    int rv;
    int any_failures = 0;
    /*
     * First test case is a simple HTTP GET
     * using an trust anchor that can't validate the server cert
     */
    rv = test_murl_untrusted_server();
    if (rv) any_failures = 1;

    /*
     * Next test case is a simple HTTP GET with server
     * using a cert w/o the key usage values set properly.
     */
    rv = test_murl_key_usage();
    if (rv) any_failures = 1;

    /*
     * Next test case is a simple HTTP GET with server
     * using a cert containing an invalid hostname.
     */
    rv = test_murl_rfc6125();
    if (rv) any_failures = 1;

    /*
     * Next test case is a simple HTTP GET with server
     * using a cert chain exceeding a depth of 7 is rejected
     * by Murl.
     */
    rv = test_murl_chain_depth();
    if (rv) any_failures = 1;

    /*
     * Test IPv6 address in URI
     */
    rv = test_murl_ipv6_address();
    if (rv) any_failures = 1;

    return any_failures;
}

