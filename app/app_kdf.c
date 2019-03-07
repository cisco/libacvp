/*****************************************************************************
* Copyright (c) 2019, Cisco Systems, Inc.
* All rights reserved.
*
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

#ifdef OPENSSL_KDF_SUPPORT

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>
#include "app_lcl.h"

#define TLS_MD_MASTER_SECRET_CONST              "master secret"
#define TLS_MD_MASTER_SECRET_CONST_SIZE         13
#define TLS_MD_KEY_EXPANSION_CONST              "key expansion"
#define TLS_MD_KEY_EXPANSION_CONST_SIZE         13

int app_kdf135_srtp_handler(ACVP_TEST_CASE *test_case) {
    return 1;
}

int app_kdf135_ikev2_handler(ACVP_TEST_CASE *test_case) {
    return 1;
}

int app_kdf135_ikev1_handler(ACVP_TEST_CASE *test_case) {
    return 1;
}

int app_kdf135_x963_handler(ACVP_TEST_CASE *test_case) {
    return 1;
}

int app_kdf108_handler(ACVP_TEST_CASE *test_case) {
    return 1;
}

int app_kdf135_tls_handler(ACVP_TEST_CASE *test_case) {
    return 1; 
}

int app_kdf135_snmp_handler(ACVP_TEST_CASE *test_case) {
    return 1;
}

int app_kdf135_ssh_handler(ACVP_TEST_CASE *test_case) {
    return 1;
}

#endif // OPENSSL_KDF_SUPPORT
