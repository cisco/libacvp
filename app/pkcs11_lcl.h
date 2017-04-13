/** @file
 *  This is the private header file to be included by CiscoSSL
 *  using libacvp.
 */
/*****************************************************************************
* Copyright (c) 2016, Cisco Systems, Inc.
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
#ifndef pkcs11_lcl_h
#define pkcs11_lcl_h

#ifdef __cplusplus
extern "C"
{
#endif

/* configuration defines */
#define ENABLE_NSS_DRBG 1 
/*#define ENABLE_ALL_TESTS 1  */

#include <pkcs11.h>
#ifndef CKM_INVALID_MECHANISM
#define CKM_INVALID_MECHANISM 0xffffffffL
#endif

/* The following do not have PKCS #11 defines. If you have vendor specific
 * mechanisms that implement these modes, replace the CKM_INVALID_MECHANISM
 * with your mechanism in the #define below. If your pkcs11.h includes
 * these already with the provided names, they will be picked up automatically
 */
#ifndef CKM_DES3_OFB64
#define CKM_DES3_OFB64 CKM_INVALID_MECHANISM
#endif
#ifndef CKM_DES3_OFB8
#define CKM_DES3_OFB8  CKM_INVALID_MECHANISM
#endif
#ifndef CKM_DES3_CFB1
#define CKM_DES3_CFB1  CKM_INVALID_MECHANISM
#endif
#ifndef CKM_DES3_CFB64
#define CKM_DES3_CFB64 CKM_INVALID_MECHANISM
#endif
#ifndef CKM_DES3_CFB8
#define CKM_DES3_CFB8  CKM_INVALID_MECHANISM
#endif

/* add the PKCS #11 2.40 defines if not in pkcs11.h. This allows us to use
 * PKCS #11 2.20 header files to compile this and still work at runtime
 * with newer pkcs11 modules */
#ifndef CKM_AES_OFB
#define CKM_AES_OFB                    0x00002104UL
#endif
#ifndef CKM_AES_CFB64
#define CKM_AES_CFB64                  0x00002105UL
#endif
#ifndef CKM_AES_CFB8
#define CKM_AES_CFB8                   0x00002106UL
#endif
#ifndef CKM_AES_CFB128
#define CKM_AES_CFB128                 0x00002107UL
#endif
#ifndef CKM_AES_CFB1
#define CKM_AES_CFB1                   0x00002108UL
#endif
#ifndef CKM_AES_KEY_WRAP
#define CKM_AES_KEY_WRAP               0x00002109UL
#endif

/* add PKCS #11 3.0 defines if not in pkcs11.h */
#ifndef CKF_MESSAGE_ENCRYPT
#define CKF_MESSAGE_ENCRYPT           0x000000002UL
#endif
#ifndef CKF_MESSAGE_DECRYPT
#define CKF_MESSAGE_DECRYPT           0x000000004UL
#endif




#ifdef __cplusplus
}
#endif
#endif
