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
/***************************************************************************
*                                  _   _ ____  _
*  Project                     ___| | | |  _ \| |
*                             / __| | | | |_) | |
*                            | (__| |_| |  _ <| |___
*                             \___|\___/|_| \_\_____|
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
#ifndef __MURL_EASY_H
#define __MURL_EASY_H
#ifdef  __cplusplus
extern "C" {
#endif

#include <stdlib.h>
typedef void CURL;

/*
 * libcurl external API function linkage decorations.
 */

#ifdef CURL_STATICLIB
#  define CURL_EXTERN
#elif defined(WIN32) || defined(_WIN32) || defined(__SYMBIAN32__)
#  if defined(BUILDING_LIBCURL)
#    define CURL_EXTERN  __declspec(dllexport)
#  else
#    define CURL_EXTERN  __declspec(dllimport)
#  endif
#elif defined(BUILDING_LIBCURL) && defined(CURL_HIDDEN_SYMBOLS)
#  define CURL_EXTERN CURL_EXTERN_SYMBOL
#else
#  define CURL_EXTERN
#endif


/* All possible error codes from all sorts of curl functions. Future versions
   may return other values, stay prepared.

   Always add new return codes last. Never *EVER* remove any. The return
   codes must remain the same!
 */

typedef enum {
    CURLE_OK = 0,
    CURLE_UNSUPPORTED_PROTOCOL,  /* 1 */
    CURLE_FAILED_INIT,           /* 2 */
    CURLE_URL_MALFORMAT,         /* 3 */
    CURLE_NOT_BUILT_IN,          /* 4 - [was obsoleted in August 2007 for
                                    7.17.0, reused in April 2011 for 7.21.5] */
    CURLE_COULDNT_RESOLVE_PROXY, /* 5 */
    CURLE_COULDNT_RESOLVE_HOST,  /* 6 */
    CURLE_COULDNT_CONNECT,       /* 7 */
    CURLE_FTP_WEIRD_SERVER_REPLY, /* 8 */
    CURLE_REMOTE_ACCESS_DENIED,  /* 9 a service was denied by the server
                                    due to lack of access - when login fails
                                    this is not returned. */
    CURLE_FTP_ACCEPT_FAILED,     /* 10 - [was obsoleted in April 2006 for
                                    7.15.4, reused in Dec 2011 for 7.24.0]*/
    CURLE_FTP_WEIRD_PASS_REPLY,  /* 11 */
    CURLE_FTP_ACCEPT_TIMEOUT,    /* 12 - timeout occurred accepting server
                                    [was obsoleted in August 2007 for 7.17.0,
                                    reused in Dec 2011 for 7.24.0]*/
    CURLE_FTP_WEIRD_PASV_REPLY,  /* 13 */
    CURLE_FTP_WEIRD_227_FORMAT,  /* 14 */
    CURLE_FTP_CANT_GET_HOST,     /* 15 */
    CURLE_HTTP2,                 /* 16 - A problem in the http2 framing layer.
                                    [was obsoleted in August 2007 for 7.17.0,
                                    reused in July 2014 for 7.38.0] */
    CURLE_FTP_COULDNT_SET_TYPE,  /* 17 */
    CURLE_PARTIAL_FILE,          /* 18 */
    CURLE_FTP_COULDNT_RETR_FILE, /* 19 */
    CURLE_OBSOLETE20,            /* 20 - NOT USED */
    CURLE_QUOTE_ERROR,           /* 21 - quote command failure */
    CURLE_HTTP_RETURNED_ERROR,   /* 22 */
    CURLE_WRITE_ERROR,           /* 23 */
    CURLE_OBSOLETE24,            /* 24 - NOT USED */
    CURLE_UPLOAD_FAILED,         /* 25 - failed upload "command" */
    CURLE_READ_ERROR,            /* 26 - couldn't open/read from file */
    CURLE_OUT_OF_MEMORY,         /* 27 */
    /* Note: CURLE_OUT_OF_MEMORY may sometimes indicate a conversion error
             instead of a memory allocation error if CURL_DOES_CONVERSIONS
             is defined
     */
    CURLE_OPERATION_TIMEDOUT,    /* 28 - the timeout time was reached */
    CURLE_OBSOLETE29,            /* 29 - NOT USED */
    CURLE_FTP_PORT_FAILED,       /* 30 - FTP PORT operation failed */
    CURLE_FTP_COULDNT_USE_REST,  /* 31 - the REST command failed */
    CURLE_OBSOLETE32,            /* 32 - NOT USED */
    CURLE_RANGE_ERROR,           /* 33 - RANGE "command" didn't work */
    CURLE_HTTP_POST_ERROR,       /* 34 */
    CURLE_SSL_CONNECT_ERROR,     /* 35 - wrong when connecting with SSL */
    CURLE_BAD_DOWNLOAD_RESUME,   /* 36 - couldn't resume download */
    CURLE_FILE_COULDNT_READ_FILE, /* 37 */
    CURLE_LDAP_CANNOT_BIND,      /* 38 */
    CURLE_LDAP_SEARCH_FAILED,    /* 39 */
    CURLE_OBSOLETE40,            /* 40 - NOT USED */
    CURLE_FUNCTION_NOT_FOUND,    /* 41 */
    CURLE_ABORTED_BY_CALLBACK,   /* 42 */
    CURLE_BAD_FUNCTION_ARGUMENT, /* 43 */
    CURLE_OBSOLETE44,            /* 44 - NOT USED */
    CURLE_INTERFACE_FAILED,      /* 45 - CURLOPT_INTERFACE failed */
    CURLE_OBSOLETE46,            /* 46 - NOT USED */
    CURLE_TOO_MANY_REDIRECTS,    /* 47 - catch endless re-direct loops */
    CURLE_UNKNOWN_OPTION,        /* 48 - User specified an unknown option */
    CURLE_TELNET_OPTION_SYNTAX,  /* 49 - Malformed telnet option */
    CURLE_OBSOLETE50,            /* 50 - NOT USED */
    CURLE_PEER_FAILED_VERIFICATION, /* 51 - peer's certificate or fingerprint
                                       wasn't verified fine */
    CURLE_GOT_NOTHING,           /* 52 - when this is a specific error */
    CURLE_SSL_ENGINE_NOTFOUND,   /* 53 - SSL crypto engine not found */
    CURLE_SSL_ENGINE_SETFAILED,  /* 54 - can not set SSL crypto engine as
                                    default */
    CURLE_SEND_ERROR,            /* 55 - failed sending network data */
    CURLE_RECV_ERROR,            /* 56 - failure in receiving network data */
    CURLE_OBSOLETE57,            /* 57 - NOT IN USE */
    CURLE_SSL_CERTPROBLEM,       /* 58 - problem with the local certificate */
    CURLE_SSL_CIPHER,            /* 59 - couldn't use specified cipher */
    CURLE_SSL_CACERT,            /* 60 - problem with the CA cert (path?) */
    CURLE_BAD_CONTENT_ENCODING,  /* 61 - Unrecognized/bad encoding */
    CURLE_LDAP_INVALID_URL,      /* 62 - Invalid LDAP URL */
    CURLE_FILESIZE_EXCEEDED,     /* 63 - Maximum file size exceeded */
    CURLE_USE_SSL_FAILED,        /* 64 - Requested FTP SSL level failed */
    CURLE_SEND_FAIL_REWIND,      /* 65 - Sending the data requires a rewind
                                    that failed */
    CURLE_SSL_ENGINE_INITFAILED, /* 66 - failed to initialise ENGINE */
    CURLE_LOGIN_DENIED,          /* 67 - user, password or similar was not
                                    accepted and we failed to login */
    CURLE_TFTP_NOTFOUND,         /* 68 - file not found on server */
    CURLE_TFTP_PERM,             /* 69 - permission problem on server */
    CURLE_REMOTE_DISK_FULL,      /* 70 - out of disk space on server */
    CURLE_TFTP_ILLEGAL,          /* 71 - Illegal TFTP operation */
    CURLE_TFTP_UNKNOWNID,        /* 72 - Unknown transfer ID */
    CURLE_REMOTE_FILE_EXISTS,    /* 73 - File already exists */
    CURLE_TFTP_NOSUCHUSER,       /* 74 - No such user */
    CURLE_CONV_FAILED,           /* 75 - conversion failed */
    CURLE_CONV_REQD,             /* 76 - caller must register conversion
                                    callbacks using curl_easy_setopt options
                                    CURLOPT_CONV_FROM_NETWORK_FUNCTION,
                                    CURLOPT_CONV_TO_NETWORK_FUNCTION, and
                                    CURLOPT_CONV_FROM_UTF8_FUNCTION */
    CURLE_SSL_CACERT_BADFILE,    /* 77 - could not load CACERT file, missing
                                    or wrong format */
    CURLE_REMOTE_FILE_NOT_FOUND, /* 78 - remote file not found */
    CURLE_SSH,                   /* 79 - error from the SSH layer, somewhat
                                    generic so the error message will be of
                                    interest when this has happened */

    CURLE_SSL_SHUTDOWN_FAILED,   /* 80 - Failed to shut down the SSL
                                    connection */
    CURLE_AGAIN,                 /* 81 - socket is not ready for send/recv,
                                    wait till it's ready and try again (Added
                                    in 7.18.2) */
    CURLE_SSL_CRL_BADFILE,       /* 82 - could not load CRL file, missing or
                                    wrong format (Added in 7.19.0) */
    CURLE_SSL_ISSUER_ERROR,      /* 83 - Issuer check failed.  (Added in
                                    7.19.0) */
    CURLE_FTP_PRET_FAILED,       /* 84 - a PRET command failed */
    CURLE_RTSP_CSEQ_ERROR,       /* 85 - mismatch of RTSP CSeq numbers */
    CURLE_RTSP_SESSION_ERROR,    /* 86 - mismatch of RTSP Session Ids */
    CURLE_FTP_BAD_FILE_LIST,     /* 87 - unable to parse FTP file list */
    CURLE_CHUNK_FAILED,          /* 88 - chunk callback reported error */
    CURLE_NO_CONNECTION_AVAILABLE, /* 89 - No connection available, the
                                      session will be queued */
    CURLE_SSL_PINNEDPUBKEYNOTMATCH, /* 90 - specified pinned public key did not
                                       match */
    CURLE_SSL_INVALIDCERTSTATUS, /* 91 - invalid certificate status */
    CURL_LAST /* never use! */
} CURLcode;

/* Signed integral data type used for curl_off_t. */
#define CURL_TYPEOF_CURL_OFF_T long
/* Data type definition of curl_off_t. */
typedef CURL_TYPEOF_CURL_OFF_T curl_off_t;


/*
 * This macro-mania below setups the CURLOPT_[what] enum, to be used with
 * curl_easy_setopt(). The first argument in the CINIT() macro is the [what]
 * word.
 */
/* long may be 32 or 64 bits, but we should never depend on anything else
   but 32 */
#define CURLOPTTYPE_LONG          0
#define CURLOPTTYPE_OBJECTPOINT   10000
#define CURLOPTTYPE_FUNCTIONPOINT 20000
#define CURLOPTTYPE_OFF_T         30000

enum {
  CURL_SSLVERSION_DEFAULT,
  CURL_SSLVERSION_TLSv1, /* TLS 1.x */
  CURL_SSLVERSION_SSLv2,
  CURL_SSLVERSION_SSLv3,
  CURL_SSLVERSION_TLSv1_0,
  CURL_SSLVERSION_TLSv1_1,
  CURL_SSLVERSION_TLSv1_2,
  CURL_SSLVERSION_TLSv1_3,

  CURL_SSLVERSION_LAST /* never use, keep last */
};

/* name is uppercase CURLOPT_<name>,
   type is one of the defined CURLOPTTYPE_<type>
   number is unique identifier */
#ifdef CINIT
#undef CINIT
#endif

#define CINIT(na,t,nu) CURLOPT_ ## na = CURLOPTTYPE_ ## t + nu

typedef enum {
    /* This is the FILE * or void * the regular output should be written to. */
    CINIT(WRITEDATA, OBJECTPOINT, 1),

    /* The full URL to get/put */
    CINIT(URL, OBJECTPOINT, 2),

    /* Function that will be called to store the output (instead of fwrite). The
     * parameters will use fwrite() syntax, make sure to follow them. */
    CINIT(WRITEFUNCTION, FUNCTIONPOINT, 11),

    /* POST static input fields. */
    CINIT(POSTFIELDS, OBJECTPOINT, 15),

    /* Set the User-Agent string (examined by some CGIs) */
    CINIT(USERAGENT, OBJECTPOINT, 18),

    /* This points to a linked list of headers, struct curl_slist kind. This
       list is also used for RTSP (in spite of its name) */
    CINIT(HTTPHEADER, OBJECTPOINT, 23),

    /* name of the file keeping your private SSL-certificate */
    CINIT(SSLCERT, OBJECTPOINT, 25),

    /* send FILE * or void * to store headers to, if you use a callback it
       is simply passed to the callback unmodified */
    CINIT(HEADERDATA, OBJECTPOINT, 29),

    /* What version to specifically try to use.
       See CURL_SSLVERSION defines below. */
    CINIT(SSLVERSION, LONG, 32),

    CINIT(CUSTOMREQUEST, OBJECTPOINT, 36),

    CINIT(NOPROGRESS, LONG, 43), /* shut off the progress meter */

    CINIT(POST, LONG, 47),       /* HTTP POST method */

    /* Set if we should verify the peer in ssl handshake, set 1 to verify. */
    CINIT(SSL_VERIFYPEER, LONG, 64),

    /* The CApath or CAfile used to validate the peer certificate
       this option is used only if SSL_VERIFYPEER is true */
    CINIT(CAINFO, OBJECTPOINT, 65),

    CINIT(HEADERFUNCTION, FUNCTIONPOINT, 79),

    /* Set if we should verify the Common name from the peer certificate in ssl
     * handshake, set 1 to check existence, 2 to ensure that it matches the
     * provided hostname. */
    CINIT(SSL_VERIFYHOST, LONG, 81),

    /* type of the file keeping your SSL-certificate ("DER", "PEM", "ENG") */
    CINIT(SSLCERTTYPE, OBJECTPOINT, 86),

    /* name of the file keeping your private SSL-key */
    CINIT(SSLKEY, OBJECTPOINT, 87),

    /* type of the file keeping your private SSL-key ("DER", "PEM", "ENG") */
    CINIT(SSLKEYTYPE, OBJECTPOINT, 88),

    /* The _LARGE version of the standard POSTFIELDSIZE option */
    CINIT(POSTFIELDSIZE_LARGE, OFF_T, 120),

    /* CRL file */
    CINIT(CRLFILE, OBJECTPOINT, 169),

    /* Collect certificate chain info and allow it to get retrievable with
     CURLINFO_CERTINFO after the transfer is complete. */
    CINIT(CERTINFO, LONG, 172),

    CINIT(TCP_KEEPALIVE, LONG, 213),

    /* Set if we should verify the server hostname against it's certificate (RFC6125) */
    CINIT(SSL_VERIFY_HOSTNAME, LONG, 901),

    CURLOPT_LASTENTRY /* the last unused */
} CURLoption;



#define CURLINFO_STRING   0x100000
#define CURLINFO_LONG     0x200000
#define CURLINFO_DOUBLE   0x300000
#define CURLINFO_SLIST    0x400000
#define CURLINFO_MASK     0x0fffff
#define CURLINFO_TYPEMASK 0xf00000

typedef enum {
    CURLINFO_NONE, /* first, never use this */
    CURLINFO_EFFECTIVE_URL = CURLINFO_STRING + 1,
    CURLINFO_RESPONSE_CODE = CURLINFO_LONG   + 2,
    CURLINFO_TOTAL_TIME = CURLINFO_DOUBLE + 3,
    CURLINFO_NAMELOOKUP_TIME = CURLINFO_DOUBLE + 4,
    CURLINFO_CONNECT_TIME = CURLINFO_DOUBLE + 5,
    CURLINFO_PRETRANSFER_TIME = CURLINFO_DOUBLE + 6,
    CURLINFO_SIZE_UPLOAD = CURLINFO_DOUBLE + 7,
    CURLINFO_SIZE_DOWNLOAD = CURLINFO_DOUBLE + 8,
    CURLINFO_SPEED_DOWNLOAD = CURLINFO_DOUBLE + 9,
    CURLINFO_SPEED_UPLOAD = CURLINFO_DOUBLE + 10,
    CURLINFO_HEADER_SIZE = CURLINFO_LONG   + 11,
    CURLINFO_REQUEST_SIZE = CURLINFO_LONG   + 12,
    CURLINFO_SSL_VERIFYRESULT = CURLINFO_LONG   + 13,
    CURLINFO_FILETIME = CURLINFO_LONG   + 14,
    CURLINFO_CONTENT_LENGTH_DOWNLOAD = CURLINFO_DOUBLE + 15,
    CURLINFO_CONTENT_LENGTH_UPLOAD = CURLINFO_DOUBLE + 16,
    CURLINFO_STARTTRANSFER_TIME = CURLINFO_DOUBLE + 17,
    CURLINFO_CONTENT_TYPE = CURLINFO_STRING + 18,
    CURLINFO_REDIRECT_TIME = CURLINFO_DOUBLE + 19,
    CURLINFO_REDIRECT_COUNT = CURLINFO_LONG   + 20,
    CURLINFO_PRIVATE = CURLINFO_STRING + 21,
    CURLINFO_HTTP_CONNECTCODE = CURLINFO_LONG   + 22,
    CURLINFO_HTTPAUTH_AVAIL = CURLINFO_LONG   + 23,
    CURLINFO_PROXYAUTH_AVAIL = CURLINFO_LONG   + 24,
    CURLINFO_OS_ERRNO = CURLINFO_LONG   + 25,
    CURLINFO_NUM_CONNECTS = CURLINFO_LONG   + 26,
    CURLINFO_SSL_ENGINES = CURLINFO_SLIST  + 27,
    CURLINFO_COOKIELIST = CURLINFO_SLIST  + 28,
    CURLINFO_LASTSOCKET = CURLINFO_LONG   + 29,
    CURLINFO_FTP_ENTRY_PATH = CURLINFO_STRING + 30,
    CURLINFO_REDIRECT_URL = CURLINFO_STRING + 31,
    CURLINFO_PRIMARY_IP = CURLINFO_STRING + 32,
    CURLINFO_APPCONNECT_TIME = CURLINFO_DOUBLE + 33,
    CURLINFO_CERTINFO = CURLINFO_SLIST  + 34,
    CURLINFO_CONDITION_UNMET = CURLINFO_LONG   + 35,
    CURLINFO_RTSP_SESSION_ID = CURLINFO_STRING + 36,
    CURLINFO_RTSP_CLIENT_CSEQ = CURLINFO_LONG   + 37,
    CURLINFO_RTSP_SERVER_CSEQ = CURLINFO_LONG   + 38,
    CURLINFO_RTSP_CSEQ_RECV = CURLINFO_LONG   + 39,
    CURLINFO_PRIMARY_PORT = CURLINFO_LONG   + 40,
    CURLINFO_LOCAL_IP = CURLINFO_STRING + 41,
    CURLINFO_LOCAL_PORT = CURLINFO_LONG   + 42,
    CURLINFO_TLS_SESSION = CURLINFO_SLIST  + 43,
    /* Fill in new entries below here! */

    CURLINFO_LASTONE = 43
} CURLINFO;

/* linked-list structure for the CURLOPT_QUOTE option (and other) */
struct curl_slist {
    char *data;
    struct curl_slist *next;
};

/* info about the certificate chain, only for OpenSSL builds. Asked
   for with CURLOPT_CERTINFO / CURLINFO_CERTINFO */
struct curl_certinfo {
  int num_of_certs;             /* number of certificates with information */
  struct curl_slist **certinfo; /* for each index in this array, there's a
                                   linked list with textual information in the
                                   format "name: value" */
};


/* CURLINFO_RESPONSE_CODE is the new name for the option previously known as
   CURLINFO_HTTP_CODE */
#define CURLINFO_HTTP_CODE CURLINFO_RESPONSE_CODE

void curl_free(void *p);

CURL_EXTERN CURL *curl_easy_init(void);
CURL_EXTERN CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...);
CURL_EXTERN CURLcode curl_easy_perform(CURL *curl);
CURL_EXTERN void curl_easy_cleanup(CURL *curl);
CURL_EXTERN CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...);
CURL_EXTERN void curl_global_cleanup(void);
CURL_EXTERN struct curl_slist *curl_slist_append(struct curl_slist *list, const char *data);
CURL_EXTERN void curl_slist_free_all(struct curl_slist *list);
CURL_EXTERN const char * curl_easy_strerror(CURLcode error);

typedef size_t (*curl_write_callback)(char *buffer,
                                      size_t size,
                                      size_t nitems,
                                      void *outstream);

#ifdef  __cplusplus
}
#endif

#endif
