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

#ifdef ACVP_NO_RUNTIME

#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "app_fips_lcl.h" /* All regular OpenSSL headers must come before here */
#include "app_lcl.h"
#include "safe_mem_lib.h"

typedef struct {
    unsigned char *ent;
    size_t entlen;
    unsigned char *nonce;
    size_t noncelen;
} DRBG_TEST_ENT;

static size_t drbg_test_entropy(DRBG_CTX *dctx,
                                unsigned char **pout,
                                int entropy,
                                size_t min_len,
                                size_t max_len) {
    if (!dctx || !pout) return 0;

    DRBG_TEST_ENT *t = (DRBG_TEST_ENT *)FIPS_drbg_get_app_data(dctx);
    if (!t) return 0;

    if (t->entlen < min_len) printf("entropy data len < min_len: %zu\n", t->entlen);
    if (t->entlen > max_len) printf("entropy data len > max_len: %zu\n", t->entlen);
    *pout = (unsigned char *)t->ent;
    return t->entlen;
}

static size_t drbg_test_nonce(DRBG_CTX *dctx,
                              unsigned char **pout,
                              int entropy,
                              size_t min_len,
                              size_t max_len) {
    if (!dctx || !pout) return 0;

    DRBG_TEST_ENT *t = (DRBG_TEST_ENT *)FIPS_drbg_get_app_data(dctx);

    if (t->noncelen < min_len) printf("nonce data len < min_len: %zu\n", t->noncelen);
    if (t->noncelen > max_len) printf("nonce data len > max_len: %zu\n", t->noncelen);
    *pout = (unsigned char *)t->nonce;
    return t->noncelen;
}

int app_drbg_handler(ACVP_TEST_CASE *test_case) {
    int result = 1;
    ACVP_DRBG_TC    *tc;
    unsigned int nid;
    int der_func = 0;
    unsigned int drbg_entropy_len;
    int fips_rc;

    unsigned char   *nonce = NULL;

    if (!test_case) {
        return result;
    }

    tc = test_case->tc.drbg;
    /*
     * Init entropy length
     */
    drbg_entropy_len = tc->entropy_len;

    switch (tc->cipher) {
    case ACVP_HASHDRBG:
        nonce = tc->nonce;
        switch (tc->mode) {
        case ACVP_DRBG_SHA_1:
            nid = NID_sha1;
            break;
        case ACVP_DRBG_SHA_224:
            nid = NID_sha256;
            break;
        case ACVP_DRBG_SHA_256:
            nid = NID_sha256;
            break;
        case ACVP_DRBG_SHA_384:
            nid = NID_sha384;
            break;
        case ACVP_DRBG_SHA_512:
            nid = NID_sha512;
            break;

        case ACVP_DRBG_SHA_512_224:
        case ACVP_DRBG_SHA_512_256:
        default:
            printf("%s: Unsupported algorithm/mode %d/%d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
                   tc->cipher, tc->mode);
            return result;

            break;
        }
        break;

    case ACVP_HMACDRBG:
        nonce = tc->nonce;
        switch (tc->mode) {
        case ACVP_DRBG_SHA_1:
            nid =   NID_hmacWithSHA1;
            break;
        case ACVP_DRBG_SHA_224:
            nid =   NID_hmacWithSHA224;
            break;
        case ACVP_DRBG_SHA_256:
            nid =   NID_hmacWithSHA256;
            break;
        case ACVP_DRBG_SHA_384:
            nid =   NID_hmacWithSHA384;
            break;
        case ACVP_DRBG_SHA_512:
            nid =   NID_hmacWithSHA512;
            break;
        case ACVP_DRBG_SHA_512_224:
        case ACVP_DRBG_SHA_512_256:
        default:
            printf("%s: Unsupported algorithm/mode %d/%d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
                   tc->cipher, tc->mode);
            return result;

            break;
        }
        break;

    case ACVP_CTRDRBG:
        /*
         * DR function Only valid in CTR mode
         * if not set nonce is ignored
         */
        if (tc->der_func_enabled) {
            der_func = DRBG_FLAG_CTR_USE_DF;
            nonce = tc->nonce;
        } else {
            /**
             * Note 5: All DRBGs are tested at their maximum supported security
             * strength so this is the minimum bit length of the entropy input that
             * ACVP will accept.  The maximum supported security strength is also
             * the default value for this input.  Longer entropy inputs are
             * permitted, with the following exception: for ctrDRBG with no df, the
             * bit length must equal the seed length.
             **/
            drbg_entropy_len = 0;
        }

        switch (tc->mode) {
        case ACVP_DRBG_AES_128:
            nid = NID_aes_128_ctr;
            break;
        case ACVP_DRBG_AES_192:
            nid = NID_aes_192_ctr;
            break;
        case ACVP_DRBG_AES_256:
            nid = NID_aes_256_ctr;
            break;
        case ACVP_DRBG_3KEYTDEA:
        default:
            printf("%s: Unsupported algorithm/mode %d/%d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
                   tc->cipher, tc->mode);
            return result;

            break;
        }
        break;
    default:
        printf("%s: Unsupported algorithm %d (tc_id=%d)\n", __FUNCTION__, tc->tc_id,
               tc->cipher);
        return result;

        break;
    }

    DRBG_CTX *drbg_ctx = NULL;
    DRBG_TEST_ENT entropy_nonce;
    memzero_s(&entropy_nonce, sizeof(DRBG_TEST_ENT));
    drbg_ctx = FIPS_drbg_new(nid, der_func | DRBG_FLAG_TEST);
    if (!drbg_ctx) {
        printf("ERROR: failed to create DRBG Context.\n");
        return result;
    }

    /*
     * Set entropy and nonce
     */
    entropy_nonce.ent = tc->entropy;
    entropy_nonce.entlen = drbg_entropy_len;

    entropy_nonce.nonce = nonce;
    entropy_nonce.noncelen = tc->nonce_len;

    FIPS_drbg_set_app_data(drbg_ctx, &entropy_nonce);

    fips_rc = FIPS_drbg_set_callbacks(drbg_ctx,
                                      drbg_test_entropy,
                                      0, 0,
                                      drbg_test_nonce,
                                      0);
    if (!fips_rc) {
        printf("ERROR: failed to Set callback DRBG ctx\n");
        long l = 9;
        char buf[2048]  = { 0 };
        while ((l = ERR_get_error())) {
            printf("ERROR:%s\n", ERR_error_string(l, buf));
        }
        goto end;
    }

    fips_rc = FIPS_drbg_instantiate(drbg_ctx, (const unsigned char *)tc->perso_string,
                                    (size_t)tc->perso_string_len);
    if (!fips_rc) {
        printf("ERROR: failed to instantiate DRBG ctx\n");
        long l = 9;
        char buf[2048]  = { 0 };
        while ((l = ERR_get_error())) {
            printf("ERROR:%s\n", ERR_error_string(l, buf));
        }
        goto end;
    }

    /*
     * Process predictive resistance flag
     */
    if (tc->pred_resist_enabled) {
        entropy_nonce.ent = tc->entropy_input_pr;
        entropy_nonce.entlen = drbg_entropy_len;

        fips_rc =  FIPS_drbg_generate(drbg_ctx, (unsigned char *)tc->drb,
                                      (size_t)(tc->drb_len),
                                      (int)1,
                                      (const unsigned char *)tc->additional_input,
                                      (size_t)(tc->additional_input_len));
        if (!fips_rc) {
            printf("ERROR: failed to generate drb\n");
            long l;
            while ((l = ERR_get_error())) {
                printf("ERROR:%s\n", ERR_error_string(l, NULL));
            }
            goto end;
        }

        entropy_nonce.ent = tc->entropy_input_pr_1;
        entropy_nonce.entlen = drbg_entropy_len;

        fips_rc =  FIPS_drbg_generate(drbg_ctx, (unsigned char *)tc->drb,
                                      (size_t)(tc->drb_len),
                                      (int)1,
                                      (const unsigned char *)tc->additional_input_1,
                                      (size_t)(tc->additional_input_len));
        if (!fips_rc) {
            printf("ERROR: failed to generate drb\n");
            long l;
            while ((l = ERR_get_error())) {
                printf("ERROR:%s\n", ERR_error_string(l, NULL));
            }
            goto end;
        }
    } else {
        fips_rc = FIPS_drbg_generate(drbg_ctx, (unsigned char *)tc->drb,
                                     (size_t)(tc->drb_len),
                                     (int)0,
                                     (const unsigned char *)tc->additional_input,
                                     (size_t)(tc->additional_input_len));
        if (!fips_rc) {
            printf("ERROR: failed to generate drb\n");
            long l;
            while ((l = ERR_get_error())) {
                printf("ERROR:%s\n", ERR_error_string(l, NULL));
            }
            goto end;
        }
    }
    result = 0;

end:
    FIPS_drbg_uninstantiate(drbg_ctx);
    FIPS_drbg_free(drbg_ctx);

    return result;
}

#endif // ACVP_NO_RUNTIME

