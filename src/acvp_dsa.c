/** @file */
/*****************************************************************************
* Copyright (c) 2016-2017, Cisco Systems, Inc.
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"

static ACVP_RESULT acvp_dsa_siggen_init_tc (ACVP_CTX *ctx,
                                     ACVP_DSA_TC *stc,
                                     unsigned int tc_id,
                                     ACVP_CIPHER alg_id,
                                     unsigned int num,
                                     unsigned char *index,
                                     int l,
                                     int n,
                                     unsigned char *sha,
                                     unsigned char *msg) {
    ACVP_RESULT rv;

    stc->l = l;
    stc->n = n;

    if (stc->l == 0) {
        return ACVP_INVALID_ARG;
    }
    if (stc->n == 0) {
        return ACVP_INVALID_ARG;
    }

        if (!strncmp((char *) sha, "SHA2-1", 6)) {
            stc->sha = ACVP_DSA_SHA1;
        }
        if (!strncmp((char *) sha, "SHA2-224", 8)) {
            stc->sha = ACVP_DSA_SHA224;
        }
        if (!strncmp((char *) sha, "SHA2-256", 8)) {
            stc->sha = ACVP_DSA_SHA256;
        }
        if (!strncmp((char *) sha, "SHA2-384", 8)) {
            stc->sha = ACVP_DSA_SHA384;
        }
        if (!strncmp((char *) sha, "SHA2-512", 8)) {
            stc->sha = ACVP_DSA_SHA512;
        }
        if (!strncmp((char *) sha, "sha2-512/224", 12)) {
            stc->sha = ACVP_DSA_SHA512_224;
        }
        if (!strncmp((char *) sha, "sha2-512/256", 12)) {
            stc->sha = ACVP_DSA_SHA512_256;
        }
        if (stc->sha == 0) {
            return ACVP_INVALID_ARG;
        }
        stc->msg = calloc(1, 1024);
        if (!stc->msg) { return ACVP_MALLOC_FAIL; }

        stc->msglen = strlen((const char *)msg)/2;
        rv = acvp_hexstr_to_bin((const unsigned char *) msg, stc->msg, 1024);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (msg)");
            return rv;
        }
        stc->p = calloc(1, ACVP_DSA_PQG_MAX);
        if (!stc->p) { return ACVP_MALLOC_FAIL; }
        stc->q = calloc(1, ACVP_DSA_PQG_MAX);
        if (!stc->q) { return ACVP_MALLOC_FAIL; }
        stc->g = calloc(1, ACVP_DSA_PQG_MAX);
        if (!stc->g) { return ACVP_MALLOC_FAIL; }
        stc->seed = calloc(1, ACVP_DSA_SEED_MAX);
        if (!stc->seed) { return ACVP_MALLOC_FAIL; }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_dsa_sigver_init_tc (ACVP_CTX *ctx,
                                     ACVP_DSA_TC *stc,
                                     unsigned int tc_id,
                                     ACVP_CIPHER alg_id,
                                     unsigned int num,
                                     unsigned char *index,
                                     int l,
                                     int n,
                                     unsigned char *sha,
                                     unsigned char *p,
                                     unsigned char *q,
                                     unsigned char *g,
                                     unsigned char *r,
                                     unsigned char *s,
                                     unsigned char *y,
                                     unsigned char *msg) {
    ACVP_RESULT rv;

    stc->l = l;
    stc->n = n;

    if (stc->l == 0) {
        return ACVP_INVALID_ARG;
    }
    if (stc->n == 0) {
        return ACVP_INVALID_ARG;
    }

        if (!strncmp((char *) sha, "SHA2-1", 6)) {
            stc->sha = ACVP_DSA_SHA1;
        }
        if (!strncmp((char *) sha, "SHA2-224", 8)) {
            stc->sha = ACVP_DSA_SHA224;
        }
        if (!strncmp((char *) sha, "SHA2-256", 8)) {
            stc->sha = ACVP_DSA_SHA256;
        }
        if (!strncmp((char *) sha, "SHA2-384", 8)) {
            stc->sha = ACVP_DSA_SHA384;
        }
        if (!strncmp((char *) sha, "SHA2-512", 8)) {
            stc->sha = ACVP_DSA_SHA512;
        }
        if (!strncmp((char *) sha, "sha2-512/224", 12)) {
            stc->sha = ACVP_DSA_SHA512_224;
        }
        if (!strncmp((char *) sha, "sha2-512/256", 12)) {
            stc->sha = ACVP_DSA_SHA512_256;
        }
        if (stc->sha == 0) {
            return ACVP_INVALID_ARG;
        }
        stc->msg = calloc(1, 1024);
        if (!stc->msg) { return ACVP_MALLOC_FAIL; }

    rv = acvp_hexstr_to_bin((const unsigned char *) msg, stc->msg, 1024);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    rv = acvp_hexstr_to_bin((const unsigned char *) p, stc->p, 1024);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    rv = acvp_hexstr_to_bin((const unsigned char *) q, stc->q, 1024);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    rv = acvp_hexstr_to_bin((const unsigned char *) g, stc->g, 1024);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    rv = acvp_hexstr_to_bin((const unsigned char *) r, stc->r, 1024);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    rv = acvp_hexstr_to_bin((const unsigned char *) s, stc->s, 1024);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    rv = acvp_hexstr_to_bin((const unsigned char *) y, stc->y, 1024);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    stc->msglen = strlen((const char *)msg)/2;
    rv = acvp_hexstr_to_bin((const unsigned char *) msg, stc->msg, 1024);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_dsa_pqggen_init_tc (ACVP_CTX *ctx,
                                     ACVP_DSA_TC *stc,
                                     unsigned int tc_id,
                                     ACVP_CIPHER alg_id,
                                     unsigned int gpq,
                                     unsigned int num,
                                     unsigned char *index,
                                     int l,
                                     int n,
                                     unsigned char *sha,
                                     unsigned char *p,
                                     unsigned char *q,
                                     unsigned char *seed) {
    ACVP_RESULT rv;

    stc->l = l;
    stc->n = n;

    if (stc->l == 0) {
        return ACVP_INVALID_ARG;
    }
    if (stc->n == 0) {
        return ACVP_INVALID_ARG;
    }
    if (!strncmp((char *) sha, "SHA2-1", 6)) {
        stc->sha = ACVP_DSA_SHA1;
    }
    if (!strncmp((char *) sha, "SHA2-224", 8)) {
        stc->sha = ACVP_DSA_SHA224;
    }
    if (!strncmp((char *) sha, "SHA2-256", 8)) {
        stc->sha = ACVP_DSA_SHA256;
    }
    if (!strncmp((char *) sha, "SHA2-384", 8)) {
        stc->sha = ACVP_DSA_SHA384;
    }
    if (!strncmp((char *) sha, "SHA2-512", 8)) {
        stc->sha = ACVP_DSA_SHA512;
    }
    if (!strncmp((char *) sha, "sha2-512/224", 12)) {
        stc->sha = ACVP_DSA_SHA512_224;
    }
    if (!strncmp((char *) sha, "sha2-512/256", 12)) {
        stc->sha = ACVP_DSA_SHA512_256;
    }
    if (stc->sha == 0) {
        return ACVP_INVALID_ARG;
    }

    stc->p = calloc(1, ACVP_DSA_PQG_MAX);
    if (!stc->p) { return ACVP_MALLOC_FAIL; }
    stc->q = calloc(1, ACVP_DSA_PQG_MAX);
    if (!stc->q) { return ACVP_MALLOC_FAIL; }
    stc->g = calloc(1, ACVP_DSA_PQG_MAX);
    if (!stc->g) { return ACVP_MALLOC_FAIL; }
    stc->seed = calloc(1, ACVP_DSA_SEED_MAX);
    if (!stc->seed) { return ACVP_MALLOC_FAIL; }

    stc->gen_pq = gpq;
    switch (gpq) {
    case ACVP_DSA_CANONICAL:
        stc->index = strtol((char *) index, NULL, 16);
        rv = acvp_hexstr_to_bin((const unsigned char *) seed, stc->seed, ACVP_DSA_SEED_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (seed)");
            return rv;
        }
        stc->seedlen = strlen((char *) stc->seed);
        stc->p = p;
        stc->q = q;
        break;
    case ACVP_DSA_UNVERIFIABLE:
        stc->p = p;
        stc->q = q;
        break;
    case ACVP_DSA_PROBABLE:
    case ACVP_DSA_PROVABLE:
        stc->num = num;
        break;
    default:
        ACVP_LOG_ERR("Invalid GPQ argument %d", gpq);
        return ACVP_INVALID_ARG;
        break;
    }
    return ACVP_SUCCESS;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_dsa_output_tc (ACVP_CTX *ctx, ACVP_DSA_TC *stc, JSON_Object *r_tobj) {
    ACVP_RESULT rv;
    char *tmp = NULL;

    switch (stc->mode) {
    case ACVP_DSA_MODE_PQGGEN:
        switch (stc->gen_pq) {
        case ACVP_DSA_CANONICAL:
        case ACVP_DSA_UNVERIFIABLE:
            json_object_set_string(r_tobj, "g", (char *) stc->g);
            break;
        case ACVP_DSA_PROBABLE:
        case ACVP_DSA_PROVABLE:
            tmp = calloc(1, ACVP_DSA_PQG_MAX);
            if (!tmp) {
                ACVP_LOG_ERR("Unable to malloc in acvp_aes_mct_output_tc");
                return ACVP_MALLOC_FAIL;
            }

            json_object_set_string(r_tobj, "p", (char *) stc->p);

            json_object_set_string(r_tobj, "q", (char *) stc->q);

            memset(tmp, 0x0, ACVP_DSA_SEED_MAX);
            rv = acvp_bin_to_hexstr(stc->seed, stc->seedlen, (unsigned char *) tmp);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("hex conversion failure (p)");
                return rv;
            }
            json_object_set_string(r_tobj, "seed", tmp);

            json_object_set_number(r_tobj, "counter", stc->counter);
            break;
        default:
            ACVP_LOG_ERR("Invalid mode argument %d", stc->mode);
            return ACVP_INVALID_ARG;
            break;
        }
        break;
    case ACVP_DSA_MODE_SIGGEN:
        json_object_set_string(r_tobj, "p", (char *) stc->p);
        json_object_set_string(r_tobj, "q", (char *) stc->q);
        json_object_set_string(r_tobj, "g", (char *) stc->g);
        json_object_set_string(r_tobj, "y", (char *) stc->y);
        json_object_set_string(r_tobj, "r", (char *) stc->r);
        json_object_set_string(r_tobj, "s", (char *) stc->s);
        break;
    case ACVP_DSA_MODE_SIGVER:
        json_object_set_string(r_tobj, "result", stc->result > 0 ? "passed" : "failed");
        break;

    case ACVP_DSA_MODE_PQGVER:
    case ACVP_DSA_MODE_KEYGEN:
    default:
        break;
    }

    free(tmp);
    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_dsa_release_tc (ACVP_DSA_TC *stc) {

    switch (stc->mode) {
    case ACVP_DSA_MODE_PQGGEN:
        free(stc->p);
        free(stc->q);
        free(stc->g);
        free(stc->seed);
        break;

    default:
        break;
    }

    memset(stc, 0x0, sizeof(ACVP_DSA_TC));

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_dsa_pqggen_handler (ACVP_CTX *ctx, ACVP_TEST_CASE tc, ACVP_CAPS_LIST *cap,
                                     JSON_Array *r_tarr, JSON_Object *groupobj) {
    unsigned char *gen_pq = NULL, *sha = NULL, *index = NULL, *gen_g = NULL;
    JSON_Array *tests;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *res_array = NULL;
    JSON_Array *res_tarr = NULL; /* Response resultsArray */
    JSON_Value *r_tval = NULL; /* Response testval */
    JSON_Object *r_tobj = NULL; /* Response testobj */
    int j, t_cnt, tc_id;
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *mval;
    JSON_Object *mobj = NULL;
    unsigned int num = 0, gpq = 0, n, l;
    unsigned char *p = NULL, *q = NULL, *seed = NULL;
    ACVP_DSA_TC *stc;

    gen_pq = (unsigned char *) json_object_get_string(groupobj, "genPQ");
    gen_g = (unsigned char *) json_object_get_string(groupobj, "genG");
    l = json_object_get_number(groupobj, "l");
    n = json_object_get_number(groupobj, "n");
    sha = (unsigned char *) json_object_get_string(groupobj, "sha");

    if (gen_pq) {
        ACVP_LOG_INFO("         genPQ: %s", gen_pq);
    }
    if (gen_g) {
        ACVP_LOG_INFO("          genG: %s", gen_g);
    }
    ACVP_LOG_INFO("             l: %d", l);
    ACVP_LOG_INFO("             n: %d", n);
    ACVP_LOG_INFO("           sha: %s", sha);

    tests = json_object_get_array(groupobj, "tests");
    t_cnt = json_array_get_count(tests);

    stc = tc.tc.dsa;

    for (j = 0; j < t_cnt; j++) {
        ACVP_LOG_INFO("Found new DSA PQGGen test vector...");
        testval = json_array_get_value(tests, j);
        testobj = json_value_get_object(testval);

        tc_id = (unsigned int) json_object_get_number(testobj, "tcId");

        ACVP_LOG_INFO("       Test case: %d", j);
        ACVP_LOG_INFO("            tcId: %d", tc_id);
        if (gen_g) {
            if (!strncmp((char *) gen_g, "canonical", 9)) {
                p = (unsigned char *) json_object_get_string(testobj, "p");
                q = (unsigned char *) json_object_get_string(testobj, "q");
                seed = (unsigned char *) json_object_get_string(testobj, "seed");
                index = (unsigned char *) json_object_get_string(testobj, "index");
                gpq = ACVP_DSA_CANONICAL;
                ACVP_LOG_INFO("               p: %s", p);
                ACVP_LOG_INFO("               q: %s", q);
                ACVP_LOG_INFO("            seed: %s", seed);
                ACVP_LOG_INFO("           index: %s", index);
            }
        }

        /* find the mode */
        if (gen_g) {
            if (!strncmp((char *) gen_g, "unverifiable", 12)) {
                p = (unsigned char *) json_object_get_string(testobj, "p");
                q = (unsigned char *) json_object_get_string(testobj, "q");
                gpq = ACVP_DSA_UNVERIFIABLE;
                ACVP_LOG_INFO("               p: %s", p);
                ACVP_LOG_INFO("               q: %s", q);
            }
        }
        if (gen_pq) {
            if (!strncmp((char *) gen_pq, "probable", 8)) {
                num = json_object_get_number(testobj, "num");
                gpq = ACVP_DSA_PROBABLE;
                ACVP_LOG_INFO("             num: %d", num);
            }
        }
        if (gen_pq) {
            if (!strncmp((char *) gen_pq, "provable", 8)) {
                num = json_object_get_number(testobj, "num");
                gpq = ACVP_DSA_PROVABLE;
                ACVP_LOG_INFO("             num: %d", num);
            }
        }


        /*
         * Setup the test case data that will be passed down to
         * the crypto module.
         * TODO: this does mallocs, we can probably do the mallocs once for
         *       the entire vector set to be more efficient
         */

        /* num used to define number of iterations for PROVABLE/PROBABLE */
        switch (gpq) {
        case ACVP_DSA_PROBABLE:
        case ACVP_DSA_PROVABLE:
            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);
            json_object_set_number(r_tobj, "tcId", tc_id);

            json_object_set_value(r_tobj, "resultsArray", json_value_init_array());
            res_tarr = json_object_get_array(r_tobj, "resultsArray");
            while (num--) {

                acvp_dsa_pqggen_init_tc(ctx, stc, tc_id, stc->cipher, gpq, num, index, l, n, sha, p, q, seed);

                /* Process the current DSA test vector... */
                rv = (cap->crypto_handler)(&tc);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("crypto module failed the operation");
                    return ACVP_CRYPTO_MODULE_FAIL;
                }

                mval = json_value_init_object();
                mobj = json_value_get_object(mval);
                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_dsa_output_tc(ctx, stc, mobj);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("JSON output failure in DSA module");
                    return rv;
                }

                /* Append the test response value to array */
                json_array_append_value(res_tarr, mval);

                stc->seedlen = 0;
                stc->counter = 0;
                stc->seed = 0;
            }
            /* Append the test response value to array */
            json_array_append_value(res_array, mval);
            break;

        case ACVP_DSA_CANONICAL:
        case ACVP_DSA_UNVERIFIABLE:
            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);
            json_object_set_number(r_tobj, "tcId", tc_id);

            /* Process the current DSA test vector... */
            acvp_dsa_pqggen_init_tc(ctx, stc, tc_id, stc->cipher, gpq, num, index, l, n, sha, p, q, seed);
            rv = (cap->crypto_handler)(&tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("crypto module failed the operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_dsa_output_tc(ctx, stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure in DSA module");
                return rv;
            }
            /* Append the test response value to array */
            json_array_append_value(res_tarr, r_tval);
            break;
        default:
            ACVP_LOG_ERR("Invalid DSA PQGGen mode");
            rv = ACVP_INVALID_ARG;
            break;
        }
    }
    /* Append the test response value to array */
    json_array_append_value(r_tarr, r_tval);
    return rv;
}

ACVP_RESULT acvp_dsa_siggen_handler (ACVP_CTX *ctx, ACVP_TEST_CASE tc, ACVP_CAPS_LIST *cap,
                                     JSON_Array *r_tarr, JSON_Object *groupobj) {
    unsigned char *sha = NULL, *index = NULL, *msg = NULL;
    JSON_Array *tests;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Value *r_tval = NULL; /* Response testval */
    int j, t_cnt, tc_id, l, n;
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *mval;
    JSON_Object *mobj = NULL;
    unsigned int num = 0;
    ACVP_DSA_TC *stc;

    l = json_object_get_number(groupobj, "l");
    n = json_object_get_number(groupobj, "n");
    sha = (unsigned char *) json_object_get_string(groupobj, "hashAlg");

    ACVP_LOG_INFO("             l: %d", l);
    ACVP_LOG_INFO("             n: %d", n);
    ACVP_LOG_INFO("           sha: %s", sha);

    tests = json_object_get_array(groupobj, "tests");
    t_cnt = json_array_get_count(tests);

    stc = tc.tc.dsa;

    for (j = 0; j < t_cnt; j++) {
        ACVP_LOG_INFO("Found new DSA SigGen test vector...");
        testval = json_array_get_value(tests, j);
        testobj = json_value_get_object(testval);

        tc_id = (unsigned int) json_object_get_number(testobj, "tcId");
        msg = (unsigned char *) json_object_get_string(testobj, "message");
        ACVP_LOG_INFO("       Test case: %d", j);
        ACVP_LOG_INFO("            tcId: %d", tc_id);
        ACVP_LOG_INFO("             msg: %s", msg);

        /*
         * Setup the test case data that will be passed down to
         * the crypto module.
         * TODO: this does mallocs, we can probably do the mallocs once for
         *       the entire vector set to be more efficient
         */
            /*
             * Create a new test case in the response
             */
                acvp_dsa_siggen_init_tc(ctx, stc, tc_id, stc->cipher, num, index, l, n, sha, msg);

                /* Process the current DSA test vector... */
                rv = (cap->crypto_handler)(&tc);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("crypto module failed the operation");
                    return ACVP_CRYPTO_MODULE_FAIL;
                }

                mval = json_value_init_object();
                mobj = json_value_get_object(mval);
                json_object_set_number(mobj, "tcId", tc_id);
                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_dsa_output_tc(ctx, stc, mobj);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("JSON output failure in DSA module");
                    return rv;
                }

                /* Append the test response value to array */
                json_array_append_value(r_tarr, mval);
    }
    /* Append the test response value to array */
    json_array_append_value(r_tarr, r_tval);
    return rv;
}

ACVP_RESULT acvp_dsa_sigver_handler (ACVP_CTX *ctx, ACVP_TEST_CASE tc, ACVP_CAPS_LIST *cap,
                                     JSON_Array *r_tarr, JSON_Object *groupobj) {
    unsigned char *sha = NULL, *index = NULL, *msg = NULL, *r = NULL, *s = NULL, *y = NULL;
    unsigned char *g = NULL;
    JSON_Array *tests;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Value *r_tval = NULL; /* Response testval */
    int j, t_cnt, tc_id, l, n;
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *mval;
    JSON_Object *mobj = NULL;
    unsigned int num = 0;
    unsigned char *p = NULL, *q = NULL;
    ACVP_DSA_TC *stc;

    l = json_object_get_number(groupobj, "l");
    n = json_object_get_number(groupobj, "n");
    sha = (unsigned char *) json_object_get_string(groupobj, "hashAlg");

    ACVP_LOG_INFO("             l: %d", l);
    ACVP_LOG_INFO("             n: %d", n);
    ACVP_LOG_INFO("           sha: %s", sha);

    tests = json_object_get_array(groupobj, "tests");
    t_cnt = json_array_get_count(tests);

    stc = tc.tc.dsa;

    for (j = 0; j < t_cnt; j++) {
        ACVP_LOG_INFO("Found new DSA SigVer test vector...");
        testval = json_array_get_value(tests, j);
        testobj = json_value_get_object(testval);

        tc_id = (unsigned int) json_object_get_number(testobj, "tcId");
        msg = (unsigned char *) json_object_get_string(testobj, "message");
        p = (unsigned char *) json_object_get_string(testobj, "p");
        q = (unsigned char *) json_object_get_string(testobj, "q");
        g = (unsigned char *) json_object_get_string(testobj, "g");
        r = (unsigned char *) json_object_get_string(testobj, "r");
        s = (unsigned char *) json_object_get_string(testobj, "s");
        y = (unsigned char *) json_object_get_string(testobj, "y");

        ACVP_LOG_INFO("       Test case: %d", j);
        ACVP_LOG_INFO("            tcId: %d", tc_id);
        ACVP_LOG_INFO("             msg: %s", msg);
        ACVP_LOG_INFO("               p: %s", p);
        ACVP_LOG_INFO("               q: %s", q);
        ACVP_LOG_INFO("               g: %s", g);
        ACVP_LOG_INFO("               r: %s", r);
        ACVP_LOG_INFO("               s: %s", s);
        ACVP_LOG_INFO("               y: %s", y);

        /*
         * Setup the test case data that will be passed down to
         * the crypto module.
         * TODO: this does mallocs, we can probably do the mallocs once for
         *       the entire vector set to be more efficient
         */
            /*
             * Create a new test case in the response
             */
                acvp_dsa_sigver_init_tc(ctx, stc, tc_id, stc->cipher, num, index, 
                                        l, n, sha, p, q, g, r, s, y, msg);

                /* Process the current DSA test vector... */
                rv = (cap->crypto_handler)(&tc);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("crypto module failed the operation");
                    return ACVP_CRYPTO_MODULE_FAIL;
                }

                mval = json_value_init_object();
                mobj = json_value_get_object(mval);
                json_object_set_number(mobj, "tcId", tc_id);
                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_dsa_output_tc(ctx, stc, mobj);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("JSON output failure in DSA module");
                    return rv;
                }

                /* Append the test response value to array */
                json_array_append_value(r_tarr, mval);
    }
    /* Append the test response value to array */
    json_array_append_value(r_tarr, r_tval);
    return rv;
}


ACVP_RESULT acvp_dsa_keygen_kat_handler (ACVP_CTX *ctx, JSON_Object *obj)
{
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_dsa_pqgver_kat_handler (ACVP_CTX *ctx, JSON_Object *obj)
{
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_dsa_pqggen_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *groups;
    ACVP_CAPS_LIST *cap;
    ACVP_DSA_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER alg_id;
    char *json_result;
    unsigned char *type;
    unsigned int g_cnt, i;

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.dsa = &stc;
    memset(&stc, 0x0, sizeof(ACVP_DSA_TC));

    /*
     * Get the crypto module handler for DSA mode
     */
    alg_id = ACVP_DSA_PQGGEN;
    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        return (ACVP_UNSUPPORTED_OP);
    }

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct. ");
        return (rv);
    }

    /*
     * Start to build the JSON response
     * TODO: This code will likely be common to all the algorithms, need to move this
     */
    if (ctx->kat_resp) {
        json_value_free(ctx->kat_resp);
    }
    ctx->kat_resp = reg_arry_val;
    r_vs_val = json_value_init_object();
    r_vs = json_value_get_object(r_vs_val);

    json_object_set_number(r_vs, "vsId", ctx->vs_id);
    json_object_set_string(r_vs, "algorithm", alg_str);
    json_object_set_value(r_vs, "testResults", json_value_init_array());
    r_tarr = json_object_get_array(r_vs, "testResults");

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);

    stc.cipher = alg_id;
    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        type = (unsigned char *) json_object_get_string(groupobj, "type");
        stc.mode = ACVP_DSA_MODE_PQGGEN;

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("          type: %s", type);

         rv = acvp_dsa_pqggen_handler(ctx, tc, cap, r_tarr, groupobj);
         if (rv != ACVP_SUCCESS) {
            return (rv);
         }
         acvp_dsa_release_tc(&stc);
    }

    json_array_append_value(reg_arry, r_vs_val);
    json_result = json_serialize_to_string_pretty(ctx->kat_resp);
    if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
        printf("\n\n%s\n\n", json_result);
    } else {
        ACVP_LOG_INFO("\n\n%s\n\n", json_result);
    }
    json_free_serialized_string(json_result);

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_dsa_siggen_kat_handler (ACVP_CTX *ctx, JSON_Object *obj)
{
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *groups;
    ACVP_CAPS_LIST *cap;
    ACVP_DSA_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER alg_id;
    char *json_result;
    unsigned char *type;
    unsigned int g_cnt, i;

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.dsa = &stc;
    memset(&stc, 0x0, sizeof(ACVP_DSA_TC));

    /*
     * Get the crypto module handler for DSA mode
     */
    alg_id = ACVP_DSA_SIGGEN;
    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        return (ACVP_UNSUPPORTED_OP);
    }

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct. ");
        return (rv);
    }

    /*
     * Start to build the JSON response
     * TODO: This code will likely be common to all the algorithms, need to move this
     */
    if (ctx->kat_resp) {
        json_value_free(ctx->kat_resp);
    }
    ctx->kat_resp = reg_arry_val;
    r_vs_val = json_value_init_object();
    r_vs = json_value_get_object(r_vs_val);

    json_object_set_number(r_vs, "vsId", ctx->vs_id);
    json_object_set_string(r_vs, "algorithm", alg_str);
    json_object_set_value(r_vs, "testResults", json_value_init_array());
    r_tarr = json_object_get_array(r_vs, "testResults");

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);

    stc.cipher = alg_id;
    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        type = (unsigned char *) json_object_get_string(groupobj, "type");
        stc.mode = ACVP_DSA_MODE_SIGGEN;

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("          type: %s", type);

        rv = acvp_dsa_siggen_handler(ctx, tc, cap, r_tarr, groupobj);
        if (rv != ACVP_SUCCESS) {
            return (rv);
        }
        acvp_dsa_release_tc(&stc);
    }

    json_array_append_value(reg_arry, r_vs_val);
    json_result = json_serialize_to_string_pretty(ctx->kat_resp);

/* TODO: we should check the return code */
    if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
        printf("\n\n%s\n\n", json_result);
    } else {
        ACVP_LOG_INFO("\n\n%s\n\n", json_result);
    }
    json_free_serialized_string(json_result);

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_dsa_sigver_kat_handler (ACVP_CTX *ctx, JSON_Object *obj)
{
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *groups;
    ACVP_CAPS_LIST *cap;
    ACVP_DSA_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER alg_id;
    char *json_result;
    unsigned char *type;
    unsigned int g_cnt, i;

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.dsa = &stc;
    memset(&stc, 0x0, sizeof(ACVP_DSA_TC));

    /*
     * Get the crypto module handler for DSA mode
     */
    alg_id = ACVP_DSA_SIGVER;
    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        return (ACVP_UNSUPPORTED_OP);
    }

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct. ");
        return (rv);
    }

    /*
     * Start to build the JSON response
     * TODO: This code will likely be common to all the algorithms, need to move this
     */
    if (ctx->kat_resp) {
        json_value_free(ctx->kat_resp);
    }
    ctx->kat_resp = reg_arry_val;
    r_vs_val = json_value_init_object();
    r_vs = json_value_get_object(r_vs_val);

    json_object_set_number(r_vs, "vsId", ctx->vs_id);
    json_object_set_string(r_vs, "algorithm", alg_str);
    json_object_set_value(r_vs, "testResults", json_value_init_array());
    r_tarr = json_object_get_array(r_vs, "testResults");

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);

    stc.cipher = alg_id;
    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        type = (unsigned char *) json_object_get_string(groupobj, "type");
        stc.mode = ACVP_DSA_MODE_SIGVER;

        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("          type: %s", type);

        rv = acvp_dsa_sigver_handler(ctx, tc, cap, r_tarr, groupobj);
        if (rv != ACVP_SUCCESS) {
            return (rv);
        }
        acvp_dsa_release_tc(&stc);
    }

    json_array_append_value(reg_arry, r_vs_val);
    json_result = json_serialize_to_string_pretty(ctx->kat_resp);
    if (!json_result) {
        ACVP_LOG_ERR("JSON unable to be serialized");
        return ACVP_JSON_ERR;
    }

    if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
        printf("\n\n%s\n\n", json_result);
    } else {
        ACVP_LOG_INFO("\n\n%s\n\n", json_result);
    }
    json_free_serialized_string(json_result);

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_dsa_kat_handler (ACVP_CTX *ctx, JSON_Object *obj)
{
    const char *mode = json_object_get_string(obj, "mode");

    if (!strncmp(mode, ACVP_ALG_DSA_PQGGEN, 6)) {
        return (acvp_dsa_pqggen_kat_handler(ctx, obj));
    }
    if (!strncmp(mode, ACVP_ALG_DSA_PQGVER, 6)) {
        return (acvp_dsa_pqgver_kat_handler(ctx, obj));
    }
    if (!strncmp(mode, ACVP_ALG_DSA_SIGGEN, 6)) {
        return (acvp_dsa_siggen_kat_handler(ctx, obj));
    }
    if (!strncmp(mode, ACVP_ALG_DSA_SIGVER, 6)) {
        return (acvp_dsa_sigver_kat_handler(ctx, obj));
    }
    if (!strncmp(mode, ACVP_ALG_DSA_KEYGEN, 6)) {
        return (acvp_dsa_keygen_kat_handler(ctx, obj));
    }
    return ACVP_INVALID_ARG;
}
