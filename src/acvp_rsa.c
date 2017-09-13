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

static void set_bitlens(ACVP_RSA_TC *stc, int bitlen1, int bitlen2, int bitlen3, int bitlen4) {
    stc->keygen_tc->bitlen1 = bitlen1;
    stc->keygen_tc->bitlen2 = bitlen2;
    stc->keygen_tc->bitlen3 = bitlen3;
    stc->keygen_tc->bitlen4 = bitlen4;
}
static void populate_common_fields(ACVP_RSA_TC *stc, JSON_Object *tc_rsp) {
    json_object_set_string(tc_rsp, "seed", (char *)stc->keygen_tc->seed);
    json_object_set_string(tc_rsp, "e", BN_bn2hex(stc->keygen_tc->e));
    json_object_set_string(tc_rsp, "p", BN_bn2hex(stc->keygen_tc->p));
    json_object_set_string(tc_rsp, "q", BN_bn2hex(stc->keygen_tc->q));
    json_object_set_string(tc_rsp, "n", BN_bn2hex(stc->keygen_tc->n));
    json_object_set_string(tc_rsp, "d", BN_bn2hex(stc->keygen_tc->d));
}

static void populate_bitlens(ACVP_RSA_TC *stc, JSON_Object *tc_rsp) {
    json_object_set_number(tc_rsp, "bitlen1", stc->keygen_tc->bitlen1);
    json_object_set_number(tc_rsp, "bitlen2", stc->keygen_tc->bitlen2);
    json_object_set_number(tc_rsp, "bitlen3", stc->keygen_tc->bitlen3);
    json_object_set_number(tc_rsp, "bitlen4", stc->keygen_tc->bitlen4);
}

static ACVP_RESULT acvp_rsa_init_siggen_tc(ACVP_CTX *ctx,
                                    ACVP_RSA_SIG_TC *sigtc,
                                    unsigned int tc_id,
                                    ACVP_CIPHER alg_id,
                                    char *sig_type,
                                    unsigned int modulo,
                                    char *hash_alg,
                                    unsigned char *msg,
                                    unsigned int salt_len
                                    )
{

    if(sigtc->mode == ACVP_RSA_MODE_SIGGEN) {
        /*
         * make room for all items
         */
        sigtc->sig_type = calloc(RSA_SIG_TYPE_MAX, sizeof(char));
        sigtc->sig_attrs_tc = calloc(1, sizeof(ACVP_RSA_SIG_ATTRS_TC));
        if (!sigtc->sig_attrs_tc) {
            ACVP_LOG_ERR("Couldn't make SigGen sig attrs object");
            return ACVP_MALLOC_FAIL;
        }
        sigtc->sig_attrs_tc->hash_alg=(char *) calloc(1, RSA_HASH_ALG_MAX_LEN);
        if(!sigtc->sig_attrs_tc->hash_alg) {
            ACVP_LOG_ERR("Couldn't make SigGen hash alg buffer");
            return ACVP_MALLOC_FAIL;
        }
        sigtc->sig_attrs_tc->msg=(unsigned char *) calloc(1, RSA_MSG_MAX_LEN);
        if(!sigtc->sig_attrs_tc->msg) {
            ACVP_LOG_ERR("Couldn't make SigGen msg buffer");
            return ACVP_MALLOC_FAIL;
        }
        /*
         * only make room and assign value to saltLen if sigType is PKCS1PSS
         */
        if(strncmp(sig_type, RSA_SIG_TYPE_PKCS1PSS_NAME, RSA_SIG_TYPE_MAX_LEN ) != 0 ) {
            salt_len=0;
        }

        /*
         * assign value to all items
         */
        sigtc->sig_type = sig_type;
        sigtc->sig_attrs_tc->mode = sigtc->mode;
        sigtc->sig_attrs_tc->tc_id = tc_id;
        sigtc->sig_attrs_tc->modulo = modulo;
        sigtc->sig_attrs_tc->salt_len = salt_len;
        memcpy(sigtc->sig_attrs_tc->hash_alg, hash_alg, RSA_HASH_ALG_MAX_LEN);
        memcpy(sigtc->sig_attrs_tc->msg, msg, RSA_MSG_MAX_LEN);
    } else {
        ACVP_LOG_ERR("Cannot init for RSA modes other than SigGen");
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}
static ACVP_RESULT acvp_rsa_init_sigver_tc(ACVP_CTX *ctx,
                                    ACVP_RSA_SIG_TC *sigtc,
                                    unsigned int tc_id,
                                    ACVP_CIPHER alg_id,
                                    char *sig_type,
                                    unsigned int modulo,
                                    char *hash_alg,
                                    unsigned char *msg,
                                    unsigned char *e,
                                    unsigned char *n,
                                    unsigned char *sig
                                    )
{

    if(sigtc->mode == ACVP_RSA_MODE_SIGVER) {
        /*
         * make room for all items
         */
        sigtc->sig_attrs_tc = calloc(1, sizeof(ACVP_RSA_SIG_ATTRS_TC));
        if (!sigtc->sig_attrs_tc) {
            ACVP_LOG_ERR("Couldn't make SigVer sig attrs object");
            return ACVP_MALLOC_FAIL;
        }
        sigtc->sig_attrs_tc->hash_alg=(char *) calloc(1, RSA_HASH_ALG_MAX_LEN);
        if(!sigtc->sig_attrs_tc->hash_alg) {
            ACVP_LOG_ERR("Couldn't make SigVer hash alg buffer");
            return ACVP_MALLOC_FAIL;
        }
        sigtc->sig_attrs_tc->msg=(unsigned char *) calloc(1, RSA_MSG_MAX_LEN);
        if(!sigtc->sig_attrs_tc->msg) {
            ACVP_LOG_ERR("Couldn't make SigVer msg buffer");
            return ACVP_MALLOC_FAIL;
        }

        /*
         * assign value to all items
         */
        sigtc->sig_type = sig_type;
        sigtc->sig_attrs_tc->mode = sigtc->mode;
        sigtc->sig_attrs_tc->tc_id = tc_id;
        sigtc->sig_attrs_tc->modulo = modulo;
        strncpy(sigtc->sig_attrs_tc->hash_alg, hash_alg, RSA_HASH_ALG_MAX_LEN);
        strncpy(sigtc->sig_attrs_tc->msg, msg, RSA_MSG_MAX_LEN);
        BIGNUM * tmp_exp = NULL;
        if(!BN_hex2bn(&sigtc->sig_attrs_tc->e, e))
        {
            ACVP_LOG_ERR("Could not convert exponent hex string to BIGNUM while initializing SigVer test case");
            return ACVP_INVALID_ARG;
        }
        if(!BN_hex2bn(&sigtc->sig_attrs_tc->n, n))
        {
            ACVP_LOG_ERR("Could not convert modulus hex string to BIGNUM while initializing SigVer test case");
            return ACVP_INVALID_ARG;
        }
        if(!BN_hex2bn(&sigtc->sig_attrs_tc->s,sig))
        {
            ACVP_LOG_ERR("Could not convert exponent hex string to BIGNUM while initializing SigVer test case");
            return ACVP_INVALID_ARG;
        }
    } else {
        ACVP_LOG_ERR("Cannot init for RSA modes other than SigVer");
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_rsa_init_tc_keygen(ACVP_CTX *ctx,
                                    ACVP_RSA_TC *stc,
                                    unsigned int tc_id,
                                    ACVP_CIPHER alg_id,
                                    int info_gen_by_server,
                                    int rand_pq,
                                    unsigned int mod,
                                    char *hash_alg,
                                    char *prime_test,
                                    char *pub_exp,
                                    unsigned char *seed,
                                    BIGNUM *e,
                                    unsigned int bitlen1,
                                    unsigned int bitlen2,
                                    unsigned int bitlen3,
                                    unsigned int bitlen4,
                                    unsigned char *p_rand,
                                    unsigned char *q_rand,
                                    unsigned char *xp,
                                    unsigned char *xp1,
                                    unsigned char *xp2,
                                    unsigned char *xq,
                                    unsigned char *xq1,
                                    unsigned char *xq2
                                    )
{
    memset(stc, 0x0, sizeof(ACVP_RSA_TC));
    stc->rand_pq = rand_pq;

    switch(stc->mode) {
    case ACVP_RSA_MODE_KEYGEN:
        stc->keygen_tc = calloc(1, sizeof(ACVP_RSA_KEYGEN_TC));
        if (!stc->keygen_tc) return ACVP_MALLOC_FAIL;
        stc->keygen_tc->e = calloc(1, sizeof(BIGNUM));
        stc->keygen_tc->seed = calloc(1, sizeof(ACVP_RSA_SEEDLEN_MAX));
        stc->keygen_tc->hash_alg = calloc(12, sizeof(char));
        stc->keygen_tc->pub_exp = calloc(6, sizeof(char));
        stc->keygen_tc->prime_test = calloc(5, sizeof(char));
        if (rand_pq == RSA_RAND_PQ_B32 || rand_pq == RSA_RAND_PQ_B34 ||
            rand_pq == RSA_RAND_PQ_B35 || rand_pq == RSA_RAND_PQ_B36) {
            stc->keygen_tc->p = calloc(1, sizeof(BIGNUM));
            stc->keygen_tc->q = calloc(1, sizeof(BIGNUM));
            stc->keygen_tc->n = calloc(1, sizeof(BIGNUM));
            stc->keygen_tc->d = calloc(1, sizeof(BIGNUM));
        }
        if (rand_pq == RSA_RAND_PQ_B35 || rand_pq == RSA_RAND_PQ_B36) {
            stc->keygen_tc->prime_seed_p2 = calloc(1, sizeof(ACVP_RSA_SEEDLEN_MAX));
            stc->keygen_tc->prime_seed_q1 = calloc(1, sizeof(ACVP_RSA_SEEDLEN_MAX));
            stc->keygen_tc->prime_seed_q2 = calloc(1, sizeof(ACVP_RSA_SEEDLEN_MAX));
        }
        switch(rand_pq) {
            case RSA_RAND_PQ_B32:
                if (info_gen_by_server) {
                    stc->keygen_tc->e = e;
                    stc->keygen_tc->seed = seed;
                }
                break;
            case RSA_RAND_PQ_B33:
                stc->keygen_tc->prime_result = calloc(10, sizeof(char));
                stc->keygen_tc->e = e;
                stc->keygen_tc->p_rand = calloc(512, sizeof(char));
                stc->keygen_tc->p_rand = p_rand;
                stc->keygen_tc->q_rand = calloc(512, sizeof(char));
                stc->keygen_tc->q_rand = q_rand;
                if (info_gen_by_server) {
                    // TODO fill the supplied values in here -- looks like they
                    // are the same either way
                }
                break;
            case RSA_RAND_PQ_B34:
                if (info_gen_by_server) {
                    stc->keygen_tc->e = e;
                    stc->keygen_tc->seed = seed;
                    stc->keygen_tc->seed_len = (unsigned int)strnlen((char *)seed, ACVP_RSA_SEEDLEN_MAX);
                    set_bitlens(stc, bitlen1, bitlen2, bitlen3, bitlen4);
                }
                break;
            case RSA_RAND_PQ_B35:
                stc->keygen_tc->p1 = calloc(512, sizeof(char));
                stc->keygen_tc->p2 = calloc(512, sizeof(char));
                stc->keygen_tc->q1 = calloc(512, sizeof(char));
                stc->keygen_tc->q2 = calloc(512, sizeof(char));
                stc->keygen_tc->xq = calloc(512, sizeof(char));
                stc->keygen_tc->xp = calloc(512, sizeof(char));
                if (info_gen_by_server) {
                    stc->keygen_tc->e = e;
                    stc->keygen_tc->seed = seed;
                    stc->keygen_tc->seed_len = (unsigned int)strnlen((char *)seed, ACVP_RSA_SEEDLEN_MAX);
                    set_bitlens(stc, bitlen1, bitlen2, bitlen3, bitlen4);                }
                break;
            case RSA_RAND_PQ_B36:
                stc->keygen_tc->xp1 = calloc(512, sizeof(char));
                stc->keygen_tc->xp2 = calloc(512, sizeof(char));
                stc->keygen_tc->xq1 = calloc(512, sizeof(char));
                stc->keygen_tc->xq2 = calloc(512, sizeof(char));
                if (info_gen_by_server) {
                    stc->keygen_tc->e = e;
                    stc->keygen_tc->seed = seed;
                    stc->keygen_tc->seed_len = (unsigned int)strnlen((char *)seed, ACVP_RSA_SEEDLEN_MAX);
                    stc->keygen_tc->bitlen1 = bitlen1;
                    stc->keygen_tc->bitlen2 = bitlen2;
                    stc->keygen_tc->bitlen3 = bitlen3;
                    stc->keygen_tc->bitlen4 = bitlen4;
                    stc->keygen_tc->xp1 = xp1;
                    stc->keygen_tc->xp2 = xp2;
                    stc->keygen_tc->xq1 = xq1;
                    stc->keygen_tc->xq2 = xq2;
                }
                break;
            default:
                break;
        }
        break;
    default:
        break;
    }

    stc->mod = mod;

    return ACVP_SUCCESS;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_rsa_output_sig_tc(ACVP_CTX *ctx, ACVP_RSA_SIG_TC *sigtc, JSON_Object *tc_rsp)
{
    switch(sigtc->mode) {
        case ACVP_RSA_MODE_SIGGEN:
            /*
             * set the JSON vals
             */
            json_object_set_string(tc_rsp, ACVP_RSA_SIGVER_EXP_OBJ_NAME , BN_bn2hex(sigtc->sig_attrs_tc->e));
            json_object_set_string(tc_rsp, ACVP_RSA_SIGVER_MOD_OBJ_NAME, BN_bn2hex(sigtc->sig_attrs_tc->n));
            json_object_set_string(tc_rsp, ACVP_RSA_SIGVER_SIG_OBJ_NAME, BN_bn2hex(sigtc->sig_attrs_tc->s));
            break;
        case ACVP_RSA_MODE_SIGVER:
            /*
             * set the JSON vals
             */
            json_object_set_string(tc_rsp,ACVP_RSA_SIGVER_PASS_OBJ_NAME, sigtc->pass?ACVP_RSA_SIGVER_PASS_YES_OBJ_NAME:ACVP_RSA_SIGVER_PASS_NO_OBJ_NAME);
            break;
        default:
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
static ACVP_RESULT acvp_rsa_output_tc(ACVP_CTX *ctx, ACVP_RSA_TC *stc, JSON_Object *tc_rsp)
{
    switch(stc->mode) {
        case ACVP_RSA_MODE_KEYGEN:
        switch(stc->rand_pq) {
            case RSA_RAND_PQ_B33:
                json_object_set_string(tc_rsp, "primeResult", (char *)stc->keygen_tc->prime_result);
                break;
            case RSA_RAND_PQ_B32:
                populate_common_fields(stc, tc_rsp);
                break;
            case RSA_RAND_PQ_B34:
                populate_common_fields(stc, tc_rsp);
                populate_bitlens(stc, tc_rsp);
                break;
            case RSA_RAND_PQ_B35:
                populate_common_fields(stc, tc_rsp);
                populate_bitlens(stc, tc_rsp);
                json_object_set_string(tc_rsp, "primeSeedP2", (char *)stc->keygen_tc->prime_seed_p2);
                json_object_set_string(tc_rsp, "p1", (char *)stc->keygen_tc->p1);
                json_object_set_string(tc_rsp, "p2", (char *)stc->keygen_tc->p2);
                json_object_set_string(tc_rsp, "xP", (char *)stc->keygen_tc->xp);
                json_object_set_string(tc_rsp, "primeSeedQ1", (char *)stc->keygen_tc->prime_seed_q1);
                json_object_set_string(tc_rsp, "q1", (char *)stc->keygen_tc->q1);
                json_object_set_string(tc_rsp, "primeSeedQ2", (char *)stc->keygen_tc->prime_seed_q2);
                json_object_set_string(tc_rsp, "q2", (char *)stc->keygen_tc->q2);
                json_object_set_string(tc_rsp, "xQ", (char *)stc->keygen_tc->xq);
                break;
            case RSA_RAND_PQ_B36:
                populate_common_fields(stc, tc_rsp);
                populate_bitlens(stc, tc_rsp);
                json_object_set_string(tc_rsp, "xP1", (char *)stc->keygen_tc->xp1);
                json_object_set_string(tc_rsp, "xP2", (char *)stc->keygen_tc->xp2);
                json_object_set_string(tc_rsp, "xQ1", (char *)stc->keygen_tc->xq1);
                json_object_set_string(tc_rsp, "xQ2", (char *)stc->keygen_tc->xq2);
                break;
            default:
                break;
            }
            break;
        default:
            break;
    }

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_rsa_release_sig_tc(ACVP_RSA_SIG_TC *sigtc)
{
    if(sigtc->sig_attrs_tc->e) BN_free(sigtc->sig_attrs_tc->e);
    sigtc->sig_attrs_tc->e=NULL;
    if(sigtc->sig_attrs_tc->n) BN_free(sigtc->sig_attrs_tc->n);
    sigtc->sig_attrs_tc->n=NULL;
    if(sigtc->sig_attrs_tc->s) BN_free(sigtc->sig_attrs_tc->s);
    sigtc->sig_attrs_tc->s=NULL;

    if(sigtc->sig_attrs_tc->hash_alg) free(sigtc->sig_attrs_tc->hash_alg);
    sigtc->sig_attrs_tc->hash_alg=NULL;

    if(sigtc->sig_attrs_tc->msg) free(sigtc->sig_attrs_tc->msg);
    sigtc->sig_attrs_tc->msg=NULL;
    free(sigtc->sig_attrs_tc);
    sigtc->sig_attrs_tc=NULL;

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */

static ACVP_RESULT acvp_rsa_release_tc(ACVP_RSA_TC *stc)
{
    if(stc->keygen_tc->e) free(stc->keygen_tc->e);
    if(stc->keygen_tc->seed) free(stc->keygen_tc->seed);
    if(stc->keygen_tc->p) free(stc->keygen_tc->p);
    if(stc->keygen_tc->q) free(stc->keygen_tc->q);
    if(stc->keygen_tc->n) free(stc->keygen_tc->n);
    if(stc->keygen_tc->d) free(stc->keygen_tc->d);
    if(stc->keygen_tc->prime_result) free(stc->keygen_tc->prime_result);
    if(stc->keygen_tc->p_rand) free(stc->keygen_tc->p_rand);
    if(stc->keygen_tc->q_rand) free(stc->keygen_tc->q_rand);
    if(stc->keygen_tc->prime_seed_p2) free(stc->keygen_tc->prime_seed_p2);
    if(stc->keygen_tc->prime_seed_q1) free(stc->keygen_tc->prime_seed_q1);
    if(stc->keygen_tc->prime_seed_q2) free(stc->keygen_tc->prime_seed_q2);
    if(stc->keygen_tc->p1) free(stc->keygen_tc->p1);
    if(stc->keygen_tc->p2) free(stc->keygen_tc->p2);
    if(stc->keygen_tc->q1) free(stc->keygen_tc->q1);
    if(stc->keygen_tc->q2) free(stc->keygen_tc->q2);
    if(stc->keygen_tc->xq) free(stc->keygen_tc->xq);
    if(stc->keygen_tc->xp) free(stc->keygen_tc->xp);
    if(stc->keygen_tc->xp1) free(stc->keygen_tc->xp1);
    if(stc->keygen_tc->xp2) free(stc->keygen_tc->xp2);
    if(stc->keygen_tc->xq1) free(stc->keygen_tc->xq1);
    if(stc->keygen_tc->xq2) free(stc->keygen_tc->xq2);

    free(stc->keygen_tc);

    return ACVP_SUCCESS;
}

static int
acvp_kat_rsa_keygen(int info_gen_by_server, int rand_pq, ACVP_CAPS_LIST* cap,
        unsigned char** p_rand, JSON_Object* testobj, unsigned char** q_rand,
        unsigned char** seed, unsigned char** xp, unsigned char** xq,
        unsigned char** xp1, unsigned char** xq1, unsigned char** xp2,
        unsigned char** xq2)
{
    info_gen_by_server =
            cap->cap.rsa_cap->rsa_cap_mode_list->cap_mode_attrs.keygen->info_gen_by_server;
    if (!info_gen_by_server) {
        if (rand_pq == RSA_RAND_PQ_B33) {
            // "probRP"
            *p_rand = (unsigned char*) json_object_get_string(testobj, "pRand");
            *q_rand = (unsigned char*) json_object_get_string(testobj, "qRand");
        }
    }
    else {
        switch (rand_pq)
        {
        case RSA_RAND_PQ_B32: // "provRP"
            *seed = (unsigned char*) json_object_get_string(testobj, "seed");
            break;
        case RSA_RAND_PQ_B34: // "provPC"
            *seed = (unsigned char*) json_object_get_string(testobj, "seed");
            break;
        case RSA_RAND_PQ_B35: // "bothPC"
            *seed = (unsigned char*) json_object_get_string(testobj, "seed");
            *xp = (unsigned char*) json_object_get_string(testobj, "xP");
            *xq = (unsigned char*) json_object_get_string(testobj, "xQ");
            break;
        case RSA_RAND_PQ_B36: // "probPC"
            *seed = (unsigned char*) json_object_get_string(testobj, "seed");
            *xp = (unsigned char*) json_object_get_string(testobj, "xP");
            *xq = (unsigned char*) json_object_get_string(testobj, "xQ");
            *xp1 = (unsigned char*) json_object_get_string(testobj, "xP1");
            *xq1 = (unsigned char*) json_object_get_string(testobj, "xQ1");
            *xp2 = (unsigned char*) json_object_get_string(testobj, "xP2");
            *xq2 = (unsigned char*) json_object_get_string(testobj, "xQ2");
            break;
        case RSA_RAND_PQ_B33:
        default:
            break;
        }
    }
    return info_gen_by_server;
}

static ACVP_RESULT
acvp_prep_keygen(int rand_pq, unsigned int mod, int info_gen_by_server,
        unsigned int tc_id, ACVP_CIPHER alg_id,
        char* rand_pq_str, JSON_Object* groupobj, char* hash_alg,
        char* prime_test, char* pub_exp, JSON_Object* testobj,
        ACVP_CAPS_LIST* cap, ACVP_CTX* ctx, ACVP_RSA_TC* stc)
{
    ACVP_RESULT rv;
    /*
     * keygen attrs
     */
    unsigned char *p_rand, *q_rand, *seed, *xp, *xp1, *xp2, *xq, *xq1, *xq2;
    unsigned int bitlen1, bitlen2, bitlen3, bitlen4;
    BIGNUM* e;
    const char* exponent;
    rand_pq_str = (char*) json_object_get_string(groupobj, "randPQ");
    rand_pq = acvp_lookup_rsa_randpq_index(rand_pq_str);
    mod = json_object_get_number(groupobj, "modRSA");
    hash_alg = (char*) json_object_get_string(groupobj, "hashAlg");
    if (rand_pq == RSA_RAND_PQ_B33 || rand_pq == RSA_RAND_PQ_B35
            || rand_pq == RSA_RAND_PQ_B36)
        prime_test = (char *) json_object_get_string(groupobj, "primeTest");

    pub_exp = (char*) json_object_get_string(groupobj, "pubExp");
    exponent = json_object_get_string(testobj, "e");
    BN_hex2bn(&e, exponent);
    bitlen1 = (unsigned int) json_object_get_number(testobj, "bitlen1");
    bitlen2 = (unsigned int) json_object_get_number(testobj, "bitlen2");
    bitlen3 = (unsigned int) json_object_get_number(testobj, "bitlen3");
    bitlen4 = (unsigned int) json_object_get_number(testobj, "bitlen4");
    info_gen_by_server = acvp_kat_rsa_keygen(info_gen_by_server, rand_pq, cap,
            &p_rand, testobj, &q_rand, &seed, &xp, &xq, &xp1, &xq1, &xp2, &xq2);
    /*
     * Setup the test case data that will be passed down to
     * the crypto module.
     * TODO: this does mallocs, we can probably do the mallocs once for
     *       the entire vector set to be more efficient
     */
    rv = acvp_rsa_init_tc_keygen(ctx, &*stc, tc_id, alg_id, /* group info */
    info_gen_by_server, rand_pq, mod, hash_alg, prime_test, pub_exp, /* keygen params */
    seed, e, bitlen1, bitlen2, bitlen3, bitlen4, p_rand, q_rand, xp, xp1, xp2,
            xq, xq1, xq2);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("ERROR: RSA Key Gen testcase Init failed.");
    }
    return rv;
}

static ACVP_RESULT acvp_kat_rsa_sig(unsigned int tc_id, ACVP_CIPHER alg_id,
        JSON_Object* groupobj, JSON_Object* testobj, ACVP_CAPS_LIST* cap,
        ACVP_CTX* ctx, ACVP_RSA_SIG_TC* sigtc)
{
    ACVP_RESULT rv;

    /*
     * Sig attrs for group obj
     */
    char *sig_type;


    /*
     * siggen attrs for test obj
     */
    unsigned int salt_len;
    salt_len = 0;

    /*
     * sigver attrs for test obj
     */
    unsigned char *e;
    unsigned char *n;
    unsigned char *sig;

    /*
     * attrs common to siggen and sigver
     */
    unsigned int modulo;
    unsigned char *msg;
    char *hash_alg;

    sig_type = (char *)json_object_get_string(groupobj, "sigType");
    modulo = (unsigned int)json_object_get_number(groupobj, ACVP_RSA_SIG_MODULO_OBJ_NAME);
    hash_alg = (char *)json_object_get_string(groupobj, ACVP_RSA_TC_HASHALG_OBJ_NAME);
    msg = (unsigned char *)json_object_get_string(testobj, ACVP_RSA_SIG_MSG_OBJ_NAME);
    /*
     * set test obj
     */
    switch(sigtc->mode) {
    case ACVP_RSA_MODE_SIGGEN:
        if(strncmp(sig_type, RSA_SIG_TYPE_PKCS1PSS_NAME, RSA_SIG_TYPE_MAX_LEN ) == 0 ) {
            salt_len = (unsigned int)json_object_get_number(testobj, ACVP_RSA_SALTLEN_OBJ_NAME);
        }

        /*
         * Setup the test case data that will be passed down to
         * the crypto module.
         * TODO: this does mallocs,kat we can probably do the mallocs once for
         *       the entire vector set to be more efficient
         */
        rv = acvp_rsa_init_siggen_tc(ctx, sigtc, tc_id, alg_id, /* note: mode is set in kat_handler */
                sig_type, modulo, hash_alg, msg, salt_len); /* siggen attrs */
        break;
    case ACVP_RSA_MODE_SIGVER:
        e = (unsigned char *)json_object_get_string(groupobj, ACVP_RSA_SIGVER_EXP_OBJ_NAME);
        n = (unsigned char *)json_object_get_string(groupobj, ACVP_RSA_SIGVER_MOD_OBJ_NAME);
        sig = (unsigned char *)json_object_get_string(testobj, ACVP_RSA_SIGVER_SIG_OBJ_NAME);
        rv = acvp_rsa_init_sigver_tc(ctx, sigtc, tc_id, alg_id, /* note: mode is set in kat_handler */
                        sig_type, modulo, hash_alg, msg, e, n, sig); /* siggen attrs */
        break;
    default:
        break;
    }
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("ERROR: RSA Sig testcase Init failed.");
    }
    return rv;
}

ACVP_RESULT acvp_rsa_kat_handler(ACVP_CTX *ctx, JSON_Object *obj)
{
    unsigned int        tc_id;
    JSON_Value          *groupval;
    JSON_Object         *groupobj = NULL;
    JSON_Value          *testval;
    JSON_Object         *testobj = NULL;
    JSON_Array          *groups;
    JSON_Array          *tests;

    JSON_Value          *reg_arry_val  = NULL;
    JSON_Object         *reg_obj       = NULL;
    JSON_Array          *reg_arry      = NULL;

    int i, g_cnt;
    int j, t_cnt;

    JSON_Value          *r_vs_val = NULL;
    JSON_Object         *r_vs = NULL;
    JSON_Array          *r_tarr = NULL; /* Response testarray */
    JSON_Value          *r_tval = NULL; /* Response testval */
    JSON_Object         *r_tobj = NULL; /* Response testobj */
    ACVP_CAPS_LIST      *cap;
    ACVP_RSA_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RSA_SIG_TC     sigtc;
    ACVP_RESULT rv;
    const char          *alg_str = json_object_get_string(obj, "algorithm");
    char                *mode_str = NULL;
    ACVP_CIPHER            alg_id;
    char *json_result, *rand_pq_str;
    unsigned int mod;

    int info_gen_by_server, rand_pq;
    char *hash_alg, *prime_test, *pub_exp;

    if (!alg_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.rsa = &stc;

    /*
     * Get the crypto module handler for this hash algorithm
     */
    alg_id = acvp_lookup_cipher_index(alg_str);
    if (alg_id < ACVP_CIPHER_START) {
        ACVP_LOG_ERR("ERROR: unsupported algorithm (%s)", alg_str);
        return (ACVP_UNSUPPORTED_OP);
    }

    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ERROR: ACVP server requesting unsupported capability");
        return (ACVP_UNSUPPORTED_OP);
    }


    mode_str = (char *)json_object_get_string(obj, "mode");
    if (!mode_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'mode' from JSON");
        return (ACVP_MALFORMED_JSON);
    }
    ACVP_LOG_INFO("    RSA mode: %s", mode_str);
    tc.tc.rsa->mode = acvp_lookup_rsa_mode_index(mode_str);
    if (tc.tc.rsa->mode >= ACVP_RSA_MODE_END) {
        ACVP_LOG_ERR("unsupported RSA mode (%s)", mode_str);
        return (ACVP_UNSUPPORTED_OP);
    }

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("ERROR: Failed to create JSON response struct. ");
        return(rv);
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
    json_object_set_string(r_vs, "mode", mode_str);
    json_object_set_value(r_vs, "testResults", json_value_init_array());
    r_tarr = json_object_get_array(r_vs, "testResults");

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);

    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);


        ACVP_LOG_INFO("    Test group: %d", i);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new RSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            ACVP_LOG_INFO("             mode: %s", mode_str);
            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            switch(tc.tc.rsa->mode) {
            case ACVP_RSA_MODE_KEYGEN:
                /*
                 * Get a reference to the abstracted test case
                 */
                
                memset(&stc, 0x0, sizeof(ACVP_RSA_TC));
                tc.tc.rsa->keygen_tc = &stc;
                stc.mode = tc.tc.rsa->mode;

                /*
                 * Retrieve values from JSON and initialize the tc
                 */
                rv = acvp_prep_keygen(rand_pq, mod, info_gen_by_server,
                        tc_id, alg_id, rand_pq_str, groupobj, hash_alg,
                        prime_test, pub_exp, testobj, cap, ctx, &stc);

                /* Process the current test vector... */
                if (rv == ACVP_SUCCESS) {
                    rv = (cap->crypto_handler)(&tc);
                    if (rv != ACVP_SUCCESS) {
                        ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                        rv = ACVP_CRYPTO_MODULE_FAIL;
                        goto key_err;
                    }
                }

                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_rsa_output_tc(ctx, &stc, r_tobj);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                    goto key_err;
                }
                /*
                 * Release all the memory associated with the test case
                 */
 key_err:       acvp_rsa_release_tc(&stc);
                break;
            case ACVP_RSA_MODE_SIGVER:
            case ACVP_RSA_MODE_SIGGEN:
                /*
                 * Get a reference to the abstracted test case
                 */
                memset(&sigtc, 0x0, sizeof(ACVP_RSA_SIG_TC));
                tc.tc.rsa->sig_tc = &sigtc;
                sigtc.mode =  tc.tc.rsa->mode;

                /*
                 * Retrieve values from JSON and init tc
                 */
                rv = acvp_kat_rsa_sig(tc_id, alg_id, groupobj, testobj, cap, ctx, &sigtc);
                /* Process the current test vector... */
                if (rv == ACVP_SUCCESS) {
                    rv = (cap->crypto_handler)(&tc);
                    if (rv != ACVP_SUCCESS) {
                        ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                        rv = ACVP_CRYPTO_MODULE_FAIL;
                        goto sig_err;
                    }
                }

                /*
                 * Output the test case results using JSON
                 */
                rv = acvp_rsa_output_sig_tc(ctx, &sigtc, r_tobj);
                if (rv != ACVP_SUCCESS) {
                    ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                    goto sig_err;
                }
                /*
                 * Release all the memory associated with the test case
                 */
sig_err:        acvp_rsa_release_sig_tc(&sigtc);
                break;
            default:
                break;
            }

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
            if(rv != ACVP_SUCCESS) {
                goto end;
            }
        }
    }

end:json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp);
    if (ctx->debug == ACVP_LOG_LVL_VERBOSE) {
        printf("\n\n%s\n\n", json_result);
    } else {
        ACVP_LOG_INFO("\n\n%s\n\n", json_result);
    }
    json_free_serialized_string(json_result);

    return rv;
}

