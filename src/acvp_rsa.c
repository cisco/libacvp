#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"

static ACVP_RESULT acvp_rsa_init_tc(ACVP_CTX *ctx,
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

    void set_bitlens() {
        stc->keygen_tc->bitlen1 = bitlen1;
        stc->keygen_tc->bitlen2 = bitlen2;
        stc->keygen_tc->bitlen3 = bitlen3;
        stc->keygen_tc->bitlen4 = bitlen4;
    }

    switch(stc->mode) {
    case ACVP_RSA_MODE_KEYGEN:
        stc->keygen_tc = calloc(1, sizeof(ACVP_RSA_KEYGEN_TC));
        if (!stc->keygen_tc) return ACVP_MALLOC_FAIL;
        stc->keygen_tc->e = calloc(1, sizeof(BIGNUM));
        stc->keygen_tc->seed = calloc(1, sizeof(ACVP_RSA_SEEDLEN_MAX));
        stc->keygen_tc->hash_alg = calloc(12, sizeof(char));
        stc->keygen_tc->pub_exp = calloc(6, sizeof(char));
        stc->keygen_tc->prime_test = calloc(5, sizeof(char));
        if (rand_pq == 1 || rand_pq == 3 || rand_pq == 4 || rand_pq == 5) {
            stc->keygen_tc->p = calloc(1, sizeof(BIGNUM));
            stc->keygen_tc->q = calloc(1, sizeof(BIGNUM));
            stc->keygen_tc->n = calloc(1, sizeof(BIGNUM));
            stc->keygen_tc->d = calloc(1, sizeof(BIGNUM));
        }
        if (rand_pq == 4 || rand_pq == 5) {
            stc->keygen_tc->prime_seed_p2 = calloc(1, sizeof(ACVP_RSA_SEEDLEN_MAX));
            stc->keygen_tc->prime_seed_q1 = calloc(1, sizeof(ACVP_RSA_SEEDLEN_MAX));
            stc->keygen_tc->prime_seed_q2 = calloc(1, sizeof(ACVP_RSA_SEEDLEN_MAX));
        }
        switch(rand_pq) {
            case 1:
                if (info_gen_by_server) {
                    stc->keygen_tc->e = e;
                    stc->keygen_tc->seed = seed;
                }
                break;
            case 2:
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
            case 3:
                if (info_gen_by_server) {
                    stc->keygen_tc->e = e;
                    stc->keygen_tc->seed = seed;
                    stc->keygen_tc->seed_len = (unsigned int)strnlen((char *)seed, ACVP_RSA_SEEDLEN_MAX);
                    set_bitlens();
                }
                break;
            case 4:
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
                    set_bitlens();
                }
                break;
            case 5:
                stc->keygen_tc->xp1 = calloc(512, sizeof(char));
                stc->keygen_tc->xp2 = calloc(512, sizeof(char));
                stc->keygen_tc->xq1 = calloc(512, sizeof(char));
                stc->keygen_tc->xq2 = calloc(512, sizeof(char));
                if (info_gen_by_server) {
                    stc->keygen_tc->e = e;
                    stc->keygen_tc->seed = seed;
                    stc->keygen_tc->seed_len = (unsigned int)strnlen((char *)seed, ACVP_RSA_SEEDLEN_MAX);
                    set_bitlens();
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
static ACVP_RESULT acvp_rsa_output_tc(ACVP_CTX *ctx, ACVP_RSA_TC *stc, JSON_Object *tc_rsp)
{
    void populate_common_fields() {
        json_object_set_string(tc_rsp, "seed", (char *)stc->keygen_tc->seed);
        json_object_set_string(tc_rsp, "e", BN_bn2hex(stc->keygen_tc->e));
        json_object_set_string(tc_rsp, "p", BN_bn2hex(stc->keygen_tc->p));
        json_object_set_string(tc_rsp, "q", BN_bn2hex(stc->keygen_tc->q));
        json_object_set_string(tc_rsp, "n", BN_bn2hex(stc->keygen_tc->n));
        json_object_set_string(tc_rsp, "d", BN_bn2hex(stc->keygen_tc->d));
    }

    void populate_bitlens() {
        json_object_set_number(tc_rsp, "bitlen1", stc->keygen_tc->bitlen1);
        json_object_set_number(tc_rsp, "bitlen2", stc->keygen_tc->bitlen2);
        json_object_set_number(tc_rsp, "bitlen3", stc->keygen_tc->bitlen3);
        json_object_set_number(tc_rsp, "bitlen4", stc->keygen_tc->bitlen4);
    }

    switch(stc->mode) {
        case ACVP_RSA_MODE_KEYGEN:
        switch(stc->rand_pq) {
            case 2:
                json_object_set_string(tc_rsp, "primeResult", (char *)stc->keygen_tc->prime_result);
                break;
            case 1:
                populate_common_fields();
                break;
            case 3:
                populate_common_fields();
                populate_bitlens();
                break;
            case 4:
                populate_common_fields();
                populate_bitlens();
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
            case 5:
                populate_common_fields();
                populate_bitlens();
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
    ACVP_RESULT rv;
    const char          *alg_str = json_object_get_string(obj, "algorithm");
    char                *mode_str = NULL;
    ACVP_CIPHER	        alg_id;
    ACVP_RSA_MODE       mode_id;
    char *json_result, *rand_pq_str;

    int info_gen_by_server, rand_pq;
    char *hash_alg, *prime_test, *pub_exp;

    /*
     * keygen attrs
     */
    unsigned char *p_rand, *q_rand, *seed, *xp, *xp1, *xp2, *xq, *xq1, *xq2;
    unsigned int bitlen1, bitlen2, bitlen3, bitlen4, mod;
    BIGNUM *e;
    const char *exponent;

    void get_bitlens() {
        bitlen1 = (unsigned int)json_object_get_number(testobj, "bitlen1");
        bitlen2 = (unsigned int)json_object_get_number(testobj, "bitlen2");
        bitlen3 = (unsigned int)json_object_get_number(testobj, "bitlen3");
        bitlen4 = (unsigned int)json_object_get_number(testobj, "bitlen4");
    }
    void get_e() {
        exponent = json_object_get_string(testobj, "e");
        BN_hex2bn(&e, exponent);
    }

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
    json_object_set_value(r_vs, "testResults", json_value_init_array());
    r_tarr = json_object_get_array(r_vs, "testResults");

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        mode_str = (char *)json_object_get_string(groupobj, "mode");
        if (!mode_str) {
            ACVP_LOG_ERR("ERROR: unable to parse 'mode' from JSON");
            return (ACVP_MALFORMED_JSON);
        }
        ACVP_LOG_INFO("    RSA mode: %s", mode_str);
        mode_id = acvp_lookup_rsa_mode_index(mode_str);
        if (mode_id >= ACVP_RSA_MODE_END) {
            ACVP_LOG_ERR("unsupported RSA mode (%s)", mode_str);
            return (ACVP_UNSUPPORTED_OP);
        }

        rand_pq_str = (char *)json_object_get_string(groupobj, "randPQ");
        rand_pq = acvp_lookup_rsa_randpq_index(rand_pq_str);
        mod = json_object_get_number(groupobj, "modRSA");
        hash_alg = (char *)json_object_get_string(groupobj, "hashAlg");
        if (rand_pq == 2 || rand_pq == 4 || rand_pq == 5)
            prime_test = (char *)json_object_get_string(groupobj, "primeTest");
        pub_exp = (char *)json_object_get_string(groupobj, "pubExp");

        ACVP_LOG_INFO("    Test group: %d", i);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new RSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            ACVP_LOG_INFO("             mode: %s", mode_str);

            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");

            switch(mode_id) {
            case ACVP_RSA_MODE_KEYGEN:
                info_gen_by_server = cap->cap.rsa_cap->rsa_cap_mode_list->cap_mode_attrs.keygen->info_gen_by_server;
                if (!info_gen_by_server) {
                    if (rand_pq == 2) { // "ProbRP"
                        get_e();
                        p_rand = (unsigned char *)json_object_get_string(testobj, "pRand");
                        q_rand = (unsigned char *)json_object_get_string(testobj, "qRand");
                    }
                } else {
                    switch(rand_pq) {
                    case 1: // "provRP"
                        get_e();
                        seed = (unsigned char *)json_object_get_string(testobj, "seed");
                        break;
                    case 3: // "provPC"
                        get_e();
                        seed = (unsigned char *)json_object_get_string(testobj, "seed");
                        get_bitlens();
                        break;
                    case 4: // "bothPC"
                        get_e();
                        seed = (unsigned char *)json_object_get_string(testobj, "seed");
                        get_bitlens();
                        xp = (unsigned char *)json_object_get_string(testobj, "xP");
                        xq = (unsigned char *)json_object_get_string(testobj, "xQ");
                        break;
                    case 5: // "probPC"
                        get_e();
                        seed = (unsigned char *)json_object_get_string(testobj, "seed");
                        get_bitlens();
                        xp = (unsigned char *)json_object_get_string(testobj, "xP");
                        xq = (unsigned char *)json_object_get_string(testobj, "xQ");
                        xp1 = (unsigned char *)json_object_get_string(testobj, "xP1");
                        xq1 = (unsigned char *)json_object_get_string(testobj, "xQ1");
                        xp2 = (unsigned char *)json_object_get_string(testobj, "xP2");
                        xq2 = (unsigned char *)json_object_get_string(testobj, "xQ2");
                        break;
                    case 2:
                    default:
                        break;
                    }
                }
                break;
            default:
                break;
            }

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             * TODO: this does mallocs, we can probably do the mallocs once for
             *       the entire vector set to be more efficient
             */

            acvp_rsa_init_tc(ctx, &stc, tc_id, alg_id,
                            /* group info */
                             info_gen_by_server, rand_pq, mod, hash_alg, prime_test, pub_exp,
                            /* keygen params... TODO this might be able to be consolidated */
                             seed, e, bitlen1, bitlen2, bitlen3, bitlen4, p_rand, q_rand,
                             xp, xp1, xp2, xq, xq1, xq2);

            /* Process the current test vector... */
            rv = (cap->crypto_handler)(&tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_rsa_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                return rv;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_rsa_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
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
