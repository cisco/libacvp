#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"

static ACVP_RESULT acvp_rsa_init_tc(ACVP_CTX *ctx,
                                    ACVP_RSA_TC *stc,
                                    unsigned int tc_id,
                                    unsigned char *seed,
                                    BIGNUM e,
                                    unsigned int bitlen1,
                                    unsigned int bitlen2,
                                    unsigned int bitlen3,
                                    unsigned int bitlen4,
                                    ACVP_CIPHER alg_id)
{
    ACVP_RESULT rv;
    memset(stc, 0x0, sizeof(ACVP_RSA_TC));

    switch(stc->mode) {
    case ACVP_RSA_MODE_KEYGEN:
        stc->keygen_tc = calloc(1, sizeof(ACVP_RSA_KEYGEN_TC));
        if (!stc->keygen_tc) return ACVP_MALLOC_FAIL;
        stc->keygen_tc->seed = calloc(1, sizeof(ACVP_RSA_SEEDLEN_MAX));
        if (!stc->keygen_tc->seed) return ACVP_MALLOC_FAIL;

        rv = acvp_hexstr_to_bin((const unsigned char *)seed, stc->keygen_tc->seed, ACVP_RSA_SEEDLEN_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex converstion failure (msg)");
            return rv;
        }
        stc->keygen_tc->e = e;
        stc->keygen_tc->bitlen1 = bitlen1;
        stc->keygen_tc->bitlen2 = bitlen2;
        stc->keygen_tc->bitlen3 = bitlen3;
        stc->keygen_tc->bitlen4 = bitlen4;
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
    // ACVP_RESULT rv;
    // char *tmp;
    //
    // tmp = calloc(1, ACVP_RSA_MSG_MAX);
    // if (!tmp) {
    //     ACVP_LOG_ERR("Unable to malloc in acvp_rsa_output_tc");
    //     return ACVP_MALLOC_FAIL;
    // }
    //
    // rv = acvp_bin_to_hexstr(stc->mac, stc->mac_len, (unsigned char*)tmp);
    // if (rv != ACVP_SUCCESS) {
    //     ACVP_LOG_ERR("hex conversion failure (mac)");
    //     return rv;
    // }
    // json_object_set_string(tc_rsp, "mac", tmp);
    //
    // free(tmp);

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_rsa_release_tc(ACVP_RSA_TC *stc)
{
    free(stc->keygen_tc->seed);
    free(stc->keygen_tc);
    memset(stc, 0x0, sizeof(ACVP_RSA_TC));

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_rsa_kat_handler(ACVP_CTX *ctx, JSON_Object *obj)
{
    unsigned int        seedlen = 0, tc_id;
    unsigned char       *seed = NULL;
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
    char                *mode_str = (char *)json_object_get_string(obj, "mode");

    ACVP_CIPHER	        alg_id;
    ACVP_RSA_MODE       mode_id;
    char *json_result;

    unsigned int bitlen1, bitlen2, bitlen3, bitlen4;
    BIGNUM *e;
    const char *exponent;

    if (!alg_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }
    if (!mode_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'mode' from JSON");
        return (ACVP_MALFORMED_JSON);
    }

    ACVP_LOG_INFO("    RSA mode: %s", mode_str);

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
    /*
     * Get RSA Mode index
     */
    mode_id = acvp_lookup_rsa_mode_index(mode_str);
    if (mode_id >= ACVP_RSA_MODE_END) {
        ACVP_LOG_ERR("unsupported RSA mode (%s)", mode_str);
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
     TODO (ELLIE) this is not quite right yet... doesn't show all the params from
     the request file and doesn't account for different modes yet
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


        ACVP_LOG_INFO("    Test group: %d", i);
        // ACVP_LOG_INFO("        msglen: %d", msglen);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new RSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");
            seed = (unsigned char *)json_object_get_string(testobj, "seed");
            exponent = json_object_get_string(testobj, "e");
            BN_hex2bn(&e, exponent);
            bitlen1 = (unsigned int)json_object_get_number(testobj, "bitlen1");
            bitlen2 = (unsigned int)json_object_get_number(testobj, "bitlen2");
            bitlen3 = (unsigned int)json_object_get_number(testobj, "bitlen3");
            bitlen4 = (unsigned int)json_object_get_number(testobj, "bitlen4");

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            // ACVP_LOG_INFO("           seedLen: %d", seedlen);
            ACVP_LOG_INFO("             seed: %s", seed);
            // ACVP_LOG_INFO("           keyLen: %d", keyLen);
            // ACVP_LOG_INFO("              key: %s", key);

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

            if (seedlen == 0) {
                seedlen = strnlen((const char *)seed, ACVP_RSA_SEEDLEN_MAX) / 2;
            }
            // acvp_rsa_init_tc(ctx, &stc, tc_id, alg_id);
            acvp_rsa_init_tc(ctx, &stc, tc_id, seed,
                             *e, bitlen1, bitlen2, bitlen3, bitlen4,
                             alg_id);

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
