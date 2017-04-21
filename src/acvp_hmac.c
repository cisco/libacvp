#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"

static ACVP_RESULT acvp_hmac_init_tc(ACVP_CTX *ctx,
                                    ACVP_HMAC_TC *stc,
                                    unsigned int tc_id,
                                    unsigned int msg_len,
                                    unsigned char *msg,
                                    unsigned int key_len,
                                    unsigned char *key,
                                    ACVP_CIPHER alg_id)
{
    ACVP_RESULT rv;

    memset(stc, 0x0, sizeof(ACVP_HMAC_TC));

    stc->msg = calloc(1, ACVP_HMAC_MSG_MAX);
    if (!stc->msg) return ACVP_MALLOC_FAIL;
    stc->md = calloc(1, ACVP_HMAC_MD_MAX);
    if (!stc->md) return ACVP_MALLOC_FAIL;
    stc->key = calloc(1, ACVP_HMAC_KEY_MAX);
    if (!stc->key) return ACVP_MALLOC_FAIL;

    rv = acvp_hexstr_to_bin((const unsigned char *)msg, stc->msg, ACVP_HMAC_MSG_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex converstion failure (msg)");
        return rv;
    }
    rv = acvp_hexstr_to_bin((const unsigned char *)key, stc->key, ACVP_HMAC_KEY_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex converstion failure (key)");
        return rv;
    }

    stc->tc_id = tc_id;
    stc->msg_len = msg_len;
    stc->cipher = alg_id;

    return ACVP_SUCCESS;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_hmac_output_tc(ACVP_CTX *ctx, ACVP_HMAC_TC *stc, JSON_Object *tc_rsp)
{
    ACVP_RESULT rv;
    char *tmp;

    tmp = calloc(1, ACVP_HMAC_MSG_MAX);
    if (!tmp) {
        ACVP_LOG_ERR("Unable to malloc in acvp_hmac_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    rv = acvp_bin_to_hexstr(stc->md, stc->md_len, (unsigned char*)tmp);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (msg)");
        return rv;
    }
    json_object_set_string(tc_rsp, "md", tmp);

    free(tmp);

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_hmac_release_tc(ACVP_HMAC_TC *stc)
{
    free(stc->msg);
    free(stc->md);
    free(stc->key);
    memset(stc, 0x0, sizeof(ACVP_HMAC_TC));

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_hmac_kat_handler(ACVP_CTX *ctx, JSON_Object *obj)
{
    unsigned int tc_id, msglen, keyLen;
    unsigned char       *msg = NULL, *key = NULL;
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
    ACVP_HMAC_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char		*alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER	        alg_id;

    if (!alg_str) {
        ACVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return (ACVP_MALFORMED_JSON);
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.hmac = &stc;

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


        ACVP_LOG_INFO("    Test group: %d", i);
        ACVP_LOG_INFO("        msglen: %d", msglen);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new hash test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");
            msglen = (unsigned int)json_object_get_number(testobj, "msgLen");
            msg = (unsigned char *)json_object_get_string(testobj, "msg");
            keyLen = (unsigned int)json_object_get_number(testobj, "keyLen");
            key = (unsigned char *)json_object_get_string(testobj, "key");

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);
            ACVP_LOG_INFO("           msgLen: %d", msglen);
            ACVP_LOG_INFO("              msg: %s", msg);
            ACVP_LOG_INFO("           keyLen: %d", keyLen);
            ACVP_LOG_INFO("              key: %s", key);

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
            acvp_hmac_init_tc(ctx, &stc, tc_id, msglen, msg, keyLen, key, alg_id);

            /* Process the current test vector... */
            rv = (cap->crypto_handler)(&tc);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: crypto module failed the operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_hmac_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("ERROR: JSON output failure in hash module");
                return rv;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_hmac_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
    }

    json_array_append_value(reg_arry, r_vs_val);
    //FIXME
    printf("\n\n%s\n\n", json_serialize_to_string_pretty(ctx->kat_resp));

    return ACVP_SUCCESS;
}
