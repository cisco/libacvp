#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"
#include "safe_lib.h"

static ACVP_RESULT acvp_ascon_output_tc(ACVP_CTX *ctx, ACVP_ASCON_TC *stc,
                                        JSON_Object *tc_rsp) {

    ACVP_RESULT rv = ACVP_SUCCESS;

    json_object_set_number(tc_rsp, "tcId", stc->tc_id);

    char *tmp_tag = calloc(ACVP_ASCON_TAG_STRING_MAX + 1, sizeof(char));
    if (!tmp_tag) {
        ACVP_LOG_ERR("Unable to malloc in acvp_ascon_output_tc");
        return ACVP_MALLOC_FAIL;
    }
    char *tmp_md = calloc(ACVP_ASCON_MSG_STRING_MAX + 1, sizeof(char));
    if (!tmp_md) {
        ACVP_LOG_ERR("Unable to malloc in acvp_ascon_output_tc");
        return ACVP_MALLOC_FAIL;
    }
    char *tmp_txt = calloc(ACVP_ASCON_MSG_STRING_MAX + 1, sizeof(char));
    if (!tmp_txt) {
        ACVP_LOG_ERR("Unable to malloc in acvp_ascon_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    switch (stc->cipher) {
    case ACVP_ASCON_AEAD128:
        if (stc->direction == ACVP_ASCON_DIR_DECRYPT) {
            json_object_set_boolean(tc_rsp, "testPassed", stc->tag_match);
            rv = acvp_bin_to_hexstr(stc->pt, stc->payload_len, tmp_txt,
                                    ACVP_ASCON_MSG_STRING_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (pt)");
                goto end;
            }
            json_object_set_string(tc_rsp, "pt", tmp_txt);
        }
        if (stc->direction == ACVP_ASCON_DIR_ENCRYPT) {
            rv = acvp_bin_to_hexstr(stc->ct, stc->payload_len, tmp_txt,
                                    ACVP_ASCON_MSG_STRING_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (ct)");
                goto end;
            }
            json_object_set_string(tc_rsp, "ct", tmp_tag);
            rv = acvp_bin_to_hexstr(stc->tag, stc->tag_len, tmp_tag,
                                    ACVP_ASCON_TAG_STRING_MAX);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Hex conversion failure (tag)");
                goto end;
            }
            json_object_set_string(tc_rsp, "tag", tmp_tag);
        }
        break;
    case ACVP_ASCON_CXOF128:
    case ACVP_ASCON_HASH256:
    case ACVP_ASCON_XOF128:
        rv = acvp_bin_to_hexstr(stc->md, stc->out_len, tmp_md,
                                ACVP_ASCON_MSG_STRING_MAX);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (md)");
            goto end;
        }
        json_object_set_string(tc_rsp, "md", tmp_md);
        break;
    default:
        rv = ACVP_INVALID_ARG;
        goto end;
    }

end:
    if (tmp_txt)
        free(tmp_txt);
    if (tmp_tag)
        free(tmp_tag);
    if (tmp_md)
        free(tmp_md);

    return rv;
}

static ACVP_RESULT acvp_ascon_aead128_init_tc(
    ACVP_CTX *ctx, ACVP_ASCON_TC *stc, ACVP_ASCON_TESTTYPE testtype, int tg_id,
    unsigned int tc_id, ACVP_ASCON_DIRECTION direction,
    bool supports_nonce_mask, const char *key, const char *nonce,
    const char *ad, int ad_len, const char *tag, int tag_len, const char *pt,
    const char *ct, int payload_len, const char *second_key) {

    if (payload_len == 0 || tag_len == 0) {
        return ACVP_INVALID_ARG;
    }

    if (!key || !nonce) {
        return ACVP_INVALID_ARG;
    }

    memzero_s(stc, sizeof(ACVP_ASCON_TC));

    stc->testtype = testtype;
    stc->cipher = ACVP_ASCON_AEAD128;
    stc->direction = direction;
    stc->supports_nonce_mask = supports_nonce_mask;
    stc->tc_id = tc_id;
    stc->tg_id = tg_id;

    stc->ad = calloc(1, ACVP_ASCON_MSG_STRING_MAX);
    if (!stc->ad) {
        return ACVP_MALLOC_FAIL;
    }
    stc->ad_len = ad_len;
    ACVP_RESULT rv = acvp_hexstr_to_bin(ad, stc->ad, ACVP_ASCON_MSG_STRING_MAX,
                                        &(stc->ad_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (ad)");
        return rv;
    }

    stc->pt = calloc(1, ACVP_ASCON_MSG_STRING_MAX);
    if (!stc->pt) {
        return ACVP_MALLOC_FAIL;
    }
    stc->ct = calloc(1, ACVP_ASCON_MSG_STRING_MAX);
    if (!stc->ct) {
        return ACVP_MALLOC_FAIL;
    }
    stc->payload_len = payload_len;

    stc->key = calloc(1, ACVP_ASCON_KEY_BYTE_MAX);
    if (!stc->key) {
        return ACVP_MALLOC_FAIL;
    }
    rv = acvp_hexstr_to_bin(key, stc->key, ACVP_ASCON_KEY_BYTE_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (key)");
        return rv;
    }
    if (supports_nonce_mask) {
        if (!second_key) {
            return ACVP_INVALID_ARG;
        }

        stc->second_key = calloc(1, ACVP_ASCON_KEY_BYTE_MAX);
        rv = acvp_hexstr_to_bin(second_key, stc->second_key,
                                ACVP_ASCON_KEY_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (second_key)");
            return rv;
        }
    }
    stc->nonce = calloc(1, ACVP_ASCON_NONCE_BYTE_MAX);
    if (!stc->nonce) {
        return ACVP_MALLOC_FAIL;
    }
    rv = acvp_hexstr_to_bin(nonce, stc->nonce, ACVP_ASCON_NONCE_BYTE_MAX, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (nonce)");
        return rv;
    }

    if (stc->direction == ACVP_ASCON_DIR_DECRYPT) {
        stc->tag = calloc(1, ACVP_ASCON_TAG_BYTE_MAX);
        stc->tag_len = tag_len;
        rv = acvp_hexstr_to_bin(tag, stc->tag, ACVP_ASCON_TAG_BYTE_MAX,
                                &(stc->tag_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (tag)");
            return rv;
        }
    }
    switch (stc->direction) {
    case ACVP_ASCON_DIR_ENCRYPT:
        rv = acvp_hexstr_to_bin(pt, stc->pt, ACVP_ASCON_MSG_STRING_MAX,
                                &(stc->payload_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (pt)");
            return rv;
        }
        break;
    case ACVP_ASCON_DIR_DECRYPT:
        rv = acvp_hexstr_to_bin(ct, stc->ct, ACVP_ASCON_MSG_STRING_MAX,
                                &(stc->payload_len));
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (ct)");
            return rv;
        }
        break;
    default:
        ACVP_LOG_ERR("Invalid direction argument %d", direction);
        return ACVP_INVALID_ARG;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_ascon_cxof128_init_tc(ACVP_CTX *ctx, ACVP_ASCON_TC *stc,
                                              int tg_id, unsigned int tc_id,
                                              ACVP_ASCON_TESTTYPE testtype,
                                              unsigned char *msg, int msg_len,
                                              int out_len, unsigned char *cs,
                                              int cs_len) {
    if (msg_len == 0 || out_len == 0 || cs_len == 0) {
        return ACVP_INVALID_ARG;
    }

    memzero_s(stc, sizeof(ACVP_ASCON_TC));

    stc->testtype = testtype;
    stc->cipher = ACVP_ASCON_XOF128;
    stc->tc_id = tc_id;
    stc->tg_id = tg_id;

    stc->msg = calloc(1, ACVP_ASCON_MSG_STRING_MAX);
    if (!stc->msg) {
        return ACVP_MALLOC_FAIL;
    }
    stc->msg_len = msg_len;
    ACVP_RESULT rv = acvp_hexstr_to_bin(
        msg, stc->msg, ACVP_ASCON_MSG_STRING_MAX, &(stc->msg_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    stc->cs = calloc(1, ACVP_ASCON_MSG_STRING_MAX);
    if (!stc->cs) {
        return ACVP_MALLOC_FAIL;
    }
    stc->cs_len = cs_len;
    rv = acvp_hexstr_to_bin(cs, stc->cs, ACVP_ASCON_MSG_STRING_MAX,
                            &(stc->cs_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (cs)");
        return rv;
    }

    stc->md = calloc(1, ACVP_ASCON_MSG_STRING_MAX);
    if (!stc->md) {
        return ACVP_MALLOC_FAIL;
    }
    stc->out_len = out_len;

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_ascon_hash256_init_tc(ACVP_CTX *ctx, ACVP_ASCON_TC *stc,
                                              int tg_id, unsigned int tc_id,
                                              ACVP_ASCON_TESTTYPE testtype,
                                              unsigned char *msg, int msg_len) {

    if (msg_len == 0) {
        return ACVP_INVALID_ARG;
    }

    memzero_s(stc, sizeof(ACVP_ASCON_TC));

    stc->testtype = testtype;
    stc->cipher = ACVP_ASCON_HASH256;
    stc->tc_id = tc_id;
    stc->tg_id = tg_id;

    stc->msg = calloc(1, ACVP_ASCON_MSG_STRING_MAX);
    if (!stc->msg) {
        return ACVP_MALLOC_FAIL;
    }
    stc->msg_len = msg_len;
    ACVP_RESULT rv =
        acvp_hexstr_to_bin((const char *)msg, stc->msg,
                           ACVP_ASCON_MSG_STRING_MAX, &(stc->msg_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    stc->md = calloc(1, ACVP_ASCON_HASH_STRING_MAX);
    if (!stc->md) {
        return ACVP_MALLOC_FAIL;
    }
    stc->out_len = ACVP_ASCON_HASH_BYTE_MAX;
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_ascon_xof128_init_tc(ACVP_CTX *ctx, ACVP_ASCON_TC *stc,
                                             int tg_id, unsigned int tc_id,
                                             ACVP_ASCON_TESTTYPE testtype,
                                             unsigned char *msg, int msg_len,
                                             int out_len) {
    if (msg_len == 0 || out_len == 0) {
        return ACVP_INVALID_ARG;
    }

    memzero_s(stc, sizeof(ACVP_ASCON_TC));

    stc->testtype = testtype;
    stc->cipher = ACVP_ASCON_XOF128;
    stc->tc_id = tc_id;
    stc->tg_id = tg_id;

    stc->msg = calloc(1, ACVP_ASCON_MSG_STRING_MAX);
    if (!stc->msg) {
        return ACVP_MALLOC_FAIL;
    }
    stc->msg_len = msg_len;
    ACVP_RESULT rv = acvp_hexstr_to_bin(
        msg, stc->msg, ACVP_ASCON_MSG_STRING_MAX, &(stc->msg_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    stc->md = calloc(1, ACVP_ASCON_MSG_STRING_MAX);
    if (!stc->md) {
        return ACVP_MALLOC_FAIL;
    }
    stc->out_len = out_len;

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_ascon_release_tc(ACVP_ASCON_TC *stc) {
    if (stc->msg)
        free(stc->msg);
    if (stc->pt)
        free(stc->pt);
    if (stc->ct)
        free(stc->ct);
    if (stc->key)
        free(stc->key);
    if (stc->nonce)
        free(stc->nonce);
    if (stc->tag)
        free(stc->tag);
    if (stc->second_key)
        free(stc->second_key);
    if (stc->md)
        free(stc->md);
    memzero_s(stc, sizeof(ACVP_CMAC_TC));

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_ascon_aead128_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *alg_str = NULL;
    ACVP_TEST_CASE tc;
    ACVP_ASCON_TC stc;
    ACVP_CIPHER alg_id = 0;
    ACVP_CAPS_LIST *cap = NULL;
    JSON_Array *reg_array = NULL, *r_garr = NULL,
               *groups = NULL, *r_tarr = NULL,
               *tests = NULL;
    JSON_Value *reg_array_val = NULL,
               *r_vs_val = NULL, *groupval = NULL,
               *r_gval = NULL;
    JSON_Object *reg_obj = NULL, *r_vs = NULL,
                *groupobj = NULL, *r_gobj = NULL;
    const char *type_str = NULL, *direction_str = NULL;
    ACVP_ASCON_DIRECTION direction = 0;
    bool supports_nonce_masking = false;
    const char *key = NULL, *second_key = NULL,
         *nonce = NULL, *tag = NULL,
         *ad = NULL, *pt = NULL, *ct = NULL;
    unsigned int payload_len = 0, ad_len = 0,
                 tag_len = 0;
    JSON_Value *mval = json_value_init_object();
    JSON_Object *mobj = json_value_get_object(mval);
    char *json_result = NULL;

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    // Get a reference to the abstracted test case
    tc.tc.ascon = &stc;
    memzero_s(&stc, sizeof(ACVP_ASCON_TC));

    // Get the crypto module handler for ASCON mode
    alg_id = ACVP_ASCON_AEAD128;
    stc.cipher = alg_id;
    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        return ACVP_UNSUPPORTED_OP;
    }

    // Create ACVP array for response
    rv = acvp_create_array(&reg_obj, &reg_array_val, &reg_array);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct.");
        goto err;
    }

    // Start to build the JSON response
    rv = acvp_setup_json_rsp_group(&ctx, &reg_array_val, &r_vs_val, &r_vs,
                                   alg_str, &r_garr);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to setup json response");
        goto err;
    }

    groups = json_object_get_array(obj, "testGroups");
    if (!groups) {
        ACVP_LOG_ERR("Failed to include testGroups.");
        rv = ACVP_MISSING_ARG;
        goto err;
    }
    const unsigned int g_cnt = json_array_get_count(groups);

    for (unsigned int i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        /*
         * Create a new group in the response with the tgid
         * and an array of tests
         */
        r_gval = json_value_init_object();
        r_gobj = json_value_get_object(r_gval);
        int tgId = 0;
        rv = acvp_tc_json_get_int(ctx, alg_id, obj, "tgId", &tgId);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        stc.cipher = ACVP_ASCON_AEAD128;

        ACVP_LOG_VERBOSE("    Test group: %d", i);

        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        ACVP_ASCON_TESTTYPE type;
        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "testType",
                                     &type_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        if (strcmp(type_str, "AFT") == 0) {
            type = ACVP_ASCON_AFT;
        } else {
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "direction",
                                     &direction_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        if (strcmp(direction_str, "encrypt") == 0) {
            direction = ACVP_ASCON_DIR_ENCRYPT;
        } else if (strcmp(direction_str, "decrypt") == 0) {
            direction = ACVP_ASCON_DIR_DECRYPT;
        } else {
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        rv = acvp_tc_json_get_boolean(ctx, alg_id, groupobj,
                                      "supportsNonceMasking",
                                      (int *)&supports_nonce_masking);

        rv = acvp_tc_json_get_array(ctx, alg_id, groupobj, "tests", &tests);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        const int t_cnt = json_array_get_count(tests);

        for (unsigned int j = 0; j < t_cnt; j++) {
            JSON_Value *testval = json_array_get_value(tests, j);
            JSON_Object *testobj = json_value_get_object(testval);

            unsigned int tc_id = 0;
            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "tcId",
                                      (int *)&tc_id);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "key", &key);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "secondKey",
                                         &second_key);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "nonce", &nonce);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "ad", &ad);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "tag", &tag);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            switch (direction) {
            case ACVP_ASCON_DIR_ENCRYPT:
                rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "pt", &pt);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }
                break;
            case ACVP_ASCON_DIR_DECRYPT:
                rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "ct", &ct);
                if (rv != ACVP_SUCCESS) {
                    goto err;
                }
                break;
            }

            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "payloadLen",
                                      (int *)&payload_len);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "adLen",
                                      (int *)&ad_len);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "tagLen",
                                      (int *)&tag_len);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            ACVP_LOG_VERBOSE("       Test case: %d", j);
            ACVP_LOG_VERBOSE("            tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("             key: %s", key);
            ACVP_LOG_VERBOSE("           nonce: %s", nonce);
            ACVP_LOG_VERBOSE("              ad: %s", ad);
            ACVP_LOG_VERBOSE("             tag: %s", tag);
            ACVP_LOG_VERBOSE("              pt: %s", pt);
            ACVP_LOG_VERBOSE("              ct: %s", ct);
            ACVP_LOG_VERBOSE("      payloadLen: %s", payload_len);
            ACVP_LOG_VERBOSE("           adLen: %s", ad_len);
            ACVP_LOG_VERBOSE("          tagLen: %s", tag_len);
            ACVP_LOG_VERBOSE("       secondKey: %s", second_key);

            acvp_ascon_aead128_init_tc(ctx, &stc, type, tgId, tc_id, direction,
                                       supports_nonce_masking, key, nonce, ad,
                                       ad_len, tag, tag_len, pt, ct,
                                       payload_len, second_key);

            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("Crypto module failed the operation");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                goto err;
            }

            // Output the test case results using JSON
            rv = acvp_ascon_output_tc(ctx, &stc, mobj);
            json_array_append_value(r_tarr, mval);
        }

        json_array_append_value(r_garr, r_gval);
        acvp_ascon_release_tc(&stc);
    }

    memzero_s(&stc, sizeof(ACVP_ASCON_TC));
    json_array_append_value(reg_array, r_vs_val);
    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    ACVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        acvp_ascon_release_tc(&stc);
    }
    return rv;
}

ACVP_RESULT acvp_ascon_cxof128_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    const char *alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    // Get a reference to the abstracted test case
    ACVP_TEST_CASE tc;
    ACVP_ASCON_TC stc;
    tc.tc.ascon = &stc;
    memzero_s(&stc, sizeof(ACVP_ASCON_TC));

    // Get the crypto module handler for ASCON mode
    const ACVP_CIPHER alg_id = ACVP_ASCON_CXOF128;
    stc.cipher = alg_id;
    const ACVP_CAPS_LIST *cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        return ACVP_UNSUPPORTED_OP;
    }

    // Create ACVP array for response
    JSON_Array *reg_array = NULL;
    JSON_Value *reg_array_val = NULL;
    JSON_Object *reg_obj = NULL;
    ACVP_RESULT rv = acvp_create_array(&reg_obj, &reg_array_val, &reg_array);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct.");
        goto err;
    }

    // Start to build the JSON response
    JSON_Value *r_vs_val = NULL;
    JSON_Array *r_garr = NULL; // Response testarray, grouparray
    JSON_Object *r_vs = NULL;
    rv = acvp_setup_json_rsp_group(&ctx, &reg_array_val, &r_vs_val, &r_vs,
                                   alg_str, &r_garr);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to setup json response");
        goto err;
    }

    const JSON_Array *groups = json_object_get_array(obj, "testGroups");
    if (!groups) {
        ACVP_LOG_ERR("Failed to include testGroups.");
        rv = ACVP_MISSING_ARG;
        goto err;
    }
    const unsigned int g_cnt = json_array_get_count(groups);

    for (unsigned int i = 0; i < g_cnt; i++) {
        const JSON_Value *groupval = json_array_get_value(groups, i);
        JSON_Object *groupobj = json_value_get_object(groupval);

        /*
         * Create a new group in the response with the tgid
         * and an array of tests
         */
        JSON_Value *r_gval = json_value_init_object();
        JSON_Object *r_gobj = json_value_get_object(r_gval);
        int tgId = 0;
        rv = acvp_tc_json_get_int(ctx, alg_id, obj, "tgId", &tgId);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        JSON_Array *r_tarr = json_object_get_array(r_gobj, "tests");

        stc.cipher = ACVP_ASCON_CXOF128;

        ACVP_LOG_VERBOSE("    Test group: %d", i);

        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        ACVP_ASCON_TESTTYPE type;
        const char *type_str;
        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "testType",
                                     &type_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        if (strcmp(type_str, "AFT") == 0) {
            type = ACVP_ASCON_AFT;
        } else {
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        JSON_Array *tests = NULL;
        rv = acvp_tc_json_get_array(ctx, alg_id, groupobj, "tests", &tests);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        const int t_cnt = json_array_get_count(tests);

        for (unsigned int j = 0; j < t_cnt; j++) {
            JSON_Value *testval = json_array_get_value(tests, j);
            JSON_Object *testobj = json_value_get_object(testval);

            unsigned int tc_id = 0;
            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "tcId",
                                      (int *)&tc_id);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            const char *msg;
            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "msg", &msg);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            unsigned int len = 0;
            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "len", (int *)&len);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            unsigned int outlen = 0;
            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "outLen", (int *)&outlen);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            const char *cs;
            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "cs", &cs);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            unsigned int cslen = 0;
            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "csLen", (int *)&cslen);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }



            ACVP_LOG_VERBOSE("       Test case: %d", j);
            ACVP_LOG_VERBOSE("            tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("             msg: %s", msg);
            ACVP_LOG_VERBOSE("             len: %s", len);
            ACVP_LOG_VERBOSE("          outlen: %s", outlen);
            ACVP_LOG_VERBOSE("              cs: %s", cs);
            ACVP_LOG_VERBOSE("           csLen: %s", cslen);
            acvp_ascon_cxof128_init_tc(ctx, &stc, tgId, tc_id, type, msg, len, outlen, cs, cslen);

            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("Crypto module failed the operation");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                goto err;
            }

            JSON_Value *mval = json_value_init_object();
            JSON_Object *mobj = json_value_get_object(mval);
            // Output the test case results using JSON
            rv = acvp_ascon_output_tc(ctx, &stc, mobj);
            json_array_append_value(r_tarr, mval);
        }

        json_array_append_value(r_garr, r_gval);
        acvp_ascon_release_tc(&stc);
    }

    memzero_s(&stc, sizeof(ACVP_ASCON_TC));
    json_array_append_value(reg_array, r_vs_val);
    char *json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    ACVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        acvp_ascon_release_tc(&stc);
    }
    return rv;
}


ACVP_RESULT acvp_ascon_hash256_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    const char *alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    // Get a reference to the abstracted test case
    ACVP_TEST_CASE tc;
    ACVP_ASCON_TC stc;
    tc.tc.ascon = &stc;
    memzero_s(&stc, sizeof(ACVP_ASCON_TC));

    // Get the crypto module handler for ASCON mode
    const ACVP_CIPHER alg_id = ACVP_ASCON_HASH256;
    stc.cipher = alg_id;
    const ACVP_CAPS_LIST *cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        return ACVP_UNSUPPORTED_OP;
    }

    // Create ACVP array for response
    JSON_Array *reg_array = NULL;
    JSON_Value *reg_array_val = NULL;
    JSON_Object *reg_obj = NULL;
    ACVP_RESULT rv = acvp_create_array(&reg_obj, &reg_array_val, &reg_array);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct.");
        goto err;
    }

    // Start to build the JSON response
    JSON_Value *r_vs_val = NULL;
    JSON_Array *r_garr = NULL; // Response testarray, grouparray
    JSON_Object *r_vs = NULL;
    rv = acvp_setup_json_rsp_group(&ctx, &reg_array_val, &r_vs_val, &r_vs,
                                   alg_str, &r_garr);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to setup json response");
        goto err;
    }

    const JSON_Array *groups = json_object_get_array(obj, "testGroups");
    if (!groups) {
        ACVP_LOG_ERR("Failed to include testGroups.");
        rv = ACVP_MISSING_ARG;
        goto err;
    }
    const unsigned int g_cnt = json_array_get_count(groups);

    for (unsigned int i = 0; i < g_cnt; i++) {
        const JSON_Value *groupval = json_array_get_value(groups, i);
        JSON_Object *groupobj = json_value_get_object(groupval);

        /*
         * Create a new group in the response with the tgid
         * and an array of tests
         */
        JSON_Value *r_gval = json_value_init_object();
        JSON_Object *r_gobj = json_value_get_object(r_gval);
        int tgId = 0;
        rv = acvp_tc_json_get_int(ctx, alg_id, obj, "tgId", &tgId);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        JSON_Array *r_tarr = json_object_get_array(r_gobj, "tests");

        stc.cipher = ACVP_ASCON_HASH256;

        ACVP_LOG_VERBOSE("    Test group: %d", i);

        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        ACVP_ASCON_TESTTYPE type;
        const char *type_str;
        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "testType",
                                     &type_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        if (strcmp(type_str, "AFT") == 0) {
            type = ACVP_ASCON_AFT;
        } else {
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        JSON_Array *tests = NULL;
        rv = acvp_tc_json_get_array(ctx, alg_id, groupobj, "tests", &tests);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        const int t_cnt = json_array_get_count(tests);

        for (unsigned int j = 0; j < t_cnt; j++) {
            JSON_Value *testval = json_array_get_value(tests, j);
            JSON_Object *testobj = json_value_get_object(testval);

            unsigned int tc_id = 0;
            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "tcId",
                                      (int *)&tc_id);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            const char *msg;
            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "msg", &msg);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            unsigned int len = 0;
            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "len", (int *)&len);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            ACVP_LOG_VERBOSE("       Test case: %d", j);
            ACVP_LOG_VERBOSE("            tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("             msg: %s", msg);
            ACVP_LOG_VERBOSE("             len: %s", len);

            acvp_ascon_hash256_init_tc(ctx, &stc, tgId, tc_id, type, msg, len);

            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("Crypto module failed the operation");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                goto err;
            }

            JSON_Value *mval = json_value_init_object();
            JSON_Object *mobj = json_value_get_object(mval);
            // Output the test case results using JSON
            rv = acvp_ascon_output_tc(ctx, &stc, mobj);
            json_array_append_value(r_tarr, mval);
        }

        json_array_append_value(r_garr, r_gval);
        acvp_ascon_release_tc(&stc);
    }

    memzero_s(&stc, sizeof(ACVP_ASCON_TC));
    json_array_append_value(reg_array, r_vs_val);
    char *json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    ACVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        acvp_ascon_release_tc(&stc);
    }
    return rv;
}

ACVP_RESULT acvp_ascon_xof128_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    const char *alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return ACVP_MALFORMED_JSON;
    }

    // Get a reference to the abstracted test case
    ACVP_TEST_CASE tc;
    ACVP_ASCON_TC stc;
    tc.tc.ascon = &stc;
    memzero_s(&stc, sizeof(ACVP_ASCON_TC));

    // Get the crypto module handler for ASCON mode
    const ACVP_CIPHER alg_id = ACVP_ASCON_XOF128;
    stc.cipher = alg_id;
    const ACVP_CAPS_LIST *cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability");
        return ACVP_UNSUPPORTED_OP;
    }

    // Create ACVP array for response
    JSON_Array *reg_array = NULL;
    JSON_Value *reg_array_val = NULL;
    JSON_Object *reg_obj = NULL;
    ACVP_RESULT rv = acvp_create_array(&reg_obj, &reg_array_val, &reg_array);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct.");
        goto err;
    }

    // Start to build the JSON response
    JSON_Value *r_vs_val = NULL;
    JSON_Array *r_garr = NULL; // Response testarray, grouparray
    JSON_Object *r_vs = NULL;
    rv = acvp_setup_json_rsp_group(&ctx, &reg_array_val, &r_vs_val, &r_vs,
                                   alg_str, &r_garr);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to setup json response");
        goto err;
    }

    const JSON_Array *groups = json_object_get_array(obj, "testGroups");
    if (!groups) {
        ACVP_LOG_ERR("Failed to include testGroups.");
        rv = ACVP_MISSING_ARG;
        goto err;
    }
    const unsigned int g_cnt = json_array_get_count(groups);

    for (unsigned int i = 0; i < g_cnt; i++) {
        const JSON_Value *groupval = json_array_get_value(groups, i);
        JSON_Object *groupobj = json_value_get_object(groupval);

        /*
         * Create a new group in the response with the tgid
         * and an array of tests
         */
        JSON_Value *r_gval = json_value_init_object();
        JSON_Object *r_gobj = json_value_get_object(r_gval);
        int tgId = 0;
        rv = acvp_tc_json_get_int(ctx, alg_id, obj, "tgId", &tgId);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        JSON_Array *r_tarr = json_object_get_array(r_gobj, "tests");

        stc.cipher = ACVP_ASCON_XOF128;

        ACVP_LOG_VERBOSE("    Test group: %d", i);

        if (rv != ACVP_SUCCESS) {
            goto err;
        }

        ACVP_ASCON_TESTTYPE type;
        const char *type_str;
        rv = acvp_tc_json_get_string(ctx, alg_id, groupobj, "testType",
                                     &type_str);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        if (strcmp(type_str, "AFT") == 0) {
            type = ACVP_ASCON_AFT;
        } else {
            rv = ACVP_INVALID_ARG;
            goto err;
        }

        JSON_Array *tests = NULL;
        rv = acvp_tc_json_get_array(ctx, alg_id, groupobj, "tests", &tests);
        if (rv != ACVP_SUCCESS) {
            goto err;
        }
        const int t_cnt = json_array_get_count(tests);

        for (unsigned int j = 0; j < t_cnt; j++) {
            JSON_Value *testval = json_array_get_value(tests, j);
            JSON_Object *testobj = json_value_get_object(testval);

            unsigned int tc_id = 0;
            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "tcId",
                                      (int *)&tc_id);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            const char *msg;
            rv = acvp_tc_json_get_string(ctx, alg_id, testobj, "msg", &msg);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            unsigned int len = 0;
            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "len", (int *)&len);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }

            unsigned int outlen = 0;
            rv = acvp_tc_json_get_int(ctx, alg_id, testobj, "outLen", (int *)&outlen);
            if (rv != ACVP_SUCCESS) {
                goto err;
            }


            ACVP_LOG_VERBOSE("       Test case: %d", j);
            ACVP_LOG_VERBOSE("            tcId: %d", tc_id);
            ACVP_LOG_VERBOSE("             msg: %s", msg);
            ACVP_LOG_VERBOSE("             len: %s", len);
            ACVP_LOG_VERBOSE("          outlen: %s", outlen);

            acvp_ascon_xof128_init_tc(ctx, &stc, tgId, tc_id, type, msg, len, outlen);

            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("Crypto module failed the operation");
                rv = ACVP_CRYPTO_MODULE_FAIL;
                goto err;
            }

            JSON_Value *mval = json_value_init_object();
            JSON_Object *mobj = json_value_get_object(mval);
            // Output the test case results using JSON
            rv = acvp_ascon_output_tc(ctx, &stc, mobj);
            json_array_append_value(r_tarr, mval);
        }

        json_array_append_value(r_garr, r_gval);
        acvp_ascon_release_tc(&stc);
    }

    memzero_s(&stc, sizeof(ACVP_ASCON_TC));
    json_array_append_value(reg_array, r_vs_val);
    char *json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    ACVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = ACVP_SUCCESS;

err:
    if (rv != ACVP_SUCCESS) {
        acvp_ascon_release_tc(&stc);
    }
    return rv;
}

#define ASCON_MODE_STR_MAX 7

ACVP_RESULT acvp_ascon_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {

    if (!ctx) {
        ACVP_LOG_ERR("CTX is NULL.");
        return ACVP_NO_CTX;
    }

    if (!obj) {
        ACVP_LOG_ERR("OBJ is NULL.");
        return ACVP_MALFORMED_JSON;
    }

    const char *mode = json_object_get_string(obj, "mode");
    int diff = 0;
    if (!mode) {
        ACVP_LOG_ERR("Failed to include mode.");
        return ACVP_MISSING_ARG;
    }

    strcmp_s(ACVP_ALG_ASCON_AEAD128, ASCON_MODE_STR_MAX, mode, &diff);
    if (!diff)
        return acvp_ascon_aead128_kat_handler(ctx, obj);

    strcmp_s(ACVP_ALG_ASCON_CXOF128, ASCON_MODE_STR_MAX, mode, &diff);
    if (!diff)
        return acvp_ascon_cxof128_kat_handler(ctx, obj);

    strcmp_s(ACVP_ALG_ASCON_HASH256, ASCON_MODE_STR_MAX, mode, &diff);
    if (!diff)
        return acvp_ascon_hash256_kat_handler(ctx, obj);

    strcmp_s(ACVP_ALG_ASCON_XOF128, ASCON_MODE_STR_MAX, mode, &diff);
    if (!diff)
        return acvp_ascon_xof128_kat_handler(ctx, obj);
}
