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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"

/*
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_kdf135_ikev2_output_tc(ACVP_CTX *ctx, ACVP_KDF135_IKEV2_TC *stc, JSON_Object *tc_rsp) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(ACVP_KDF135_IKEV2_SKEY_SEED_STR_MAX + 1, sizeof(char));
    if (!tmp) { return ACVP_MALLOC_FAIL; }

    rv = acvp_bin_to_hexstr(stc->s_key_seed, stc->key_out_len, tmp, ACVP_KDF135_IKEV2_SKEY_SEED_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (s_key_seed)");
        goto err;
    }
    json_object_set_string(tc_rsp, "sKeySeed", (const char *)tmp);
    memset(tmp, 0x0, ACVP_KDF135_IKEV2_SKEY_SEED_STR_MAX);

    rv = acvp_bin_to_hexstr(stc->s_key_seed_rekey, stc->key_out_len, tmp, ACVP_KDF135_IKEV2_SKEY_SEED_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (s_key_seed_rekey)");
        goto err;
    }
    json_object_set_string(tc_rsp, "sKeySeedReKey", (const char *)tmp);
    memset(tmp, 0x0, ACVP_KDF135_IKEV2_SKEY_SEED_STR_MAX);
    free(tmp);


    tmp = calloc(ACVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX, sizeof(char));
    rv = acvp_bin_to_hexstr(stc->derived_keying_material, stc->keying_material_len, tmp, ACVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (derived_keying_material)");
        goto err;
    }
    json_object_set_string(tc_rsp, "derivedKeyingMaterial", (const char *)tmp);
    memset(tmp, 0x0, ACVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX);

    rv = acvp_bin_to_hexstr(stc->derived_keying_material_child, stc->keying_material_len, tmp, ACVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (derived_keying_material)");
        goto err;
    }
    json_object_set_string(tc_rsp, "derivedKeyingMaterialChild", (const char *)tmp);
    memset(tmp, 0x0, ACVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX);

    rv = acvp_bin_to_hexstr(stc->derived_keying_material_child_dh, stc->keying_material_len, tmp, ACVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("hex conversion failure (derived_keying_material)");
        goto err;
    }
    json_object_set_string(tc_rsp, "derivedKeyingMaterialDh", (const char *)tmp);
    memset(tmp, 0x0, ACVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX);

err:
    free(tmp);
    return rv;
}

static ACVP_RESULT acvp_kdf135_ikev2_init_tc(ACVP_CTX *ctx,
                                             ACVP_KDF135_IKEV2_TC *stc,
                                             unsigned int tc_id,
                                             ACVP_HASH_ALG hash_alg,
                                             int init_nonce_len,
                                             int resp_nonce_len,
                                             int dh_secret_len,
                                             int keying_material_len,
                                             char *init_nonce,
                                             char *resp_nonce,
                                             char *init_spi,
                                             char *resp_spi,
                                             char *gir,
                                             char *gir_new) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    memset(stc, 0x0, sizeof(ACVP_KDF135_IKEV2_TC));

    stc->tc_id = tc_id;

    stc->hash_alg = hash_alg;
    stc->init_nonce_len = init_nonce_len;
    stc->resp_nonce_len = resp_nonce_len;

    stc->dh_secret_len = dh_secret_len;
    stc->keying_material_len = ACVP_BIT2BYTE(keying_material_len);

    stc->init_nonce = calloc(ACVP_KDF135_IKEV2_INIT_NONCE_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->init_nonce) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(init_nonce, stc->init_nonce, ACVP_KDF135_IKEV2_INIT_NONCE_BYTE_MAX, &(stc->init_nonce_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (init_nonce)");
        return rv;
    }

    stc->resp_nonce = calloc(ACVP_KDF135_IKEV2_RESP_NONCE_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->resp_nonce) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(resp_nonce, stc->resp_nonce, ACVP_KDF135_IKEV2_RESP_NONCE_BYTE_MAX, &(stc->resp_nonce_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (resp_nonce)");
        return rv;
    }

    stc->init_spi = calloc(ACVP_KDF135_IKEV2_SPI_BYTE_MAX,
                           sizeof(unsigned char));
    if (!stc->init_spi) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(init_spi, stc->init_spi, ACVP_KDF135_IKEV2_SPI_BYTE_MAX, &(stc->init_spi_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (init_spi)");
        return rv;
    }

    stc->resp_spi = calloc(ACVP_KDF135_IKEV2_SPI_BYTE_MAX,
                           sizeof(unsigned char));
    if (!stc->resp_spi) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(resp_spi, stc->resp_spi, ACVP_KDF135_IKEV2_SPI_BYTE_MAX, &(stc->resp_spi_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (resp_spi)");
        return rv;
    }

    stc->gir = calloc(ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BYTE_MAX,
                      sizeof(unsigned char));
    if (!stc->gir) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(gir, stc->gir, ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BYTE_MAX, &(stc->gir_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (gir)");
        return rv;
    }

    stc->gir_new = calloc(ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BYTE_MAX,
                          sizeof(unsigned char));
    if (!stc->gir_new) { return ACVP_MALLOC_FAIL; }
    rv = acvp_hexstr_to_bin(gir_new, stc->gir_new, ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BYTE_MAX, &(stc->gir_new_len));
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Hex conversion failure (gir_new)");
        return rv;
    }

    /* allocate memory for answers so app doesn't have to touch library memory */
    stc->s_key_seed = calloc(ACVP_KDF135_IKEV2_SKEY_SEED_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->s_key_seed) { return ACVP_MALLOC_FAIL; }

    stc->s_key_seed_rekey = calloc(ACVP_KDF135_IKEV2_SKEY_SEED_BYTE_MAX,
                                   sizeof(unsigned char));
    if (!stc->s_key_seed_rekey) { return ACVP_MALLOC_FAIL; }

    stc->derived_keying_material = calloc(ACVP_KDF135_IKEV2_DKEY_MATERIAL_BYTE_MAX,
                                          sizeof(unsigned char));
    if (!stc->derived_keying_material) { return ACVP_MALLOC_FAIL; }

    stc->derived_keying_material_child_dh = calloc(ACVP_KDF135_IKEV2_DKEY_MATERIAL_BYTE_MAX,
                                                   sizeof(unsigned char));
    if (!stc->derived_keying_material_child_dh) { return ACVP_MALLOC_FAIL; }

    stc->derived_keying_material_child = calloc(ACVP_KDF135_IKEV2_DKEY_MATERIAL_BYTE_MAX,
                                                sizeof(unsigned char));
    if (!stc->derived_keying_material_child) { return ACVP_MALLOC_FAIL; }

    return rv;
}

static ACVP_RESULT acvp_kdf135_ikev2_release_tc(ACVP_KDF135_IKEV2_TC *stc) {
    if (stc->init_nonce) { free(stc->init_nonce); }
    if (stc->resp_nonce) { free(stc->resp_nonce); }
    if (stc->init_spi) { free(stc->init_spi); }
    if (stc->resp_spi) { free(stc->resp_spi); }
    if (stc->gir) { free(stc->gir); }
    if (stc->gir_new) { free(stc->gir_new); }
    if (stc->s_key_seed) { free(stc->s_key_seed); }
    if (stc->s_key_seed_rekey) { free(stc->s_key_seed_rekey); }
    if (stc->derived_keying_material) { free(stc->derived_keying_material); }
    if (stc->derived_keying_material_child) { free(stc->derived_keying_material_child); }
    if (stc->derived_keying_material_child_dh) { free(stc->derived_keying_material_child_dh); }
    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_kdf135_ikev2_kat_handler(ACVP_CTX *ctx, JSON_Object *obj) {
    unsigned int tc_id;
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *groups;
    JSON_Array *tests;

    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;

    int i, g_cnt;
    int j, t_cnt;

    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL, *r_garr = NULL;  /* Response testarray, grouparray */
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    ACVP_CAPS_LIST *cap;
    ACVP_KDF135_IKEV2_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    ACVP_CIPHER alg_id;
    char *json_result;

    ACVP_HASH_ALG hash_alg;
    const char *hash_alg_str = NULL;
    char *init_nonce = NULL, *resp_nonce = NULL, *init_spi = NULL;
    char *resp_spi = NULL, *gir = NULL, *gir_new = NULL;
    int init_nonce_len = 0, resp_nonce_len = 0, dh_secret_len = 0, keying_material_len = 0;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for handler operation");
        return ACVP_NO_CTX;
    }

    if (!alg_str) {
        ACVP_LOG_ERR("unable to parse 'algorithm' from JSON for KDF SSH.");
        return ACVP_MALFORMED_JSON;
    }

    if (strncmp(alg_str, "kdf-components", strlen("kdf-components"))) {
        ACVP_LOG_ERR("Invalid algorithm for this function %s", alg_str);
        return ACVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_ikev2 = &stc;
    alg_id = ACVP_KDF135_IKEV2;
    stc.cipher = alg_id;

    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        ACVP_LOG_ERR("ACVP server requesting unsupported capability %s : %d.", alg_str, alg_id);
        return ACVP_UNSUPPORTED_OP;
    }

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to create JSON response struct. ");
        return rv;
    }

    /*
     * Start to build the JSON response
     */
    rv = acvp_setup_json_rsp_group(&ctx, &reg_arry_val, &r_vs_val, &r_vs, alg_str, &r_garr);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Failed to setup json response");
        return rv;
    }

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        /*
         * Create a new group in the response with the tgid
         * and an array of tests
         */
        r_gval = json_value_init_object();
        r_gobj = json_value_get_object(r_gval);
        tgId = json_object_get_number(groupobj, "tgId");
        if (!tgId) {
            ACVP_LOG_ERR("Missing tgid from server JSON groub obj");
            return ACVP_MALFORMED_JSON;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        hash_alg_str = json_object_get_string(groupobj, "hashAlg");
        if (!hash_alg_str) {
            ACVP_LOG_ERR("Failed to include hashAlg");
            return ACVP_MISSING_ARG;
        }

        init_nonce_len = json_object_get_number(groupobj, "nInitLength");
        if (!(init_nonce_len >= ACVP_KDF135_IKEV2_INIT_NONCE_BIT_MIN &&
              init_nonce_len <= ACVP_KDF135_IKEV2_INIT_NONCE_BIT_MAX)) {
            ACVP_LOG_ERR("nInitLength incorrect, %d", init_nonce_len);
            return ACVP_INVALID_ARG;
        }

        resp_nonce_len = json_object_get_number(groupobj, "nRespLength");
        if (!(resp_nonce_len >= ACVP_KDF135_IKEV2_RESP_NONCE_BIT_MIN &&
              resp_nonce_len <= ACVP_KDF135_IKEV2_RESP_NONCE_BIT_MAX)) {
            ACVP_LOG_ERR("nRespLength incorrect, %d", resp_nonce_len);
            return ACVP_INVALID_ARG;
        }

        dh_secret_len = json_object_get_number(groupobj, "dhLength");
        if (!(dh_secret_len >= ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MIN &&
              dh_secret_len <= ACVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MAX)) {
            ACVP_LOG_ERR("dhLength incorrect, %d", dh_secret_len);
            return ACVP_INVALID_ARG;
        }

        keying_material_len = json_object_get_number(groupobj, "derivedKeyingMaterialLength");
        if (!(keying_material_len >= ACVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MIN &&
              keying_material_len <= ACVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MAX)) {
            ACVP_LOG_ERR("derivedKeyingMaterialLength incorrect, %d", keying_material_len);
            return ACVP_INVALID_ARG;
        }

        /*
         * Determine the hash algorithm.
         */
        if (strncmp(hash_alg_str, ACVP_STR_SHA_1, strnlen(ACVP_STR_SHA_1, ACVP_STR_SHA_MAX)) == 0) {
            hash_alg = ACVP_SHA1;
        } else if (strncmp(hash_alg_str, ACVP_STR_SHA2_224, strnlen(ACVP_STR_SHA2_224, ACVP_STR_SHA_MAX)) == 0) {
            hash_alg = ACVP_SHA224;
        } else if (strncmp(hash_alg_str, ACVP_STR_SHA2_256, strnlen(ACVP_STR_SHA2_256, ACVP_STR_SHA_MAX)) == 0) {
            hash_alg = ACVP_SHA256;
        } else if (strncmp(hash_alg_str, ACVP_STR_SHA2_384, strnlen(ACVP_STR_SHA2_384, ACVP_STR_SHA_MAX)) == 0) {
            hash_alg = ACVP_SHA384;
        } else if (strncmp(hash_alg_str, ACVP_STR_SHA2_512, strnlen(ACVP_STR_SHA2_512, ACVP_STR_SHA_MAX)) == 0) {
            hash_alg = ACVP_SHA512;
        } else {
            ACVP_LOG_ERR("ACVP server requesting invalid hash alg");
            return ACVP_INVALID_ARG;
        }

        ACVP_LOG_INFO("\n    Test group: %d", i);
        ACVP_LOG_INFO("        hash alg: %s", hash_alg_str);
        ACVP_LOG_INFO("  init nonce len: %d", init_nonce_len);
        ACVP_LOG_INFO("  resp nonce len: %d", resp_nonce_len);
        ACVP_LOG_INFO("   dh secret len: %d", dh_secret_len);
        ACVP_LOG_INFO("derived key material: %d", keying_material_len);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            ACVP_LOG_INFO("Found new KDF IKEv2 test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");

            init_nonce = (char *)json_object_get_string(testobj, "nInit");
            if (!init_nonce) {
                ACVP_LOG_ERR("Failed to include nInit");
                return ACVP_MISSING_ARG;
            }
            if (strnlen(init_nonce, init_nonce_len) != init_nonce_len / 4) {
                ACVP_LOG_ERR("nInit length(%d) incorrect, expected(%d)",
                             strnlen((char *)init_nonce, ACVP_KDF135_IKEV2_INIT_NONCE_STR_MAX),
                             init_nonce_len / 4);
                return ACVP_INVALID_ARG;
            }

            resp_nonce = (char *)json_object_get_string(testobj, "nResp");
            if (!resp_nonce) {
                ACVP_LOG_ERR("Failed to include nResp");
                return ACVP_MISSING_ARG;
            }
            if (strnlen(resp_nonce, resp_nonce_len) != resp_nonce_len / 4) {
                ACVP_LOG_ERR("nResp length(%d) incorrect, expected(%d)",
                             strnlen((char *)resp_nonce, ACVP_KDF135_IKEV2_RESP_NONCE_STR_MAX),
                             resp_nonce_len / 4);
                return ACVP_INVALID_ARG;
            }

            init_spi = (char *)json_object_get_string(testobj, "spiInit");
            if (!init_spi) {
                ACVP_LOG_ERR("Failed to include spiInit");
                return ACVP_MISSING_ARG;
            }
            if (strnlen(init_spi, ACVP_KDF135_IKEV2_SPI_STR_MAX + 1)
                > ACVP_KDF135_IKEV2_SPI_STR_MAX) {
                ACVP_LOG_ERR("spiInit too long, max allowed=(%d)",
                             ACVP_KDF135_IKEV2_SPI_STR_MAX);
                return ACVP_INVALID_ARG;
            }

            resp_spi = (char *)json_object_get_string(testobj, "spiResp");
            if (!resp_spi) {
                ACVP_LOG_ERR("Failed to include spiResp");
                return ACVP_MISSING_ARG;
            }
            if (strnlen(resp_spi, ACVP_KDF135_IKEV2_SPI_STR_MAX + 1)
                > ACVP_KDF135_IKEV2_SPI_STR_MAX) {
                ACVP_LOG_ERR("spiResp too long, max allowed=(%d)",
                             ACVP_KDF135_IKEV2_SPI_STR_MAX);
                return ACVP_INVALID_ARG;
            }

            gir = (char *)json_object_get_string(testobj, "gir");
            if (!gir) {
                ACVP_LOG_ERR("Failed to include gir");
                return ACVP_MISSING_ARG;
            }
            if (strnlen(gir, ACVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX + 1)
                > ACVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX) {
                ACVP_LOG_ERR("gir too long, max allowed=(%d)",
                             ACVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX);
                return ACVP_INVALID_ARG;
            }

            gir_new = (char *)json_object_get_string(testobj, "girNew");
            if (!gir_new) {
                ACVP_LOG_ERR("Failed to include girNew");
                return ACVP_MISSING_ARG;
            }
            if (strnlen(gir_new, ACVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX + 1)
                > ACVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX) {
                ACVP_LOG_ERR("girNew too long, max allowed=(%d)",
                             ACVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX);
                return ACVP_INVALID_ARG;
            }

            ACVP_LOG_INFO("        Test case: %d", j);
            ACVP_LOG_INFO("             tcId: %d", tc_id);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             */
            rv = acvp_kdf135_ikev2_init_tc(ctx, &stc, tc_id, hash_alg,
                                           init_nonce_len, resp_nonce_len,
                                           dh_secret_len, keying_material_len,
                                           init_nonce, resp_nonce,
                                           init_spi, resp_spi,
                                           gir, gir_new);
            if (rv != ACVP_SUCCESS) {
                acvp_kdf135_ikev2_release_tc(&stc);
                return rv;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                ACVP_LOG_ERR("crypto module failed");
                acvp_kdf135_ikev2_release_tc(&stc);
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_kdf135_ikev2_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("JSON output failure");
                acvp_kdf135_ikev2_release_tc(&stc);
                return rv;
            }
            /*
             * Release all the memory associated with the test case
             */
            acvp_kdf135_ikev2_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
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
