/** @file */
/*****************************************************************************
* Copyright (c) 2018, Cisco Systems, Inc.
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
#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"

typedef struct acvp_prereqs_mode_name_t {
    ACVP_PREREQ_ALG alg;
    char *name;
} ACVP_PREREQ_MODE_NAME;

#define ACVP_NUM_PREREQS 10
struct acvp_prereqs_mode_name_t acvp_prereqs_tbl[ACVP_NUM_PREREQS] = {
    { ACVP_PREREQ_AES,   "AES"   },
    { ACVP_PREREQ_CCM,   "CCM"   },
    { ACVP_PREREQ_CMAC,  "CMAC"  },
    { ACVP_PREREQ_DRBG,  "DRBG"  },
    { ACVP_PREREQ_DSA,   "DSA"   },
    { ACVP_PREREQ_ECDSA, "ECDSA" },
    { ACVP_PREREQ_HMAC,  "HMAC"  },
    { ACVP_PREREQ_KAS,   "KAS"   },
    { ACVP_PREREQ_SHA,   "SHA"   },
    { ACVP_PREREQ_TDES,  "TDES"  }
};

static ACVP_RESULT acvp_lookup_prereqVals(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    JSON_Array *prereq_array = NULL;
    ACVP_PREREQ_LIST *prereq_vals, *next_pre_req;
    ACVP_PREREQ_ALG_VAL *pre_req;
    char *alg_str;
    int i = 0;

    if (!cap_entry) { return ACVP_INVALID_ARG; }

    if (!cap_entry->has_prereq) { return ACVP_SUCCESS; }
    /*
     * Init json array
     */
    json_object_set_value(cap_obj, ACVP_PREREQ_OBJ_STR, json_value_init_array());
    prereq_array = json_object_get_array(cap_obj, ACVP_PREREQ_OBJ_STR);

    /*
     * return OK if nothing present
     */
    prereq_vals = cap_entry->prereq_vals;

    while (prereq_vals) {
        JSON_Value *val = NULL;
        JSON_Object *obj = NULL;
        val = json_value_init_object();
        obj = json_value_get_object(val);
        pre_req = &prereq_vals->prereq_alg_val;

        for (i = 0; i < ACVP_NUM_PREREQS; i++) {
            if (acvp_prereqs_tbl[i].alg == pre_req->alg) {
                alg_str = acvp_prereqs_tbl[i].name;
                json_object_set_string(obj, "algorithm", alg_str);
                json_object_set_string(obj, ACVP_PREREQ_VAL_STR, pre_req->val);
                break;
            }
        }

        json_array_append_value(prereq_array, val);
        next_pre_req = prereq_vals->next;
        prereq_vals = next_pre_req;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_hash_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
    if (!cap_entry->cap.hash_cap) {
        return ACVP_MISSING_ARG;
    }
    json_object_set_boolean(cap_obj, "inBit", cap_entry->cap.hash_cap->in_bit);
    json_object_set_boolean(cap_obj, "inEmpty", cap_entry->cap.hash_cap->in_empty);

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_hmac_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_arr = NULL;
    ACVP_RESULT result;
    ACVP_HMAC_CAP *hmac_cap = cap_entry->cap.hmac_cap;

    if (!cap_entry->cap.hmac_cap) {
        return ACVP_NO_CAP;
    }
    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    /*
     * Set the supported key lengths
     */
    json_object_set_value(cap_obj, "keyLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "keyLen");
    if (hmac_cap->key_len.value) {
        json_array_append_number(temp_arr, hmac_cap->key_len.value);
    } else {
        JSON_Value *key_len_val = NULL;
        JSON_Object *key_len_obj = NULL;

        key_len_val = json_value_init_object();
        key_len_obj = json_value_get_object(key_len_val);

        json_object_set_number(key_len_obj, "min", hmac_cap->key_len.min);
        json_object_set_number(key_len_obj, "max", hmac_cap->key_len.max);
        json_object_set_number(key_len_obj, "increment", hmac_cap->key_len.increment);
        json_array_append_value(temp_arr, key_len_val);
    }

    /*
     * Set the supported mac lengths
     */
    json_object_set_value(cap_obj, "macLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "macLen");
    if (hmac_cap->mac_len.value) {
        json_array_append_number(temp_arr, hmac_cap->mac_len.value);
    } else {
        JSON_Value *mac_len_val = NULL;
        JSON_Object *mac_len_obj = NULL;

        mac_len_val = json_value_init_object();
        mac_len_obj = json_value_get_object(mac_len_val);

        json_object_set_number(mac_len_obj, "min", hmac_cap->mac_len.min);
        json_object_set_number(mac_len_obj, "max", hmac_cap->mac_len.max);
        json_object_set_number(mac_len_obj, "increment", hmac_cap->mac_len.increment);
        json_array_append_value(temp_arr, mac_len_val);
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_cmac_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_arr = NULL, *capabilities_arr = NULL;
    JSON_Value *capabilities_val = NULL, *msg_len_val = NULL, *mac_len_val = NULL;
    JSON_Object *capabilities_obj = NULL, *msg_len_obj = NULL, *mac_len_obj = NULL;
    ACVP_SL_LIST *sl_list;
    ACVP_RESULT result;
    ACVP_CMAC_CAP *cmac_cap = cap_entry->cap.cmac_cap;

    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    capabilities_val = json_value_init_object();
    capabilities_obj = json_value_get_object(capabilities_val);

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    capabilities_arr = json_object_get_array(cap_obj, "capabilities");

    json_object_set_value(capabilities_obj, "direction", json_value_init_array());
    temp_arr = json_object_get_array(capabilities_obj, "direction");
    if (!cap_entry->cap.cmac_cap->direction_gen && !cap_entry->cap.cmac_cap->direction_ver) {
        return ACVP_MISSING_ARG;
    }
    if (cap_entry->cap.cmac_cap->direction_gen) { json_array_append_string(temp_arr, "gen"); }
    if (cap_entry->cap.cmac_cap->direction_ver) { json_array_append_string(temp_arr, "ver"); }

    json_object_set_value(capabilities_obj, "msgLen", json_value_init_array());
    temp_arr = json_object_get_array(capabilities_obj, "msgLen");
    if (cmac_cap->msg_len.value) {
        json_array_append_number(temp_arr, cmac_cap->msg_len.value);
    } else {
        msg_len_val = json_value_init_object();
        msg_len_obj = json_value_get_object(msg_len_val);
        json_object_set_number(msg_len_obj, "min", cmac_cap->msg_len.min);
        json_object_set_number(msg_len_obj, "max", cmac_cap->msg_len.max);
        json_object_set_number(msg_len_obj, "increment", cmac_cap->msg_len.increment);
        json_array_append_value(temp_arr, msg_len_val);
    }

    /*
     * Set the supported mac lengths
     */
    json_object_set_value(capabilities_obj, "macLen", json_value_init_array());
    temp_arr = json_object_get_array(capabilities_obj, "macLen");
    if (cmac_cap->mac_len.value) {
        json_array_append_number(temp_arr, cmac_cap->mac_len.value);
    } else {
        mac_len_val = json_value_init_object();
        mac_len_obj = json_value_get_object(mac_len_val);
        json_object_set_number(mac_len_obj, "min", cmac_cap->mac_len.min);
        json_object_set_number(mac_len_obj, "max", cmac_cap->mac_len.max);
        json_object_set_number(mac_len_obj, "increment", cmac_cap->mac_len.increment);
        json_array_append_value(temp_arr, mac_len_val);
    }

    if (cap_entry->cipher == ACVP_CMAC_AES) {
        /*
         * Set the supported key lengths. if CMAC-AES
         */
        json_object_set_value(capabilities_obj, "keyLen", json_value_init_array());
        temp_arr = json_object_get_array(capabilities_obj, "keyLen");
        sl_list = cap_entry->cap.cmac_cap->key_len;
        while (sl_list) {
            json_array_append_number(temp_arr, sl_list->length);
            sl_list = sl_list->next;
        }
    } else if (cap_entry->cipher == ACVP_CMAC_TDES) {
        /*
         * Set the supported key lengths. if CMAC-TDES
         */
        json_object_set_value(capabilities_obj, "keyingOption", json_value_init_array());
        temp_arr = json_object_get_array(capabilities_obj, "keyingOption");
        sl_list = cap_entry->cap.cmac_cap->keying_option;
        if (!sl_list) {
            return ACVP_MISSING_ARG;
        }
        while (sl_list) {
            json_array_append_number(temp_arr, sl_list->length);
            sl_list = sl_list->next;
        }
    }

    json_array_append_value(capabilities_arr, capabilities_val);

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_sym_cipher_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    JSON_Array *kwc_arr = NULL;
    JSON_Array *mode_arr = NULL;
    JSON_Array *opts_arr = NULL;
    ACVP_SL_LIST *sl_list;
    ACVP_RESULT result;
    ACVP_SYM_CIPHER_CAP *sym_cap;

    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));

    sym_cap = cap_entry->cap.sym_cap;
    if (!sym_cap) {
        return ACVP_MISSING_ARG;
    }
    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    /*
     * Set the direction capability
     */
    if (!sym_cap->direction) {
        return ACVP_MISSING_ARG;
    }
    json_object_set_value(cap_obj, "direction", json_value_init_array());
    mode_arr = json_object_get_array(cap_obj, "direction");
    if (sym_cap->direction == ACVP_SYM_CIPH_DIR_ENCRYPT ||
        sym_cap->direction == ACVP_SYM_CIPH_DIR_BOTH) {
        json_array_append_string(mode_arr, "encrypt");
    }
    if (sym_cap->direction == ACVP_SYM_CIPH_DIR_DECRYPT ||
        sym_cap->direction == ACVP_SYM_CIPH_DIR_BOTH) {
        json_array_append_string(mode_arr, "decrypt");
    }

    /*
     * Set the keywrap modes capability
     */
    if ((cap_entry->cipher == ACVP_AES_KW) || (cap_entry->cipher == ACVP_AES_KWP) ||
        (cap_entry->cipher == ACVP_TDES_KW)) {
        json_object_set_value(cap_obj, "kwCipher", json_value_init_array());
        kwc_arr = json_object_get_array(cap_obj, "kwCipher");
        if (sym_cap->kw_mode & ACVP_SYM_KW_CIPHER) {
            json_array_append_string(kwc_arr, "cipher");
        }
        if (sym_cap->kw_mode & ACVP_SYM_KW_INVERSE) {
            json_array_append_string(kwc_arr, "inverse");
        }
    }

    if ((cap_entry->cipher == ACVP_AES_CTR) || (cap_entry->cipher == ACVP_TDES_CTR)) {
        json_object_set_boolean(cap_obj, "incrementalCounter", sym_cap->ctr_incr);
        json_object_set_boolean(cap_obj, "overflowCounter", sym_cap->ctr_ovrflw);
    }

    /*
     * Set the IV generation source if applicable
     */
    switch (sym_cap->ivgen_source) {
    case ACVP_SYM_CIPH_IVGEN_SRC_INT:
        json_object_set_string(cap_obj, "ivGen", "internal");
        break;
    case ACVP_SYM_CIPH_IVGEN_SRC_EXT:
        json_object_set_string(cap_obj, "ivGen", "external");
        break;
    default:
        /* do nothing, this is an optional capability */
        break;
    }

    /*
     * Set the IV generation mode if applicable
     */
    switch (sym_cap->ivgen_mode) {
    case ACVP_SYM_CIPH_IVGEN_MODE_821:
        json_object_set_string(cap_obj, "ivGenMode", "8.2.1");
        break;
    case ACVP_SYM_CIPH_IVGEN_MODE_822:
        json_object_set_string(cap_obj, "ivGenMode", "8.2.2");
        break;
    default:
        /* do nothing, this is an optional capability */
        break;
    }

    /*
     * Set the TDES keyingOptions  if applicable
     */
    if (sym_cap->keying_option != ACVP_SYM_CIPH_KO_NA) {
        json_object_set_value(cap_obj, "keyingOption", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "keyingOption");
        if (sym_cap->keying_option == ACVP_SYM_CIPH_KO_THREE ||
            sym_cap->keying_option == ACVP_SYM_CIPH_KO_BOTH) {
            json_array_append_number(opts_arr, 1);
        }
        if (sym_cap->keying_option == ACVP_SYM_CIPH_KO_TWO ||
            sym_cap->keying_option == ACVP_SYM_CIPH_KO_BOTH) {
            json_array_append_number(opts_arr, 2);
        }
    }
    /*
     * Set the supported key lengths
     */
    json_object_set_value(cap_obj, "keyLen", json_value_init_array());
    opts_arr = json_object_get_array(cap_obj, "keyLen");
    sl_list = sym_cap->keylen;
    if (!sl_list) {
        return ACVP_MISSING_ARG;
    }
    while (sl_list) {
        json_array_append_number(opts_arr, sl_list->length);
        sl_list = sl_list->next;
    }

    /*
     * Set the supported tag lengths (for AEAD ciphers)
     */
    if ((cap_entry->cipher == ACVP_AES_GCM) || (cap_entry->cipher == ACVP_AES_CCM)) {
        json_object_set_value(cap_obj, "tagLen", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "tagLen");
        sl_list = sym_cap->taglen;
        while (sl_list) {
            json_array_append_number(opts_arr, sl_list->length);
            sl_list = sl_list->next;
        }
    }

    /*
     * Set the supported IV lengths
     */
    switch (cap_entry->cipher) {
    case ACVP_TDES_ECB:
    case ACVP_TDES_CBC:
    case ACVP_TDES_CBCI:
    case ACVP_TDES_OFB:
    case ACVP_TDES_OFBI:
    case ACVP_TDES_CFB1:
    case ACVP_TDES_CFB8:
    case ACVP_TDES_CFB64:
    case ACVP_TDES_CFBP1:
    case ACVP_TDES_CFBP8:
    case ACVP_TDES_CFBP64:
    case ACVP_TDES_CTR:
    case ACVP_TDES_KW:
    case ACVP_AES_ECB:
    case ACVP_AES_CFB1:
    case ACVP_AES_CFB8:
    case ACVP_AES_CFB128:
    case ACVP_AES_CTR:
    case ACVP_AES_OFB:
    case ACVP_AES_CBC:
    case ACVP_AES_KW:
    case ACVP_AES_KWP:
    case ACVP_AES_XTS:
        break;
    default:
        json_object_set_value(cap_obj, "ivLen", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "ivLen");
        sl_list = sym_cap->ivlen;
        while (sl_list) {
            json_array_append_number(opts_arr, sl_list->length);
            sl_list = sl_list->next;
        }
    }

    /*
     * Set the supported lengths (could be pt, ct, data, etc.
     * see alg spec for more details)
     */
    json_object_set_value(cap_obj, "payloadLen", json_value_init_array());
    opts_arr = json_object_get_array(cap_obj, "payloadLen");

    sl_list = sym_cap->ptlen;
    while (sl_list) {
        json_array_append_number(opts_arr, sl_list->length);
        sl_list = sl_list->next;
    }

    if (cap_entry->cipher == ACVP_AES_XTS) {
        json_object_set_value(cap_obj, "tweakMode", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "tweakMode");
        sl_list = sym_cap->tweak;
        while (sl_list) {
            switch (sym_cap->tweak->length) {
            case ACVP_SYM_CIPH_TWEAK_HEX:
                json_array_append_string(opts_arr, "hex");
                break;
            case ACVP_SYM_CIPH_TWEAK_NUM:
                json_array_append_string(opts_arr, "number");
                break;
            default:
                break;
            }
            sl_list = sl_list->next;
        }
    }

    /*
     * Set the supported AAD lengths (for AEAD ciphers)
     */
    if ((cap_entry->cipher == ACVP_AES_GCM) || (cap_entry->cipher == ACVP_AES_CCM)) {
        json_object_set_value(cap_obj, "aadLen", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "aadLen");
        sl_list = sym_cap->aadlen;
        while (sl_list) {
            json_array_append_number(opts_arr, sl_list->length);
            sl_list = sl_list->next;
        }
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_lookup_drbg_prereqVals(JSON_Object *cap_obj, ACVP_DRBG_CAP_MODE *drbg_cap_mode) {
    JSON_Array *prereq_array = NULL;
    ACVP_PREREQ_LIST *prereq_vals, *next_pre_req;
    ACVP_PREREQ_ALG_VAL *pre_req;
    char *alg_str;
    int i;

    if (!drbg_cap_mode) { return ACVP_INVALID_ARG; }

    /*
     * Init json array
     */
    json_object_set_value(cap_obj, ACVP_PREREQ_OBJ_STR, json_value_init_array());
    prereq_array = json_object_get_array(cap_obj, ACVP_PREREQ_OBJ_STR);

    /*
     * return OK if nothing present
     */
    prereq_vals = drbg_cap_mode->prereq_vals;
    if (!prereq_vals) {
        return ACVP_SUCCESS;
    }


    while (prereq_vals) {
        JSON_Value *val = NULL;
        JSON_Object *obj = NULL;
        val = json_value_init_object();
        obj = json_value_get_object(val);
        pre_req = &prereq_vals->prereq_alg_val;

        for (i = 0; i < ACVP_NUM_PREREQS; i++) {
            if (acvp_prereqs_tbl[i].alg == pre_req->alg) {
                alg_str = acvp_prereqs_tbl[i].name;
                json_object_set_string(obj, "algorithm", alg_str);
                json_object_set_string(obj, ACVP_PREREQ_VAL_STR, pre_req->val);
                break;
            }
        }

        json_array_append_value(prereq_array, val);
        next_pre_req = prereq_vals->next;
        prereq_vals = next_pre_req;
    }
    return ACVP_SUCCESS;
}

static char *acvp_lookup_drbg_mode_string(ACVP_CAPS_LIST *cap_entry) {
    char *mode_str = NULL;

    if (!cap_entry) { return NULL; }
    if (!cap_entry->cap.drbg_cap) { return NULL; }
    if (!cap_entry->cap.drbg_cap->drbg_cap_mode_list) { return NULL; }

    switch (cap_entry->cap.drbg_cap->drbg_cap_mode_list->cap_mode.mode) {
    case ACVP_DRBG_SHA_1:
        mode_str = ACVP_STR_SHA_1;
        break;
    case ACVP_DRBG_SHA_224:
        mode_str = ACVP_STR_SHA2_224;
        break;
    case ACVP_DRBG_SHA_256:
        mode_str = ACVP_STR_SHA2_256;
        break;
    case ACVP_DRBG_SHA_384:
        mode_str = ACVP_STR_SHA2_384;
        break;
    case ACVP_DRBG_SHA_512:
        mode_str = ACVP_STR_SHA2_512;
        break;
    case ACVP_DRBG_SHA_512_224:
        mode_str = ACVP_STR_SHA2_512_224;
        break;
    case ACVP_DRBG_SHA_512_256:
        mode_str = ACVP_STR_SHA2_512_256;
        break;
    case ACVP_DRBG_3KEYTDEA:
        mode_str = ACVP_DRBG_MODE_3KEYTDEA;
        break;
    case ACVP_DRBG_AES_128:
        mode_str = ACVP_DRBG_MODE_AES_128;
        break;
    case ACVP_DRBG_AES_192:
        mode_str = ACVP_DRBG_MODE_AES_192;
        break;
    case ACVP_DRBG_AES_256:
        mode_str = ACVP_DRBG_MODE_AES_256;
        break;
    default:
        return NULL;
    }
    return mode_str;
}

static ACVP_RESULT acvp_build_drbg_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    ACVP_RESULT result;
    ACVP_DRBG_CAP_MODE *drbg_cap_mode = NULL;
    JSON_Object *len_obj = NULL;
    JSON_Value *len_val = NULL;
    JSON_Array *array = NULL;

    char *mode_str = acvp_lookup_drbg_mode_string(cap_entry);

    if (!mode_str) { return ACVP_INVALID_ARG; }

    if (!&cap_entry->cap.drbg_cap) {
        return ACVP_NO_CAP;
    }
    if (!&cap_entry->cap.drbg_cap->drbg_cap_mode_list) {
        return ACVP_MISSING_ARG;
    }
    drbg_cap_mode = &cap_entry->cap.drbg_cap->drbg_cap_mode_list->cap_mode;
    if (!drbg_cap_mode) {
        return ACVP_MISSING_ARG;
    }
    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));

    result = acvp_lookup_drbg_prereqVals(cap_obj, drbg_cap_mode);
    if (result != ACVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "predResistanceEnabled", json_value_init_array());
    array = json_object_get_array(cap_obj, "predResistanceEnabled");
    json_array_append_boolean(array, drbg_cap_mode->pred_resist_enabled);
    json_object_set_boolean(cap_obj, "reseedImplemented", drbg_cap_mode->reseed_implemented);

    JSON_Array *capabilities_array = NULL;
    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    capabilities_array = json_object_get_array(cap_obj, "capabilities");
    JSON_Value *val = NULL;
    JSON_Object *capabilities_obj = NULL;
    val = json_value_init_object();
    capabilities_obj = json_value_get_object(val);
    json_object_set_string(capabilities_obj, "mode", mode_str);
    json_object_set_boolean(capabilities_obj, "derFuncEnabled", drbg_cap_mode->der_func_enabled);

    //Set entropy range
    json_object_set_value(capabilities_obj, "entropyInputLen", json_value_init_array());
    array = json_object_get_array(capabilities_obj, "entropyInputLen");
    if (!drbg_cap_mode->entropy_len_step) {
        if (drbg_cap_mode->entropy_len_min) {
            json_array_append_number(array, drbg_cap_mode->entropy_len_min);
        } else if (drbg_cap_mode->entropy_len_max) {
            json_array_append_number(array, drbg_cap_mode->entropy_len_max);
        }
    } else {
        len_val = json_value_init_object();
        len_obj = json_value_get_object(len_val);
        json_object_set_number(len_obj, "max", drbg_cap_mode->entropy_len_max);
        json_object_set_number(len_obj, "min", drbg_cap_mode->entropy_len_min);
        json_object_set_number(len_obj, "step", drbg_cap_mode->entropy_len_step);
        json_array_append_value(array, len_val);
    }

    json_object_set_value(capabilities_obj, "nonceLen", json_value_init_array());
    array = json_object_get_array(capabilities_obj, "nonceLen");
    if (!drbg_cap_mode->nonce_len_step) {
        if (drbg_cap_mode->nonce_len_min) {
            json_array_append_number(array, drbg_cap_mode->nonce_len_min);
        } else if (drbg_cap_mode->nonce_len_max) {
            json_array_append_number(array, drbg_cap_mode->nonce_len_max);
        }
    } else {
        len_val = json_value_init_object();
        len_obj = json_value_get_object(len_val);
        json_object_set_number(len_obj, "max", drbg_cap_mode->nonce_len_max);
        json_object_set_number(len_obj, "min", drbg_cap_mode->nonce_len_min);
        json_object_set_number(len_obj, "step", drbg_cap_mode->nonce_len_step);
        json_array_append_value(array, len_val);
    }

    json_object_set_value(capabilities_obj, "persoStringLen", json_value_init_array());
    array = json_object_get_array(capabilities_obj, "persoStringLen");
    if (!drbg_cap_mode->perso_len_step) {
        if (drbg_cap_mode->perso_len_min) {
            json_array_append_number(array, drbg_cap_mode->perso_len_min);
        } else if (drbg_cap_mode->perso_len_max) {
            json_array_append_number(array, drbg_cap_mode->perso_len_max);
        }
    } else {
        len_val = json_value_init_object();
        len_obj = json_value_get_object(len_val);
        json_object_set_number(len_obj, "max", drbg_cap_mode->perso_len_max);
        json_object_set_number(len_obj, "min", drbg_cap_mode->perso_len_min);
        json_object_set_number(len_obj, "step", drbg_cap_mode->perso_len_step);
        json_array_append_value(array, len_val);
    }

    json_object_set_value(capabilities_obj, "additionalInputLen", json_value_init_array());
    array = json_object_get_array(capabilities_obj, "additionalInputLen");
    if (!drbg_cap_mode->additional_in_len_step) {
        if (drbg_cap_mode->additional_in_len_min) {
            json_array_append_number(array, drbg_cap_mode->additional_in_len_min);
        } else if (drbg_cap_mode->additional_in_len_max) {
            json_array_append_number(array, drbg_cap_mode->additional_in_len_max);
        }
    } else {
        len_val = json_value_init_object();
        len_obj = json_value_get_object(len_val);
        json_object_set_number(len_obj, "max", drbg_cap_mode->additional_in_len_max);
        json_object_set_number(len_obj, "min", drbg_cap_mode->additional_in_len_min);
        json_object_set_number(len_obj, "step", drbg_cap_mode->additional_in_len_step);
        json_array_append_value(array, len_val);
    }

    //Set DRBG Length
    json_object_set_number(capabilities_obj, "returnedBitsLen", drbg_cap_mode->returned_bits_len);

    json_array_append_value(capabilities_array, val);

    return ACVP_SUCCESS;
}

/*
 * Builds the JSON object for RSA keygen primes
 */
static ACVP_RESULT acvp_lookup_rsa_primes(JSON_Object *cap_obj, ACVP_RSA_KEYGEN_CAP *rsa_cap) {
    JSON_Array *primes_array = NULL, *hash_array = NULL, *prime_test_array = NULL;

    ACVP_RSA_MODE_CAPS_LIST *current_mode_cap;
    ACVP_NAME_LIST *comp_name, *next_name;

    if (!rsa_cap) { return ACVP_INVALID_ARG; }

    /*
     * return OK if nothing present
     */
    current_mode_cap = rsa_cap->mode_capabilities;
    if (!current_mode_cap) {
        return ACVP_SUCCESS;
    }

    json_object_set_value(cap_obj, "properties", json_value_init_array());
    primes_array = json_object_get_array(cap_obj, "properties");

    while (current_mode_cap) {
        JSON_Value *val = NULL;
        JSON_Object *obj = NULL;
        val = json_value_init_object();
        obj = json_value_get_object(val);

        json_object_set_number(obj, "modulo", current_mode_cap->modulo);

        json_object_set_value(obj, "hashAlg", json_value_init_array());
        hash_array = json_object_get_array(obj, "hashAlg");
        comp_name = current_mode_cap->hash_algs;

        while (comp_name) {
            if (acvp_lookup_hash_alg(comp_name->name)) {
                json_array_append_string(hash_array, comp_name->name);
            }
            next_name = comp_name->next;
            comp_name = next_name;
        }

        comp_name = current_mode_cap->prime_tests;

        if (comp_name) {
            json_object_set_value(obj, "primeTest", json_value_init_array());
            prime_test_array = json_object_get_array(obj, "primeTest");

            while (comp_name) {
                if (is_valid_prime_test(comp_name->name) == ACVP_SUCCESS) {
                    json_array_append_string(prime_test_array, comp_name->name);
                }
                next_name = comp_name->next;
                comp_name = next_name;
            }
        }

        json_array_append_value(primes_array, val);
        current_mode_cap = current_mode_cap->next;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_rsa_keygen_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    ACVP_RESULT result;

    json_object_set_string(cap_obj, "algorithm", "RSA");
    json_object_set_string(cap_obj, "mode", "keyGen");

    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    /*
     * Iterate through list of RSA modes and create registration object
     * for each one, appending to the array as we go
     */
    ACVP_RSA_KEYGEN_CAP *keygen_cap = cap_entry->cap.rsa_keygen_cap;
    if (!keygen_cap) {
        return ACVP_NO_CAP;
    }

    JSON_Array *alg_specs_array = NULL;
    JSON_Value *alg_specs_val = NULL;
    JSON_Object *alg_specs_obj = NULL;

    json_object_set_boolean(cap_obj, "infoGeneratedByServer", keygen_cap->info_gen_by_server);
    if (!keygen_cap->pub_exp_mode) {
        return ACVP_MISSING_ARG;
    }
    json_object_set_string(cap_obj, "pubExpMode",
                           keygen_cap->pub_exp_mode == ACVP_RSA_PUB_EXP_MODE_FIXED ?
                           ACVP_RSA_PUB_EXP_MODE_FIXED_STR : ACVP_RSA_PUB_EXP_MODE_RANDOM_STR);
    if (keygen_cap->pub_exp_mode == ACVP_RSA_PUB_EXP_MODE_FIXED) {
        json_object_set_string(cap_obj, "fixedPubExp", (const char *)keygen_cap->fixed_pub_exp);
    }
    json_object_set_string(cap_obj, "keyFormat", keygen_cap->key_format_crt ? "crt" : "standard");

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    alg_specs_array = json_object_get_array(cap_obj, "capabilities");

    while (keygen_cap) {
        alg_specs_val = json_value_init_object();
        alg_specs_obj = json_value_get_object(alg_specs_val);

        json_object_set_string(alg_specs_obj, "randPQ", acvp_lookup_rsa_randpq_name(keygen_cap->rand_pq));
        result = acvp_lookup_rsa_primes(alg_specs_obj, keygen_cap);
        if (result != ACVP_SUCCESS) {
            return result;
        }

        json_array_append_value(alg_specs_array, alg_specs_val);
        keygen_cap = keygen_cap->next;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_rsa_sig_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_RSA_SIG_CAP *rsa_cap_mode = NULL;
    JSON_Array *alg_specs_array = NULL, *sig_type_caps_array = NULL, *hash_pair_array = NULL;
    JSON_Value *alg_specs_val = NULL, *sig_type_val = NULL, *hash_pair_val = NULL;
    JSON_Object *alg_specs_obj = NULL, *sig_type_obj = NULL, *hash_pair_obj = NULL;

    json_object_set_string(cap_obj, "algorithm", "RSA");
    if (cap_entry->cipher == ACVP_RSA_SIGGEN) {
        json_object_set_string(cap_obj, "mode", "sigGen");
        rsa_cap_mode = cap_entry->cap.rsa_siggen_cap;
        if (!rsa_cap_mode) {
            return ACVP_MISSING_ARG;
        }
    } else if (cap_entry->cipher == ACVP_RSA_SIGVER) {
        json_object_set_string(cap_obj, "mode", "sigVer");
        rsa_cap_mode = cap_entry->cap.rsa_sigver_cap;
        if (!rsa_cap_mode) {
            return ACVP_MISSING_ARG;
        }
        json_object_set_string(cap_obj, "pubExpMode", rsa_cap_mode->pub_exp_mode ? "fixed" : "random");
        if (cap_entry->cap.rsa_sigver_cap->pub_exp_mode) {
            json_object_set_string(cap_obj, "fixedPubExp", (const char *)cap_entry->cap.rsa_sigver_cap->fixed_pub_exp);
        }
    }

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    alg_specs_array = json_object_get_array(cap_obj, "capabilities");

    while (rsa_cap_mode) {
        alg_specs_val = json_value_init_object();
        alg_specs_obj = json_value_get_object(alg_specs_val);
        json_object_set_string(alg_specs_obj, "sigType", rsa_cap_mode->sig_type_str);

        json_object_set_value(alg_specs_obj, "properties", json_value_init_array());
        sig_type_caps_array = json_object_get_array(alg_specs_obj, "properties");

        ACVP_RSA_MODE_CAPS_LIST *current_sig_type_cap = rsa_cap_mode->mode_capabilities;

        while (current_sig_type_cap) {
            sig_type_val = json_value_init_object();
            sig_type_obj = json_value_get_object(sig_type_val);

            json_object_set_number(sig_type_obj, "modulo", current_sig_type_cap->modulo);
            json_object_set_value(sig_type_obj, "hashPair", json_value_init_array());
            hash_pair_array = json_object_get_array(sig_type_obj, "hashPair");

            ACVP_RSA_HASH_PAIR_LIST *current_hash_pair = current_sig_type_cap->hash_pair;
            while (current_hash_pair) {
                hash_pair_val = json_value_init_object();
                hash_pair_obj = json_value_get_object(hash_pair_val);
                if (!current_hash_pair->name) {
                    return ACVP_MISSING_ARG;
                }
                json_object_set_string(hash_pair_obj, "hashAlg", current_hash_pair->name);
                if (strncmp(rsa_cap_mode->sig_type_str, "pss", 3) == 0) {
                    json_object_set_number(hash_pair_obj, "saltLen", current_hash_pair->salt);
                }

                json_array_append_value(hash_pair_array, hash_pair_val);
                current_hash_pair = current_hash_pair->next;
            }

            current_sig_type_cap = current_sig_type_cap->next;
            json_array_append_value(sig_type_caps_array, sig_type_val);
        }
        json_array_append_value(alg_specs_array, alg_specs_val);
        rsa_cap_mode = rsa_cap_mode->next;
    }

    return result;
}

static ACVP_RESULT acvp_build_ecdsa_register_cap(ACVP_CIPHER cipher, JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    ACVP_RESULT result;
    JSON_Array *caps_arr = NULL, *curves_arr = NULL, *secret_modes_arr = NULL, *hash_arr = NULL;
    ACVP_NAME_LIST *current_curve = NULL, *current_secret_mode = NULL, *current_hash = NULL;
    JSON_Value *alg_caps_val;
    JSON_Object *alg_caps_obj;

    json_object_set_string(cap_obj, "algorithm", "ECDSA");

    switch (cipher) {
    case ACVP_ECDSA_KEYGEN:
        json_object_set_string(cap_obj, "mode", "keyGen");
        if (!cap_entry->cap.ecdsa_keygen_cap) {
            return ACVP_NO_CAP;
        }
        current_curve = cap_entry->cap.ecdsa_keygen_cap->curves;
        current_secret_mode = cap_entry->cap.ecdsa_keygen_cap->secret_gen_modes;
        break;
    case ACVP_ECDSA_KEYVER:
        json_object_set_string(cap_obj, "mode", "keyVer");
        if (!cap_entry->cap.ecdsa_keyver_cap) {
            return ACVP_NO_CAP;
        }
        current_curve = cap_entry->cap.ecdsa_keyver_cap->curves;
        break;
    case ACVP_ECDSA_SIGGEN:
        json_object_set_string(cap_obj, "mode", "sigGen");
        if (!cap_entry->cap.ecdsa_siggen_cap) {
            return ACVP_NO_CAP;
        }
        current_curve = cap_entry->cap.ecdsa_siggen_cap->curves;
        current_hash = cap_entry->cap.ecdsa_siggen_cap->hash_algs;
        break;
    case ACVP_ECDSA_SIGVER:
        json_object_set_string(cap_obj, "mode", "sigVer");
        if (!cap_entry->cap.ecdsa_sigver_cap) {
            return ACVP_NO_CAP;
        }
        current_curve = cap_entry->cap.ecdsa_sigver_cap->curves;
        current_hash = cap_entry->cap.ecdsa_sigver_cap->hash_algs;
        break;
    default:
        return ACVP_INVALID_ARG;

        break;
    }

    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    if (cipher == ACVP_ECDSA_SIGVER || cipher == ACVP_ECDSA_SIGGEN) {
        json_object_set_value(cap_obj, "capabilities", json_value_init_array());
        caps_arr = json_object_get_array(cap_obj, "capabilities");
    }
    alg_caps_val = json_value_init_object();
    alg_caps_obj = json_value_get_object(alg_caps_val);

    /*
     * Iterate through list of RSA modes and create registration object
     * for each one, appending to the array as we go
     */
    if (cipher == ACVP_ECDSA_SIGVER || cipher == ACVP_ECDSA_SIGGEN) {
        json_object_set_value(alg_caps_obj, "curve", json_value_init_array());
        curves_arr = json_object_get_array(alg_caps_obj, "curve");
    } else {
        json_object_set_value(cap_obj, "curve", json_value_init_array());
        curves_arr = json_object_get_array(cap_obj, "curve");
    }
    if (!current_curve) {
        return ACVP_MISSING_ARG;
    }
    while (current_curve) {
        if (!current_curve->name) {
            return ACVP_MISSING_ARG;
        }
        json_array_append_string(curves_arr, current_curve->name);
        current_curve = current_curve->next;
    }

    if (cipher == ACVP_ECDSA_KEYGEN) {
        json_object_set_value(cap_obj, "secretGenerationMode", json_value_init_array());
        secret_modes_arr = json_object_get_array(cap_obj, "secretGenerationMode");
        while (current_secret_mode) {
            if (!current_secret_mode->name) {
                return ACVP_MISSING_ARG;
            }
            json_array_append_string(secret_modes_arr, current_secret_mode->name);
            current_secret_mode = current_secret_mode->next;
        }
    }

    if (cipher == ACVP_ECDSA_SIGGEN || cipher == ACVP_ECDSA_SIGVER) {
        json_object_set_value(alg_caps_obj, "hashAlg", json_value_init_array());
        hash_arr = json_object_get_array(alg_caps_obj, "hashAlg");
        while (current_hash) {
            if (!current_hash->name) {
                return ACVP_MISSING_ARG;
            }
            json_array_append_string(hash_arr, current_hash->name);
            current_hash = current_hash->next;
        }
        json_array_append_value(caps_arr, alg_caps_val);
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kdf135_tls_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_arr = NULL;
    ACVP_RESULT result;

    json_object_set_string(cap_obj, "algorithm", ACVP_KDF135_ALG_STR);
    json_object_set_string(cap_obj, "mode", ACVP_ALG_KDF135_TLS);
    json_object_set_value(cap_obj, "tlsVersion", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "tlsVersion");
    if (cap_entry->cap.kdf135_tls_cap->method[0] == ACVP_KDF135_TLS10_TLS11) {
        json_array_append_string(temp_arr, "v1.0/1.1");
    } else if (cap_entry->cap.kdf135_tls_cap->method[0] == ACVP_KDF135_TLS12) {
        json_array_append_string(temp_arr, "v1.2");
    }

    if (cap_entry->cap.kdf135_tls_cap->method[1] == ACVP_KDF135_TLS10_TLS11) {
        json_array_append_string(temp_arr, "v1.0/1.1");
    } else if (cap_entry->cap.kdf135_tls_cap->method[1] == ACVP_KDF135_TLS12) {
        json_array_append_string(temp_arr, "v1.2");
    }

    json_object_set_value(cap_obj, "hashAlg", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "hashAlg");
    if (cap_entry->cap.kdf135_tls_cap->sha & ACVP_SHA256) {
        json_array_append_string(temp_arr, "SHA2-256");
    }
    if (cap_entry->cap.kdf135_tls_cap->sha & ACVP_SHA384) {
        json_array_append_string(temp_arr, "SHA2-384");
    }
    if (cap_entry->cap.kdf135_tls_cap->sha & ACVP_SHA512) {
        json_array_append_string(temp_arr, "SHA2-512");
    }

    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kdf135_snmp_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    ACVP_RESULT result;
    JSON_Array *temp_arr = NULL;
    ACVP_NAME_LIST *current_engid;
    ACVP_SL_LIST *current_val;

    json_object_set_string(cap_obj, "algorithm", ACVP_KDF135_ALG_STR);
    json_object_set_string(cap_obj, "mode", ACVP_ALG_KDF135_SNMP);

    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "engineId", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "engineId");

    current_engid = cap_entry->cap.kdf135_snmp_cap->eng_ids;
    while (current_engid) {
        json_array_append_string(temp_arr, current_engid->name);
        current_engid = current_engid->next;
    }

    json_object_set_value(cap_obj, "passwordLength", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "passwordLength");

    current_val = cap_entry->cap.kdf135_snmp_cap->pass_lens;
    while (current_val) {
        json_array_append_number(temp_arr, current_val->length);
        current_val = current_val->next;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kdf108_mode_register(JSON_Object **mode_obj, ACVP_KDF108_MODE_PARAMS *mode_params) {
    JSON_Array *tmp_arr = NULL;
    JSON_Value *tmp_val = NULL;
    JSON_Object *tmp_obj = NULL;
    ACVP_NAME_LIST *nl_obj;
    ACVP_SL_LIST *sl_obj;

    /* mac mode list */
    json_object_set_value(*mode_obj, "macMode", json_value_init_array());
    tmp_arr = json_object_get_array(*mode_obj, "macMode");
    nl_obj = mode_params->mac_mode;
    while (nl_obj) {
        json_array_append_string(tmp_arr, nl_obj->name);
        nl_obj = nl_obj->next;
    }

    /* supported lens domain obj */
    json_object_set_value(*mode_obj, "supportedLengths", json_value_init_array());
    tmp_arr = json_object_get_array(*mode_obj, "supportedLengths");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", mode_params->supported_lens.min);
    json_object_set_number(tmp_obj, "max", mode_params->supported_lens.max);
    json_object_set_number(tmp_obj, "increment", mode_params->supported_lens.increment);
    json_array_append_value(tmp_arr, tmp_val);

    /* fixed data order list */
    json_object_set_value(*mode_obj, "fixedDataOrder", json_value_init_array());
    tmp_arr = json_object_get_array(*mode_obj, "fixedDataOrder");
    nl_obj = mode_params->data_order;
    while (nl_obj) {
        json_array_append_string(tmp_arr, nl_obj->name);
        nl_obj = nl_obj->next;
    }

    /* counter length list */
    json_object_set_value(*mode_obj, "counterLength", json_value_init_array());
    tmp_arr = json_object_get_array(*mode_obj, "counterLength");
    sl_obj = mode_params->counter_lens;
    while (sl_obj) {
        json_array_append_number(tmp_arr, sl_obj->length);
        sl_obj = sl_obj->next;
    }

    json_object_set_boolean(*mode_obj, "supportsEmptyIv", mode_params->empty_iv_support);

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kdf108_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    ACVP_RESULT result;
    JSON_Array *alg_specs_array = NULL;
    JSON_Value *alg_specs_counter_val = NULL, *alg_specs_feedback_val = NULL, *alg_specs_dpi_val = NULL;
    JSON_Object *alg_specs_counter_obj = NULL, *alg_specs_feedback_obj = NULL, *alg_specs_dpi_obj = NULL;

    json_object_set_string(cap_obj, "algorithm", "KDF");

    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    alg_specs_array = json_object_get_array(cap_obj, "capabilities");

    if (cap_entry->cap.kdf108_cap->counter_mode.kdf_mode) {
        alg_specs_counter_val = json_value_init_object();
        alg_specs_counter_obj = json_value_get_object(alg_specs_counter_val);
        json_object_set_string(alg_specs_counter_obj, "kdfMode", "counter");
        acvp_build_kdf108_mode_register(&alg_specs_counter_obj, &cap_entry->cap.kdf108_cap->counter_mode);
        json_array_append_value(alg_specs_array, alg_specs_counter_val);
    }
    if (cap_entry->cap.kdf108_cap->feedback_mode.kdf_mode) {
        alg_specs_feedback_val = json_value_init_object();
        alg_specs_feedback_obj = json_value_get_object(alg_specs_feedback_val);
        json_object_set_string(alg_specs_feedback_obj, "kdfMode", "feedback");
        acvp_build_kdf108_mode_register(&alg_specs_feedback_obj, &cap_entry->cap.kdf108_cap->feedback_mode);
        json_array_append_value(alg_specs_array, alg_specs_feedback_val);
    }
    if (cap_entry->cap.kdf108_cap->dpi_mode.kdf_mode) {
        alg_specs_dpi_val = json_value_init_object();
        alg_specs_dpi_obj = json_value_get_object(alg_specs_dpi_val);
        json_object_set_string(alg_specs_dpi_obj, "kdfMode", "dpi");
        acvp_build_kdf108_mode_register(&alg_specs_dpi_obj, &cap_entry->cap.kdf108_cap->dpi_mode);
        json_array_append_value(alg_specs_array, alg_specs_dpi_val);
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kdf135_x963_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    ACVP_RESULT result;
    JSON_Array *tmp_arr = NULL;
    ACVP_NAME_LIST *nl_obj;
    ACVP_SL_LIST *sl_obj;

    json_object_set_string(cap_obj, "algorithm", ACVP_KDF135_ALG_STR);
    json_object_set_string(cap_obj, "mode", "ansix9.63");

    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    /* Array of hash algs */
    json_object_set_value(cap_obj, "hashAlg", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "hashAlg");
    nl_obj = cap_entry->cap.kdf135_x963_cap->hash_algs;
    while (nl_obj) {
        json_array_append_string(tmp_arr, nl_obj->name);
        nl_obj = nl_obj->next;
    }

    /* key data length list */
    json_object_set_value(cap_obj, "keyDataLength", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "keyDataLength");
    sl_obj = cap_entry->cap.kdf135_x963_cap->key_data_lengths;
    while (sl_obj) {
        json_array_append_number(tmp_arr, sl_obj->length);
        sl_obj = sl_obj->next;
    }

    /* field size list */
    json_object_set_value(cap_obj, "fieldSize", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "fieldSize");
    sl_obj = cap_entry->cap.kdf135_x963_cap->field_sizes;
    while (sl_obj) {
        json_array_append_number(tmp_arr, sl_obj->length);
        sl_obj = sl_obj->next;
    }

    /* shared info length list */
    json_object_set_value(cap_obj, "sharedInfoLength", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "sharedInfoLength");
    sl_obj = cap_entry->cap.kdf135_x963_cap->shared_info_lengths;
    while (sl_obj) {
        json_array_append_number(tmp_arr, sl_obj->length);
        sl_obj = sl_obj->next;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kdf135_ikev2_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    ACVP_RESULT result;
    JSON_Array *tmp_arr = NULL, *alg_specs_array = NULL;
    JSON_Value *tmp_val = NULL, *alg_specs_val = NULL;
    JSON_Object *tmp_obj = NULL, *alg_specs_obj = NULL;
    ACVP_NAME_LIST *current_hash;
    ACVP_KDF135_IKEV2_CAP *cap = cap_entry->cap.kdf135_ikev2_cap;

    json_object_set_string(cap_obj, "algorithm", ACVP_KDF135_ALG_STR);
    json_object_set_string(cap_obj, "mode", ACVP_ALG_KDF135_IKEV2);
    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    alg_specs_array = json_object_get_array(cap_obj, "capabilities");

    alg_specs_val = json_value_init_object();
    alg_specs_obj = json_value_get_object(alg_specs_val);

    /* initiator nonce len */
    json_object_set_value(alg_specs_obj, "initiatorNonceLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "initiatorNonceLength");
    if (cap->init_nonce_len_domain.value) {
        json_array_append_number(tmp_arr, cap->init_nonce_len_domain.value);
    } else {
        tmp_val = json_value_init_object();
        tmp_obj = json_value_get_object(tmp_val);
        json_object_set_number(tmp_obj, "min", cap->init_nonce_len_domain.min);
        json_object_set_number(tmp_obj, "max", cap->init_nonce_len_domain.max);
        json_object_set_number(tmp_obj, "increment", cap->init_nonce_len_domain.increment);
        json_array_append_value(tmp_arr, tmp_val);
    }

    /* responder nonce len */
    json_object_set_value(alg_specs_obj, "responderNonceLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "responderNonceLength");
    if (cap->respond_nonce_len_domain.value) {
        json_array_append_number(tmp_arr, cap->respond_nonce_len_domain.value);
    } else {
        tmp_val = json_value_init_object();
        tmp_obj = json_value_get_object(tmp_val);
        json_object_set_number(tmp_obj, "min", cap->respond_nonce_len_domain.min);
        json_object_set_number(tmp_obj, "max", cap->respond_nonce_len_domain.max);
        json_object_set_number(tmp_obj, "increment", cap->respond_nonce_len_domain.increment);
        json_array_append_value(tmp_arr, tmp_val);
    }

    /* Diffie Hellman shared secret len */
    json_object_set_value(alg_specs_obj, "diffieHellmanSharedSecretLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "diffieHellmanSharedSecretLength");
    if (cap->dh_secret_len.value) {
        json_array_append_number(tmp_arr, cap->dh_secret_len.value);
    } else {
        tmp_val = json_value_init_object();
        tmp_obj = json_value_get_object(tmp_val);
        json_object_set_number(tmp_obj, "min", cap->dh_secret_len.min);
        json_object_set_number(tmp_obj, "max", cap->dh_secret_len.max);
        json_object_set_number(tmp_obj, "increment", cap->dh_secret_len.increment);
        json_array_append_value(tmp_arr, tmp_val);
    }

    /* Derived keying material len */
    json_object_set_value(alg_specs_obj, "derivedKeyingMaterialLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "derivedKeyingMaterialLength");
    if (cap->key_material_len.value) {
        json_array_append_number(tmp_arr, cap->key_material_len.value);
    } else {
        tmp_val = json_value_init_object();
        tmp_obj = json_value_get_object(tmp_val);
        json_object_set_number(tmp_obj, "min", cap->key_material_len.min);
        json_object_set_number(tmp_obj, "max", cap->key_material_len.max);
        json_object_set_number(tmp_obj, "increment", cap->key_material_len.increment);
        json_array_append_value(tmp_arr, tmp_val);
    }

    /* Array of hash algs */
    json_object_set_value(alg_specs_obj, "hashAlg", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "hashAlg");
    current_hash = cap->hash_algs;
    while (current_hash) {
        json_array_append_string(tmp_arr, current_hash->name);
        current_hash = current_hash->next;
    }

    json_array_append_value(alg_specs_array, alg_specs_val);

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kdf135_ikev1_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    ACVP_RESULT result;
    JSON_Array *alg_specs_array = NULL, *tmp_arr = NULL;
    JSON_Value *alg_specs_val = NULL, *tmp_val = NULL;
    JSON_Object *alg_specs_obj = NULL, *tmp_obj = NULL;
    ACVP_NAME_LIST *current_hash;

    json_object_set_string(cap_obj, "algorithm", ACVP_KDF135_ALG_STR);
    json_object_set_string(cap_obj, "mode", ACVP_ALG_KDF135_IKEV1);
    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    alg_specs_array = json_object_get_array(cap_obj, "capabilities");

    alg_specs_val = json_value_init_object();
    alg_specs_obj = json_value_get_object(alg_specs_val);

    /* initiator nonce len */
    json_object_set_value(alg_specs_obj, "initiatorNonceLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "initiatorNonceLength");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap_entry->cap.kdf135_ikev1_cap->init_nonce_len_domain.min);
    json_object_set_number(tmp_obj, "max", cap_entry->cap.kdf135_ikev1_cap->init_nonce_len_domain.max);
    json_object_set_number(tmp_obj, "increment", cap_entry->cap.kdf135_ikev1_cap->init_nonce_len_domain.increment);
    json_array_append_value(tmp_arr, tmp_val);

    /* responder nonce len */
    json_object_set_value(alg_specs_obj, "responderNonceLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "responderNonceLength");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap_entry->cap.kdf135_ikev1_cap->respond_nonce_len_domain.min);
    json_object_set_number(tmp_obj, "max", cap_entry->cap.kdf135_ikev1_cap->respond_nonce_len_domain.max);
    json_object_set_number(tmp_obj, "increment", cap_entry->cap.kdf135_ikev1_cap->respond_nonce_len_domain.increment);
    json_array_append_value(tmp_arr, tmp_val);

    /* Diffie Hellman shared secret len */
    json_object_set_value(alg_specs_obj, "diffieHellmanSharedSecretLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "diffieHellmanSharedSecretLength");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap_entry->cap.kdf135_ikev1_cap->dh_secret_len.min);
    json_object_set_number(tmp_obj, "max", cap_entry->cap.kdf135_ikev1_cap->dh_secret_len.max);
    json_object_set_number(tmp_obj, "increment", cap_entry->cap.kdf135_ikev1_cap->dh_secret_len.increment);
    json_array_append_value(tmp_arr, tmp_val);

    /* Pre shared key len */
    json_object_set_value(alg_specs_obj, "preSharedKeyLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "preSharedKeyLength");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap_entry->cap.kdf135_ikev1_cap->psk_len.min);
    json_object_set_number(tmp_obj, "max", cap_entry->cap.kdf135_ikev1_cap->psk_len.max);
    json_object_set_number(tmp_obj, "increment", cap_entry->cap.kdf135_ikev1_cap->psk_len.increment);
    json_array_append_value(tmp_arr, tmp_val);

    /* Array of hash algs */
    json_object_set_value(alg_specs_obj, "hashAlg", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "hashAlg");
    current_hash = cap_entry->cap.kdf135_ikev1_cap->hash_algs;
    while (current_hash) {
        json_array_append_string(tmp_arr, current_hash->name);
        current_hash = current_hash->next;
    }

    json_object_set_string(alg_specs_obj, "authenticationMethod", cap_entry->cap.kdf135_ikev1_cap->auth_method);

    json_array_append_value(alg_specs_array, alg_specs_val);

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kdf135_srtp_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    ACVP_RESULT result;
    JSON_Array *tmp_arr = NULL;
    int i;
    ACVP_SL_LIST *current_aes_keylen;

    json_object_set_string(cap_obj, "algorithm", ACVP_KDF135_ALG_STR);
    json_object_set_string(cap_obj, "mode", ACVP_ALG_KDF135_SRTP);

    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "aesKeyLength", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "aesKeyLength");
    current_aes_keylen = cap_entry->cap.kdf135_srtp_cap->aes_keylens;
    while (current_aes_keylen) {
        json_array_append_number(tmp_arr, current_aes_keylen->length);
        current_aes_keylen = current_aes_keylen->next;
    }

    json_object_set_boolean(cap_obj, "supportsZeroKdr", cap_entry->cap.kdf135_srtp_cap->supports_zero_kdr);

    json_object_set_value(cap_obj, "kdrExponent", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "kdrExponent");
    for (i = 0; i < 24; i++) {
        if (cap_entry->cap.kdf135_srtp_cap->kdr_exp[i] == 1) {
            json_array_append_number(tmp_arr, i + 1);
        }
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kdf135_ssh_register_cap(JSON_Object *cap_obj, ACVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_arr = NULL;
    ACVP_RESULT result;

    json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
    json_object_set_string(cap_obj, "mode", ACVP_ALG_KDF135_SSH);
    json_object_set_value(cap_obj, "cipher", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "cipher");
    if (cap_entry->cap.kdf135_ssh_cap->method[0] == ACVP_SSH_METH_TDES_CBC) {
        json_array_append_string(temp_arr, "TDES");
    }

    if (cap_entry->cap.kdf135_ssh_cap->method[1] == ACVP_SSH_METH_AES_128_CBC) {
        json_array_append_string(temp_arr, "AES-128");
    }

    if (cap_entry->cap.kdf135_ssh_cap->method[2] == ACVP_SSH_METH_AES_192_CBC) {
        json_array_append_string(temp_arr, "AES-192");
    }

    if (cap_entry->cap.kdf135_ssh_cap->method[3] == ACVP_SSH_METH_AES_256_CBC) {
        json_array_append_string(temp_arr, "AES-256");
    }

    json_object_set_value(cap_obj, "hashAlg", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "hashAlg");
    if (cap_entry->cap.kdf135_ssh_cap->sha & ACVP_SHA1) {
        json_array_append_string(temp_arr, "SHA-1");
    }
    if (cap_entry->cap.kdf135_ssh_cap->sha & ACVP_SHA224) {
        json_array_append_string(temp_arr, "SHA2-224");
    }
    if (cap_entry->cap.kdf135_ssh_cap->sha & ACVP_SHA256) {
        json_array_append_string(temp_arr, "SHA2-256");
    }
    if (cap_entry->cap.kdf135_ssh_cap->sha & ACVP_SHA384) {
        json_array_append_string(temp_arr, "SHA2-384");
    }
    if (cap_entry->cap.kdf135_ssh_cap->sha & ACVP_SHA512) {
        json_array_append_string(temp_arr, "SHA2-512");
    }

    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_dsa_hashalgs(JSON_Object *cap_obj,
                                           JSON_Array *temp_arr,
                                           ACVP_DSA_ATTRS *attrs) {
    JSON_Array *sha_arr = NULL;

    json_object_set_value(cap_obj, "hashAlg", json_value_init_array());
    sha_arr = json_object_get_array(cap_obj, "hashAlg");

    if (attrs->sha & ACVP_SHA1) {
        json_array_append_string(sha_arr, "SHA2-1");
    }
    if (attrs->sha & ACVP_SHA224) {
        json_array_append_string(sha_arr, "SHA2-224");
    }
    if (attrs->sha & ACVP_SHA256) {
        json_array_append_string(sha_arr, "SHA2-256");
    }
    if (attrs->sha & ACVP_SHA384) {
        json_array_append_string(sha_arr, "SHA2-384");
    }
    if (attrs->sha & ACVP_SHA512) {
        json_array_append_string(sha_arr, "SHA2-512");
    }
    if (attrs->sha & ACVP_SHA512_224) {
        json_array_append_string(sha_arr, "SHA2-512-224");
    }
    if (attrs->sha & ACVP_SHA512_256) {
        json_array_append_string(sha_arr, "SHA2-512-256");
    }

    if (json_array_get_count(sha_arr) == 0) {
        return ACVP_MISSING_ARG;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_dsa_pqggen_register(JSON_Array *meth_array,
                                                  ACVP_CAPS_LIST *cap_entry) {
    ACVP_DSA_ATTRS *attrs = NULL;
    ACVP_RESULT rv;
    ACVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    JSON_Array *temp_arr = NULL;
    JSON_Value *new_cap_val = NULL;
    JSON_Object *new_cap_obj = NULL;

    dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[ACVP_DSA_MODE_PQGGEN - 1];
    attrs = dsa_cap_mode->dsa_attrs;
    if (!attrs) {
        return ACVP_MISSING_ARG;
    }

    while (attrs) {
        new_cap_val = json_value_init_object();
        new_cap_obj = json_value_get_object(new_cap_val);

        json_object_set_value(new_cap_obj, "pqGen", json_value_init_array());
        temp_arr = json_object_get_array(new_cap_obj, "pqGen");
        if (dsa_cap_mode->gen_pq_prob) {
            json_array_append_string(temp_arr, "probable");
        }
        if (dsa_cap_mode->gen_pq_prov) {
            json_array_append_string(temp_arr, "provable");
        }
        if (!dsa_cap_mode->gen_pq_prob && !dsa_cap_mode->gen_pq_prov) {
            return ACVP_MISSING_ARG;
        }

        json_object_set_value(new_cap_obj, "gGen", json_value_init_array());
        temp_arr = json_object_get_array(new_cap_obj, "gGen");
        if (dsa_cap_mode->gen_g_unv) {
            json_array_append_string(temp_arr, "unverifiable");
        }
        if (dsa_cap_mode->gen_g_can) {
            json_array_append_string(temp_arr, "canonical");
        }
        if (!dsa_cap_mode->gen_g_unv && !dsa_cap_mode->gen_g_can) {
            return ACVP_MISSING_ARG;
        }

        switch (attrs->modulo) {
        case ACVP_DSA_LN2048_224:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 224);
            break;
        case ACVP_DSA_LN2048_256:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        case ACVP_DSA_LN3072_256:
            json_object_set_number(new_cap_obj, "l", 3072);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        default:
            return ACVP_INVALID_ARG;

            break;
        }
        rv = acvp_build_dsa_hashalgs(new_cap_obj, temp_arr, attrs);
        if (rv != ACVP_SUCCESS) {
            return rv;
        }

        attrs = attrs->next;
        json_array_append_value(meth_array, new_cap_val);
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_dsa_pqgver_register(JSON_Array *meth_array,
                                                  ACVP_CAPS_LIST *cap_entry) {
    ACVP_RESULT result = ACVP_SUCCESS;
    ACVP_DSA_ATTRS *attrs = NULL;
    ACVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    JSON_Array *temp_arr = NULL;
    JSON_Value *new_cap_val = NULL;
    JSON_Object *new_cap_obj = NULL;

    dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[ACVP_DSA_MODE_PQGVER - 1];
    attrs = dsa_cap_mode->dsa_attrs;

    while (attrs) {
        new_cap_val = json_value_init_object();
        new_cap_obj = json_value_get_object(new_cap_val);

        json_object_set_value(new_cap_obj, "pqGen", json_value_init_array());
        temp_arr = json_object_get_array(new_cap_obj, "pqGen");
        if (dsa_cap_mode->gen_pq_prob) {
            json_array_append_string(temp_arr, "probable");
        }
        if (dsa_cap_mode->gen_pq_prov) {
            json_array_append_string(temp_arr, "provable");
        }
        if (!dsa_cap_mode->gen_pq_prob && !dsa_cap_mode->gen_pq_prov) {
            return ACVP_MISSING_ARG;
        }

        json_object_set_value(new_cap_obj, "gGen", json_value_init_array());
        temp_arr = json_object_get_array(new_cap_obj, "gGen");
        if (dsa_cap_mode->gen_g_unv) {
            json_array_append_string(temp_arr, "unverifiable");
        }
        if (dsa_cap_mode->gen_g_can) {
            json_array_append_string(temp_arr, "canonical");
        }
        if (!dsa_cap_mode->gen_g_unv && !dsa_cap_mode->gen_g_can) {
            return ACVP_MISSING_ARG;
        }

        switch (attrs->modulo) {
        case ACVP_DSA_LN2048_224:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 224);
            break;
        case ACVP_DSA_LN2048_256:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        case ACVP_DSA_LN3072_256:
            json_object_set_number(new_cap_obj, "l", 3072);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        default:
            break;
        }
        result = acvp_build_dsa_hashalgs(new_cap_obj, temp_arr, attrs);
        if (result != ACVP_SUCCESS) {
            return result;
        }

        attrs = attrs->next;
        json_array_append_value(meth_array, new_cap_val);
    }

    return result;
}

static ACVP_RESULT acvp_build_dsa_keygen_register(JSON_Array *meth_array,
                                                  ACVP_CAPS_LIST *cap_entry) {
    ACVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    ACVP_DSA_ATTRS *attrs = NULL;
    JSON_Value *ln_val = NULL;
    JSON_Object *ln_obj = NULL;

    dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[ACVP_DSA_MODE_KEYGEN - 1];
    attrs = dsa_cap_mode->dsa_attrs;

    while (attrs) {
        switch (attrs->modulo) {
        case ACVP_DSA_LN2048_224:
            ln_val = json_value_init_object();
            ln_obj = json_value_get_object(ln_val);
            json_object_set_number(ln_obj, "l", 2048);
            json_object_set_number(ln_obj, "n", 224);
            json_array_append_value(meth_array, ln_val);
            break;
        case ACVP_DSA_LN2048_256:
            ln_val = json_value_init_object();
            ln_obj = json_value_get_object(ln_val);
            json_object_set_number(ln_obj, "l", 2048);
            json_object_set_number(ln_obj, "n", 256);
            json_array_append_value(meth_array, ln_val);
            break;
        case ACVP_DSA_LN3072_256:
            ln_val = json_value_init_object();
            ln_obj = json_value_get_object(ln_val);
            json_object_set_number(ln_obj, "l", 3072);
            json_object_set_number(ln_obj, "n", 256);
            json_array_append_value(meth_array, ln_val);
            break;
        default:
            break;
        }
        attrs = attrs->next;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_dsa_siggen_register(JSON_Array *meth_array,
                                                  ACVP_CAPS_LIST *cap_entry) {
    ACVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    ACVP_RESULT rv;
    ACVP_DSA_ATTRS *attrs = NULL;
    JSON_Value *new_cap_val = NULL;
    JSON_Object *new_cap_obj = NULL;

    dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[ACVP_DSA_MODE_SIGGEN - 1];
    attrs = dsa_cap_mode->dsa_attrs;

    while (attrs) {
        new_cap_val = json_value_init_object();
        new_cap_obj = json_value_get_object(new_cap_val);

        switch (attrs->modulo) {
        case ACVP_DSA_LN2048_224:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 224);
            break;
        case ACVP_DSA_LN2048_256:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        case ACVP_DSA_LN3072_256:
            json_object_set_number(new_cap_obj, "l", 3072);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        default:
            break;
        }
        rv = acvp_build_dsa_hashalgs(new_cap_obj, meth_array, attrs);
        if (rv != ACVP_SUCCESS) {
            return rv;
        }
        attrs = attrs->next;
        json_array_append_value(meth_array, new_cap_val);
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_dsa_sigver_register(JSON_Array *meth_array,
                                                  ACVP_CAPS_LIST *cap_entry) {
    ACVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    ACVP_RESULT rv;
    ACVP_DSA_ATTRS *attrs = NULL;
    JSON_Value *new_cap_val = NULL;
    JSON_Object *new_cap_obj = NULL;

    dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[ACVP_DSA_MODE_SIGVER - 1];
    attrs = dsa_cap_mode->dsa_attrs;

    while (attrs) {
        new_cap_val = json_value_init_object();
        new_cap_obj = json_value_get_object(new_cap_val);

        switch (attrs->modulo) {
        case ACVP_DSA_LN2048_224:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 224);
            break;
        case ACVP_DSA_LN2048_256:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        case ACVP_DSA_LN3072_256:
            json_object_set_number(new_cap_obj, "l", 3072);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        default:
            break;
        }
        rv = acvp_build_dsa_hashalgs(new_cap_obj, meth_array, attrs);
        if (rv != ACVP_SUCCESS) {
            return rv;
        }

        attrs = attrs->next;
        json_array_append_value(meth_array, new_cap_val);
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_dsa_register_cap(JSON_Object *cap_obj,
                                               ACVP_CAPS_LIST *cap_entry,
                                               ACVP_DSA_MODE mode) {
    ACVP_RESULT result;
    JSON_Array *meth_array = NULL;

    if (!cap_entry->cap.dsa_cap) {
        return ACVP_NO_CAP;
    }
    json_object_set_string(cap_obj, "algorithm", "DSA");

    switch (mode) {
    case ACVP_DSA_MODE_PQGGEN:
        json_object_set_string(cap_obj, "mode", "pqgGen");
        break;
    case ACVP_DSA_MODE_PQGVER:
        json_object_set_string(cap_obj, "mode", "pqgVer");
        break;
    case ACVP_DSA_MODE_KEYGEN:
        json_object_set_string(cap_obj, "mode", "keyGen");
        break;
    case ACVP_DSA_MODE_SIGGEN:
        json_object_set_string(cap_obj, "mode", "sigGen");
        break;
    case ACVP_DSA_MODE_SIGVER:
        json_object_set_string(cap_obj, "mode", "sigVer");
        break;
    default:
        return ACVP_INVALID_ARG;
    }
    result = acvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != ACVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    meth_array = json_object_get_array(cap_obj, "capabilities");

    switch (mode) {
    case ACVP_DSA_MODE_PQGGEN:
        if (cap_entry->cap.dsa_cap->dsa_cap_mode[mode - 1].defined) {
            result = acvp_build_dsa_pqggen_register(meth_array, cap_entry);
            if (result != ACVP_SUCCESS) { return result; }
        }
        break;
    case ACVP_DSA_MODE_PQGVER:
        if (cap_entry->cap.dsa_cap->dsa_cap_mode[mode - 1].defined) {
            result = acvp_build_dsa_pqgver_register(meth_array, cap_entry);
            if (result != ACVP_SUCCESS) { return result; }
        }
        break;
    case ACVP_DSA_MODE_KEYGEN:
        if (cap_entry->cap.dsa_cap->dsa_cap_mode[mode - 1].defined) {
            result = acvp_build_dsa_keygen_register(meth_array, cap_entry);
            if (result != ACVP_SUCCESS) { return result; }
        }
        break;
    case ACVP_DSA_MODE_SIGGEN:
        if (cap_entry->cap.dsa_cap->dsa_cap_mode[mode - 1].defined) {
            result = acvp_build_dsa_siggen_register(meth_array, cap_entry);
            if (result != ACVP_SUCCESS) { return result; }
        }
        break;
    case ACVP_DSA_MODE_SIGVER:
        if (cap_entry->cap.dsa_cap->dsa_cap_mode[mode - 1].defined) {
            result = acvp_build_dsa_sigver_register(meth_array, cap_entry);
            if (result != ACVP_SUCCESS) { return result; }
        }
        break;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_lookup_kas_ecc_prereqVals(JSON_Object *cap_obj,
                                                  ACVP_KAS_ECC_CAP_MODE *kas_ecc_mode) {
    JSON_Array *prereq_array = NULL;
    ACVP_PREREQ_LIST *prereq_vals, *next_pre_req;
    ACVP_PREREQ_ALG_VAL *pre_req;
    char *alg_str;
    int i;

    if (!kas_ecc_mode) { return ACVP_INVALID_ARG; }

    /*
     * Init json array
     */
    json_object_set_value(cap_obj, ACVP_PREREQ_OBJ_STR, json_value_init_array());
    prereq_array = json_object_get_array(cap_obj, ACVP_PREREQ_OBJ_STR);

    /*
     * return OK if nothing present
     */
    prereq_vals = kas_ecc_mode->prereq_vals;
    if (!prereq_vals) {
        return ACVP_SUCCESS;
    }


    while (prereq_vals) {
        JSON_Value *val = NULL;
        JSON_Object *obj = NULL;
        val = json_value_init_object();
        obj = json_value_get_object(val);
        pre_req = &prereq_vals->prereq_alg_val;

        for (i = 0; i < ACVP_NUM_PREREQS; i++) {
            if (acvp_prereqs_tbl[i].alg == pre_req->alg) {
                alg_str = acvp_prereqs_tbl[i].name;
                json_object_set_string(obj, "algorithm", alg_str);
                json_object_set_string(obj, ACVP_PREREQ_VAL_STR, pre_req->val);
                break;
            }
        }

        json_array_append_value(prereq_array, val);
        next_pre_req = prereq_vals->next;
        prereq_vals = next_pre_req;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kas_ecc_register_cap(ACVP_CTX *ctx,
                                                   JSON_Object *cap_obj,
                                                   ACVP_CAPS_LIST *cap_entry,
                                                   int i) {
    JSON_Array *temp_arr = NULL;
    ACVP_RESULT result;
    ACVP_KAS_ECC_CAP_MODE *kas_ecc_mode;
    ACVP_KAS_ECC_CAP *kas_ecc_cap;
    ACVP_PARAM_LIST *current_func;
    ACVP_PARAM_LIST *current_curve;
    JSON_Value *func_val = NULL;
    JSON_Object *func_obj = NULL;
    JSON_Value *sch_val = NULL;
    JSON_Object *sch_obj = NULL;
    JSON_Value *kdf_val = NULL;
    JSON_Object *kdf_obj = NULL;
    JSON_Value *pset_val = NULL;
    JSON_Object *pset_obj = NULL;
    JSON_Value *set_val = NULL;
    JSON_Object *set_obj = NULL;
    ACVP_KAS_ECC_SCHEME *current_scheme;
    ACVP_KAS_ECC_PSET *current_pset;
    ACVP_PARAM_LIST *sha, *role;
    ACVP_KAS_ECC_SET kdf;
    ACVP_KAS_ECC_SCHEMES scheme;
    int set;

    kas_ecc_cap = cap_entry->cap.kas_ecc_cap;
    if (!kas_ecc_cap) {
        return ACVP_NO_CAP;
    }
    kas_ecc_mode = &kas_ecc_cap->kas_ecc_mode[i - 1];
    if (kas_ecc_mode->prereq_vals) {
        json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
        switch (kas_ecc_mode->cap_mode) {
        case ACVP_KAS_ECC_MODE_CDH:
            json_object_set_string(cap_obj, "mode", "CDH-Component");
            break;
        case ACVP_KAS_ECC_MODE_COMPONENT:
            json_object_set_string(cap_obj, "mode", "Component");
            break;
        case ACVP_KAS_ECC_MODE_NOCOMP:
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-ECC mode %d", kas_ecc_mode->cap_mode);
            return ACVP_INVALID_ARG;

            break;
        }
        result = acvp_lookup_kas_ecc_prereqVals(cap_obj, kas_ecc_mode);
        if (result != ACVP_SUCCESS) { return result; }
        switch (i) {
        case ACVP_KAS_ECC_MODE_CDH:

            json_object_set_value(cap_obj, "function", json_value_init_array());
            temp_arr = json_object_get_array(cap_obj, "function");
            current_func = kas_ecc_mode->function;
            while (current_func) {
                switch (current_func->param) {
                case ACVP_KAS_ECC_FUNC_PARTIAL:
                    json_array_append_string(temp_arr, "partialVal");
                    break;
                case ACVP_KAS_ECC_FUNC_DPGEN:
                    json_array_append_string(temp_arr, "dpGen");
                    break;
                case ACVP_KAS_ECC_FUNC_DPVAL:
                    json_array_append_string(temp_arr, "dpVal");
                    break;
                case ACVP_KAS_ECC_FUNC_KEYPAIR:
                    json_array_append_string(temp_arr, "keyPairGen");
                    break;
                case ACVP_KAS_ECC_FUNC_KEYREGEN:
                    json_array_append_string(temp_arr, "keyRegen");
                    break;
                case ACVP_KAS_ECC_FUNC_FULL:
                    json_array_append_string(temp_arr, "fullVal");
                    break;
                default:
                    ACVP_LOG_ERR("\nUnsupported KAS-ECC function %d", current_func->param);
                    return ACVP_INVALID_ARG;

                    break;
                }
                current_func = current_func->next;
            }
            json_object_set_value(cap_obj, "curve", json_value_init_array());
            temp_arr = json_object_get_array(cap_obj, "curve");
            current_curve = kas_ecc_mode->curve;
            while (current_curve) {
                char *curve_str = NULL;

                curve_str = acvp_lookup_ec_curve_name(kas_ecc_cap->cipher,
                                                      current_curve->param);
                if (!curve_str) {
                    ACVP_LOG_ERR("\nUnsupported curve %d",
                                 current_curve->param);
                    return ACVP_INVALID_ARG;
                }

                json_array_append_string(temp_arr, curve_str);

                current_curve = current_curve->next;
            }
            break;
        case ACVP_KAS_ECC_MODE_COMPONENT:
            json_object_set_value(cap_obj, "function", json_value_init_array());
            temp_arr = json_object_get_array(cap_obj, "function");
            current_func = kas_ecc_mode->function;
            while (current_func) {
                switch (current_func->param) {
                case ACVP_KAS_ECC_FUNC_PARTIAL:
                    json_array_append_string(temp_arr, "partialVal");
                    break;
                case ACVP_KAS_ECC_FUNC_DPGEN:
                case ACVP_KAS_ECC_FUNC_DPVAL:
                case ACVP_KAS_ECC_FUNC_KEYPAIR:
                case ACVP_KAS_ECC_FUNC_KEYREGEN:
                case ACVP_KAS_ECC_FUNC_FULL:
                default:
                    ACVP_LOG_ERR("\nUnsupported KAS-ECC function %d", current_func->param);
                    return ACVP_INVALID_ARG;

                    break;
                }
                current_func = current_func->next;
            }

            sch_val = json_value_init_object();
            sch_obj = json_value_get_object(sch_val);

            func_val = json_value_init_object();
            func_obj = json_value_get_object(func_val);

            kdf_val = json_value_init_object();
            kdf_obj = json_value_get_object(kdf_val);

            pset_val = json_value_init_object();
            pset_obj = json_value_get_object(pset_val);

            current_scheme = kas_ecc_mode->scheme;
            while (current_scheme) {
                kdf = current_scheme->kdf;
                scheme = current_scheme->scheme;
                current_pset = current_scheme->pset;
                while (current_pset) {
                    char *curve_str = NULL;

                    set_val = json_value_init_object();
                    set_obj = json_value_get_object(set_val);

                    set = current_pset->set;

                    curve_str = acvp_lookup_ec_curve_name(kas_ecc_cap->cipher,
                                                          current_pset->curve);
                    if (!curve_str) {
                        ACVP_LOG_ERR("\nUnsupported curve %d",
                                     current_pset->curve);
                        return ACVP_INVALID_ARG;
                    }
                    json_object_set_string(set_obj, "curve", curve_str);

                    json_object_set_value(set_obj, "hashAlg", json_value_init_array());
                    temp_arr = json_object_get_array(set_obj, "hashAlg");
                    sha = current_pset->sha;
                    while (sha) {
                        switch (sha->param) {
                        case ACVP_SHA224:
                            json_array_append_string(temp_arr, "SHA2-224");
                            break;
                        case ACVP_SHA256:
                            json_array_append_string(temp_arr, "SHA2-256");
                            break;
                        case ACVP_SHA384:
                            json_array_append_string(temp_arr, "SHA2-384");
                            break;
                        case ACVP_SHA512:
                            json_array_append_string(temp_arr, "SHA2-512");
                            break;
                        default:
                            ACVP_LOG_ERR("\nUnsupported KAS-ECC sha param %d", sha->param);
                            return ACVP_INVALID_ARG;

                            break;
                        }
                        sha = sha->next;
                    }
                    switch (set) {
                    case ACVP_KAS_ECC_EB:
                        json_object_set_value(pset_obj, "eb", set_val);
                        break;
                    case ACVP_KAS_ECC_EC:
                        json_object_set_value(pset_obj, "ec", set_val);
                        break;
                    case ACVP_KAS_ECC_ED:
                        json_object_set_value(pset_obj, "ed", set_val);
                        break;
                    case ACVP_KAS_ECC_EE:
                        json_object_set_value(pset_obj, "ee", set_val);
                        break;
                    default:
                        ACVP_LOG_ERR("\nUnsupported KAS-ECC set %d", set);
                        return ACVP_INVALID_ARG;

                        break;
                    }
                    current_pset = current_pset->next;
                }
                json_object_set_value(kdf_obj, "parameterSet", pset_val);

                json_object_set_value(func_obj, "kasRole", json_value_init_array());
                temp_arr = json_object_get_array(func_obj, "kasRole");
                role = current_scheme->role;
                while (role) {
                    switch (role->param) {
                    case ACVP_KAS_ECC_ROLE_INITIATOR:
                        json_array_append_string(temp_arr, "initiator");
                        break;
                    case ACVP_KAS_ECC_ROLE_RESPONDER:
                        json_array_append_string(temp_arr, "responder");
                        break;
                    default:
                        ACVP_LOG_ERR("\nUnsupported KAS-ECC role %d", role->param);
                        return ACVP_INVALID_ARG;

                        break;
                    }
                    role = role->next;
                }
                switch (kdf) {
                case ACVP_KAS_ECC_NOKDFNOKC:
                    json_object_set_value(func_obj, "noKdfNoKc", kdf_val);
                    break;
                case ACVP_KAS_ECC_KDFNOKC:
                    json_object_set_value(func_obj, "kdfNoKc", kdf_val);
                    break;
                case ACVP_KAS_ECC_KDFKC:
                    json_object_set_value(func_obj, "kdfKc", kdf_val);
                    break;
                default:
                    ACVP_LOG_ERR("\nUnsupported KAS-ECC kdf %d", kdf);
                    return ACVP_INVALID_ARG;

                    break;
                }
                switch (scheme) {
                case ACVP_KAS_ECC_EPHEMERAL_UNIFIED:
                    json_object_set_value(sch_obj, "ephemeralUnified", func_val);
                    break;
                case ACVP_KAS_ECC_FULL_MQV:
                case ACVP_KAS_ECC_FULL_UNIFIED:
                case ACVP_KAS_ECC_ONEPASS_DH:
                case ACVP_KAS_ECC_ONEPASS_MQV:
                case ACVP_KAS_ECC_ONEPASS_UNIFIED:
                case ACVP_KAS_ECC_STATIC_UNIFIED:
                default:
                    ACVP_LOG_ERR("\nUnsupported KAS-ECC scheme %d", scheme);
                    return ACVP_INVALID_ARG;

                    break;
                }
                json_object_set_value(cap_obj, "scheme", sch_val);
                current_scheme = current_scheme->next;
            }
            break;
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-ECC mode %d", i);
            return ACVP_INVALID_ARG;

            break;
        }
    } else {
        return ACVP_MISSING_ARG;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_lookup_kas_ffc_prereqVals(JSON_Object *cap_obj,
                                                  ACVP_KAS_FFC_CAP_MODE *kas_ffc_mode) {
    JSON_Array *prereq_array = NULL;
    ACVP_PREREQ_LIST *prereq_vals, *next_pre_req;
    ACVP_PREREQ_ALG_VAL *pre_req;
    char *alg_str;
    int i;

    if (!kas_ffc_mode) { return ACVP_INVALID_ARG; }

    /*
     * Init json array
     */
    json_object_set_value(cap_obj, ACVP_PREREQ_OBJ_STR, json_value_init_array());
    prereq_array = json_object_get_array(cap_obj, ACVP_PREREQ_OBJ_STR);

    /*
     * return OK if nothing present
     */
    prereq_vals = kas_ffc_mode->prereq_vals;
    if (!prereq_vals) {
        return ACVP_SUCCESS;
    }


    while (prereq_vals) {
        JSON_Value *val = NULL;
        JSON_Object *obj = NULL;
        val = json_value_init_object();
        obj = json_value_get_object(val);
        pre_req = &prereq_vals->prereq_alg_val;

        for (i = 0; i < ACVP_NUM_PREREQS; i++) {
            if (acvp_prereqs_tbl[i].alg == pre_req->alg) {
                alg_str = acvp_prereqs_tbl[i].name;
                json_object_set_string(obj, "algorithm", alg_str);
                json_object_set_string(obj, ACVP_PREREQ_VAL_STR, pre_req->val);
                break;
            }
        }

        json_array_append_value(prereq_array, val);
        next_pre_req = prereq_vals->next;
        prereq_vals = next_pre_req;
    }
    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_build_kas_ffc_register_cap(ACVP_CTX *ctx,
                                                   JSON_Object *cap_obj,
                                                   ACVP_CAPS_LIST *cap_entry,
                                                   int i) {
    JSON_Array *temp_arr = NULL;
    ACVP_RESULT result;
    ACVP_KAS_FFC_CAP_MODE *kas_ffc_mode;
    ACVP_KAS_FFC_CAP *kas_ffc_cap;
    ACVP_PARAM_LIST *current_func;
    JSON_Value *func_val = NULL;
    JSON_Object *func_obj = NULL;
    JSON_Value *sch_val = NULL;
    JSON_Object *sch_obj = NULL;
    JSON_Value *kdf_val = NULL;
    JSON_Object *kdf_obj = NULL;
    JSON_Value *pset_val = NULL;
    JSON_Object *pset_obj = NULL;
    JSON_Value *set_val = NULL;
    JSON_Object *set_obj = NULL;
    ACVP_KAS_FFC_SCHEME *current_scheme;
    ACVP_KAS_FFC_PSET *current_pset;
    ACVP_PARAM_LIST *sha, *role;
    ACVP_KAS_FFC_SET kdf;
    ACVP_KAS_FFC_SCHEMES scheme;
    int set;

    kas_ffc_cap = cap_entry->cap.kas_ffc_cap;
    if (!kas_ffc_cap) {
        return ACVP_NO_CAP;
    }
    kas_ffc_mode = &kas_ffc_cap->kas_ffc_mode[i - 1];
    if (kas_ffc_mode->prereq_vals) {
        json_object_set_string(cap_obj, "algorithm", acvp_lookup_cipher_name(cap_entry->cipher));
        switch (kas_ffc_mode->cap_mode) {
        case ACVP_KAS_FFC_MODE_COMPONENT:
            json_object_set_string(cap_obj, "mode", "Component");
            break;
        case ACVP_KAS_FFC_MODE_NOCOMP:
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-FFC mode %d", kas_ffc_mode->cap_mode);
            return ACVP_INVALID_ARG;

            break;
        }
        result = acvp_lookup_kas_ffc_prereqVals(cap_obj, kas_ffc_mode);
        if (result != ACVP_SUCCESS) { return result; }
        switch (i) {
        case ACVP_KAS_FFC_MODE_COMPONENT:
            json_object_set_value(cap_obj, "function", json_value_init_array());
            temp_arr = json_object_get_array(cap_obj, "function");
            current_func = kas_ffc_mode->function;
            while (current_func) {
                switch (current_func->param) {
                case ACVP_KAS_FFC_FUNC_DPGEN:
                    json_array_append_string(temp_arr, "dpGen");
                    break;
                case ACVP_KAS_FFC_FUNC_DPVAL:
                    json_array_append_string(temp_arr, "dpVal");
                    break;
                case ACVP_KAS_FFC_FUNC_KEYPAIR:
                    json_array_append_string(temp_arr, "keyPairGen");
                    break;
                case ACVP_KAS_FFC_FUNC_KEYREGEN:
                    json_array_append_string(temp_arr, "keyRegen");
                    break;
                case ACVP_KAS_FFC_FUNC_FULL:
                    json_array_append_string(temp_arr, "fullVal");
                    break;
                default:
                    ACVP_LOG_ERR("\nUnsupported KAS-FFC function %d", current_func->param);
                    return ACVP_INVALID_ARG;

                    break;
                }
                current_func = current_func->next;
            }

            sch_val = json_value_init_object();
            sch_obj = json_value_get_object(sch_val);

            func_val = json_value_init_object();
            func_obj = json_value_get_object(func_val);

            kdf_val = json_value_init_object();
            kdf_obj = json_value_get_object(kdf_val);

            pset_val = json_value_init_object();
            pset_obj = json_value_get_object(pset_val);

            current_scheme = kas_ffc_mode->scheme;
            while (current_scheme) {
                kdf = current_scheme->kdf;
                scheme = current_scheme->scheme;
                current_pset = current_scheme->pset;
                while (current_pset) {
                    set_val = json_value_init_object();
                    set_obj = json_value_get_object(set_val);

                    set = current_pset->set;

                    json_object_set_value(set_obj, "hashAlg", json_value_init_array());
                    temp_arr = json_object_get_array(set_obj, "hashAlg");
                    sha = current_pset->sha;
                    while (sha) {
                        switch (sha->param) {
                        case ACVP_SHA224:
                            json_array_append_string(temp_arr, "SHA2-224");
                            break;
                        case ACVP_SHA256:
                            json_array_append_string(temp_arr, "SHA2-256");
                            break;
                        case ACVP_SHA384:
                            json_array_append_string(temp_arr, "SHA2-384");
                            break;
                        case ACVP_SHA512:
                            json_array_append_string(temp_arr, "SHA2-512");
                            break;
                        default:
                            ACVP_LOG_ERR("\nUnsupported KAS-FFC sha param %d", sha->param);
                            return ACVP_INVALID_ARG;

                            break;
                        }
                        sha = sha->next;
                    }
                    switch (set) {
                    case ACVP_KAS_FFC_FB:
                        json_object_set_value(pset_obj, "fb", set_val);
                        break;
                    case ACVP_KAS_FFC_FC:
                        json_object_set_value(pset_obj, "fc", set_val);
                        break;
                    default:
                        ACVP_LOG_ERR("\nUnsupported KAS-FFC set %d", set);
                        return ACVP_INVALID_ARG;

                        break;
                    }
                    current_pset = current_pset->next;
                }
                json_object_set_value(kdf_obj, "parameterSet", pset_val);

                json_object_set_value(func_obj, "kasRole", json_value_init_array());
                temp_arr = json_object_get_array(func_obj, "kasRole");
                role = current_scheme->role;
                while (role) {
                    switch (role->param) {
                    case ACVP_KAS_FFC_ROLE_INITIATOR:
                        json_array_append_string(temp_arr, "initiator");
                        break;
                    case ACVP_KAS_FFC_ROLE_RESPONDER:
                        json_array_append_string(temp_arr, "responder");
                        break;
                    default:
                        ACVP_LOG_ERR("\nUnsupported KAS-FFC role %d", role->param);
                        return ACVP_INVALID_ARG;

                        break;
                    }
                    role = role->next;
                }
                switch (kdf) {
                case ACVP_KAS_FFC_NOKDFNOKC:
                    json_object_set_value(func_obj, "noKdfNoKc", kdf_val);
                    break;
                case ACVP_KAS_FFC_KDFNOKC:
                    json_object_set_value(func_obj, "kdfNoKc", kdf_val);
                    break;
                case ACVP_KAS_FFC_KDFKC:
                    json_object_set_value(func_obj, "kdfKc", kdf_val);
                    break;
                default:
                    ACVP_LOG_ERR("\nUnsupported KAS-FFC kdf %d", kdf);
                    return ACVP_INVALID_ARG;

                    break;
                }
                switch (scheme) {
                case ACVP_KAS_FFC_DH_EPHEMERAL:
                    json_object_set_value(sch_obj, "dhEphem", func_val);
                    break;
                case ACVP_KAS_FFC_FULL_MQV1:
                case ACVP_KAS_FFC_FULL_MQV2:
                case ACVP_KAS_FFC_DH_HYBRID1:
                case ACVP_KAS_FFC_DH_HYBRID_ONEFLOW:
                case ACVP_KAS_FFC_DH_ONEFLOW:
                case ACVP_KAS_FFC_DH_STATIC:
                default:
                    ACVP_LOG_ERR("\nUnsupported KAS-FFC scheme %d", scheme);
                    return ACVP_INVALID_ARG;

                    break;
                }
                json_object_set_value(cap_obj, "scheme", sch_val);
                current_scheme = current_scheme->next;
            }
            break;
        default:
            ACVP_LOG_ERR("\nUnsupported KAS-FFC mode %d", i);
            return ACVP_INVALID_ARG;

            break;
        }
    } else {
        return ACVP_MISSING_ARG;
    }
    return ACVP_SUCCESS;
}

/*
 * This function builds the JSON message to register an OE dependency
 * with the validating server
 */
ACVP_RESULT acvp_build_dependency(ACVP_DEPENDENCY_LIST *dep, char **reg) {
    JSON_Value *reg_arry_val = NULL;
    JSON_Value *ver_val = NULL;
    JSON_Object *ver_obj = NULL;
    ACVP_KV_LIST *kv_list;
    JSON_Array *reg_arry = NULL;

    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;

    if (!dep) {
        return ACVP_MISSING_ARG;
    }

    /*
     * Start the registration array
     */
    reg_arry_val = json_value_init_array();
    reg_arry = json_array((const JSON_Value *)reg_arry_val);

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
    json_array_append_value(reg_arry, ver_val);

    val = json_value_init_object();
    obj = json_value_get_object(val);

    kv_list = dep->attrs_list;
    while (kv_list) {
        json_object_set_string(obj, kv_list->key, kv_list->value);
        kv_list = kv_list->next;
    }

    json_array_append_value(reg_arry, val);
    *reg = json_serialize_to_string_pretty(reg_arry_val);
    json_value_free(reg_arry_val);

    return ACVP_SUCCESS;
}

/*
 * This function builds the JSON register message that
 * will be sent to the ACVP server to advertised the crypto
 * capabilities of the module under test.
 */
ACVP_RESULT acvp_build_test_session(ACVP_CTX *ctx, char **reg) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_CAPS_LIST *cap_entry;

    JSON_Value *reg_arry_val = NULL;
    JSON_Value *ver_val = NULL;
    JSON_Object *ver_obj = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;

    JSON_Array *caps_arr = NULL;
    JSON_Value *cap_val = NULL;
    JSON_Object *cap_obj = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for build_test_session");
        return ACVP_NO_CTX;
    }

    /*
     * Start the registration array
     */
    reg_arry_val = json_value_init_array();
    reg_arry = json_array((const JSON_Value *)reg_arry_val);

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
    json_array_append_value(reg_arry, ver_val);

    val = json_value_init_object();
    obj = json_value_get_object(val);

    json_object_set_string(obj, "moduleUrl", ctx->module_url);
    if (ctx->is_sample) {
        json_object_set_boolean(obj, "isSample", 1);
    }
    if (ctx->debug_request) {
        json_object_set_string(obj, "debugRequest", "yes");
    }

    /*
     * Start the capabilities advertisement
     */
    json_object_set_value(obj, "algorithms", json_value_init_array());
    caps_arr = json_object_get_array(obj, "algorithms");

    /*
     * Iterate through all the capabilities the user has enabled
     */
    if (ctx->caps_list) {
        cap_entry = ctx->caps_list;
        while (cap_entry) {
            /*
             * Create a new capability to be advertised in the JSON
             * registration message
             */
            cap_val = json_value_init_object();
            cap_obj = json_value_get_object(cap_val);

            /*
             * Build up the capability JSON based on the cipher type
             */
            switch (cap_entry->cipher) {
            case ACVP_AES_GCM:
            case ACVP_AES_CCM:
            case ACVP_AES_ECB:
            case ACVP_AES_CFB1:
            case ACVP_AES_CFB8:
            case ACVP_AES_CFB128:
            case ACVP_AES_CTR:
            case ACVP_AES_OFB:
            case ACVP_AES_CBC:
            case ACVP_AES_KW:
            case ACVP_AES_KWP:
            case ACVP_AES_XTS:
            case ACVP_TDES_ECB:
            case ACVP_TDES_CBC:
            case ACVP_TDES_CTR:
            case ACVP_TDES_OFB:
            case ACVP_TDES_CFB64:
            case ACVP_TDES_CFB8:
            case ACVP_TDES_CFB1:
            case ACVP_TDES_KW:
                rv = acvp_build_sym_cipher_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_HASH_SHA1:
            case ACVP_HASH_SHA224:
            case ACVP_HASH_SHA256:
            case ACVP_HASH_SHA384:
            case ACVP_HASH_SHA512:
                rv = acvp_build_hash_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_HASHDRBG:
            case ACVP_HMACDRBG:
            case ACVP_CTRDRBG:
                rv = acvp_build_drbg_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_HMAC_SHA1:
            case ACVP_HMAC_SHA2_224:
            case ACVP_HMAC_SHA2_256:
            case ACVP_HMAC_SHA2_384:
            case ACVP_HMAC_SHA2_512:
                rv = acvp_build_hmac_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_CMAC_AES:
            case ACVP_CMAC_TDES:
                rv = acvp_build_cmac_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_DSA_KEYGEN:
                rv = acvp_build_dsa_register_cap(cap_obj, cap_entry, ACVP_DSA_MODE_KEYGEN);
                break;
            case ACVP_DSA_PQGVER:
                rv = acvp_build_dsa_register_cap(cap_obj, cap_entry, ACVP_DSA_MODE_PQGVER);
                break;
            case ACVP_DSA_PQGGEN:
                rv = acvp_build_dsa_register_cap(cap_obj, cap_entry, ACVP_DSA_MODE_PQGGEN);
                break;
            case ACVP_DSA_SIGGEN:
                rv = acvp_build_dsa_register_cap(cap_obj, cap_entry, ACVP_DSA_MODE_SIGGEN);
                break;
            case ACVP_DSA_SIGVER:
                rv = acvp_build_dsa_register_cap(cap_obj, cap_entry, ACVP_DSA_MODE_SIGVER);
                break;
            case ACVP_RSA_KEYGEN:
                rv = acvp_build_rsa_keygen_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_RSA_SIGGEN:
            case ACVP_RSA_SIGVER:
                rv = acvp_build_rsa_sig_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_ECDSA_KEYGEN:
            case ACVP_ECDSA_KEYVER:
            case ACVP_ECDSA_SIGGEN:
            case ACVP_ECDSA_SIGVER:
                rv = acvp_build_ecdsa_register_cap(cap_entry->cipher, cap_obj, cap_entry);
                break;
            case ACVP_KDF135_TLS:
                rv = acvp_build_kdf135_tls_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_KDF135_SNMP:
                rv = acvp_build_kdf135_snmp_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_KDF135_SSH:
                rv = acvp_build_kdf135_ssh_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_KDF135_SRTP:
                rv = acvp_build_kdf135_srtp_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_KDF135_IKEV2:
                rv = acvp_build_kdf135_ikev2_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_KDF135_IKEV1:
                rv = acvp_build_kdf135_ikev1_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_KDF135_X963:
                rv = acvp_build_kdf135_x963_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_KDF108:
                rv = acvp_build_kdf108_register_cap(cap_obj, cap_entry);
                break;
            case ACVP_KAS_ECC_CDH:
                rv = acvp_build_kas_ecc_register_cap(ctx, cap_obj, cap_entry, ACVP_KAS_ECC_MODE_CDH);
                break;
            case ACVP_KAS_ECC_COMP:
                rv = acvp_build_kas_ecc_register_cap(ctx, cap_obj, cap_entry, ACVP_KAS_ECC_MODE_COMPONENT);
                break;
            case ACVP_KAS_ECC_NOCOMP:
                rv = acvp_build_kas_ecc_register_cap(ctx, cap_obj, cap_entry, ACVP_KAS_ECC_MODE_NOCOMP);
                break;
            case ACVP_KAS_FFC_COMP:
                rv = acvp_build_kas_ffc_register_cap(ctx, cap_obj, cap_entry, ACVP_KAS_FFC_MODE_COMPONENT);
                break;
            case ACVP_KAS_FFC_NOCOMP:
                rv = acvp_build_kas_ffc_register_cap(ctx, cap_obj, cap_entry, ACVP_KAS_FFC_MODE_NOCOMP);
                break;
            default:
                ACVP_LOG_ERR("Cap entry not found, %d.", cap_entry->cipher);
                return ACVP_NO_CAP;
            }

            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("failed to build registration for cipher %s (%d)", acvp_lookup_cipher_name(cap_entry->cipher), rv);
                return rv;
            }

            /*
             * Now that we've built up the JSON for this capability,
             * add it to the array of capabilities on the register message.
             */
            json_array_append_value(caps_arr, cap_val);

            /* Advance to next cap entry */
            cap_entry = cap_entry->next;
        }
    } else {
        ACVP_LOG_ERR("No capabilities added to ctx");
        return ACVP_NO_CAP;
    }

    /*
     * Add the entire caps exchange section to the top object
     */
    json_array_append_value(reg_arry, val);
    *reg = json_serialize_to_string_pretty(reg_arry_val);
    json_value_free(reg_arry_val);

    return ACVP_SUCCESS;
}

/*
 * This function builds the JSON message to register an OE with the
 * validating crypto server
 */
ACVP_RESULT acvp_build_oes(ACVP_CTX *ctx, char **reg) {
    JSON_Value *reg_arry_val = NULL;
    JSON_Value *ver_val = NULL;
    JSON_Object *ver_obj = NULL;

    JSON_Array *reg_arry = NULL;

    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    JSON_Array *dep_array_val = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for build_oes");
        return ACVP_NO_CTX;
    }

    /*
     * Start the registration array
     */
    reg_arry_val = json_value_init_array();
    reg_arry = json_array((const JSON_Value *)reg_arry_val);

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
    json_array_append_value(reg_arry, ver_val);

    val = json_value_init_object();
    obj = json_value_get_object(val);

    json_object_set_string(obj, "name", ctx->oe_name);
    json_object_set_value(obj, "dependencyUrls", json_value_init_array());
    dep_array_val = json_object_get_array(obj, "dependencyUrls");

    ACVP_DEPENDENCY_LIST *dependency = ctx->dependency_list;
    while (dependency) {
        json_array_append_string(dep_array_val, dependency->url);
        dependency = dependency->next;
    }

    json_array_append_value(reg_arry, val);
    *reg = json_serialize_to_string_pretty(reg_arry_val);
    json_value_free(reg_arry_val);

    return ACVP_SUCCESS;
}

/*
 * This function builds the JSON message that registers a module with
 * the validating crypto server
 */
ACVP_RESULT acvp_build_modules(ACVP_CTX *ctx, char **reg) {
    JSON_Value *reg_arry_val = NULL;
    JSON_Value *ver_val = NULL;
    JSON_Object *ver_obj = NULL;

    JSON_Array *reg_arry = NULL;

    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for build_modules");
        return ACVP_NO_CTX;
    }

    /*
     * Start the registration array
     */
    reg_arry_val = json_value_init_array();
    reg_arry = json_array((const JSON_Value *)reg_arry_val);

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
    json_array_append_value(reg_arry, ver_val);

    val = json_value_init_object();
    obj = json_value_get_object(val);

    json_object_set_string(obj, "name", ctx->module_name);
    json_object_set_string(obj, "version", ctx->module_version);
    json_object_set_string(obj, "type", ctx->module_type);
    json_object_set_string(obj, "vendorUrl", ctx->vendor_url);
    json_object_set_string(obj, "implementationDescription", ctx->module_desc);

    json_array_append_value(reg_arry, val);
    *reg = json_serialize_to_string_pretty(reg_arry_val);
    json_value_free(reg_arry_val);

    return ACVP_SUCCESS;
}

/*
 * This function builds the JSON message to register a vendor with the
 * validating crypto server
 */
ACVP_RESULT acvp_build_vendors(ACVP_CTX *ctx, char **reg) {
    JSON_Value *reg_arry_val = NULL;
    JSON_Value *ver_val = NULL;
    JSON_Object *ver_obj = NULL;

    JSON_Array *reg_arry = NULL, *contact_array = NULL;

    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;

    /*
     * As of right now, we only support one contact with a name, website,
     * contact name, and contact email
     */
    JSON_Value *contact_val = NULL;
    JSON_Object *contact_obj = NULL;
    JSON_Array *email_array = NULL;

    if (!ctx) {
        ACVP_LOG_ERR("No ctx for build vendor");
        return ACVP_NO_CTX;
    }

    /*
     * Start the registration array
     */
    reg_arry_val = json_value_init_array();
    reg_arry = json_array((const JSON_Value *)reg_arry_val);

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, "acvVersion", ACVP_VERSION);
    json_array_append_value(reg_arry, ver_val);

    val = json_value_init_object();
    obj = json_value_get_object(val);

    json_object_set_string(obj, "name", ctx->vendor_name);
    if (ctx->vendor_website) json_object_set_string(obj, "website", ctx->vendor_website);
    if (ctx->contact_name || ctx->contact_email) {
        json_object_set_value(obj, "contacts", json_value_init_array());
        contact_array = json_object_get_array(obj, "contacts");

        contact_val = json_value_init_object();
        contact_obj = json_value_get_object(contact_val);

        if (ctx->contact_name) json_object_set_string(contact_obj, "name", ctx->contact_name);
        if (ctx->contact_email) {
            json_object_set_value(contact_obj, "emails", json_value_init_array());
            email_array = json_object_get_array(obj, "emails");
            json_array_append_string(email_array, ctx->contact_email);
        }
        json_array_append_value(contact_array, contact_val);
    }
    json_array_append_value(reg_arry, val);

    *reg = json_serialize_to_string_pretty(reg_arry_val);
    json_value_free(reg_arry_val);

    return ACVP_SUCCESS;
}
