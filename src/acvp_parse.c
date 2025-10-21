/** @file */
/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include <limits.h>
#include <math.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"

// Helper function to convert JSON_Value_Type enum to string for error messages
static const char *acvp_json_get_type_name(JSON_Value_Type type) {
    switch(type) {
        case JSONString: return "string";
        case JSONNumber: return "number";
        case JSONBoolean: return "boolean";
        case JSONObject: return "object";
        case JSONArray: return "array";
        case JSONNull: return "null";
        default: return "unknown";
    }
}

// Parse and validate a string field from JSON
ACVP_RESULT acvp_tc_json_get_string(ACVP_CTX *ctx, ACVP_CIPHER alg_id,
                                     JSON_Object *obj, const char *key,
                                     const char **out) {
    const char *val = NULL;
    JSON_Value *json_val = NULL;
    ACVP_RESULT rv = ACVP_INTERNAL_ERR;

    if (!json_object_has_value(obj, key)) {
        ACVP_LOG_ERR("[%s] Server JSON is missing '%s' data",
                     acvp_lookup_cipher_name(alg_id), key);
        rv = ACVP_TC_MISSING_DATA;
        goto err;
    }

    if (!json_object_has_value_of_type(obj, key, JSONString)) {
        json_val = json_object_get_value(obj, key);
        ACVP_LOG_ERR("[%s] Server JSON field '%s' has wrong type (expected %s, got %s)",
                     acvp_lookup_cipher_name(alg_id), key,
                     acvp_json_get_type_name(JSONString),
                     acvp_json_get_type_name(json_value_get_type(json_val)));
        rv = ACVP_TC_INVALID_DATA;
        goto err;
    }

    val = json_object_get_string(obj, key);
    if (!val) {
        ACVP_LOG_ERR("[%s] Server JSON field '%s' returned NULL string",
                     acvp_lookup_cipher_name(alg_id), key);
        rv = ACVP_TC_INVALID_DATA;
        goto err;
    }

    *out = val;
    rv = ACVP_SUCCESS;
err:
    return rv;
}

// Parse and validate an integer field from JSON
ACVP_RESULT acvp_tc_json_get_int(ACVP_CTX *ctx, ACVP_CIPHER alg_id,
                                  JSON_Object *obj, const char *key,
                                  int *out) {
    double num_val = 0;
    JSON_Value *json_val = NULL;
    ACVP_RESULT rv = ACVP_INTERNAL_ERR;

    if (!json_object_has_value(obj, key)) {
        ACVP_LOG_ERR("[%s] Server JSON is missing '%s' data",
                     acvp_lookup_cipher_name(alg_id), key);
        rv = ACVP_TC_MISSING_DATA;
        goto err;
    }

    if (!json_object_has_value_of_type(obj, key, JSONNumber)) {
        json_val = json_object_get_value(obj, key);
        ACVP_LOG_ERR("[%s] Server JSON field '%s' has wrong type (expected %s, got %s)",
                     acvp_lookup_cipher_name(alg_id), key,
                     acvp_json_get_type_name(JSONNumber),
                     acvp_json_get_type_name(json_value_get_type(json_val)));
        rv = ACVP_TC_INVALID_DATA;
        goto err;
    }

    num_val = json_object_get_number(obj, key);

    /*
     * Check if the number is a whole number (no fractional part)
     * Note that this has imperfect precision, but we assume for ACVP purposes
     * that we will never get decimals that are extremely close to an integer.
     */
    if (num_val - floor(num_val) > ACVP_DOUBLE_EPSILON) {
        ACVP_LOG_ERR("[%s] Server JSON field '%s' has decimal (expected integer)",
                     acvp_lookup_cipher_name(alg_id), key);
        rv = ACVP_TC_INVALID_DATA;
        goto err;
    }

    /* Check if the value is within int range */
    if (num_val < (double)INT_MIN || num_val > (double)INT_MAX) {
        ACVP_LOG_ERR("[%s] Server JSON field '%s' value out of range for int",
                     acvp_lookup_cipher_name(alg_id), key);
        rv = ACVP_TC_INVALID_DATA;
        goto err;
    }

    *out = (int)num_val;
    rv = ACVP_SUCCESS;
err:
    return rv;
}

// Parse and validate a boolean field from JSON
ACVP_RESULT acvp_tc_json_get_boolean(ACVP_CTX *ctx, ACVP_CIPHER alg_id,
                                      JSON_Object *obj, const char *key,
                                      int *out) {
    int bool_val = 0;
    JSON_Value *json_val = NULL;
    ACVP_RESULT rv = ACVP_INTERNAL_ERR;

    if (!json_object_has_value(obj, key)) {
        ACVP_LOG_ERR("[%s] Server JSON is missing '%s' data",
                     acvp_lookup_cipher_name(alg_id), key);
        rv = ACVP_TC_MISSING_DATA;
        goto err;
    }

    if (!json_object_has_value_of_type(obj, key, JSONBoolean)) {
        json_val = json_object_get_value(obj, key);
        ACVP_LOG_ERR("[%s] Server JSON field '%s' has wrong type (expected %s, got %s)",
                     acvp_lookup_cipher_name(alg_id), key,
                     acvp_json_get_type_name(JSONBoolean),
                     acvp_json_get_type_name(json_value_get_type(json_val)));
        rv = ACVP_TC_INVALID_DATA;
        goto err;
    }

    bool_val = json_object_get_boolean(obj, key);
    *out = bool_val;
    rv = ACVP_SUCCESS;
err:
    return rv;
}

// Parse and validate an object field from JSON
ACVP_RESULT acvp_tc_json_get_object(ACVP_CTX *ctx, ACVP_CIPHER alg_id,
                                     JSON_Object *obj, const char *key,
                                     JSON_Object **out) {
    JSON_Object *obj_val = NULL;
    JSON_Value *json_val = NULL;
    ACVP_RESULT rv = ACVP_INTERNAL_ERR;

    if (!json_object_has_value(obj, key)) {
        ACVP_LOG_ERR("[%s] Server JSON is missing '%s' data",
                     acvp_lookup_cipher_name(alg_id), key);
        rv = ACVP_TC_MISSING_DATA;
        goto err;
    }

    if (!json_object_has_value_of_type(obj, key, JSONObject)) {
        json_val = json_object_get_value(obj, key);
        ACVP_LOG_ERR("[%s] Server JSON field '%s' has wrong type (expected %s, got %s)",
                     acvp_lookup_cipher_name(alg_id), key,
                     acvp_json_get_type_name(JSONObject),
                     acvp_json_get_type_name(json_value_get_type(json_val)));
        rv = ACVP_TC_INVALID_DATA;
        goto err;
    }

    obj_val = json_object_get_object(obj, key);
    if (!obj_val) {
        ACVP_LOG_ERR("[%s] Server JSON field '%s' returned NULL object",
                     acvp_lookup_cipher_name(alg_id), key);
        rv = ACVP_TC_INVALID_DATA;
        goto err;
    }

    *out = obj_val;
    rv = ACVP_SUCCESS;
err:
    return rv;
}

// Parse and validate an array field from JSON
ACVP_RESULT acvp_tc_json_get_array(ACVP_CTX *ctx, ACVP_CIPHER alg_id,
                                    JSON_Object *obj, const char *key,
                                    JSON_Array **out) {
    JSON_Array *arr_val = NULL;
    JSON_Value *json_val = NULL;
    ACVP_RESULT rv = ACVP_INTERNAL_ERR;

    if (!json_object_has_value(obj, key)) {
        ACVP_LOG_ERR("[%s] Server JSON is missing '%s' data",
                     acvp_lookup_cipher_name(alg_id), key);
        rv = ACVP_TC_MISSING_DATA;
        goto err;
    }

    if (!json_object_has_value_of_type(obj, key, JSONArray)) {
        json_val = json_object_get_value(obj, key);
        ACVP_LOG_ERR("[%s] Server JSON field '%s' has wrong type (expected %s, got %s)",
                     acvp_lookup_cipher_name(alg_id), key,
                     acvp_json_get_type_name(JSONArray),
                     acvp_json_get_type_name(json_value_get_type(json_val)));
        rv = ACVP_TC_INVALID_DATA;
        goto err;
    }

    arr_val = json_object_get_array(obj, key);
    if (!arr_val) {
        ACVP_LOG_ERR("[%s] Server JSON field '%s' returned NULL array",
                     acvp_lookup_cipher_name(alg_id), key);
        rv = ACVP_TC_INVALID_DATA;
        goto err;
    }

    *out = arr_val;
    rv = ACVP_SUCCESS;
err:
    return rv;
}
