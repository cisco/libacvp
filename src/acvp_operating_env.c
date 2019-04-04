/** @file */
/*****************************************************************************
* Copyright (c) 2019, Cisco Systems, Inc.
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

#include <stdlib.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"
#include "safe_lib.h"


static ACVP_RESULT copy_oe_string(char **dest, const char *src) {
    if (src == NULL) {
        return ACVP_MISSING_ARG;
    }
    if (!string_fits(src, ACVP_SESSION_PARAMS_STR_LEN_MAX)) {
        return ACVP_INVALID_ARG;
    }

    if (*dest) { 
        memzero_s(*dest, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1);
    } else {
        *dest = calloc(ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    }
    strcpy_s(*dest, ACVP_SESSION_PARAMS_STR_LEN_MAX + 1, src);

    return ACVP_SUCCESS;
}

static ACVP_DEPENDENCY *find_dependency(ACVP_CTX *ctx,
                                        unsigned int dependency_id) {
    ACVP_DEPENDENCIES *dependencies = NULL;

    if (!ctx) return NULL;

    /* Get a handle on the Dependencies */
    dependencies = &ctx->dependencies;

    if (dependency_id == 0 || dependency_id > dependencies->count) {
        ACVP_LOG_ERR("Invalid 'dependency_id', please make sure you are using a value returned from acvp_dependency_new()");
        return NULL;
    }

    return &dependencies->deps[dependency_id - 1];
}

/**
 * @brief Designate a new Dependency entry for this session.
 *
 * @return non-zero value representing the "dependency_id"
 * @return 0 fail
 */
unsigned int acvp_oe_dependency_new(ACVP_CTX *ctx) {
    ACVP_DEPENDENCIES *dependencies = NULL;

    if (!ctx) return 0;

    /* Get a handle on the Dependencies */
    dependencies = &ctx->dependencies;

    if (dependencies->count == LIBACVP_DEPENDENCIES_MAX) {
        ACVP_LOG_ERR("Libacvp already reached max Dependency capacity (%u)",
                     LIBACVP_DEPENDENCIES_MAX);
        return 0;
    }

    dependencies->count++;
    return dependencies->count; /** Return the array position + 1 */
}

ACVP_RESULT acvp_oe_dependency_add_attribute(ACVP_CTX *ctx,
                                             unsigned int dependency_id,
                                             const char *key,
                                             const char *value) {
    ACVP_DEPENDENCY *dep = NULL;
    ACVP_KV_LIST *kv = NULL;
    ACVP_RESULT rv = 0;

    if (!ctx) return 0;

    if (!(dep = find_dependency(ctx, dependency_id))) {
        return ACVP_INVALID_ARG;
    }

    if (!dep->attribute_list) {
        dep->attribute_list = calloc(1, sizeof(ACVP_KV_LIST));
        kv = dep->attribute_list;
    } else {
        ACVP_KV_LIST *current_attr = dep->attribute_list;
        while (current_attr->next) {
            current_attr = current_attr->next;
        }
        current_attr->next = calloc(1, sizeof(ACVP_KV_LIST));
        kv = current_attr;
    }

    
    copy_oe_string(&kv->key, key);
    if (ACVP_INVALID_ARG == rv) {
        ACVP_LOG_ERR("'key` string too long");
        return rv;
    }
    if (ACVP_MISSING_ARG == rv) {
        ACVP_LOG_ERR("Required parameter 'key` is NULL");
        return rv;
    }

    copy_oe_string(&kv->value, value);
    if (ACVP_INVALID_ARG == rv) {
        ACVP_LOG_ERR("'value` string too long");
        return rv;
    }
    if (ACVP_MISSING_ARG == rv) {
        ACVP_LOG_ERR("Required parameter 'value` is NULL");
        return rv;
    }

    return ACVP_SUCCESS; 
}

/**
 * @brief Designate a new OE entry for this session.
 *
 * @return non-zero value representing the "oe_id"
 * @return 0 fail
 */
unsigned int acvp_oe_oe_new(ACVP_CTX *ctx, const char *name) {
    ACVP_OES *oes = NULL;
    ACVP_OE *new_oe = NULL;
    ACVP_RESULT rv = 0;

    if (!ctx) return 0;

    /* Get a handle on the OES */
    oes = &ctx->oes;

    if (oes->count == LIBACVP_OES_MAX) {
        ACVP_LOG_ERR("Libacvp already reached max OE capacity (%u)",
                     LIBACVP_OES_MAX);
        return 0;
    }

    new_oe = &oes->oe[oes->count];
    oes->count++;

    copy_oe_string(&new_oe->name, name);
    if (ACVP_INVALID_ARG == rv) {
        ACVP_LOG_ERR("'name` string too long");
        return 0;
    }
    if (ACVP_MISSING_ARG == rv) {
        ACVP_LOG_ERR("Required parameter 'name` is NULL");
        return 0;
    }

    return oes->count; /** Return the array position + 1 */
}

static ACVP_OE *find_oe(ACVP_CTX *ctx,
                        unsigned int id) {
    ACVP_OES *oes = NULL;

    if (!ctx) return NULL;

    /* Get a handle on the Vendors */
    oes = &ctx->oes;

    if (id == 0 || id > oes->count) {
        ACVP_LOG_ERR("Invalid 'id', please make sure you are using a value returned from acvp_oe_new()");
        return NULL;
    }

    return &oes->oe[id - 1];
}

ACVP_RESULT acvp_oe_oe_add_dependency(ACVP_CTX *ctx,
                                      unsigned int oe_id,
                                      unsigned int dependency_id) {
    ACVP_OE *oe = NULL;
    ACVP_DEPENDENCY *dep = NULL;

    if (!ctx) return ACVP_NO_CTX;

    /* Get a handle on the selected OE */
    if (!(oe = find_oe(ctx, oe_id))) {
        return ACVP_INVALID_ARG;
    }

    /* Make sure we have a slot to store the dep */
    if (oe->num_deps == LIBACVP_DEPENDENCIES_MAX) {
        ACVP_LOG_ERR("OE corresponding to `oe_id' (%u) already reached max Dependency capacity (%u)",
                     oe_id, LIBACVP_DEPENDENCIES_MAX);
        return ACVP_UNSUPPORTED_OP;
    }

    /* Insert a pointer to the actual Dependency struct location */
    if (!(dep = find_dependency(ctx, dependency_id))) {
        return ACVP_INVALID_ARG;
    }
    oe->deps[oe->num_deps] = dep;
    oe->num_deps++;

    return ACVP_SUCCESS;
}

static ACVP_VENDOR *find_vendor(ACVP_CTX *ctx,
                                unsigned int id) {
    ACVP_VENDORS *vendors = NULL;

    if (!ctx) return NULL;

    /* Get a handle on the Vendors */
    vendors = &ctx->vendors;

    if (id == 0 || id > vendors->count) {
        ACVP_LOG_ERR("Invalid 'id', please make sure you are using a value returned from acvp_vendor_new()");
        return NULL;
    }

    return &vendors->v[id - 1];
}

ACVP_RESULT acvp_oe_vendor_new(ACVP_CTX *ctx, const char *name) {
    ACVP_VENDORS *vendors = NULL;
    ACVP_VENDOR *new_vendor = NULL;
    ACVP_RESULT rv = 0;

    if (!ctx) return ACVP_NO_CTX;

    /* Get handle on vendor fields */
    vendors = &ctx->vendors;

    if (vendors->count == LIBACVP_VENDORS_MAX) {
        ACVP_LOG_ERR("Libacvp already reached max Vendor capacity (%u)",
                     LIBACVP_VENDORS_MAX);
        return 0;
    }

    new_vendor = &vendors->v[vendors->count];
    vendors->count++;

    copy_oe_string(&new_vendor->name, name);
    if (ACVP_INVALID_ARG == rv) {
        ACVP_LOG_ERR("'name` string too long");
        return 0;
    }
    if (ACVP_MISSING_ARG == rv) {
        ACVP_LOG_ERR("Required parameter 'name` is NULL");
        return 0;
    }

    return vendors->count; /** Return the array position + 1 */
}

ACVP_RESULT acvp_oe_vendor_add_address(ACVP_CTX *ctx,
                                       unsigned int id,
                                       const char *street,
                                       const char *locality,
                                       const char *region,
                                       const char *country,
                                       const char *postal_code) {
    ACVP_VENDOR *vendor = NULL;
    ACVP_VENDOR_ADDRESS *address = NULL;
    ACVP_RESULT rv = 0;

    if (!ctx) return ACVP_NO_CTX;

    if (!street && !locality && !region &&
        !country && !postal_code) {
        ACVP_LOG_ERR("Need at least 1 of the parameters to be non-NULL");
        return ACVP_INVALID_ARG;
    }

    vendor = find_vendor(ctx, id);
    if (!vendor) return ACVP_INVALID_ARG;

    if (vendor->addresses.count == VENDOR_ADDRESSES_MAX) {
        ACVP_LOG_ERR("Libacvp already reached max Vendor Address capacity (%u)",
                     VENDOR_ADDRESSES_MAX);
        return ACVP_UNSUPPORTED_OP;
    }

    address = &vendor->addresses.address[vendor->addresses.count];
    vendor->addresses.count++;

    if (street) {
        copy_oe_string(&address->street, street);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'street' string too long");
            return rv;
        }
    }
    if (locality) {
        copy_oe_string(&address->locality, locality);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'locality' string too long");
            return rv;
        }
    }
    if (region) {
        copy_oe_string(&address->region, region);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'region' string too long");
            return rv;
        }
    }
    if (country) {
        copy_oe_string(&address->country, country);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'country' string too long");
            return rv;
        }
    }
    if (postal_code) {
        copy_oe_string(&address->postal_code, postal_code);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'postal_code' string too long");
            return rv;
        }
    }

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_oe_vendor_set_email_website_phone(ACVP_CTX *ctx,
                                                   unsigned int id,
                                                   const char *email,
                                                   const char *website,
                                                   const char *phone) {
    ACVP_VENDOR *vendor = NULL;
    ACVP_RESULT rv = 0;

    if (!ctx) return ACVP_NO_CTX;

    if (!email && !website && !phone) {
        ACVP_LOG_ERR("Need at least 1 of the parameters to be non-NULL");
        return ACVP_INVALID_ARG;
    } 

    vendor = find_vendor(ctx, id);
    if (!vendor) return ACVP_INVALID_ARG;

    if (email) {
        copy_oe_string(&vendor->email, email);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'email' string too long");
            return rv;
        }
    }

    if (website) {
        copy_oe_string(&vendor->website, website);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'website' string too long");
            return rv;
        }
    }

    if (phone) {
        copy_oe_string(&vendor->phone_number, phone);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'phone' string too long");
            return rv;
        }
    }

    return ACVP_SUCCESS;
}

/**
 * @brief Designate a new Person entry for this session.
 *
 * @param name Full-Name of the person
 *
 * @return non-zero value representing the "id"
 * @return 0 fail
 */
unsigned int acvp_oe_person_new(ACVP_CTX *ctx, const char *name) {
    ACVP_PERSONS *persons = NULL;
    ACVP_PERSON *new_person = NULL;
    ACVP_RESULT rv = 0;

    if (!ctx) return 0;

    /* Get a handle on the OES */
    persons = &ctx->persons;

    if (persons->count == LIBACVP_PERSONS_MAX) {
        ACVP_LOG_ERR("Libacvp already reached max PERSON capacity (%u)",
                     LIBACVP_PERSONS_MAX);
        return 0;
    }

    new_person = &persons->person[persons->count];
    persons->count++;

    copy_oe_string(&new_person->full_name, name);
    if (ACVP_INVALID_ARG == rv) {
        ACVP_LOG_ERR("'name` string too long");
        return 0;
    }
    if (ACVP_MISSING_ARG == rv) {
        ACVP_LOG_ERR("Required parameter 'name` is NULL");
        return 0;
    }

    return persons->count; /** Return the array position + 1 */
}

static ACVP_PERSON *find_person(ACVP_CTX *ctx,
                                unsigned int id) {
    ACVP_PERSONS *persons = NULL;

    if (!ctx) return NULL;

    /* Get a handle on the Vendors */
    persons = &ctx->persons;

    if (id == 0 || id > persons->count) {
        ACVP_LOG_ERR("Invalid 'id', please make sure you are using a value returned from acvp_person_new()");
        return NULL;
    }

    return &persons->person[id - 1];
}

ACVP_RESULT acvp_oe_person_add_vendor(ACVP_CTX *ctx,
                                      unsigned int person_id,
                                      unsigned int vendor_id) {
    ACVP_PERSON *person = NULL;
    ACVP_VENDOR *vendor = NULL;

    if (!ctx) return ACVP_NO_CTX;

    /* Get a handle on the selected Person */
    if (!(person = find_person(ctx, person_id))) {
        return ACVP_INVALID_ARG;
    }

    /* Make sure we have a slot to store the Vendor */
    if (person->num_vendors == LIBACVP_VENDORS_MAX) {
        ACVP_LOG_ERR("Person corresponding to `person_id' (%u) already reached max Vendor capacity (%u)",
                     person_id, LIBACVP_VENDORS_MAX);
        return ACVP_UNSUPPORTED_OP;
    }

    /* Insert a pointer to the actual Vendor struct location */
    if (!(vendor = find_vendor(ctx, vendor_id))) {
        return ACVP_INVALID_ARG;
    }
    person->vendor[person->num_vendors] = vendor;
    person->num_vendors++;

    return ACVP_SUCCESS;
}

ACVP_RESULT acvp_oe_person_set_email_phone(ACVP_CTX *ctx,
                                           unsigned int id,
                                           const char *email,
                                           const char *phone) {
    ACVP_PERSON *person = NULL;
    ACVP_RESULT rv = 0;

    if (!ctx) return ACVP_NO_CTX;

    if (!email && !phone) {
        ACVP_LOG_ERR("Need at least 1 of the parameters to be non-NULL");
        return ACVP_INVALID_ARG;
    } 

    person = find_person(ctx, id);
    if (!person) return ACVP_INVALID_ARG;

    if (email) {
        copy_oe_string(&person->email, email);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'email' string too long");
            return rv;
        }
    }

    if (phone) {
        copy_oe_string(&person->phone_number, phone);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'phone' string too long");
            return rv;
        }
    }

    return ACVP_SUCCESS;
}

/**
 * @brief Designate a new Module entry for this session.
 *
 * @param name Name of the module
 *
 * @return non-zero value representing the "id"
 * @return 0 fail
 */
unsigned int acvp_oe_module_new(ACVP_CTX *ctx,
                                unsigned int vendor_id,
                                const char *name) {
    ACVP_MODULES *modules = NULL;
    ACVP_MODULE *new_module = NULL;
    ACVP_VENDOR *vendor = NULL;
    ACVP_RESULT rv = 0;

    if (!ctx) return 0;

    /* Get a handle on the OES */
    modules = &ctx->modules;

    if (modules->count == LIBACVP_MODULES_MAX) {
        ACVP_LOG_ERR("Libacvp already reached max MODULE capacity (%u)",
                     LIBACVP_MODULES_MAX);
        return 0;
    }

    new_module = &modules->module[modules->count];
    modules->count++;

    /* Insert a pointer to the actual Vendor struct location */
    if (!(vendor = find_vendor(ctx, vendor_id))) {
        return ACVP_INVALID_ARG;
    }
    new_module->vendor = vendor;

    copy_oe_string(&new_module->name, name);
    if (ACVP_INVALID_ARG == rv) {
        ACVP_LOG_ERR("'name` string too long");
        return 0;
    }
    if (ACVP_MISSING_ARG == rv) {
        ACVP_LOG_ERR("Required parameter 'name` is NULL");
        return 0;
    }

    return modules->count; /** Return the array position + 1 */
}

static ACVP_MODULE *find_module(ACVP_CTX *ctx,
                                unsigned int id) {
    ACVP_MODULES *modules = NULL;

    if (!ctx) return NULL;

    modules = &ctx->modules;

    if (id == 0 || id > modules->count) {
        ACVP_LOG_ERR("Invalid 'id', please make sure you are using a value returned from acvp_module_new()");
        return NULL;
    }

    return &modules->module[id - 1];
}

ACVP_RESULT acvp_oe_module_set_type_version_desc(ACVP_CTX *ctx,
                                                 unsigned int id,
                                                 const char *type,
                                                 const char *version,
                                                 const char *description) {
    ACVP_MODULE *module = NULL;
    ACVP_RESULT rv = 0;

    if (!ctx) return ACVP_NO_CTX;

    if (!type && !version && !description) {
        ACVP_LOG_ERR("Need at least 1 of the parameters to be non-NULL");
        return ACVP_INVALID_ARG;
    } 

    module = find_module(ctx, id);
    if (!module) return ACVP_INVALID_ARG;

    if (type) {
        copy_oe_string(&module->type, type);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'type' string too long");
            return rv;
        }
    }
    if (version) {
        copy_oe_string(&module->version, version);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'version' string too long");
            return rv;
        }
    }
    if (description) {
        copy_oe_string(&module->description, description);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'description' string too long");
            return rv;
        }
    }

    return ACVP_SUCCESS;
}

/*
 * Verify that the JSON contains the 'approvedUrl' key.
 * Also checks to make sure the value is within
 * accepted string length bounds.
 */
static JSON_Value *acvp_json_validate_identifier(ACVP_CTX *ctx) {
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    const char *url = NULL;

    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return NULL;
    }

    obj = acvp_get_obj_from_rsp(val);
    url = json_object_get_string(obj, "approvedUrl");
    if (!url) {
        ACVP_LOG_ERR("Server JSON 'approvedUrl' missing");
        goto error;
    }

    if (!string_fits(url, ACVP_ATTR_URL_MAX)) {
        ACVP_LOG_ERR("Server JSON 'approvedUrl' string too long");
        goto error;
    }

    /* Success */
    return val;

error:
    if (val) json_value_free(val);
    return NULL;
}

static const char *acvp_json_value_get_identifier(JSON_Value *val) {
    JSON_Object *obj = acvp_get_obj_from_rsp(val);
    return json_object_get_string(obj, "approvedUrl");
}

static ACVP_RESULT acvp_oe_vendor_record_identifier(ACVP_CTX *ctx,
                                                    ACVP_VENDOR *vendor) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *val = NULL;
    const char *url = NULL;

    val = acvp_json_validate_identifier(ctx);
    if (!val) return ACVP_JSON_ERR;

    /* Grab the 'approvedUrl' identifier */
    url = acvp_json_value_get_identifier(val);

    /* Record it */
    vendor->url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
    strcpy_s(vendor->url, ACVP_ATTR_URL_MAX, url);

    json_value_free(val);

    return rv;
}

static ACVP_RESULT acvp_oe_person_record_identifier(ACVP_CTX *ctx,
                                                    ACVP_PERSON *person) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *val = NULL;
    const char *url = NULL;

    val = acvp_json_validate_identifier(ctx);
    if (!val) return ACVP_JSON_ERR;

    /* Grab the 'approvedUrl' identifier */
    url = acvp_json_value_get_identifier(val);

    /* Record it */
    person->url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
    strcpy_s(person->url, ACVP_ATTR_URL_MAX, url);

    json_value_free(val);

    return rv;
}

static ACVP_RESULT acvp_oe_oe_record_identifier(ACVP_CTX *ctx,
                                                ACVP_OE *oe) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *val = NULL;
    const char *url = NULL;

    val = acvp_json_validate_identifier(ctx);
    if (!val) return ACVP_JSON_ERR;

    /* Grab the 'approvedUrl' identifier */
    url = acvp_json_value_get_identifier(val);

    /* Record it */
    oe->url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
    strcpy_s(oe->url, ACVP_ATTR_URL_MAX, url);

    json_value_free(val);

    return rv;
}

static ACVP_RESULT acvp_oe_dependency_record_identifier(ACVP_CTX *ctx,
                                                        ACVP_DEPENDENCY *dep) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *val = NULL;
    const char *url = NULL;

    val = acvp_json_validate_identifier(ctx);
    if (!val) return ACVP_JSON_ERR;

    /* Grab the 'approvedUrl' identifier */
    url = acvp_json_value_get_identifier(val);

    /* Record it */
    dep->url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
    strcpy_s(dep->url, ACVP_ATTR_URL_MAX, url);

    json_value_free(val);

    return rv;
}

/*
 * This routine performs the JSON parsing of the modules response
 * from the ACVP server.  The response should contain a url to
 * access the registered module
 */
static ACVP_RESULT acvp_oe_module_record_identifier(ACVP_CTX *ctx, ACVP_MODULE *module) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Value *val = NULL;
    const char *url = NULL;

    val = acvp_json_validate_identifier(ctx);
    if (!val) return ACVP_JSON_ERR;

    /* Grab the 'approvedUrl' identifier */
    url = acvp_json_value_get_identifier(val);

    /* Record it */
    module->url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
    strcpy_s(module->url, ACVP_ATTR_URL_MAX, url);

    json_value_free(val);

    return rv;
}

ACVP_RESULT acvp_oe_register_oes(ACVP_CTX *ctx) {
    ACVP_RESULT rv = 0;
    char *json_str = NULL;
    int i = 0;

    if (!ctx) return ACVP_NO_CTX;

    for (i = 0; i < ctx->oes.count; i++) {
        ACVP_OE *cur_oe = &ctx->oes.oe[i];
        int json_len = 0;

        rv = acvp_register_build_oe(ctx, cur_oe, &json_str, &json_len);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to build oe message");
            goto end;
        }

        rv = acvp_transport_send_oe_registration(ctx, json_str, json_len);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to send OE registration");
            goto end;
        }
        ACVP_LOG_STATUS("200 OK %s", ctx->curl_buf);

        rv = acvp_oe_oe_record_identifier(ctx, cur_oe);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to parse oe response");
            goto end;
        }

        /* Free for the next iteration */
        if (json_str) json_free_serialized_string(json_str);
        json_str = NULL;
    }

end:
    if (json_str) json_free_serialized_string(json_str);

    return rv;
}

ACVP_RESULT acvp_oe_register_dependencies(ACVP_CTX *ctx) {
    ACVP_RESULT rv = 0;
    char *json_str = NULL;
    int i = 0;

    if (!ctx) return ACVP_NO_CTX;

    for (i = 0; i < ctx->dependencies.count; i++) {
        ACVP_DEPENDENCY *cur_dep = &ctx->dependencies.deps[i];
        int json_len = 0;

        rv = acvp_register_build_dependency(ctx, cur_dep, &json_str, &json_len);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to build Dependency message");
            goto end;
        }

        rv = acvp_transport_send_dependency_registration(ctx, json_str, json_len);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to send Dependency registration");
            goto end;
        }
        ACVP_LOG_STATUS("200 OK %s", ctx->curl_buf);

        rv = acvp_oe_dependency_record_identifier(ctx, cur_dep);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to parse oe response");
            goto end;
        }

        /* Free for the next iteration */
        if (json_str) json_free_serialized_string(json_str);
        json_str = NULL;
    }

end:
    if (json_str) json_free_serialized_string(json_str);

    return rv;
}

ACVP_RESULT acvp_oe_register_vendors(ACVP_CTX *ctx) {
    ACVP_RESULT rv = 0;
    char *json_str = NULL;
    int i = 0;

    if (!ctx) return ACVP_NO_CTX;

    for (i = 0; i < ctx->vendors.count; i++) {
        ACVP_VENDOR *cur_vendor = &ctx->vendors.v[i];
        int json_len = 0;

        rv = acvp_register_build_vendor(ctx, cur_vendor, &json_str, &json_len);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to build Vendor message");
            goto end;
        }

        rv = acvp_transport_send_vendor_registration(ctx, json_str, json_len);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to send Vendor registration");
            goto end;
        }
        ACVP_LOG_STATUS("200 OK %s", ctx->curl_buf);

        rv = acvp_oe_vendor_record_identifier(ctx, cur_vendor);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to parse Vendor response");
            goto end;
        }

        /* Free for the next iteration */
        if (json_str) json_free_serialized_string(json_str);
        json_str = NULL;
    }

end:
    if (json_str) json_free_serialized_string(json_str);

    return rv;
}

ACVP_RESULT acvp_oe_register_persons(ACVP_CTX *ctx) {
    ACVP_RESULT rv = 0;
    char *json_str = NULL;
    int i = 0;

    if (!ctx) return ACVP_NO_CTX;

    for (i = 0; i < ctx->persons.count; i++) {
        ACVP_PERSON *cur_person = &ctx->persons.person[i];
        int json_len = 0;
        int k = 0;
        
        for (k = 0; k < cur_person->num_vendors; k++) {
            ACVP_VENDOR *vendor = find_vendor(ctx, k + 1);

            /*
             * Need to send a message for each Vendor this person belongs to
             */
            rv = acvp_register_build_person(ctx, cur_person, vendor->url, &json_str, &json_len);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Unable to build Person message");
                goto end;
            }

            rv = acvp_transport_send_person_registration(ctx, json_str, json_len);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Person registration failed");
                goto end;
            }
            ACVP_LOG_STATUS("200 OK %s", ctx->curl_buf);

            rv = acvp_oe_person_record_identifier(ctx, cur_person);
            if (rv != ACVP_SUCCESS) {
                ACVP_LOG_ERR("Failed to parse Person response");
                goto end;
            }

            /* Free for the next iteration */
            if (json_str) json_free_serialized_string(json_str);
            json_str = NULL;
        }
    }

end:
    if (json_str) json_free_serialized_string(json_str);

    return rv;
}

ACVP_RESULT acvp_oe_register_modules(ACVP_CTX *ctx) {
    ACVP_RESULT rv = 0;
    char *json_str = NULL;
    int i = 0;

    if (!ctx) return ACVP_NO_CTX;

    for (i = 0; i < ctx->modules.count; i++) {
        ACVP_MODULE *cur_module = &ctx->modules.module[i];
        int json_len = 0;

        rv = acvp_register_build_module(ctx, cur_module, &json_str, &json_len);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to build Module message");
            goto end;
        }

        rv = acvp_transport_send_module_registration(ctx, json_str, json_len);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to send Module registration");
            goto end;
        }
        ACVP_LOG_STATUS("200 OK %s", ctx->curl_buf);

        rv = acvp_oe_module_record_identifier(ctx, cur_module);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Failed to parse Module response");
            goto end;
        }

        /* Free for the next iteration */
        if (json_str) json_free_serialized_string(json_str);
        json_str = NULL;
    }

end:
    if (json_str) json_free_serialized_string(json_str);

    return rv;
}

ACVP_RESULT acvp_oe_register_operating_env(ACVP_CTX *ctx) {
    ACVP_RESULT rv = 0;

    /*
     * Register the Vendors
     */
    rv = acvp_oe_register_vendors(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to register Vendors");
        return rv;
    }

    /*
     * Register the Persons
     */
    rv = acvp_oe_register_persons(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to register Persons");
        return rv;
    }

    /*
     * Register the Modules
     */
    rv = acvp_oe_register_modules(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to register Modules");
        return rv;
    }

    /*
     * Register the Dependencies
     */
    rv = acvp_oe_register_dependencies(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to register Dependencies");
        return rv;
    }

    /*
     * Register the Operating Environments (OES)
     */
    rv = acvp_oe_register_oes(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to register OES");
        return rv;
    }

    return ACVP_SUCCESS;
}

/******************
 * ****************
 * Cleanup functions
 * ****************
 *****************/

static void acvp_dependencies_free(ACVP_CTX *ctx) {
    int i = 0;

    if (ctx->dependencies.count == 0) {
        /* Nothing to free */
        return;
    }

    for (i = 0; i < ctx->dependencies.count; i++) {
        ACVP_DEPENDENCY *dep = &ctx->dependencies.deps[i];
        if (dep->url) free(dep->url);
        acvp_free_kv_list(dep->attribute_list);
    }
}

static void acvp_oes_free(ACVP_CTX *ctx) {
    int i = 0;

    for (i = 0; i < ctx->oes.count; i++) {
        ACVP_OE *oe = &ctx->oes.oe[i];
        if (oe->name) free(oe->name);
        if (oe->url) free(oe->url);
    }
}

static void acvp_vendor_free_addresses(ACVP_VENDOR *vendor) {
    int k = 0;

    for (k = 0; k < vendor->addresses.count; k++) {
        ACVP_VENDOR_ADDRESS *address = &vendor->addresses.address[k];

        if (address->street) free(address->street);
        if (address->locality) free(address->locality);
        if (address->region) free(address->region);
        if (address->country) free(address->country);
        if (address->postal_code) free(address->postal_code);
        if (address->url) free(address->url);
    }
}

static void acvp_vendors_free(ACVP_CTX *ctx) {
    int i = 0;

    for (i = 0; i < ctx->vendors.count; i++) {
        ACVP_VENDOR *vendor = &ctx->vendors.v[i];

        if (vendor->name) free(vendor->name);
        if (vendor->website) free(vendor->website);
        if (vendor->email) free(vendor->email);
        if (vendor->phone_number) free(vendor->phone_number);
        if (vendor->url) free(vendor->url);

        acvp_vendor_free_addresses(vendor);
    }
}

static void acvp_persons_free(ACVP_CTX *ctx) {
    int i = 0;

    for (i = 0; i < ctx->persons.count; i++) {
        ACVP_PERSON *person = &ctx->persons.person[i];

        if (person->full_name) free(person->full_name);
        if (person->email) free(person->email);
        if (person->phone_number) free(person->phone_number);
        if (person->url) free(person->url);
    }
}

static void acvp_modules_free(ACVP_CTX *ctx) {
    int i = 0;

    for (i = 0; i < ctx->modules.count; i++) {
        ACVP_MODULE *module = &ctx->modules.module[i];

        if (module->name) free(module->name);
        if (module->type) free(module->type);
        if (module->version) free(module->version);
        if (module->description) free(module->description);
        if (module->url) free(module->url);
    }
}

void acvp_oe_free_operating_env(ACVP_CTX *ctx) {
    acvp_oes_free(ctx);
    acvp_dependencies_free(ctx);
    acvp_vendors_free(ctx);
    acvp_persons_free(ctx);
    acvp_modules_free(ctx);
}

