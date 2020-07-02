/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"
#include "safe_lib.h"


/* Keeps track of what to use the next Dependency ID */
static unsigned int glb_dependency_id = 1; 
static unsigned int glb_vendor_id = 1; 
static unsigned int glb_module_id = 1; 
static unsigned int glb_oe_id = 1; 

static ACVP_RESULT copy_oe_string(char **dest, const char *src) {
    if (dest == NULL) {
        return ACVP_MISSING_ARG;
    }
    if (src == NULL) {
        return ACVP_MISSING_ARG;
    }
    if (!string_fits(src, ACVP_OE_STR_MAX)) {
        return ACVP_INVALID_ARG;
    }

    if (*dest) { 
        memzero_s(*dest, ACVP_OE_STR_MAX + 1);
    } else {
        *dest = calloc(ACVP_OE_STR_MAX + 1, sizeof(char));
        if (NULL == *dest) {
            return ACVP_MALLOC_FAIL;
        }
    }
    strcpy_s(*dest, ACVP_OE_STR_MAX + 1, src);

    return ACVP_SUCCESS;
}

static ACVP_DEPENDENCY *find_dependency(ACVP_CTX *ctx,
                                        unsigned int id) {
    ACVP_DEPENDENCIES *dependencies = NULL;
    unsigned int k = 0;

    if (!ctx) return NULL;

    /* Get a handle on the Dependencies */
    dependencies = &ctx->op_env.dependencies;

    if (id == 0) {
        ACVP_LOG_ERR("Invalid 'id', must be non-zero");
        return NULL;
    }
    for (k = 0; k < dependencies->count; k++) {
        if (id == dependencies->deps[k].id) {
            /* Match */
            return &dependencies->deps[k];
        }
    }

    ACVP_LOG_ERR("Invalid 'id' (%u)", id);
    return NULL;
}

/**
 * @brief Create a new Dependency for FIPS.
 *
 * @param ctx ACVP_CTX
 * @param id ID that will be assigned to this Dependency (user defined)
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_oe_dependency_new(ACVP_CTX *ctx, unsigned int id) {
    ACVP_DEPENDENCIES *dependencies = NULL;
    ACVP_DEPENDENCY *new_dep = NULL;
    unsigned int k = 0;

    if (!ctx) return ACVP_NO_CTX;

    /* Get a handle on the Dependencies */
    dependencies = &ctx->op_env.dependencies;

    if (dependencies->count == LIBACVP_DEPENDENCIES_MAX) {
        ACVP_LOG_ERR("Libacvp already reached max Dependency capacity (%u)",
                     LIBACVP_DEPENDENCIES_MAX);
        return 0;
    }

    if (!id) {
        ACVP_LOG_ERR("Required parameter 'id' must be non-zero");
        return ACVP_INVALID_ARG;
    }

    for (k = 0; k < dependencies->count; k++) {
        if (id == dependencies->deps[k].id) {
            ACVP_LOG_ERR("A Dependency already exists with this same 'id'(%d)", id);
            return ACVP_INVALID_ARG;
        }
    }

    new_dep = &dependencies->deps[dependencies->count];
    dependencies->count++;

    /* Set the ID */
    new_dep->id = id;

    return ACVP_SUCCESS;
}

typedef enum dependency_field {
    DEPENDENCY_FIELD_TYPE = 1,
    DEPENDENCY_FIELD_NAME,
    DEPENDENCY_FIELD_DESC,
    DEPENDENCY_FIELD_MAN,
    DEPENDENCY_FIELD_VERSION,
    DEPENDENCY_FIELD_FAMILY,
    DEPENDENCY_FIELD_SERIES
} DEPENDENCY_FIELD;

static ACVP_RESULT acvp_oe_dependency_set_field(ACVP_CTX *ctx,
                                                DEPENDENCY_FIELD field,
                                                unsigned int dep_id,
                                                const char *value) {
    ACVP_RESULT rv = 0;
    ACVP_DEPENDENCY *dep = NULL;

    if (!ctx) return ACVP_NO_CTX;

    if (!dep_id) {
        ACVP_LOG_ERR("Required parameter 'dep' is NULL");
        return ACVP_INVALID_ARG;
    }

    if (!(dep = find_dependency(ctx, dep_id))) {
        return ACVP_INVALID_ARG;
    }

    if (DEPENDENCY_FIELD_TYPE == field) {
        rv = copy_oe_string(&dep->type, value);
    } else if (DEPENDENCY_FIELD_NAME == field) {
        rv = copy_oe_string(&dep->name, value);
    } else if (DEPENDENCY_FIELD_DESC == field) {
        rv = copy_oe_string(&dep->description, value);
    } else if (DEPENDENCY_FIELD_SERIES == field) {
        rv = copy_oe_string(&dep->series, value);
    } else if (DEPENDENCY_FIELD_FAMILY == field) {
        rv = copy_oe_string(&dep->family, value);
    } else if (DEPENDENCY_FIELD_VERSION == field) {
        rv = copy_oe_string(&dep->version, value);
    } else if (DEPENDENCY_FIELD_MAN == field) {
        rv = copy_oe_string(&dep->manufacturer, value);
    } else {
        ACVP_LOG_ERR("Invalid value for parameter 'field'");
        return ACVP_INVALID_ARG;
    }

    if (ACVP_INVALID_ARG == rv) {
        ACVP_LOG_ERR("'value' string too long");
        return rv;
    }
    if (ACVP_MISSING_ARG == rv) {
        ACVP_LOG_ERR("Required parameter 'value` is NULL");
        return rv;
    }

    return ACVP_SUCCESS; 
}

/**
 * @brief Create a new Operating Environment for FIPS.
 *
 * @param ctx ACVP_CTX
 * @param id ID that will be assigned to this OE (user defined)
 * @param name String representing "name" 
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_oe_oe_new(ACVP_CTX *ctx,
                           unsigned int id,
                           const char *name) {
    ACVP_OES *oes = NULL;
    ACVP_OE *new_oe = NULL;
    ACVP_RESULT rv = 0;
    int k = 0;

    if (!ctx) return ACVP_NO_CTX;

    /* Get a handle on the OES */
    oes = &ctx->op_env.oes;

    if (oes->count == LIBACVP_OES_MAX) {
        ACVP_LOG_ERR("Libacvp already reached max OE capacity (%u)",
                     LIBACVP_OES_MAX);
        return ACVP_UNSUPPORTED_OP;
    }

    if (!id) {
        ACVP_LOG_ERR("Required parameter 'id' must be non-zero");
        return ACVP_INVALID_ARG;
    }


    if (!name) {
        ACVP_LOG_ERR("Required parameter 'name' must be non-null");
        return ACVP_MISSING_ARG;
    }

    for (k = 0; k < oes->count; k++) {
        if (id == oes->oe[k].id) {
            ACVP_LOG_ERR("An OE already exists with this same 'id'(%d)", id);
            return ACVP_INVALID_ARG;
        }
    }

    new_oe = &oes->oe[oes->count];
    oes->count++;

    /* Set the ID */
    new_oe->id = id;

    rv = copy_oe_string(&new_oe->name, name);
    if (ACVP_INVALID_ARG == rv) {
        ACVP_LOG_ERR("'name` string too long");
        return rv;
    }
    if (ACVP_MISSING_ARG == rv) {
        ACVP_LOG_ERR("Required parameter 'name` is NULL");
        return rv;
    }

    return ACVP_SUCCESS;
}

static ACVP_OE *find_oe(ACVP_CTX *ctx,
                        unsigned int id) {
    ACVP_OES *oes = NULL;
    int k = 0;

    if (!ctx) return NULL;

    /* Get a handle on the Vendors */
    oes = &ctx->op_env.oes;

    if (id == 0) {
        ACVP_LOG_ERR("Invalid 'id', must be non-zero");
        return NULL;
    }
    for (k = 0; k < oes->count; k++) {
        if (id == oes->oe[k].id) {
            /* Match */
            return &oes->oe[k];
        }
    }

    ACVP_LOG_ERR("Invalid 'id' (%u)", id);
    return NULL;
}

/**
 * @brief Add a dependency to an Operating Environment.
 *
 * @param ctx ACVP_CTX
 * @param id ID for this operating environment
 * @param dependency_id ID of dependency to attach to this module
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_oe_oe_set_dependency(ACVP_CTX *ctx,
                                      unsigned int oe_id,
                                      unsigned int dependency_id) {
    ACVP_OE *oe = NULL;
    ACVP_DEPENDENCY *dep = NULL;

    if (!ctx) return ACVP_NO_CTX;

    /* Get a handle on the selected OE */
    if (!(oe = find_oe(ctx, oe_id))) {
        return ACVP_INVALID_ARG;
    }

    /* Insert a pointer to the actual Dependency struct location */
    if (!(dep = find_dependency(ctx, dependency_id))) {
        return ACVP_INVALID_ARG;
    }

    if (oe->dependencies.count == LIBACVP_DEPENDENCIES_MAX) {
        ACVP_LOG_ERR("Libacvp already reached max OE(%u) dependency capacity (%u)",
                     oe_id, LIBACVP_VENDORS_MAX);
        return ACVP_UNSUPPORTED_OP;
    }

    /* Set pointer to the dependency */
    oe->dependencies.deps[oe->dependencies.count] = dep;
    oe->dependencies.count++;

    return ACVP_SUCCESS;
}

static ACVP_VENDOR *find_vendor(ACVP_CTX *ctx,
                                unsigned int id) {
    ACVP_VENDORS *vendors = NULL;
    int k = 0;

    if (!ctx) return NULL;

    /* Get a handle on the Vendors */
    vendors = &ctx->op_env.vendors;

    if (id == 0) {
        ACVP_LOG_ERR("Invalid 'id', must be non-zero");
        return NULL;
    }
    for (k = 0; k < vendors->count; k++) {
        if (id == vendors->v[k].id) {
            /* Match */
            return &vendors->v[k];
        }
    }

    ACVP_LOG_ERR("Invalid 'id' (%u)", id);
    return NULL;
}


static ACVP_RESULT acvp_oe_vendor_new(ACVP_CTX *ctx,
                                      unsigned int id,
                                      const char *name) {
    ACVP_VENDORS *vendors = NULL;
    ACVP_VENDOR *new_vendor = NULL;
    ACVP_RESULT rv = 0;
    int i = 0;

    if (!ctx) return ACVP_NO_CTX;

    /* Get handle on vendor fields */
    vendors = &ctx->op_env.vendors;

    if (vendors->count == LIBACVP_VENDORS_MAX) {
        ACVP_LOG_ERR("Libacvp already reached max Vendor capacity (%u)",
                     LIBACVP_VENDORS_MAX);
        return ACVP_UNSUPPORTED_OP;
    }

    if (!id) {
        ACVP_LOG_ERR("Required parameter 'id' must be non-zero");
        return ACVP_INVALID_ARG;
    }

    for (i = 0; i < vendors->count; i++) {
        if (id == vendors->v[i].id) {
            ACVP_LOG_ERR("A Vendor already exists with this same 'id'(%d)", id);
            return ACVP_INVALID_ARG;
        }
    }

    new_vendor = &vendors->v[vendors->count];
    vendors->count++;

    /* Set the ID */
    new_vendor->id = id;

    rv = copy_oe_string(&new_vendor->name, name);
    if (ACVP_INVALID_ARG == rv) {
        ACVP_LOG_ERR("'name` string too long");
        return rv;
    }
    if (ACVP_MISSING_ARG == rv) {
        ACVP_LOG_ERR("Required parameter 'name` is NULL");
        return rv;
    }

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_oe_vendor_add_address(ACVP_CTX *ctx,
                                              ACVP_VENDOR *vendor,
                                              const char *street_1,
                                              const char *street_2,
                                              const char *street_3,
                                              const char *locality,
                                              const char *region,
                                              const char *country,
                                              const char *postal_code) {
    ACVP_VENDOR_ADDRESS *address = NULL;
    ACVP_RESULT rv = 0;

    if (!ctx) return ACVP_NO_CTX;

    if (!street_1 && !street_2 && !street_3 &&
        !locality && !region && !country && !postal_code) {
        ACVP_LOG_ERR("Need at least 1 of the parameters to be non-NULL");
        return ACVP_INVALID_ARG;
    }

    /* Get handle on the address field */
    address = &vendor->address;

    if (street_1) {
        rv = copy_oe_string(&address->street_1, street_1);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'street1' string too long");
            return rv;
        }
    }
    if (street_2) {
        rv = copy_oe_string(&address->street_2, street_2);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'street2' string too long");
            return rv;
        }
    }
    if (street_3) {
        rv = copy_oe_string(&address->street_3, street_3);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'street3' string too long");
            return rv;
        }
    }
    if (locality) {
        rv = copy_oe_string(&address->locality, locality);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'locality' string too long");
            return rv;
        }
    }
    if (region) {
        rv = copy_oe_string(&address->region, region);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'region' string too long");
            return rv;
        }
    }
    if (country) {
        rv = copy_oe_string(&address->country, country);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'country' string too long");
            return rv;
        }
    }
    if (postal_code) {
        rv = copy_oe_string(&address->postal_code, postal_code);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'postal_code' string too long");
            return rv;
        }
    }

    return ACVP_SUCCESS;
}

/**
 * @brief Create a new Module for the Operating Environment.
 *
 * @param ctx ACVP_CTX
 * @param id ID for this module (defined by user)
 * @param vendor_id ID of vendor to attach to this module
 * @param name String representing "name"
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_oe_module_new(ACVP_CTX *ctx,
                               unsigned int id,
                               const char *name) {
    ACVP_MODULES *modules = NULL;
    ACVP_MODULE *new_module = NULL;
    ACVP_VENDOR *vendor = NULL;
    ACVP_RESULT rv = 0;
    int k = 0;

    if (!ctx) return ACVP_NO_CTX;

    /* Get a handle on the Modules */
    modules = &ctx->op_env.modules;

    if (modules->count == LIBACVP_MODULES_MAX) {
        ACVP_LOG_ERR("Libacvp already reached max MODULE capacity (%u)",
                     LIBACVP_MODULES_MAX);
        return ACVP_UNSUPPORTED_OP;
    }
    if (!id) {
        ACVP_LOG_ERR("Required parameter 'id' must be non-zero");
        return ACVP_INVALID_ARG;
    }

    for (k = 0; k < modules->count; k++) {
        if (id == modules->module[k].id) {
            ACVP_LOG_ERR("A Module already exists with this same 'id'(%d)", id);
            return ACVP_INVALID_ARG;
        }
    }

    new_module = &modules->module[modules->count];
    modules->count++;

    /* Set the ID */
    new_module->id = id;

    /* Insert a pointer to the actual Vendor struct location */
    if (!(vendor = find_vendor(ctx, id))) return ACVP_INVALID_ARG;
    new_module->vendor = vendor;

    rv = copy_oe_string(&new_module->name, name);
    if (ACVP_INVALID_ARG == rv) {
        ACVP_LOG_ERR("'name` string too long");
        return rv;
    }
    if (ACVP_MISSING_ARG == rv) {
        ACVP_LOG_ERR("Required parameter 'name` is NULL");
        return rv;
    }

    return ACVP_SUCCESS;
}

static ACVP_MODULE *find_module(ACVP_CTX *ctx,
                                unsigned int id) {
    ACVP_MODULES *modules = NULL;
    int k = 0;

    if (!ctx) return NULL;

    modules = &ctx->op_env.modules;

    if (id == 0) {
        ACVP_LOG_ERR("Invalid 'id', must be non-zero");
        return NULL;
    }
    for (k = 0; k < modules->count; k++) {
        if (id == modules->module[k].id) {
            /* Match */
            return &modules->module[k];
        }
    }

    ACVP_LOG_ERR("Invalid 'id' (%u)", id);
    return NULL;
}

/**
 * @brief Set the module type, version or description.
 *
 * The user does not need to provide each of \p type,
 * \p version, \p description but must provide at least one.
 *
 * @param ctx ACVP_CTX
 * @param type String representing "type"
 * @param version String representing "version"
 * @param description String representing "description"
 *
 * @return ACVP_RESULT
 */
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
        rv = copy_oe_string(&module->type, type);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'type' string too long");
            return rv;
        }
    }
    if (version) {
        rv = copy_oe_string(&module->version, version);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'version' string too long");
            return rv;
        }
    }
    if (description) {
        rv = copy_oe_string(&module->description, description);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'description' string too long");
            return rv;
        }
    }

    return ACVP_SUCCESS;
}

/**
 * @brief Compare two dependencies to see if they are equal.
 *
 * @param a First dependency
 * @param b Second dependency
 *
 * @return 1 for equal, 0 for not-equal
 */
static int compare_dependencies(const ACVP_DEPENDENCY *a, const ACVP_DEPENDENCY *b) {
    int diff = 0;

    if (!a->type || !a->name || !a->description) {
        return 0;
    }

    if (!b->type || !b->name || !b->description) {
        return 0;
    }

    strcmp_s(a->type, ACVP_OE_STR_MAX, b->type, &diff);
    if (diff != 0) return 0;

    strcmp_s(a->name, ACVP_OE_STR_MAX, b->name, &diff);
    if (diff != 0) return 0;

    strcmp_s(a->description, ACVP_OE_STR_MAX, b->description, &diff);
    if (diff != 0) return 0;

    /* Reached the end, we have a full match */
    return 1;
}

/**
 * @brief Compare the page of Dependencies returned by server DB to the
 *        specified Dependency data.
 *
 * This will compare each Dependency object in the "page" returned by the server DB
 * with the specified Dependency. If a match is found, then the \p match parameter
 * is set to 1 and the URL is copied.
 *
 * If a match is not found, then the function will allocate and copy the "next" page
 * URL into \p next_endpoint, which should be compared next.
 *
 * @param ctx ACVP_CTX
 * @param dep Pointer to the Dependency data which will be compared
 * @param match Pointer to int which will be set to 1 if match is found
 * @param next_endpoint The next page URL endpoint
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT match_dependencies_page(ACVP_CTX *ctx,
                                           ACVP_DEPENDENCY *dep,
                                           int *match,
                                           char **next_endpoint) {
    ACVP_RESULT rv = 0;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL, *links_obj = NULL;
    JSON_Array *data_array = NULL;
    const char *next = NULL, *name = NULL, *type = NULL, *description = NULL;
    int i = 0, data_count = 0;
    ACVP_DEPENDENCY tmp_dep = {0, 0, 0, 0, 0};

    if (!ctx) return ACVP_NO_CTX;
    if (dep == NULL) {
        ACVP_LOG_ERR("Parameter 'dependency' must be non-NULL");
        return ACVP_INVALID_ARG;
    }
    if (match == NULL) {
        ACVP_LOG_ERR("Parameter 'match' must be non-NULL");
        return ACVP_INVALID_ARG;
    }
    *match = 0;

    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }

    obj = acvp_get_obj_from_rsp(ctx, val);
    if (!obj) {
        rv = ACVP_JSON_ERR;
        goto end;
    }

    data_array = json_object_get_array(obj, "data"); 
    data_count = json_array_get_count(data_array);

    for (i = 0; i < data_count; i++) {
        int this_match = 0;
        JSON_Object *dep_obj = json_array_get_object(data_array, i);
        if (dep_obj == NULL)  {
            rv = ACVP_JSON_ERR;
            goto end;
        }

        // Soft copy so don't need to free
        type = json_object_get_string(dep_obj, "type");
        name = json_object_get_string(dep_obj, "name");
        description = json_object_get_string(dep_obj, "description");

        if (type) tmp_dep.type = strdup(type);
        if (name) tmp_dep.name = strdup(name);
        if (description) tmp_dep.description = strdup(description);

        this_match = compare_dependencies(dep, &tmp_dep);
        if (this_match) {
            /*
             * Found a match.
             * Copy the url and skip to end.
             */
            const char *url = json_object_get_string(dep_obj, "url");
            if (url == NULL) {
                ACVP_LOG_ERR("JSON dependency object missing 'url'");
                rv = ACVP_JSON_ERR;
                goto end;
            }

            dep->url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
            if (dep->url == NULL) {
                ACVP_LOG_ERR("Failed to malloc");
                rv = ACVP_MALLOC_FAIL;
                goto end;
            }
            ACVP_LOG_INFO("Dependencies Match");
            strcpy_s(dep->url, ACVP_ATTR_URL_MAX + 1, url);
            *match = 1; 
            goto end;
        }
        free(tmp_dep.type);
        free(tmp_dep.name);
        free(tmp_dep.description);
        tmp_dep.type = NULL;
        tmp_dep.name = NULL;
        tmp_dep.description = NULL;
    }

    links_obj = json_object_get_object(obj, "links");
    if (links_obj == NULL) {
        ACVP_LOG_ERR("No links object");
        rv = ACVP_JSON_ERR;
        goto end;
    }
    if (*next_endpoint) {
        free(*next_endpoint);
        *next_endpoint = NULL;
    }
    
    next = json_object_get_string(links_obj, "next");
    if (next) {
        // Copy the next page endpoint
        *next_endpoint = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
        if (*next_endpoint == NULL) {
            ACVP_LOG_ERR("Failed to malloc");
            rv = ACVP_MALLOC_FAIL;
            goto end;
        }
        strcpy_s(*next_endpoint, ACVP_ATTR_URL_MAX + 1, next);
    }

end:
    free(tmp_dep.type);
    free(tmp_dep.name);
    free(tmp_dep.description);
    if (val) json_value_free(val);

    return rv;
}

/**
 * @brief Query the server DB for the specified Dependency data.
 *
 * This will query the server DB to check if the data exists, and it will retrieve
 * the Dependency URL.
 *
 * @param ctx ACVP_CTX
 * @param dep Pointer to the Dependency data which will be queried
 * @param endpoint The URL endpoint string
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT query_dependency(ACVP_CTX *ctx,
                                    ACVP_DEPENDENCY *dep,
                                    const char *endpoint) {
    ACVP_RESULT rv = 0;
    ACVP_KV_LIST *parameters = NULL;
    char *first_endpoint = NULL, *next_endpoint = NULL;
    int match = 0;

    if (!ctx) return ACVP_NO_CTX;
    if (dep == NULL) {
        ACVP_LOG_ERR("Parameter 'dependency' must be non-NULL");
        return ACVP_INVALID_ARG;
    }

    if (dep->url) {
        /*
         * This resource has already been verified as existing.
         */
        return ACVP_SUCCESS;
    }

    if (endpoint == NULL) {
        first_endpoint = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
        if (first_endpoint == NULL) {
            ACVP_LOG_ERR("Failed to malloc");
            return ACVP_MALLOC_FAIL;
        }
        endpoint = first_endpoint;

        /*
         * Prepare the first query.
         */
        snprintf(first_endpoint, ACVP_ATTR_URL_MAX, "%s%s",
                 ctx->path_segment, "dependencies?");

        if (dep->type) {
            rv = acvp_kv_list_append(&parameters, "type[0]=eq:", dep->type);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Failed acvp_kv_list_append()");
                goto end;
            }
        }

        if (dep->name) {
            rv = acvp_kv_list_append(&parameters, "name[0]=eq:", dep->name);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Failed acvp_kv_list_append()");
                goto end;
            }
        }

        if (dep->description) {
            rv = acvp_kv_list_append(&parameters, "description[0]=eq:", dep->description);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Failed acvp_kv_list_append()");
                goto end;
            }
        }
    }


    do {
        /* Query the server DB. */
        if (parameters) {
            /* Use parameters and free them, as we get the next pages'
             * URLs from the server */
            rv = acvp_transport_get(ctx, endpoint, parameters);
            acvp_kv_list_free(parameters);
            parameters = NULL;
        } else {
            rv = acvp_transport_get(ctx, endpoint, NULL);
        }
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to query Dependency");
            goto end;
        }

        /* Try to match the dependency against the page returned by server. */
        rv = match_dependencies_page(ctx, dep, &match, &next_endpoint);

        /* Only query the next page if we are within the limit */
        if (rv != ACVP_SUCCESS || match) {
            break;
        }

        endpoint = next_endpoint;
    } while (endpoint);

end:
    if (first_endpoint) free(first_endpoint);
    if (next_endpoint) free(next_endpoint);
    if (parameters) acvp_kv_list_free(parameters);

    return rv;
}

/**
 * @brief Verify the OE dependencies data which the user intends to send for a FIPS validation.
 *
 * This will query the server DB to check if the data exists, and it will retrieve
 * the Dependencies URLs.
 *
 * - If all dependencies are found, then status COMPLETE is given
 * - If only a subset of the dependencies are found, then PARTIAL
 * - If none of the dependencies are found, then INCOMPLETE
 *
 * @param ctx ACVP_CTX
 * @param dependencies Pointer to array of dependencies
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT verify_fips_oe_dependencies(ACVP_CTX *ctx,
                                               ACVP_OE_DEPENDENCIES *dependencies) {
    ACVP_RESULT rv = 0;
    unsigned int i = 0, all_incomplete = 1;

    if (!ctx) return ACVP_NO_CTX;
    if (dependencies == NULL) {
        ACVP_LOG_ERR("Parameter 'dependencies' must be non-NULL");
        return ACVP_INVALID_ARG;
    }

    dependencies->status = ACVP_RESOURCE_STATUS_COMPLETE; // Start with this
    for (i = 0; i < dependencies->count; i++) {
        ACVP_DEPENDENCY *cur_dep = dependencies->deps[i];

        rv = query_dependency(ctx, cur_dep, NULL);
        if (ACVP_SUCCESS != rv) {
            ACVP_LOG_ERR("Unable to query this Dependency[%d]", i);
            return rv;
        }

        if (cur_dep->url == NULL) {
            /* This dependency does not exist. Mark the flag :) */
            dependencies->status = ACVP_RESOURCE_STATUS_PARTIAL;
        } else {
            /* At least this Dependency exists */
            all_incomplete = 0;
        }
    }

    if (all_incomplete) {
        // None of the dependencies exist
        dependencies->status = ACVP_RESOURCE_STATUS_INCOMPLETE;
    }

    return ACVP_SUCCESS;
}

/**
 * @brief Compare the page of OES returned by server DB to the specified OE data.
 *
 * This will compare each OE object in the "page" returned by the server DB
 * with the specified OE. If a match is found, then the \p match parameter is set to 1
 * and the URL is copied.
 *
 * If a match is not found, then the function will allocate and copy the "next" page
 * URL into \p next_endpoint, which should be compared next.
 *
 * @param ctx ACVP_CTX
 * @param oe Pointer to the OE data which will be compared
 * @param match Pointer to int which will be set to 1 if match is found
 * @param next_endpoint The next page URL endpoint
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT match_oes_page(ACVP_CTX *ctx,
                                  ACVP_OE *oe,
                                  int *match,
                                  char **next_endpoint) {
    ACVP_RESULT rv = 0;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL, *links_obj = NULL;
    JSON_Array *data_array = NULL;
    const char *next = NULL;
    int i = 0, data_count = 0;

    if (!ctx) return ACVP_NO_CTX;
    if (oe == NULL) {
        ACVP_LOG_ERR("Parameter 'oe' must be non-NULL");
        return ACVP_INVALID_ARG;
    }
    if (match == NULL) {
        ACVP_LOG_ERR("Parameter 'match' must be non-NULL");
        return ACVP_INVALID_ARG;
    }
    *match = 0;

    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }

    obj = acvp_get_obj_from_rsp(ctx, val);
    if (!obj) {
        rv = ACVP_JSON_ERR;
        goto end;
    }

    data_array = json_object_get_array(obj, "data");
    data_count = json_array_get_count(data_array);

    for (i = 0; i < data_count; i++) {
        unsigned int k = 0;
        int equal = 1;
        JSON_Array *dependency_urls = NULL;
        JSON_Object *oe_obj = json_array_get_object(data_array, i);
        if (oe_obj == NULL)  {
            rv = ACVP_JSON_ERR;
            goto end;
        }

        dependency_urls = json_object_get_array(oe_obj, "dependencyUrls");
        if (dependency_urls == NULL)  {
            ACVP_LOG_ERR("No dependencies object");
            rv = ACVP_JSON_ERR;
            goto end;
        }

        if (oe->dependencies.count != json_array_get_count(dependency_urls)) {
            /* The number of array elements must be same */
            continue;
        }

        for (k = 0; k < oe->dependencies.count; k++) {
            int diff = 0;
            const char *parsed_url = json_array_get_string(dependency_urls, k);
            if (parsed_url) {
                strcmp_s(oe->dependencies.deps[k]->url, ACVP_ATTR_URL_MAX,
                         parsed_url, &diff);
                if (diff != 0) {
                    equal = 0;
                    break;
                }
            }
        }

        if (equal) {
            /*
             * Found a match.
             * Copy the url and skip to end.
             */
            const char *url = json_object_get_string(oe_obj, "url");
            if (url == NULL) {
                ACVP_LOG_ERR("JSON oe object missing 'url'");
                rv = ACVP_JSON_ERR;
                goto end;
            }

            oe->url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
            if (oe->url == NULL) {
                ACVP_LOG_ERR("Failed to malloc");
                rv = ACVP_MALLOC_FAIL;
                goto end;
            }

            strcpy_s(oe->url, ACVP_ATTR_URL_MAX + 1, url);
            *match = 1;
            ACVP_LOG_INFO("OE Match");
            goto end;
        }
    }

    links_obj = json_object_get_object(obj, "links");
    if (links_obj == NULL) {
        ACVP_LOG_ERR("No links object");
        rv = ACVP_JSON_ERR;
        goto end;
    }
    
    if (*next_endpoint) {
        free(*next_endpoint);
        *next_endpoint = NULL;
    }
    
    next = json_object_get_string(links_obj, "next");
    if (next) {
        // Copy the next page endpoint
        *next_endpoint = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
        if (*next_endpoint == NULL) {
            ACVP_LOG_ERR("Failed to malloc");
            rv = ACVP_MALLOC_FAIL;
            goto end;
        }
        strcpy_s(*next_endpoint, ACVP_ATTR_URL_MAX + 1, next);
    }

end:
    if (val) json_value_free(val);

    return rv;
}

/**
 * @brief Query the server DB for the specified Operating Environment data.
 *
 * This will query the server DB to check if the data exists, and it will retrieve
 * the Operating Environment URL.
 *
 * @param ctx ACVP_CTX
 * @param oe Pointer to the Operating Environment data which will be queried
 * @param endpoint The URL endpoint string
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT query_oe(ACVP_CTX *ctx,
                            ACVP_OE *oe,
                            const char *endpoint) {
    ACVP_RESULT rv = 0;
    ACVP_KV_LIST *parameters = NULL;
    char *first_endpoint = NULL, *next_endpoint = NULL;
    int match = 0;

    if (!ctx) return ACVP_NO_CTX;
    if (oe == NULL) {
        ACVP_LOG_ERR("Parameter 'oe' must be non-NULL");
        return ACVP_INVALID_ARG;
    }

    if (oe->url) {
        /*
         * This resource has already been verified as existing.
         */
        return ACVP_SUCCESS;
    }

    if (endpoint == NULL) {
        first_endpoint = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
        if (first_endpoint == NULL) {
            ACVP_LOG_ERR("Failed to malloc");
            return ACVP_MALLOC_FAIL;
        }
        endpoint = first_endpoint;

        /*
         * Prepare the first query.
         */
        snprintf(first_endpoint, ACVP_ATTR_URL_MAX, "%s%s",
                 ctx->path_segment, "oes?");

        if (oe->name) {
            rv = acvp_kv_list_append(&parameters, "name[0]=eq:", oe->name);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Failed acvp_kv_list_append()");
                goto end;
            }
        }
    }

    do {
        /* Query the server DB. */
        if (parameters) {
            /* Use parameters and free them, as we get the next pages'
             * URLs from the server */
            rv = acvp_transport_get(ctx, endpoint, parameters);
            acvp_kv_list_free(parameters);
            parameters = NULL;
        } else {
            rv = acvp_transport_get(ctx, endpoint, NULL);
        }
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to query Operating Environment");
            goto end;
        }

        /* Try to match against the page returned by server. */
        rv = match_oes_page(ctx, oe, &match, &next_endpoint);

        /* Only query the next page if we are within the limit */
        if (rv != ACVP_SUCCESS || match) {
            break;
        }
        
        endpoint = next_endpoint;
    } while (endpoint);

end:
    if (first_endpoint) free(first_endpoint);
    if (next_endpoint) free(next_endpoint);
    if (parameters) acvp_kv_list_free(parameters);

    return rv;
}

/**
 * @brief Verify the OE data which the user intends to send for a FIPS validation.
 *
 * This will query the server DB to check if the data exists, and it will retrieve
 * the OE URL along with all of its sub-object URLs.
 *
 * The OE will be created during the PUT operation if:
 * - The OE with given name or other fields are not found
 * - Any of the attached dependencies are not found
 *
 * @param ctx ACVP_CTX Holds the fips.oe
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT verify_fips_oe(ACVP_CTX *ctx) {
    ACVP_RESULT rv = 0;
    unsigned int i = 0;

    if (!ctx) return ACVP_NO_CTX;

    /*
     * First, check the linked Dependencies because some/all of them may already exist.
     */
    rv = verify_fips_oe_dependencies(ctx, &ctx->fips.oe->dependencies);
    if (ACVP_SUCCESS != rv) {
        ACVP_LOG_ERR("Failed to verify linked Dependencies of OE(%u)", ctx->fips.oe->id);
        return rv;
    }

    for (i = 0; i < ctx->fips.oe->dependencies.count; i++) {
        if (ctx->fips.oe->dependencies.deps[i]->url == NULL) {
            /*
             * At least one of the Dependencies doesn't exist yet.
             * This means we need to ask the server to create this OE.
             * No need to query the OE.
             */
            return ACVP_SUCCESS;
        }
    }

    rv = query_oe(ctx, ctx->fips.oe, NULL);
    if (ACVP_SUCCESS != rv) {
        ACVP_LOG_ERR("Unable to query the OE(%u)", ctx->fips.oe->id);
        return rv;
    }

    return ACVP_SUCCESS;
}

/**
 * @brief Compare the JSON array of emails with the specified emails.
 *
 * This will compare each email string in the JSON array with the
 * specified list of emails. If a match is found, then the \p match
 * parameter is set to 1.
 *
 * @param emails Pointer to the list of emails which will be compared
 * @param candidate_emails Pointer to the JSON array of emails
 * @param match Pointer to int which will be set to 1 if match is found
 *
 * @return ACVP_RESULT
 */
static int compare_emails(ACVP_STRING_LIST *email_list,
                          JSON_Array *candidate_emails,
                          int *match) {
    ACVP_STRING_LIST *tmp_ptr = NULL;
    size_t email_list_len = 0;
    int i = 0;

    if (email_list == NULL || candidate_emails == NULL || match == NULL) {
        return ACVP_INVALID_ARG;
    }

    tmp_ptr = email_list;
    while (tmp_ptr) {
        email_list_len++;
        tmp_ptr = email_list->next;
    }

    if (email_list_len != json_array_get_count(candidate_emails)) {
        /* Must be same length */
        *match = 0;
        return ACVP_SUCCESS;
    }

    while (email_list) {
        int diff = 0;
        char *email = email_list->string;
        const char *tmp_email = NULL;

        tmp_email = json_array_get_string(candidate_emails, i);
        if (tmp_email) {
            strcmp_s(email, ACVP_OE_STR_MAX, tmp_email, &diff);
            if (diff != 0) {
                *match = 0;
                return ACVP_SUCCESS;
            }
        }

        email_list = email_list->next;
        i++;
    }

    *match = 1;
    return ACVP_SUCCESS;
}

/**
 * @brief Compare the JSON array of vendor phone numbers with the specified
 *        Vendor phone numbers.
 *
 * This will compare each vendor phone number object in the JSON array with the
 * specified list of Vendor phone numbers. If a match is found, then the \p match
 * parameter is set to 1.
 *
 * @param phone_list Pointer to list of vendor phone numbers which will be compared
 * @param candidate_phones Pointer to the JSON array of vendor phone numbers
 * @param match Pointer to int which will be set to 1 if match is found
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT compare_phone_numbers(ACVP_OE_PHONE_LIST *phone_list,
                                         JSON_Array *candidate_phones,
                                         int *match) {
    ACVP_OE_PHONE_LIST *tmp_ptr = NULL;
    size_t phone_list_len = 0;
    int i = 0;

    if (candidate_phones == NULL || match == NULL) {
        return ACVP_INVALID_ARG;
    }

    if (phone_list == NULL && json_array_get_count(candidate_phones) == 0) {
        *match = 1;
        return ACVP_SUCCESS;
    }

    if (phone_list == NULL) {
        return ACVP_INVALID_ARG;
    }

    tmp_ptr = phone_list;
    while (tmp_ptr) {
        phone_list_len++;
        tmp_ptr = tmp_ptr->next;
    }

    if (phone_list_len != json_array_get_count(candidate_phones)) {
        /* Must be same length */
        *match = 0;
        return ACVP_SUCCESS;
    }

    while (phone_list) {
        JSON_Object *obj = NULL;
        const char *tmp_number = NULL, *tmp_type = NULL;
        int diff = 0;

        obj = json_array_get_object(candidate_phones, i);
        if (NULL == obj) {
            return ACVP_JSON_ERR;
        }

        tmp_number = json_object_get_string(obj, "number");
        if (tmp_number) {
            strcmp_s(phone_list->number, ACVP_OE_STR_MAX, tmp_number, &diff);
            if (diff != 0) {
                *match = 0;
                return ACVP_SUCCESS;
            }
        }

        tmp_type = json_object_get_string(obj, "type");
        if (tmp_type) {
            strcmp_s(phone_list->type, ACVP_OE_STR_MAX, tmp_type, &diff);
            if (diff != 0) {
                *match = 0;
                return ACVP_SUCCESS;
            }
        }

        phone_list = phone_list->next;
        i++;
    }

    *match = 1;
    return ACVP_SUCCESS;
}

/**
 * @brief Compare the JSON array of vendor addresses with the specified Vendor address data.
 *
 * This will compare each vendor address object in the array with the specified Vendor
 * address. If a match is found, then the \p match parameter is set to 1.
 *
 * @param address Pointer to the vendor address which will be compared
 * @param candidate_addresses Pointer to the JSON array of vendor addresses
 * @param match Pointer to int which will be set to 1 if match is found
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT compare_vendor_address(ACVP_CTX *ctx, ACVP_VENDOR_ADDRESS *address,
                                          JSON_Array *candidate_addresses,
                                          int *match) {
    size_t i = 0;
    size_t num_candidates = 0;

    if (address == NULL || candidate_addresses == NULL || match == NULL) {
        return ACVP_INVALID_ARG;
    }

    *match = 0;
    num_candidates = json_array_get_count(candidate_addresses);
    for (i = 0; i < num_candidates; i++) {
        const char *street_1 = NULL, *street_2 = NULL,
                   *street_3 = NULL, *locality = NULL,
                   *region = NULL, *country = NULL,
                   *postal_code = NULL;
        const char *url = NULL;
        JSON_Object *obj = NULL;
        int diff = 0;

        obj = json_array_get_object(candidate_addresses, i);
        if (NULL == obj) {
            return ACVP_JSON_ERR;
        }

        street_1 = json_object_get_string(obj, "street1");
        if ((address->street_1 && !street_1) || (street_1 && !address->street_1)) {
            // Either of them is missing, automatic disqualify
            continue;
        } else if (address->street_1 && street_1) {
            // Both exist, compare
            strcmp_s(address->street_1, ACVP_OE_STR_MAX, street_1, &diff);
            if (diff != 0) {
                 ACVP_LOG_VERBOSE("Street1 not equal");
                 continue; // Not equal
            }
        }

        street_2 = json_object_get_string(obj, "street2");
        if ((address->street_2 && !street_2) || (street_2 && !address->street_2)) {
            // Either of them is missing, automatic disqualify
            continue;
        } else if (address->street_2 && street_2) {
            // Both exist, compare
            strcmp_s(address->street_2, ACVP_OE_STR_MAX, street_2, &diff);
            if (diff != 0) {
                 ACVP_LOG_VERBOSE("Street2 mismatch");
                 continue; // Not equal
            }
        }

        street_3 = json_object_get_string(obj, "street3");
        if ((address->street_3 && !street_3) || (street_3 && !address->street_3)) {
            // Either of them is missing, automatic disqualify
            continue;
        } else if (address->street_3 && street_3) {
            // Both exist, compare
            strcmp_s(address->street_3, ACVP_OE_STR_MAX, street_3, &diff);
            if (diff != 0) {
                 ACVP_LOG_VERBOSE("Street3 not equal");
                 continue; // Not equal
            }
        }

        locality = json_object_get_string(obj, "locality");
        if ((address->locality && !locality) || (locality && !address->locality)) {
            // Either of them is missing, automatic disqualify
            continue;
        } else if (address->locality && locality) {
            // Both exist, compare
            strcmp_s(address->locality, ACVP_OE_STR_MAX, locality, &diff);
            if (diff != 0) {
                 ACVP_LOG_VERBOSE("Locality not equal");
                 continue; // Not equal
            }
        }

        region = json_object_get_string(obj, "region");
        if ((address->region && !region) || (region && !address->region)) {
            // Either of them is missing, automatic disqualify
            continue;
        } else if (address->region && region) {
            // Both exist, compare
            strcmp_s(address->region, ACVP_OE_STR_MAX, region, &diff);
            if (diff != 0) {
                 ACVP_LOG_VERBOSE("Region not equal");
                 continue; // Not equal
            }
        }

        country = json_object_get_string(obj, "country");
        if ((address->country && !country) || (country && !address->country)) {
            // Either of them is missing, automatic disqualify
            continue;
        } else if (address->country && country) {
            // Both exist, compare
            strcmp_s(address->country, ACVP_OE_STR_MAX, country, &diff);
            if (diff != 0) {
                 ACVP_LOG_VERBOSE("Country not equal");
                 continue; // Not equal
            }
        }

        postal_code = json_object_get_string(obj, "postalCode");
        if ((address->postal_code && !postal_code) || (postal_code && !address->postal_code)) {
            // Either of them is missing, automatic disqualify
            continue;
        } else if (address->postal_code && postal_code) {
            // Both exist, compare
            strcmp_s(address->postal_code, ACVP_OE_STR_MAX, postal_code, &diff);
            if (diff != 0) {
                 ACVP_LOG_VERBOSE("Postal code not equal");
                 continue; // Not equal
            }
        }

        url = json_object_get_string(obj, "url");
        if (url) {
            /*
             * Found a match.
             * Copy the url and return.
             */
            if (address->url) {
                memzero_s(address->url, ACVP_ATTR_URL_MAX + 1);
            } else {
                address->url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
                if (address->url == NULL) {
                    return ACVP_MALLOC_FAIL;
                }
            }
            strcpy_s(address->url, ACVP_ATTR_URL_MAX + 1, url);
            *match = 1;
            ACVP_LOG_VERBOSE("Vendor Address Match");
            return ACVP_SUCCESS;
        }
    }

    // None of the candidates matched.
    return ACVP_SUCCESS;
}

/**
 * @brief Query the server DB for the specified Vendor contacts data.
 *
 * This will query the server DB to ensure that the data exists, and it will retrieve
 * the Vendor contact URLs.
 *
 * This function will only try to find a match in the first page for each given contact.
 *
 * @param ctx ACVP_CTX
 * @param persons Pointer to the vendor persons which will be queried
 * @param endpoint The URL endpoint string
 * @param match Pointer to int which will be set to 1 if match is found
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT query_vendor_contacts(ACVP_CTX *ctx,
                                         ACVP_PERSONS *persons,
                                         const char *endpoint,
                                         int *match) {
    ACVP_RESULT rv = 0;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    JSON_Array *data_array = NULL;
    int i = 0, k = 0, data_count = 0;
    const char *url = NULL;

    if (persons == NULL || match == NULL) {
        return ACVP_INVALID_ARG;
    }
    *match = 0;

    if (endpoint == NULL) {
        if (persons->count == 0) {
            // They are both empty
            *match = 1;
            ACVP_LOG_VERBOSE("Vendor No Contacts Match");
            return ACVP_SUCCESS;
        } else {
            return ACVP_SUCCESS; // No match
        }
    }

    /*
     * Query the server DB.
     */
    rv = acvp_transport_get(ctx, endpoint, NULL);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to query endpoint");
        return rv;
    }

    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }
    obj = acvp_get_obj_from_rsp(ctx, val);
    if (!obj) {
        rv = ACVP_JSON_ERR;
        goto end;
    }

    data_array = json_object_get_array(obj, "data");
    data_count = json_array_get_count(data_array);

    for (k = 0; k < persons->count; k++) {
        ACVP_PERSON *person = &persons->person[k];
        int matched_contact = 0;

        for (i = 0; i < data_count; i++) {
            int equal = 1, diff = 0;
            const char *full_name = NULL;
            JSON_Array *emails = NULL, *phone_numbers = NULL;
            JSON_Object *contact_obj = json_array_get_object(data_array, i);
            if (contact_obj == NULL)  {
                rv = ACVP_JSON_ERR;
                goto end;
            }

            full_name = json_object_get_string(contact_obj, "fullName");
            if (full_name == NULL) {
                ACVP_LOG_ERR("No fullName object");
                rv = ACVP_JSON_ERR;
                goto end;
            }
            strcmp_s(person->full_name, ACVP_OE_STR_MAX, full_name, &diff);
            if (diff != 0) {
                 ACVP_LOG_VERBOSE("Name not equal, checking next...");
                 continue; // Not equal
            }

            emails = json_object_get_array(contact_obj, "emails");
            if (emails == NULL)  {
                ACVP_LOG_ERR("No emails object");
                rv = ACVP_JSON_ERR;
                goto end;
            }
            rv = compare_emails(person->emails, emails, &equal);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Problem comparing person emails");
                goto end;
            }
            if (!equal) {
                ACVP_LOG_VERBOSE("Emails do not match, checking next...");
                continue;
            }
            ACVP_LOG_VERBOSE("Email Match");

            phone_numbers = json_object_get_array(contact_obj, "phoneNumbers");
            if (phone_numbers != NULL)  {
                rv = compare_phone_numbers(person->phone_numbers, phone_numbers, &equal);
                if (ACVP_SUCCESS != rv) {
                    ACVP_LOG_ERR("Problem comparing person phone numbers");
                    goto end;
                }
                if (!equal) {
                    ACVP_LOG_VERBOSE("Phone numbers do not match");
                    continue;
                }
                ACVP_LOG_VERBOSE("Phone Match");
            }

            /*
             * Found a match.
             * Copy the url.
             */
            if (person->url) {
                memzero_s(person->url, ACVP_ATTR_URL_MAX + 1);
            } else {
                person->url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
                if (person->url == NULL) {
                    return ACVP_MALLOC_FAIL;
                }
            }

            url = json_object_get_string(contact_obj, "url");
            if (url) {
                strcpy_s(person->url, ACVP_ATTR_URL_MAX + 1, url);
                matched_contact = 1;
            }
            break;
        }

        if (!matched_contact) {
            /*
             * We didn't fine a match for this Person.
             */
            goto end;
        }
    }

    // Got thorugh all of the linked Persons
    ACVP_LOG_VERBOSE("Contacts Match");
    *match = 1;

end:
    if (val) json_value_free(val);
    return rv;
}

/**
 * @brief Compare the page of vendors returned by server DB to the specified Vendor data.
 *
 * This will compare each vendor object in the "page" returned by the server DB
 * with the specified Vendor. If a match is found, then the \p match parameter is set to 1
 * and the URL is copied.
 *
 * If a match is not found, then the function will allocate and copy the "next" page
 * URL into \p next_endpoint, which should be compared next.
 *
 * @param ctx ACVP_CTX
 * @param vendor Pointer to the vendor data which will be compared
 * @param match Pointer to int which will be set to 1 if match is found
 * @param next_endpoint The next page URL endpoint
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT match_vendors_page(ACVP_CTX *ctx,
                                      ACVP_VENDOR *vendor,
                                      int *match,
                                      char **next_endpoint) {
    ACVP_RESULT rv = 0;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL, *links_obj = NULL;
    JSON_Array *data_array = NULL;
    const char *next = NULL;
    int i = 0, data_count = 0;

    if (!ctx) return ACVP_NO_CTX;
    if (vendor == NULL) {
        ACVP_LOG_ERR("Parameter 'vendor' must be non-NULL");
        return ACVP_INVALID_ARG;
    }
    if (match == NULL) {
        ACVP_LOG_ERR("Parameter 'match' must be non-NULL");
        return ACVP_INVALID_ARG;
    }
    *match = 0;

    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }

    obj = acvp_get_obj_from_rsp(ctx, val);
    if (!obj) {
        rv = ACVP_JSON_ERR;
        goto end;
    }

    data_array = json_object_get_array(obj, "data");
    data_count = json_array_get_count(data_array);

    for (i = 0; i < data_count; i++) {
        int equal = 1;
        const char *contacts_url = NULL, *url = NULL;
        JSON_Array *emails = NULL, *phone_numbers = NULL, *addresses = NULL;
        JSON_Object *vendor_obj = json_array_get_object(data_array, i);
        if (vendor_obj == NULL)  {
            rv = ACVP_JSON_ERR;
            goto end;
        }

        emails = json_object_get_array(vendor_obj, "emails");
        if (emails == NULL)  {
            ACVP_LOG_ERR("No emails object");
            rv = ACVP_JSON_ERR;
            goto end;
        }
        rv = compare_emails(vendor->emails, emails, &equal);
        if (ACVP_SUCCESS != rv) {
            ACVP_LOG_ERR("Problem comparing vendor emails");
            goto end;
        }
        if (!equal) {
            ACVP_LOG_VERBOSE("Emails do not match");
            continue;
        }

        phone_numbers = json_object_get_array(vendor_obj, "phoneNumbers");
        if (phone_numbers != NULL)  {
            rv = compare_phone_numbers(vendor->phone_numbers, phone_numbers, &equal);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Problem comparing vendor phone numbers");
                goto end;
            }
            if (!equal) {
                ACVP_LOG_VERBOSE("Phone numbers do not match");
                continue;
            }
        }

        addresses = json_object_get_array(vendor_obj, "addresses");
        if (addresses == NULL)  {
            ACVP_LOG_ERR("No addresses object");
            rv = ACVP_JSON_ERR;
            goto end;
        }
        rv = compare_vendor_address(ctx, &vendor->address, addresses, &equal);
        if (ACVP_SUCCESS != rv) {
            ACVP_LOG_ERR("Problem comparing vendor address");
            goto end;
        }
        if (!equal) {
            ACVP_LOG_VERBOSE("Addresses do not match");
            continue;
        }

        contacts_url = json_object_get_string(vendor_obj, "contactsUrl");
        query_vendor_contacts(ctx, &vendor->persons, contacts_url, &equal);
        if (ACVP_SUCCESS != rv) {
            ACVP_LOG_ERR("Problem comparing vendor contacts");
            goto end;
        }
        if (!equal) {
            ACVP_LOG_VERBOSE("Contact URLs do not match");
            continue;
        }

        /*
         * Found a match.
         * Copy the url and skip to end.
         */
        url = json_object_get_string(vendor_obj, "url");
        if (url == NULL) {
            ACVP_LOG_ERR("JSON object missing 'url'");
            ACVP_LOG_ERR("No url object");
            rv = ACVP_JSON_ERR;
            goto end;
        }

        vendor->url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
        if (vendor->url == NULL) {
            ACVP_LOG_ERR("Failed to malloc");
            rv = ACVP_MALLOC_FAIL;
            goto end;
        }

        strcpy_s(vendor->url, ACVP_ATTR_URL_MAX + 1, url);
        ACVP_LOG_INFO("Vendors Match");
        *match = 1;
        goto end;
    }


    links_obj = json_object_get_object(obj, "links");
    if (links_obj == NULL) {
        ACVP_LOG_ERR("No links object");
        rv = ACVP_JSON_ERR;
        goto end;
    }
    
    if (*next_endpoint) {
        free(*next_endpoint);
        *next_endpoint = NULL;
    }
    next = json_object_get_string(links_obj, "nextPage");
    if (next) {
        // Copy the next page endpoint
        *next_endpoint = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
        if (*next_endpoint == NULL) {
            ACVP_LOG_ERR("Failed to malloc");
            rv = ACVP_MALLOC_FAIL;
            goto end;
        }
        strcpy_s(*next_endpoint, ACVP_ATTR_URL_MAX + 1, next);
    }

end:
    if (val) json_value_free(val);

    return rv;
}

/**
 * @brief Query the server DB for the specified Vendor data.
 *
 * This will query the server DB to ensure that the data exists, and it will retrieve
 * the Vendor URL along with all of its sub-object URLs.
 *
 * @param ctx ACVP_CTX
 * @param vendor Pointer to the vendor data which will be queried
 * @param endpoint The URL endpoint string
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT query_vendor(ACVP_CTX *ctx,
                                ACVP_VENDOR *vendor,
                                const char *endpoint) {
    ACVP_RESULT rv = 0;
    ACVP_KV_LIST *parameters = NULL;
    char *first_endpoint = NULL, *next_endpoint = NULL;
    int match = 0;

    if (!ctx) return ACVP_NO_CTX;
    if (vendor == NULL) {
        ACVP_LOG_ERR("Parameter 'vendor' must be non-NULL");
        return ACVP_INVALID_ARG;
    }

    if (vendor->url) {
        /*
         * This resource has already been verified as existing.
         */
        return ACVP_SUCCESS;
    }

    if (endpoint == NULL) {
        first_endpoint = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
        if (first_endpoint == NULL) {
            ACVP_LOG_ERR("Failed to malloc");
            return ACVP_MALLOC_FAIL;
        }
        endpoint = first_endpoint;

        /*
         * Prepare the first query.
         */
        snprintf(first_endpoint, ACVP_ATTR_URL_MAX, "%s%s",
                 ctx->path_segment, "vendors?");

        if (vendor->name) {
            rv = acvp_kv_list_append(&parameters, "name[0]=eq:", vendor->name);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Failed acvp_kv_list_append()");
                goto end;
            }
        }

        if (vendor->website) {
            rv = acvp_kv_list_append(&parameters, "website[0]=eq:", vendor->website);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Failed acvp_kv_list_append()");
                goto end;
            }
        }
        
        /* Query using the first email in the list */
        if (vendor->emails) {
            rv = acvp_kv_list_append(&parameters, "email[0]=eq:", vendor->emails->string);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Failed acvp_kv_list_append()");
                goto end;
            }
        }
    }


    do {
        /* Query the server DB. */
        if (parameters) {
            /* Use parameters and free them, as we get the next pages'
             * URLs from the server */
            rv = acvp_transport_get(ctx, endpoint, parameters);
            acvp_kv_list_free(parameters);
            parameters = NULL;
        } else {
            rv = acvp_transport_get(ctx, endpoint, NULL);
        }
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to query Operating Environment");
            goto end;
        }

        /* Try to match against the page returned by server. */
        rv = match_vendors_page(ctx, vendor, &match, &next_endpoint);

        /* Only query the next page if there is one */
        if (rv != ACVP_SUCCESS || match) {
            break;
        }
        endpoint = next_endpoint;
    } while (endpoint);

end:
    if (first_endpoint) free(first_endpoint);
    if (next_endpoint) free(next_endpoint);
    if (parameters) acvp_kv_list_free(parameters);

    return rv;
}

/**
 * @brief Compare two modules to see if they are equal.
 *
 * @param a First module 
 * @param b Second module 
 *
 * @return 1 for equal, 0 for not-equal
 */
static int compare_modules(const ACVP_MODULE *a, const ACVP_MODULE *b) {
    int diff = 0;
    int i = 0;

    if (!a->type || !a->name || !a->description || !a->version || !a->vendor->url || !a->vendor->address.url) {
        return 0;
    }

    if (!b->type || !b->name || !b->description || !b->version || !b->vendor->url || !b->vendor->address.url) {
        return 0;
    }

    strcmp_s(a->type, ACVP_OE_STR_MAX, b->type, &diff);
    if (diff != 0) return 0;

    strcmp_s(a->name, ACVP_OE_STR_MAX, b->name, &diff);
    if (diff != 0) return 0;

    strcmp_s(a->version, ACVP_OE_STR_MAX, b->version, &diff);
    if (diff != 0) return 0;

    strcmp_s(a->description, ACVP_OE_STR_MAX, b->description, &diff);
    if (diff != 0) return 0;

    strcmp_s(a->vendor->url, ACVP_ATTR_URL_MAX,
             b->vendor->url, &diff);
    if (diff != 0) return 0;

    strcmp_s(a->vendor->address.url, ACVP_ATTR_URL_MAX,
             b->vendor->address.url, &diff);
    if (diff != 0) return 0;

    for (i = 0; i < a->vendor->persons.count; i++) {
        if (!a->vendor->persons.person[i].url || !b->vendor->persons.person[i].url) {
            return 0;
        }
        strcmp_s(a->vendor->persons.person[i].url, ACVP_ATTR_URL_MAX,
                 b->vendor->persons.person[i].url, &diff);
        if (diff != 0) return 0;
    }

    /* Reached the end, we have a full match */
    return 1;
}

/**
 * @brief Compare the page of modules returned by server DB to the specified Module data.
 *
 * This will compare each module object in the "page" returned by the server DB
 * with the specified Module. If a match is found, then the \p match parameter is set to 1
 * and the URL is copied.
 *
 * If a match is not found, then the function will allocate and copy the "next" page
 * URL into \p next_endpoint, which should be compared next.
 *
 * @param ctx ACVP_CTX
 * @param module Pointer to the module data which will be compared
 * @param match Pointer to int which will be set to 1 if match is found
 * @param next_endpoint The next page URL endpoint
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT match_modules_page(ACVP_CTX *ctx,
                                      ACVP_MODULE *module,
                                      int *match,
                                      char **next_endpoint) {
    ACVP_RESULT rv = 0;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL, *links_obj = NULL;
    JSON_Array *data_array = NULL;
    const char *next = NULL, *c_urls = NULL;
    int i = 0, data_count = 0;
    const char *aurl = NULL, *vurl = NULL, *name = NULL, *description = NULL, *type = NULL, *version = NULL;
    ACVP_MODULE *tmp_module = NULL;
    ACVP_VENDOR *tmp_vendor = NULL;

    if (!ctx) return ACVP_NO_CTX;
    if (module == NULL) {
        ACVP_LOG_ERR("Parameter 'module' must be non-NULL");
        return ACVP_INVALID_ARG;
    }
    if (match == NULL) {
        ACVP_LOG_ERR("Parameter 'match' must be non-NULL");
        return ACVP_INVALID_ARG;
    }
    *match = 0;

    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        ACVP_LOG_ERR("JSON parse error");
        return ACVP_JSON_ERR;
    }

    tmp_module = calloc(sizeof(ACVP_MODULE), sizeof(char));
    if (!tmp_module) {
        rv = ACVP_MALLOC_FAIL;
        goto end;
    }
    tmp_vendor = calloc(sizeof(ACVP_VENDOR), sizeof(char));
    if (!tmp_vendor) {
        rv = ACVP_MALLOC_FAIL;
        goto end;
    }

    obj = acvp_get_obj_from_rsp(ctx, val);
    if (!obj) {
        rv = ACVP_JSON_ERR;
        goto end;
    }

    data_array = json_object_get_array(obj, "data");
    data_count = json_array_get_count(data_array);

    for (i = 0; i < data_count; i++) {
        int this_match = 0, num_contacts = 0, k = 0;
        JSON_Array *contact_urls = NULL;
        JSON_Object *module_obj = json_array_get_object(data_array, i);

        memset_s(tmp_module, sizeof(ACVP_MODULE), 0, sizeof(ACVP_MODULE));
        memset_s(tmp_vendor, sizeof(ACVP_VENDOR), 0, sizeof(ACVP_VENDOR));
        if (module_obj == NULL)  {
            rv = ACVP_JSON_ERR;
            goto end;
        }

        // Soft copy 
        type = json_object_get_string(module_obj, "type");
        name = json_object_get_string(module_obj, "name");
        version = json_object_get_string(module_obj, "version");
        description = json_object_get_string(module_obj, "description");

        if (type) tmp_module->type = strdup(type);
        if (name) tmp_module->name = strdup(name);
        if (version) tmp_module->version = strdup(version);
        if (description) tmp_module->description = strdup(description);

        tmp_module->vendor = tmp_vendor;
        vurl = json_object_get_string(module_obj, "vendorUrl");
        aurl = json_object_get_string(module_obj, "addressUrl");
        if (vurl) tmp_vendor->url = strdup(vurl);
        if (aurl) tmp_vendor->address.url = strdup(aurl);

        /*
         * Construct the tmp_vendor->persons
         */
        contact_urls = json_object_get_array(module_obj, "contactUrls");
        if (contact_urls == NULL)  {
            ACVP_LOG_ERR("No contactUrls object");
            rv = ACVP_JSON_ERR;
            goto end;
        }

        num_contacts = json_array_get_count(contact_urls);
        if (num_contacts != module->vendor->persons.count ||
            num_contacts > LIBACVP_PERSONS_MAX) {
            /* Length of the contactsUrl array is different */
            continue;
        }

        for (k = 0; k < num_contacts; k++) {
            /*
             * Soft copy the array of contactUrls
             * Assume they are in same order.
             */
            c_urls = json_array_get_string(contact_urls, i);
            if (c_urls && (tmp_module->vendor != NULL)) {
                tmp_module->vendor->persons.person[k].url = strdup(c_urls);
            }
        }

        this_match = compare_modules(module, tmp_module);
        for (k = 0; k < num_contacts; k++) {
            if (tmp_module->vendor->persons.person[k].url) {
                free(tmp_module->vendor->persons.person[k].url);
            }
        }
        free(tmp_module->type);
        free(tmp_module->name);
        free(tmp_module->version);
        free(tmp_module->description);
        free(tmp_vendor->url);
        free(tmp_vendor->address.url);
        tmp_module->type = NULL;
        tmp_module->name = NULL;
        tmp_module->version = NULL;
        tmp_module->description = NULL;
        tmp_vendor->url = NULL;
        tmp_vendor->address.url = NULL;
        if (this_match) {
            /*
             * Found a match.
             * Copy the url and skip to end.
             */
            const char *url = json_object_get_string(module_obj, "url");
            if (url == NULL) {
                ACVP_LOG_ERR("JSON module object missing 'url'");
                rv = ACVP_JSON_ERR;
                goto end;
            }

            module->url = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
            if (module->url == NULL) {
                ACVP_LOG_ERR("Failed to malloc");
                rv = ACVP_MALLOC_FAIL;
                goto end;
            }

            strcpy_s(module->url, ACVP_ATTR_URL_MAX + 1, url);
            ACVP_LOG_INFO("Modules Match");
            *match = 1; 
            goto end;
        }
    }

    links_obj = json_object_get_object(obj, "links");
    if (links_obj == NULL) {
        ACVP_LOG_ERR("No links object");
        rv = ACVP_JSON_ERR;
        goto end;
    }
    if (*next_endpoint) {
        free (*next_endpoint);
        *next_endpoint = NULL;
    }
    
    next = json_object_get_string(links_obj, "nextPage");
    if (next) {
        // Copy the next page endpoint
        *next_endpoint = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
        if (*next_endpoint == NULL) {
            ACVP_LOG_ERR("Failed to malloc");
            rv = ACVP_MALLOC_FAIL;
            goto end;
        }
        strcpy_s(*next_endpoint, ACVP_ATTR_URL_MAX + 1, next);
    }

end:
    if (tmp_module) {
        if (tmp_module->type) free(tmp_module->type);
        if (tmp_module->name) free(tmp_module->name);
        if (tmp_module->version) free(tmp_module->version);
        if (tmp_module->description) free(tmp_module->description);
        free(tmp_module);
    }
    if (tmp_vendor) {
        if (tmp_vendor->url) free(tmp_vendor->url);
        if (tmp_vendor->address.url) free(tmp_vendor->address.url);
        free(tmp_vendor);
    }

    if (val) json_value_free(val);

    return rv;
}

/**
 * @brief Query the server DB for the specified Module data.
 *
 * This will query the server DB to ensure that the data exists, and it will retrieve
 * the Module URL.
 *
 * @param ctx ACVP_CTX
 * @param module Pointer to the module data which will be queried
 * @param endpoint The URL endpoint string
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT query_module(ACVP_CTX *ctx,
                                ACVP_MODULE *module,
                                const char *endpoint) {
    ACVP_RESULT rv = 0;
    ACVP_KV_LIST *parameters = NULL;
    char *first_endpoint = NULL, *next_endpoint = NULL;
    int match = 0;

    if (!ctx) return ACVP_NO_CTX;
    if (module == NULL) {
        ACVP_LOG_ERR("Parameter 'module' must be non-NULL");
        return ACVP_INVALID_ARG;
    }
    if (module->url) {
        /* This resource has already been verified as existing. */
        return ACVP_SUCCESS;
    }

    if (endpoint == NULL) {
        size_t vendor_url_len = 0;
        char *ptr = NULL, *ptr_old = NULL;

        first_endpoint = calloc(ACVP_ATTR_URL_MAX + 1, sizeof(char));
        if (first_endpoint == NULL) {
            ACVP_LOG_ERR("Failed to malloc");
            return ACVP_MALLOC_FAIL;
        }
        endpoint = first_endpoint;

        /* Prepare the first query. */
        snprintf(first_endpoint, ACVP_ATTR_URL_MAX, "%s%s",
                 ctx->path_segment, "modules?");

        if (module->name) {
            rv = acvp_kv_list_append(&parameters, "name[0]=eq:", module->name);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Failed acvp_kv_list_append()");
                goto end;
            }
        }

        if (module->type) {
            rv = acvp_kv_list_append(&parameters, "type[0]=eq:", module->type);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Failed acvp_kv_list_append()");
                goto end;
            }
        }

        if (module->version) {
            rv = acvp_kv_list_append(&parameters, "version[0]=eq:", module->version);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Failed acvp_kv_list_append()");
                goto end;
            }
        }

        if (module->description) {
            rv = acvp_kv_list_append(&parameters, "description[0]=eq:", module->description);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Failed acvp_kv_list_append()");
                goto end;
            }
        }

        /* Parse the vendorId */
        vendor_url_len = strnlen_s(module->vendor->url, ACVP_ATTR_URL_MAX);

        ptr = module->vendor->url;
        ptr_old = ptr;
        while (1) {
            int remaining_space = vendor_url_len - (ptr - ptr_old);

            strstr_s(ptr, remaining_space, "/", 1, &ptr);
            if (ptr == NULL) break;
            ptr_old = ptr;
            /* Need to move past this occurence */
            ptr += 1;
        }
        ptr = ptr_old; // The position of the last delimiter

        rv = acvp_kv_list_append(&parameters, "vendorId[0]=eq:", ptr + 1);
        if (ACVP_SUCCESS != rv) {
            ACVP_LOG_ERR("Failed acvp_kv_list_append()");
            goto end;
        }
    }

    do {
        /* Query the server DB. */
        if (parameters) {
            /* Use parameters and free them, as we get the next pages'
             * URLs from the server */
            rv = acvp_transport_get(ctx, endpoint, parameters);
            acvp_kv_list_free(parameters);
            parameters = NULL;
        } else {
            rv = acvp_transport_get(ctx, endpoint, NULL);
        }
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Unable to query Operating Environment");
            goto end;
        }

        /* Try to match against the page returned by server, iterate endpoint */
        rv = match_modules_page(ctx, module, &match, &next_endpoint);

        /* Only query the next page if we are within the limit */
        if (rv != ACVP_SUCCESS || match) {
           break;
        }
        
        endpoint = next_endpoint;
    } while (endpoint);
    
end:
    if (first_endpoint) free(first_endpoint);
    if (next_endpoint) free(next_endpoint);
    if (parameters) acvp_kv_list_free(parameters);

    return rv;
}

/**
 * @brief Verify the Module data which the user intends to send for a FIPS validation.
 *
 * This will query the server DB to ensure that the data exists, and it will retrieve
 * the Module URL along with all of its sub-object URLs. If the attached Vendor is not
 * successfully verified, then this function will fail (because it cannot be created during
 * the PUT operation).
 *
 * @param ctx ACVP_CTX Holds the fips.module
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT verify_fips_module(ACVP_CTX *ctx) {
    ACVP_RESULT rv = 0;

    if (!ctx) return ACVP_NO_CTX;

    /*
     * Query the Vendor first.
     */
    rv = query_vendor(ctx, ctx->fips.module->vendor, NULL);
    if (ACVP_SUCCESS != rv) {
        ACVP_LOG_ERR("Failed to query the Vendor(%u)", ctx->fips.module->vendor->id);
        return rv;
    }
    if (ctx->fips.module->vendor->url == NULL) {
        /*
         * The Vendor data does not exist on server DB.
         * It cannot be created during the PUT operation.
         * The user must create the Vendor using some other program
         * such as metadata.py
         */
        ACVP_LOG_ERR("The Vendor(%u) does not exist in server DB. Must create first!",
                     ctx->fips.module->vendor->id);
        return ACVP_INVALID_ARG;
    }

    /*
     * Query the module to verify sanity
     */
    rv = query_module(ctx, ctx->fips.module, NULL);
    if (ACVP_SUCCESS != rv) {
        ACVP_LOG_ERR("Unable to query the Module(%u)", ctx->fips.module->id);
        return rv;
    }

    return ACVP_SUCCESS;
}

/**
 * @brief Verify that the selected FIPS validation metadata is sane.
 *
 * If the Vendor and it's sub-objects are not found in the server DB,
 * then this function will return failure.
 *
 * If the Module or OE is not found in the server DB, then the client
 * will attempt to create this resource later on during the
 * PUT /testSessions/{testSessionId}.
 *
 * For the OE, any linked Dependencies not found will be created during
 * the PUT /testSessions/{testSessionId}. Conversely, any Dependencies that
 * are found will have their 'url' field set to a valid resource endpoint.
 *
 * @param ctx ACVP_CTX
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_oe_verify_fips_operating_env(ACVP_CTX *ctx) {
    ACVP_RESULT rv = 0;

    if (!ctx) return ACVP_NO_CTX;

    /*
     * Verify the Module.
     * This includes the linked Vendor.
     */
    rv = verify_fips_module(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to verify Vendor");
        return rv;
    }

    /*
     * Verify the OE.
     * This includes the linked Dependencies.
     */
    rv = verify_fips_oe(ctx);
    if (rv != ACVP_SUCCESS) {
        ACVP_LOG_ERR("Unable to verify Module");
        return rv;
    }

    return ACVP_SUCCESS;
}

/******************
 * ****************
 * Cleanup functions
 * ****************
 *****************/

static void free_phone_list(ACVP_OE_PHONE_LIST **phone_list) {
    ACVP_OE_PHONE_LIST *p = NULL;
    ACVP_OE_PHONE_LIST *tmp = NULL;

    if (phone_list == NULL) return;
    p = *phone_list;
    if (p == NULL) return;

    while (p) {
        if (p->number) free(p->number);
        if (p->type) free(p->type);
        tmp = p;
        p = p->next;
        free(tmp);
    }

    *phone_list = NULL;
}

static void free_dependencies(ACVP_DEPENDENCIES *dependencies) {
    unsigned int i = 0;

    for (i = 0; i < dependencies->count; i++) {
        ACVP_DEPENDENCY *dep = &dependencies->deps[i];
        if (dep->url) free(dep->url);
        if (dep->type) free(dep->type);
        if (dep->name) free(dep->name);
        if (dep->description) free(dep->description);
    }
}

static void free_oes(ACVP_OES *oes) {
    int i = 0;

    for (i = 0; i < oes->count; i++) {
        ACVP_OE *oe = &oes->oe[i];
        if (oe->name) free(oe->name);
        if (oe->url) free(oe->url);
    }
}

static void free_vendor_persons(ACVP_VENDOR *vendor) {
    ACVP_PERSONS *persons = &vendor->persons;
    int i = 0;

    for (i = 0; i < persons->count; i++) {
        ACVP_PERSON *person = &persons->person[i];

        if (person->url) free(person->url);
        if (person->full_name) free(person->full_name);
        acvp_free_str_list(&person->emails);
        free_phone_list(&person->phone_numbers);
    }
}

static void free_vendor_address(ACVP_VENDOR *vendor) {
    ACVP_VENDOR_ADDRESS *address = &vendor->address;

    if (address->street_1) free(address->street_1);
    if (address->street_2) free(address->street_2);
    if (address->street_3) free(address->street_3);
    if (address->locality) free(address->locality);
    if (address->region) free(address->region);
    if (address->country) free(address->country);
    if (address->postal_code) free(address->postal_code);
    if (address->url) free(address->url);
}

static void free_vendors(ACVP_VENDORS *vendors) {
    int i = 0;

    for (i = 0; i < vendors->count; i++) {
        ACVP_VENDOR *vendor = &vendors->v[i];

        if (vendor->url) free(vendor->url);
        if (vendor->name) free(vendor->name);
        if (vendor->website) free(vendor->website);
        acvp_free_str_list(&vendor->emails);
        free_phone_list(&vendor->phone_numbers);

        free_vendor_address(vendor);
        free_vendor_persons(vendor);
    }
}

static void free_modules(ACVP_MODULES *modules) {
    int i = 0;

    for (i = 0; i < modules->count; i++) {
        ACVP_MODULE *module = &modules->module[i];

        if (module->name) free(module->name);
        if (module->type) free(module->type);
        if (module->version) free(module->version);
        if (module->description) free(module->description);
        if (module->url) free(module->url);
    }
}

/**
 * @brief Free all of the memory associated with the Operating Environment.
 *
 * Frees anything under ctx->op_env
 *
 * @param ctx ACVP_CTX
 */
void acvp_oe_free_operating_env(ACVP_CTX *ctx) {
    if (ctx) {
        free_vendors(&ctx->op_env.vendors);
        free_modules(&ctx->op_env.modules);
        free_dependencies(&ctx->op_env.dependencies);
        free_oes(&ctx->op_env.oes);
    }
}

/******************
 * ****************
 * Metadata functions
 * ****************
 *****************/

/**
 * @brief Parse the Vendor.address from the JSON and load into library memory.
 *
 * @param ctx ACVP_CTX
 * @param obj The JSON object holding Vendor data.
 * @param vendor Pointer to the Vendor library struct.
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT acvp_oe_metadata_parse_vendor_address(ACVP_CTX *ctx,
                                                         JSON_Object *obj,
                                                         ACVP_VENDOR *vendor) {
    JSON_Object *a_obj = NULL;
    const char *street_1 = NULL, *street_2 = NULL, *street_3 = NULL,
               *locality = NULL, *region= NULL, *country = NULL,
               *postal_code = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) return ACVP_NO_CTX;
    if (!obj) {
        ACVP_LOG_ERR("Requried parameter 'obj' is NULL");
        return ACVP_INVALID_ARG;
    }
    if (!vendor) {
        ACVP_LOG_ERR("Requried parameter 'vendor' is NULL");
        return ACVP_INVALID_ARG;
    }

    a_obj = json_object_get_object(obj, "address");
    if (!a_obj) {
        ACVP_LOG_ERR("Json missing 'address'");
        return ACVP_MISSING_ARG;
    }

    street_1 = json_object_get_string(a_obj, "street1");
    street_2 = json_object_get_string(a_obj, "street2");
    street_3 = json_object_get_string(a_obj, "street3");
    locality = json_object_get_string(a_obj, "locality");
    region = json_object_get_string(a_obj, "region");
    country = json_object_get_string(a_obj, "country");
    postal_code = json_object_get_string(a_obj, "postalCode");

    rv = acvp_oe_vendor_add_address(ctx, vendor, street_1, street_2, street_3,
                                    locality, region, country, postal_code);
    if (ACVP_SUCCESS != rv) {
        ACVP_LOG_ERR("Failed to parse Vendor Address");
        return rv;
    }

    return ACVP_SUCCESS;
}

/**
 * @brief Parse the emails from the JSON and load into library memory.
 *
 * @param ctx ACVP_CTX
 * @param obj The JSON object holding emails.
 * @param email_list Pointer to the ACVP_STRING_LIST that will be constructed.
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT acvp_oe_metadata_parse_emails(ACVP_CTX *ctx,
                                                 JSON_Object *obj,
                                                 ACVP_STRING_LIST **email_list) {
    JSON_Array *emails_array = NULL;
    ACVP_STRING_LIST *email = NULL;
    int i = 0, count = 0;
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) return ACVP_NO_CTX;
    if (!obj) {
        ACVP_LOG_ERR("Requried parameter 'obj' is NULL");
        return ACVP_INVALID_ARG;
    }
    if (!email_list) {
        ACVP_LOG_ERR("Requried parameter 'email_list' is NULL");
        return ACVP_INVALID_ARG;
    }
    if (*email_list != NULL) {
        ACVP_LOG_ERR("Dereferencing parameter 'email_list' must be NULL");
        return ACVP_INVALID_ARG;
    }

    emails_array = json_object_get_array(obj, "emails");
    count = json_array_get_count(emails_array);
    if (emails_array && count) {
        for (i = 0; i < count; i++) {
            const char *email_str = json_array_get_string(emails_array, i);
            if (!email_str) {
                ACVP_LOG_ERR("Problem parsing email string from JSON");
                return ACVP_JSON_ERR;
            }

            if (i == 0) {
                *email_list = calloc(1, sizeof(ACVP_STRING_LIST));
                if (*email_list == NULL) return ACVP_MALLOC_FAIL;
                email = *email_list;
            } else {
                email->next = calloc(1, sizeof(ACVP_STRING_LIST));
                if (email->next == NULL) return ACVP_MALLOC_FAIL;
                email = email->next;
            }

            rv = copy_oe_string(&email->string, email_str);
            if (ACVP_INVALID_ARG == rv) {
                ACVP_LOG_ERR("'street' string too long");
                return rv;
            }
        }
    }

    return ACVP_SUCCESS;
}

/**
 * @brief Parse the phone numbers from the JSON and load into library memory.
 *
 * @param ctx ACVP_CTX
 * @param obj The JSON object holding phone numbers.
 * @param phone_list Pointer to ACVP_OE_PHONE_LIST that will be constructed.
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT acvp_oe_metadata_parse_phone_numbers(ACVP_CTX *ctx,
                                                        JSON_Object *obj,
                                                        ACVP_OE_PHONE_LIST **phone_list) {
    JSON_Array *phones_array = NULL;
    ACVP_OE_PHONE_LIST *phone = NULL;
    int i = 0, count = 0;
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) return ACVP_NO_CTX;
    if (!obj) {
        ACVP_LOG_ERR("Requried parameter 'obj' is NULL");
        return ACVP_INVALID_ARG;
    }
    if (!phone_list) {
        ACVP_LOG_ERR("Requried parameter 'phone_list' is NULL");
        return ACVP_INVALID_ARG;
    }
    if (*phone_list != NULL) {
        ACVP_LOG_ERR("Dereferencing parameter 'phone_list' must be NULL");
        return ACVP_INVALID_ARG;
    }

    phones_array = json_object_get_array(obj, "phoneNumbers");
    count = json_array_get_count(phones_array);
    if (phones_array && count) {
        for (i = 0; i < count; i++) {
            JSON_Object *phone_obj = NULL;
            const char *number_str = NULL, *type_str = NULL;

            phone_obj = json_array_get_object(phones_array, i);
            if (!phone_obj) {
                ACVP_LOG_ERR("Problem parsing phone object from JSON");
                return ACVP_JSON_ERR;
            }

            number_str = json_object_get_string(phone_obj, "number");
            if (!number_str) {
                ACVP_LOG_ERR("Problem parsing 'number' string from JSON");
                return ACVP_JSON_ERR;
            }

            type_str = json_object_get_string(phone_obj, "type");
            if (!type_str) {
                ACVP_LOG_ERR("Problem parsing 'type' string from JSON");
                return ACVP_JSON_ERR;
            }

            if (i == 0) {
                *phone_list = calloc(1, sizeof(ACVP_OE_PHONE_LIST));
                if (*phone_list == NULL) return ACVP_MALLOC_FAIL;
                phone = *phone_list;
            } else {
                phone->next = calloc(1, sizeof(ACVP_OE_PHONE_LIST));
                if (phone->next == NULL) return ACVP_MALLOC_FAIL;
                phone = phone->next;
            }

            rv = copy_oe_string(&phone->number, number_str);
            if (ACVP_INVALID_ARG == rv) {
                ACVP_LOG_ERR("'number' string too long");
                return rv;
            }
            rv = copy_oe_string(&phone->type, type_str);
            if (ACVP_INVALID_ARG == rv) {
                ACVP_LOG_ERR("'type' string too long");
                return rv;
            }
        }
    }

    return ACVP_SUCCESS;
}

/**
 * @brief Parse the Vendor contacts from the JSON and load into library memory.
 *
 * @param ctx ACVP_CTX
 * @param obj The JSON object holding contacts.
 * @param vendor Pointer to the ACVP_VENDOR struct.
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT acvp_oe_metadata_parse_vendor_contacts(ACVP_CTX *ctx,
                                                          JSON_Object *obj,
                                                          ACVP_VENDOR *vendor) {
    JSON_Array *contacts_array = NULL;
    int i = 0, count = 0;
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) return ACVP_NO_CTX;
    if (!obj) {
        ACVP_LOG_ERR("Requried parameter 'obj' is NULL");
        return ACVP_INVALID_ARG;
    }
    if (!vendor) {
        ACVP_LOG_ERR("Requried parameter 'vendor' is NULL");
        return ACVP_INVALID_ARG;
    }

    if (vendor->persons.count) {
        ACVP_LOG_ERR("Need to start with person.count == 0");
        return ACVP_INVALID_ARG;
    }

    contacts_array = json_object_get_array(obj, "contacts");
    count = json_array_get_count(contacts_array);
    if (count > LIBACVP_PERSONS_MAX) {
        ACVP_LOG_ERR("Number of contacts (%d) > max allowed (%d)", count, LIBACVP_PERSONS_MAX);
        return ACVP_JSON_ERR;
    }
    if (count == 0) {
        ACVP_LOG_ERR("Need at least 1 contact");
        return ACVP_JSON_ERR;
    }

    for (i = 0; i < count; i++) {
        const char *name_str = NULL;
        ACVP_PERSON *person = &vendor->persons.person[i];
        JSON_Object *contact_obj = json_array_get_object(contacts_array, i);
        if (!contact_obj) {
            ACVP_LOG_ERR("Problem parsing 'contact' object from JSON");
            return ACVP_JSON_ERR;
        }

        /* Increment (in case of error below, we will still cleanup) */
        vendor->persons.count++;

        name_str = json_object_get_string(contact_obj, "fullName");
        if (!name_str) {
            ACVP_LOG_ERR("Problem parsing 'fullName' string from JSON");
            return ACVP_JSON_ERR;
        }
        rv = copy_oe_string(&person->full_name, name_str);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'fullName' string too long");
            return rv;
        }

        /* Parse the Emails (if it exists)*/
        rv = acvp_oe_metadata_parse_emails(ctx, contact_obj, &person->emails);
        if (ACVP_SUCCESS != rv) return rv;

        /* Parse the Phone Numbers (if it exists)*/
        rv = acvp_oe_metadata_parse_phone_numbers(ctx, contact_obj, &person->phone_numbers);
        if (ACVP_SUCCESS != rv) return rv;
    }

    return ACVP_SUCCESS;
}

/**
 * @brief Parse the Vendor from the JSON and load into library memory.
 *
 * @param ctx ACVP_CTX
 * @param obj The JSON object holding Vendor data.
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT acvp_oe_metadata_parse_vendor(ACVP_CTX *ctx, JSON_Object *obj) {
    ACVP_VENDOR *vendor = NULL;
    const char *name = NULL, *website = NULL;
    int id = 0;
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) return ACVP_NO_CTX;
    if (!obj) {
        ACVP_LOG_ERR("Requried parameter 'obj' is NULL");
        return ACVP_INVALID_ARG;
    } 

    id = glb_vendor_id;
    glb_vendor_id++;

    name = json_object_get_string(obj, "name");
    if (!name) {
        ACVP_LOG_ERR("Metadata JSON missing 'name'");
        return ACVP_INVALID_ARG;
    }

    /* Designate and init new Vendor struct */
    rv = acvp_oe_vendor_new(ctx, id, name);
    if (rv != ACVP_SUCCESS) return rv;

    /* Get pointer to the new vendor */
    vendor = find_vendor(ctx, id);
    if (!vendor) return ACVP_INVALID_ARG;

    website = json_object_get_string(obj, "website");
    if (website) {
        /* Copy the "website" */
        rv = copy_oe_string(&vendor->website, website);
        if (ACVP_INVALID_ARG == rv) {
            ACVP_LOG_ERR("'website' string too long");
            return rv;
        }
    }

    /* Parse the Emails (if it exists) */
    rv = acvp_oe_metadata_parse_emails(ctx, obj, &vendor->emails);
    if (ACVP_SUCCESS != rv) return rv;

    /* Parse the Phone Numbers (if it exists) */
    rv = acvp_oe_metadata_parse_phone_numbers(ctx, obj, &vendor->phone_numbers);
    if (ACVP_SUCCESS != rv) return rv;

    /* Parse the Address */
    rv = acvp_oe_metadata_parse_vendor_address(ctx, obj, vendor);
    if (ACVP_SUCCESS != rv) return rv;

    /* Parse the Contacts */
    rv = acvp_oe_metadata_parse_vendor_contacts(ctx, obj, vendor);
    if (ACVP_SUCCESS != rv) return rv;

    return ACVP_SUCCESS;
}

/**
 * @brief Parse the array of Vendors from the JSON and load into library memory.
 *
 * @param ctx ACVP_CTX
 * @param obj The JSON object holding the array of Vendors.
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT acvp_oe_metadata_parse_vendors(ACVP_CTX *ctx, JSON_Object *obj) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Array *vendors_array = NULL;
    int i = 0, vendors_count = 0;

    if (!ctx) return ACVP_NO_CTX;
    if (!obj) {
        ACVP_LOG_ERR("Requried parameter 'obj' is NULL");
        return ACVP_INVALID_ARG;
    }

    vendors_array = json_object_get_array(obj, "vendors");
    if (!vendors_array) {
        ACVP_LOG_ERR("Unable to resolve the 'vendors' array");
        return ACVP_JSON_ERR;
    }

    vendors_count = json_array_get_count(vendors_array);
    if (vendors_count == 0) {
        ACVP_LOG_ERR("Need at least one object in the 'vendors' array");
        return ACVP_MALFORMED_JSON;
    }
    for (i = 0; i < vendors_count; i++) {
        JSON_Object *vendor_obj = json_array_get_object(vendors_array, i);
        if (!vendor_obj) {
            ACVP_LOG_ERR("Unable to parse object at 'vendors'[%d]", i);
            return ACVP_JSON_ERR;
        }

        rv = acvp_oe_metadata_parse_vendor(ctx, vendor_obj);
        if (ACVP_SUCCESS != rv) return rv; /* Fail */
    }

    /* Success */
    return ACVP_SUCCESS;
}

/**
 * @brief Parse the Module from the JSON and load into library memory.
 *
 * @param ctx ACVP_CTX
 * @param obj The JSON object holding the Module data.
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT acvp_oe_metadata_parse_module(ACVP_CTX *ctx, JSON_Object *obj) {
    const char *name = NULL, *version = NULL, *type = NULL, *description = NULL;
    int module_id = 0;
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) return ACVP_NO_CTX;
    if (!obj) {
        ACVP_LOG_ERR("Requried parameter 'obj' is NULL");
        return ACVP_INVALID_ARG;
    } 

    module_id = glb_module_id;
    glb_module_id++;
    name = json_object_get_string(obj, "name");
    if (!name) {
        ACVP_LOG_ERR("Metadata JSON missing 'name'");
        return ACVP_INVALID_ARG;
    }

    /* Designate and init new Module struct */
    rv = acvp_oe_module_new(ctx, module_id, name);
    if (rv != ACVP_SUCCESS) return rv;

    type = json_object_get_string(obj, "type");
    version = json_object_get_string(obj, "version");
    description = json_object_get_string(obj, "description");

    rv = acvp_oe_module_set_type_version_desc(ctx, module_id, type, version, description);
    if (ACVP_SUCCESS != rv) return rv;

    return ACVP_SUCCESS;
}

/**
 * @brief Parse the array of Modules from the JSON and load into library memory.
 *
 * @param ctx ACVP_CTX
 * @param obj The JSON object holding the array of Modules.
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT acvp_oe_metadata_parse_modules(ACVP_CTX *ctx, JSON_Object *obj) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Array *modules_array = NULL;
    int i = 0, modules_count = 0;

    if (!ctx) return ACVP_NO_CTX;
    if (!obj) {
        ACVP_LOG_ERR("Requried parameter 'obj' is NULL");
        return ACVP_INVALID_ARG;
    }

    modules_array = json_object_get_array(obj, "modules");
    if (!modules_array) {
        ACVP_LOG_ERR("Unable to resolve the 'modules' array");
        return ACVP_JSON_ERR;
    }

    modules_count = json_array_get_count(modules_array);
    /* 
     * Not required to be in the metadata file.
     * The user can specify modules via libacvp API.
     */
    if (modules_count == 0) return ACVP_SUCCESS; 

    for (i = 0; i < modules_count; i++) {
        JSON_Object *module_obj = json_array_get_object(modules_array, i);
        if (!module_obj) {
            ACVP_LOG_ERR("Unable to parse object at 'modules'[%d]", i);
            return ACVP_JSON_ERR;
        }

        rv = acvp_oe_metadata_parse_module(ctx, module_obj);
        if (ACVP_SUCCESS != rv) return rv; /* Fail */
    }

    /* Success */
    return ACVP_SUCCESS;
}

static unsigned int match_dependency(ACVP_CTX *ctx, const ACVP_DEPENDENCY *dep) {
    unsigned int i = 0;

    if (!ctx) return 0;
    if (dep == NULL) {
        ACVP_LOG_ERR("Required parameter 'dep' must be non-NULL");
        return 0;
    }

    if (ctx->op_env.dependencies.count == 0) return 0;

    for (i = 0; i < ctx->op_env.dependencies.count; i++) {
        ACVP_DEPENDENCY *this_dep = &ctx->op_env.dependencies.deps[i];
        int match = 0;

        match = compare_dependencies(dep, this_dep);
        if (match) return dep->id;
    }

    return 0;
}

/**
 * @brief Parse the array of Dependencies from the JSON and load into library memory.
 *
 * @param ctx ACVP_CTX
 * @param obj The JSON object holding the array of Dependencies
 * @param oe_id The ID of the ACVP_OE that the dependencies will be saved into
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT acvp_oe_metadata_parse_oe_dependencies(ACVP_CTX *ctx,
                                                          JSON_Object *obj,
                                                          unsigned int oe_id) {
    ACVP_DEPENDENCY *dep = NULL;
    JSON_Array *deps_array = NULL;
    int i = 0, count = 0;
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) return ACVP_NO_CTX;
    if (!obj) {
        ACVP_LOG_ERR("Requried parameter 'obj' is NULL");
        return ACVP_INVALID_ARG;
    }

    deps_array = json_object_get_array(obj, "dependencies");
    if (!deps_array) {
        ACVP_LOG_ERR("Missing 'dependencies' array in JSON");
        return ACVP_JSON_ERR;
    }
    count = json_array_get_count(deps_array);
    if (!count) {
        ACVP_LOG_ERR("Requires at least 1 item in 'dependencies' array JSON");
        return ACVP_JSON_ERR;
    }

    for (i = 0; i < count; i++) {
        ACVP_DEPENDENCY tmp_dep = {0, 0, 0, 0, 0, 0, 0, 0, 0};
        const char *type_str = NULL, *name_str = NULL, *desc_str = NULL;
        const char *family_str = NULL, *series_str = NULL, *version_str = NULL;
        const char *man_str = NULL;
        JSON_Object *dep_obj = json_array_get_object(deps_array, i);
        unsigned int dep_id = 0;

        type_str = json_object_get_string(dep_obj, "type");
        name_str = json_object_get_string(dep_obj, "name");
        desc_str = json_object_get_string(dep_obj, "description");
        family_str = json_object_get_string(dep_obj, "family");
        series_str = json_object_get_string(dep_obj, "series");
        man_str = json_object_get_string(dep_obj, "manufacturer");
        version_str = json_object_get_string(dep_obj, "version");

        if (!type_str && !name_str && !desc_str) {
            ACVP_LOG_ERR("Need at least 1 of type, name, description");
            return ACVP_JSON_ERR;
        }

        // Soft copy, no need to free
        if (type_str) {
            tmp_dep.type = strdup(type_str);
        }
        if (name_str) {
            tmp_dep.name = strdup(name_str);
        }
        if (desc_str) {
            tmp_dep.description = strdup(desc_str);
        }
        if (family_str) {
            tmp_dep.family = strdup(family_str);
        }
        if (version_str) {
            tmp_dep.version = strdup(version_str);
        }
        if (series_str) {
            tmp_dep.series = strdup(series_str);
        }
        if (man_str) {
            tmp_dep.manufacturer = strdup(man_str);
        }


        dep_id = match_dependency(ctx, &tmp_dep);
        free(tmp_dep.type);
        free(tmp_dep.name);
        free(tmp_dep.description);
        free(tmp_dep.manufacturer);
        free(tmp_dep.version);
        free(tmp_dep.series);
        free(tmp_dep.family);
        if (dep_id == 0) {
            /*
             * We didn't find a Dependency in memory that matches exactly.
             * Make a new one!
             */
            dep_id = glb_dependency_id;

            rv = acvp_oe_dependency_new(ctx, dep_id);
            if (ACVP_SUCCESS != rv) {
                ACVP_LOG_ERR("Failed to create new Dependency");
                return rv;
            }

            dep = find_dependency(ctx, dep_id);
            if (!dep) {
                rv = ACVP_INVALID_ARG;
                return rv;
            }

            if (type_str) {
                rv = acvp_oe_dependency_set_field(ctx, DEPENDENCY_FIELD_TYPE, dep_id, type_str);
                if (ACVP_SUCCESS != rv) return rv;
            }

            if (name_str) {
                rv = acvp_oe_dependency_set_field(ctx, DEPENDENCY_FIELD_NAME, dep_id, name_str);
                if (ACVP_SUCCESS != rv) return rv;
            }

            if (desc_str) {
                rv = acvp_oe_dependency_set_field(ctx, DEPENDENCY_FIELD_DESC, dep_id, desc_str);
                if (ACVP_SUCCESS != rv) return rv;
            }

            if (man_str) {
                rv = acvp_oe_dependency_set_field(ctx, DEPENDENCY_FIELD_MAN, dep_id, man_str);
                if (ACVP_SUCCESS != rv) return rv;
            }

            if (version_str) {
                rv = acvp_oe_dependency_set_field(ctx, DEPENDENCY_FIELD_VERSION, dep_id, version_str);
                if (ACVP_SUCCESS != rv) return rv;
            }

            if (family_str) {
                rv = acvp_oe_dependency_set_field(ctx, DEPENDENCY_FIELD_FAMILY, dep_id, family_str);
                if (ACVP_SUCCESS != rv) return rv;
            }

            if (series_str) {
                rv = acvp_oe_dependency_set_field(ctx, DEPENDENCY_FIELD_SERIES, dep_id, series_str);
                if (ACVP_SUCCESS != rv) return rv;
            }



            /* Increment Global dependency ID*/
            glb_dependency_id++;
        }

        /* Add the Dependency to the OE */
        acvp_oe_oe_set_dependency(ctx, oe_id, dep_id);
    }
    return rv;
}

/**
 * @brief Parse the Operating Environment from the JSON and load into library memory.
 *
 * @param ctx ACVP_CTX
 * @param obj The JSON object holding the Operating Environment data
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT acvp_oe_metadata_parse_oe(ACVP_CTX *ctx, JSON_Object *obj) {
    const char *name = NULL;
    int oe_id = 0;
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) return ACVP_NO_CTX;
    if (!obj) {
        ACVP_LOG_ERR("Requried parameter 'obj' is NULL");
        return ACVP_INVALID_ARG;
    } 

    oe_id = glb_oe_id;
    glb_oe_id++;

    name = json_object_get_string(obj, "name");
    if (!name) {
        ACVP_LOG_ERR("Metadata JSON missing 'name'");
        return ACVP_INVALID_ARG;
    }

    /* Designate and init new OE struct */
    rv = acvp_oe_oe_new(ctx, oe_id, name);
    if (rv != ACVP_SUCCESS) return rv;

    /*
     * Parse the dependencies
     */
    rv = acvp_oe_metadata_parse_oe_dependencies(ctx, obj, oe_id);
    if (ACVP_SUCCESS != rv) return rv;

    return ACVP_SUCCESS;
}

/**
 * @brief Parse the array of Operating Environment from the JSON and load into library memory.
 *
 * @param ctx ACVP_CTX
 * @param obj The JSON object holding the array of Operating Environment data
 *
 * @return ACVP_RESULT
 */
static ACVP_RESULT acvp_oe_metadata_parse_oes(ACVP_CTX *ctx, JSON_Object *obj) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    JSON_Array *oes_array = NULL;
    int i = 0, oes_count = 0;

    if (!ctx) return ACVP_NO_CTX;
    if (!obj) {
        ACVP_LOG_ERR("Requried parameter 'obj' is NULL");
        return ACVP_INVALID_ARG;
    }

    oes_array = json_object_get_array(obj, "operating_environments");
    if (!oes_array) {
        ACVP_LOG_ERR("Unable to resolve the 'operating_environments' array");
        return ACVP_JSON_ERR;
    }

    oes_count = json_array_get_count(oes_array);
    /* 
     * Not required to be in the metadata file.
     * The user can specify oes via libacvp API.
     */
    if (oes_count == 0) return ACVP_SUCCESS; 

    for (i = 0; i < oes_count; i++) {
        JSON_Object *oe_obj = json_array_get_object(oes_array, i);
        if (!oe_obj) {
            ACVP_LOG_ERR("Unable to parse object at 'operating_environments'[%d]", i);
            return ACVP_JSON_ERR;
        }

        rv = acvp_oe_metadata_parse_oe(ctx, oe_obj);
        if (ACVP_SUCCESS != rv) return rv; /* Fail */
    }

    /* Success */
    return ACVP_SUCCESS;
}

/**
 * @brief Load the operating environment metadata from a JSON file.
 *
 * This metadata MUST be provided by the user when attempting to do a
 * FIPS validation. This function will fail if the file cannot be found.
 * The function will fail if the JSON is not properly formatted according
 * to the instructions.
 *
 * @param ctx ACVP_CTX
 * @param metadata_file The absolute path to JSON file holding the Operating Environment data
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_oe_ingest_metadata(ACVP_CTX *ctx, const char *metadata_file) {
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (!ctx) return ACVP_NO_CTX;
    if (!metadata_file) {
        ACVP_LOG_ERR("Must provide string value for 'metadata_file'");
        return ACVP_MISSING_ARG;
    }

    if (strnlen_s(metadata_file, ACVP_JSON_FILENAME_MAX + 1) > ACVP_JSON_FILENAME_MAX) {
        ACVP_LOG_ERR("Provided 'metadata_file' string length > max(%d)", ACVP_JSON_FILENAME_MAX);
        return ACVP_INVALID_ARG;
    }

    val = json_parse_file(metadata_file);
    if (!val) {
        ACVP_LOG_ERR("Failed to parse JSON in metadata file");
        return ACVP_JSON_ERR;
    }
    obj = json_value_get_object(val);
    if (!obj) {
        ACVP_LOG_ERR("Failed to parse JSON object in metadata file");
        rv = ACVP_JSON_ERR;
        goto end;
    }

    rv = acvp_oe_metadata_parse_vendors(ctx, obj);
    if (ACVP_SUCCESS != rv) {
        ACVP_LOG_ERR("Failed to parse 'vendors' from metadata JSON");
        goto end;
    }

    rv = acvp_oe_metadata_parse_modules(ctx, obj);
    if (ACVP_SUCCESS != rv) {
        ACVP_LOG_ERR("Failed to parse 'modules' from metadata JSON");
        goto end;
    }

    rv = acvp_oe_metadata_parse_oes(ctx, obj);
    if (ACVP_SUCCESS != rv) {
        ACVP_LOG_ERR("Failed to parse 'operating_environments' from metadata JSON");
        goto end;
    }

    /*
     * The metadata is loaded into memory.
     * It must be verified before running a validation on a testSession.
     */
    ctx->fips.metadata_loaded = 1;

end:
    if (val) json_value_free(val);

    return rv;
}

/**
 * @brief Specify which Operating Environment and Module to use for a FIPS validation.
 *
 * This metadata MUST have already been loaded, either by acvp_oe_ingest_metadata and/or
 * the proper library API.
 *
 * This function will fail if the \p module_id or \p oe_id are not valid.
 * The user may choose to invoke this function with both \p module_id and \p oe_id or
 * each of them seperately so long as the pair is eventually set. I.e. \p module_id for
 * first invocation then \p oe_id for the second invocation.
 *
 * This function can be invoked in order to change either \p module_id or \p oe_id after
 * they have been set previously in order to do a FIPS validation with different metadata
 * without the need to exit program.
 *
 * @param ctx ACVP_CTX
 * @param module_id The ID of the Module
 * @param oe_id The ID of the Operating Environment
 *
 * @return ACVP_RESULT
 */
ACVP_RESULT acvp_oe_set_fips_validation_metadata(ACVP_CTX *ctx,
                                                 unsigned int module_id,
                                                 unsigned int oe_id) {
    ACVP_MODULE *module = NULL;
    ACVP_OE *oe = NULL;

    if (ctx == NULL) return ACVP_NO_CTX;

    /*
     * Check that everything needed for the FIPS validation is sane.
     */
    if (!ctx->fips.metadata_loaded) {
        ACVP_LOG_ERR("User needs to load a valid metadata JSON file via acvp_oe_ingest_metadata()");
        return ACVP_INVALID_ARG;
    }

    if (module_id == 0 && oe_id == 0) {
        ACVP_LOG_ERR("Required parameters 'module_id' and 'oe_id' both == 0."
                     "At least one parameter must be non-zero");
        return ACVP_INVALID_ARG;
    }

    if (module_id) {
        module = find_module(ctx, module_id);
        if (module == NULL) {
            ACVP_LOG_ERR("Failed to find module with id(%u)", module_id);
            return ACVP_INVALID_ARG;
        }

        // Set the Module for the validation
        ctx->fips.module = module;
    }

    if (oe_id) {
        oe = find_oe(ctx, oe_id);
        if (oe == NULL) {
            ACVP_LOG_ERR("Failed to find oe with id(%u)", oe_id);
            return ACVP_INVALID_ARG;
        }

        // Set the OE for the validation
        ctx->fips.oe = oe;
    }

    return ACVP_SUCCESS;
}

