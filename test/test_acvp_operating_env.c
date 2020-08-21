/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include "ut_common.h"
#include "acvp/acvp_lcl.h"

char *server;
int port;
char *ca_chain_file;
char *cert_file;
char *key_file;
char *path_segment;
char *api_context;
static ACVP_CTX *ctx = NULL;
ACVP_RESULT rv;


static void setup(void) {
    setup_empty_ctx(&ctx);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
    ctx = NULL;
}

/*
 * Test  acvp_oe_free_operating_env
 */
Test(FREE_OPERATING_ENV, free_operating_env, .init = setup, .fini = teardown) {

    acvp_oe_free_operating_env(NULL);
    acvp_oe_free_operating_env(ctx);
}

/*
 * Test  acvp_oe_ingest_metadata
 */
Test(INGEST_METADATA, ingest_metadata, .init = setup, .fini = teardown) {

    rv = acvp_oe_ingest_metadata(NULL, "json/meta.json");
    cr_assert(rv == ACVP_NO_CTX);

    rv = acvp_oe_ingest_metadata(ctx, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);

    rv = acvp_oe_ingest_metadata(ctx, "invalid.json");
    cr_assert(rv == ACVP_JSON_ERR);

    rv = acvp_oe_ingest_metadata(ctx, "json/meta.json");
    cr_assert(rv == ACVP_SUCCESS);

}

/*
 * Test  acvp_oe_set_fips_validation_metadata
 */
Test(FIPS_VALIDATION_METADATA, set_fips_validation_metadata, .init = setup, .fini = teardown) {


    rv = acvp_oe_set_fips_validation_metadata(NULL, 1, 1);
    cr_assert(rv == ACVP_NO_CTX);

    rv = acvp_oe_set_fips_validation_metadata(ctx, 1, 1);
    cr_assert(rv == ACVP_INVALID_ARG);

    rv = acvp_oe_set_fips_validation_metadata(ctx, 0, 0);
    cr_assert(rv == ACVP_INVALID_ARG);

    rv = acvp_oe_set_fips_validation_metadata(ctx, 1, 0);
    cr_assert(rv == ACVP_INVALID_ARG);

    rv = acvp_oe_set_fips_validation_metadata(ctx, 0, 1);
    cr_assert(rv == ACVP_INVALID_ARG);

}

/*
 * Test  acvp_oe_verify_fips_operating_env
 */
Test(VERIFY_FIPS_OPERATING_ENV, verify_fips_operating_env, .init = setup, .fini = teardown) {

    rv = acvp_oe_verify_fips_operating_env(NULL);
    cr_assert(rv == ACVP_NO_CTX);

    rv = acvp_oe_ingest_metadata(ctx, "json/meta.json");
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_oe_set_fips_validation_metadata(ctx, 1, 1);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_oe_verify_fips_operating_env(ctx);
#ifdef ACVP_OFFLINE
    cr_assert(rv == ACVP_TRANSPORT_FAIL);
#else
    cr_assert(rv == ACVP_MISSING_ARG);
#endif
}

/*
 * Test  acvp_oe_dependency_new
 */
Test(DEPENDENCY_NEW, dependency_new, .init = setup, .fini = teardown) {

    rv = acvp_oe_dependency_new(NULL, 1);
    cr_assert(rv == ACVP_NO_CTX);

    rv = acvp_oe_dependency_new(ctx, 0);
    cr_assert(rv == ACVP_INVALID_ARG);

    rv = acvp_oe_dependency_new(ctx, 1);
    cr_assert(rv == ACVP_SUCCESS);

}


/*
 * Test  acvp_oe_oe_new
 */
Test(OE_NEW, oe_new, .init = setup, .fini = teardown) {

    rv = acvp_oe_oe_new(NULL, 1, "name");
    cr_assert(rv == ACVP_NO_CTX);

    rv = acvp_oe_oe_new(ctx, 0, "name");
    cr_assert(rv == ACVP_INVALID_ARG);

    rv = acvp_oe_oe_new(ctx, 1, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);

    rv = acvp_oe_oe_new(ctx, 1, "name");
    cr_assert(rv == ACVP_SUCCESS);

}

/*
 * Test  acvp_oe_oe_set_dependency
 */
Test(OE_SET_DEPENDENCY, oe_set_dependency, .init = setup, .fini = teardown) {

    rv = acvp_oe_oe_set_dependency(NULL, 1, 1);
    cr_assert(rv == ACVP_NO_CTX);

    rv = acvp_oe_oe_set_dependency(ctx, 1, 1);
    cr_assert(rv == ACVP_INVALID_ARG);

}

/*
 * Test  acvp_oe_module_new
 */
Test(MODULE_NEW, module_new, .init = setup, .fini = teardown) {

    rv = acvp_oe_module_new(NULL, 1, "name");
    cr_assert(rv == ACVP_NO_CTX);

    rv = acvp_oe_module_new(ctx, 1, "name");
    cr_assert(rv == ACVP_INVALID_ARG);

}

/*
 * Test  acvp_oe_module_set_type_version_desc
 */
Test(MODULE_SET_TYPE_VERSION_DESC, module_set_type_version_desc, .init = setup, .fini = teardown) {

    rv = acvp_oe_module_set_type_version_desc(NULL, 1, "type", "ver", "desc");
    cr_assert(rv == ACVP_NO_CTX);

    rv = acvp_oe_module_set_type_version_desc(ctx, 1, "type", "ver", "desc");
    cr_assert(rv == ACVP_INVALID_ARG);

}
