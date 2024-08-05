/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"
#include "implementations/openssl/3/iut.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"

#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#ifndef OPENSSL_VERSION_TEXT
#define OPENSSL_VERSION_TEXT "not detected"
#endif

int fips_ver = 0;
int dsa_disabled = 0;
int max_ldt_size = 0;

void iut_print_version(APP_CONFIG *cfg) {
    const char *str = NULL;
    printf(" Compiled SSL version: %s\n", OPENSSL_VERSION_TEXT);
    printf("   Linked SSL version: %s\n\n", OpenSSL_version(OPENSSL_VERSION));

    if (!cfg->disable_fips) {
        printf("       FIPS requested: yes\n");
        /* Get the FIPS provider version number */
        str = get_provider_version("OpenSSL FIPS Provider");
        if (!str) {
           printf("Error: Unable to detect FIPS provider version; please ensure it is configured properly\n");
        } else {
            printf("FIPS Provider Version: %s\n", get_provider_version(FIPS_PROVIDER_LOOKUP_NAME));
        }
    } else {
        printf("       FIPS requested: no\n");
    }
}

ACVP_RESULT iut_cleanup() {
    app_aes_cleanup();
    app_des_cleanup();
    app_dsa_cleanup();
    app_rsa_cleanup();
    app_ecdsa_cleanup();

    return ACVP_SUCCESS;
}

/**
 * Enable fips if applicable, run sanity check, check if certain algs disabled, call the correct
 * registration for linked FP
 */
ACVP_RESULT iut_setup(APP_CONFIG *cfg) {
    const char *ver_str = NULL;
    ACVP_RESULT rv = -1;

    if (!cfg->disable_fips) {
        /* sets the property "fips=yes" to be included implicitly in cipher fetches */
        EVP_default_properties_enable_fips(NULL, 1);
        if (!EVP_default_properties_is_fips_enabled(NULL)) {
            printf("Error setting FIPS property at startup\n\n");
            return 1;
        }
        /* Run a quick sanity check to determine that the FIPS provider is functioning properly */
        rv = fips_sanity_check();
        if (rv != ACVP_SUCCESS) {
            printf("Error occured when testing FIPS at startup (rv = %d). Please verify the FIPS provider is\n", rv);
            printf("properly installed and configured. Exiting...\n\n");
            return 1;
        }

        ver_str = get_provider_version("OpenSSL FIPS Provider");
        fips_ver = provider_ver_str_to_int(ver_str);
        if (fips_ver < 0) {
            printf("Error getting FIPS provider version number\n");
            return ACVP_INTERNAL_ERR;
        }
    } else {
        printf("***********************************************************************************\n");
        printf("* WARNING: You have chosen to not fetch the FIPS provider for this run. Any tests *\n");
        printf("* created or performed during this run MUST NOT have any validation requested     *\n");
        printf("* on it. Proceed at your own risk. Continuing in 5 seconds...                     *\n");
        printf("***********************************************************************************\n");
        printf("\n");
        acvp_sleep(5);
    }

    /* Check if the provider has DSA disabled; other conditional algorithm flags can be checked here in the future if needed */
    //TODO
    max_ldt_size = cfg->max_ldt_size;
    rv = ACVP_SUCCESS;
    return rv;
}

ACVP_RESULT iut_register_capabilities(ACVP_CTX *ctx, APP_CONFIG *cfg) {
    if (!fips_ver) {
        return register_capabilities_non_fips(ctx, cfg);
    } else if (fips_ver <= OPENSSL_FIPS_309) {
        /* 3.0.X registrations are so nearly identical, we left them combined. */
        return register_capabilities_fp_30X(ctx, cfg);
    } else if (fips_ver >= OPENSSL_FIPS_312) {
        return register_capabilities_fp_312(ctx, cfg);
    } else {
        return ACVP_INTERNAL_ERR;
    }
}
