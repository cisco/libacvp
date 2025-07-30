/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"
#include "implementations/liboqs/iut.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"

#include <oqs/common.h>

void iut_print_version(APP_CONFIG *cfg) {
    if (!cfg) {
        printf("Error: missing app_config in version request\n");
        return;
    }
    printf("liboqs version: %s\n", OQS_version());

}

ACVP_RESULT iut_cleanup() {
    iut_ml_kem_cleanup();
    return ACVP_SUCCESS;
}


ACVP_RESULT iut_setup(APP_CONFIG *cfg) {
    if (!cfg) {
        printf("Error: missing app_config in IUT setup request\n");
        return ACVP_MISSING_ARG;
    }
    return ACVP_SUCCESS;
}

ACVP_RESULT iut_register_capabilities(ACVP_CTX *ctx, APP_CONFIG *cfg) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    if (cfg->ml_kem || cfg->testall) {
        rv = acvp_enable_algorithm(ctx, ACVP_ML_KEM_KEYGEN, &app_ml_kem_handler);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_kem_set_parm(ctx, ACVP_ML_KEM_KEYGEN, ACVP_ML_KEM_PARAM_PARAMETER_SET, ACVP_ML_KEM_PARAM_SET_ML_KEM_512);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_kem_set_parm(ctx, ACVP_ML_KEM_KEYGEN, ACVP_ML_KEM_PARAM_PARAMETER_SET, ACVP_ML_KEM_PARAM_SET_ML_KEM_768);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_kem_set_parm(ctx, ACVP_ML_KEM_KEYGEN, ACVP_ML_KEM_PARAM_PARAMETER_SET, ACVP_ML_KEM_PARAM_SET_ML_KEM_1024);
        CHECK_ENABLE_CAP_RV(rv);

        rv = acvp_enable_algorithm(ctx, ACVP_ML_KEM_XCAP, &app_ml_kem_handler);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_kem_set_parm(ctx, ACVP_ML_KEM_XCAP, ACVP_ML_KEM_PARAM_PARAMETER_SET, ACVP_ML_KEM_PARAM_SET_ML_KEM_512);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_kem_set_parm(ctx, ACVP_ML_KEM_XCAP, ACVP_ML_KEM_PARAM_PARAMETER_SET, ACVP_ML_KEM_PARAM_SET_ML_KEM_768);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_kem_set_parm(ctx, ACVP_ML_KEM_XCAP, ACVP_ML_KEM_PARAM_PARAMETER_SET, ACVP_ML_KEM_PARAM_SET_ML_KEM_1024);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_kem_set_parm(ctx, ACVP_ML_KEM_XCAP, ACVP_ML_KEM_PARAM_FUNCTION, ACVP_ML_KEM_FUNCTION_ENCAPSULATE);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_kem_set_parm(ctx, ACVP_ML_KEM_XCAP, ACVP_ML_KEM_PARAM_FUNCTION, ACVP_ML_KEM_FUNCTION_DECAPSULATE);
        CHECK_ENABLE_CAP_RV(rv);
    }

    /**
     * Based on test_acvp_vectors.py in liboqs, we should be able to test keygen, internal interfaces with internal MU,
     * or external interfaces without prehash mode. Should support deterministic and non-deterministic modes.
     */
    if (cfg->ml_dsa || cfg->testall) {
        rv = acvp_enable_algorithm(ctx, ACVP_ML_DSA_KEYGEN, &app_ml_dsa_handler);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_KEYGEN, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET, ACVP_ML_DSA_PARAM_SET_ML_DSA_44);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_KEYGEN, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET, ACVP_ML_DSA_PARAM_SET_ML_DSA_65);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_KEYGEN, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET, ACVP_ML_DSA_PARAM_SET_ML_DSA_87);
        CHECK_ENABLE_CAP_RV(rv);

        rv = acvp_enable_algorithm(ctx, ACVP_ML_DSA_SIGGEN, &app_ml_dsa_handler);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGGEN, 0, ACVP_ML_DSA_PARAM_DETERMINISTIC_MODE, ACVP_DETERMINISTIC_BOTH);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGGEN, 0, ACVP_ML_DSA_PARAM_SIG_INTERFACE, ACVP_SIG_INTERFACE_BOTH);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGGEN, 0, ACVP_ML_DSA_PARAM_PREHASH, ACVP_SIG_PREHASH_NO);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGGEN, 0, ACVP_ML_DSA_PARAM_MU, ACVP_ML_DSA_MU_INTERNAL);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGGEN, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET, ACVP_ML_DSA_PARAM_SET_ML_DSA_44);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGGEN, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET, ACVP_ML_DSA_PARAM_SET_ML_DSA_65);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGGEN, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET, ACVP_ML_DSA_PARAM_SET_ML_DSA_87);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_domain(ctx, ACVP_ML_DSA_SIGGEN, 0, ACVP_ML_DSA_PARAM_MSG_LEN, 8, 65536, 8);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_domain(ctx, ACVP_ML_DSA_SIGGEN, 0, ACVP_ML_DSA_PARAM_CONTEXT_LEN, 0, 2040, 8);
        CHECK_ENABLE_CAP_RV(rv);

        rv = acvp_enable_algorithm(ctx, ACVP_ML_DSA_SIGVER, &app_ml_dsa_handler);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGVER, 0, ACVP_ML_DSA_PARAM_SIG_INTERFACE, ACVP_SIG_INTERFACE_BOTH);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGVER, 0, ACVP_ML_DSA_PARAM_PREHASH, ACVP_SIG_PREHASH_NO);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGVER, 0, ACVP_ML_DSA_PARAM_MU, ACVP_ML_DSA_MU_INTERNAL);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGVER, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET, ACVP_ML_DSA_PARAM_SET_ML_DSA_44);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGVER, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET, ACVP_ML_DSA_PARAM_SET_ML_DSA_65);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGVER, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET, ACVP_ML_DSA_PARAM_SET_ML_DSA_87);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_domain(ctx, ACVP_ML_DSA_SIGVER, 0, ACVP_ML_DSA_PARAM_MSG_LEN, 8, 65536, 8);
        CHECK_ENABLE_CAP_RV(rv);
        rv = acvp_cap_ml_dsa_set_domain(ctx, ACVP_ML_DSA_SIGVER, 0, ACVP_ML_DSA_PARAM_CONTEXT_LEN, 0, 2040, 8);
        CHECK_ENABLE_CAP_RV(rv);
    }

end:
    return rv;
}
