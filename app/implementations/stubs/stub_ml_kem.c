/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include "app_lcl.h"

int app_ml_kem_handler(ACVP_TEST_CASE *test_case) {
    /*
     * "tc" is test_case->tc.ml_kem. All modes use tc->param_set to specify ML-KEM-512, 768, or 
     * 1024.
     *
     * For keygen, take tc->d and tc->z (seeds) and use them to generate tc->ek (encapsulation key)
     * and tc->dk (decapsulation key) as well as their _len values
     *
     * For encap/decap, AFT test types (tc->type) correspond to an encapsulate operation, and VAL
     * tests correspond to a decapsulate operation (you can also look at the tc->function value).
     *
     * For encapsulating, take tc->ek and tc->m (m being a given random value) and use them to
     * generate a shared secret (tc->k) and ciphertext (tc->c).
     *
     * For decapsulating, take tc->dk and tc->c and attempt to generate tc->k. Note that in the
     * case of invalid ciphertext being provided, the IuT is expected to still provide a k value
     * that aligns with the "implicit rejection" function described in FIPS203. 
     */


    if (!test_case) {
        return -1;
    }

    return 0;
}

