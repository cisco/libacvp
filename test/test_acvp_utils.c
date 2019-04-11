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
#include "acvp_lcl.h"

ACVP_CTX *ctx;

/*
 * Try to pass acvp_locate_cap_entry NULL ctx
 */
Test(LocateCapEntry, null_ctx) {
    ACVP_CAPS_LIST *list;

    list = acvp_locate_cap_entry(NULL, ACVP_AES_GCM);
    cr_assert_null(list);
}

Test(LookupCipherIndex, null_param) {
    ACVP_CIPHER cipher;
    cipher = acvp_lookup_cipher_index(NULL);
    cr_assert(cipher == ACVP_CIPHER_START);
}

Test(LookupRSARandPQIndex, null_param) {
    int rv = acvp_lookup_rsa_randpq_index(NULL);
    cr_assert(!rv);
}