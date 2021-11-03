/** @file */
/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#ifdef ACVP_NO_RUNTIME

#include "ut_common.h"
#include "app_common.h"
#include "acvp/acvp_lcl.h"

ACVP_CTX *ctx;
ACVP_TEST_CASE *test_case;
ACVP_DRBG_TC *drbg_tc;
ACVP_RESULT rv;

void free_drbg_tc(ACVP_DRBG_TC *stc) {
    if (stc->drb) free(stc->drb);
    if (stc->additional_input_0) free(stc->additional_input_0);
    if (stc->additional_input_1) free(stc->additional_input_1);
    if (stc->additional_input_2) free(stc->additional_input_2);
    if (stc->entropy) free(stc->entropy);
    if (stc->entropy_input_pr_0) free(stc->entropy_input_pr_0);
    if (stc->entropy_input_pr_1) free(stc->entropy_input_pr_1);
    if (stc->entropy_input_pr_2) free(stc->entropy_input_pr_2);
    if (stc->nonce) free(stc->nonce);
    if (stc->perso_string) free(stc->perso_string);
    free(stc);
}

int initialize_drbg_tc(ACVP_DRBG_TC *drbg_tc, int alg_id, int mode_id,
                       char *ad_in_0, char *ent_in_0,
                       char *ad_in_1, char *ent_in_1,
                       char *ad_in_2, char *ent_in_2,
                       unsigned int pr1_len,  unsigned int pr2_len,
                       char *perso_string, char *ent, char *nonce,
                       unsigned int additional_input_len, unsigned int perso_string_len,
                       unsigned int entropy_len, unsigned int nonce_len, unsigned int drb_len,
                       unsigned int der_func_enabled, unsigned int pred_resist_enabled,
                       unsigned int reseed, int corrupt) {
    ACVP_RESULT rv;

    if (!corrupt) {
        drbg_tc->drb = calloc(ACVP_DRB_BYTE_MAX, sizeof(unsigned char));
        if (!drbg_tc->drb) { goto err; }
    }
    if (ad_in_0) {
        drbg_tc->additional_input_0 = calloc(ACVP_DRBG_ADDI_IN_BYTE_MAX, sizeof(unsigned char));
        if (!drbg_tc->additional_input_0) { goto err; }
    }
    if (ad_in_1) {
        drbg_tc->additional_input_1 = calloc(ACVP_DRBG_ADDI_IN_BYTE_MAX, sizeof(unsigned char));
        if (!drbg_tc->additional_input_1) { goto err; }
    }
    if (ad_in_2) {
        drbg_tc->additional_input_2 = calloc(ACVP_DRBG_ADDI_IN_BYTE_MAX, sizeof(unsigned char));
        if (!drbg_tc->additional_input_2) { goto err; }
    }
    if (ent) {
        drbg_tc->entropy = calloc(ACVP_DRBG_ENTPY_IN_BYTE_MAX, sizeof(unsigned char));
        if (!drbg_tc->entropy) { goto err; }
    }
    if (ent_in_0) {
        drbg_tc->entropy_input_pr_0 = calloc(ACVP_DRBG_ENTPY_IN_BYTE_MAX, sizeof(unsigned char));
        if (!drbg_tc->entropy_input_pr_0) { goto err; }
    }
    if (ent_in_1) {
        drbg_tc->entropy_input_pr_1 = calloc(ACVP_DRBG_ENTPY_IN_BYTE_MAX, sizeof(unsigned char));
        if (!drbg_tc->entropy_input_pr_1) { goto err; }
    }
    if (ent_in_2) {
        drbg_tc->entropy_input_pr_2 = calloc(ACVP_DRBG_ENTPY_IN_BYTE_MAX, sizeof(unsigned char));
        if (!drbg_tc->entropy_input_pr_2) { goto err; }
    }
    if (nonce) {
        drbg_tc->nonce = calloc(ACVP_DRBG_NONCE_BYTE_MAX, sizeof(unsigned char));
        if (!drbg_tc->nonce) { goto err; }
    }
    if (perso_string) {
        drbg_tc->perso_string = calloc(ACVP_DRBG_PER_SO_BYTE_MAX, sizeof(unsigned char));
        if (!drbg_tc->perso_string) { goto err; }
    }

    if (ad_in_0) {
        rv = acvp_hexstr_to_bin(ad_in_0, drbg_tc->additional_input_0,
                                ACVP_DRBG_ADDI_IN_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (ad_in_0)");
            goto err;
        }
    }

    if (ent_in_0) {
        rv = acvp_hexstr_to_bin(ent_in_0, drbg_tc->entropy_input_pr_0,
                                ACVP_DRBG_ENTPY_IN_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (ent_in_0)");
            goto err;
        }
    }

    if (ad_in_1) {
        rv = acvp_hexstr_to_bin(ad_in_1, drbg_tc->additional_input_1,
                                ACVP_DRBG_ADDI_IN_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (ad_in_1)");
            goto err;
        }
    }

    if (ent_in_1) {
        rv = acvp_hexstr_to_bin(ent_in_1, drbg_tc->entropy_input_pr_1,
                                ACVP_DRBG_ENTPY_IN_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (ent_in_1)");
            goto err;
        }
    }

    if (ad_in_2) {
        rv = acvp_hexstr_to_bin(ad_in_2, drbg_tc->additional_input_2,
                                ACVP_DRBG_ADDI_IN_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (2nd additional_input_2)");
            goto err;
        }
    }

    if (ent_in_2) {
        rv = acvp_hexstr_to_bin(ent_in_2, drbg_tc->entropy_input_pr_2,
                                ACVP_DRBG_ENTPY_IN_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (2nd entropy_input_pr_2)");
            goto err;
        }
    }

    if (ent) {
        rv = acvp_hexstr_to_bin(ent, drbg_tc->entropy,
                                ACVP_DRBG_ENTPY_IN_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (ent)");
            goto err;
        }
    }

    if (perso_string) {
        rv = acvp_hexstr_to_bin(perso_string, drbg_tc->perso_string,
                                ACVP_DRBG_PER_SO_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (perso_string)");
            goto err;
        }
    }

    if (nonce) {
        rv = acvp_hexstr_to_bin(nonce, drbg_tc->nonce,
                                ACVP_DRBG_NONCE_BYTE_MAX, NULL);
        if (rv != ACVP_SUCCESS) {
            ACVP_LOG_ERR("Hex conversion failure (nonce)");
            goto err;
        }
    }

    drbg_tc->der_func_enabled = der_func_enabled;
    drbg_tc->pred_resist_enabled = pred_resist_enabled;
    drbg_tc->reseed = reseed;
    drbg_tc->pr1_len = pr1_len;
    drbg_tc->pr2_len = pr2_len;
    drbg_tc->additional_input_len = additional_input_len / 8;
    drbg_tc->perso_string_len = perso_string_len / 8;
    drbg_tc->entropy_len = entropy_len / 8;
    drbg_tc->nonce_len = nonce_len / 8;
    drbg_tc->drb_len = drb_len / 8;

    drbg_tc->mode = mode_id;
    drbg_tc->cipher = alg_id;

    return 1;
err:
    free_drbg_tc(drbg_tc);
    return 0;
}

/*
 * bad cipher
 */
Test(APP_DRBG_HANDLER, bad_cipher) {
    char *ad0 = "AD4D53F913CEF2A6";
    char *ent0 = "CAEA62F10D1D2D25A9B682D4925CCF11BA7FB1B7FCC42C722475F1BF8ED38552";
    char *ad1 = "69CE80C1549A3393";
    char *ent1 = "52DBC6F7E8A2024B";
    char *ad2 = "D4F65D0BA8CEB20A";
    char *ent2 = "30F942BAFD4C5399";
    char *perso = "4809F09F39069C45";
    char *ent = "639062E106E8BA57";
    char *nonce = "B0ED3A9002B90650";
    drbg_tc = calloc(1, sizeof(ACVP_DRBG_TC));

    if (!initialize_drbg_tc(drbg_tc, ACVP_HASH_SHAKE_128, ACVP_DRBG_TDES,
            ad0, ent0, ad1,
            ent1, ad2, ent2,
            64, 64, //pr_1 len, pr_2 len
            perso, ent, nonce,
            64, 64, 256, //additional_input_len, perso_len, entropy_len
            64, 128, //nonce_len, drb_len (output)
            1, 0, 1, 0)) { //der_func_enabled, pred_resist_enabled, reseed, corrupt
        cr_assert_fail("drbg init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.drbg = drbg_tc;

    rv = app_drbg_handler(test_case);
    cr_assert_neq(rv, 0);

    free_drbg_tc(drbg_tc);
    free(test_case);
}

/*
 * bad mode
 */
Test(APP_DRBG_HANDLER, bad_mode) {
    char *ad0 = NULL;
    char *ent0 = NULL;
    char *ad1 = "16A682A659754C5E08CD6F52C07263A0";
    char *ent1 = "7409CB837AC8A9D2";
    char *ad2 = "A39EB8BC982D15BF11B9B519E8090AF7";
    char *ent2 = "8F32A84226C54963";
    char *perso = "E098F0569B560BEF";
    char *ent = "492DAD96D57F6895";
    char *nonce = "5B15109AB2C574C8";

    drbg_tc = calloc(1, sizeof(ACVP_DRBG_TC));
    if (!initialize_drbg_tc(drbg_tc, ACVP_HASHDRBG, ACVP_DRBG_TDES,
            ad0, ent0, ad1,
            ent1, ad2, ent2,
            64, 64, //pr_1 len, pr_2 len
            perso, ent, nonce,
            128, 64, 256, //additional_input_len, perso_len, entropy_len
            64, 256, //nonce_len, drb_len (output)
            1, 1, 1, 0)) { //der_func_enabled, pred_resist_enabled, reseed, corrupt
        cr_assert_fail("drbg init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.drbg = drbg_tc;
    rv = app_drbg_handler(test_case);
    cr_assert_neq(rv, 0);
    free_drbg_tc(drbg_tc);

    drbg_tc = calloc(1, sizeof(ACVP_DRBG_TC));
    if (!initialize_drbg_tc(drbg_tc, ACVP_HMACDRBG, ACVP_DRBG_AES_128,
            ad0, ent0, ad1,
            ent1, ad2, ent2,
            64, 64, //pr_1 len, pr_2 len
            perso, ent, nonce,
            128, 64, 256, //additional_input_len, perso_len, entropy_len
            64, 256, //nonce_len, drb_len (output)
            1, 1, 1, 0)) { //der_func_enabled, pred_resist_enabled, reseed, corrupt
        cr_assert_fail("drbg init tc failure");
    }
    test_case->tc.drbg = drbg_tc;
    rv = app_drbg_handler(test_case);
    cr_assert_neq(rv, 0);
    free_drbg_tc(drbg_tc);

    drbg_tc = calloc(1, sizeof(ACVP_DRBG_TC));
    if (!initialize_drbg_tc(drbg_tc, ACVP_CTRDRBG, ACVP_DRBG_SHA_256,
            ad0, ent0, ad1,
            ent1, ad2, ent2,
            64, 64, //pr_1 len, pr_2 len
            perso, ent, nonce,
            128, 64, 256, //additional_input_len, perso_len, entropy_len
            64, 256, //nonce_len, drb_len (output)
            1, 1, 1, 0)) { //der_func_enabled, pred_resist_enabled, reseed, corrupt
        cr_assert_fail("drbg init tc failure");
    }
    test_case->tc.drbg = drbg_tc;
    rv = app_drbg_handler(test_case);
    cr_assert_neq(rv, 0);
    free_drbg_tc(drbg_tc);

    free(test_case);
}

/*
 * bad alloc for output
 */
Test(APP_DRBG_HANDLER, bad_alloc_out) {
    char *ad0 = "EF430757010779411CB741268DBB8E626BD12975ACFBAD95";
    char *ent0 = "CAEA62F10D1D2D25E3A967F6C22971DFA67BD28853C0FFACD348F84CEBCD198E";
    char *ad1 = "262C0BD1CFD95F9E5AD8B30B9695815C7ED43728EB20D1F3";
    char *ent1 = "185E6630F6E9AC5ABA33EF07BF17CDC5";
    char *ad2 = "68F25592BAAB974B3F4540C8390E4C1EDD5688112D6C085C";
    char *ent2 = "38659CDCF09A949BFE3A1A0553546CA2";
    char *perso = "4809F09F39069C45FB6E63CFA2C81F8F3A3E356055F4A3191052BED5E8FC680E";
    char *ent = "639062E106E8BA57";
    char *nonce = "A9B682D4925CCF11BA7FB1B7FCC42C72";
    drbg_tc = calloc(1, sizeof(ACVP_DRBG_TC));

    if (!initialize_drbg_tc(drbg_tc, ACVP_HASHDRBG, ACVP_DRBG_SHA_256,
            ad0, ent0, ad1,
            ent1, ad2, ent2,
            128, 128, //pr_1 len, pr_2 len
            perso, ent, nonce,
            192, 256, 256, //additional_input_len, perso_len, entropy_len
            128, 0, //nonce_len, drb_len (output)
            1, 0, 1, 1)) { //der_func_enabled, pred_resist_enabled, reseed, corrupt
        cr_assert_fail("drbg init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.drbg = drbg_tc;

    rv = app_drbg_handler(test_case);
    cr_assert_neq(rv, 0);

    free_drbg_tc(drbg_tc);
    free(test_case);
}

/*
 * Missing a (currently) required entropy value
 */
Test(APP_DRBG_HANDLER, missing_entropy) {
    char *ad0 = "3D9597588DEC8519F848676B952CD66ABE0D2D056ED6386418309B63614540F9";
    char *ent0 = "700BF362EEDCFDFB1A984949B8B2FD8BA17015BFB3FB0EF85C6F4DAE931D7C59";
    char *ad1 = "70CC3371476CC53D969FBACEE004B123D20CD9BA95D6C52F5CCB3073A025212E";
    char *ent1 = NULL;
    char *ad2 = "4355D5A546BACF74587C1CE661097656166D0C3641EA5E26A9D7C77F6496D8F3";
    char *ent2 = "550FE5A91635D2221E808CAC29D103304040FD0C8F0765EB4BA5881C0795A386";
    char *perso = "18B9EB21871CADD1DBA8885FD084F373AF08F1BCCDD348745E8D9C320F58BA75";
    char *ent = "AE308B6601264418F241F9BD4C9713D71C7FFF33366340B205B1A560F66D4021";
    char *nonce = "A9B682D4925CCF11BA7FB1B7FCC42C72";
    drbg_tc = calloc(1, sizeof(ACVP_DRBG_TC));

    if (!initialize_drbg_tc(drbg_tc, ACVP_CTRDRBG, ACVP_DRBG_AES_256,
            ad0, ent0, ad1,
            ent1, ad2, ent2,
            256, 256, //pr_1 len, pr_2 len
            perso, ent, nonce,
            256, 256, 256, //additional_input_len, perso_len, entropy_len
            128, 256, //nonce_len, drb_len (output)
            1, 1, 0, 0)) { //der_func_enabled, pred_resist_enabled, reseed, corrupt
        cr_assert_fail("drbg init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.drbg = drbg_tc;

    rv = app_drbg_handler(test_case);
    cr_assert_neq(rv, 0);

    free_drbg_tc(drbg_tc);
    free(test_case);
}

/*
 * Missing perso value
 */
Test(APP_DRBG_HANDLER, no_perso) {
    char *ad0 = NULL;
    char *ent0 = NULL;
    char *ad1 = "70CC3371476CC53D969FBACEE004B123D20CD9BA95D6C52F5CCB3073A025212E";
    char *ent1 = "AE308B6601264418F241F9BD4C9713D71C7FFF33366340B205B1A560F66D4021";
    char *ad2 = "4355D5A546BACF74587C1CE661097656166D0C3641EA5E26A9D7C77F6496D8F3";
    char *ent2 = "550FE5A91635D2221E808CAC29D103304040FD0C8F0765EB4BA5881C0795A386";
    char *perso = NULL;
    char *ent = "AE308B6601264418F241F9BD4C9713D71C7FFF33366340B205B1A560F66D4021";
    char *nonce = "A9B682D4925CCF11BA7FB1B7FCC42C72";
    drbg_tc = calloc(1, sizeof(ACVP_DRBG_TC));

    if (!initialize_drbg_tc(drbg_tc, ACVP_CTRDRBG, ACVP_DRBG_AES_256,
            ad0, ent0, ad1,
            ent1, ad2, ent2,
            256, 256, //pr_1 len, pr_2 len
            perso, ent, nonce,
            256, 256, 256, //additional_input_len, perso_len, entropy_len
            128, 256, //nonce_len, drb_len (output)
            1, 1, 1, 0)) { //der_func_enabled, pred_resist_enabled, reseed, corrupt
        cr_assert_fail("drbg init tc failure");
    }
    test_case = calloc(1, sizeof(ACVP_TEST_CASE));
    test_case->tc.drbg = drbg_tc;

    rv = app_drbg_handler(test_case);
    cr_assert_neq(rv, 0);

    free_drbg_tc(drbg_tc);
    free(test_case);
}

#endif
