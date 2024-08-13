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

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/param_build.h>
#include <openssl/kdf.h>
#include "safe_lib.h"

#define TLS_EXT_MASTER_SECRET_CONST      "extended master secret"
#define TLS_EXT_MASTER_SECRET_CONST_SIZE 22
#define TLS_KEY_EXPAND_CONST             "key expansion"
#define TLS_KEY_EXPAND_CONST_SIZE        13

#define TLS12_BUF_MAX 4096 /* match library */
#define TLS12_SEED_BUF_MAX (TLS12_BUF_MAX + TLS_EXT_MASTER_SECRET_CONST_SIZE)


/* For simplicty, define as non-const; the OSSL_PARAM functions don't use const */
static char ssh_kdf_a[] = "A";
static char ssh_kdf_b[] = "B";
static char ssh_kdf_c[] = "C";
static char ssh_kdf_d[] = "D";
static char ssh_kdf_e[] = "E";
static char ssh_kdf_f[] = "F";

static unsigned char tls13_c_e_traffic[] = "c e traffic";
static unsigned char tls13_e_exp_master[] = "e exp master";
static unsigned char tls13_derived[] = "derived";
static unsigned char tls13_c_hs_traffic[] = "c hs traffic";
static unsigned char tls13_s_hs_traffic[] = "s hs traffic";
static unsigned char tls13_c_ap_traffic[] = "c ap traffic";
static unsigned char tls13_s_ap_traffic[] = "s ap traffic";
static unsigned char tls13_exp_master[] = "exp master";
static unsigned char tls13_res_master[] = "res master";
static unsigned char tls13_prefix[] = "tls13 ";

static char tls13_extract[] = "EXTRACT_ONLY";
static char tls13_expand[] = "EXPAND_ONLY";

int app_kdf135_x942_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDF135_X942_TC *stc = NULL;
    int rc = 1, info_len = 0, iter = 0;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    const char *alg = NULL, *oid = NULL;
    unsigned char *acvp_info = NULL;

    if (!test_case) {
        printf("Missing KDF X942 test case\n");
        return -1;
    }
    stc = test_case->tc.kdf135_x942;
    if (!stc) {
        printf("Missing KDF X942 test case\n");
        return -1;
    }

    alg = get_md_string_for_hash_alg(stc->hash_alg, NULL);
    if (!alg) {
        printf("Invalid hash alg given for KDF x942\n");
        goto end;
    }

    oid = get_string_from_oid(stc->oid, stc->oid_len);
    if (!oid) {
        printf("Invalid OID string given for KDF x942\n");
        goto end;
    }

    kdf = EVP_KDF_fetch(NULL, "X942KDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        printf("Error creating KDF CTX in KDF X942\n");
        goto end;
    }

    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("Error creating param_bld in KDF X942\n");
        goto end;
    }

    OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_DIGEST, alg, 0);
    OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_CEK_ALG, oid, 0);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_SECRET, stc->zz, stc->zz_len);

    /**
     * For ACVP, we need to manually build the acvp-info string instead of using the regular param setters.
     * Format:
     * A0 | #partyUInfo | partyUInfo | A1 | #partyVInfo | partyVInfo | A2 | #suppPubInfo | suppPubInfo |
     * A3 | #suppPrivInfo | suppPrivInfo
     */
    info_len = stc->party_u_len + stc->party_v_len + stc->supp_pub_len + stc->supp_priv_len + 8;
    if (info_len > 8) {
        acvp_info = calloc(info_len, sizeof(unsigned char));
        if (!acvp_info) {
            printf("Error allocating memory for acvp-info string in KDF x942\n");
            goto end;
        }
        acvp_info[iter] = 0xA0;
        iter++;
        acvp_info[iter] = (unsigned char)stc->party_u_len;
        iter++;
        memcpy_s(&acvp_info[iter], info_len - iter, stc->party_u_info, stc->party_u_len);
        iter += stc->party_u_len;
        acvp_info[iter] = 0xA1;
        iter++;
        acvp_info[iter] = (unsigned char)stc->party_v_len;
        iter++;
        memcpy_s(&acvp_info[iter], info_len - iter, stc->party_v_info, stc->party_v_len);
        iter += stc->party_v_len;
        acvp_info[iter] = 0xA2;
        iter++;
        acvp_info[iter] = (unsigned char)stc->supp_pub_len;
        iter++;
        memcpy_s(&acvp_info[iter], info_len - iter, stc->supp_pub_info, stc->supp_pub_len);
        iter += stc->supp_pub_len;
        acvp_info[iter] = 0xA3;
        iter++;
        acvp_info[iter] = (unsigned char)stc->supp_priv_len;
        iter++;
        memcpy_s(&acvp_info[iter], info_len - iter, stc->supp_priv_info, stc->supp_priv_len);

        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_X942_ACVPINFO, acvp_info, info_len);
    }
    OSSL_PARAM_BLD_push_int(pbld, OSSL_KDF_PARAM_X942_USE_KEYBITS, 0);

    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params in KDF X942\n");
        goto end;
    }

    if (EVP_KDF_derive(kctx, stc->dkm, stc->key_len, params) != 1) {
        printf("Failure deriving key material in KDF X942\n");
        goto end;
    }

    stc->dkm_len = stc->key_len;
    rc = 0;
end:
    if (acvp_info) free(acvp_info);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    return rc;
}

int app_kdf135_x963_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDF135_X963_TC *stc = NULL;
    int rc = 1;
    char *aname = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    const char *alg = NULL;

    if (!test_case) {
        printf("Missing KDF X963 test case\n");
        return -1;
    }
    stc = test_case->tc.kdf135_x963;
    if (!stc) {
        printf("Missing KDF X963 test case\n");
        return -1;
    }

    alg = get_md_string_for_hash_alg(stc->hash_alg, NULL);
    if (!alg) {
        printf("Invalid hmac type given for KDF x963\n");
        goto end;
    }

    aname = calloc(256, sizeof(char)); //avoid const removal warnings
    if (!aname) {
        printf("Error allocating memory for KDF X963\n");
        goto end;
    }
    strcpy_s(aname, 256, alg);

    kdf = EVP_KDF_fetch(NULL, "X963KDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        printf("Error creating KDF CTX in KDF X963\n");
        goto end;
    }

    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("Error creating param_bld in KDF X963\n");
        goto end;
    }
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_KEY, stc->z, stc->z_len);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_INFO, stc->shared_info, stc->shared_info_len);
    OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_DIGEST, aname, 0);
    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params in KDF X963\n");
        goto end;
    }

    if (EVP_KDF_derive(kctx, stc->key_data, stc->key_data_len, params) != 1) {
        printf("Failure deriving key material in KDF X963\n");
        goto end;
    }
    rc = 0;
end:
    if (aname) free(aname);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    return rc;
}

int app_kdf108_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDF108_TC *stc = NULL;
    int rc = 1, isHmac = 1, fixed_len = 64;
    char *aname = NULL;
    unsigned char *fixed = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    const char *alg = NULL, *mac = NULL;

    if (!test_case) {
        printf("Missing kdf108 test case\n");
        return -1;
    }
    stc = test_case->tc.kdf108;
    if (!stc) {
        printf("Missing kdf108 test case\n");
        return -1;
    }

    switch (stc->mac_mode) {
    case ACVP_KDF108_MAC_MODE_HMAC_SHA1:
        alg = "SHA-1";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA224:
        alg = "SHA2-224";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA256:
        alg = "SHA2-256";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA384:
        alg = "SHA2-384";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA512:
        alg = "SHA2-512";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA512_224:
        alg = "SHA2-512/224";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA512_256:
        alg = "SHA2-512/256";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA3_224:
        alg = "SHA3-224";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA3_256:
        alg = "SHA3-256";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA3_384:
        alg = "SHA3-384";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_HMAC_SHA3_512:
        alg = "SHA3-512";
        mac = "HMAC";
        break;
    case ACVP_KDF108_MAC_MODE_CMAC_AES128:
        alg = "AES128";
        mac = "CMAC";
        isHmac = 0;
        break;
    case ACVP_KDF108_MAC_MODE_CMAC_AES192:
        alg = "AES192";
        mac = "CMAC";
        isHmac = 0;
        break;
    case ACVP_KDF108_MAC_MODE_CMAC_AES256:
        alg = "AES256";
        mac = "CMAC";
        isHmac = 0;
        break;
    case ACVP_KDF108_MAC_MODE_KMAC_128:
        mac = "KMAC128";
        break;
    case ACVP_KDF108_MAC_MODE_KMAC_256:
        mac = "KMAC256";
        break;
    case ACVP_KDF108_MAC_MODE_MIN:
    case ACVP_KDF108_MAC_MODE_CMAC_TDES:
    case ACVP_KDF108_MAC_MODE_MAX:
    default:
        printf("app_kda_kdf108_handler error: Unsupported mac algorithm\n");
        return 1;
    }

    if (alg) {
        aname = calloc(256, sizeof(char)); //avoid const removal warnings
        if (!aname) {
            printf("Error allocating memory for KDF 108\n");
            goto end;
        }
        strcpy_s(aname, 256, alg);
    }

    if (stc->mac_mode != ACVP_KDF108_MAC_MODE_KMAC_128 && stc->mac_mode != ACVP_KDF108_MAC_MODE_KMAC_256) {
        fixed = calloc(fixed_len, sizeof(char)); //arbitrary length fixed info
        if (!fixed) {
            printf("Error allocating memory for KDF 108\n");
            goto end;
        }
        RAND_bytes(fixed, fixed_len);
        memcpy_s(stc->fixed_data, ACVP_KDF108_FIXED_DATA_MAX, fixed, fixed_len);
        stc->fixed_data_len = fixed_len;
    }

    kdf = EVP_KDF_fetch(NULL, "KBKDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        printf("Error creating KDF CTX in kdf108\n");
        goto end;
    }
    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("Error creating param_bld in kdf108\n");
        goto end;
    }
    OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_MAC, mac, 0);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_KEY, stc->key_in, stc->key_in_len);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_SEED, stc->iv, stc->iv_len);
    if (stc->mac_mode == ACVP_KDF108_MAC_MODE_KMAC_128 || stc->mac_mode == ACVP_KDF108_MAC_MODE_KMAC_256) {
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_INFO, stc->context, stc->context_len);
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_SALT, stc->label, stc->label_len);
    } else {
        OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_INFO, fixed, fixed_len);
    }
    OSSL_PARAM_BLD_push_int(pbld, OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, 0);
    OSSL_PARAM_BLD_push_int(pbld, OSSL_KDF_PARAM_KBKDF_USE_L, 0);

    if (aname) {
        if (isHmac) {
            OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_DIGEST, aname, 0);
        } else {
            OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_CIPHER, aname, 0);
        }
    }

    if (stc->mode == ACVP_KDF108_MODE_COUNTER) {
        OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_MODE, "COUNTER", 0);
    } else if (stc->mode == ACVP_KDF108_MODE_FEEDBACK) {
        OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_MODE, "FEEDBACK", 0);
    }

    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params in kdf108\n");
        goto end;
    }

    if (EVP_KDF_derive(kctx, stc->key_out, stc->key_out_len, params) != 1) {
        printf("Failure deriving key material in kdf108\n");
        goto end;
    }

    rc = 0;
end:
    if (aname) free(aname);
    if (fixed) free(fixed);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    return rc;
}

int app_kdf135_ssh_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDF135_SSH_TC *stc = NULL;
    int rc = 1;
    char *aname = NULL;
    OSSL_PARAM params[6];
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    const char *alg = NULL;

    if (!test_case) {
        printf("Missing kdf135-ssh test case\n");
        return -1;
    }
    stc = test_case->tc.kdf135_ssh;
    if (!stc) {
        printf("Missing kdf135-ssh test case\n");
        return -1;
    }

    alg = get_md_string_for_hash_alg(stc->sha_type, NULL);
    if (!alg) {
        printf("Invalid hash type given for kdf135-ssh\n");
        goto end;
    }

    aname = calloc(256, sizeof(char)); //avoid const removal warnings
    if (!aname) {
        printf("Error allocating memory for kdf135-ssh\n");
        goto end;
    }
    strcpy_s(aname, 256, alg);

    kdf = EVP_KDF_fetch(NULL, "SSHKDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        printf("Error creating KDF CTX in kdf135-ssh\n");
        goto end;
    }

    params[0] = OSSL_PARAM_construct_utf8_string("digest", aname, 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", stc->shared_secret_k, stc->shared_secret_len);
    params[2] = OSSL_PARAM_construct_octet_string("session_id", stc->session_id, stc->session_id_len);
    params[3] = OSSL_PARAM_construct_octet_string("xcghash", stc->hash_h, stc->hash_len);
    //params(4) will be the "type" of operation, before each call
    params[5] = OSSL_PARAM_construct_end();

    params[4] = OSSL_PARAM_construct_utf8_string("type", ssh_kdf_a, 1);
    if (EVP_KDF_derive(kctx, stc->cs_init_iv, stc->iv_len, params) != 1) {
        printf("Failure deriving key material in kdf135-ssh (A)\n");
        goto end;
    }

    params[4] = OSSL_PARAM_construct_utf8_string("type", ssh_kdf_b, 1);
    if (EVP_KDF_derive(kctx, stc->sc_init_iv, stc->iv_len, params) != 1) {
        printf("Failure deriving key material in kdf135-ssh (B)\n");
        goto end;
    }

    params[4] = OSSL_PARAM_construct_utf8_string("type", ssh_kdf_c, 1);
    if (EVP_KDF_derive(kctx, stc->cs_encrypt_key, stc->e_key_len, params) != 1) {
        printf("Failure deriving key material in kdf135-ssh (C)\n");
        goto end;
    }

    params[4] = OSSL_PARAM_construct_utf8_string("type", ssh_kdf_d, 1);
    if (EVP_KDF_derive(kctx, stc->sc_encrypt_key, stc->e_key_len, params) != 1) {
        printf("Failure deriving key material in kdf135-ssh (D)\n");
        goto end;
    }

    params[4] = OSSL_PARAM_construct_utf8_string("type", ssh_kdf_e, 1);
    if (EVP_KDF_derive(kctx, stc->cs_integrity_key, stc->i_key_len, params) != 1) {
        printf("Failure deriving key material in kdf135-ssh (E)\n");
        goto end;
    }

    params[4] = OSSL_PARAM_construct_utf8_string("type", ssh_kdf_f, 1);
    if (EVP_KDF_derive(kctx, stc->sc_integrity_key, stc->i_key_len, params) != 1) {
        printf("Failure deriving key material in kdf135-ssh (F)\n");
        goto end;
    }

    rc = 0;
end:
    if (aname) free(aname);
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    return rc;
}

int app_pbkdf_handler(ACVP_TEST_CASE *test_case) {
    ACVP_PBKDF_TC *stc = NULL;
    int rc = 1;
    char *aname = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    const char *alg = NULL;

    if (!test_case) {
        printf("Missing PBKDF test case\n");
        return -1;
    }
    stc = test_case->tc.pbkdf;
    if (!stc) {
        printf("Missing PBKDF test case\n");
        return -1;
    }

    alg = get_md_string_for_hash_alg(stc->hmac_type, NULL);
    if (!alg) {
        printf("Invalid hmac type given for PBKDF\n");
        goto end;
    }

    aname = calloc(256, sizeof(char)); //avoid const removal warnings
    if (!aname) {
        printf("Error allocating memory for PBKDF\n");
        goto end;
    }
    strcpy_s(aname, 256, alg);

    kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        printf("Error creating KDF CTX in PBKDF\n");
        goto end;
    }

    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("Error creating param_bld in PBKDF\n");
        goto end;
    }
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_PASSWORD, stc->password, stc->pw_len);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_SALT, stc->salt, stc->salt_len);
    OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_DIGEST, aname, 0);
    OSSL_PARAM_BLD_push_uint(pbld, OSSL_KDF_PARAM_ITER, stc->iterationCount);
    OSSL_PARAM_BLD_push_int(pbld, OSSL_KDF_PARAM_PKCS5, 1); /* disables compliance checks, dont want limit checks for ACVP tests */
    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params in PBKDF\n");
        goto end;
    }

    if (EVP_KDF_derive(kctx, stc->key, stc->key_len, params) != 1) {
        printf("Failure deriving key material in PBKDF\n");
    }
    rc = 0;
end:
    if (aname) free(aname);
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    return rc;
}

int app_kdf_tls12_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDF_TLS12_TC *tc;
    unsigned char *seed = NULL;
    int rc = 1, ret = 0, seed_len = 0;
    const char *alg = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM_BLD *pbld = NULL;
    OSSL_PARAM *params = NULL;

    if (!test_case) {
        printf("Missing TLS1.2 KDF test case\n");
        return -1;
    }
    tc = test_case->tc.kdf_tls12;
    if (!tc) {
        printf("Missing TLS1.2 KDF test case\n");
        return -1;
    }

    /* We need to concatenate label + seed ourselves for PRF() */
    seed = calloc(TLS12_SEED_BUF_MAX, sizeof(char));
    if (!seed) {
        printf("Error allocating memory for seed in TLS1.2 KDF\n");
        return -1;
    }

    alg = get_md_string_for_hash_alg(tc->md, NULL);
    if (!alg) {
        printf("Invalid hash type given for TLS1.2 KDF\n");
        goto end;
    }

    kdf = EVP_KDF_fetch(NULL, "TLS1-PRF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        printf("Error creating KDF CTX in TLS1.2 KDF\n");
        goto end;
    }

    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("Error creating param_bld in TLS1.2 KDF (1)\n");
        goto end;
    }

    /* calculate msecret */
    seed_len = TLS_EXT_MASTER_SECRET_CONST_SIZE + tc->session_hash_len;
    /* copy label to buffer */
    memcpy_s(seed, TLS12_SEED_BUF_MAX, TLS_EXT_MASTER_SECRET_CONST, TLS_EXT_MASTER_SECRET_CONST_SIZE);
    /* concatenate session_hash to buffer */
    memcpy_s(seed + TLS_EXT_MASTER_SECRET_CONST_SIZE, TLS12_SEED_BUF_MAX - TLS_EXT_MASTER_SECRET_CONST_SIZE,
             tc->session_hash, tc->session_hash_len);

    OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_DIGEST, alg, 0);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_SECRET, tc->pm_secret, tc->pm_len);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_SEED, seed, seed_len);
    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params in TLS1.2 KDF (1)\n");
        goto end;
    }
    ret = EVP_KDF_derive(kctx, tc->msecret, TLS12_BUF_MAX, params);
    if (ret != 1) {
        printf("Error deriving msecret in TLS1.2 KDF\n");
        goto end;
    }

    /* calculate kblock */
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    pbld = OSSL_PARAM_BLD_new();
    if (!pbld) {
        printf("Error creating param_bld in TLS1.2 KDF (2)\n");
        goto end;
    }
    EVP_KDF_CTX_reset(kctx);

    seed_len = TLS_KEY_EXPAND_CONST_SIZE + tc->s_rnd_len + tc->c_rnd_len;
    /* Copy label to buffer */
    memcpy_s(seed, TLS12_SEED_BUF_MAX, TLS_KEY_EXPAND_CONST, TLS_KEY_EXPAND_CONST_SIZE);
    /* Concatenate s_rnd to buffer */
    memcpy_s(seed + TLS_KEY_EXPAND_CONST_SIZE, TLS12_SEED_BUF_MAX - TLS_KEY_EXPAND_CONST_SIZE,
             tc->s_rnd, tc->s_rnd_len);
    /* Concatenate c_rnd to buffer */
    memcpy_s(seed + TLS_KEY_EXPAND_CONST_SIZE + tc->s_rnd_len,
             TLS12_SEED_BUF_MAX - TLS_KEY_EXPAND_CONST_SIZE - tc->s_rnd_len,
             tc->c_rnd, tc->c_rnd_len);

    OSSL_PARAM_BLD_push_utf8_string(pbld, OSSL_KDF_PARAM_DIGEST, alg, 0);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_SECRET, tc->msecret, tc->pm_len);
    OSSL_PARAM_BLD_push_octet_string(pbld, OSSL_KDF_PARAM_SEED, seed, seed_len);
    params = OSSL_PARAM_BLD_to_param(pbld);
    if (!params) {
        printf("Error generating params in TLS1.2 KDF (2)\n");
        goto end;
    }
    ret = EVP_KDF_derive(kctx, tc->kblock, TLS12_BUF_MAX, params);
    if (ret != 1) {
        printf("Error deriving kblock in TLS1.2 KDF\n");
        goto end;
    }

    rc = 0;
end:
    if (pbld) OSSL_PARAM_BLD_free(pbld);
    if (params) OSSL_PARAM_free(params);
    if (kctx) EVP_KDF_CTX_free(kctx);
    if (kdf) EVP_KDF_free(kdf);
    if (seed) free(seed);
    return rc;
}

int app_kdf_tls13_handler(ACVP_TEST_CASE *test_case) {
    ACVP_KDF_TLS13_TC *tc = NULL;
    char *md = NULL;
    const char *md_str = NULL;
    const EVP_MD    *md_obj;
    EVP_MD_CTX *mctx = NULL;
    unsigned char *hello_hash = NULL, *client_hello_hash = NULL, *handshake_secret = NULL,
                  *client_hash = NULL, *finish_hash = NULL, *master_secret = NULL,
                  *early_secret = NULL, *zero_input = NULL;
    OSSL_PARAM ext_params[7] = { NULL }, exp_params[7] = { NULL };
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    int rv = 1, ret = 0, md_size = 0;

    if (!test_case) {
        printf("Error: No tc for TLS1.3 KDF\n");
        return -1;
    }

    tc = test_case->tc.kdf_tls13;
    if (!tc) {
        printf("Error: No tc for TLS1.3 KDF\n");
        return -1;
    }

    md_str = get_md_string_for_hash_alg(tc->hmac_alg, &md_size);
    if (!md_str) {
        printf("Invalid mac alg given for TLS 1.3 KDF\n");
        return -1;
    }

    md = remove_str_const(md_str);
    if (!md) {
        printf("Invalid mac alg given for TLS1.3 KDF (%d)\n", tc->hmac_alg);
        return -1;
    }

    md_obj = get_md_for_hash_alg(tc->hmac_alg);
    if (!md_obj) {
        printf("Unable to retrieve md object for %s in TLS1.3 KDF\n", md);
    }

    zero_input = calloc(md_size, sizeof(unsigned char));
    early_secret = calloc(md_size, sizeof(unsigned char));
    handshake_secret = calloc(md_size, sizeof(unsigned char));
    master_secret = calloc(md_size, sizeof(unsigned char));

    /**
     * We need hashes of some values for the expand steps since the library does not do hashes
     * itself. Listed here in order of use:
     */
    client_hello_hash = calloc(md_size, sizeof(unsigned char));
    hello_hash = calloc(md_size, sizeof(unsigned char));
    finish_hash = calloc(md_size, sizeof(unsigned char));
    client_hash = calloc(md_size, sizeof(unsigned char));
    if (!zero_input || !early_secret || !handshake_secret || !master_secret ||
        !client_hello_hash || !hello_hash || !finish_hash || !client_hash) {
        printf("Calloc failure in TLS1.3 KDF\n");
        goto err;
    }

    if (!tc->c_hello_rand || !tc->c_hello_rand_len || !tc->s_hello_rand || !tc->s_hello_rand_len ||
        !tc->fin_s_hello_rand || !tc->fin_s_hello_rand_len ||
        !tc->fin_c_hello_rand || !tc->fin_c_hello_rand_len || !tc->c_early_traffic_secret ||
        !tc->early_expt_master_secret || !tc->c_hs_traffic_secret || !tc->s_hs_traffic_secret ||
        !tc->c_app_traffic_secret || !tc->s_app_traffic_secret || !tc->expt_master_secret ||
        !tc->resume_master_secret) {
        printf("Library calloc failure in TLS1.3 KDF\n");
        goto err;
    }

    if ((tc->running_mode == ACVP_KDF_TLS13_RUN_MODE_PSK_DHE) ||
        (tc->running_mode == ACVP_KDF_TLS13_RUN_MODE_PSK)) {
        if (!tc->psk || !tc->psk_len) {
            printf("No PSK in PSK mode in TLS1.3 KDF\n");
            goto err;
        }
    }

    if ((tc->running_mode != ACVP_KDF_TLS13_RUN_MODE_PSK_DHE) &&
        (tc->running_mode != ACVP_KDF_TLS13_RUN_MODE_PSK)) {
        if (tc->psk_len) {
            printf("PSK in non-PSK mode in TLS1.3 KDF\n");
            goto err;
        }
    }

    if ((tc->running_mode == ACVP_KDF_TLS13_RUN_MODE_PSK_DHE) ||
        (tc->running_mode == ACVP_KDF_TLS13_RUN_MODE_DHE)) {
        if (!tc->dhe || !tc->dhe_len) {
            printf("No DHE in DHE mode in TLS1.3 KDF\n");
            goto err;
        }
    }

    if ((tc->running_mode != ACVP_KDF_TLS13_RUN_MODE_PSK_DHE) &&
        (tc->running_mode != ACVP_KDF_TLS13_RUN_MODE_DHE)) {
        if (tc->dhe_len) {
            printf("DHE in non-DHE mode in TLS1.3 KDF\n");
            goto err;
        }
    }
    /* generate all the hashes first */
    mctx = EVP_MD_CTX_new();
    /* The client early secrets step uses a hash of client hello */
    if (mctx == NULL
            || EVP_DigestInit_ex(mctx, md_obj, NULL) <= 0
            || EVP_DigestUpdate(mctx, tc->c_hello_rand, tc->c_hello_rand_len) <= 0
            || EVP_DigestFinal_ex(mctx, client_hello_hash, NULL) <= 0) {
            printf("Client hello hash failed in TLS1.3 KDF\n");
        EVP_MD_CTX_free(mctx);
        goto err;
    }
    EVP_MD_CTX_free(mctx);

    mctx = EVP_MD_CTX_new();
    /* The handshake secrets step uses a hash of client server hello */
    if (mctx == NULL
            || EVP_DigestInit_ex(mctx, md_obj, NULL) <= 0
            || EVP_DigestUpdate(mctx, tc->c_hello_rand, tc->c_hello_rand_len) <= 0
            || EVP_DigestUpdate(mctx, tc->s_hello_rand, tc->s_hello_rand_len) <= 0
            || EVP_DigestFinal_ex(mctx, hello_hash, NULL) <= 0) {
            printf("Combined hello hash failed in TLS1.3 KDF\n");
        EVP_MD_CTX_free(mctx);
        goto err;
    }
    EVP_MD_CTX_free(mctx);

    mctx = EVP_MD_CTX_new();
    /* The application secret steps uses a hash of client hello and server finish */
    if (mctx == NULL
            || EVP_DigestInit_ex(mctx, md_obj, NULL) <= 0
            || EVP_DigestUpdate(mctx, tc->c_hello_rand, tc->c_hello_rand_len) <= 0
            || EVP_DigestUpdate(mctx, tc->s_hello_rand, tc->s_hello_rand_len) <= 0
            || EVP_DigestUpdate(mctx, tc->fin_s_hello_rand, tc->fin_s_hello_rand_len) <= 0
            || EVP_DigestFinal_ex(mctx, finish_hash, NULL) <= 0) {
            printf("Combined finish hash failed in TLS1.3 KDF\n");
        EVP_MD_CTX_free(mctx);
        goto err;
    }
    EVP_MD_CTX_free(mctx);

    mctx = EVP_MD_CTX_new();
    /* The resume secret step uses a hash of client hello and client finish */
    if (mctx == NULL
            || EVP_DigestInit_ex(mctx, md_obj, NULL) <= 0
            || EVP_DigestUpdate(mctx, tc->c_hello_rand, tc->c_hello_rand_len) <= 0
            || EVP_DigestUpdate(mctx, tc->s_hello_rand, tc->s_hello_rand_len) <= 0
            || EVP_DigestUpdate(mctx, tc->fin_s_hello_rand, tc->fin_s_hello_rand_len) <= 0
            || EVP_DigestUpdate(mctx, tc->fin_c_hello_rand, tc->fin_c_hello_rand_len) <= 0
            || EVP_DigestFinal_ex(mctx, client_hash, NULL) <= 0) {
            printf("Combined client hash failed in TLS1.3 KDF\n");
        EVP_MD_CTX_free(mctx);
        goto err;
    }
    EVP_MD_CTX_free(mctx);

    kdf = EVP_KDF_fetch(NULL, "TLS13-KDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        printf("Error creating CTX in TLS1.3 KDF\n");
        goto err;
    }

    /* Create early secret */
    ext_params[0] = OSSL_PARAM_construct_utf8_string("digest", md, 0);
    ext_params[1] = OSSL_PARAM_construct_utf8_string("mode", tls13_extract, 0);
    if (tc->psk_len) {
        ext_params[2] = OSSL_PARAM_construct_octet_string("key", tc->psk, tc->psk_len);
    } else {
        ext_params[2] = OSSL_PARAM_construct_octet_string("key", zero_input, md_size);
    }
    /* Leave [3] so we can use a salt later on */
    /* Leave [4] for label later on */
    /* Leave [5] for prefix later on */
    ext_params[6] = OSSL_PARAM_construct_end();

    ret = EVP_KDF_derive(kctx, early_secret, md_size, ext_params);
    if (ret != 1) {
        printf("Error deriving early secret in TLS1.3 KDF\n");
        goto err;
    }

    /* Create the early traffic secret */
    EVP_KDF_CTX_reset(kctx);
    exp_params[0] = OSSL_PARAM_construct_utf8_string("digest", md, 0);
    exp_params[1] = OSSL_PARAM_construct_utf8_string("mode", tls13_expand, 0);
    exp_params[2] = OSSL_PARAM_construct_octet_string("prefix", tls13_prefix, sizeof(tls13_prefix) - 1);
    exp_params[3] = OSSL_PARAM_construct_octet_string("label", tls13_c_e_traffic, sizeof(tls13_c_e_traffic) - 1);
    exp_params[4] = OSSL_PARAM_construct_octet_string("key", early_secret, md_size);
    exp_params[5] = OSSL_PARAM_construct_octet_string("data", client_hello_hash, md_size);
    exp_params[6] = OSSL_PARAM_construct_end();

    ret = EVP_KDF_derive(kctx, tc->c_early_traffic_secret, md_size, exp_params);
    if (ret != 1) {
        printf("Error deriving client early traffic secret in TLS1.3 KDF\n");
        goto err;
    }
    tc->cets_len = md_size;

    /* Create the early exporter master secret */
    EVP_KDF_CTX_reset(kctx);
    exp_params[3] = OSSL_PARAM_construct_octet_string("label", tls13_e_exp_master, sizeof(tls13_e_exp_master) - 1);
    ret = EVP_KDF_derive(kctx, tc->early_expt_master_secret, md_size, exp_params);
    if (ret != 1) {
        printf("Error deriving early exporter master secret in TLS1.3 KDF\n");
        goto err;
    }
    tc->eems_len = md_size;

    /* Create handshake secret, if registered for DHE use it */
    EVP_KDF_CTX_reset(kctx);
    if (tc->dhe_len) {
        ext_params[2] = OSSL_PARAM_construct_octet_string("key", tc->dhe, tc->dhe_len);
    } else {
        ext_params[2] = OSSL_PARAM_construct_octet_string("key", zero_input, md_size);
    }
    ext_params[3] = OSSL_PARAM_construct_octet_string("salt", early_secret, md_size);
    ext_params[4] = OSSL_PARAM_construct_octet_string("label", tls13_derived, sizeof(tls13_derived) - 1);
    ext_params[5] = OSSL_PARAM_construct_octet_string("prefix", tls13_prefix, sizeof(tls13_prefix) - 1);
    ret = EVP_KDF_derive(kctx, handshake_secret, md_size, ext_params);
    if (ret != 1) {
        printf("Error deriving handshake secret in TLS1.3 KDF\n");
        goto err;
    }

    /* Create client handshake traffic secret */
    EVP_KDF_CTX_reset(kctx);
    exp_params[3] = OSSL_PARAM_construct_octet_string("label", tls13_c_hs_traffic, sizeof(tls13_c_hs_traffic) - 1);
    exp_params[4] = OSSL_PARAM_construct_octet_string("key", handshake_secret, md_size);
    exp_params[5] = OSSL_PARAM_construct_octet_string("data", hello_hash, md_size);
    ret = EVP_KDF_derive(kctx, tc->c_hs_traffic_secret, md_size, exp_params);
    if (ret != 1) {
        printf("Error deriving client handshake traffic secret in TLS1.3 KDF\n");
        goto err;
    }
    tc->chts_len = md_size;


    /* Create server handshake traffic secret */
    EVP_KDF_CTX_reset(kctx);
    exp_params[3] = OSSL_PARAM_construct_octet_string("label", tls13_s_hs_traffic, sizeof(tls13_s_hs_traffic) - 1);
    ret = EVP_KDF_derive(kctx, tc->s_hs_traffic_secret, md_size, exp_params);
    if (ret != 1) {
        printf("Error deriving server handshake traffic secret in TLS1.3 KDF\n");
        goto err;
    }
    tc->shts_len = md_size;

    /* Create master secret */
    ext_params[2] = OSSL_PARAM_construct_octet_string("key", zero_input, md_size);
    ext_params[3] = OSSL_PARAM_construct_octet_string("salt", handshake_secret, md_size);
    ret = EVP_KDF_derive(kctx, master_secret, md_size, ext_params);
    if (ret != 1) {
        printf("Error deriving master secret in TLS1.3 KDF\n");
        goto err;
    }

    /* Create client application traffic secret */
    EVP_KDF_CTX_reset(kctx);
    exp_params[3] = OSSL_PARAM_construct_octet_string("label", tls13_c_ap_traffic, sizeof(tls13_c_ap_traffic) - 1);
    exp_params[4] = OSSL_PARAM_construct_octet_string("key", master_secret, md_size);
    exp_params[5] = OSSL_PARAM_construct_octet_string("data", finish_hash, md_size);
    ret = EVP_KDF_derive(kctx, tc->c_app_traffic_secret, md_size, exp_params);
    if (ret != 1) {
        printf("Error deriving client application traffic secret in TLS1.3 KDF\n");
        goto err;
    }
    tc->cats_len = md_size;

    /* Create server application traffic secret */
    EVP_KDF_CTX_reset(kctx);
    exp_params[3] = OSSL_PARAM_construct_octet_string("label", tls13_s_ap_traffic, sizeof(tls13_s_ap_traffic) - 1);
    ret = EVP_KDF_derive(kctx, tc->s_app_traffic_secret, md_size, exp_params);
    if (ret != 1) {
        printf("Error deriving server application traffic secret in TLS1.3 KDF\n");
        goto err;
    }
    tc->sats_len = md_size;

    /* Create exporter master secret */
    EVP_KDF_CTX_reset(kctx);
    exp_params[3] = OSSL_PARAM_construct_octet_string("label", tls13_exp_master, sizeof(tls13_exp_master) - 1);
    ret = EVP_KDF_derive(kctx, tc->expt_master_secret, md_size, exp_params);
    if (ret != 1) {
        printf("Error deriving exporter master secret in TLS1.3 KDF\n");
        goto err;
    }
    tc->ems_len = md_size;

    /* Create resumption master secret */
    EVP_KDF_CTX_reset(kctx);
    exp_params[3] = OSSL_PARAM_construct_octet_string("label", tls13_res_master, sizeof(tls13_res_master) - 1);
    exp_params[5] = OSSL_PARAM_construct_octet_string("data", client_hash, md_size);
    ret = EVP_KDF_derive(kctx, tc->resume_master_secret, md_size, exp_params);
    if (ret != 1) {
        printf("Error deriving resume master secret in TLS1.3 KDF\n");
        goto err;
    }
    tc->rms_len = md_size;

    rv = 0;

err:
    if (zero_input) free(zero_input);
    if (handshake_secret) free(handshake_secret);
    if (master_secret) free(master_secret);
    if (early_secret) free(early_secret);
    if (finish_hash) free(finish_hash);
    if (hello_hash) free(hello_hash);
    if (client_hello_hash) free(client_hello_hash);
    if (client_hash) free(client_hash);
    if (md) free(md);
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    return rv;
}
