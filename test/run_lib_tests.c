/** @file */
/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include "ut_common.h"

// Library TEST_GROUP_RUNNER definitions

TEST_GROUP_RUNNER(AES_API) {
    RUN_TEST_CASE(AES_API, empty_ctx);
    RUN_TEST_CASE(AES_API, null_ctx);
    RUN_TEST_CASE(AES_API, null_json_obj);
}

TEST_GROUP_RUNNER(AES_CAPABILITY) {
    RUN_TEST_CASE(AES_CAPABILITY, good);
}

TEST_GROUP_RUNNER(AES_HANDLER) {
    RUN_TEST_CASE(AES_HANDLER, good);
    RUN_TEST_CASE(AES_HANDLER, wrong_algorithm);
    RUN_TEST_CASE(AES_HANDLER, missing_direction);
    RUN_TEST_CASE(AES_HANDLER, wrong_direction);
    RUN_TEST_CASE(AES_HANDLER, missing_testType);
    RUN_TEST_CASE(AES_HANDLER, wrong_testType);
    RUN_TEST_CASE(AES_HANDLER, missing_keyLen);
    RUN_TEST_CASE(AES_HANDLER, wrong_keyLen);
    RUN_TEST_CASE(AES_HANDLER, big_ptLen);
    RUN_TEST_CASE(AES_HANDLER, missing_ivLen);
    RUN_TEST_CASE(AES_HANDLER, small_ivLen_gcm);
    RUN_TEST_CASE(AES_HANDLER, big_ivLen_gcm);
    RUN_TEST_CASE(AES_HANDLER, small_ivLen_ccm);
    RUN_TEST_CASE(AES_HANDLER, big_ivLen_ccm);
    RUN_TEST_CASE(AES_HANDLER, wrong_ivLen_ccm);
    RUN_TEST_CASE(AES_HANDLER, small_tagLen);
    RUN_TEST_CASE(AES_HANDLER, big_tagLen);
    RUN_TEST_CASE(AES_HANDLER, big_aadLen);
    RUN_TEST_CASE(AES_HANDLER, missing_key);
    RUN_TEST_CASE(AES_HANDLER, long_key);
    RUN_TEST_CASE(AES_HANDLER, missing_pt);
    RUN_TEST_CASE(AES_HANDLER, long_pt);
    RUN_TEST_CASE(AES_HANDLER, missing_ct);
    RUN_TEST_CASE(AES_HANDLER, long_ct);
    RUN_TEST_CASE(AES_HANDLER, missing_tag);
    RUN_TEST_CASE(AES_HANDLER, long_tag);
    RUN_TEST_CASE(AES_HANDLER, missing_iv);
    RUN_TEST_CASE(AES_HANDLER, long_iv);
    RUN_TEST_CASE(AES_HANDLER, missing_aad);
    RUN_TEST_CASE(AES_HANDLER, long_aad);
    RUN_TEST_CASE(AES_HANDLER, missing_gid);
    RUN_TEST_CASE(AES_HANDLER, bad_inc_ctr);
    RUN_TEST_CASE(AES_HANDLER, bad_ovrflw_ctr);
    RUN_TEST_CASE(AES_HANDLER, tgLast);
    RUN_TEST_CASE(AES_HANDLER, tcLast);
    RUN_TEST_CASE(AES_HANDLER, cryptoFail1);
    RUN_TEST_CASE(AES_HANDLER, cryptoFail2);
    RUN_TEST_CASE(AES_HANDLER, cryptoFail3);
    RUN_TEST_CASE(AES_HANDLER, cryptoFail4);
}

TEST_GROUP_RUNNER(BUILD_DEPS) {
    // RUN_TEST_CASE(BUILD_DEPS, null_dep);  // Disabled (in #if 0)
    // RUN_TEST_CASE(BUILD_DEPS, good_deps_output);  // Disabled (in #if 0)
}

TEST_GROUP_RUNNER(BUILD_MODULES) {
    // RUN_TEST_CASE(BUILD_MODULES, null_ctx);  // Disabled (in #if 0)
    // RUN_TEST_CASE(BUILD_MODULES, good_modules_output);  // Disabled (in #if 0)
}

TEST_GROUP_RUNNER(BUILD_OES) {
    // RUN_TEST_CASE(BUILD_OES, null_ctx);  // Disabled (in #if 0)
    // RUN_TEST_CASE(BUILD_OES, good_oes_output);  // Disabled (in #if 0)
}

TEST_GROUP_RUNNER(BUILD_TEST_SESSION) {
    RUN_TEST_CASE(BUILD_TEST_SESSION, null_ctx);
    RUN_TEST_CASE(BUILD_TEST_SESSION, np_caps_ctx);
    RUN_TEST_CASE(BUILD_TEST_SESSION, good_aes_output);
    RUN_TEST_CASE(BUILD_TEST_SESSION, missing_required_keylen_aes);
    RUN_TEST_CASE(BUILD_TEST_SESSION, missing_required_direction_aes);
    RUN_TEST_CASE(BUILD_TEST_SESSION, good_hash);
    RUN_TEST_CASE(BUILD_TEST_SESSION, good_drbg);
    RUN_TEST_CASE(BUILD_TEST_SESSION, drbg_missing_cap_parms);
    RUN_TEST_CASE(BUILD_TEST_SESSION, good_cmac_output);
    RUN_TEST_CASE(BUILD_TEST_SESSION, cmac_missing_direction);
    RUN_TEST_CASE(BUILD_TEST_SESSION, cmac_missing_tdes_ko);
    RUN_TEST_CASE(BUILD_TEST_SESSION, good_hmac);
    RUN_TEST_CASE(BUILD_TEST_SESSION, good_dsa);
    RUN_TEST_CASE(BUILD_TEST_SESSION, dsa_missing_pqgen);
    RUN_TEST_CASE(BUILD_TEST_SESSION, dsa_missing_ggen);
    RUN_TEST_CASE(BUILD_TEST_SESSION, dsa_missing_hashalgs);
    RUN_TEST_CASE(BUILD_TEST_SESSION, good_des_output);
    RUN_TEST_CASE(BUILD_TEST_SESSION, good_rsa);
    RUN_TEST_CASE(BUILD_TEST_SESSION, rsa_no_params);
    RUN_TEST_CASE(BUILD_TEST_SESSION, good_ecdsa);
    RUN_TEST_CASE(BUILD_TEST_SESSION, ecdsa_no_params);
    RUN_TEST_CASE(BUILD_TEST_SESSION, good_kdf);
    RUN_TEST_CASE(BUILD_TEST_SESSION, kdf_more_modes);
    RUN_TEST_CASE(BUILD_TEST_SESSION, good_kas_ecc);
    RUN_TEST_CASE(BUILD_TEST_SESSION, kas_ecc_no_params);
    RUN_TEST_CASE(BUILD_TEST_SESSION, good_kas_ffc);
    RUN_TEST_CASE(BUILD_TEST_SESSION, kas_ffc_no_params);
}

TEST_GROUP_RUNNER(BUILD_VENDORS) {
    // RUN_TEST_CASE(BUILD_VENDORS, null_ctx);  // Disabled (in #if 0)
    // RUN_TEST_CASE(BUILD_VENDORS, good_vendors_output);  // Disabled (in #if 0)
}

TEST_GROUP_RUNNER(CHECK_RESULTS) {
    RUN_TEST_CASE(CHECK_RESULTS, no_vs_list);
}

TEST_GROUP_RUNNER(CMAC_AES_CAPABILITY) {
    RUN_TEST_CASE(CMAC_AES_CAPABILITY, good);
}

TEST_GROUP_RUNNER(CMAC_API) {
    RUN_TEST_CASE(CMAC_API, empty_ctx);
    RUN_TEST_CASE(CMAC_API, null_ctx);
    RUN_TEST_CASE(CMAC_API, null_json_obj);
    RUN_TEST_CASE(CMAC_API, good_aes);
    RUN_TEST_CASE(CMAC_API, good_tdes);
    RUN_TEST_CASE(CMAC_API, wrong_algorithm);
    RUN_TEST_CASE(CMAC_API, missing_direction);
    RUN_TEST_CASE(CMAC_API, wrong_direction);
    RUN_TEST_CASE(CMAC_API, missing_keyLen);
    RUN_TEST_CASE(CMAC_API, missing_msgLen);
    RUN_TEST_CASE(CMAC_API, missing_macLen);
    RUN_TEST_CASE(CMAC_API, missing_key_aes);
    RUN_TEST_CASE(CMAC_API, missing_msg);
    RUN_TEST_CASE(CMAC_API, missing_mac);
    RUN_TEST_CASE(CMAC_API, key_wrong_length);
    RUN_TEST_CASE(CMAC_API, missing_keyingOption_tdes);
    RUN_TEST_CASE(CMAC_API, wrong_keyingOption_tdes);
    RUN_TEST_CASE(CMAC_API, missing_key1_tdes);
    RUN_TEST_CASE(CMAC_API, missing_key2_tdes);
    RUN_TEST_CASE(CMAC_API, missing_key3_tdes);
    RUN_TEST_CASE(CMAC_API, msg_too_long);
    RUN_TEST_CASE(CMAC_API, key1_wrong_length);
    RUN_TEST_CASE(CMAC_API, key2_wrong_length);
    RUN_TEST_CASE(CMAC_API, key3_wrong_length);
    RUN_TEST_CASE(CMAC_API, tgid_missing);
    RUN_TEST_CASE(CMAC_API, cryptoFail1);
    RUN_TEST_CASE(CMAC_API, cryptoFail2);
    RUN_TEST_CASE(CMAC_API, cryptoFail3);
    RUN_TEST_CASE(CMAC_API, cryptoFail4);
    RUN_TEST_CASE(CMAC_API, tgFail1);
    RUN_TEST_CASE(CMAC_API, tcFail1);
    RUN_TEST_CASE(CMAC_API, tgFail2);
    RUN_TEST_CASE(CMAC_API, tcFail2);
}

TEST_GROUP_RUNNER(CMAC_TDES_CAPABILITY) {
    RUN_TEST_CASE(CMAC_TDES_CAPABILITY, good);
}

TEST_GROUP_RUNNER(CREATE_CTX) {
    RUN_TEST_CASE(CREATE_CTX, good);
    RUN_TEST_CASE(CREATE_CTX, dup_ctx);
    RUN_TEST_CASE(CREATE_CTX, null_ctx);
}

TEST_GROUP_RUNNER(Cleanup) {
    RUN_TEST_CASE(Cleanup, null_ctx);
}

TEST_GROUP_RUNNER(CreateSession) {
    RUN_TEST_CASE(CreateSession, properly);
    RUN_TEST_CASE(CreateSession, null_ctx);
}

TEST_GROUP_RUNNER(DEPENDENCY_NEW) {
    RUN_TEST_CASE(DEPENDENCY_NEW, dependency_new);
}

TEST_GROUP_RUNNER(DES_API) {
    RUN_TEST_CASE(DES_API, empty_ctx);
    RUN_TEST_CASE(DES_API, null_ctx);
    RUN_TEST_CASE(DES_API, null_json_obj);
}

TEST_GROUP_RUNNER(DES_CAPABILITY) {
    RUN_TEST_CASE(DES_CAPABILITY, good);
}

TEST_GROUP_RUNNER(DES_HANDLER) {
    RUN_TEST_CASE(DES_HANDLER, good);
    RUN_TEST_CASE(DES_HANDLER, wrong_algorithm);
    RUN_TEST_CASE(DES_HANDLER, missing_direction);
    RUN_TEST_CASE(DES_HANDLER, wrong_direction);
    RUN_TEST_CASE(DES_HANDLER, missing_testType);
    RUN_TEST_CASE(DES_HANDLER, wrong_testType);
    RUN_TEST_CASE(DES_HANDLER, missing_key1);
    RUN_TEST_CASE(DES_HANDLER, wrong_key1);
    RUN_TEST_CASE(DES_HANDLER, missing_key2);
    RUN_TEST_CASE(DES_HANDLER, wrong_key2);
    RUN_TEST_CASE(DES_HANDLER, missing_key3);
    RUN_TEST_CASE(DES_HANDLER, wrong_key3);
    RUN_TEST_CASE(DES_HANDLER, missing_pt);
    RUN_TEST_CASE(DES_HANDLER, wrong_pt);
    RUN_TEST_CASE(DES_HANDLER, missing_ct);
    RUN_TEST_CASE(DES_HANDLER, wrong_ct);
    RUN_TEST_CASE(DES_HANDLER, missing_iv);
    RUN_TEST_CASE(DES_HANDLER, wrong_iv);
    RUN_TEST_CASE(DES_HANDLER, missing_tgid);
    RUN_TEST_CASE(DES_HANDLER, bad_inc_ctr);
    RUN_TEST_CASE(DES_HANDLER, bad_ovrflw_ctr);
    RUN_TEST_CASE(DES_HANDLER, tgLast);
    RUN_TEST_CASE(DES_HANDLER, tcLast);
    RUN_TEST_CASE(DES_HANDLER, cryptoFail1);
    RUN_TEST_CASE(DES_HANDLER, cryptoFail2);
    RUN_TEST_CASE(DES_HANDLER, cryptoFail3);
    RUN_TEST_CASE(DES_HANDLER, cryptoFail4);
}

TEST_GROUP_RUNNER(DRBG_API) {
    RUN_TEST_CASE(DRBG_API, empty_ctx);
    RUN_TEST_CASE(DRBG_API, null_ctx);
    RUN_TEST_CASE(DRBG_API, null_json_obj);
}

TEST_GROUP_RUNNER(DRBG_CAPABILITY) {
    RUN_TEST_CASE(DRBG_CAPABILITY, good);
}

TEST_GROUP_RUNNER(DRBG_HANDDLER) {
    RUN_TEST_CASE(DRBG_HANDDLER, cryptoFail1);
    RUN_TEST_CASE(DRBG_HANDDLER, cryptoFail2);
    RUN_TEST_CASE(DRBG_HANDDLER, tgFail1);
    RUN_TEST_CASE(DRBG_HANDDLER, tcFail1);
}

TEST_GROUP_RUNNER(DRBG_HANDLER) {
    RUN_TEST_CASE(DRBG_HANDLER, good);
    RUN_TEST_CASE(DRBG_HANDLER, missing_algorithm);
    RUN_TEST_CASE(DRBG_HANDLER, wrong_algorithm);
    RUN_TEST_CASE(DRBG_HANDLER, missing_mode);
    RUN_TEST_CASE(DRBG_HANDLER, wrong_mode);
    RUN_TEST_CASE(DRBG_HANDLER, missing_predResistance);
    RUN_TEST_CASE(DRBG_HANDLER, missing_derFunc);
    RUN_TEST_CASE(DRBG_HANDLER, missing_entropyInputLen);
    RUN_TEST_CASE(DRBG_HANDLER, small_entropyInputLen);
    RUN_TEST_CASE(DRBG_HANDLER, big_entropyInputLen);
    RUN_TEST_CASE(DRBG_HANDLER, missing_nonceLen);
    RUN_TEST_CASE(DRBG_HANDLER, small_nonceLen);
    RUN_TEST_CASE(DRBG_HANDLER, big_nonceLen);
    RUN_TEST_CASE(DRBG_HANDLER, big_persoStringLen);
    RUN_TEST_CASE(DRBG_HANDLER, missing_returnedBitsLen);
    RUN_TEST_CASE(DRBG_HANDLER, big_returnedBitsLen);
    RUN_TEST_CASE(DRBG_HANDLER, big_additionalInputLen);
    RUN_TEST_CASE(DRBG_HANDLER, missing_persoString);
    RUN_TEST_CASE(DRBG_HANDLER, long_persoString);
    RUN_TEST_CASE(DRBG_HANDLER, missing_entropyInput);
    RUN_TEST_CASE(DRBG_HANDLER, long_entropyInput);
    RUN_TEST_CASE(DRBG_HANDLER, missing_nonce);
    RUN_TEST_CASE(DRBG_HANDLER, long_nonce);
    RUN_TEST_CASE(DRBG_HANDLER, missing_otherInput);
    RUN_TEST_CASE(DRBG_HANDLER, empty_otherInput);
    RUN_TEST_CASE(DRBG_HANDLER, missing_additionalInput_oi0);
    RUN_TEST_CASE(DRBG_HANDLER, long_additionalInput_oi0);
    RUN_TEST_CASE(DRBG_HANDLER, missing_entropyInput_oi0);
    RUN_TEST_CASE(DRBG_HANDLER, long_entropyInput_oi0);
    RUN_TEST_CASE(DRBG_HANDLER, missing_additionalInput_oi1);
    RUN_TEST_CASE(DRBG_HANDLER, long_additionalInput_oi1);
    RUN_TEST_CASE(DRBG_HANDLER, missing_entropyInput_oi1);
    RUN_TEST_CASE(DRBG_HANDLER, long_entropyInput_oi1);
}

TEST_GROUP_RUNNER(DsaKeyGenApi) {
    RUN_TEST_CASE(DsaKeyGenApi, null_ctx);
}

TEST_GROUP_RUNNER(DsaKeyGenFunc) {
    RUN_TEST_CASE(DsaKeyGenFunc, null_ctx);
}

TEST_GROUP_RUNNER(DsaKeyGen_HANDLER) {
    RUN_TEST_CASE(DsaKeyGen_HANDLER, cryptoFail1);
    RUN_TEST_CASE(DsaKeyGen_HANDLER, cryptoFail2);
}

TEST_GROUP_RUNNER(DsaPqgGenApi) {
    RUN_TEST_CASE(DsaPqgGenApi, null_ctx);
}

TEST_GROUP_RUNNER(DsaPqgGenFunc) {
    RUN_TEST_CASE(DsaPqgGenFunc, null_ctx);
}

TEST_GROUP_RUNNER(DsaPqgVerApi) {
    RUN_TEST_CASE(DsaPqgVerApi, null_ctx);
}

TEST_GROUP_RUNNER(DsaPqgVerFunc) {
    RUN_TEST_CASE(DsaPqgVerFunc, null_ctx);
}

TEST_GROUP_RUNNER(DsaPqgVer_HANDLER) {
    RUN_TEST_CASE(DsaPqgVer_HANDLER, cryptoFail1);
    RUN_TEST_CASE(DsaPqgVer_HANDLER, cryptoFail2);
}

TEST_GROUP_RUNNER(DsaSigGenApi) {
    RUN_TEST_CASE(DsaSigGenApi, null_ctx);
}

TEST_GROUP_RUNNER(DsaSigGenFunc) {
    RUN_TEST_CASE(DsaSigGenFunc, null_ctx);
}

TEST_GROUP_RUNNER(DsaSigVerApi) {
    RUN_TEST_CASE(DsaSigVerApi, null_ctx);
}

TEST_GROUP_RUNNER(DsaSigVerFunc) {
    RUN_TEST_CASE(DsaSigVerFunc, null_ctx);
}

TEST_GROUP_RUNNER(ECDSA_API) {
    RUN_TEST_CASE(ECDSA_API, empty_ctx);
    RUN_TEST_CASE(ECDSA_API, null_ctx);
    RUN_TEST_CASE(ECDSA_API, null_json_obj);
}

TEST_GROUP_RUNNER(ECDSA_CAPABILITY) {
    RUN_TEST_CASE(ECDSA_CAPABILITY, good);
}

TEST_GROUP_RUNNER(ECDSA_HANDLER) {
    RUN_TEST_CASE(ECDSA_HANDLER, good_sv);
    RUN_TEST_CASE(ECDSA_HANDLER, good_kg);
    RUN_TEST_CASE(ECDSA_HANDLER, good_kv);
    RUN_TEST_CASE(ECDSA_HANDLER, good_sg);
    RUN_TEST_CASE(ECDSA_HANDLER, wrong_algorithm);
    RUN_TEST_CASE(ECDSA_HANDLER, missing_mode);
    RUN_TEST_CASE(ECDSA_HANDLER, wrong_mode);
    RUN_TEST_CASE(ECDSA_HANDLER, missing_testgroups);
    RUN_TEST_CASE(ECDSA_HANDLER, missing_curve);
    RUN_TEST_CASE(ECDSA_HANDLER, wrong_curve);
    RUN_TEST_CASE(ECDSA_HANDLER, missing_tgid);
    RUN_TEST_CASE(ECDSA_HANDLER, missing_hashalg_sg);
    RUN_TEST_CASE(ECDSA_HANDLER, wrong_hashalg);
    RUN_TEST_CASE(ECDSA_HANDLER, missing_message);
    RUN_TEST_CASE(ECDSA_HANDLER, too_long_message);
    RUN_TEST_CASE(ECDSA_HANDLER, missing_qx);
    RUN_TEST_CASE(ECDSA_HANDLER, missing_qy);
    RUN_TEST_CASE(ECDSA_HANDLER, too_long_qx);
    RUN_TEST_CASE(ECDSA_HANDLER, too_long_qy);
    RUN_TEST_CASE(ECDSA_HANDLER, missing_r);
    RUN_TEST_CASE(ECDSA_HANDLER, missing_s);
    RUN_TEST_CASE(ECDSA_HANDLER, too_long_r);
    RUN_TEST_CASE(ECDSA_HANDLER, too_long_s);
    RUN_TEST_CASE(ECDSA_HANDLER, cryptoFail1);
    RUN_TEST_CASE(ECDSA_HANDLER, cryptoFail2);
    RUN_TEST_CASE(ECDSA_HANDLER, cryptoFail3);
    RUN_TEST_CASE(ECDSA_HANDLER, cryptoFail4);
    RUN_TEST_CASE(ECDSA_HANDLER, cryptoFail5);
    RUN_TEST_CASE(ECDSA_HANDLER, cryptoFail6);
    RUN_TEST_CASE(ECDSA_HANDLER, cryptoFail7);
    RUN_TEST_CASE(ECDSA_HANDLER, cryptoFail8);
    RUN_TEST_CASE(ECDSA_HANDLER, tgFail1);
    RUN_TEST_CASE(ECDSA_HANDLER, tcFail1);
    RUN_TEST_CASE(ECDSA_HANDLER, tgFail2);
    RUN_TEST_CASE(ECDSA_HANDLER, tcFail2);
    RUN_TEST_CASE(ECDSA_HANDLER, tgFail3);
    RUN_TEST_CASE(ECDSA_HANDLER, tcFail3);
    RUN_TEST_CASE(ECDSA_HANDLER, tgFail4);
    RUN_TEST_CASE(ECDSA_HANDLER, tcFail4);
}

TEST_GROUP_RUNNER(EnableCapAES) {
    RUN_TEST_CASE(EnableCapAES, properly);
    RUN_TEST_CASE(EnableCapAES, alg_mismatch);
    RUN_TEST_CASE(EnableCapAES, bad_conformance);
    RUN_TEST_CASE(EnableCapAES, invalid_callback);
    RUN_TEST_CASE(EnableCapAES, invalid_dir);
    RUN_TEST_CASE(EnableCapAES, cipher_param_mismatch);
    RUN_TEST_CASE(EnableCapAES, invalid_keylens);
    RUN_TEST_CASE(EnableCapAES, invalid_param_lens);
    RUN_TEST_CASE(EnableCapAES, cipher_invalid_parm_domain);
    RUN_TEST_CASE(EnableCapAES, cipher_domain_no_ctx);
    RUN_TEST_CASE(EnableCapAES, cipher_domain_bad_values);
    RUN_TEST_CASE(EnableCapAES, dup_payload_registration);
}

TEST_GROUP_RUNNER(EnableCapCMAC) {
    RUN_TEST_CASE(EnableCapCMAC, properly);
    RUN_TEST_CASE(EnableCapCMAC, param_alg_mismatch);
    RUN_TEST_CASE(EnableCapCMAC, null_handler);
    RUN_TEST_CASE(EnableCapCMAC, invalid_args);
}

TEST_GROUP_RUNNER(EnableCapDRBG) {
    RUN_TEST_CASE(EnableCapDRBG, good_hash);
    RUN_TEST_CASE(EnableCapDRBG, good_hmac);
    RUN_TEST_CASE(EnableCapDRBG, good_ctr);
    RUN_TEST_CASE(EnableCapDRBG, null_ctx);
}

TEST_GROUP_RUNNER(EnableCapECDSA) {
    RUN_TEST_CASE(EnableCapECDSA, good_keygen);
    RUN_TEST_CASE(EnableCapECDSA, mode_mismatch_kg);
    RUN_TEST_CASE(EnableCapECDSA, invalid_params_kg);
    RUN_TEST_CASE(EnableCapECDSA, good_keyver);
    RUN_TEST_CASE(EnableCapECDSA, invalid_params_kv);
    RUN_TEST_CASE(EnableCapECDSA, good_siggen);
    RUN_TEST_CASE(EnableCapECDSA, invalid_args_sg);
    RUN_TEST_CASE(EnableCapECDSA, good_sigver);
    RUN_TEST_CASE(EnableCapECDSA, invalid_args_sv);
}

TEST_GROUP_RUNNER(EnableCapHMAC) {
    RUN_TEST_CASE(EnableCapHMAC, properly);
    RUN_TEST_CASE(EnableCapHMAC, param_alg_mismatch);
    RUN_TEST_CASE(EnableCapHMAC, null_handler);
    RUN_TEST_CASE(EnableCapHMAC, invalid_args);
}

TEST_GROUP_RUNNER(EnableCapHash) {
    RUN_TEST_CASE(EnableCapHash, properly);
    RUN_TEST_CASE(EnableCapHash, param_alg_mismatch);
    RUN_TEST_CASE(EnableCapHash, null_handler);
    RUN_TEST_CASE(EnableCapHash, invalid_args);
}

TEST_GROUP_RUNNER(EnableCapKASECC) {
    RUN_TEST_CASE(EnableCapKASECC, good);
    RUN_TEST_CASE(EnableCapKASECC, null_ctx);
    RUN_TEST_CASE(EnableCapKASECC, invalid_params);
}

TEST_GROUP_RUNNER(EnableCapKASFFC) {
    RUN_TEST_CASE(EnableCapKASFFC, good);
    RUN_TEST_CASE(EnableCapKASFFC, null_ctx);
    RUN_TEST_CASE(EnableCapKASFFC, invalid_params);
}

TEST_GROUP_RUNNER(EnableCapKASHKDF) {
    RUN_TEST_CASE(EnableCapKASHKDF, invalid_params);
}

TEST_GROUP_RUNNER(EnableCapKASKDFONESTEP) {
    RUN_TEST_CASE(EnableCapKASKDFONESTEP, invalid_params);
}

TEST_GROUP_RUNNER(EnableCapKDF108) {
    RUN_TEST_CASE(EnableCapKDF108, good);
    RUN_TEST_CASE(EnableCapKDF108, alg_mismatch);
    RUN_TEST_CASE(EnableCapKDF108, invalid_domain);
    RUN_TEST_CASE(EnableCapKDF108, invalid_params);
}

TEST_GROUP_RUNNER(EnableCapKDF135IKEv1) {
    RUN_TEST_CASE(EnableCapKDF135IKEv1, good);
    RUN_TEST_CASE(EnableCapKDF135IKEv1, null_vals);
    RUN_TEST_CASE(EnableCapKDF135IKEv1, invalid_domain);
    RUN_TEST_CASE(EnableCapKDF135IKEv1, invalid_params);
}

TEST_GROUP_RUNNER(EnableCapKDF135IKEv2) {
    RUN_TEST_CASE(EnableCapKDF135IKEv2, good);
    RUN_TEST_CASE(EnableCapKDF135IKEv2, good_domain);
    RUN_TEST_CASE(EnableCapKDF135IKEv2, null_params);
    RUN_TEST_CASE(EnableCapKDF135IKEv2, invalid_len_params);
    RUN_TEST_CASE(EnableCapKDF135IKEv2, invalid_hash_alg);
}

TEST_GROUP_RUNNER(EnableCapKDFSNMP) {
    RUN_TEST_CASE(EnableCapKDFSNMP, properly);
    RUN_TEST_CASE(EnableCapKDFSNMP, param_alg_mismatch);
    RUN_TEST_CASE(EnableCapKDFSNMP, invalid_params);
}

TEST_GROUP_RUNNER(EnableCapKDFSRTP) {
    RUN_TEST_CASE(EnableCapKDFSRTP, good);
    RUN_TEST_CASE(EnableCapKDFSRTP, null_ctx);
    RUN_TEST_CASE(EnableCapKDFSRTP, invalid_params);
}

TEST_GROUP_RUNNER(EnableCapKDFSSH) {
    RUN_TEST_CASE(EnableCapKDFSSH, properly);
    RUN_TEST_CASE(EnableCapKDFSSH, null_ctx);
    RUN_TEST_CASE(EnableCapKDFSSH, invalid_params);
    RUN_TEST_CASE(EnableCapKDFSSH, param_alg_mismatch);
}

TEST_GROUP_RUNNER(EnableCapKDFTLS13) {
    RUN_TEST_CASE(EnableCapKDFTLS13, valid_params);
    RUN_TEST_CASE(EnableCapKDFTLS13, invalid_params);
}

TEST_GROUP_RUNNER(EnableCapKDFx963) {
    RUN_TEST_CASE(EnableCapKDFx963, properly);
    RUN_TEST_CASE(EnableCapKDFx963, null_ctx);
    RUN_TEST_CASE(EnableCapKDFx963, invalid_params);
}

TEST_GROUP_RUNNER(EnableCapRSAkeyGen) {
    RUN_TEST_CASE(EnableCapRSAkeyGen, proper_params);
    RUN_TEST_CASE(EnableCapRSAkeyGen, proper_modes);
    RUN_TEST_CASE(EnableCapRSAkeyGen, proper_modes_params);
    RUN_TEST_CASE(EnableCapRSAkeyGen, alg_mismatch);
    RUN_TEST_CASE(EnableCapRSAkeyGen, invalid_params);
    RUN_TEST_CASE(EnableCapRSAkeyGen, invalid_modes_params);
    RUN_TEST_CASE(EnableCapRSAkeyGen, cipher_param_mismatch);
}

TEST_GROUP_RUNNER(EnableCapTDES) {
    RUN_TEST_CASE(EnableCapTDES, properly);
    RUN_TEST_CASE(EnableCapTDES, alg_param_mismatch);
}

TEST_GROUP_RUNNER(FIPS_VALIDATION_METADATA) {
    RUN_TEST_CASE(FIPS_VALIDATION_METADATA, set_fips_validation_metadata);
}

TEST_GROUP_RUNNER(FREE_CTX) {
    RUN_TEST_CASE(FREE_CTX, good);
}

TEST_GROUP_RUNNER(FREE_OPERATING_ENV) {
    RUN_TEST_CASE(FREE_OPERATING_ENV, free_operating_env);
}

TEST_GROUP_RUNNER(FREE_TEST_SESSION) {
    RUN_TEST_CASE(FREE_TEST_SESSION, good);
    RUN_TEST_CASE(FREE_TEST_SESSION, null_ctx);
    RUN_TEST_CASE(FREE_TEST_SESSION, good_full);
}

TEST_GROUP_RUNNER(GET_LIBRARY_VERSION) {
    RUN_TEST_CASE(GET_LIBRARY_VERSION, good);
}

TEST_GROUP_RUNNER(GET_PROTOCOL_VERSION) {
    RUN_TEST_CASE(GET_PROTOCOL_VERSION, good);
}

TEST_GROUP_RUNNER(GetObjFromRsp) {
    RUN_TEST_CASE(GetObjFromRsp, null_ctx);
}

TEST_GROUP_RUNNER(HASH_API) {
    RUN_TEST_CASE(HASH_API, empty_ctx);
    RUN_TEST_CASE(HASH_API, null_ctx);
    RUN_TEST_CASE(HASH_API, null_json_obj);
}

TEST_GROUP_RUNNER(HASH_CAPABILITY) {
    RUN_TEST_CASE(HASH_CAPABILITY, good);
}

TEST_GROUP_RUNNER(HASH_HANDLER) {
    RUN_TEST_CASE(HASH_HANDLER, good);
    RUN_TEST_CASE(HASH_HANDLER, wrong_algorithm);
    RUN_TEST_CASE(HASH_HANDLER, missing_testType);
    RUN_TEST_CASE(HASH_HANDLER, wrong_testType);
    RUN_TEST_CASE(HASH_HANDLER, missing_msg);
    RUN_TEST_CASE(HASH_HANDLER, long_msg);
    RUN_TEST_CASE(HASH_HANDLER, missing_tgId);
    RUN_TEST_CASE(HASH_HANDLER, missing_lasttgId);
    RUN_TEST_CASE(HASH_HANDLER, missing_lasttcId);
    RUN_TEST_CASE(HASH_HANDLER, cryptoFail1);
    RUN_TEST_CASE(HASH_HANDLER, cryptoFail2);
    RUN_TEST_CASE(HASH_HANDLER, cryptoFail3);
    RUN_TEST_CASE(HASH_HANDLER, cryptoFail4);
}

TEST_GROUP_RUNNER(HMAC_HANDLER) {
    RUN_TEST_CASE(HMAC_HANDLER, cryptoFail1);
    RUN_TEST_CASE(HMAC_HANDLER, cryptoFail2);
}

TEST_GROUP_RUNNER(HmacApi) {
    RUN_TEST_CASE(HmacApi, null_ctx);
}

TEST_GROUP_RUNNER(HmacFunc) {
    RUN_TEST_CASE(HmacFunc, null_ctx);
}

TEST_GROUP_RUNNER(INGEST_METADATA) {
    RUN_TEST_CASE(INGEST_METADATA, ingest_metadata);
}

TEST_GROUP_RUNNER(JsonSerializeToFilePrettyA) {
    RUN_TEST_CASE(JsonSerializeToFilePrettyA, null_param);
}

TEST_GROUP_RUNNER(JsonSerializeToFilePrettyW) {
    RUN_TEST_CASE(JsonSerializeToFilePrettyW, null_param);
}

TEST_GROUP_RUNNER(KAS_ECC_API) {
    RUN_TEST_CASE(KAS_ECC_API, null_ctx);
    RUN_TEST_CASE(KAS_ECC_API, null_json_obj);
}

TEST_GROUP_RUNNER(KAS_ECC_CAPABILITY) {
    RUN_TEST_CASE(KAS_ECC_CAPABILITY, good);
}

TEST_GROUP_RUNNER(KAS_ECC_CDH_API) {
    RUN_TEST_CASE(KAS_ECC_CDH_API, empty_ctx);
}

TEST_GROUP_RUNNER(KAS_ECC_CDH_HANDLER) {
    RUN_TEST_CASE(KAS_ECC_CDH_HANDLER, good);
    RUN_TEST_CASE(KAS_ECC_CDH_HANDLER, missing_algorithm);
    RUN_TEST_CASE(KAS_ECC_CDH_HANDLER, wrong_mode);
    RUN_TEST_CASE(KAS_ECC_CDH_HANDLER, missing_testType);
    RUN_TEST_CASE(KAS_ECC_CDH_HANDLER, wrong_testType);
    RUN_TEST_CASE(KAS_ECC_CDH_HANDLER, missing_curve);
    RUN_TEST_CASE(KAS_ECC_CDH_HANDLER, wrong_curve);
    RUN_TEST_CASE(KAS_ECC_CDH_HANDLER, missing_publicServerX);
    RUN_TEST_CASE(KAS_ECC_CDH_HANDLER, wrong_publicServerX);
    RUN_TEST_CASE(KAS_ECC_CDH_HANDLER, missing_publicServerY);
    RUN_TEST_CASE(KAS_ECC_CDH_HANDLER, wrong_publicServerY);
    RUN_TEST_CASE(KAS_ECC_CDH_HANDLER, tgFail1);
    RUN_TEST_CASE(KAS_ECC_CDH_HANDLER, tcFail1);
}

TEST_GROUP_RUNNER(KAS_ECC_COMP_API) {
    RUN_TEST_CASE(KAS_ECC_COMP_API, empty_ctx);
}

TEST_GROUP_RUNNER(KAS_ECC_COMP_HANDLER) {
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, good);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, missing_algorithm);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, wrong_mode);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, missing_testType);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, wrong_testType);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, missing_curve);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, wrong_curve);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, missing_hashAlg);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, wrong_hashAlg);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, missing_ephemeralPublicServerX);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, wrong_ephemeralPublicServerX);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, missing_ephemeralPublicServerY);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, wrong_ephemeralPublicServerY);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, missing_ephemeralPrivateIut);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, wrong_ephemeralPrivateIut);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, missing_ephemeralPublicIutX);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, wrong_ephemeralPublicIutX);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, missing_ephemeralPublicIutY);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, wrong_ephemeralPublicIutY);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, missing_hashZIut);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, wrong_hashZIut);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, cryptoFail1);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, cryptoFail2);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, cryptoFail3);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, cryptoFail4);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, tgFail1);
    RUN_TEST_CASE(KAS_ECC_COMP_HANDLER, tcFail1);
}

TEST_GROUP_RUNNER(KAS_ECC_SSC_HANDLER) {
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, good);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, missing_algorithm);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, missing_testType);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, wrong_testType);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, missing_curve);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, wrong_curve);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, missing_hashFunctionZ);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, wrong_hashFunctionZ);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, missing_ephemeralPublicServerX);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, wrong_ephemeralPublicServerX);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, missing_ephemeralPublicServerY);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, wrong_ephemeralPublicServerY);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, missing_ephemeralPrivateIut);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, missing_ephemeralPublicIutX);
    RUN_TEST_CASE(KAS_ECC_SSC_HANDLER, missing_ephemeralPublicIutY);
}

TEST_GROUP_RUNNER(KAS_FFC_API) {
    RUN_TEST_CASE(KAS_FFC_API, null_ctx);
    RUN_TEST_CASE(KAS_FFC_API, null_json_obj);
}

TEST_GROUP_RUNNER(KAS_FFC_CAPABILITY) {
    RUN_TEST_CASE(KAS_FFC_CAPABILITY, good);
}

TEST_GROUP_RUNNER(KAS_FFC_COMP_API) {
    RUN_TEST_CASE(KAS_FFC_COMP_API, empty_ctx);
}

TEST_GROUP_RUNNER(KAS_FFC_COMP_HANDLER) {
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, good);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, missing_algorithm);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, wrong_mode);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, missing_testType);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, wrong_testType);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, missing_hashAlg);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, wrong_hashAlg);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, missing_p);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, wrong_p);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, missing_q);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, wrong_q);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, missing_g);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, wrong_g);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, missing_ephemeralPublicServer);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, wrong_ephemeralPublicServer);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, missing_ephemeralPrivateIut);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, wrong_ephemeralPrivateIut);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, missing_ephemeralPublicIut);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, wrong_ephemeralPublicIut);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, missing_hashZ);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, wrong_hashZIut);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, cryptoFail1);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, cryptoFail2);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, tgFail1);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, tcFail1);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, ps_missing);
    RUN_TEST_CASE(KAS_FFC_COMP_HANDLER, ps_wrong);
}

TEST_GROUP_RUNNER(KAS_FFC_SP_HANDLER) {
    RUN_TEST_CASE(KAS_FFC_SP_HANDLER, good);
}

TEST_GROUP_RUNNER(KAS_FFC_SSC_HANDLER) {
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, good);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, missing_algorithm);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, missing_testType);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, wrong_testType);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, missing_hashAlg);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, wrong_hashAlg);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, missing_p);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, wrong_p);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, missing_q);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, wrong_q);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, missing_g);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, wrong_g);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, missing_ephemeralPublicServer);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, wrong_ephemeralPublicServer);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, missing_ephemeralPrivateIut);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, wrong_ephemeralPrivateIut);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, missing_ephemeralPublicIut);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, wrong_ephemeralPublicIut);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, missing_hashZ);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, wrong_hashZ);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, cryptoFail1);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, cryptoFail2);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, tgFail1);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, tcFail1);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, dpgm_missing);
    RUN_TEST_CASE(KAS_FFC_SSC_HANDLER, dpgm_wrong);
}

TEST_GROUP_RUNNER(KAS_IFC_API) {
    RUN_TEST_CASE(KAS_IFC_API, null_ctx);
    RUN_TEST_CASE(KAS_IFC_API, null_json_obj);
}

TEST_GROUP_RUNNER(KAS_IFC_CAPABILITY) {
    RUN_TEST_CASE(KAS_IFC_CAPABILITY, good);
}

TEST_GROUP_RUNNER(KAS_IFC_SSC_API) {
    RUN_TEST_CASE(KAS_IFC_SSC_API, empty_ctx);
}

TEST_GROUP_RUNNER(KAS_IFC_SSC_HANDLER) {
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, good);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_algorithm);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_testType);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, wrong_testType);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_hashFunctionZ);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, wrong_hashFunctionZ);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_p);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_q);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_d);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_e);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_n);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_serverc);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_servere);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_c);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_z);
    // RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_hashz);  // Disabled (in #if 0)
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_scheme);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_kasrole);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_keygen);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_modulo);
    RUN_TEST_CASE(KAS_IFC_SSC_HANDLER, missing_fixedpub);
}

TEST_GROUP_RUNNER(KDA_API) {
    RUN_TEST_CASE(KDA_API, empty_ctx);
    RUN_TEST_CASE(KDA_API, null_ctx);
    RUN_TEST_CASE(KDA_API, null_json_obj);
}

TEST_GROUP_RUNNER(KDA_CAPABILITY) {
    RUN_TEST_CASE(KDA_CAPABILITY, good);
}

TEST_GROUP_RUNNER(KDA_HANDLER) {
    RUN_TEST_CASE(KDA_HANDLER, good);
}

TEST_GROUP_RUNNER(KDA_HKDF_HANDLER) {
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_algorithm);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_mode);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, bad_mode);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_type);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, bad_type);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_kdfConfiguration);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_l);
    // RUN_TEST_CASE(KDA_HKDF_HANDLER, bad_saltlen);  // Disabled (commented out)
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_saltmethod);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, bad_saltmethod);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_fixedinfoencoding);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, bad_fixedinfoencoding);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_hmacalg);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, bad_hmacalg);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_fixedinfopattern);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, empty_fixedinfopattern);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, bad_hex_fixedinfopattern);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_vpartyinfo_fixedinfopattern);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_upartyinfo_fixedinfopattern);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_salt);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_z);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_fixedinfopartyu);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_upartyid);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_fixedinfopartyv);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_vpartyid);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_algorithmid);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_label);
    RUN_TEST_CASE(KDA_HKDF_HANDLER, missing_context);
}

TEST_GROUP_RUNNER(KDA_ONESTEP_HANDLER) {
    RUN_TEST_CASE(KDA_ONESTEP_HANDLER, missing_algorithm);
    RUN_TEST_CASE(KDA_ONESTEP_HANDLER, missing_mode);
    RUN_TEST_CASE(KDA_ONESTEP_HANDLER, wrong_mode);
    RUN_TEST_CASE(KDA_ONESTEP_HANDLER, missing_auxfunction);
    RUN_TEST_CASE(KDA_ONESTEP_HANDLER, bad_auxfunction);
}

TEST_GROUP_RUNNER(KDF108_API) {
    RUN_TEST_CASE(KDF108_API, empty_ctx);
    RUN_TEST_CASE(KDF108_API, null_ctx);
    RUN_TEST_CASE(KDF108_API, null_json_obj);
}

TEST_GROUP_RUNNER(KDF108_CAPABILITY) {
    RUN_TEST_CASE(KDF108_CAPABILITY, good);
}

TEST_GROUP_RUNNER(KDF108_HANDLER) {
    RUN_TEST_CASE(KDF108_HANDLER, good);
    RUN_TEST_CASE(KDF108_HANDLER, wrong_algorithm);
    RUN_TEST_CASE(KDF108_HANDLER, missing_kdfMode);
    RUN_TEST_CASE(KDF108_HANDLER, wrong_kdfMode);
    RUN_TEST_CASE(KDF108_HANDLER, missing_macMode);
    RUN_TEST_CASE(KDF108_HANDLER, wrong_macMode);
    RUN_TEST_CASE(KDF108_HANDLER, missing_keyOutLength);
    RUN_TEST_CASE(KDF108_HANDLER, big_keyOutLength);
    RUN_TEST_CASE(KDF108_HANDLER, missing_counterLength);
    RUN_TEST_CASE(KDF108_HANDLER, wrong_counterLength);
    RUN_TEST_CASE(KDF108_HANDLER, missing_counterLocation);
    RUN_TEST_CASE(KDF108_HANDLER, wrong_counterLocation);
    RUN_TEST_CASE(KDF108_HANDLER, missing_keyIn);
    RUN_TEST_CASE(KDF108_HANDLER, long_keyIn);
    RUN_TEST_CASE(KDF108_HANDLER, missing_iv);
    RUN_TEST_CASE(KDF108_HANDLER, long_iv);
    RUN_TEST_CASE(KDF108_HANDLER, missing_deferred);
    RUN_TEST_CASE(KDF108_HANDLER, missing_tgId);
    RUN_TEST_CASE(KDF108_HANDLER, missing_tgLoop);
    RUN_TEST_CASE(KDF108_HANDLER, missing_tcLoop);
    RUN_TEST_CASE(KDF108_HANDLER, cryptoFail1);
    RUN_TEST_CASE(KDF108_HANDLER, cryptoFail2);
}

TEST_GROUP_RUNNER(KDF135_IKEV1_API) {
    RUN_TEST_CASE(KDF135_IKEV1_API, empty_ctx);
    RUN_TEST_CASE(KDF135_IKEV1_API, null_ctx);
    RUN_TEST_CASE(KDF135_IKEV1_API, null_json_obj);
}

TEST_GROUP_RUNNER(KDF135_IKEV1_CAPABILITY) {
    RUN_TEST_CASE(KDF135_IKEV1_CAPABILITY, good);
}

TEST_GROUP_RUNNER(KDF135_IKEV1_HANDLER) {
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, good);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, wrong_algorithm);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, missing_hashAlg);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, wrong_hashAlg);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, missing_authenticationMethod);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, wrong_authenticationMethod);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, missing_nInitLength);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, small_nInitLength);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, big_nInitLength);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, missing_nRespLength);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, small_nRespLength);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, big_nRespLength);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, missing_dhLength);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, small_dhLength);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, big_dhLength);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, missing_preSharedKeyLength);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, small_preSharedKeyLength);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, big_preSharedKeyLength);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, missing_nInit);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, wrong_nInit);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, missing_nResp);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, wrong_nResp);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, missing_ckyInit);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, long_ckyInit);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, missing_ckyResp);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, long_ckyResp);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, missing_gxy);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, long_gxy);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, missing_preSharedKey);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, long_preSharedKey);
    RUN_TEST_CASE(KDF135_IKEV1_HANDLER, missing_tgId);
}

TEST_GROUP_RUNNER(KDF135_IKEV2_API) {
    RUN_TEST_CASE(KDF135_IKEV2_API, empty_ctx);
    RUN_TEST_CASE(KDF135_IKEV2_API, null_ctx);
    RUN_TEST_CASE(KDF135_IKEV2_API, null_json_obj);
}

TEST_GROUP_RUNNER(KDF135_IKEV2_CAPABILITY) {
    RUN_TEST_CASE(KDF135_IKEV2_CAPABILITY, good);
}

TEST_GROUP_RUNNER(KDF135_IKEV2_HANDLER) {
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, good);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, wrong_algorithm);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, missing_hashAlg);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, wrong_hashAlg);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, missing_nInitLength);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, small_nInitLength);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, big_nInitLength);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, missing_nRespLength);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, small_nRespLength);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, big_nRespLength);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, missing_dhLength);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, small_dhLength);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, big_dhLength);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, missing_derivedKeyingMaterialLength);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, small_derivedKeyingMaterialLength);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, big_derivedKeyingMaterialLength);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, missing_nInit);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, wrong_nInit);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, missing_nResp);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, wrong_nResp);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, missing_spiInit);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, long_spiInit);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, missing_spiResp);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, long_spiResp);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, missing_gir);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, long_gir);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, missing_girNew);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, long_girNew);
    RUN_TEST_CASE(KDF135_IKEV2_HANDLER, missing_tgId);
}

TEST_GROUP_RUNNER(KDF135_SRTP_API) {
    RUN_TEST_CASE(KDF135_SRTP_API, empty_ctx);
    RUN_TEST_CASE(KDF135_SRTP_API, null_ctx);
    RUN_TEST_CASE(KDF135_SRTP_API, null_json_obj);
}

TEST_GROUP_RUNNER(KDF135_SRTP_CAPABILITY) {
    RUN_TEST_CASE(KDF135_SRTP_CAPABILITY, good);
}

TEST_GROUP_RUNNER(KDF135_SRTP_HANDLER) {
    RUN_TEST_CASE(KDF135_SRTP_HANDLER, good);
    RUN_TEST_CASE(KDF135_SRTP_HANDLER, wrong_algorithm);
    RUN_TEST_CASE(KDF135_SRTP_HANDLER, missing_aesKeyLength);
    RUN_TEST_CASE(KDF135_SRTP_HANDLER, missing_kdr);
    RUN_TEST_CASE(KDF135_SRTP_HANDLER, missing_masterKey);
    RUN_TEST_CASE(KDF135_SRTP_HANDLER, missing_index);
    RUN_TEST_CASE(KDF135_SRTP_HANDLER, missing_srtcpIndex);
    RUN_TEST_CASE(KDF135_SRTP_HANDLER, missing_tgId);
}

TEST_GROUP_RUNNER(KDF_TLS12_API) {
    RUN_TEST_CASE(KDF_TLS12_API, empty_ctx);
    RUN_TEST_CASE(KDF_TLS12_API, null_ctx);
    RUN_TEST_CASE(KDF_TLS12_API, null_json_obj);
}

TEST_GROUP_RUNNER(KDF_TLS12_CAPABILITY) {
    RUN_TEST_CASE(KDF_TLS12_CAPABILITY, good);
}

TEST_GROUP_RUNNER(KDF_TLS12_HANDLER) {
    RUN_TEST_CASE(KDF_TLS12_HANDLER, good);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, wrong_algorithm);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, wrong_mode);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, missing_mode);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, wrong_hashAlg);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, missing_hashAlg);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, wrong_preMasterSecretLength);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, missing_preMasterSecretLength);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, missing_keyBlockLength);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, wrong_preMasterSecret);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, missing_preMasterSecret);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, missing_sessionHash);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, missing_clientRandom);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, missing_serverRandom);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, missing_tgId);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, cryptoFail1);
    RUN_TEST_CASE(KDF_TLS12_HANDLER, cryptoFail2);
}

TEST_GROUP_RUNNER(KDF_TLS13_API) {
    RUN_TEST_CASE(KDF_TLS13_API, empty_ctx);
    RUN_TEST_CASE(KDF_TLS13_API, null_ctx);
    RUN_TEST_CASE(KDF_TLS13_API, null_json_obj);
}

TEST_GROUP_RUNNER(KDF_TLS13_CAPABILITY) {
    RUN_TEST_CASE(KDF_TLS13_CAPABILITY, good);
}

TEST_GROUP_RUNNER(KDF_TLS13_HANDLER) {
    RUN_TEST_CASE(KDF_TLS13_HANDLER, good);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, bad_algorithm);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, no_algorithm);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, bad_mode);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, no_mode);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, bad_hmacalg);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, no_hmacalg);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, bad_runningmode);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, no_runningmode);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, bad_testtype);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, no_testtype);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, no_tcid);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, no_hcr);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, no_hsr);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, no_fcr);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, no_fsr);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, no_psk);
    RUN_TEST_CASE(KDF_TLS13_HANDLER, no_dhe);
}

TEST_GROUP_RUNNER(KMAC_128_CAPABILITY) {
    RUN_TEST_CASE(KMAC_128_CAPABILITY, good);
}

TEST_GROUP_RUNNER(KMAC_256_CAPABILITY) {
    RUN_TEST_CASE(KMAC_256_CAPABILITY, good);
}

TEST_GROUP_RUNNER(KMAC_API) {
    RUN_TEST_CASE(KMAC_API, empty_ctx);
    RUN_TEST_CASE(KMAC_API, null_ctx);
    RUN_TEST_CASE(KMAC_API, null_json_obj);
    RUN_TEST_CASE(KMAC_API, good_aes);
    RUN_TEST_CASE(KMAC_API, wrong_algorithm);
    RUN_TEST_CASE(KMAC_API, wrong_test_type);
    RUN_TEST_CASE(KMAC_API, missing_xof);
    RUN_TEST_CASE(KMAC_API, missing_hex_customization);
    RUN_TEST_CASE(KMAC_API, missing_msgLen);
    RUN_TEST_CASE(KMAC_API, missing_macLen);
    RUN_TEST_CASE(KMAC_API, missing_keyLen);
    RUN_TEST_CASE(KMAC_API, bad_msgLen);
    RUN_TEST_CASE(KMAC_API, bad_keyLen);
    RUN_TEST_CASE(KMAC_API, bad_macLen);
    RUN_TEST_CASE(KMAC_API, missing_msg);
    RUN_TEST_CASE(KMAC_API, missing_key);
    RUN_TEST_CASE(KMAC_API, missing_mac);
}

TEST_GROUP_RUNNER(KTS_IFC_API) {
    RUN_TEST_CASE(KTS_IFC_API, empty_ctx);
    RUN_TEST_CASE(KTS_IFC_API, null_ctx);
    RUN_TEST_CASE(KTS_IFC_API, null_json_obj);
}

TEST_GROUP_RUNNER(KTS_IFC_CAPABILITY) {
    RUN_TEST_CASE(KTS_IFC_CAPABILITY, good);
}

TEST_GROUP_RUNNER(KTS_IFC_HANDLER) {
    RUN_TEST_CASE(KTS_IFC_HANDLER, good);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_algorithm);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_testType);
    RUN_TEST_CASE(KTS_IFC_HANDLER, wrong_testType);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_hashAlg);
    RUN_TEST_CASE(KTS_IFC_HANDLER, wrong_hashAlg);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_adp);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_encoding);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_l);
    // RUN_TEST_CASE(KTS_IFC_HANDLER, missing_fpe);  // Disabled (in #if 0)
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_modulo);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_kgm);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_kr);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_scheme);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_ii);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_si);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_kcd);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_kcr);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_iutn);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_iute);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_iutp);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_iutq);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_iutd);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_serverc);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_servern);
    RUN_TEST_CASE(KTS_IFC_HANDLER, missing_servere);
}

TEST_GROUP_RUNNER(Kdf135SnmpApi) {
    RUN_TEST_CASE(Kdf135SnmpApi, null_ctx);
}

TEST_GROUP_RUNNER(Kdf135SnmpFail) {
    RUN_TEST_CASE(Kdf135SnmpFail, cryptoFail1);
    RUN_TEST_CASE(Kdf135SnmpFail, cryptoFail2);
    RUN_TEST_CASE(Kdf135SnmpFail, tcidFail);
    RUN_TEST_CASE(Kdf135SnmpFail, tcFail);
}

TEST_GROUP_RUNNER(Kdf135SnmpFunc) {
    RUN_TEST_CASE(Kdf135SnmpFunc, null_ctx);
}

TEST_GROUP_RUNNER(Kdf135SrtpFail) {
    RUN_TEST_CASE(Kdf135SrtpFail, cryptoFail1);
    RUN_TEST_CASE(Kdf135SrtpFail, cryptoFail2);
    RUN_TEST_CASE(Kdf135SrtpFail, tcidFail);
    RUN_TEST_CASE(Kdf135SrtpFail, tcFail);
}

TEST_GROUP_RUNNER(Kdf135SshApi) {
    RUN_TEST_CASE(Kdf135SshApi, null_ctx);
}

TEST_GROUP_RUNNER(Kdf135SshFail) {
    RUN_TEST_CASE(Kdf135SshFail, cryptoFail1);
    RUN_TEST_CASE(Kdf135SshFail, cryptoFail2);
    RUN_TEST_CASE(Kdf135SshFail, tcidFail);
    RUN_TEST_CASE(Kdf135SshFail, tcFail);
}

TEST_GROUP_RUNNER(Kdf135SshFunc) {
    RUN_TEST_CASE(Kdf135SshFunc, null_ctx);
}

TEST_GROUP_RUNNER(Kdf135ikeV1Fail) {
    RUN_TEST_CASE(Kdf135ikeV1Fail, cryptoFail1);
    RUN_TEST_CASE(Kdf135ikeV1Fail, cryptoFail2);
    RUN_TEST_CASE(Kdf135ikeV1Fail, tgFail);
    RUN_TEST_CASE(Kdf135ikeV1Fail, tcFail);
}

TEST_GROUP_RUNNER(Kdf135ikeV2Fail) {
    RUN_TEST_CASE(Kdf135ikeV2Fail, cryptoFail1);
    RUN_TEST_CASE(Kdf135ikeV2Fail, cryptoFail2);
    RUN_TEST_CASE(Kdf135ikeV2Fail, tgFail);
    RUN_TEST_CASE(Kdf135ikeV2Fail, tcFail);
}

TEST_GROUP_RUNNER(Kdf135x963Fail) {
    RUN_TEST_CASE(Kdf135x963Fail, cryptoFail1);
    RUN_TEST_CASE(Kdf135x963Fail, cryptoFail2);
    RUN_TEST_CASE(Kdf135x963Fail, tgFail);
    RUN_TEST_CASE(Kdf135x963Fail, tcFail);
}

TEST_GROUP_RUNNER(Kdf135x963Func) {
    RUN_TEST_CASE(Kdf135x963Func, null_ctx);
}

TEST_GROUP_RUNNER(Kdf135x963Func1) {
    RUN_TEST_CASE(Kdf135x963Func1, null_ctx);
}

TEST_GROUP_RUNNER(Kdf135x963Func10) {
    RUN_TEST_CASE(Kdf135x963Func10, missing);
}

TEST_GROUP_RUNNER(Kdf135x963Func11) {
    RUN_TEST_CASE(Kdf135x963Func11, missing);
    RUN_TEST_CASE(Kdf135x963Func11, missing_tgid);
}

TEST_GROUP_RUNNER(Kdf135x963Func2) {
    RUN_TEST_CASE(Kdf135x963Func2, null_obj);
}

TEST_GROUP_RUNNER(Kdf135x963Func3) {
    RUN_TEST_CASE(Kdf135x963Func3, properly);
}

TEST_GROUP_RUNNER(Kdf135x963Func4) {
    RUN_TEST_CASE(Kdf135x963Func4, missing);
}

TEST_GROUP_RUNNER(Kdf135x963Func5) {
    RUN_TEST_CASE(Kdf135x963Func5, missing);
}

TEST_GROUP_RUNNER(Kdf135x963Func6) {
    RUN_TEST_CASE(Kdf135x963Func6, missing);
}

TEST_GROUP_RUNNER(Kdf135x963Func7) {
    RUN_TEST_CASE(Kdf135x963Func7, invalid);
}

TEST_GROUP_RUNNER(Kdf135x963Func8) {
    RUN_TEST_CASE(Kdf135x963Func8, missing);
}

TEST_GROUP_RUNNER(Kdf135x963Func9) {
    RUN_TEST_CASE(Kdf135x963Func9, missing);
}

TEST_GROUP_RUNNER(KvList) {
    RUN_TEST_CASE(KvList, null_ctx);
}

TEST_GROUP_RUNNER(LocateCapEntry) {
    RUN_TEST_CASE(LocateCapEntry, null_ctx);
}

TEST_GROUP_RUNNER(LogMsg) {
    RUN_TEST_CASE(LogMsg, null_ctx);
}

TEST_GROUP_RUNNER(LookupCipherIndex) {
    RUN_TEST_CASE(LookupCipherIndex, null_param);
}

TEST_GROUP_RUNNER(LookupCipherRevision) {
    RUN_TEST_CASE(LookupCipherRevision, null_ctx);
}

TEST_GROUP_RUNNER(LookupErrorString) {
    RUN_TEST_CASE(LookupErrorString, null_ctx);
}

TEST_GROUP_RUNNER(LookupRSARandPQIndex) {
    RUN_TEST_CASE(LookupRSARandPQIndex, null_param);
}

TEST_GROUP_RUNNER(MODULE_NEW) {
    RUN_TEST_CASE(MODULE_NEW, module_new);
}

TEST_GROUP_RUNNER(MODULE_SET_TYPE_VERSION_DESC) {
    RUN_TEST_CASE(MODULE_SET_TYPE_VERSION_DESC, module_set_type_version_desc);
}

TEST_GROUP_RUNNER(OE_NEW) {
    RUN_TEST_CASE(OE_NEW, oe_new);
}

TEST_GROUP_RUNNER(OE_SET_DEPENDENCY) {
    RUN_TEST_CASE(OE_SET_DEPENDENCY, oe_set_dependency);
}

TEST_GROUP_RUNNER(PBKDF_API) {
    RUN_TEST_CASE(PBKDF_API, empty_ctx);
    RUN_TEST_CASE(PBKDF_API, null_ctx);
    RUN_TEST_CASE(PBKDF_API, null_json_obj);
}

TEST_GROUP_RUNNER(PBKDF_CAPABILITY) {
    RUN_TEST_CASE(PBKDF_CAPABILITY, good);
}

TEST_GROUP_RUNNER(PBKDF_HANDLER) {
    RUN_TEST_CASE(PBKDF_HANDLER, good);
    RUN_TEST_CASE(PBKDF_HANDLER, wrong_algorithm);
    RUN_TEST_CASE(PBKDF_HANDLER, no_algorithm);
    RUN_TEST_CASE(PBKDF_HANDLER, no_hmacalg);
    RUN_TEST_CASE(PBKDF_HANDLER, bad_hmacalg);
    RUN_TEST_CASE(PBKDF_HANDLER, bad_testtype);
    RUN_TEST_CASE(PBKDF_HANDLER, no_testtype);
    RUN_TEST_CASE(PBKDF_HANDLER, no_tcid);
    RUN_TEST_CASE(PBKDF_HANDLER, bad_keylen);
    RUN_TEST_CASE(PBKDF_HANDLER, no_keylen);
    RUN_TEST_CASE(PBKDF_HANDLER, bad_salt);
    RUN_TEST_CASE(PBKDF_HANDLER, no_salt);
    RUN_TEST_CASE(PBKDF_HANDLER, bad_password);
    RUN_TEST_CASE(PBKDF_HANDLER, bad_password_2);
    RUN_TEST_CASE(PBKDF_HANDLER, no_password);
    RUN_TEST_CASE(PBKDF_HANDLER, bad_iterationCount);
    RUN_TEST_CASE(PBKDF_HANDLER, bad_iterationCount_2);
    RUN_TEST_CASE(PBKDF_HANDLER, no_iterationCount);
    RUN_TEST_CASE(PBKDF_HANDLER, bad_salt_2);
}

TEST_GROUP_RUNNER(PROCESS_TESTS) {
    RUN_TEST_CASE(PROCESS_TESTS, good);
    RUN_TEST_CASE(PROCESS_TESTS, null_ctx);
    RUN_TEST_CASE(PROCESS_TESTS, no_vs_list);
    RUN_TEST_CASE(PROCESS_TESTS, run_vectors_from_file);
    RUN_TEST_CASE(PROCESS_TESTS, upload_vectors_from_file);
    RUN_TEST_CASE(PROCESS_TESTS, put_data_from_file);
    RUN_TEST_CASE(PROCESS_TESTS, mark_as_sample);
    RUN_TEST_CASE(PROCESS_TESTS, mark_as_post_only);
    RUN_TEST_CASE(PROCESS_TESTS, mark_as_request_only);
    RUN_TEST_CASE(PROCESS_TESTS, mark_as_get_only);
    RUN_TEST_CASE(PROCESS_TESTS, mark_as_delete_only);
    RUN_TEST_CASE(PROCESS_TESTS, get_vector_set_count);
    RUN_TEST_CASE(PROCESS_TESTS, mark_as_put_after_test);
    RUN_TEST_CASE(PROCESS_TESTS, acvp_get_results_from_server);
    RUN_TEST_CASE(PROCESS_TESTS, acvp_resume_test_session);
    RUN_TEST_CASE(PROCESS_TESTS, acvp_cancel_test_session);
    RUN_TEST_CASE(PROCESS_TESTS, acvp_get_expected_results);
}

TEST_GROUP_RUNNER(REFRESH) {
    RUN_TEST_CASE(REFRESH, good_without_totp);
    RUN_TEST_CASE(REFRESH, null_ctx);
    RUN_TEST_CASE(REFRESH, good_with_totp);
}

TEST_GROUP_RUNNER(RSA_DECPRIM_API) {
    RUN_TEST_CASE(RSA_DECPRIM_API, empty_ctx);
    // RUN_TEST_CASE(RSA_DECPRIM_API, pass);  // Disabled (in #if 0)
    RUN_TEST_CASE(RSA_DECPRIM_API, error_paths);
}

TEST_GROUP_RUNNER(RSA_KEYGEN_API) {
    RUN_TEST_CASE(RSA_KEYGEN_API, empty_ctx);
    RUN_TEST_CASE(RSA_KEYGEN_API, null_ctx);
    RUN_TEST_CASE(RSA_KEYGEN_API, null_json_obj);
}

TEST_GROUP_RUNNER(RSA_KEYGEN_CAPABILITY) {
    RUN_TEST_CASE(RSA_KEYGEN_CAPABILITY, good);
}

TEST_GROUP_RUNNER(RSA_KEYGEN_HANDLER) {
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, good);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, wrong_algorithm);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, missing_mode);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, wrong_mode);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, missing_infoGeneratedByServer);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, missing_pubExpMode);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, wrong_pubExpMode);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, missing_fixedPubExp);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, missing_keyFormat);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, wrong_keyFormat);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, missing_randPQ);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, wrong_randPQ);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, missing_primeTest);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, wrong_primeTest);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, missing_modulo);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, wrong_modulo);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, missing_hashAlg);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, wrong_hashAlg);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, missing_e);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, long_e);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, wrong_size_bitlens);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, missing_seed);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, long_seed);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, missing_tgid);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, cryptoFail1);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, cryptoFail2);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, tgFail1);
    RUN_TEST_CASE(RSA_KEYGEN_HANDLER, tcFail1);
}

TEST_GROUP_RUNNER(RSA_PRIM_CAPABILITY) {
    RUN_TEST_CASE(RSA_PRIM_CAPABILITY, good);
}

TEST_GROUP_RUNNER(RSA_SIGGEN_API) {
    RUN_TEST_CASE(RSA_SIGGEN_API, empty_ctx);
    RUN_TEST_CASE(RSA_SIGGEN_API, null_ctx);
    RUN_TEST_CASE(RSA_SIGGEN_API, null_json_obj);
}

TEST_GROUP_RUNNER(RSA_SIGGEN_CAPABILITY) {
    RUN_TEST_CASE(RSA_SIGGEN_CAPABILITY, good);
}

TEST_GROUP_RUNNER(RSA_SIGGEN_HANDLER) {
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, good);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, wrong_algorithm);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, missing_mode);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, wrong_mode);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, missing_sigType);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, missing_hashAlg);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, missing_mod);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, wrong_mod);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, missing_message);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, missing_tcId);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, message_too_long);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, cryptoFail1);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, cryptoFail2);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, tgFail1);
    RUN_TEST_CASE(RSA_SIGGEN_HANDLER, tcFail1);
}

TEST_GROUP_RUNNER(RSA_SIGPRIM_API) {
    RUN_TEST_CASE(RSA_SIGPRIM_API, empty_ctx);
    RUN_TEST_CASE(RSA_SIGPRIM_API, pass);
    RUN_TEST_CASE(RSA_SIGPRIM_API, error_paths);
}

TEST_GROUP_RUNNER(RSA_SIGVER_API) {
    RUN_TEST_CASE(RSA_SIGVER_API, empty_ctx);
    RUN_TEST_CASE(RSA_SIGVER_API, null_ctx);
    RUN_TEST_CASE(RSA_SIGVER_API, null_json_obj);
}

TEST_GROUP_RUNNER(RSA_SIGVER_CAPABILITY) {
    RUN_TEST_CASE(RSA_SIGVER_CAPABILITY, good);
}

TEST_GROUP_RUNNER(RSA_SIGVER_HANDLER) {
    RUN_TEST_CASE(RSA_SIGVER_HANDLER, good);
    RUN_TEST_CASE(RSA_SIGVER_HANDLER, missing_e);
    RUN_TEST_CASE(RSA_SIGVER_HANDLER, missing_n);
    RUN_TEST_CASE(RSA_SIGVER_HANDLER, missing_signature);
    RUN_TEST_CASE(RSA_SIGVER_HANDLER, invalid_signature_len);
    RUN_TEST_CASE(RSA_SIGVER_HANDLER, invalid_e_len);
    RUN_TEST_CASE(RSA_SIGVER_HANDLER, invalid_n_len);
    RUN_TEST_CASE(RSA_SIGVER_HANDLER, missing_tgid);
    RUN_TEST_CASE(RSA_SIGVER_HANDLER, cryptoFail1);
    RUN_TEST_CASE(RSA_SIGVER_HANDLER, cryptoFail2);
    RUN_TEST_CASE(RSA_SIGVER_HANDLER, tgFail1);
    RUN_TEST_CASE(RSA_SIGVER_HANDLER, tcFail1);
}

TEST_GROUP_RUNNER(RUN) {
    RUN_TEST_CASE(RUN, missing_path);
    RUN_TEST_CASE(RUN, marked_as_get);
    RUN_TEST_CASE(RUN, good);
    RUN_TEST_CASE(RUN, bad_totp_cb);
    RUN_TEST_CASE(RUN, good_without_totp);
    RUN_TEST_CASE(RUN, null_ctx);
}

TEST_GROUP_RUNNER(SAFE_PRIMES_API) {
    RUN_TEST_CASE(SAFE_PRIMES_API, empty_ctx);
    RUN_TEST_CASE(SAFE_PRIMES_API, null_ctx);
    RUN_TEST_CASE(SAFE_PRIMES_API, null_json_obj);
}

TEST_GROUP_RUNNER(SAFE_PRIMES_HANDLER) {
    RUN_TEST_CASE(SAFE_PRIMES_HANDLER, good);
    RUN_TEST_CASE(SAFE_PRIMES_HANDLER, missing_mode);
    RUN_TEST_CASE(SAFE_PRIMES_HANDLER, bad_mode);
    RUN_TEST_CASE(SAFE_PRIMES_HANDLER, missing_alg);
    RUN_TEST_CASE(SAFE_PRIMES_HANDLER, missing_tg);
    RUN_TEST_CASE(SAFE_PRIMES_HANDLER, missing_tc);
    RUN_TEST_CASE(SAFE_PRIMES_HANDLER, missing_dgm);
    RUN_TEST_CASE(SAFE_PRIMES_HANDLER, bad_dgm);
    RUN_TEST_CASE(SAFE_PRIMES_HANDLER, missing_y);
    RUN_TEST_CASE(SAFE_PRIMES_HANDLER, missing_x);
    RUN_TEST_CASE(SAFE_PRIMES_HANDLER, missing_testtype);
    RUN_TEST_CASE(SAFE_PRIMES_HANDLER, bad_testtype);
}

TEST_GROUP_RUNNER(SET_SESSION_PARAMS) {
    RUN_TEST_CASE(SET_SESSION_PARAMS, good_2fa);
    RUN_TEST_CASE(SET_SESSION_PARAMS, null_params_2fa);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_input_json_good);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_input_json_null_params);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_server_good);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_server_null_params);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_server_overflow);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_path_segment_good);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_path_segment_null_params);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_path_segment_overflow);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_cacerts_good);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_cacerts_null_params);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_cacerts_overflow);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_cert_key_good);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_cert_key_null_params);
    RUN_TEST_CASE(SET_SESSION_PARAMS, set_cert_key_overflow);
    RUN_TEST_CASE(SET_SESSION_PARAMS, mark_as_sample_good);
    RUN_TEST_CASE(SET_SESSION_PARAMS, mark_as_sample_null_ctx);
}

TEST_GROUP_RUNNER(SetupSessionParams) {
    RUN_TEST_CASE(SetupSessionParams, proper_ctx_params);
    RUN_TEST_CASE(SetupSessionParams, null_server_param);
    // RUN_TEST_CASE(SetupSessionParams, null_vendor_info_params);  // Disabled (in #if 0)
}

TEST_GROUP_RUNNER(SigGen_HANDLER) {
    RUN_TEST_CASE(SigGen_HANDLER, cryptoFail1);
    RUN_TEST_CASE(SigGen_HANDLER, cryptoFail2);
}

TEST_GROUP_RUNNER(StringFits) {
    RUN_TEST_CASE(StringFits, null_ctx);
}

TEST_GROUP_RUNNER(TRANSPORT_DELETE) {
    RUN_TEST_CASE(TRANSPORT_DELETE, good);
}

TEST_GROUP_RUNNER(TRANSPORT_FULL_INTERACTION) {
    // RUN_TEST_CASE(TRANSPORT_FULL_INTERACTION, good);  // Disabled (in #if 0)
}

TEST_GROUP_RUNNER(TRANSPORT_GET) {
    RUN_TEST_CASE(TRANSPORT_GET, good);
}

TEST_GROUP_RUNNER(TRANSPORT_POST) {
    RUN_TEST_CASE(TRANSPORT_POST, good);
}

TEST_GROUP_RUNNER(TRANSPORT_PUT) {
    RUN_TEST_CASE(TRANSPORT_PUT, good);
}

TEST_GROUP_RUNNER(TRANSPORT_PUT_VALIDATION) {
    RUN_TEST_CASE(TRANSPORT_PUT_VALIDATION, good);
}

TEST_GROUP_RUNNER(TRANSPORT_RETRIEVE_RESULT) {
    RUN_TEST_CASE(TRANSPORT_RETRIEVE_RESULT, incomplete_ctx);
    RUN_TEST_CASE(TRANSPORT_RETRIEVE_RESULT, missing_vsid_url);
    RUN_TEST_CASE(TRANSPORT_RETRIEVE_RESULT, missing_ctx);
    RUN_TEST_CASE(TRANSPORT_RETRIEVE_RESULT, good);
}

TEST_GROUP_RUNNER(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS) {
    RUN_TEST_CASE(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS, incomplete_ctx);
    RUN_TEST_CASE(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS, missing_vsid_url);
    RUN_TEST_CASE(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS, missing_ctx);
    RUN_TEST_CASE(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS, good);
}

TEST_GROUP_RUNNER(TRANSPORT_RETRIEVE_VECTOR_SET) {
    RUN_TEST_CASE(TRANSPORT_RETRIEVE_VECTOR_SET, incomplete_ctx);
    RUN_TEST_CASE(TRANSPORT_RETRIEVE_VECTOR_SET, missing_vsid_url);
    RUN_TEST_CASE(TRANSPORT_RETRIEVE_VECTOR_SET, missing_ctx);
    RUN_TEST_CASE(TRANSPORT_RETRIEVE_VECTOR_SET, good);
}

TEST_GROUP_RUNNER(TRANSPORT_SEND_DEP_REG) {
    // RUN_TEST_CASE(TRANSPORT_SEND_DEP_REG, missing_reg);  // Disabled (in #if 0)
    // RUN_TEST_CASE(TRANSPORT_SEND_DEP_REG, missing_ctx);  // Disabled (in #if 0)
    // RUN_TEST_CASE(TRANSPORT_SEND_DEP_REG, incomplete_ctx);  // Disabled (in #if 0)
    // RUN_TEST_CASE(TRANSPORT_SEND_DEP_REG, good);  // Disabled (in #if 0)
}

TEST_GROUP_RUNNER(TRANSPORT_SEND_LOGIN) {
    RUN_TEST_CASE(TRANSPORT_SEND_LOGIN, missing_reg);
    RUN_TEST_CASE(TRANSPORT_SEND_LOGIN, missing_ctx);
    RUN_TEST_CASE(TRANSPORT_SEND_LOGIN, incomplete_ctx);
    RUN_TEST_CASE(TRANSPORT_SEND_LOGIN, good);
}

TEST_GROUP_RUNNER(TRANSPORT_SEND_MODULE_REG) {
    // RUN_TEST_CASE(TRANSPORT_SEND_MODULE_REG, missing_reg);  // Disabled (in #if 0)
    // RUN_TEST_CASE(TRANSPORT_SEND_MODULE_REG, missing_ctx);  // Disabled (in #if 0)
    // RUN_TEST_CASE(TRANSPORT_SEND_MODULE_REG, incomplete_ctx);  // Disabled (in #if 0)
    // RUN_TEST_CASE(TRANSPORT_SEND_MODULE_REG, good);  // Disabled (in #if 0)
}

TEST_GROUP_RUNNER(TRANSPORT_SEND_OE_REG) {
    // RUN_TEST_CASE(TRANSPORT_SEND_OE_REG, missing_reg);  // Disabled (in #if 0)
    // RUN_TEST_CASE(TRANSPORT_SEND_OE_REG, missing_ctx);  // Disabled (in #if 0)
    // RUN_TEST_CASE(TRANSPORT_SEND_OE_REG, incomplete_ctx);  // Disabled (in #if 0)
    // RUN_TEST_CASE(TRANSPORT_SEND_OE_REG, good);  // Disabled (in #if 0)
}

TEST_GROUP_RUNNER(TRANSPORT_SEND_TEST_SESSION_REG) {
    RUN_TEST_CASE(TRANSPORT_SEND_TEST_SESSION_REG, missing_reg);
    RUN_TEST_CASE(TRANSPORT_SEND_TEST_SESSION_REG, missing_ctx);
    RUN_TEST_CASE(TRANSPORT_SEND_TEST_SESSION_REG, incomplete_ctx);
    RUN_TEST_CASE(TRANSPORT_SEND_TEST_SESSION_REG, good);
}

TEST_GROUP_RUNNER(TRANSPORT_SEND_VENDOR_REG) {
    // RUN_TEST_CASE(TRANSPORT_SEND_VENDOR_REG, missing_reg);  // Disabled (in #if 0)
    // RUN_TEST_CASE(TRANSPORT_SEND_VENDOR_REG, missing_ctx);  // Disabled (in #if 0)
    // RUN_TEST_CASE(TRANSPORT_SEND_VENDOR_REG, incomplete_ctx);  // Disabled (in #if 0)
    // RUN_TEST_CASE(TRANSPORT_SEND_VENDOR_REG, good);  // Disabled (in #if 0)
}

TEST_GROUP_RUNNER(TRANSPORT_SUBMIT_VECTOR_SET) {
    RUN_TEST_CASE(TRANSPORT_SUBMIT_VECTOR_SET, incomplete_ctx);
    RUN_TEST_CASE(TRANSPORT_SUBMIT_VECTOR_SET, missing_ctx);
    RUN_TEST_CASE(TRANSPORT_SUBMIT_VECTOR_SET, missing_vsid);
}

TEST_GROUP_RUNNER(VERIFY_FIPS_OPERATING_ENV) {
    RUN_TEST_CASE(VERIFY_FIPS_OPERATING_ENV, verify_fips_operating_env);
}

TEST_GROUP_RUNNER(ValidRsaMod) {
    RUN_TEST_CASE(ValidRsaMod, null_ctx);
}

// Main test runner function

// Function to run all library tests
void run_lib_tests(void) {
    RUN_TEST_GROUP(AES_API);
    RUN_TEST_GROUP(AES_CAPABILITY);
    RUN_TEST_GROUP(AES_HANDLER);
    RUN_TEST_GROUP(BUILD_DEPS);
    RUN_TEST_GROUP(BUILD_MODULES);
    RUN_TEST_GROUP(BUILD_OES);
    RUN_TEST_GROUP(BUILD_TEST_SESSION);
    RUN_TEST_GROUP(BUILD_VENDORS);
    RUN_TEST_GROUP(CHECK_RESULTS);
    RUN_TEST_GROUP(CMAC_AES_CAPABILITY);
    RUN_TEST_GROUP(CMAC_API);
    RUN_TEST_GROUP(CMAC_TDES_CAPABILITY);
    RUN_TEST_GROUP(CREATE_CTX);
    RUN_TEST_GROUP(Cleanup);
    RUN_TEST_GROUP(CreateSession);
    RUN_TEST_GROUP(DEPENDENCY_NEW);
    RUN_TEST_GROUP(DES_API);
    RUN_TEST_GROUP(DES_CAPABILITY);
    RUN_TEST_GROUP(DES_HANDLER);
    RUN_TEST_GROUP(DRBG_API);
    RUN_TEST_GROUP(DRBG_CAPABILITY);
    RUN_TEST_GROUP(DRBG_HANDDLER);
    RUN_TEST_GROUP(DRBG_HANDLER);
    RUN_TEST_GROUP(DsaKeyGenApi);
    RUN_TEST_GROUP(DsaKeyGenFunc);
    RUN_TEST_GROUP(DsaKeyGen_HANDLER);
    RUN_TEST_GROUP(DsaPqgGenApi);
    RUN_TEST_GROUP(DsaPqgGenFunc);
    RUN_TEST_GROUP(DsaPqgVerApi);
    RUN_TEST_GROUP(DsaPqgVerFunc);
    RUN_TEST_GROUP(DsaPqgVer_HANDLER);
    RUN_TEST_GROUP(DsaSigGenApi);
    RUN_TEST_GROUP(DsaSigGenFunc);
    RUN_TEST_GROUP(DsaSigVerApi);
    RUN_TEST_GROUP(DsaSigVerFunc);
    RUN_TEST_GROUP(ECDSA_API);
    RUN_TEST_GROUP(ECDSA_CAPABILITY);
    RUN_TEST_GROUP(ECDSA_HANDLER);
    RUN_TEST_GROUP(EnableCapAES);
    RUN_TEST_GROUP(EnableCapCMAC);
    RUN_TEST_GROUP(EnableCapDRBG);
    RUN_TEST_GROUP(EnableCapECDSA);
    RUN_TEST_GROUP(EnableCapHMAC);
    RUN_TEST_GROUP(EnableCapHash);
    RUN_TEST_GROUP(EnableCapKASECC);
    RUN_TEST_GROUP(EnableCapKASFFC);
    RUN_TEST_GROUP(EnableCapKASHKDF);
    RUN_TEST_GROUP(EnableCapKASKDFONESTEP);
    RUN_TEST_GROUP(EnableCapKDF108);
    RUN_TEST_GROUP(EnableCapKDF135IKEv1);
    RUN_TEST_GROUP(EnableCapKDF135IKEv2);
    RUN_TEST_GROUP(EnableCapKDFSNMP);
    RUN_TEST_GROUP(EnableCapKDFSRTP);
    RUN_TEST_GROUP(EnableCapKDFSSH);
    RUN_TEST_GROUP(EnableCapKDFTLS13);
    RUN_TEST_GROUP(EnableCapKDFx963);
    RUN_TEST_GROUP(EnableCapRSAkeyGen);
    RUN_TEST_GROUP(EnableCapTDES);
    RUN_TEST_GROUP(FIPS_VALIDATION_METADATA);
    RUN_TEST_GROUP(FREE_CTX);
    RUN_TEST_GROUP(FREE_OPERATING_ENV);
    RUN_TEST_GROUP(FREE_TEST_SESSION);
    RUN_TEST_GROUP(GET_LIBRARY_VERSION);
    RUN_TEST_GROUP(GET_PROTOCOL_VERSION);
    RUN_TEST_GROUP(GetObjFromRsp);
    RUN_TEST_GROUP(HASH_API);
    RUN_TEST_GROUP(HASH_CAPABILITY);
    RUN_TEST_GROUP(HASH_HANDLER);
    RUN_TEST_GROUP(HMAC_HANDLER);
    RUN_TEST_GROUP(HmacApi);
    RUN_TEST_GROUP(HmacFunc);
    RUN_TEST_GROUP(INGEST_METADATA);
    RUN_TEST_GROUP(JsonSerializeToFilePrettyA);
    RUN_TEST_GROUP(JsonSerializeToFilePrettyW);
    RUN_TEST_GROUP(KAS_ECC_API);
    RUN_TEST_GROUP(KAS_ECC_CAPABILITY);
    RUN_TEST_GROUP(KAS_ECC_CDH_API);
    RUN_TEST_GROUP(KAS_ECC_CDH_HANDLER);
    RUN_TEST_GROUP(KAS_ECC_COMP_API);
    RUN_TEST_GROUP(KAS_ECC_COMP_HANDLER);
    RUN_TEST_GROUP(KAS_ECC_SSC_HANDLER);
    RUN_TEST_GROUP(KAS_FFC_API);
    RUN_TEST_GROUP(KAS_FFC_CAPABILITY);
    RUN_TEST_GROUP(KAS_FFC_COMP_API);
    RUN_TEST_GROUP(KAS_FFC_COMP_HANDLER);
    RUN_TEST_GROUP(KAS_FFC_SP_HANDLER);
    RUN_TEST_GROUP(KAS_FFC_SSC_HANDLER);
    RUN_TEST_GROUP(KAS_IFC_API);
    RUN_TEST_GROUP(KAS_IFC_CAPABILITY);
    RUN_TEST_GROUP(KAS_IFC_SSC_API);
    RUN_TEST_GROUP(KAS_IFC_SSC_HANDLER);
    RUN_TEST_GROUP(KDA_API);
    RUN_TEST_GROUP(KDA_CAPABILITY);
    RUN_TEST_GROUP(KDA_HANDLER);
    RUN_TEST_GROUP(KDA_HKDF_HANDLER);
    RUN_TEST_GROUP(KDA_ONESTEP_HANDLER);
    RUN_TEST_GROUP(KDF108_API);
    RUN_TEST_GROUP(KDF108_CAPABILITY);
    RUN_TEST_GROUP(KDF108_HANDLER);
    RUN_TEST_GROUP(KDF135_IKEV1_API);
    RUN_TEST_GROUP(KDF135_IKEV1_CAPABILITY);
    RUN_TEST_GROUP(KDF135_IKEV1_HANDLER);
    RUN_TEST_GROUP(KDF135_IKEV2_API);
    RUN_TEST_GROUP(KDF135_IKEV2_CAPABILITY);
    RUN_TEST_GROUP(KDF135_IKEV2_HANDLER);
    RUN_TEST_GROUP(KDF135_SRTP_API);
    RUN_TEST_GROUP(KDF135_SRTP_CAPABILITY);
    RUN_TEST_GROUP(KDF135_SRTP_HANDLER);
    RUN_TEST_GROUP(KDF_TLS12_API);
    RUN_TEST_GROUP(KDF_TLS12_CAPABILITY);
    RUN_TEST_GROUP(KDF_TLS12_HANDLER);
    RUN_TEST_GROUP(KDF_TLS13_API);
    RUN_TEST_GROUP(KDF_TLS13_CAPABILITY);
    RUN_TEST_GROUP(KDF_TLS13_HANDLER);
    RUN_TEST_GROUP(KMAC_128_CAPABILITY);
    RUN_TEST_GROUP(KMAC_256_CAPABILITY);
    RUN_TEST_GROUP(KMAC_API);
    RUN_TEST_GROUP(KTS_IFC_API);
    RUN_TEST_GROUP(KTS_IFC_CAPABILITY);
    RUN_TEST_GROUP(KTS_IFC_HANDLER);
    RUN_TEST_GROUP(Kdf135SnmpApi);
    RUN_TEST_GROUP(Kdf135SnmpFail);
    RUN_TEST_GROUP(Kdf135SnmpFunc);
    RUN_TEST_GROUP(Kdf135SrtpFail);
    RUN_TEST_GROUP(Kdf135SshApi);
    RUN_TEST_GROUP(Kdf135SshFail);
    RUN_TEST_GROUP(Kdf135SshFunc);
    RUN_TEST_GROUP(Kdf135ikeV1Fail);
    RUN_TEST_GROUP(Kdf135ikeV2Fail);
    RUN_TEST_GROUP(Kdf135x963Fail);
    RUN_TEST_GROUP(Kdf135x963Func);
    RUN_TEST_GROUP(Kdf135x963Func1);
    RUN_TEST_GROUP(Kdf135x963Func10);
    RUN_TEST_GROUP(Kdf135x963Func11);
    RUN_TEST_GROUP(Kdf135x963Func2);
    RUN_TEST_GROUP(Kdf135x963Func3);
    RUN_TEST_GROUP(Kdf135x963Func4);
    RUN_TEST_GROUP(Kdf135x963Func5);
    RUN_TEST_GROUP(Kdf135x963Func6);
    RUN_TEST_GROUP(Kdf135x963Func7);
    RUN_TEST_GROUP(Kdf135x963Func8);
    RUN_TEST_GROUP(Kdf135x963Func9);
    RUN_TEST_GROUP(KvList);
    RUN_TEST_GROUP(LocateCapEntry);
    RUN_TEST_GROUP(LogMsg);
    RUN_TEST_GROUP(LookupCipherIndex);
    RUN_TEST_GROUP(LookupCipherRevision);
    RUN_TEST_GROUP(LookupErrorString);
    RUN_TEST_GROUP(LookupRSARandPQIndex);
    RUN_TEST_GROUP(MODULE_NEW);
    RUN_TEST_GROUP(MODULE_SET_TYPE_VERSION_DESC);
    RUN_TEST_GROUP(OE_NEW);
    RUN_TEST_GROUP(OE_SET_DEPENDENCY);
    RUN_TEST_GROUP(PBKDF_API);
    RUN_TEST_GROUP(PBKDF_CAPABILITY);
    RUN_TEST_GROUP(PBKDF_HANDLER);
    RUN_TEST_GROUP(PROCESS_TESTS);
    RUN_TEST_GROUP(REFRESH);
    RUN_TEST_GROUP(RSA_DECPRIM_API);
    RUN_TEST_GROUP(RSA_KEYGEN_API);
    RUN_TEST_GROUP(RSA_KEYGEN_CAPABILITY);
    RUN_TEST_GROUP(RSA_KEYGEN_HANDLER);
    RUN_TEST_GROUP(RSA_PRIM_CAPABILITY);
    RUN_TEST_GROUP(RSA_SIGGEN_API);
    RUN_TEST_GROUP(RSA_SIGGEN_CAPABILITY);
    RUN_TEST_GROUP(RSA_SIGGEN_HANDLER);
    RUN_TEST_GROUP(RSA_SIGPRIM_API);
    RUN_TEST_GROUP(RSA_SIGVER_API);
    RUN_TEST_GROUP(RSA_SIGVER_CAPABILITY);
    RUN_TEST_GROUP(RSA_SIGVER_HANDLER);
    RUN_TEST_GROUP(RUN);
    RUN_TEST_GROUP(SAFE_PRIMES_API);
    RUN_TEST_GROUP(SAFE_PRIMES_HANDLER);
    RUN_TEST_GROUP(SET_SESSION_PARAMS);
    RUN_TEST_GROUP(SetupSessionParams);
    RUN_TEST_GROUP(SigGen_HANDLER);
    RUN_TEST_GROUP(StringFits);
    RUN_TEST_GROUP(TRANSPORT_DELETE);
    RUN_TEST_GROUP(TRANSPORT_FULL_INTERACTION);
    RUN_TEST_GROUP(TRANSPORT_GET);
    RUN_TEST_GROUP(TRANSPORT_POST);
    RUN_TEST_GROUP(TRANSPORT_PUT);
    RUN_TEST_GROUP(TRANSPORT_PUT_VALIDATION);
    RUN_TEST_GROUP(TRANSPORT_RETRIEVE_RESULT);
    RUN_TEST_GROUP(TRANSPORT_RETRIEVE_SAMPLE_ANSWERS);
    RUN_TEST_GROUP(TRANSPORT_RETRIEVE_VECTOR_SET);
    RUN_TEST_GROUP(TRANSPORT_SEND_DEP_REG);
    RUN_TEST_GROUP(TRANSPORT_SEND_LOGIN);
    RUN_TEST_GROUP(TRANSPORT_SEND_MODULE_REG);
    RUN_TEST_GROUP(TRANSPORT_SEND_OE_REG);
    RUN_TEST_GROUP(TRANSPORT_SEND_TEST_SESSION_REG);
    RUN_TEST_GROUP(TRANSPORT_SEND_VENDOR_REG);
    RUN_TEST_GROUP(TRANSPORT_SUBMIT_VECTOR_SET);
    RUN_TEST_GROUP(VERIFY_FIPS_OPERATING_ENV);
    RUN_TEST_GROUP(ValidRsaMod);
}
