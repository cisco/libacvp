/*
 * Copyright (c) 2024, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/safestack.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include "app_lcl.h"
#include "safe_lib.h"

int get_nid_for_curve(ACVP_EC_CURVE curve) {
    switch (curve) {
    case ACVP_EC_CURVE_B233:
        return NID_sect233r1;
    case ACVP_EC_CURVE_B283:
        return NID_sect283r1;
    case ACVP_EC_CURVE_B409:
        return NID_sect409r1;
    case ACVP_EC_CURVE_B571:
        return NID_sect571r1;
    case ACVP_EC_CURVE_K233:
        return NID_sect233k1;
    case ACVP_EC_CURVE_K283:
        return NID_sect283k1;
    case ACVP_EC_CURVE_K409:
        return NID_sect409k1;
    case ACVP_EC_CURVE_K571:
        return NID_sect571k1;
    case ACVP_EC_CURVE_P224:
        return NID_secp224r1;
    case ACVP_EC_CURVE_P256:
        return NID_X9_62_prime256v1; /* OpenSSL omits the secp names since these are the same thing */
    case ACVP_EC_CURVE_P384:
        return NID_secp384r1;
    case ACVP_EC_CURVE_P521:
        return NID_secp521r1;
    case ACVP_EC_CURVE_B163:
        return NID_sect163r2;
    case ACVP_EC_CURVE_K163:
        return NID_sect163k1;
    case ACVP_EC_CURVE_P192:
        return NID_X9_62_prime192v1;
    case ACVP_EC_CURVE_START:
    case ACVP_EC_CURVE_END:
    default:
        return NID_undef;
    }
}

const EVP_MD *get_md_for_hash_alg(ACVP_HASH_ALG alg) {
    switch (alg) {
    case ACVP_SHA1:
        return EVP_sha1();
    case ACVP_SHA224:
        return EVP_sha224();
    case ACVP_SHA256:
        return EVP_sha256();
    case ACVP_SHA384:
        return EVP_sha384();
    case ACVP_SHA512:
        return EVP_sha512();
    case ACVP_SHA512_224:
        return EVP_sha512_224();
    case ACVP_SHA512_256:
        return EVP_sha512_256();
    case ACVP_SHA3_224:
        return EVP_sha3_224();
    case ACVP_SHA3_256:
        return EVP_sha3_256();
    case ACVP_SHA3_384:
        return EVP_sha3_384();
    case ACVP_SHA3_512:
        return EVP_sha3_512();
    case ACVP_SHAKE_128:
        return EVP_shake128();
    case ACVP_SHAKE_256:
        return EVP_shake256();
    case ACVP_NO_SHA:
    case ACVP_HASH_ALG_MAX:
    default:
       return NULL;
    }
}

const char *get_md_string_for_hash_alg(ACVP_HASH_ALG alg, int *md_size) {
    const char *str = NULL;
    int size = 0;

    switch (alg) {
    case ACVP_SHA1:
        size = 160;
        str = "SHA-1";
        break;
    case ACVP_SHA224:
        size = 224;
        str = "SHA2-224";
        break;
    case ACVP_SHA256:
        size = 256;
        str = "SHA2-256";
        break;
    case ACVP_SHA384:
        size = 384;
        str = "SHA2-384";
        break;
    case ACVP_SHA512:
        size = 512;
        str = "SHA2-512";
        break;
    case ACVP_SHA512_224:
        size = 224;
        str = "SHA2-512/224";
        break;
    case ACVP_SHA512_256:
        size = 256;
        str = "SHA2-512/256";
        break;
    case ACVP_SHA3_224:
        size = 224;
        str = "SHA3-224";
        break;
    case ACVP_SHA3_256:
        size = 256;
        str = "SHA3-256";
        break;
    case ACVP_SHA3_384:
        size = 384;
        str = "SHA3-384";
        break;
    case ACVP_SHA3_512:
        size = 512;
        str = "SHA3-512";
        break;
    case ACVP_SHAKE_128:
        str = "SHAKE-128";
        break;
    case ACVP_SHAKE_256:
        str = "SHAKE-256";
        break;
    case ACVP_NO_SHA:
    case ACVP_HASH_ALG_MAX:
    default:
        return NULL;
    }

    if (md_size) {
        *md_size = size / 8;
    }
    return str;
}

/** Convert the X and Y coordinates into the expected key format, since OpenSSL does not
 * allow setting X and Y directly */
char *ec_point_to_pub_key(unsigned char *x, int x_len, unsigned char *y, int y_len, int *key_len) {
    int key_size = 0;
    char *key = NULL;

    key_size = x_len + y_len + 1;
    key = calloc(key_size, sizeof(char));
    if (!key) {
        printf("Error allocating memory while creating EC public key\n");
        return NULL;
    }
    key[0] = 0x04;
    memcpy_s(&key[1], key_size - 1, x, x_len);
    memcpy_s(&key[x_len + 1], key_size - x_len - 1, y, y_len);

    *key_len = key_size;
    return key;
}

static const unsigned char sanity_msg[] = { 0xA5, 0x30, 0xD4, 0x60, 0x93, 0xA3, 0x5E, 0x50, 0x2C, 0xA1, 0x64, 0xB7,
                                            0x50, 0x24, 0xE4 };

static const unsigned char sanity_hash[] = { 0x13, 0x80, 0x22, 0xF7, 0xF3, 0xC6, 0xB9, 0x59, 0x36, 0x2D, 0xFE, 0xAE,
                                             0x59, 0xE9, 0xA3, 0x72, 0x24, 0x04, 0x3C, 0x61, 0x1E, 0xE4, 0xAA, 0x01,
                                             0xF0, 0xAA, 0x04, 0x2A };

/*
 * This performs a quick digest to make sure the FIPS provider is running properly. Othewise, we
 * will get a vague error trying to perform some unrelated operation later on. The return code is
 *  the biggest indicator, but we might as well check for correctness too.
 */
ACVP_RESULT fips_sanity_check(void) {
    ACVP_RESULT rv = ACVP_CRYPTO_MODULE_FAIL;
    size_t md_len;
    int diff;

    unsigned char *md = calloc(28, sizeof(unsigned char));
    if (!md) {
        printf("Failed to allocate memory for FIPS test.\n");
        return ACVP_MALLOC_FAIL;
    }
    if (EVP_Q_digest(NULL, "SHA2-224", "fips=yes", &sanity_msg, 15, md, &md_len) != 1) {
        printf("Crypto module returned failure code when running quick digest.\n");
        goto end;
    }
    memcmp_s(sanity_hash, 28, md, md_len, &diff);
    if (!diff) {
        rv = ACVP_SUCCESS;
    } else {
        printf("Crypto module failed correctness check on quick digest.\n");
    }
end:
    if (md) free(md);
    return rv;
}

static const unsigned char tdes_oid[] = { 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x06 };
static const unsigned char aes128_oid[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05 };
static const unsigned char aes192_oid[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x19 };
static const unsigned char aes256_oid[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D };

const char *get_string_from_oid(unsigned char *oid, int oid_len) {
    int diff = 0;

    memcmp_s(tdes_oid, sizeof(tdes_oid), oid, oid_len, &diff);
    if (!diff) return "DES3-WRAP";
    memcmp_s(aes128_oid, sizeof(aes128_oid), oid, oid_len, &diff);
    if (!diff) return "AES-128-WRAP";
    memcmp_s(aes192_oid, sizeof(aes192_oid), oid, oid_len, &diff);
    if (!diff) return "AES-192-WRAP";
    memcmp_s(aes256_oid, sizeof(aes256_oid), oid, oid_len, &diff);
    if (!diff) return "AES-256-WRAP";

    return NULL;
}

const char *get_ed_instance_param(ACVP_ED_CURVE curve, int is_prehash, int has_context) {
    switch (curve) {
    case ACVP_ED_CURVE_25519:
        return is_prehash ? "Ed25519ph" : (has_context ? "Ed25519ctx" : "Ed25519");
    case ACVP_ED_CURVE_448:
        return is_prehash ? "Ed448ph" : "Ed448";
    case ACVP_ED_CURVE_START:
    case ACVP_ED_CURVE_END:
    default:
        return NULL;
    }
}

const char *get_ed_curve_string(ACVP_ED_CURVE curve) {
    switch (curve) {
    case ACVP_ED_CURVE_25519:
        return "ED25519";
    case ACVP_ED_CURVE_448:
        return "ED448";
    case ACVP_ED_CURVE_START:
    case ACVP_ED_CURVE_END:
    default:
        return NULL;
    }
}

/*
 * The following code was taken from OpenSSL and modified to meet libacvp's use case. The Apache
 * License V2 can be found in the root of this project.
 */
DEFINE_STACK_OF(OSSL_PROVIDER)

static int collect_providers(OSSL_PROVIDER *provider, void *stack) {
    STACK_OF(OSSL_PROVIDER) *provider_stack = stack;
    return sk_OSSL_PROVIDER_push(provider_stack, provider) > 0 ? 1 : 0;
}

const char *get_provider_version(const char *provider_name) {
    STACK_OF(OSSL_PROVIDER) *providers = sk_OSSL_PROVIDER_new_null();
    OSSL_PROVIDER *prov = NULL;
    OSSL_PARAM params[3];
    char *name = NULL, *version = NULL, *ret = NULL;
    int i = 0, diff = 0;

    if (providers == NULL) {
        printf( "Error allocating space for list of active providers\n");
        goto end;
    }

    if (OSSL_PROVIDER_do_all(NULL, &collect_providers, providers) != 1) {
        printf( "Error collecting list of current active providers\n");
        goto end;
    }

    for (i = 0; i < sk_OSSL_PROVIDER_num(providers); i++) {
        prov = sk_OSSL_PROVIDER_value(providers, i);

        /* Get names and versions for each provider, compare name against what we are looking for */
        params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, &name, 0);
        params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, &version, 0);
        params[2] = OSSL_PARAM_construct_end();
        if (!OSSL_PROVIDER_get_params(prov, params)) {
            printf("Error getting list of params for an active provider\n");
            goto end;
        } else {
            strcmp_s(provider_name, strnlen_s(provider_name, PROVIDER_NAME_MAX_LEN), name, &diff);
            if (!diff) {
                ret = version;
                break;
            }
        }
    }
end:
    if (providers) sk_OSSL_PROVIDER_free(providers);
    return ret;
}
/* End OpenSSL code */

/* Converts a provider version string in the format MAJOR.MINOR.PATCH to an integer in the format (major * 1000000) + (minor * 10000) + patch */
int provider_ver_str_to_int(const char *str) {
    int major = 0, minor = 0, patch = 0, result = 0;

    if (!str) {
        return -1;
    }

    result = sscanf(str, "%d.%d.%d", &major, &minor, &patch);

    if (result != 3) { /* Check if the parsing was successful */
        return -1;
    }

    /* Ensure that the version components are within a valid range */
    if (major < 0 || major > 99) {
        return -1;
    }
    if (minor < 0 || minor > 99) {
        return -1;
    }
    if (patch < 0 || patch > 9999) {
        return -1;
    }

    return (major * 1000000) + (minor * 10000) + patch;

}

