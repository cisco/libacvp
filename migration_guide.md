# Libacvp 2.0 Migration Guide

## New in 2.3.2

### ACVP Testing Revision Updates

Libacvp now registers the current ACVP testing revisions for DRBG, LMS signatures, SHAKE,
ML-KEM encapsulation/decapsulation, ML-DSA signature generation, and HMAC. Existing applications
will typically continue to test the same capabilities without source changes. When a new revision
requires an explicit capability that was implicit in the previous revision, libacvp selects a
backwards-compatible default and logs a warning. Applications can use the APIs below to advertise
their capabilities explicitly and remove those warnings.

All lengths in these examples are in bits. Applications should adjust the example domains and
values to match the capabilities of their IUT.

#### DRBG SP800-90Ar1

ctrDRBG, hashDRBG, and hmacDRBG now register revision `SP800-90Ar1`. Existing
`ACVP_DRBG_RET_BITS_LEN` calls continue to register the same single supported length. The new
revision also permits a returned-bits domain through `acvp_cap_drbg_set_length()`.

ctrDRBG additionally requires `counterFieldLen`. If it is not set, libacvp preserves revision 1.0
behavior by using the full block length and logs a warning. Set it explicitly with:

```c
rv = acvp_cap_drbg_set_parm(ctx, ACVP_CTRDRBG, ACVP_DRBG_AES_128, 0,
                            ACVP_DRBG_COUNTER_FIELD_LEN, 128);
```

The selected value is provided to the crypto callback in
`ACVP_DRBG_TC.counter_field_len`.

#### LMS SP800-208

LMS sigGen and sigVer now register revision `SP800-208`; LMS keyGen remains revision `1.0`.
The new signature revision requires a supported message-length domain. If it is not set, libacvp
uses the byte-aligned range supported by the previous revision and logs a warning.

Set the domain explicitly for each enabled signature mode:

```c
rv = acvp_cap_lms_set_domain(ctx, ACVP_LMS_SIGGEN, ACVP_LMS_PARAM_MSG_LEN,
                             8, 65536, 8);
rv = acvp_cap_lms_set_domain(ctx, ACVP_LMS_SIGVER, ACVP_LMS_PARAM_MSG_LEN,
                             8, 65536, 8);
```

An increment of `1` may be used by implementations that support non-byte-aligned messages.
`ACVP_LMS_TC.msg_len` remains the message buffer length in bytes for backwards compatibility;
`ACVP_LMS_TC.msg_bit_len` contains the exact message length in bits.

The SP800-208 sigGen testing also checks that a one-time signature key is not reused.

#### SHAKE FIPS202

SHAKE-128 and SHAKE-256 now register revision `FIPS202`. The `inBit`, `inEmpty`, and `outBit`
registration properties are no longer used by this revision. SHAKE message lengths are
byte-aligned, and MCT testing is no longer performed.

Use `ACVP_HASH_MESSAGE_LEN` to replace the old input flags:

```c
/* Supports empty messages. */
rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHAKE_128,
                              ACVP_HASH_MESSAGE_LEN, 0, 65536, 8);

/* Does not support empty messages. */
rv = acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHAKE_256,
                              ACVP_HASH_MESSAGE_LEN, 8, 65536, 8);
```

If no message-length domain is set, libacvp uses a byte-aligned default and preserves the old
`ACVP_HASH_IN_EMPTY` setting. Remove obsolete `ACVP_HASH_IN_BIT`, `ACVP_HASH_IN_EMPTY`, and
`ACVP_HASH_OUT_BIT` calls after adding the explicit domain to eliminate their warnings.

#### ML-KEM FIPS203-tr1

ML-KEM encapDecap now registers revision `FIPS203-tr1`; ML-KEM keyGen remains revision
`FIPS203`. The new revision adds private-key format registration. If no format is set, libacvp
uses the expanded format from the previous revision and logs a warning.

Register the supported format explicitly with:

```c
rv = acvp_cap_ml_kem_set_parm(ctx, ACVP_ML_KEM_XCAP,
                              ACVP_ML_KEM_PARAM_KEY_FORMAT,
                              ACVP_ML_KEM_KEY_FORMAT_EXPANDED);
```

Call the API again with `ACVP_ML_KEM_KEY_FORMAT_SEED` if seed-format decapsulation is also
supported. Seed-format test cases provide `d` and `z` separately in `ACVP_ML_KEM_TC`.

#### ML-DSA FIPS204-tr1

ML-DSA sigGen now registers revision `FIPS204-tr1`; ML-DSA keyGen and sigVer remain revision
`FIPS204`. The new sigGen revision adds private-key format registration. If no format is set,
libacvp uses the expanded format from the previous revision and logs a warning.

Register the supported format explicitly with:

```c
rv = acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGGEN, 0,
                              ACVP_ML_DSA_PARAM_KEY_FORMAT,
                              ACVP_ML_DSA_KEY_FORMAT_EXPANDED);
```

Call the API again with `ACVP_ML_DSA_KEY_FORMAT_SEED` if seed-format signature generation is
also supported.

#### HMAC 2.0

HMAC registers revision `2.0`. Calls that request revision `1.0` are ignored with a warning so
existing applications continue using the supported revision. Remove the obsolete
`ACVP_HMAC_REVISION` call to eliminate that warning.

Revision 2.0 requires a message-length domain. If it is not set, libacvp uses the full
byte-aligned revision 2.0 range and logs a warning. Set it explicitly with:

```c
rv = acvp_cap_hmac_set_domain(ctx, ACVP_HMAC_SHA2_256, ACVP_HMAC_MSGLEN,
                              0, 4096, 8);
```

## New in 2.2.0

The included acvp_app application has had a restructure. For details on how to integrate a harness
into the new structure, view app/implementations/README.md.

## About
With the release of libacvp 2.0.0, various changes have been made that are not backwards-compatible
with software designed for previous versions of libacvp. This guide is meant to help users migrate
applications made for previous versions of libacvp migrate to libacvp 2.0.

We understand that any non-backwards-compatible change can be frustrating to accommodate; however,
many changes were required to add support for new functionality. In other cases, we felt these changes
introduced needed improvements to the library. As the number of crypto ciphers/algorithms continues
to grow, it is important that the existing codebase is as clean, adaptable, and maintainable as
possible.

This guide will attempt to cover all non-backwards compatible changes. We cannot advise on how
best to implement these changes into your application, as each IuT is unique and should be tested
in a way specific to that IuT.

This guide does not cover new APIs or features, just changed or removed ones. If you find this
guide does not cover every change that needs to be made, please open an issue/case with the libacvp
team.

---
# API Changes
This section will cover changes made to libacvp's public facing APIs between libacvp 1.X and
libacvp 2.0.0. Any calls to these APIs in your application must be updated to reflect the new
formats.

## Logging API
The callback function provided to the library as the application's logging function now needs to
include an extra parameter, ACVP_LOG_LVL. This allows the application to handle log messages of 
different levels differently.

Before:
```
ACVP_RESULT acvp_create_test_session(ACVP_CTX **ctx,
                                     ACVP_RESULT (*progress_cb)(char *msg),
                                     ACVP_LOG_LVL level);
```

Libacvp 2.0:
```
ACVP_RESULT acvp_create_test_session(ACVP_CTX **ctx,
                                     ACVP_RESULT (*progress_cb)(char *msg, ACVP_LOG_LVL level),
                                     ACVP_LOG_LVL level);
```

## DRBG Capability APIs
The capability registration function for DRBG needed the ability to specify different, unrelated
groups of capabilities. A new integer parameter has been added to allow specifying a group of
capabilities. If you do not need different groups (unchanged behavior from previous versions
of libacvp), you can simply add a "0" for this "group" parameter in every call.

Before:
```
ACVP_RESULT acvp_cap_drbg_set_parm(ACVP_CTX *ctx,
                                   ACVP_CIPHER cipher,
                                   ACVP_DRBG_MODE mode,
                                   ACVP_DRBG_PARM param,
                                   int value);
```

Libacvp 2.0:
```
ACVP_RESULT acvp_cap_drbg_set_parm(ACVP_CTX *ctx,
                                   ACVP_CIPHER cipher,
                                   ACVP_DRBG_MODE mode,
                                   int group,
                                   ACVP_DRBG_PARM param,
                                   int value);
```
This also applies to `acvp_cap_drbg_set_length()`.

## GET Request APIs

`acvp_set_get_save_file()` has been removed, and merged into `acvp_mark_as_get_only()`, which now
has an extra argument that has can be used to specify a file to save the GET response to.

Before:
```
ACVP_RESULT acvp_mark_as_get_only(ACVP_CTX *ctx, char *string);
```
Libacvp 2.0:
```
ACVP_RESULT acvp_mark_as_get_only(ACVP_CTX *ctx, char *string, const char *save_filename);
```

## Renamed

`acvp_set_json_filename()` has been renamed to `acvp_set_registration_file`. No other changes.

## Removed

`acvp_load_kat_filename()` has been removed; it had unclear and redundant functionality.

---
# Enumerator Changes

* The enumerator `ACVP_HMAC_ALG_VAL` has been removed. Any capability API calls that reference this
enumerator should reference `ACVP_HASH_ALG` values instead. This affects the `acvp_cap_pbkdf_*` 
APIs, the `acvp_cap_kdf_tls13_*` APIs, and the `acvp_cap_kda_*` APIs. In other words, all
references to:
```
ACVP_HMAC_ALG_MIN,
ACVP_HMAC_ALG_SHA1,
ACVP_HMAC_ALG_SHA224,
ACVP_HMAC_ALG_SHA256,
ACVP_HMAC_ALG_SHA384,
ACVP_HMAC_ALG_SHA512,
ACVP_HMAC_ALG_SHA512_224,
ACVP_HMAC_ALG_SHA512_256,
ACVP_HMAC_ALG_SHA3_224,
ACVP_HMAC_ALG_SHA3_256,
ACVP_HMAC_ALG_SHA3_384,
ACVP_HMAC_ALG_SHA3_512,
ACVP_HMAC_ALG_MAX
```
Should be replaced with, respectively:
```
ACVP_NO_SHA,
ACVP_SHA1,
ACVP_SHA224,
ACVP_SHA256,
ACVP_SHA384,
ACVP_SHA512,
ACVP_SHA512_224,
ACVP_SHA512_256,
ACVP_SHA3_224,
ACVP_SHA3_256,
ACVP_SHA3_384,
ACVP_SHA3_512,
ACVP_HASH_ALG_MAX
```

* References to `ACVP_KDA_HKDF_HMAC_ALG` for KDA algorithms need to be replaced with 
`ACVP_KDA_MAC_ALG`.

---
# Test Case Structure Changes

This section will cover changes made to test case structs between libacvp 1.X and 2.0.0. These
changes involve the inputs and outputs of tests; It is very important that you take care to
understand the inputs and outputs of each test while making these changes.

## KAS-IFC Structure Changes

Drastic changes to the KAS-IFC test case structure were required. For more details, please review
the new `ACVP_KAS_IFC_TC` in `acvp.h`, and the code and comments in `app_kas.c` in the included
acvp_app for reference. If you have further questions please feel free to reach out to the libacvp
team. This is the most complex change (by far) required to update to libacvp 2.0.

## KTS-IFC Structure Change

In previous versions of libacvp, for KTS-IFC tests, the plain-text derived key material was stored
in the `n` field; the user was expected to modify this test input field that originally contained
key info. In libacvp 2.0, plain-text DKM should be stored in the `pt` field.

## TLS 1.2 KDF Structure Change

Cleaned up some redundancy - 
`msecret1`, `msecret2`, `kblock1`, and `kblock2` values removed and replaced with just `msecret` 
and `kblock`.
Output was previously taken from `msecret1` and `kblock1`; now taken from `msecret` and `kblock`.

---
# Return Code Value Changes

The included acvp_app does not use many of the ACVP_RESULT values by default; if your client uses
them, you should adjust them:

* `ACVP_CRYPTO_TAG_FAIL` removed; Replace with `ACVP_CRYPTO_MODULE_FAIL`
* `ACVP_CRYPTO_WRAP_FAIL` removed; Replace with `ACVP_CRYPTO_MODULE_FAIL`
* `ACVP_NO_TOKEN` removed; Replace with `ACVP_JWT_MISSING`
* `ACVP_TOTP_DECODE_FAIL` removed; Replace with `ACVP_TOTP_FAIL`
* `ACVP_TOTP_MISSING_SEED` removed; replace with `ACVP_TOTP_FAIL`
* `ACVP_DUPLICATE_CTX` removed; Replace with `ACVP_CTX_NOT_EMPTY`

Other new return values have been added; for a complete list see `acvp.h`. Return values from
within the library have been adjusted in several places to be more relevant or descriptive. We
expect to continue to adjust return values in future releases; we may add new possible return
values but will not remove or change existing ones outside of major releases.

---
# Build/Run Process Changes

The process for building libacvp itself has not changed. On Windows platforms, some options
(deemed likely to be redundant or unused) have been removed. For users also intending to use the
included acvp_app, please view the README for more details about how building and testing with
OpenSSL 3.X has changed.


---
# Libacvp 2.1.0 Changes

Further changes were required in libacvp 2.1.0 that are not backwards compatible with the libacvp
2.0.0 API. those changes are described here.

## RSA Primitive APIs

We needed the ability to set parameters for both RSA decryption primitive AND signature primitive
using the appropriate APIs for their new revisions. The old API version assumed you were using
signature primitive.

Before:
```
ACVP_RESULT acvp_cap_rsa_prim_set_parm(ACVP_CTX *ctx,
                                       ACVP_RSA_PARM prim_type,
                                       int value);
```

Libacvp 2.1.0:
```
ACVP_RESULT acvp_cap_rsa_prim_set_parm(ACVP_CTX *ctx,
                                       ACVP_CIPHER cipher,
                                       ACVP_RSA_PARM param,
                                       int value);
```

Simply adding `ACVP_RSA_SIGPRIM` for cipher should make existing calls behave.

## RSA Registration Logic Change

For RSA registrations, the value `ACVP_RSA_PARM_KEY_FORMAT_CRT` has been replaced with
`ACVP_RSA_PARM_KEY_FORMAT`. The expected value is no longer a 1 or a 0, but an enum from
`ACVP_RSA_KEY_FORMAT`.


## Test Case Structure Changes

Several test cases have new fields which should not affect existing testing. For RSA primitive
testing, an `int` field for `key_format` was replaced with an appropriate enum,
`ACVP_RSA_KEY_FORMAT`.
