# OpenSSL 3.x ACVP Testing Harness

## Overview

This harness tests various versions of OpenSSL 3. It should be capable of testing all releases, but the registration
is designed to handle specific versions of FIPS providers.


## Building

By default, this harness expects an OpenSSL build to be configured to load and activate a FIPS provider. This typically
entails using `enable-fips` in the OpenSSL configure command. Then, modifications must be made to `openssl.cnf` so that:

* The `fipsmodule.cnf` header is properly included
* the `fips_sect` is added
* the default provider is explicitly activated (Not needed for offline builds, but required for many online builds)


Alternatively, at runtime, `--disable_fips` can be provided, which will prevent the FIPS property from being requested
by default. This flag MUST NOT be used for any certification effort.

To build acvp_app with this harness, provide `--with-ssl-dir=<install dir>` during `configure`. For testing situations
that require moving builds or dependencies around, the following environment variables may assist with runtime loading
of the correct configuration files:
* `OPENSSL_CONF`
* `OPENSSL_CONF_INCLUDE`
* `OPENSSL_MODULES`


We cannot provide further assistance with configuring OpenSSL, as every use case may vary greatly. Please ensure that
any configurations for ACVP testing do not apply to production deployments of OpenSSL without ensuring they are
relevant there as well.


## Supported Algorithms

This OpenSSL 3.x implementation harness supports most possible algorithms depending on the version.
For details about specific parameters for a given algorithm, please see the relevant registration
file in a versions `registrations` folder. Notes:

- Different versions can have parameter changes on a given algorithm between versions, and those differences are not listed here
- The non-FIPS registration is not exhaustive and not intended to be frequently updated at this time

---
### All OpenSSL 3.x Versions (Common Support)

#### Symmetric Ciphers
- AES-CBC
- AES-CBC-CS1
- AES-CBC-CS2
- AES-CBC-CS3
- AES-CFB1
- AES-CFB8
- AES-CFB128
- AES-CTR
- AES-ECB
- AES-GCM
- AES-KW
- AES-KWP
- AES-OFB
- AES-XTS

#### Secure Hash
- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA-512/224
- SHA-512/256
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
- SHAKE-128
- SHAKE-256

#### Message Authentication
- AES-CCM
- AES-GMAC
- CMAC-AES
- HMAC-SHA-1
- HMAC-SHA2-224
- HMAC-SHA2-256
- HMAC-SHA2-384
- HMAC-SHA2-512
- HMAC-SHA2-512/224
- HMAC-SHA2-512/256
- HMAC-SHA3-224
- HMAC-SHA3-256
- HMAC-SHA3-384
- HMAC-SHA3-512

#### XOFs
- KMAC-128
- KMAC-256

#### DRBG
- ctrDRBG-AES-128
- ctrDRBG-AES-192
- ctrDRBG-AES-256
- HASH DRBG
- HMAC DRBG

#### Digital Signature
- RSA mode: keyGen
- RSA mode: sigGen
- RSA mode: sigVer
- RSA mode: signaturePrimitive
- ECDSA mode: keyGen
- ECDSA mode: keyVer
- ECDSA mode: sigGen
- ECDSA mode: sigVer
- DSA mode: sigVer
- DSA mode: pqgVer

#### Key Agreement
- KAS-ECC-SSC ephemeralUnified
- KAS-ECC CDH-component
- KAS-FFC-SSC dhEphem
- KAS-IFC-SSC
- KTS-IFC

#### Key Derivation
- KDA HKDF
- KDA onestep
- KDA twostep
- SP800-108 KDF
- SSH
- TLS 1.2
- TLS 1.3
- ANSX9.63
- ANSX9.42
- PBKDF

#### Safe Primes
- SafePrimes KeyGen
- SafePrimes KeyVer


---
#### FIPS Provider 3.0.X Only

- TDES-CBC
- TDES-ECB

---
#### FIPS Provider 3.0.X and 3.1.2 Only

- DSA mode: keyGen
- DSA mode: sigGen
- DSA mode: pqgGen

---
#### FIPS Provider 3.4.0+ Only

- EdDSA mode: keyGen
- EdDSA mode: keyVer
- EdDSA mode: sigGen
- EdDSA mode: sigVer
- RSA mode: decryptionPrimitive

---
#### FIPS Provider 3.5.0+ Only

- ML-KEM mode: keyGen
- ML-KEM mode: encapDecap
- ML-DSA mode: keyGen
- ML-DSA mode: sigGen
- ML-DSA mode: sigVer
- SLH-DSA mode: keyGen
- SLH-DSA mode: sigGen
- SLH-DSA mode: sigVer


## Disclaimer
The maintainers of this testing harness do not provide any guarantee of correctness or certification upon its use.
Support for any given implementation does not imply an endorsement of the implementation.
