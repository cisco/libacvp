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


## Disclaimer
The maintainers of this testing harness do not provide any guarantee of correctness or certification upon its use.
Support for any given implementation does not imply an endorsement of the implementation.
