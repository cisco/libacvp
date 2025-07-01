# JitterEntropy ACVP Testing Harness

## Overview

This harness tests the SHA3 implementation in the JitterEntropy library created by Stephan Mueller (smueller@chronox.de)
https://github.com/smuellerDD/jitterentropy-library/

It is designed for versions 3.4.1 and lower. The code can be adjusted for newer versions by altering the function
calls both in `iut.c` and in the changes below (`jent_` was prefixed in newer versions, among other changes).


## Building

Changes are required to the build of jitterentropy-library in order to run this ACVP testing. These changes expose the
internal SHA3 APIs, and install the header needed to reference them.  **This build then MUST NOT be used for any other
purpose except ACVP testing.**

1. Modify `src/jitterentropy-sha3.c` to add the prefix `JENT_PRIVATE_STATIC` to these functions:
    * `sha3_alloc`
    * `sha3_dealloc`
    * `sha3_256_init`
    * `sha3_update`
    * `sha3_final`

2. Modify `Makefile` to ensure the install process copies the needed `jitterentropy-sha3.h` header
    * Locate the `install-includes` section
    * add `install -m 0644 src/jitterentropy-sha3.h $(DESTDIR)$(PREFIX)/$(INCDIR)/` to the bottom


Any of these steps can change depending on the version. These are known to work with 3.4.1.

To build acvp_app against this version of jent, just provide `--with-jent-dir=<install dir>` during `configure`.


## Supported Algorithms

### Secure Hash
- SHA3-256


## Disclaimer
The maintainers of this testing harness do not provide any guarantee of correctness or certification upon its use.
Support for any given implementation does not imply an endorsement of the implementation.
