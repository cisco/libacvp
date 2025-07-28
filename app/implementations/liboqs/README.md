# liboqs ACVP Testing Harness

## Overview

This harness tests the ML-KEM and ML-DSA implementations provided by liboqs.
Other algorithms are not supported at this time; we will happily accept PRs adding other algorithms,
as long as they are thoroughly tested and cleanly written.


## Building

This harness is tested to build against `liboqs.a` and `liboqs.so`. To do so, provide `--with-liboqs-dir=<install dir>`
during `configure`. If liboqs is linked against OpenSSL, `--with-ssl-dir=<install dir>` can also be provided, and the
liboqs harness will still be built. 


## Supported Algorithms

#### Digital Signature
- ML-DSA mode: keyGen
- ML-DSA mode: sigGen
- ML-DSA mode: sigVer

#### Key Encapsulation
- ML-KEM mode: keyGen
- ML-KEM mode: encapDecap


## Disclaimer
The maintainers of this testing harness do not provide any guarantee of correctness or certification upon its use.
Support for any given implementation does not imply an endorsement of the implementation.
