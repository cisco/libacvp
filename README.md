        __       __  .______        ___       ______ ____    ____ .______
        |  |     |  | |   _  \      /   \     /      |\   \  /   / |   _  \
        |  |     |  | |  |_)  |    /  ^  \   |  ,----' \   \/   /  |  |_)  |
        |  |     |  | |   _  <    /  /_\  \  |  |       \      /   |   ___/
        |  `----.|  | |  |_)  |  /  _____  \ |  `----.   \    /    |  |
        |_______||__| |______/  /__/     \__\ \______|    \__/     | _|   

        A library that implements the client-side of the ACVP protocol.
        The ACVP specification is a work-in-progress and can be found at
        https://github.com/usnistgov/ACVP

### License
Libacvp is licensed under the Apache License 2.0, which means that
you are free to get and use it for commercial and non-commercial
purposes as long as you fulfill its conditions. See the LICENSE
file for details.

### Recent Changes!
The client library is compatible with the ACVP spec version 1.0, see https://github.com/usnistgov/ACVP however not all algorithms and options are supported. See the support list in the Supported Algorithms section below.

Metadata processing has been simplified and no longer requires id fields. Please review the new metadata directory sample json files to see the new format. Older formats should continue to work, but will have some unused keywords and fields.

To track any and all changes please review recent commits for more detail.

## Overview

Libacvp is a client-side ACVP library implementation, and also includes
an example application which utilizes the library. 

libacvp will login and then register with the ACVP server (advertising capabilities)
The server will respond with a list of vector set identifiers that need to be processed.
libacvp will download each vector set, process the vectors, and send the results back to the server.
This is performed in real-time by default. The user can also use "offline" mode for non-realtime
processing.

The `app/` directory contains a sample application which uses libacvp. This app
provides the glue between the crypto module DUT and the library itself.
Depending upon the DUT, the crypto backend API, and other factors, the user
may need to enhance the reference application, or create a new one from scratch.

The application within `app/` is only provided here for unit testing and demonstrating how to use libacvp. 
The application layer (app_main.c) is required to interface with the crypto module that will
be tested. In this example it uses OpenSSL, which introduces libcrypto.so as
the DUT.

The library also provides an example on how a standalone module could be
tested. In this case it uses the OpenSSL FOM canister. The FOM canister
has a few algorithms that can only be tested when not running in a final
product. These algorithms can be tested under this configuration.
The FOM build also requires the path to the canister header files and object which
is defined in the `./configure` CLI to enable non-runtime shown below which
automatically adds the compile time flag -DACVP_NO_RUNTIME.

The `certs/` directory contains the certificates used to establish a TLS
session with well-known ACVP servers. If the ACVP server uses a self-signed certificate,
then the proper CA file must be specified.
libacvp also requires a client certificate and key pair,
which the ACVP server uses to identify the client. You will need to
contact NIST to register your client certificate with their server.

The murl directory contains experimental code to replace the Curl
dependency. This may be useful for target platforms that don't support
Curl, such as Android or iOS. Murl is a "minimal" Curl implementation.
It implements a handful of the Curl API entry points used by libacvp.
The Murl code is currently in an experimental stage and is not supported
or maintained as part of libacvp and should not be used in any
production environment.


## Dependencies
* autotools
* gcc
* make
* curl (or substitution)
* openssl (or substitution)

Curl is used for sending REST calls to the ACVP server.

Openssl is used for TLS transport by libcurl.

Parson is used to parse and generate JSON data for the REST calls.
The parson code is included and compiled as part of libacvp.

libcurl, libssl and libcrypto are not included, and must
be installed separately on your build/target host,
including the header files.

###### Dealing with system-default dependencies
This codebase uses features in OpenSSL >= 1.0.2.
If the system-default install does not meet this requirement,
you will need to download, compile and install at least OpenSSL 1.0.2 on your system.
The new OpenSSL resources should typically be installed into /usr/local/ssl to avoid
overwriting the default OpenSSL that comes with your distro.

It is highly recommended to use versions of OpenSSL 1.1.1 or greater when possible, 
as all previous versions have reached end of life status. 

The next problem is the default libcurl on the Linux distro may be linked against
the previously mentioned default OpenSSL. This could result in linker failures when trying to use
the system default libcurl with the new OpenSSL install (due to missing symbols).
Therefore, you SHOULD download the Curl source, compile it against the "new" OpenSSL
header files, and link libcurl against the "new" OpenSSL. 
libacvp uses compile time macro logic to address differences in the APIs of different OpenSSL
versions.


## Building

`--prefix<path to install dir>` can be used with any configure options to specify where you would
like the library and application to install to. 

#### To build for runtime testing

```
./configure --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir>
make clean
make
make install
```

#### To build for non-runtime testing

```
./configure --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir> --with-fom_dir=<path to where FOM is installed>
make clean
make
make install
```

#### Cross Compiling
Requires options --build and --host.
Your `$PATH` must contain a path the gcc.

```
export CROSS_COMPILE=powerpc-buildroot-linux-uclibc
./configure --build=<local target prefix> --host=<gcc prefix of target host> --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir>
```

Example with build and host information:
```
./configure --build=localx86_64-unknown-linux-gnu --host=mips64-octeon-linux-gnu --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir>`
```
All dependent libraries must have been built with the same cross compile.

If using murl for cross compliles use the same CROSS_COMPILE and HOSTCC used with openssl, for example:

CROSS_COMPILE=arm-linux-gnueabihf-
HOSTCC=gcc

## Windows
1. Modify and run `scripts/gradle_env.bat`
2. Run `gradle build`
3. Modify and run `scripts/nist_setup.bat`

After successfully completing, the .dll and .lib library files are loacted in `build/libs/acvp`
and the example executable is located in `build/exe/`.
*Note:* Windows executables require that dependent libraries be in very specific locations
(or in the Windows path). One of these locations is the base directory of the executable.

## Running
1. `export LD_LIBRARY_PATH=<path to ssl lib>`
2. Modify and run `scripts/nist_setup.sh`
3. `./app/acvp_app --<options>`

Use `./app/acvp_app --help` for more information on available options.

#### How to test offline
1. Download vectors on network accessible device:
`./app/acvp_app --<algs of choice or all_algs> --vector_req <filename1>`
 - where <filename1> is the file you are saving the tests to.

2. Copy vectors and acvp_app to target:
`./app/acvp_app --all_algs --vector_req <filename1> --vector_rsp <filename2>`
 - where <filename1> is the file the tests are saved in, and <filename2> is the file
you want to save your results to.

3. Copy respones(filename2) to network accessible device:
`./app/acvp_app --all_algs --vector_upload <filename2>`
 - where <filename2> is the file containing the results of the tests.

*Note:* If the target in Step 2 does not have the standard libraries used by
libacvp you may configure and build a special app used only for Step 2. This
can be done by using --enable-offline and --enable-static when running 
./configure and do not use --with-libcurl-dir or --with-libmurl-dir which
will  minimize the library dependencies. Note that openssl with FOM must also
be built as static.

For example:
```
export FIPSLD_CC=gcc     (or whatever compiler is being used)
./configure --with-ssl-dir=<ciscossl install> --with-fom-dir=<fom install> --prefix=<libacvp install> --enable-static --enable-offline
```



## Testing
Move to the test/ directory and see the README.md there. The tests depend upon
a C test framework called Criterion, found here: https://github.com/Snaipe/Criterion


## Contributing
Before opening a pull request on libacvp, please ensure that all unit tests are
passing. Additionally, new tests should be added for new library features.

We also run the uncrustify tool as a linter to keep code-style consistent
throughout the library. That can be found in the `uncrustify/` directory.

## FAQ

`I get "unable to process test vectors" for certain algorithms when libacvp is built without a FOM. Why?`
Some algorithms need to have internal mechanisms tested that are not available in the
regular APIs for that algorithm. These cannot be tested at runtime and are only avaible to
be tested when linked to a FOM for non-runtime testing. --all_algs attempts to run these
algorithms as well, so for runtime testing without linking to a FOM, specify the algorithms
you wish to run individually.

`I get some sort of hard crash while processing vector sets - why?`
It is probable that libacvp is linking to a different version of a library than the one
it was configured and built with. libacvp/acvp_app depend on library versions in enabling 
or disabling certain features at build time, so please make sure libacvp and acvp_app are 
built and run with the same versions of each library.


## Credits
This package was initially written by John Foley of Cisco Systems.

## Supported Algorithms

|   Algorithm Type   |    Library Support    |   Client App Support    |
| :---------------:  | :-------------------: | :---------------------: |
| **Block Cipher Modes** |                       |                         |   
| **AES-CBC** |                      Y  |                      Y |
| **AES-CFB1** |  Y  |  Y  |
| **AES-CFB8** |  Y  |  Y  |
| **AES-CFB128** |  Y  |  Y  |
| **AES-CTR** |  Y  |  Y  |
| **AES-ECB** |  Y  |  Y  |
| **AES-GCM** |  Y  |  Y  |
| **AES-GCM-SIV** |  Y  |  Y  |
| **AES-KW** |  Y  |  Y  |
| **AES-KWP** |  Y  |  Y  |
| **AES-OFB** |  Y  |  Y  |
| **AES-XPN** |  Y  |  Y  |
| **AES-XTS** |  Y  |  Y  |
| **AES-FF1** |  Y  |  Y  |
| **AES-FF3-1** |  Y  |  Y  |
| **TDES-CBC** |  Y  |  Y  |
| **TDES-CBCI** |  Y  |  Y  |
| **TDES-CFBP1** |  Y  |  Y  |
| **TDES-CFBP8** |  Y  |  Y  |
| **TDES-CFBP64** |  Y  |  Y  |
| **TDES-CTR** |  Y  |  Y  |
| **TDES-ECB** |  Y  |  Y  |
| **TDES-KW** |  Y  |  Y  |
| **TDES-OFB** |  Y  |  Y  |
| **TDES-OFBI** |  Y  |  Y  |
| **Secure Hash** | |
| **SHA-1** |  Y  |  Y  |
| **SHA-224** |  Y  |  Y  |
| **SHA-256** |  Y  |  Y  |
| **SHA-384** |  Y  |  Y  |
| **SHA-512** |  Y  |  Y  |
| **SHA-512/224** |  Y  |  Y  |
| **SHA-512/256** |  Y  |  Y  |
| **SHA3-224** |  Y  |  Y  |
| **SHA3-256** |  Y  |  Y  |
| **SHA3-384** |  Y  |  Y  |
| **SHA3-512** |  Y  |  Y  |
| **SHAKE-128** |  Y  |  Y  |
| **SHAKE-256** |  Y  |  Y  |
| **XOFs** | | |
| **cSHAKE-128** |  Y  |  Y  |
| **cSHAKE-256** |  Y  |  Y  |
| **KMAC-128** |  Y  |  Y  |
| **KMAC-256** |  Y  |  Y  |
| **ParallelHash-128** |  Y  |  Y  |
| **ParallelHash-256** |  Y  |  Y  |
| **TupleHash-128** |  Y  |  Y  |
| **TupleHash-256** |  Y  |  Y  |
| **Message Authentication** | |
| **AES-GMAC** |  Y  |  Y  |
| **AES-CCM** |  Y  |  Y  |
| **CMAC-AES** |  Y  |  Y  |
| **CMAC-TDES** |  Y  |  Y  |
| **HMAC-SHA-1** |  Y  |  Y  |
| **HMAC-SHA2-224** |  Y  |  Y  |
| **HMAC-SHA2-256** |  Y  |  Y  |
| **HMAC-SHA2-384** |  Y  |  Y  |
| **HMAC-SHA2-512** |  Y  |  Y  |
| **HMAC-SHA2-512/224** |  Y  |  Y  |
| **HMAC-SHA2-512/256** |  Y  |  Y  |
| **HMAC-SHA3-224** |  Y  |  Y  |
| **HMAC-SHA3-256** |  Y  |  Y  |
| **HMAC-SHA3-384** |  Y  |  Y  |
| **HMAC-SHA3-512** |  Y  |  Y  |
| **DRBG** | |
| **ctrDRBG-AES-128** |  Y  |  Y  |
| **ctrDRBG-AES-192** |  Y  |  Y  |
| **ctrDRBG-AES-256** |  Y  |  Y  |
| **ctrDRBG-TDES** |  Y  |  Y  |
| **HASH DRBG** |  Y  |  Y  |
| **HMAC DRBG** |  Y  |  Y  |
| **Digital Signature** | |
| **RSA mode: keyGen** |  Y  |  Y  |
| **RSA mode: sigGen** |  Y  |  Y  |
| **RSA mode: sigVer** |  Y  |  Y  |
| **RSA mode: signatureComponent** |  Y  |  Y  |
| **RSA mode: decryptionComponent** |  Y  |  Y  |
| **RSA mode: legacySigVer** |  Y  |  Y  |
| **ECDSA mode: sigGenComponent** |  Y  |  Y  |
| **ECDSA mode: keyGen** |  Y  |  Y  |
| **ECDSA mode: keyVer** |  Y  |  Y  |
| **ECDSA mode: sigGen** |  Y  |  Y  |
| **ECDSA mode: sigVer** |  Y  |  Y  |
| **DSA mode: keyGen** |  Y  |  Y  |
| **DSA mode: sigVer** |  Y  |  Y  |
| **DSA mode: sigGen** |  Y  |  Y  |
| **DSA mode: pqgGen** |  Y  |  Y  |
| **DSA mode: pqgVer** |  Y  |  Y  |
| **EDDSA mode: keyGen** |  Y  |  Y  |
| **EDDSA mode: keyVer** |  Y  |  Y  |
| **EDDSA mode: sigGen** |  Y  |  Y  |
| **EDDSA mode: sigVer** |  Y  |  Y  |
| **Key Agreement** | |
| **KAS ECC ephemeralUnified** |  Y  |  Y  |
| **KAS ECC fullMqv** |  Y  |  Y  |
| **KAS ECC fullUnified** |  Y  |  Y  |
| **KAS ECC onePassDh** |  Y  |  Y  |
| **KAS ECC onePassMqv** |  Y  |  Y  |
| **KAS ECC OnePassUnified** |  Y  |  Y  |
| **KAS ECC staticUnified** |  Y  |  Y  |
| **KAS ECC CDH-Component** |  Y  |  Y  |
| **KAS FFC dhHybrid1** |  Y  |  Y  |
| **KAS FFC mqv2** |  Y  |  Y  |
| **KAS FFC dhEphem** |  Y  |  Y  |
| **KAS FFC dhHybridOneFlow** |  Y  |  Y  |
| **KAS FFC mqv1** |  Y  |  Y  |
| **KAS FFC dhOneFlow** |  Y  |  Y  |
| **KAS FFC dhStatic** |  Y  |  Y  |
| **KAS IFC KAS1-basic** |  Y  |  Y  |
| **KAS IFC KAS1-Party_V-confirmation** |  Y  |  Y  |
| **KAS IFC KAS2-basic** |  Y  |  Y  |
| **KAS IFC KAS2-bilateral-confirmation** |  Y  |  Y  |
| **KAS IFC KAS2-Party_U-confirmation** |  Y  |  Y  |
| **KAS IFC KAS2-Party_V-confirmation** |  Y  |  Y  |
| **KTS IFC KTS-OAEP-basic** |  Y  |  Y  |
| **KTS IFC KTS-OAEP-Party_V-confirmation** |  Y  |  Y  |
| **KDFs** | |
| **Counter KDF** |  Y  |  Y  |
| **Feedback KDF** |  Y  |  Y  |
| **Double Pipeline Iterator KDF** |  Y  |  Y  |
| **IKEv1** |  Y  |  Y  |
| **IKEv2** |  Y  |  Y  |
| **SNMP** |  Y  |  Y  |
| **SRTP** |  Y  |  Y  |
| **SSH** |  Y  |  Y  |
| **TLS** |  Y  |  Y  |
| **TPM** |  Y  |  Y  |
| **ANSX9.63** |  Y  |  Y  |
| **ANSX9.42** |  Y  |  Y  |
| **PBKDF** |  Y  |  Y  |
| **Safe Primes** | |
| **SafePrimes KeyGen** |  Y  |  Y  |
| **SafePrimes KeyVer** |  Y  |  Y  |
