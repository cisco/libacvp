```
         __       __   ______        ___       ______ ____    ____  ______
        |  |     |  | |   _  \      /   \     /      |\   \  /   / |   _  \
        |  |     |  | |  |_)  |    /  ^  \   |  ,----' \   \/   /  |  |_)  |
        |  |     |  | |   _  <    /  /_\  \  |  |       \      /   |   ___/
        |  `----.|  | |  |_)  |  /  _____  \ |  `----.   \    /    |  |
        |_______||__| |______/  /__/     \__\ \______|    \__/     | _|   

           A library that implements the client-side of the ACVP protocol.
      The ACVP specification can be found at https://github.com/usnistgov/ACVP
```

## License
Libacvp is licensed under the Apache License 2.0, which means that
you are free to get and use it for commercial and non-commercial
purposes as long as you fulfill its conditions. See the LICENSE
file for details.


## Recent Changes

Libacvp has been updated to 2.0.0! The included acvp_app now supports OpenSSL 3.0. Various new
algorithms are supported and tested on top of multiple other new features and improvements. Please
see the release notes for more details.
Support for OpenSSL 1.0.2 has been removed.


# Overview

Libacvp is a client-side ACVP library implementation, and also includes
an example application (acvp_app) which utilizes the library.

libacvp will login and then register with the ACVP server (advertising capabilities).
The server will respond with a list of vector set identifiers that need to be processed.
libacvp will download each vector set, process the vectors, and send the results back to the server.
This is performed in real-time by default. The user can also use "offline" mode for non-realtime
processing.

The `app/` directory contains a sample application which uses libacvp. This app
provides the glue between the crypto module DUT and the library itself.
Depending upon the DUT, the crypto backend API, and other factors, the user
may need to enhance the reference application, or create a new one from scratch.

The application within `app/` demonstrates how to use libacvp to interface with a crypto module on
top of providing a broad testing harness for OpenSSL.

This application includes support for FIPS testing OpenSSL 3.X. Historically, support was included
for FIPS testing OpenSSL's FIPS module for 1.0.2; this is end of life and support has been removed. Some
artifacts have been left behind in case users have need to test a similar FOM structure for OpenSSL
1.1.1 (OpenSSL does not support this themselves). For OpenSSL 3.X, testing the FIPS provider
or the default provider is managed at runtime. If you are testing a different provider, you will need
to modify the application code to fetch those algorithms accordingly. For previous versions, a build
time argument providing a path to the FIPS module being tested was required.

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
* libcriterion (for unit tests only)
* doxygen (for building documentation only)

Curl is used for sending REST calls to the ACVP server.

Openssl is used for TLS transport by libcurl.

Parson is used to parse and generate JSON data for the REST calls.
The parson code is included and compiled as part of libacvp.

libcurl, libssl and libcrypto are not included, and must
be installed separately on your build/target host,
including the header files.

##### Dealing with system-default dependencies
This codebase uses features in OpenSSL >= 1.1.1.
If the system-default install does not meet this requirement,
you will need to download, compile and install at least OpenSSL 1.1.1 on your system.
The new OpenSSL resources should typically be installed into /usr/local/ssl to avoid
overwriting the default OpenSSL that comes with your distro.

Version 1.1.1 of OpenSSL reaches end of life officially on September 11, 2023. Updating to OpenSSL
3.X is highly recommended when possible. All previous versions have reached end of life status.

A potential source of issues is the default libcurl on the Linux distro, which may be linked against
the previously mentioned default OpenSSL. This could result in linker failures when trying to use
the system default libcurl with the new OpenSSL install (due to missing symbols).
Therefore, you SHOULD download the Curl source, compile it against the "new" OpenSSL
header files, and link libcurl against the "new" OpenSSL. 
libacvp uses compile time macro logic to address differences in the APIs of different OpenSSL
versions; therefore, it is important that you ensure libacvp is linking to the correct openSSL versions
at run time as well.

Libacvp is designed to work with curl version 7.80.0 or newer. Some operating systems may ship with
older versions of Curl which are missing certain features that libacvp depends on. In this case you
should either acquire a newer version through your OS package manager if possible or build a newer
version from source. While it is possible some older versions may work, they are not tested or
supported.

## Building

The instructions below indicate how to build libacvp for OpenSSL 3.X testing. The process is the same
for building 1.1.1 without FIPS. If you have a FIPS module for 1.1.1, we are unable to officially
support it as OpenSSL does not have a FIPS for 1.1.1 and there is no standard format to follow.
However, some support for building with a FOM (such as that included with 1.0.2) remains; for more
details, see the README included with versions prior to 2.0. It will be up to the user to maintain an
application capable of testing your implementation.

`--prefix<path to install dir>` can be used with any configure options to specify where you would
like the library and application to install to. 

#### To build app and library for supported algorithm testing

```
./configure --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir>
make clean
make
make install
```

#### Building libacvp without the application code.
Use the following ./configure command line option and only the library will be built and installed.

--disable-app

Note that this option is not useful when building for offline testing since the application is needed.
Using this option, only a libcurl installation dir needs to be provided.
 
#### Building acvp_app only without the library code
Use the following ./configure command line option and only the app will be built. Note that it depends
on libacvp having already been built. The libacvp directory can be provided using --with-libacvp-dir=
Otherwise, it will look in the default build directory in the root folder for libacvp.

--disable-lib

#### Other build options
More info about all available configure options can be found by using ./configure --help. Some important
ones include:
--enable-offline : Removes the Curl dependency and builds a version of libacvp that can only work
 offline. In current versions of libacvp, this does not affect if libraries are linked statically
 or dynamically.
--disable-kdf : Will disable kdf registration and processing in the application, in cases where the given
 crypto implementation does not support it (E.g. all OpenSSL prior to 3.0)
--disable-lib-check : This will disable autoconf's attempts to automatically detect prerequisite libraries
 before building libacvp. This may be useful in some edge cases where the libraries exist but autoconf
 cannot detect them; however, it will give more cryptic error messages in the make stage if there are issues
--enable-force-static-linking : This will force a build of acvp_app to attempt to link to every
dependency library, including libc, statically.

Libacvp will attempt to link a shared library for a given dependency if it exists, and will use a static library
if a shared one is not found. Statically linking the OpenSSL FIPS provider is not supported at this time as OpenSSL
does not support static building of the FIPS provider.

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

If using murl for cross compiles use the same CROSS_COMPILE and HOSTCC used with openssl, for example:

CROSS_COMPILE=arm-linux-gnueabihf-
HOSTCC=gcc

## Windows
The Visual Studio projects for acvp_app and libacvp are set to use 2017 tools and are designed to
be easily updated to use the latest versions of Microsoft build tools while being backwards
compatible with Visual Studio 2017 and some older Windows 10 SDK versions.

Prerequisites:
This system assumes all dependency library paths have /include folders containing all the headers
needed to properly link. This can be altered in the scripts if needed.

For these steps, use the Visual Studio Command Prompt for your platform (x64, x86, x86_64, or 
x64_86)

Steps:
1.) Edit and run ms\config_windows.bat
    -Add all of the directories for your dependencies
	-Change any needed settings
2.) Open libacvp.sln and acvp_app.sln in Visual Studio and allow the dialog to update the projects'
    versions of MSVC and windows SDK to the latest installed (May be unnecessary if versions match)
3.) run ms/make_lib.bat
4.) run ms/make_app.bat

The library files and app files will be placed in the ms/build/ directory.

Notes:
Windows will only search specific paths for shared libraries, and will not check the
locations you specify in config_windows.bat by default unless they are in your path. This results
in acvp_app not being able to run. An alternative to altering your path or moving libraries to
system folders is moving/copying any needed .dll files to the same directory as acvp_app.

If you are building statically, it is assumed for acvp_app that you have built Curl with OpenSSL, 
and that you are linking acvp_app to the exact same version of OpenSSL that Curl is linked to. Other
configurations are not supported, untested, and may not work. Libacvp itself is indifferent
to which crypto and SSL libraries Curl uses, but any applications using libacvp statically
need to link to those libraries.

Murl is not supported in windows at this time.

## Running
1. `export LD_LIBRARY_PATH="<path to ssl lib;path to curl lib>"`
2. Modify scripts/nist_setup.sh and run `source scripts/nist_setup.sh`
3. `./app/acvp_app --<options>`

Use `./app/acvp_app --help` for more information on available options.

libacvp generates a file containing information that can be used to resume or check the results
of a session. By default, this is usually placed in the folder of the executable utilizing
libacvp, though this can be different on some OS. The name, by default, is
testSession_(ID number).json. The path and prefix can be controlled using ACV_SESSION_SAVE_PATH
and ACV_SESSION_SAVE_PREFIX in your environment, respectively. 


## FIPS and OpenSSL 3.X
For OpenSSL 3.X, FIPS mode is determined by the acvp_app at runtime instead of
build time. Acvp_app will attempt to utilize the OpenSSL FIPS provider by default; a runtime
argument can be provided to not fetch FIPS crypto (CERTIFICATIONS MUST NOT BE PERFORMED THIS WAY).

We cannot advise specifically how to configure OpenSSL 3.X as that will vary on a platform-specific
basis. Generally, the OpenSSL config file must include the fipsmodule.cnf file, must explicitly
include the fips section, and must explicitly activate the FIPS provider. When the FIPS provider is
explicitly activated, the default provider is no longer implicitly activated and must also be
explicitly activated in some cases. In our testing, offline sessions can be run without explicitly
activating the default provider (since all the crypto tests seek the FIPS provider), but Curl (and
thus any online sessions or requests) requires the default provider to be activated to function
properly.

acvp_app will perform a quick operation at startup using the FIPS provider to determine if FIPS
crypto is working properly. If it fails, it will return an error; in this case please review your
OpenSSL install, libacvp build steps, and especially your OpenSSL configuration before contacting
the libacvp team.


### How to test offline
1. Download vectors on network accessible device:
`./app/acvp_app --<algs of choice or all_algs> --vector_req <filename1>`
 - where `<filename1>` is the file you are saving the tests to.

2. Copy vectors and acvp_app to target:
`./app/acvp_app --all_algs --vector_req <filename1> --vector_rsp <filename2>`
 - where `<filename1>` is the file the tests are saved in, and `<filename2>` is the file
you want to save your results to.

3. Copy responses(filename2) to network accessible device:
`./app/acvp_app --all_algs --vector_upload <filename2>`
 - where `<filename2>` is the file containing the results of the tests.

*Note:* If the target in Step 2 does not have the standard libraries used by
libacvp you may configure and build a special app used only for Step 2. This
can be done by using --enable-offline when running ./configure which will help
minimize library dependencies. By using --disable-shared at configure time,
libacvp can be linked to acvp_app statically as well; acvp_app will link to other
dependencies as described above under `other build options`.

## Testing
Move to the test/ directory and see the README.md there. The tests depend upon
a C test framework called Criterion, found here: https://github.com/Snaipe/Criterion


## Contributing
Before opening a pull request on libacvp, please ensure that all unit tests are
passing. Additionally, new tests should be added for new library features.

We also run the uncrustify tool as a linter to keep code-style consistent
throughout the library. That can be found in the `uncrustify/` directory.

Any and all new API functions must also be added to ms\resources\source.def.

## FAQ

`I get "unable to process test vectors" for certain algorithms. Why?`
This usually indicates that you have requested to test certain algorithms or features within
algorithms that cannot be tested with the given version of OpenSSL as built.

`I get some sort of hard crash while processing vector sets - why?`
It is probable that acvp_app is linking to a different version of a dependency than the one
it was configured and built with. libacvp/acvp_app depend on library versions in enabling 
or disabling certain features at build time, so please make sure libacvp and acvp_app are 
built and run with the same versions of each library.

`Can I redownload vector sets from a previously created session?`
Yes. running acvp_app with the --resume_session AND --vector_req options will redownload
those vector sets to the given file without processing or uploading anything. See the app
help section for more details about these commands.

`I have been getting retry messages for X amount of time. Is this normal?`
Yes; the server actively sends retry messages when it is still in the process of generating
tests or waiting to generate tests. This period of time can vary wildly if the server is under
intense load, anywhere from a few seconds to a few days. If there is an issue and the connection
is lost or the server experiences an error, the library output will indicate it.

`I received a vector set from somewhere other than libacvp, such as a lab. How can I process it?`
Libacvp expects vector set json files to have a specific formatting. It is possible to manually
modify the JSON file to make it work though we do not officially support or endorse this process.
We plan to add support for this usage soon.

Moving your vector set into a json array, and putting this as the json object before the vector set
should allow libacvp to process it using the offline testing process described above; you would
also need to remove these entries from the output file.
```
{
    "jwt": "NA",
    "url": "NA",
    "isSample": false,
    "vectorSetUrls": [
        "NA"
    ]
}
```
Note that this file will not be able to be submitted using libacvp unless you manually input all
of the correct information in the above object; we do not recommend this and you should instead
try to submit via wherever you originally got the vector set from.

## Credits
This package was initially written by John Foley of Cisco Systems.
Contributors include (non-exhaustive):
Barry Fussell (Cisco Systems)
Andrew Karcher (Cisco Systems)

## Supported Algorithms

|   Algorithm Type   |    Library Support    |    App Support (Open SSL 1.1.1)    |    App Support (OpenSSL 3.X)    |
| :---------------:  | :-------------------: | :--------------------------------: | :-----------------------------: |
| **Block Cipher Modes** |                   |                                    |
| **AES-CBC** |  Y  |  Y  |  Y  |
| **AES-CFB1** |  Y  |  Y  |  Y  |
| **AES-CFB8** |  Y  |  Y  |  Y  |
| **AES-CFB128** |  Y  |  Y  |  Y  |
| **AES-CTR** |  Y  |  Y  |  Y  |
| **AES-ECB** |  Y  |  Y  |  Y  |
| **AES-GCM** |  Y  |  Y  |  Y  |
| **AES-GCM-SIV** |  Y  |  Y  |  Y  |
| **AES-KW** |  Y  |  Y  |  Y  |
| **AES-KWP** |  Y  |  Y  |  Y  |
| **AES-OFB** |  Y  |  Y  |  Y  |
| **AES-XPN** |  N  |  N  |  Y  |
| **AES-XTS** |  Y  |  Y  |  Y  |
| **AES-FF1** |  N  |  N  |  N  |
| **AES-FF3-1** |  N  |  N  |  N  |
| **TDES-CBC** |  Y  |  Y  |  Y  |
| **TDES-CBCI** |  N  |  N  |  N  |
| **TDES-CFBP1** |  N  |  N  |  N  |
| **TDES-CFBP8** |  N  |  N  |  N  |
| **TDES-CFBP64** |  N  |  N  |  N  |
| **TDES-CTR** |  Y  |  Y  |  N  |
| **TDES-ECB** |  Y  |  Y  |  Y  |
| **TDES-KW** |  Y  |  N  |  N  |
| **TDES-OFB** |  Y  |  Y  |  N  |
| **TDES-OFBI** |  N  |  N  |  N  |
| **Secure Hash** | | |
| **SHA-1** |  Y  |  Y  |  Y  |
| **SHA-224** |  Y  |  Y  |  Y  |
| **SHA-256** |  Y  |  Y  |  Y  |
| **SHA-384** |  Y  |  Y  |  Y  |
| **SHA-512** |  Y  |  Y  |  Y  |
| **SHA-512/224** |  Y  |  Y  |  Y  |
| **SHA-512/256** |  Y  |  Y  |  Y  |
| **SHA3-224** |  Y  |  Y  |  Y  |
| **SHA3-256** |  Y  |  Y  |  Y  |
| **SHA3-384** |  Y  |  Y  |  Y  |
| **SHA3-512** |  Y  |  Y  |  Y  |
| **SHAKE-128** |  Y  |  Y  |  Y  |
| **SHAKE-256** |  Y  |  Y  |  Y  |
| **XOFs** | | |
| **cSHAKE-128** |  N  |  N  |  N  |
| **cSHAKE-256** |  N  |  N  |  N  |
| **KMAC-128** |  Y  |  N  |  Y  |
| **KMAC-256** |  Y  |  N  |  Y  |
| **ParallelHash-128** |  N  |  N  |  N  |
| **ParallelHash-256** |  N  |  N  |  N  |
| **TupleHash-128** |  N  |  N  |  N  |
| **TupleHash-256** |  N  |  N  |  N  |
| **Message Authentication** | | |
| **AES-GMAC** |  Y  |  Y  |  Y  |
| **AES-CCM** |  Y  |  Y  |  Y  |
| **CMAC-AES** |  Y  |  Y  |  Y  |
| **CMAC-TDES** |  Y  |  Y  |  N  |
| **HMAC-SHA-1** |  Y  |  Y  |  Y  |
| **HMAC-SHA2-224** |  Y  |  Y  |  Y  |
| **HMAC-SHA2-256** |  Y  |  Y  |  Y  |
| **HMAC-SHA2-384** |  Y  |  Y  |  Y  |
| **HMAC-SHA2-512** |  Y  |  Y  |  Y  |
| **HMAC-SHA2-512/224** |  Y  |  Y  |  Y  |
| **HMAC-SHA2-512/256** |  Y  |  Y  |  Y  |
| **HMAC-SHA3-224** |  Y  |  Y  |  Y  |
| **HMAC-SHA3-256** |  Y  |  Y  |  Y  |
| **HMAC-SHA3-384** |  Y  |  Y  |  Y  |
| **HMAC-SHA3-512** |  Y  |  Y  |  Y  |
| **DRBG** | | |
| **ctrDRBG-AES-128** |  Y  |  N  |  Y  |
| **ctrDRBG-AES-192** |  Y  |  N  |  Y  |
| **ctrDRBG-AES-256** |  Y  |  N  |  Y  |
| **ctrDRBG-TDES** |  N  |  N  |  N  |
| **HASH DRBG** |  Y  |  N  |  Y  |
| **HMAC DRBG** |  Y  |  N  |  Y  |
| **Digital Signature** | | |
| **RSA mode: keyGen** |  Y  |  N  |  Y  |
| **RSA mode: sigGen** |  Y  |  N  |  Y  |
| **RSA mode: sigVer** |  Y  |  N  |  Y  |
| **RSA mode: signatureComponent** |  Y  |  N  |  Y  |
| **RSA mode: decryptionComponent** |  Y  |  N  |  N  |
| **RSA mode: legacySigVer** |  N  |  N  |  N  |
| **ECDSA mode: sigGenComponent** |  Y  |  N  |  Y  |
| **ECDSA mode: keyGen** |  Y  |  N  |  Y  |
| **ECDSA mode: keyVer** |  Y  |  N  |  Y  |
| **ECDSA mode: sigGen** |  Y  |  N  |  Y  |
| **ECDSA mode: sigVer** |  Y  |  N  |  Y  |
| **DSA mode: keyGen** |  Y  |  N  |  Y  |
| **DSA mode: sigVer** |  Y  |  N  |  Y  |
| **DSA mode: sigGen** |  Y  |  N  |  Y  |
| **DSA mode: pqgGen** |  Y  |  N  |  Y  |
| **DSA mode: pqgVer** |  Y  |  N  |  Y  |
| **EDDSA mode: keyGen** |  Y  |  N  |  Y  |
| **EDDSA mode: keyVer** |  N  |  N  |  N  |
| **EDDSA mode: sigGen** |  Y  |  N  |  Y  |
| **EDDSA mode: sigVer** |  Y  |  N  |  Y  |
| **LMS mode: keyGen** |  Y  |  N  |  N  |
| **LMS mode: sigGen** |  Y  |  N  |  N  |
| **LMS mode: sigVer** |  Y  |  N  |  N  |
| **Key Agreement** | | |
| **KAS ECC ephemeralUnified** |  Y  |  N  |  N  |
| **KAS ECC SSC ephemeralUnified** |  Y  |  N  |  Y  |
| **KAS ECC fullMqv** |  N  |  N  |  N  |
| **KAS ECC fullUnified** |  N  |  N  |  N  |
| **KAS ECC onePassDh** |  N  |  N  |  N  |
| **KAS ECC onePassMqv** |  N  |  N  |  N  |
| **KAS ECC OnePassUnified** |  N  |  N  |  N  |
| **KAS ECC staticUnified** |  N  |  N  |  N  |
| **KAS ECC CDH-Component** |  Y  |  N  |  Y  |
| **KAS FFC dhHybrid1** |  N  |  N  |  N  |
| **KAS FFC mqv2** |  N  |  N  |  N  |
| **KAS FFC dhEphem** |  Y  |  N  |  N  |
| **KAS FFC SSC dhEphem** |  Y  |  N  |  Y  |
| **KAS FFC dhHybridOneFlow** |  N  |  N  |  N  |
| **KAS FFC mqv1** |  N  |  N  |  N  |
| **KAS FFC dhOneFlow** |  N  |  N  |  N  |
| **KAS FFC dhStatic** |  N  |  N  |  N  |
| **KAS IFC SSC KAS1** |  Y  |  N  |  Y  |
| **KAS IFC SSC KAS2** |  Y  |  N  |  Y  |
| **KAS IFC KAS1-basic** |  N  |  N  |  N  |
| **KAS IFC KAS1-Party_V-confirmation** |  N  |  N  |  N  |
| **KAS IFC KAS2-basic** |  N  |  N  |  N  |
| **KAS IFC KAS2-bilateral-confirmation** |  N  |  N  |  N  |
| **KAS IFC KAS2-Party_U-confirmation** |  N  |  N  |  N  |
| **KAS IFC KAS2-Party_V-confirmation** |  N  |  N  |  N  |
| **KTS IFC KTS-OAEP-basic** |  Y  |  N  |  Y  |
| **KTS IFC KTS-OAEP-Party_V-confirmation** |  N  |  N  |  N  |
| **KDA HKDF** |  Y  |  N  |  Y  |
| **KDA ONESTEP** |  Y  |  N  |  Y  |
| **KDA TWOSTEP** |  Y  |  N  |  Y  |
| **KDFs** | | |
| **Counter KDF** |  Y  |  N  |  Y  |
| **Feedback KDF** |  Y  |  N  |  Y  |
| **Double Pipeline Iterator KDF** |  Y  |  N  |  N  |
| **KMAC KDF** |  Y  |  N  |  N  |
| **IKEv1** |  Y  |  N  |  N  |
| **IKEv2** |  Y  |  N  |  N  |
| **SNMP** |  Y  |  N  |  N  |
| **SRTP** |  Y  |  N  |  N  |
| **SSH** |  Y  |  N  |  Y  |
| **TLS 1.2** |  Y  |  N  |  Y  |
| **TLS 1.3** |  Y  |  N  |  Y  |
| **TPM** |  N  |  N  |  N  |
| **ANSX9.63** |  Y  |  N  |  Y  |
| **ANSX9.42** |  Y  |  N  |  Y  |
| **PBKDF** |  Y  |  N  |  Y  |
| **Safe Primes** | | |
| **SafePrimes KeyGen** |  Y  |  N  |  Y  |
| **SafePrimes KeyVer** |  Y  |  N  |  Y  |

