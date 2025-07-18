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

In Libacvp 2.2.0, the application has been completely restructured with multiple benefits.
- The application is now built around the idea of supporting different implementations
  - Support for testing part of liboqs, and the SHA implementation within jitterentropy-library,
    as well as OpenSSL 3.X, are now included
- acvp_app is now no longer dependent on OpenSSL for running TOTP operations; the app no longer
  requires a link to OpenSSL when testing other implementations
- registrations are now split into different files for better readability and maintenance
- Command line invocation is shared amongst different implementations for consistent behavior

# Overview

Libacvp is a client-side ACVP library implementation, and also includes
an example application (acvp_app) which utilizes the library.

libacvp will login and then register with the ACVP server (advertising capabilities).
The server will respond with a list of vector set identifiers that need to be processed.
libacvp will download each vector set, process the vectors, and send the results back to the server.
This is performed in real-time by default. The user can also use "offline" mode for non-realtime
processing.

The `app/` directory contains an application which uses libacvp. This app
provides the glue between a crypto module and the library itself. This application includes
support for OpenSSL, parts of liboqs, and an internal SHA implementation within jitterentropy-library.
Depending upon the operating environment, the crypto backend API, and other factors, the user
may need to enhance the reference application, or create a new one from scratch.
app/implementations/README.md describes how support for a different implementation under test
can be added.

For more details about how to build and run against a certain supported implementation, view the
`README.md` file within a given IUT's folder in `app/implementations`.

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
* libcriterion (for unit tests only)
* doxygen (for building documentation only)

Curl is used for sending REST calls to the ACVP server.

Openssl is used for TLS transport by libcurl.

Parson is used to parse and generate JSON data for the REST calls.
The parson code is included and compiled as part of libacvp.

libcurl, and any of its dependencies, must be installed separately on your build/target host.
Headers are also required for libcurl.

##### Dealing with system-default dependencies

There are various cases where libacvp will need to link against OpenSSL.
- You are testing the implementation of OpenSSL
- libcurl is dependent on OpenSSL
- another supported implementation has links to OpenSSL

If you are using OpenSSL as the implementation under test, libcurl must be built against it. Without
doing so, many platforms will attempt to link a built-in version of OpenSSL alongside the desired
testing version, and create conflicts.

It is the user's responsibility to ensure that the correct versions of implementations under test are
linked, both at configure/build time and at runtime. The `acvp_app --version` command can help identify
this, but should not be relied upon verbatim.

Libacvp is designed to work with curl version 7.80.0 or newer. Some operating systems may ship with
older versions of Curl which are missing certain features that libacvp depends on. In this case you
should either acquire a newer version through your OS package manager if possible or build a newer
version from source. While it is possible some older versions may work, they are not tested or
supported.

## Building

The instructions below indicate how to build libacvp and/or acvp_app.

`--prefix<path to install dir>` can be used with any configure options to specify where you would
like the library and application to install to. 

Regardless of which IUT is being linked, `--with-ssl-dir` can be provided if OpenSSL is a dependency
and is installed in non-standard paths.  if `--with-ssl-dir` is provided on top of another IUT's
link argument, the harness for the other IUT will be built. If `--with-ssl-dir` is provided alone,
the OpenSSL harness will be built.

#### To build app and library for supported algorithm testing

One of the following should be provided in the `configure` command below.
- `--with-ssl-dir=<path>`
- `--with-liboqs-dir=<path>`
- `--with-jent-dir=<path>`

```
./configure  --with-libcurl-dir=<path to curl dir>
make clean
make
make install
```

Note: `--with-libcurl-dir` can be excluded if a version of libcurl with headers exists in the
system's default search paths. This can be helpful if you are not testing OpenSSL and do not
have specific requirements from the library used for TLS.

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

#### Offline builds

Adding `--enable-offline` to configure creates a library with no link to libcurl. This can be used for
running tests in environments that have no or limited network connectivity; a traditional build can
be used to request vectors outside of this environment which can then be copied over.

#### Other build options
More info about all available configure options can be found by using ./configure --help.

Libacvp will attempt to link a shared library for a given dependency if it exists, and will use a static library
if a shared one is not found.

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
1. Edit and run ms\config_windows.bat
    -Add all of the directories for your dependencies
    -Change any needed settings
2. Open libacvp.sln and acvp_app.sln in Visual Studio and allow the dialog to update the projects'
   versions of MSVC and windows SDK to the latest installed (May be unnecessary if versions match)
3. run ms/make_lib.bat
4. run ms/make_app.bat

The library files and app files will be placed in the ms/build/ directory.

Notes:
Windows will only search specific paths for shared libraries, and will not check the
locations you specify in config_windows.bat by default unless they are in your path. This results
in acvp_app not being able to run. An alternative to altering your path or moving libraries to
system folders is moving/copying any needed .dll files to the same directory as acvp_app.

Windows currently has limited application IUT support. Expanding this support is a very low
priority unless we receive substantial feedback about needs for further support.


## Running
1. Ensure the runtime linker environment is aware of all dependency libraries, such as libcurl
   and any IUT libraries. On Linux/GNU platforms, this is typically done by setting 
   `LD_LIBRARY_PATH`.
2. Modify scripts/nist_setup.sh and run `source scripts/nist_setup.sh`
3. `./app/acvp_app --<options>`

Use `./app/acvp_app --help` for more information on available options.

libacvp generates a file containing information that can be used to resume or check the results
of a session. By default, this is usually placed in the folder of the executable utilizing
libacvp, though this can be different on some OS. The name, by default, is
testSession_(ID number).json. The path and prefix can be controlled using ACV_SESSION_SAVE_PATH
and ACV_SESSION_SAVE_PREFIX in your environment, respectively. 


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
algorithms that cannot be tested with the given version of the IUT as built.

`I get some sort of hard crash while processing vector sets - why?`
It is probable that acvp_app is linking to a different version of a dependency than the one
it was configured and built with. libacvp/acvp_app depend on library versions in enabling 
or disabling certain features at build time, so please make sure libacvp and acvp_app are 
built and run with the same versions of each library.

`Can I redownload vector sets from a previously created session?`
Yes. running acvp_app with the --resume_session AND --vector_req options will re-download
those vector sets to the given file without processing or uploading anything. See the app
help section for more details about these commands.

`I have been getting retry messages for X amount of time. Is this normal?`
Yes; the server actively sends retry messages when it is still in the process of generating
tests or waiting to generate tests. This period of time can vary wildly if the server is under
intense load, anywhere from a few seconds to a few days. If there is an issue and the connection
is lost or the server experiences an error, the library output will indicate it.

`I received a vector set from somewhere other than libacvp, such as a lab. How can I process it?`
Libacvp by default expects vector set json files to have the same specific formatting it uses to store
those vector set files.

If you have a single object vector set file without this formatting, you should be able to run it by
providing `--generic` alongside the `--vector_req` and `--vector_rsp` commands you would normally use
to run vectors offline.

## Credits
This package was initially written by John Foley of Cisco Systems.
Contributors include (non-exhaustive):
Barry Fussell (Cisco Systems)
Andrew Karcher (Cisco Systems)

## Supported Algorithms

This table lists the algorithms supported by the library itself. An implementation typically will
support a subset of these. If an algorithm is not listed, it can be assumed to be not supported.
For information about which algorithm each implementation harness supports, please view the README
for that implementation in the app/implementations folder.

| Algorithm Type        |   Algorithm Name                     | Support |
| :-------------------: | :----------------------------------: | :-----: |
| **Symmetric Ciphers** | AES-CBC                              |    ✓    |
|                       | AES-CBC-CS1                          |    ✓    |
|                       | AES-CBC-CS2                          |    ✓    |
|                       | AES-CBC-CS3                          |    ✓    |
|                       | AES-CFB1                             |    ✓    |
|                       | AES-CFB8                             |    ✓    |
|                       | AES-CFB128                           |    ✓    |
|                       | AES-CTR                              |    ✓    |
|                       | AES-ECB                              |    ✓    |
|                       | AES-GCM                              |    ✓    |
|                       | AES-GCM-SIV                          |    ✓    |
|                       | AES-KW                               |    ✓    |
|                       | AES-KWP                              |    ✓    |
|                       | AES-OFB                              |    ✓    |
|                       | AES-XPN                              |         |
|                       | AES-XTS                              |    ✓    |
|                       | AES-FF1                              |         |
|                       | AES-FF3-1                            |         |
|                       | TDES-CBC                             |    ✓    |
|                       | TDES-CBCI                            |         |
|                       | TDES-CFBP1                           |         |
|                       | TDES-CFBP8                           |         |
|                       | TDES-CFBP64                          |         |
|                       | TDES-CTR                             |    ✓    |
|                       | TDES-ECB                             |    ✓    |
|                       | TDES-KW                              |    ✓    |
|                       | TDES-OFB                             |    ✓    |
|                       | TDES-OFBI                            |         |
|                       | Ascon AEAD128                        |         |
| **Secure Hash**       | SHA-1                                |    ✓    |
|                       | SHA-224                              |    ✓    |
|                       | SHA-256                              |    ✓    |
|                       | SHA-384                              |    ✓    |
|                       | SHA-512                              |    ✓    |
|                       | SHA-512/224                          |    ✓    |
|                       | SHA-512/256                          |    ✓    |
|                       | SHA3-224                             |    ✓    |
|                       | SHA3-256                             |    ✓    |
|                       | SHA3-384                             |    ✓    |
|                       | SHA3-512                             |    ✓    |
|                       | SHAKE-128                            |    ✓    |
|                       | SHAKE-256                            |    ✓    |
|                       | Ascon Hash256                        |         |
| **XOFs**              | cSHAKE-128                           |         |
|                       | cSHAKE-256                           |         |
|                       | KMAC-128                             |    ✓    |
|                       | KMAC-256                             |    ✓    |
|                       | ParallelHash-128                     |         |
|                       | ParallelHash-256                     |         |
|                       | TupleHash-128                        |         |
|                       | TupleHash-256                        |         |
|                       | Ascon CXOF128                        |         |
|                       | Ascon XOF128                         |         |
| **Message Auth**      | AES-GMAC                             |    ✓    |
|                       | AES-CCM                              |    ✓    |
|                       | CMAC-AES                             |    ✓    |
|                       | CMAC-TDES                            |    ✓    |
|                       | HMAC-SHA-1                           |    ✓    |
|                       | HMAC-SHA2-224                        |    ✓    |
|                       | HMAC-SHA2-256                        |    ✓    |
|                       | HMAC-SHA2-384                        |    ✓    |
|                       | HMAC-SHA2-512                        |    ✓    |
|                       | HMAC-SHA2-512/224                    |    ✓    |
|                       | HMAC-SHA2-512/256                    |    ✓    |
|                       | HMAC-SHA3-224                        |    ✓    |
|                       | HMAC-SHA3-256                        |    ✓    |
|                       | HMAC-SHA3-384                        |    ✓    |
|                       | HMAC-SHA3-512                        |    ✓    |
| **DRBG**              | ctrDRBG-AES-128                      |    ✓    |
|                       | ctrDRBG-AES-192                      |    ✓    |
|                       | ctrDRBG-AES-256                      |    ✓    |
|                       | ctrDRBG-TDES                         |         |
|                       | HASH DRBG                            |    ✓    |
|                       | HMAC DRBG                            |    ✓    |
| **Digital Signature** | RSA mode: keyGen                     |    ✓    |
|                       | RSA mode: sigGen                     |    ✓    |
|                       | RSA mode: sigVer                     |    ✓    |
|                       | RSA mode: signatureComponent         |    ✓    |
|                       | RSA mode: decryptionComponent        |    ✓    |
|                       | RSA mode: legacySigVer               |         |
|                       | ECDSA mode: sigGenComponent          |    ✓    |
|                       | ECDSA mode: keyGen                   |    ✓    |
|                       | ECDSA mode: keyVer                   |    ✓    |
|                       | ECDSA mode: sigGen                   |    ✓    |
|                       | ECDSA mode: sigVer                   |    ✓    |
|                       | Det-ECDSA mode: sigGen               |    ✓    |
|                       | DSA mode: keyGen                     |    ✓    |
|                       | DSA mode: sigVer                     |    ✓    |
|                       | DSA mode: sigGen                     |    ✓    |
|                       | DSA mode: pqgGen                     |    ✓    |
|                       | DSA mode: pqgVer                     |    ✓    |
|                       | EDDSA mode: keyGen                   |    ✓    |
|                       | EDDSA mode: keyVer                   |         |
|                       | EDDSA mode: sigGen                   |    ✓    |
|                       | EDDSA mode: sigVer                   |    ✓    |
|                       | LMS mode: keyGen                     |    ✓    |
|                       | LMS mode: sigGen                     |    ✓    |
|                       | LMS mode: sigVer                     |    ✓    |
|                       | ML-DSA mode: keyGen                  |    ✓    |
|                       | ML-DSA mode: sigGen                  |    ✓    |
|                       | ML-DSA mode: sigVer                  |    ✓    |
|                       | SLH-DSA mode: keyGen                 |    ✓    |
|                       | SLH-DSA mode: sigGen                 |    ✓    |
|                       | SLH-DSA mode: sigVer                 |    ✓    |
| **Key Agreement**     | KAS ECC ephemeralUnified             |    ✓    |
|                       | KAS ECC SSC ephemeralUnified         |    ✓    |
|                       | KAS ECC fullMqv                      |         |
|                       | KAS ECC fullUnified                  |         |
|                       | KAS ECC onePassDh                    |         |
|                       | KAS ECC onePassMqv                   |         |
|                       | KAS ECC OnePassUnified               |         |
|                       | KAS ECC staticUnified                |         |
|                       | KAS ECC CDH-Component                |    ✓    |
|                       | KAS FFC dhHybrid1                    |         |
|                       | KAS FFC mqv2                         |         |
|                       | KAS FFC dhEphem                      |    ✓    |
|                       | KAS FFC SSC dhEphem                  |    ✓    |
|                       | KAS FFC dhHybridOneFlow              |         |
|                       | KAS FFC mqv1                         |         |
|                       | KAS FFC dhOneFlow                    |         |
|                       | KAS FFC dhStatic                     |         |
|                       | KAS IFC SSC KAS1                     |    ✓    |
|                       | KAS IFC SSC KAS2                     |    ✓    |
|                       | KAS IFC KAS1-basic                   |         |
|                       | KAS IFC KAS1-Party_V-confirmation    |         |
|                       | KAS IFC KAS2-basic                   |         |
|                       | KAS IFC KAS2-bilateral-confirmation  |         |
|                       | KAS IFC KAS2-Party_U-confirmation    |         |
|                       | KAS IFC KAS2-Party_V-confirmation    |         |
|                       | KTS IFC KTS-OAEP-basic               |    ✓    |
|                       | KTS IFC KTS-OAEP-Party_V-confirmation|         |
|                       | KDA HKDF                             |    ✓    |
|                       | KDA ONESTEP                          |    ✓    |
|                       | KDA TWOSTEP                          |    ✓    |
|                       | ML-KEM mode: keyGen                  |    ✓    |
|                       | ML-KEM mode: encapDecap              |    ✓    |
| **KDFs**              | Counter KDF                          |    ✓    |
|                       | Feedback KDF                         |    ✓    |
|                       | Double Pipeline Iterator KDF         |    ✓    |
|                       | KMAC KDF                             |    ✓    |
|                       | IKEv1                                |    ✓    |
|                       | IKEv2                                |    ✓    |
|                       | SNMP                                 |    ✓    |
|                       | SRTP                                 |    ✓    |
|                       | SSH                                  |    ✓    |
|                       | TLS 1.2                              |    ✓    |
|                       | TLS 1.3                              |    ✓    |
|                       | TPM                                  |         |
|                       | ANSX9.63                             |    ✓    |
|                       | ANSX9.42                             |    ✓    |
|                       | PBKDF                                |    ✓    |
| **Safe Primes**       | SafePrimes KeyGen                    |    ✓    |
|                       | SafePrimes KeyVer                    |    ✓    |
| **Conditioning**      | AES-CBC-MAC                          |         |
|                       | BlockCipher_DF                       |         |
|                       | Hash_DF                              |         |

