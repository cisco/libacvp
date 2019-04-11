        __       __  .______        ___       ______ ____    ____ .______
        |  |     |  | |   _  \      /   \     /      |\   \  /   / |   _  \
        |  |     |  | |  |_)  |    /  ^  \   |  ,----' \   \/   /  |  |_)  |
        |  |     |  | |   _  <    /  /_\  \  |  |       \      /   |   ___/
        |  `----.|  | |  |_)  |  /  _____  \ |  `----.   \    /    |  |
        |_______||__| |______/  /__/     \__\ \______|    \__/     | _|   

        A library that implements the client-side of the ACVP protocol.
        The ACVP specification is a work-in-progress and can be found at
        https://github.com/usnistgov/ACVP

License
        Libacvp is licensed under the Apache License 2.0, which means that
        you are free to get and use it for commercial and non-commercial
        purposes as long as you fulfill its conditions. See the LICENSE
        file for details.

Recent Changes!
        The client library has been updated to be compatible with the
        ACVP spec version 1.0, see https://github.com/usnistgov/ACVP

Overview

    libacvp is a client-side ACVP reference implementation.  This library 
    currently has three dependencies: openssl, libcurl and parson.  Curl is
    used for sending REST calls to the ACVP server.  Parson is used to parse
    and generate JSON data for the REST calls.  Openssl is used for TLS
    transport by libcurl. The parson code is included and compiled as part
    of libacvp.  libcurl, libssl and libcrypto are not included, and must
    be installed separately on your build host, including the header files.

    This code uses features in OpenSSL 1.0.2, but not present in OpenSSL 1.0.1.
    Many Linux distros still ship with OpenSSL 1.0.1.  Under this situation
    you will need to download, compile and install OpenSSL 1.0.2 on your system.
    This would typically be installed into /usr/local/ssl to avoid
    overwriting the OpenSSL that comes with your distro.  When doing this, the
    next problem is the libcurl on the Linux distro may be linked against
    OpenSSL 1.0.1.  This will result in linker failures when trying to use
    libcurl with libacvp and OpenSSL 1.0.2.  Therefore, you may need to
    download the Curl source, compile it against the OpenSSL 1.0.2
    header files, and link libcurl against OpenSSL 1.0.2.  OpenSSL 1.0.2
    is used for AES keywrap support, which isn't available in OpenSSL 1.0.1.
    libacvp can also be used with 1.1.X versions of openssl and have compile
    time checks to address differences in the API.

    libacvp will register with the ACVP server, advertising capabilities to
    the server.  The server will respond with a list of vector set identifiers
    that need to be processed.  libacvp will download each vector set, process
    the vectors, and send the results back to the server.  This is performed
    realtime. If non-realtime support is required the library will require
    enhancing.

    The app directory contains a sample application that uses libacvp.  The software
    that uses libacvp for crypto testing may require additional enhancements
    or a new app depending on the crypto under test.  acvp_app is only provided
    here for unit testing and demonstrating how to use libacvp.  The application
    layer (app_main.c) is required to interface with the crypto module that will
    be tested.  In this example it uses OpenSSL, which introduces libcrypto.so as
    the module under test.  The OpenSSL development package needs to be installed
    on your Linux system.

    The library also provides an example on how a standalone module could be
    tested.  In this case it uses the openssl FOM canister.  The FOM canister
    has a few algorithms that can only be tested when not running in a final
    product, These algorithms can be tested under this configuration. The FOM
    build also requires the path to the canister header files and object which
    is defined in the configure command line for no runtime shown below which
    automatically adds the compile time flag -DACVP_NO_RUNTIME.

    The certs directory contains the certificates used to establish a TLS
    session with well-known ACVP servers.  libacvp requires one or more
    trust anchor certificates that can verify the identity of the ACVP
    server.  The NIST ACVP server currently uses a self-signed certificate,
    which is included in the certs directory and can be used as the trust
    anchor.  libacvp also requires a client certificate and key pair,
    which the ACVP server uses to identify the client.  You will need to
    contact NIST to register your client certificate with their server.

    The murl directory contains experimental code to replace the Curl
    dependency.  This may be useful for target platforms that don't support
    Curl, such as Android or iOS.  Murl is a "minimal" Curl implementation.
    It implements a handful of the Curl API entry points used by libacvp.
    The Murl code is currently in an experimental stage and is not supported
    or maintained as part of libacvp and should not be used in any
    production environment.


Building

    Dependencies:
        libacvp is dependent on autotools, gcc, make, curl (or substitution) and
        openssl (or substitution)

    To build for runtime testing:
        ./configure --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir>
        make clean
        make
        make install

    To build for no runtime testing:
        ./configure --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir> --with-fom_dir=<path to where FOM is installed>
        make clean
        make
        make install

    Cross compiles also require environment variables options --build and --host, 
    for example:
        export CROSS_COMPILE=powerpc-buildroot-linux-uclibc
        Your $PATH must contain a path the gcc
        ./configure --build=<local target prefix> --host=<gcc prefix of target host> --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir>

  
     exmaple with build and host information:
        ./configure --build=<localx86_64-unknown-linux-gnu --host=mips64-octeon-linux-gnu --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir>

    All dependent libraries must have been built with the same cross compile.

    To run:
        1. export LD_LIBRARY_PATH=<path to ssl lib>
        2. update and run scripts/nist_setup.sh
        3. ./app/acvp_app

    On Windows:
        1. Update and run the scripts/gradle_env.bat script
            Note: some of the required .dll's and include headers are in the windows directory.
                  If these aren't the version you are looking for, you will need to point
                  the environment variables to your own install.
        2. 'gradle build'
        3. Update and run the scripts/nist_setup.bat script
        4. The library is in build/libs/acvp and the example executable
            is in build/exe/


Testing

    Move to the test directory and see the README.md there. The tests depend upon
    a C test framework called Criterion, found here: https://github.com/Snaipe/Criterion


Contributing

    Before opening a pull request on libacvp, please ensure that all unit tests are
    passing. Additionally, new tests should be added for new library features.

    We also run the uncrustify tool as a linter to keep code-style consistent
    throughout the library. That can be found in the 'uncrustify' directory.


Credits

        This package was initially written by John Foley of Cisco Systems.
