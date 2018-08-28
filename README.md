        __       __  .______        ___       ______ ____    ____ .______
        |  |     |  | |   _  \      /   \     /      |\   \  /   / |   _  \
        |  |     |  | |  |_)  |    /  ^  \   |  ,----' \   \/   /  |  |_)  |
        |  |     |  | |   _  <    /  /_\  \  |  |       \      /   |   ___/
        |  `----.|  | |  |_)  |  /  _____  \ |  `----.   \    /    |  |
        |_______||__| |______/  /__/     \__\ \______|    \__/     | _|   

        A library that implements the client-side of the ACVP protocol.
        The ACVP specification is a work-in-progress and can be found at
        https://github.com/usnistgov/ACVP

Upcoming Changes!
    
    The library API has been updated as of **August 2018** to store hex buffers
    as their equivalent byte arrays. This simplifies the responsibilities of
    the applicatin layer as most C crypto libraries ingest/output byte
    arrays by default. From now on, test case properties that show in the ACVP
    spec as hex strings will be stored as byte arrays, and the library will
    expect the application to populate result attributes as byte arrays as
    well. For examples, see app/app_main.c.


Overview

    libacvp is a client-side ACVP implementation.  This library currently
    has two dependencies: libcurl and parson.  Curl is used for sending
    REST calls to the ACVP server.  Parson is used to parse and generate
    JSON data for the REST calls.  The parson code is included and compiled
    as part of libacvp.  libcurl is not included, and must be installed
    separately on your Linux host, including the Curl header files.

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

    libacvp will register with the ACVP server, advertising capabilities to
    the server.  Currently only AES-GCM is supported.  The server will
    respond with a list of vector set identifiers that need to be
    processed.  libacvp will download each vector set, process the vectors,
    and send the results back to the server.

    The app directory contains a sample application that uses libacvp.  The software
    that uses libacvp for crypto validation will be responsible for writing
    a similar app for their platform.  acvp_app is only provided here for
    unit testing and demonstrating how to use libacvp.  The application
    layer (acvp_app.c) is required to provide the crypto module that will
    be FIPS validated.  In this example it uses OpenSSL, which introduces
    libcrypto.so as a new dependency when compiling the app.  The OpenSSL
    development package needs to be installed on your Linux system.

    There is also a FOM Makefile which provides an example on how a
    standalone module could be tested.  In this case it uses the openssl
    FOM canister.  The FOM canister has a few algorithms that can only
    be tested when not running in a final product, and they are compiled
    in using -DACVP_NO_RUNTIME. These algorithms can be tested under this
    configuration. The FOM build also requires the path to the canister
    header files and object which is defined using the environment
    variable MODULE_ROOT.

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
    The Murl code is currently in an experimental stage.


Building

    IMPORTANT: The example client application has placeholders for some
    vector processing handlers that are not currently supported in OpenSSL,
    namely KDFs, RSA key generation, and TDES CTR. The respective handlers
    have skeleton code and are marked with a comment "IMPORTANT: ...".
    You will have to fill these in with your crypto module's API in order
    for vector tests to pass.

    Dependencies:
        libacvp is dependent on autotools, gcc, make, curl (or substitution) and
        openssl (or substitution)

    To build:
        ./configure --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir>
        make
        make install

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

Credits

        This package was initially written by John Foley of Cisco Systems.
