@echo off

rem "x86" or "x64"
set ACVP_ARCH=x64

rem path to OpenSSL 1.1.1 or greater
set SSL_DIR=C:\Path\to\dir

rem for non-runtime testing. Only provided for SSL versions less than 3.0.
set FOM_DIR=

rem if libcurl dir is empty, libacvp will build for offline mode only
set LIBCURL_DIR=C:\Path\to\dir
