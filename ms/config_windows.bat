@echo off

rem "x86" or "x64"
set ACVP_ARCH=x64

set SSL_DIR=C:\Path\to\dir
rem set true for SSL versions before 1.1.0
set LEGACY_SSL=FALSE

rem for non-runtime testing - will use OpenSSL as normal if empty
set FOM_DIR=C:\Path\to\dir

rem if libcurl dir is empty, OFFLINE_BUILD must be true for windows
set LIBCURL_DIR=C:\Path\to\dir

rem if SAFEC_DIR is empty, we will not use an external library and use the safeC stub instead
set SAFEC_DIR=C:\Path\to\dir

rem options
rem build libacvp statically - will also look for static dependencies
set STATIC_BUILD=FALSE
rem for static builds only; creates a version of library that can only be used for offline processing of vector sets
set OFFLINE_BUILD=FALSE
rem Needed for using acvp_app with a FOM that does not support NIST KDF functions, like OpenSSL fom 2.0
set DISABLE_KDF=TRUE