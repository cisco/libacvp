@echo off

rem "x86" or "x64"
set ACVP_ARCH=x64

set SSL_DIR=C:\Path\to\dir
rem set true for SSL versions before 1.1.0
set LEGACY_SSL=FALSE

rem for non-runtime testing
set FOM_DIR=C:\Path\to\dir

rem if libcurl dir is empty, we will attempt to use libmurl and directly build it in
set LIBCURL_DIR=C:\Path\to\dir

set SAFEC_DIR=C:\Path\to\dir
rem if DISABLE_SAFEC is true, we will use safe C stub
set DISABLE_SAFEC=TRUE

set STATIC_BUILD=FALSE
rem offline builds must be static as well
set OFFLINE_BUILD=FALSE
