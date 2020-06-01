@echo off

rem "x86" or "x64"
set ACVP_ARCH=x64
set SSL_DIR=C:\Users\ankarche\dependencies\ssl102fom
set FOM_DIR=C:\Users\ankarche\dependencies\fom62a
set LIBCURL_DIR=C:\Users\ankarche\Desktop\acvp_win\curl_shared
rem if libcurl dir is empty, we will attempt to use libmurl and directly build it in
set SAFEC_DIR=C:\Users\ankarche\dependencies\csafec
set DISABLE_SAFEC=FALSE
set STATIC_BUILD=FALSE
rem offline builds must be static as well
set OFFLINE_BUILD=FALSE
rem set true for SSL versions before 1.1.0
set LEGACY_SSL=TRUE