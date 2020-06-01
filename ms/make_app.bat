@echo off

if [%FOM_DIR%]==[] (
  echo "No fom, some algorithms will not be available for testing"
  set PROJ_CONFIG=nofom
) ELSE (
  set ACV_LIBPATH=%FOM_DIR%\lib
  set ACV_INCLUDE=%FOM_DIR%\include
  set PROJ_CONFIG=fom
)

if [%SSL_DIR%]==[] (
  echo "Missing SSL dir, stopping"
  goto :end
) ELSE (
  set ACV_LIBPATH=%ACV_LIBPATH%;%SSL_DIR%\lib
  set ACV_INCLUDE=%ACV_INCLUDE%;%SSL_DIR%\include
)

if %LEGACY_SSL%==TRUE (
  set PROJ_CONFIG=%PROJ_CONFIG%_legacy_ssl
)

if %DISABLE_SAFEC%==TRUE (
  set PROJ_CONFIG=%PROJ_CONFIG%_no_safec
  set ACV_INCLUDE=%ACV_INCLUDE%;%cd%\safe_c_stub\include
) ELSE (
  set ACV_LIBPATH=%ACV_LIBPATH%;%SAFEC_DIR%\lib
  set ACV_INCLUDE=%ACV_INCLUDE%;%SAFEC_DIR%\include
)

set ACV_LIBPATH=%ACV_LIBPATH%;%cd%\ms\build

set INCLUDE=%ACV_INCLUDE%;%cd%\include;%INCLUDE%
set LIB=%ACV_LIBPATH%;%LIB%

msbuild ms\acvp_app.sln /p:Configuration=%PROJ_CONFIG% /p:Platform=%ACVP_ARCH% /p:UseEnv=True

:end