@echo off

set ACV_INC_PATHS=
set ACV_LIB_PATHS=
set ACV_ROOT_PATH=

rem Visual Studio wants absolute paths in some cases
set ACV_ROOT_PATH_REL=%~dp0..\
for %%i in ("%ACV_ROOT_PATH_REL%") do SET "ACV_ROOT_PATH=%%~fi

if [%FOM_DIR%]==[] (
  echo "No fom, some algorithms will not be available for testing"
  set PROJ_CONFIG=nofom
) ELSE (
  set ACV_LIB_PATHS=%FOM_DIR%\lib
  set ACV_INC_PATHS=%FOM_DIR%\include
  set PROJ_CONFIG=fom
)

if [%SSL_DIR%]==[] (
  echo "Missing SSL dir, stopping"
  goto :end
) ELSE (
  set ACV_LIB_PATHS=%ACV_LIB_PATHS%;%SSL_DIR%\lib
  set ACV_INC_PATHS=%ACV_INC_PATHS%;%SSL_DIR%\include
)

if %LEGACY_SSL%==TRUE (
  set PROJ_CONFIG=%PROJ_CONFIG%_legacy_ssl
)

if [%SAFEC_DIR%]==[] (
  set PROJ_CONFIG=%PROJ_CONFIG%_no_safec
  set ACV_INC_PATHS=%ACV_INC_PATHS%;%ACV_ROOT_PATH%\safe_c_stub\include
) ELSE (
  set ACV_LIB_PATHS=%ACV_LIB_PATHS%;%SAFEC_DIR%
  set ACV_INC_PATHS=%ACV_INC_PATHS%;%SAFEC_DIR%\include
)

if NOT %DISABLE_KDF%==TRUE (
  set ACV_KDF_SUPPORT=OPENSSL_KDF_SUPPORT
)

if %STATIC_BUILD%==TRUE (
  set ACV_CURL_STATIC=CURL_STATICLIB
)

set ACV_LIB_PATHS=%ACV_LIB_PATHS%;%~dp0%build
set ACV_INC_PATHS=%ACV_INC_PATHS%;%ACV_ROOT_PATH%\include

msbuild ms\acvp_app.sln /p:Configuration=%PROJ_CONFIG% /p:Platform=%ACVP_ARCH% /p:UseEnv=True

:end