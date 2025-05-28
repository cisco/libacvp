@echo off

set ACV_INC_PATHS=
set ACV_LIB_PATHS=

rem Visual Studio wants absolute paths in some cases
set ACV_ROOT_PATH_REL=%~dp0..\
for %%i in ("%ACV_ROOT_PATH_REL%") do SET "ACV_ROOT_PATH=%%~fi

set PROJ_CONFIG="openssl3"

if [%SSL_DIR%] == [] (
  echo "Missing SSL dir, stopping"
  goto :error
) else (
  set ACV_LIB_PATHS=%ACV_LIB_PATHS%;%SSL_DIR%\lib
  set ACV_INC_PATHS=%ACV_INC_PATHS%;%SSL_DIR%\include
)

set ACV_LIB_PATHS=%ACV_LIB_PATHS%;%~dp0%build
set ACV_INC_PATHS=%ACV_INC_PATHS%;%ACV_ROOT_PATH%\include

msbuild ms\acvp_app.sln /p:Configuration=%PROJ_CONFIG% /p:Platform=%ACVP_ARCH% /p:UseEnv=True || goto :error
goto :end

:error
  exit /b

:end

