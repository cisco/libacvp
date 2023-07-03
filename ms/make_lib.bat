@echo off

set ACV_INC_PATHS=
set ACV_LIB_PATHS=

rem Visual Studio wants absolute paths in some cases
set ACV_ROOT_PATH_REL=%~dp0..\
for %%i in ("%ACV_ROOT_PATH_REL%") do SET "ACV_ROOT_PATH=%%~fi

set PROJ_CONFIG=shared

if [%LIBCURL_DIR%] == [] (
  set PROJ_CONFIG=offline
) else (
  set ACV_LIB_PATHS=%LIBCURL_DIR%\lib
  set ACV_INC_PATHS=%LIBCURL_DIR%\include
)

if [%LIBCURL_DIR%] == [] (
  if [%SSL_DIR%] == [] (
    echo "No SSL dir specified. Must be provided for online builds. exiting..."
    goto :error
  ) else (
    set ACV_LIB_PATHS=%ACV_LIB_PATHS%;%SSL_DIR%\lib
    set ACV_INC_PATHS=%ACV_INC_PATHS%;%SSL_DIR%\include
  )
)

set ACV_INC_PATHS=%ACV_INC_PATHS%;%ACV_ROOT_PATH%\include\acvp

msbuild ms\libacvp.sln /p:Configuration=%PROJ_CONFIG% /p:Platform=%ACVP_ARCH% /p:UseEnv=True || goto :error
goto :end

:error
  exit /b
  
:end

