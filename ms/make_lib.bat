@echo off

set ACV_INC_PATHS=
set ACV_LIB_PATHS=

rem Visual Studio wants absolute paths in some cases
set ACV_ROOT_PATH_REL=%~dp0..\
for %%i in ("%ACV_ROOT_PATH_REL%") do SET "ACV_ROOT_PATH=%%~fi

if %STATIC_BUILD%==TRUE (
  set PROJ_CONFIG=static
) ELSE (
  set PROJ_CONFIG=shared
)

if %OFFLINE_BUILD%==TRUE (
  set PROJ_CONFIG=%PROJ_CONFIG%_offline
) ELSE (
  if [%LIBCURL_DIR%]==[] (
    echo "curl dir not specified - attempting to use murl and link to ssl..."
	if [%SSL_DIR%]==[] (
	  echo "No SSL dir specified. Curl directory, or SSL dir if using Murl, must be specified. exiting..."
      exit 1
	) ELSE (
      set ACV_LIB_PATHS=%SSL_DIR%\lib
	  set ACV_INC_PATHS=%SSL_DIR%\include
	)
  ) ELSE (
    set ACV_LIB_PATHS=%LIBCURL_DIR%\lib
   	set ACV_INC_PATHS=%LIBCURL_DIR%\include
  )
)

if [%SAFEC_DIR%]==[] (
  set PROJ_CONFIG=%PROJ_CONFIG%_no_safec
  set ACV_INC_PATHS=%ACV_INC_PATHS%;%ACV_ROOT_PATH%\safe_c_stub\include
) ELSE (
  set ACV_LIB_PATHS=%ACV_LIB_PATHS%;%SAFEC_DIR%
  set ACV_INC_PATHS=%ACV_INC_PATHS%;%SAFEC_DIR%\include
  
)

if [%LIBCURL_DIR%]==[] (
  set PROJ_CONFIG=%PROJ_CONFIG%_murl
  set ACV_INC_PATHS=%ACV_INC_PATHS%;%ACV_ROOT_PATH%\murl
)

set ACV_INC_PATHS=%ACV_INC_PATHS%;%ACV_ROOT_PATH%\include\acvp

msbuild ms\libacvp.sln /p:Configuration=%PROJ_CONFIG% /p:Platform=%ACVP_ARCH% /p:UseEnv=True