@echo off

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
      set ACV_LIBPATH=%SSL_DIR%\lib
	  set ACV_INCLUDE=%SSL_DIR%\include
	)
  ) ELSE (
    set ACV_LIBPATH=%LIBCURL_DIR%\lib
   	set ACV_INCLUDE=%LIBCURL_DIR%\include
  )
)

if %DISABLE_SAFEC%==TRUE (
  set PROJ_CONFIG=%PROJ_CONFIG%_no_safec
  set ACV_INCLUDE=%ACV_INCLUDE%;%cd%\safe_c_stub\include
) ELSE (
  set ACV_LIBPATH=%ACV_LIBPATH%;%SAFEC_DIR%
  set ACV_INCLUDE=%ACV_INCLUDE%;%SAFEC_DIR%\include
  
)

if [%LIBCURL_DIR%]==[] (
  PROJ_CONFIG=%PROJ_CONFIG%_murl
)

set ACV_INCLUDE=%ACV_INCLUDE%;%cd%\include\acvp

set INCLUDE=%ACV_INCLUDE%;%INCLUDE%
set LIB=%ACV_LIBPATH%;%LIB%

msbuild ms\libacvp.sln /p:Configuration=%PROJ_CONFIG% /p:Platform=%ACVP_ARCH% /p:UseEnv=True