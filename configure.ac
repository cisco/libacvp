#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# When to bump versions.
# Major - Bumped if an API or ABI changes, Build changes etc.
# Minor - Bumped for every release of software
# Micro - Bumped for patch releases only
# age - Represents how many revisions back of the Major/Current this library
#       supports. Each library client, Mgmt, common can be ABI compatible
#       depending on the change in the library.
#
#       Once a number gets incremented all numbers to the left get reset to zero.
# Shared objects are named library.so.Major.age.Minor by autotools
#
m4_define([libacvp_major_version], [2])
m4_define([libacvp_minor_version], [0])
m4_define([libacvp_micro_version], [0])
AC_INIT([libacvp], [libacvp_major_version.libacvp_minor_version.libacvp_micro_version], [https://github.com/cisco/libacvp/issues])

# Safety checks in case user overwritten --srcdir
SUBDIRS=src
AC_CONFIG_MACRO_DIR([m4])
m4_pattern_allow([^AM_])
m4_pattern_allow([^AC_])

# Store the auxiliary build tools (e.g., install-sh, config.sub, config.guess)
# in this dir (build-aux)
AC_CONFIG_AUX_DIR([config])

# Init automake, and specify this program use relaxed structures.
# i.e. this program doesn't follow the gnu coding standards, and doesn't have
# ChangeLog, COPYING, AUTHORS, INSTALL, README etc. files.
AM_MAINTAINER_MODE
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign])

# Check for C compiler
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR
LT_INIT
# We can add more checks in this section
AC_CANONICAL_HOST

##
# OSX doesn't need/support -z,noexecstack
# only add if running on linux
##
gcc_z_support=no
case "${host_os}" in
    linux*)
        gcc_z_support=yes
        ;;
esac

AS_IF(
    [test "$gcc_z_support" = "yes"],
    [[CFLAGS="$CFLAGS -Wl,-z,noexecstack -pthread"]])

###########################################
# Read in arguments and set internal vars #
###########################################

# Option to disable app builds
AC_ARG_ENABLE([app],
[AS_HELP_STRING([--disable-app], [To build library only and not app code])],
[disable_app="yes"],
[disable_app="no"])
AM_CONDITIONAL([APP_NOT_SUPPORTED], [test "x$disable_app" == "xyes"])

# Option to disable library builds (app only)
AC_ARG_ENABLE([lib],
[AS_HELP_STRING([--disable-lib], [To build acvp_app only without library])],
[disable_lib="yes"],
[disable_lib="no"])
AM_CONDITIONAL([LIB_NOT_SUPPORTED], [test "x$disable_lib" == "xyes"])

# libacvp library installation dir - only used when building just the app
if test "x$disable_lib" = "xyes" ; then
    AC_ARG_WITH([libacvp-dir],
        [AS_HELP_STRING([--with-libacvp-dir],
        [Path to libacvp install directory, for use when building the app only])],
        [libacvpdir="$withval"],
        [with_libacvpdir=no])
fi

# SSL and FOM dirs only used if building app too 
if test "x$disable_app" = "xno" ; then
    # ssl installation directory path
    AC_ARG_WITH([ssl-dir],
        [AS_HELP_STRING([--with-ssl-dir],
        [location of OpenSSL install folder, defaults to /usr/local/ssl])],
        [ssldir="$withval"],
        [ssldir="/usr/local/ssl"])
    # FOM installation directory path
    AC_ARG_WITH([fom-dir],
        [AS_HELP_STRING([--with-fom-dir],
        [Path to FOM install directory])],
        [fomdir="$withval"],
        [with_fomdir=no])
    # If using SSL >= 3.0.0, FIPS is mananged at runtime
fi

# Offline mode
AC_ARG_ENABLE([offline],
[AS_HELP_STRING([--enable-offline],
[Flag to indicate use of offline mode])],
[offline="$enableval"],
[enable_offline=false])
AM_CONDITIONAL([BUILDING_OFFLINE], [test "x$offline" != "x"])

#Link dependencies statically where possible
AC_ARG_ENABLE([force-static-linking],
[AS_HELP_STRING([--enable-force-static-linking],
[Flag to try and force all needed libraries to link statically])],
[static="true"],
[static="false"])
AM_CONDITIONAL([FORCE_STATIC], [test "x$static" == "xtrue"])

# Libcurl/murl installation path. Check for Curl first, use murl if no curl
if test "x$enable_offline" = "xfalse" && test "x$disable_lib" != "xyes" ; then
    AC_ARG_WITH([libcurl-dir],
        [AS_HELP_STRING([--with-libcurl-dir],
        [enable support for client proxy using libcurl])],
        [libcurldir="$withval"],
        [with_libcurldir=no])

    if test "x$libcurldir" = "x" && test "x$offline" = "xfalse" ; then
        AC_MSG_FAILURE([libcurl or libmurl directory must be set if building library for online use])
    fi
fi

# Use much more strict compile flags
AC_ARG_ENABLE([cflags],
[AS_HELP_STRING([--enable-cflags],
[Flag to indicate use of enhanced CFLAGS])],
[cflags="$enableval"],
[enable_cflags=false])

# Gcoverage
AC_ARG_ENABLE([gcov],
[AS_HELP_STRING([--enable-gcov],
[Flag to indicate use of gcov tool])],
[gcov="$enableval"],
[enable_gcov=false])

# Unit testing
AC_ARG_WITH([criterion-dir],
    [AS_HELP_STRING([--with-criterion-dir],
    [location of Criterion install folder])],
    [criteriondir="$withval"],
    [with_criteriondir="no"])

# Disable check for library presence during configure stage
AC_MSG_CHECKING([disable lib check])
AC_ARG_ENABLE(lib-check,
    [AS_HELP_STRING([--disable-lib-check],[Disables checking for presence of libraries during configure. This is ONLY recommended if you have issues with detection and you know the library exists])],
    [disable_lib_detection="yes"],
    [disable_lib_detection="no"])
if test "x$disable_lib_detection" = "xyes"; then
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi

# Disable SSP, in case a platform does not support it
AC_MSG_CHECKING([disable ssp])
AC_ARG_ENABLE(ssp,
    [AS_HELP_STRING([--disable-ssp],[Turn off fstack-protector cflag; not all platforms support])],
    [disable_ssp="yes"],
    [disable_ssp="no"])
if test "x$disable_ssp" = "xyes"; then
    AC_MSG_RESULT(yes)
else
    CFLAGS="$CFLAGS -fstack-protector-all"
    AC_MSG_RESULT(no)
fi

# Enable a wrapper to turn acvp_app into a small library (Only for static offline builds)
AC_ARG_ENABLE([wrapper-library],
[AS_HELP_STRING([--enable-wrapper-library],
[Designed for use with offline builds, turns acvp_app into a single API library for processing offline tests])],
[wraplib="$enableval"],
[wrap_lib=false])

########################################################################################
# End reading arguments. Begin testing presence of libs and setting certain make vars. #
########################################################################################

##
# Set the CFLAGS
##
CFLAGS="$CFLAGS -Wall -D_FORTIFY_SOURCE=2"

# Hold onto the LIBS variable before AC_SEARCH_LIBS modifies it
pre_libs="$LIBS"
# script modifies LDFLAGS to correctly search for libs. we unset these changes so
# makefile.am have complete control over linker flags
pre_ldflags="$LDFLAGS"
found_crypto="false"
found_ssl="false"
ssl_lib64="false"

if test "x$disable_lib_detection" = "xno"; then
    # Be more lenient in library detection stage
    LDFLAGS=" -Wl,--allow-multiple-definition $LDFLAGS"

    lib_dependencies=""
    # OpenSSL can depend on libdl; Curl can depend on libz. Check if these are present
    # and add them to LIBS if so.
    AC_SEARCH_LIBS([dlopen], [dl], [lib_dependencies+="-ldl "], [], [])
    AC_SEARCH_LIBS([gzdopen], [z], [lib_dependencies+="-lz "], [], [])
    AC_SUBST([ADDL_LIB_DEPENDENCIES], "$lib_dependencies")

    # Check what version of SSL is being linked. Determines how any FIPS stuff is handled, and what APIs are used in some places
    proj_temp_cppflags="$CPPFLAGS"
    CPPFLAGS="-I$ssldir/include"
    AC_CHECK_HEADER([openssl/opensslv.h], [], [AC_MSG_FAILURE([Unable to read opensslslv.h to determine SSL library version])])
    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([[
            #include <openssl/opensslv.h>
            #if OPENSSL_VERSION_NUMBER >= 0x30000000L
            #error "Detected OpenSSL version 3.0.0 or greater"
            #endif
        ]])],
        [use_ssl_3="false"],
        [use_ssl_3="true"])
    CPPFLAGS="$proj_temp_cppflags"

    # Search for SSL and Crypto libs, and if it doesn't fail set the make vars accordingly
    if test "x$disable_app" = "xno" ; then
        LDFLAGS="$LDFLAGS -L$ssldir/lib"
        AC_SEARCH_LIBS([EVP_EncryptInit], [crypto], [found_crypto="true"], [
            LDFLAGS="$LDFLAGS -L$ssldir/lib64"
            unset ac_cv_search_EVP_EncryptInit # This value gets referenced as a cache so needs unsetting
            AC_SEARCH_LIBS([EVP_EncryptInit], [crypto], [found_crypto="true" && ssl_lib64="true"], 
                           [AC_MSG_FAILURE([Cannot locate libcrypto])], ["$lib_dependencies"])],
        [])

        AC_SEARCH_LIBS([SSL_CTX_new], [ssl], [],
                    [AC_MSG_FAILURE([Cannot locate libssl])], ["$lib_dependencies"])
    fi

    if test "x$disable_lib" = "xyes" ; then
        if test "x$libacvpdir" != "x" ; then
            LDFLAGS="$LDFLAGS -L$libalibcvpdir/lib"
        else
            LDFLAGS="$LDFLAGS -Lsrc/.libs"
        fi
        AC_CHECK_LIB([acvp], [acvp_create_test_session], [],
                [AC_MSG_FAILURE([Cannot find libacvp library])], [])
    fi

    # Check for curl
    if test "x$libcurldir" != "x" ; then
        LDFLAGS="$LDFLAGS -L$libcurldir/lib"
        AC_CHECK_LIB([curl], [curl_easy_init], [],
            [AC_MSG_FAILURE(Curl not found in provided curl dir)], ["$lib_dependencies"])
    fi

else
    #assume we are using openssl < 3 if lib check is disabled
    use_ssl_3="false"
fi
#SSL versions < 3 use --with-fom-dir for FIPS. Versions >= 3 use --enable-fips or --enable-runtime-fips
if test "x$use_ssl_3" = "xtrue" && test "x$with_fomdir" != "xno" ; then
    AC_MSG_FAILURE([--with-fom-dir should not be provided with versions of SSL greater than 1.1.1;
                    use --enable-fips or --enable-runtime-fips instead])
fi

if test "x$disable_app" = "xno" ; then
    AC_SUBST([SSL_CFLAGS], "-I$ssldir/include")
    if test "x$ssl_lib64" = "xtrue" ; then
        AC_SUBST([SSL_LDFLAGS], "-L$ssldir/lib64 -lcrypto")
    else
        AC_SUBST([SSL_LDFLAGS], "-L$ssldir/lib -lcrypto")
    fi
    AC_ARG_VAR(FOM_OBJ_DIR, "directory with fipscanister.o")
fi
if test "x$libcurldir" != "x" ; then
    AC_SUBST([LIBCURL_CFLAGS], "-I$libcurldir/include")
    AC_SUBST([LIBCURL_LDFLAGS], "-L$libcurldir/lib -lcurl")
elif test "x$usemurl" != "x" ; then
    AC_SUBST([LIBCURL_CFLAGS], "-I$libmurldir/include")
    AC_SUBST([LIBCURL_LDFLAGS], "-L$libmurldir/lib -lcurl")
fi

#########################################################################
# Done checking for existance of libs. Set other appropriate make vars. #
#########################################################################
LDFLAGS="$pre_ldflags"
LIBS="$pre_libs"

#Set any applicable FIPS flags
if test "x$with_fomdir" != "xno" ; then
    AC_SUBST([FOM_CFLAGS], "-DACVP_NO_RUNTIME -DOPENSSL_FIPS -I$fomdir/include")
    AC_SUBST([FOM_LDFLAGS], "-L$fomdir/lib")
    AC_SUBST([FOM_OBJ_DIR], "$fomdir/lib")
fi
AM_CONDITIONAL([USE_FOM_OBJ], [test "x$with_fomdir" != "xno"])

# If given a libacvp_dir, use that when building things dependent on library, otherwise, use defaults
if test "x$libacvpdir" != "x" ; then
    AC_SUBST([LIBACVP_LDFLAGS], ["-L$libacvpdir/lib -lacvp"])
    AC_SUBST([LIBACVP_CFLAGS], ["-I$libacvpdir/include"])
else
    AC_SUBST([LIBACVP_LDFLAGS], ["-L../src/.libs -lacvp"])
    AC_SUBST([LIBACVP_CFLAGS], ["-I../include"])
fi

if test "x$enable_cflags" != "xfalse" ; then
    CFLAGS="$CFLAGS -Wcast-align -Wchar-subscripts -Wcomment -Wdeprecated-declarations -Wdisabled-optimization -Wdiv-by-zero -Wendif-labels  -Wformat -Wformat-extra-args  -Wformat-security -Wformat-y2k -Wimplicit -Wimplicit-function-declaration -Wimplicit-int -Wimport -Winvalid-pch -Wmain -Wmissing-braces  -Wmissing-format-attribute -Wmissing-noreturn  -Wmultichar -Wnested-externs -Wnonnull -Wparentheses -Wpointer-arith -Wreturn-type -Wsequence-point -Wshadow -Wsign-compare -Wstrict-aliasing -Wstrict-prototypes -Wswitch -Wswitch-default -Wtrigraphs  -Wunknown-pragmas -Wunused -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -Wwrite-strings -Wno-pointer-sign  -Wcast-qual -Wfloat-equal  -Wuninitialized -Winline -Wno-error=cast-align -Wbad-function-cast  -Wswitch-enum -Wsystem-headers -Wunused-but-set-variable -Wextra"
fi

if test "x$enable_gcov" != "xfalse" ; then
    CFLAGS="$CFLAGS --coverage"
    LDFLAGS="$LDFLAGS -lgcov"
fi

if test "x$enable_gcov" != "xfalse" ; then
  CLEANFILES="app/*.gcda app/*.gcno src/*.gcda src/*.gcno test/*.gcda test/*.gcno safe_c_stub/src/*.gcno"
  AC_SUBST(CLEANFILES)
fi

if test "x$with_criterion" != "xno" ; then
    AC_SUBST([CRITERION_CFLAGS], "-I$criteriondir/include")
    AC_SUBST([CRITERION_LDFLAGS], "-L$criteriondir/lib -lcriterion")
fi

AM_CONDITIONAL([UNIT_TEST_SUPPORTED], [test "x$with_criteriondir" != "xno"])

AM_CONDITIONAL([BUILD_APP_AS_LIB], [test "x$wrap_lib" != "xfalse"])

##
# SafeC Stub
##
SAFEC_STUB_DIR='$(abs_top_builddir)/safe_c_stub'
AC_SUBST(SAFEC_STUB_DIR)
safecdir="$SAFEC_STUB_DIR"
AC_SUBST([SAFEC_CFLAGS], "-I$safecdir/include")
AC_SUBST([SAFEC_LDFLAGS], "$safecdir/lib/libsafe_lib.la")

#At the end, SUBST any conditional algorithm cflags we have acquired
AC_SUBST([COND_ALG_CFLAGS], "$cond_alg_cflags")

# Default installation directory
AC_PREFIX_DEFAULT([/usr/local/acvp])

cp confdefs.h acvp_config.h

AC_CONFIG_FILES([Makefile safe_c_stub/Makefile safe_c_stub/lib/Makefile src/Makefile app/Makefile test/Makefile])
AC_OUTPUT

