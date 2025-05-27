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
m4_define([libacvp_minor_version], [2])
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
    darwin*)
        allow_multiple=no
        ;;
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

lib_dependencies=""
ssl_ver=""
iut_cflags=""
iut_ldflags=""
iut_lib_flags=""
iut_lib_name=""

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

# This var should be set to indicate the crypto library being tested with a given build of acvp_app
# This does not apply for --disable-app builds
# Set default value here, change based on args below 
# iut_lib_name should match the name of the library lib<name>. Multiple library names can be referenced using single space delimiter.
acvp_app_iut=""
iut_specified=0;
# SSL dir only used if building app too 
if test "x$disable_app" = "xno" ; then
    # ssl installation directory path
    AC_ARG_WITH([ssl-dir],
        [AS_HELP_STRING([--with-ssl-dir],
        [location of OpenSSL install folder])],
        [iut_dir="$withval"; iut_specified=$((iut_specified+1)); acvp_app_iut="openssl"; iut_lib_name="ssl crypto"; use_strict_linking="yes"],
        [])

    AC_ARG_WITH([jent-dir],
        [AS_HELP_STRING([--with-jent-dir],
        [Path to JENT install directory])],
        [iut_dir="$withval"; iut_specified=$((iut_specified+1)); acvp_app_iut="jent"; iut_lib_name="jitterentropy"; use_strict_linking="yes"],
        [])

    AC_ARG_WITH([liboqs-dir],
        [AS_HELP_STRING([--with-liboqs-dir],
        [Path to liboqs install directory])],
        [iut_dir="$withval"; iut_specified=$((iut_specified+1)); acvp_app_iut="liboqs"; iut_lib_name="oqs"; use_strict_linking="yes"],
        [])

    if test $iut_specified -gt 1 ; then
        AC_MSG_FAILURE([Multiple testable implementations provided. Please only provide a path to one testable implementation])
    fi

    if test $iut_specified -eq 0 ; then
            AC_MSG_FAILURE([At least one testable implementation path must be provided or use --disable-app])
    fi
fi

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

if test "x$disable_lib_detection" = "xno"; then
    proj_temp_cppflags="$CPPFLAGS"

    # Be more lenient in library detection stage
    if test "x$allow_multiple" != "xno"; then
        LDFLAGS=" -Wl,--allow-multiple-definition $LDFLAGS"
    fi

    if test "x$enable_offline" != "xfalse"; then
        AC_SEARCH_LIBS([gzdopen], [z], [lib_dependencies="${lib_dependencies} -lz "], [], [])
    fi

    if test "x$disable_app" = "xno" ; then
        ##########################################################
        # Begin checks for IUT. Only one of these should be done #
        ##########################################################

        # Note about linking behavior for IUTs:
        # By default, compiler/linker tends to look in its preset system directories for libraries if it cannot find libraries
        # In the path we have provided. In the case of IUT testing, we definitely do not want this. We ONLY want to link to a
        # IUT in a user provided path, so we don't accidentally link to and test a system library. There really is not a great
        # mechanism to exclude grabbing specific libraries from the system paths; you can exclude all system dirs, but then the
        # project does not know how to link to the system level dependencies like libc or even crt0. The best approach is seemingly
        # to point the linker to the EXACT path and name of the library you want. However, we often still want to automatically
        # detect and switch between static or shared libraries (check for shared, if none, use static). That is logic we have to
        # handle ourselves.

        if test "x$use_strict_linking" = "xyes"; then
            # Iterate over each library in iut_lib_name. set IFS to a space; use IFS to parse the words. Hopefully is portable enough.
            tmp_ifs="$IFS"
            IFS=" "
            for lib in $iut_lib_name; do
                AC_MSG_CHECKING(for presence of lib${lib} in lib/lib64 dirs)
                # Check for shared libraries in lib64, then lib. If no match, check for static libraries in either dir.
                if test -f "$iut_dir/lib64/lib${lib}.so"; then
                    iut_lib_flags="${iut_lib_flags} $iut_dir/lib64/lib${lib}.so "
                elif test -f "$iut_dir/lib64/lib${lib}.dylib"; then
                    iut_lib_flags="${iut_lib_flags} $iut_dir/lib64/lib${lib}.dylib "
                elif test -f "$iut_dir/lib/lib${lib}.so"; then
                    iut_lib_flags="${iut_lib_flags} $iut_dir/lib/lib${lib}.so "
                elif test -f "$iut_dir/lib/lib${lib}.dylib"; then
                    iut_lib_flags="${iut_lib_flags} $iut_dir/lib/lib${lib}.dylib "
                elif test -f "$iut_dir/lib64/lib${lib}.a"; then
                    iut_lib_flags="${iut_lib_flags} $iut_dir/lib64/lib${lib}.a "
                elif test -f "$iut_dir/lib/lib${lib}.a"; then
                    iut_lib_flags="${iut_lib_flags} $iut_dir/lib/lib${lib}.a "
                else
                    AC_MSG_FAILURE([Cannot locate lib${lib} in $iut_dir/lib64 or $iut_dir/lib])
                fi
                AC_MSG_RESULT(yes)
            done
            IFS="$tmp_ifs"
            tmp_cflags="$CFLAGS"
            CFLAGS="$CFLAGS -I$iut_dir/include"
            LIBS="${iut_lib_flags} $LIBS"
        fi

        if test "x$acvp_app_iut" = "xopenssl"; then
            AC_SEARCH_LIBS([dlopen], [dl], [lib_dependencies="${lib_dependencies} -ldl "], [], [])

            AC_COMPILE_IFELSE(
                [AC_LANG_PROGRAM([[
                    #include <$iut_dir/include/openssl/opensslv.h>
                    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
                    #error "Detected OpenSSL version 3.0.0 or greater"
                    #endif
                ]])],
                [AC_MSG_FAILURE([OpenSSL versions under 3 not currently supported])],
                [ssl_ver="3"])

            # Attempt to link to IUT. We don't use AC_SEARCH_LIBS or CHECK_LIB here since we need to control search paths
            AC_MSG_CHECKING(for link to libcrypto)
            AC_LINK_IFELSE(
                [AC_LANG_PROGRAM([
                    #include <openssl/evp.h>
                ], [OpenSSL_version(0);])],
                [AC_MSG_RESULT(yes)],[AC_MSG_FAILURE([Cannot link to given libcrypto])]
            )
            AC_MSG_CHECKING(for link to libssl)
            AC_LINK_IFELSE(
                [AC_LANG_PROGRAM([
                    #include <openssl/ssl.h>
                ], [SSL_CTX_get0_param(NULL);])],
                [AC_MSG_RESULT(yes)],[AC_MSG_FAILURE([Cannot link to given libssl])]
            )

        elif test "x$acvp_app_iut" = "xjent"; then

            AC_MSG_CHECKING(for link to jitterentropy)
            AC_LINK_IFELSE(
                [AC_LANG_PROGRAM([
                    #include <jitterentropy.h>
                ], [jent_entropy_init();])],
                [AC_MSG_RESULT(yes)],[AC_MSG_FAILURE([Cannot link to given liboqs])]
            )

        elif test "x$acvp_app_iut" = "xliboqs"; then
            AC_MSG_CHECKING(for link to liboqs)
            AC_LINK_IFELSE(
                [AC_LANG_PROGRAM([
                    #include <oqs/common.h>
                ], [OQS_version();])],
                [AC_MSG_RESULT(yes)],[AC_MSG_FAILURE([Cannot link to given liboqs])]
            )
        fi
        ######################
        # End checks for IUT #
        ######################
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
        CPPFLAGS="$CPPFLAGS -I$libcurldir/include"
        AC_CHECK_LIB([curl], [curl_easy_init], [],
            [AC_MSG_FAILURE(Curl not found in provided curl dir)], ["$lib_dependencies"])
    fi

    # Reset the flags variables to what they were before checking for libs, we want to manage these
    CPPFLAGS="$proj_temp_cppflags"
    LDFLAGS="$pre_ldflags"
    LIBS="$pre_libs"
    if test "x$use_strict_linking" = "xyes"; then
        CFLAGS="$tmp_cflags"
    fi
else
    #assume we are using openssl 3.X if lib check is disabled
    if test "x$acvp_app_iut" = "xopenssl"; then
        acvp_app_iut="openssl"
        ssl_ver="3"
    fi
fi

# Regenerate the IUT name if using SSL, appending the version
if test "x$acvp_app_iut" = "xopenssl"; then
    acvp_app_iut="$acvp_app_iut"_"$ssl_ver"
fi

#########################################################################
# Done checking for existance of libs. Set other appropriate make vars. #
#########################################################################

if test "x$disable_app" = "xno" ; then
    # Set any IUT specific flags not captured previously

    # Set flags needed for all IUTs
    iut_cflags="-I$iut_dir/include"

    if test "x$use_strict_linking" != "xyes"; then
        iut_ldflags="$iut_ldflags -L$iut_dir/lib"
    fi

    # Send the flags off to the automake files
    AC_SUBST([IUT_CFLAGS], "$iut_cflags")
    AC_SUBST([IUT_LDFLAGS], "$iut_ldflags")
    AC_SUBST([IUT_LIBS], "$iut_lib_flags")
fi

# Tell the automake files which IUT we are using. Only one of these should ever be enabled.
# NOTE: These must called here even if not building the app for the sake of autoconf sanity
#       AM_CONDITIONAL should never be...conditionally called
AM_CONDITIONAL([APP_IUT_JENT], [test "x$acvp_app_iut" = "xjent"])
AM_CONDITIONAL([APP_IUT_OPENSSL_1], [test "x$acvp_app_iut" = "xopenssl_1"])
AM_CONDITIONAL([APP_IUT_OPENSSL_3], [test "x$acvp_app_iut" = "xopenssl_3"])
AM_CONDITIONAL([APP_IUT_LIBOQS], [test "x$acvp_app_iut" = "xliboqs"])

# Set the flags needed for curl/murl library
if test "x$libcurldir" != "x" ; then
    AC_SUBST([LIBCURL_CFLAGS], "-I$libcurldir/include")
    AC_SUBST([LIBCURL_LDFLAGS], "-L$libcurldir/lib -lcurl")
elif test "x$usemurl" != "x" ; then
    AC_SUBST([LIBCURL_CFLAGS], "-I$libmurldir/include")
    AC_SUBST([LIBCURL_LDFLAGS], "-L$libmurldir/lib -lcurl")
fi

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

AC_SUBST([SELECTED_IUT], "$acvp_app_iut")
AC_SUBST([ADDL_LIB_DEPENDENCIES], "$lib_dependencies")

#At the end, SUBST any conditional algorithm cflags we have acquired
AC_SUBST([COND_ALG_CFLAGS], "$cond_alg_cflags")

# Default installation directory
AC_PREFIX_DEFAULT([/usr/local/acvp])

cp confdefs.h acvp_config.h

AC_CONFIG_FILES([Makefile safe_c_stub/Makefile safe_c_stub/lib/Makefile src/Makefile app/Makefile test/Makefile])
AC_OUTPUT

