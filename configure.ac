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
m4_define([libacvp_major_version], [1])
m4_define([libacvp_minor_version], [0])
m4_define([libacvp_micro_version], [4])
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
# Set the CFLAGS
##
CFLAGS="$CFLAGS -Wall -fstack-protector-all -D_FORTIFY_SOURCE=2"

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
    [[CFLAGS="$CFLAGS -Wl,-z,noexecstack"]])

##
# Option to disable app builds
##
AC_ARG_ENABLE([app],
[AS_HELP_STRING([--disable-app], [To build library only and not app code])],
[disable_app="yes"],
[disable_app="no"])
AM_CONDITIONAL([APP_NOT_SUPPORTED], [test "x$disable_app" == "xyes"])

##
# Option to disable library builds (app only)
##
AC_ARG_ENABLE([lib],
[AS_HELP_STRING([--disable-lib], [To build acvp_app only without library])],
[disable_lib="yes"],
[disable_lib="no"])
AM_CONDITIONAL([LIB_NOT_SUPPORTED], [test "x$disable_lib" == "xyes"])


if test "x$disable_app" = "xno" ; then
##
# OpenSSL variables
##
AC_ARG_WITH([ssl-dir],
	    [AS_HELP_STRING([--with-ssl-dir],
		[location of OpenSSL install folder, defaults to /usr/local/ssl])],
	    [ssldir="$withval"],
	    [ssldir="/usr/local/ssl"])

AC_SUBST([SSL_CFLAGS], "-I$ssldir/include")
AC_SUBST([SSL_LDFLAGS], "-L$ssldir/lib -lssl -lcrypto")
LDFLAGS="$LDFLAGS -L$ssldir/lib"


# Hold onto the LIBS variable before AC_SEARCH_LIBS modifies it
pre_libs="$LIBS"

AC_SEARCH_LIBS([EVP_EncryptInit], [crypto], [],
               [AC_MSG_FAILURE([can't find openssl crypto lib])], [])

if test "$is_freebsd" = "1" ; then
AC_SEARCH_LIBS([EVP_EncryptInit], [crypto], [],
               [AC_MSG_FAILURE([can't find openssl crypto lib])], [])
else
AC_SEARCH_LIBS([EVP_EncryptInit], [crypto], [],
               [AC_MSG_FAILURE([can't find openssl crypto lib])], [-ldl])
fi
AC_SEARCH_LIBS([SSL_CTX_new], [ssl], [],
               [AC_MSG_FAILURE([can't find openssl ssl lib])], [])

##
# FOM installation directory path
##
AC_ARG_VAR(FOM_OBJ_DIR, "directory with fipscanister.o")

AC_ARG_WITH([fom-dir],
    [AS_HELP_STRING([--with-fom-dir],
    [Path to FOM install directory])],
    [fomdir="$withval"],
    [with_fomdir=no])

fi

##
# libacvp library installation dir - only used when building just the app
##
if test "x$disable_lib" = "xyes" ; then
    AC_ARG_WITH([libacvp-dir],
        [AS_HELP_STRING([--with-libacvp-dir],
        [Path to libacvp install directory, for use when building the app only])],
        [libacvpdir="$withval"],
        [with_libacvpdir=no])
    if test "x$libacvpdir" != "x" ; then
        LDFLAGS="$LDFLAGS -L$libacvpdir/lib"
        AC_SEARCH_LIBS([acvp_create_test_session], [acvp], [],
                       [AC_MSG_FAILURE([can't find libacvp library])], [-ldl])
    else
	#Cannot test for lib here as relative paths will confused ld later on, and absolute paths make Makefile immoveable
        LDFLAGS="$LDFLAGS -L../src/.libs"
    fi
fi

# If given a libacvp_dir, use that when building things dependent on library, otherwise, use defaults
if test "x$libacvpdir" != "x" ; then
    AC_SUBST([LIBACVP_LDFLAGS], ["-L$libacvpdir/lib"])
    AC_SUBST([LIBACVP_CFLAGS], ["-I$libacvpdir/include"])
else
    AC_SUBST([LIBACVP_LDFLAGS], ["-L../src/.libs"])
    AC_SUBST([LIBACVP_CFLAGS], ["-I../include"])
fi

##
# Option to disable KDF functionality (useful for FOM without KDF support)
##
AC_ARG_ENABLE([kdf],
[AS_HELP_STRING([--disable-kdf],
[For use if using a FOM with no KDF support, such as OpenSSL 1.0.2 FOM])],
[no-kdf="$enableval"],
[disable_kdf=false])


AS_IF([test "x$with_fomdir" != xno],
      [AS_IF([test "x$disable_kdf" != "xfalse"],
          [AC_SUBST([FOM_CFLAGS], "-DACVP_NO_RUNTIME -DOPENSSL_FIPS -I$fomdir/include")],
          [AC_SUBST([FOM_CFLAGS], "-DACVP_NO_RUNTIME -DOPENSSL_FIPS -DOPENSSL_KDF_SUPPORT -I$fomdir/include")])
       AC_SUBST([FOM_LDFLAGS], "-L$fomdir/lib")
       AC_SUBST([FOM_OBJ_DIR], "$fomdir/lib")
      ]
     )
AM_CONDITIONAL([USE_FOM], [test "x$with_fomdir" != xno])

##
# Offline mode
##
AC_ARG_ENABLE([offline],
[AS_HELP_STRING([--enable-offline],
[Flag to indicate use of offline mode])],
[offline="$enableval"],
[enable_offline=false])

if test "x$disable_app" = "xno" ; then
  AC_SUBST([SSL_LDFLAGS], "-L$ssldir/lib -lcrypto")
fi

AS_IF(
 [test "x$enable_offline" != "xfalse"],
 [[CFLAGS="$CFLAGS -DACVP_OFFLINE"]
  [LDFLAGS="-static $LDFLAGS"]
  AS_IF([test "x$disable_app" = "xno"],
    [CC="$fomdir/bin/fipsld"])
 ]
)


##
# Libcurl/murl installation path. Check for Curl first, use murl if no curl
##
if test "x$enable_offline" = "xfalse" && test "x$disable_lib" = "xno" ; then
    AC_ARG_WITH([libcurl-dir],
        [AS_HELP_STRING([--with-libcurl-dir],
        [enable support for client proxy using libcurl])],
        [libcurldir="$withval"],
        [with_libcurldir=no])

    if test "x$libcurldir" != "x"; then
        AC_SUBST([LIBCURL_CFLAGS], "-I$libcurldir/include")
        AC_SUBST([LIBCURL_LDFLAGS], "-L$libcurldir/lib -lcurl")
        LDFLAGS="$LDFLAGS -L$libcurldir/lib"

        #only run this test if we are building app; otherwise configure tries to link an example executable and fails because missing dependencies
        if test "x$disable_app" = xno ; then
            AC_SEARCH_LIBS([curl_easy_init], [curl], [],
                [AC_MSG_FAILURE([test for libcurl failed - please define --with-libcurl-dir and ensure it is valid])]
            )
        fi
    else
        AC_ARG_WITH([libmurl-dir],
            [AS_HELP_STRING([--with-libmurl-dir],
            [enable support for client proxy using libmurl])],
            [libmurldir="$withval"],
            [with_libmurldir=no])

    if test "x$libmurldir" != "x"; then
            CFLAGS="$CFLAGS -I$libmurldir -DUSE_MURL"
            LDFLAGS="$LDFLAGS -L$libmurldir -lmurl"
            #only run this test if we are building app; otherwise configure tries to link an example executable and fails because missing dependencies
            if test "x$disable_app" = xno ; then
                AC_SEARCH_LIBS([curl_easy_init], [murl], [],
                    [AC_MSG_FAILURE([test for murl failed - please define ensure murl dir given is valid])]
                )
            fi
        else
            AC_MSG_FAILURE([either --with-libcurl-dir or --with-libmurl-dir must be defined and valid!])
        fi
    fi 
fi



AC_ARG_ENABLE([cflags],
[AS_HELP_STRING([--enable-cflags],
[Flag to indicate use of enhanced CFLAGS])],
[cflags="$enableval"],
[enable_cflags=false])

AS_IF(
 [test "x$enable_cflags" != "xfalse"],
 [[CFLAGS="$CFLAGS -Wcast-align -Wchar-subscripts -Wcomment -Wdeprecated-declarations -Wdisabled-optimization -Wdiv-by-zero -Wendif-labels  -Wformat -Wformat-extra-args  -Wformat-security -Wformat-y2k -Wimplicit -Wimplicit-function-declaration -Wimplicit-int -Wimport -Winvalid-pch -Wmain -Wmissing-braces  -Wmissing-format-attribute -Wmissing-noreturn  -Wmultichar -Wnested-externs -Wnonnull -Wparentheses -Wpointer-arith -Wreturn-type -Wsequence-point -Wshadow -Wsign-compare -Wstrict-aliasing -Wstrict-prototypes -Wswitch -Wswitch-default -Wtrigraphs  -Wunknown-pragmas -Wunused -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -Wwrite-strings -Wno-pointer-sign  -Wcast-qual -Wfloat-equal  -Wuninitialized -Wno-error=unreachable-code -Winline -Wno-error=cast-align -Wbad-function-cast  -Wswitch-enum -Wsystem-headers -Wunused-but-set-variable -Wextra -Wno-error=unreachable-code"]
 ]
)

##
# Gcoverage
##
AC_ARG_ENABLE([gcov],
[AS_HELP_STRING([--enable-gcov],
[Flag to indicate use of gcov tool])],
[gcov="$enableval"],
[enable_gcov=false])

AS_IF(
 [test "x$enable_gcov" != "xfalse"],
 [[CFLAGS="$CFLAGS --coverage"]
  [LDFLAGS="$LDFLAGS -lgcov"]
 ]
)

if test "x$enable_gcov" != "xfalse" ; then
  CLEANFILES="app/*.gcda app/*.gcno src/*.gcda src/*.gcno test/*.gcda test/*.gcno safe_c_stub/src/*.gcno"
  AC_SUBST(CLEANFILES)
fi

AC_ARG_WITH([criterion-dir],
        [AS_HELP_STRING([--with-criterion-dir],
        [location of Criterion install folder])],
        [criteriondir="$withval"],
        [with_criteriondir="no"])

AS_IF([test "x$with_criterion" != xno],
      [AC_SUBST([CRITERION_CFLAGS], "-I$criteriondir/include")
       AC_SUBST([CRITERION_LDFLAGS], "-L$criteriondir/lib -lcriterion")
      ]
     )
AM_CONDITIONAL([UNIT_TEST_SUPPORTED], [test "x$with_criteriondir" != "xno"])


##
# SafeC Stub
##
SAFEC_STUB_DIR='$(abs_top_builddir)/safe_c_stub'
AC_SUBST(SAFEC_STUB_DIR)
safecdir="$SAFEC_STUB_DIR"
AC_SUBST([SAFEC_CFLAGS], "-I$safecdir/include")
AC_SUBST([SAFEC_LDFLAGS], "$safecdir/lib/libsafe_lib.la")

# Reset LIBS to original
LIBS="$pre_libs"

# Default installation directory
AC_PREFIX_DEFAULT([/usr/local/acvp])

cp confdefs.h acvp_config.h

AC_CONFIG_FILES([Makefile safe_c_stub/Makefile safe_c_stub/lib/Makefile src/Makefile app/Makefile test/Makefile])
AC_OUTPUT

