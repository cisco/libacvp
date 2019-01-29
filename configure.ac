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
m4_define([libacvp_major_version], [0])
m4_define([libacvp_minor_version], [5])
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
    [[CFLAGS="$CFLAGS -z,noexecstack"]])

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
# Libcurl installation directory path
##
AC_ARG_WITH([libcurl-dir],
    [AS_HELP_STRING([--with-libcurl-dir],
    [enable support for client proxy using libcurl])],
    [libcurldir="$withval"],
    [with_libcurldir=no])

AS_IF([test "x$with_libcurldir" != xno],
      [AC_SUBST([LIBCURL_CFLAGS], "-I$libcurldir/include")
       AC_SUBST([LIBCURL_LDFLAGS], "-L$libcurldir/lib -lcurl")
       LDFLAGS="$LDFLAGS -L$libcurldir/lib"
       AC_SEARCH_LIBS([curl_easy_init], [curl], [],
                      [AC_MSG_FAILURE([--with-libcurl-dir was given, but test for libcurl failed])]
       )
      ]
     )


##
# Libmurl installation directory path
##
AC_ARG_WITH([libmurl-dir],
    [AS_HELP_STRING([--with-libmurl-dir],
    [enable support for client proxy using libmurl])],
    [libmurldir="$withval"],
    [with_libmurldir=no])

AS_IF(
     [test "x$with_libmurldir" != xno],
     [[CFLAGS="$CFLAGS -I$libmurldir/include -DUSE_MURL"]
      [LDFLAGS="$LDFLAGS -L$libmurldir/lib -lmurl"]]
      )


##
# FOM installation directory path
##
AC_ARG_VAR(FOM_OBJ_DIR, "directory with fipscanister.o")

AC_ARG_WITH([fom-dir],
    [AS_HELP_STRING([--with-fom-dir],
    [Path to FOM install directory])],
    [fomdir="$withval"],
    [with_fomdir=no])

AS_IF([test "x$with_fomdir" != xno],
      [AC_SUBST([FOM_CFLAGS], "-DACVP_NO_RUNTIME -DOPENSSL_FIPS -DOPENSSL_KDF_SUPPORT -I$fomdir/include")
       AC_SUBST([FOM_LDFLAGS], "-L$fomdir/lib")
       AC_SUBST([FOM_OBJ_DIR], "$fomdir/lib")
      ]
     )
AM_CONDITIONAL([USE_FOM], [test "x$with_fomdir" != xno])


##
# Gcoverage
##
AC_ARG_WITH([gcov],
[AS_HELP_STRING([--gcov],
[flag to indicate use of coverage - true|false])],
[gcov="$withval"],
[with_gcov=no])

AS_IF(
 [test "x$with_gcov" != xno],
 [[CFLAGS="$CFLAGS --coverage"]
  [LDFLAGS="$LDFLAGS -lgcov"]
 ]
)


##
# SafeC Stub
##
SAFEC_STUB_DIR='$(abs_top_builddir)/safe_c_stub'
AC_SUBST(SAFEC_STUB_DIR)
safecdir="$SAFEC_STUB_DIR"
AC_SUBST([SAFEC_CFLAGS], "-I$safecdir/include")
AC_SUBST([SAFEC_LDFLAGS], "-L$safecdir/lib -lsafe_lib")

# Reset LIBS to original
LIBS="$pre_libs"

# Default installation directory
AC_PREFIX_DEFAULT([/usr/local/acvp])

cp confdefs.h acvp_config.h

AC_CONFIG_FILES([Makefile safe_c_stub/Makefile safe_c_stub/lib/Makefile src/Makefile app/Makefile])
AC_OUTPUT

