# Must init the autoconf setup
# The first parameter is project name
# second is version number
# third is bug report address
AC_INIT([libacvp], [0.5], [ccsm-support@cisco.com])

# Safety checks in case user overwritten --srcdir
SUBDIRS=src
AC_CONFIG_MACRO_DIR([m4])

# Store the auxiliary build tools (e.g., install-sh, config.sub, config.guess)
# in this dir (build-aux)
AC_CONFIG_AUX_DIR([config])

# Init automake, and specify this program use relaxed structures.
# i.e. this program doesn't follow the gnu coding standards, and doesn't have
# ChangeLog, COPYING, AUTHORS, INSTALL, README etc. files.
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign])

# Check for C compiler
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR
LT_INIT
# We can add more checks in this section

AC_ARG_WITH([ssl-dir],
	    [AS_HELP_STRING([--with-ssl-dir],
		[location of OpenSSL install folder, defaults to /usr/local/ssl])],
	    [ssldir="$withval"],
	    [ssldir="/usr/local/ssl"])
AC_SUBST([SSL_CFLAGS], "$ssldir/include")
AC_SUBST([SSL_LDFLAGS], "$ssldir/lib")

CFLAGS="$CFLAGS -Wall -I$ssldir/include"
LDFLAGS="$LDFLAGS -L$ssldir/lib"
if test "$is_freebsd" = "1" ; then
AC_CHECK_LIB([crypto], [EVP_EncryptInit], [],
             [AC_MSG_FAILURE([can't find openssl crypto lib])]
	     [])
else
AC_CHECK_LIB([crypto], [EVP_EncryptInit], [],
             [AC_MSG_FAILURE([can't find openssl crypto lib])]
	     [-ldl])
fi
AC_CHECK_LIB([ssl], [SSL_CTX_new], [],
             [AC_MSG_FAILURE([can't find openssl ssl lib])])

##
# Libcurl installation directory path
##
AC_ARG_WITH([libcurl-dir],
    [AS_HELP_STRING([--with-libcurl-dir],
    [enable support for client proxy using libcurl])],
    [libcurldir="$withval"],
    [with_libcurldir=no])

AS_IF(
     [test "x$with_libcurldir" != xno],
     [[CFLAGS="$CFLAGS -I$libcurldir/include"]
      [LDFLAGS="$LDFLAGS -L$libcurldir/lib -lcurl"]
      AC_CHECK_LIB(
           [curl],
           [curl_easy_init],
          [
            AC_DEFINE([HAVE_LIBCURL],[1],[Define if you have libcurl])
           ],
           [AC_MSG_FAILURE([--with-libcurl was given, but test for libcurl failed])]
          )
     ]
    )

##
# FOM installation directory path
##
AC_ARG_WITH([fom-dir],
    [AS_HELP_STRING([--with-fom-dir],
    [Path to FOM install directory])],
    [fomdir="$withval"],
    [with_fomdir=no])

AS_IF(
     [test "x$with_fomdir" != xno],
     [[CFLAGS="$CFLAGS -DACVP_NO_RUNTIME -DOPENSSL_FIPS -DOPENSSL_KDF_SUPPORT -I$fomdir/include"]
      [LDFLAGS="$LDFLAGS -L$fomdir/lib -lcurl"]
     ]
    )

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

SAFEC_STUB_DIR='$(abs_top_builddir)/safe_c_stub'
AC_SUBST(SAFEC_STUB_DIR)

##
# SafeC installation directory path
##
AC_ARG_WITH([safec-dir],
            [AS_HELP_STRING([--with-safec-dir],
            [location of SAFEC install folder, This is a required option. --disable-safec can be used to override])],
            [safecdir="$withval"],
            [safecdir="no"])

# Default installation directory
AC_PREFIX_DEFAULT([/usr/local/acvp])

cp confdefs.h acvp_config.h

AC_CONFIG_FILES([Makefile safe_c_stub/Makefile safe_c_stub/lib/Makefile src/Makefile app/Makefile])
AC_OUTPUT

