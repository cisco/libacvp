tmp_sources = app_main.c \
              app_cli.c \
              app_utils.c \
              app_lcl.h \
              totp/totp.c \
              totp/hmac_sha256.c \
              totp/sha256.c \
              totp/hmac_sha256.h \
              totp/sha256.h \
              ketopt.h

if APP_IUT_OPENSSL_3
tmp_sources += implementations/openssl/3/iut.c \
               implementations/openssl/3/iut.h \
               implementations/openssl/3/iut_utils.c \
               implementations/openssl/3/registrations/fp_30X.c \
               implementations/openssl/3/registrations/fp_312.c \
               implementations/openssl/3/registrations/non_fips.c \
               implementations/openssl/3/registrations/fp_340.c \
               implementations/openssl/3/registrations/fp_350.c \
               implementations/openssl/3/iut_aes.c \
               implementations/openssl/3/iut_cmac.c \
               implementations/openssl/3/iut_des.c \
               implementations/openssl/3/iut_drbg.c \
               implementations/openssl/3/iut_dsa.c \
               implementations/openssl/3/iut_ecdsa.c \
               implementations/openssl/3/iut_eddsa.c \
               implementations/openssl/3/iut_hmac.c \
               implementations/openssl/3/iut_kas.c \
               implementations/openssl/3/iut_kdf.c \
               implementations/openssl/3/iut_kda.c \
               implementations/openssl/3/iut_kmac.c \
               implementations/openssl/3/iut_rsa.c \
               implementations/openssl/3/iut_hash.c \
               implementations/openssl/3/iut_ml_dsa.c \
               implementations/openssl/3/iut_ml_kem.c
endif

if APP_IUT_JENT
tmp_sources += implementations/jitter_entropy/iut.c
endif

if APP_IUT_LIBOQS
tmp_sources += implementations/liboqs/iut.c \
               implementations/liboqs/iut.h \
               implementations/liboqs/iut_ml_kem.c \
               implementations/liboqs/iut_ml_dsa.c
endif

if !BUILD_APP_AS_LIB
bin_PROGRAMS = acvp_app

acvp_app_includedir=$(includedir)/acvp
acvp_app_SOURCES = ${tmp_sources}
acvp_app_CFLAGS = -g -fPIE $(LIBACVP_CFLAGS) $(IUT_CFLAGS) $(SAFEC_CFLAGS) $(COND_ALG_CFLAGS)
acvp_app_LDFLAGS = $(LIBACVP_LDFLAGS) $(IUT_LDFLAGS)
acvp_app_LDADD = $(ADDL_LIB_DEPENDENCIES)

if FORCE_STATIC
acvp_app_LDFLAGS += -all-static
endif

if ! BUILDING_OFFLINE
acvp_app_LDFLAGS += $(LIBCURL_LDFLAGS)
acvp_app_CFLAGS += $(LIBCURL_CFLAGS)
endif

else
lib_LTLIBRARIES = libacvp_app.la
libacvp_app_includedir=${includedir}/acvp
libacvp_app_la_SOURCES = ${tmp_sources}

AM_CFLAGS = -g -fPIE $(LIBACVP_CFLAGS) $(IUT_CFLAGS) $(SAFEC_CFLAGS) $(COND_ALG_CFLAGS) -DACVP_APP_LIB_WRAPPER
libacvp_app_la_LIBADD = $(LIBACVP_LDFLAGS) $(IUT_LDFLAGS)

libacvp_app_include_HEADERS = $(top_srcdir)/app/libacvp_app.h

endif
