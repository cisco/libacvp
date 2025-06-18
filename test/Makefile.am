noinst_PROGRAMS = runtest
runtest_SOURCES = ut_common.c
tmp_cflags = -g -O0 -Wall -DNO_SSL_DL $(SAFEC_CFLAGS) $(CRITERION_CFLAGS) $(LIBACVP_CFLAGS) -I../include
tmp_ldflags= $(CRITERION_LDFLAGS) $(SAFEC_LDFLAGS) $(LIBACVP_LDFLAGS)

if ! LIB_NOT_SUPPORTED
runtest_SOURCES += create_session.c \
      test_acvp_utils.c \
      test_acvp_drbg.c \
      test_acvp_dsa.c \
      test_acvp_hmac.c \
      test_acvp_kdf135_ssh.c \
      test_acvp_kdf135_snmp.c \
      test_acvp_kdf135_x963.c \
      test_acvp_kdf135_srtp.c \
      test_acvp_kdf135_ikev2.c \
      test_acvp_kdf135_ikev1.c \
      test_acvp_kdf108.c \
      test_acvp_pbkdf.c \
      test_acvp_kdf_tls12.c \
      test_acvp_kdf_tls13.c \
      test_acvp_rsa_keygen.c \
      test_acvp_rsa_sig.c \
      test_acvp_rsa_prim.c \
      test_acvp_cmac.c \
      test_acvp_des.c \
      test_acvp_capabilities.c \
      test_acvp_hash.c \
      test_acvp_build_register.c \
      test_acvp_aes.c \
      test_acvp.c \
      test_acvp_transport.c \
      test_acvp_operating_env.c \
      test_acvp_ecdsa.c \
      test_acvp_kas_ecc.c \
      test_acvp_kas_ifc.c \
      test_acvp_kts_ifc.c \
      test_acvp_kas_ffc.c \
      test_acvp_safe_primes.c \
      test_acvp_kda.c \
      test_acvp_kmac.c

tmp_cflags += $(LIBCURL_CFLAGS)
tmp_ldflags += $(LIBCURL_LDFLAGS)
endif

if ! APP_NOT_SUPPORTED

APP_LINK = ../app/acvp_app-app_cli.o \
           ../app/acvp_app-app_utils.o \
           ../app/totp/acvp_app-hmac_sha256.o \
           ../app/totp/acvp_app-sha256.o \
           ../app/totp/acvp_app-totp.o

runtest_SOURCES += app_common.c

if APP_IUT_OPENSSL_3
runtest_SOURCES += implementations/openssl/3/test_iut_aes.c \
                   implementations/openssl/3/test_iut_cmac.c \
                   implementations/openssl/3/test_iut_des.c \
                   implementations/openssl/3/test_iut_drbg.c \
                   implementations/openssl/3/test_iut_ecdsa.c \
                   implementations/openssl/3/test_iut_hmac.c \
                   implementations/openssl/3/test_iut_kas_ecc.c \
                   implementations/openssl/3/test_iut_kas_ffc.c \
                   implementations/openssl/3/test_iut_kas_ifc.c \
                   implementations/openssl/3/test_iut_rsa_keygen.c \
                   implementations/openssl/3/test_iut_rsa_sig.c \
                   implementations/openssl/3/test_iut_hash.c \
                   implementations/openssl/3/test_iut_safe_primes.c \
                   implementations/openssl/3/test_iut_kda.c \
                   implementations/openssl/3/test_iut_kmac.c \
                   implementations/openssl/3/test_iut_kdf_tls12.c \
                   implementations/openssl/3/test_iut_kdf_tls13.c \
                   implementations/openssl/3/test_iut_kdf108.c \
                   implementations/openssl/3/test_iut_kdf135_ssh.c \
                   implementations/openssl/3/test_iut_kts_ifc.c \
                   implementations/openssl/3/test_iut_pbkdf.c

APP_LINK += ../app/implementations/openssl/3/acvp_app-iut.o \
            ../app/implementations/openssl/3/acvp_app-iut_utils.o \
            ../app/implementations/openssl/3/registrations/acvp_app-fp_30X.o \
            ../app/implementations/openssl/3/registrations/acvp_app-fp_312.o \
            ../app/implementations/openssl/3/registrations/acvp_app-non_fips.o \
            ../app/implementations/openssl/3/acvp_app-iut_hash.o \
            ../app/implementations/openssl/3/acvp_app-iut_hmac.o \
            ../app/implementations/openssl/3/acvp_app-iut_aes.o \
            ../app/implementations/openssl/3/acvp_app-iut_des.o \
            ../app/implementations/openssl/3/acvp_app-iut_cmac.o \
            ../app/implementations/openssl/3/acvp_app-iut_kdf.o \
            ../app/implementations/openssl/3/acvp_app-iut_dsa.o \
            ../app/implementations/openssl/3/acvp_app-iut_kas.o \
            ../app/implementations/openssl/3/acvp_app-iut_rsa.o \
            ../app/implementations/openssl/3/acvp_app-iut_ecdsa.o \
            ../app/implementations/openssl/3/acvp_app-iut_drbg.o \
            ../app/implementations/openssl/3/acvp_app-iut_kda.o \
            ../app/implementations/openssl/3/acvp_app-iut_kmac.o

endif


tmp_cflags += $(IUT_CFLAGS) -I../app
tmp_ldflags += $(IUT_LDFLAGS)
endif

runtest_CFLAGS = ${tmp_cflags}
runtest_LDFLAGS = ${tmp_ldflags}

if ! APP_NOT_SUPPORTED
runtest_LDADD = $(APP_LINK) $(IUT_LIBS)
endif

runtestdir=
runtest_HEADERS = ut_common.h
if ! APP_NOT_SUPPORTED
runtest_HEADERS += app_common.h
endif

