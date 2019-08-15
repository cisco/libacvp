noinst_PROGRAMS = runtest
runtest_SOURCES = ut_common.c \
      create_session.c \
      test_acvp_utils.c \
      test_acvp_drbg.c \
      test_acvp_dsa.c \
      test_acvp_hmac.c \
      test_acvp_kdf135_ssh.c \
      test_acvp_kdf135_snmp.c \
      test_acvp_kdf135_x963.c \
      test_acvp_kdf135_tls.c \
      test_acvp_kdf135_srtp.c \
      test_acvp_kdf135_ikev2.c \
      test_acvp_kdf135_ikev1.c \
      test_acvp_kdf108.c \
      test_acvp_rsa_keygen.c \
      test_acvp_cmac.c \
      test_acvp_des.c \
      test_acvp_rsa_sig.c \
      test_acvp_capabilities.c \
      test_acvp_hash.c \
      test_acvp_build_register.c \
      test_acvp_aes.c \
      test_acvp.c \
      test_acvp_transport.c \
      test_acvp_operating_env.c \
      test_acvp_ecdsa.c \
      test_acvp_kas_ecc.c \
      test_acvp_kas_ffc.c \
      test_app_cmac.c \
      test_app_ecdsa.c \
      test_app_hmac.c \
      test_app_kas_ecc.c \
      test_app_kas_ffc.c \
      test_app_rsa_keygen.c \
      test_app_rsa_sig.c \
      test_app_sha.c

APP_LINK = ../app/acvp_app-app_sha.o \
           ../app/acvp_app-app_hmac.o \
           ../app/acvp_app-app_aes.o \
           ../app/acvp_app-app_des.o \
           ../app/acvp_app-app_cmac.o \
           ../app/acvp_app-app_kdf.o \
           ../app/acvp_app-app_dsa.o \
           ../app/acvp_app-app_kas.o \
           ../app/acvp_app-app_rsa.o \
           ../app/acvp_app-app_ecdsa.o \
           ../app/acvp_app-app_drbg.o

runtest_CFLAGS = -g -O0 -Wall -DNO_SSL_DL -I$(top_srcdir)/include -I$(top_srcdir)/include/acvp -I$(top_srcdir)/app \
                 $(SSL_CFLAGS) $(FOM_CFLAGS) $(SAFEC_CFLAGS) $(LIBCURL_CFLAGS) $(CRITERION_CFLAGS)
runtest_LDFLAGS = -L../src/.libs -ldl -lacvp \
                  $(SSL_LDFLAGS) $(LIBCURL_LDFLAGS) $(CRITERION_LDFLAGS) $(FOM_LDFLAGS)
runtest_LDADD = $(APP_LINK)
if USE_FOM
runtest_LDADD += $(FOM_OBJ_DIR)/fipscanister.o
endif
runtestdir=
runtest_HEADERS = ut_common.h
