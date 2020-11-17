noinst_PROGRAMS = runtest
runtest_SOURCES = ut_common.c
tmp_cflags = -g -O0 -Wall -DNO_SSL_DL -p $(SAFEC_CFLAGS) $(CRITERION_CFLAGS) $(LIBACVP_CFLAGS) -I../include
tmp_ldflags= -ldl $(CRITERION_LDFLAGS) $(SAFEC_LDFLAGS) $(LIBACVP_LDFLAGS)
if ! LIB_NOT_SUPPORTED
runtest_SOURCES += create_session.c \
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
      test_acvp_pbkdf.c \
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
      test_acvp_kas_ffc.c

tmp_cflags += $(LIBCURL_CFLAGS)
tmp_ldflags += $(LIBCURL_LDFLAGS)
endif

if ! APP_NOT_SUPPORTED
runtest_SOURCES += app_common.c \
      test_app_aes.c \
      test_app_cmac.c \
      test_app_des.c \
      test_app_ecdsa.c \
      test_app_hmac.c \
      test_app_kas_ecc.c \
      test_app_kas_ffc.c \
      test_app_kas_ifc.c \
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

tmp_cflags += $(SSL_CFLAGS) $(FOM_CFLAGS) -I../app
tmp_ldflags += $(SSL_LDFLAGS) $(FOM_LDFLAGS)
endif

runtest_CFLAGS = ${tmp_cflags}
runtest_LDFLAGS = ${tmp_ldflags}

if ! APP_NOT_SUPPORTED
runtest_LDADD = $(APP_LINK)
if USE_FOM
runtest_LDADD += $(FOM_OBJ_DIR)/fipscanister.o
endif
endif

runtestdir=
runtest_HEADERS = ut_common.h
if ! APP_NOT_SUPPORTED
runtest_HEADERS += app_common.h
endif

