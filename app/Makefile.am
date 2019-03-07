bin_PROGRAMS = acvp_app
acvp_app_includedir=$(includedir)/acvp
acvp_app_SOURCES = app_main.c \
				   app_aes.c \
				   app_cli.c \
				   app_cmac.c \
				   app_des.c \
				   app_drbg.c \
				   app_dsa.c \
				   app_ecdsa.c \
				   app_hmac.c \
				   app_kas.c \
				   app_kdf.c \
				   app_rsa.c \
				   app_sha.c \
				   app_utils.c \
				   app_fips_lcl.h \
				   app_fips_init_lcl.h \
				   app_lcl.h
acvp_app_CFLAGS = -g -fPIE -I$(top_srcdir)/include $(SSL_CFLAGS) $(FOM_CFLAGS) $(SAFEC_CFLAGS)
acvp_app_LDFLAGS = -L../src/.libs -ldl -lacvp $(SSL_LDFLAGS) $(FOM_LDFLAGS)
if USE_FOM
acvp_app_LDADD = $(FOM_OBJ_DIR)/fipscanister.o
endif
