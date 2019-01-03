bin_PROGRAMS = acvp_app
acvp_app_includedir=$(includedir)/acvp
acvp_app_SOURCES = app_main.c
acvp_app_CFLAGS = -g -fPIE -I../.. -I$(srcdir)/../src $(SSL_CFLAGS) $(FOM_CFLAGS) $(SAFEC_CFLAGS)
acvp_app_LDFLAGS = -L../src/.libs -ldl -lacvp $(SSL_LDFLAGS) $(FOM_LDFLAGS)
if USE_FOM
acvp_app_LDADD = $(FOM_OBJ_DIR)/fipscanister.o
endif
