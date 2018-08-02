bin_PROGRAMS = acvp_app
acvp_app_includedir=$(includedir)/acvp
acvp_app_SOURCES = app_main.c
AM_CFLAGS = -I../.. -I$(srcdir)/../src -I$(SSL_CFLAGS) -g  $(FOM_CFLAGS)
DL=-ldl
acvp_app_LDFLAGS = -L../src/.libs $(DL) -lacvp -lssl -lcrypto

