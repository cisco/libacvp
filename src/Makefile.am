lib_LTLIBRARIES = libacvp.la
AM_CFLAGS = -I../.. $(SAFEC_CFLAGS) $(LIBCURL_CFLAGS)
libacvp_la_SOURCES =  acvp.c \
                    acvp_build_register.c \
                    acvp_capabilities.c \
                    acvp_aes.c \
                    acvp_des.c \
                    acvp_hash.c \
                    acvp_drbg.c \
                    acvp_transport.c \
                    acvp_util.c \
                    parson.c \
                    acvp_hmac.c \
                    acvp_cmac.c \
                    acvp_rsa_keygen.c \
                    acvp_rsa_sig.c \
                    acvp_dsa.c \
                    acvp_kdf135_tls.c \
                    acvp_kdf135_snmp.c \
                    acvp_kdf135_ssh.c \
                    acvp_kdf135_srtp.c \
                    acvp_kdf135_ikev2.c \
                    acvp_kdf135_ikev1.c \
                    acvp_kdf135_x963.c \
                    acvp_kdf108.c \
                    acvp_kas_ecc.c \
                    acvp_kas_ffc.c \
                    acvp_ecdsa.c

libacvp_la_LIBADD = $(SAFEC_LDFLAGS) $(LIBCURL_LDFLAGS)
library_includedir=$(includedir)/acvp
library_include_HEADERS = acvp.h
