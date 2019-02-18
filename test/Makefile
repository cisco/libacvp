# source files.
SRC = ut_common.c \
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
	  test_acvp_ecdsa.c \
	  test_acvp_kas_ecc.c \
	  test_acvp_kas_ffc.c

OBJ = $(SRC:.c=.o)
OUT = runtest

ifndef OPENSSL_DIR
    OPENSSL_DIR=/usr/local/ssl
endif
ifndef CURL_DIR
    CURL_DIR=/usr/local/curl
    CURL_CC_DEFINE =
else
    CURL_CC_DEFINE = -DHAVE_LIBCURL
endif

# include directories
INCLUDES = -I../include/acvp -I$(OPENSSL_DIR)/include -I$(CURL_DIR)/include \
		   -I$(CRITERION_DIR)/include

# C++ compiler flags (-g -O2 -Wall)
CCFLAGS = -Wall -g -DNO_SSL_DL $(CURL_CC_DEFINE) $(CFLAGS)

# compiler
CC = gcc

# linker flags
LDFLAGS += -ldl -lcriterion -lacvp -lcurl -lcrypto $(LGCOV)

# library paths
LIBS = -L../src/.libs -L$(OPENSSL_DIR)/lib -L$(CURL_DIR)/lib -L$(CRITERION_DIR)/lib \
        $(LDFLAGS)



.SUFFIXES: .c

default: runtest

.c.o:
	$(CC) $(INCLUDES) $(CCFLAGS) -c $< -o $@

runtest: $(OBJ)
	$(CC) -o $(OUT) $(OBJ) $(LIBS) 

clean:
	rm -f $(OBJ)  
	rm -f runtest
