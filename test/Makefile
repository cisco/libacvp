# source files.
SRC = ut_common.c \
      create_session.c \
      register_hash.c
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
INCLUDES = -I$(ACVP_DIR)/src -I$(OPENSSL_DIR)/include -I$(CURL_DIR)/include \
         -I$(CRITERION_DIR)/include

# C++ compiler flags (-g -O2 -Wall)
CCFLAGS = -Wall -g -DNO_SSL_DL $(CURL_CC_DEFINE) $(CFLAGS)

# compiler
CC = gcc

# linker flags
LDFLAGS += -ldl -lcriterion -lacvp -lcurl -lcrypto


# library paths
LIBS = -L$(OPENSSL_DIR)/lib -L$(CURL_DIR)/lib -L$(CRITERION_DIR)/lib \
        -L$(ACVP_DIR) $(LDFLAGS)



.SUFFIXES: .c

default:	runtest

.c.o:
	$(CC) $(INCLUDES) $(CCFLAGS) -c $< -o $@

runtest: $(OBJ)
	$(CC) -o $(OUT) $(OBJ) $(LIBS) 

clean:
	rm -f $(OBJ)  
	rm -f runtest