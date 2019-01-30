#
# Unfortunately the real safec library does not follow
# Linux convention having libraries start with lib.
# So here I'm forcing a non-standard build of 
# our safec stub to match the library names
# used with safec
#
#
noinst_LTLIBRARIES= libsafe_lib.la

libsafe_lib_la_SOURCES =  \
../src/safe_mem_stub.c \
../src/safe_str_stub.c

libsafe_lib_la_CFLAGS=-I../include -fPIC

