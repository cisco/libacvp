CC = gcc
CFLAGS+=-g -O0 -fPIC -Wall
LDFLAGS+=
INCDIRS+=-I. -Isrc
PKCS11_INCDIRS+=-I/usr/include/nss3 -I/usr/include/nspr4

SOURCES=src/acvp.c src/acvp_aes.c src/acvp_des.c src/acvp_hash.c src/acvp_transport.c src/acvp_util.c src/parson.c src/acvp_drbg.c src/acvp_hmac.c
OBJECTS=$(SOURCES:.c=.o)

all: libacvp.a acvp_app pkcs11_app

.PHONY: test testcpp

libacvp.a: $(OBJECTS)
	ar rcs libacvp.a $(OBJECTS)


.c.o:
	$(CC) $(INCDIRS) $(CFLAGS) -c $< -o $@

libacvp.so: $(OBJECTS)
	$(CC) $(INCDIRS) $(CFLAGS) -shared -Wl,-soname,libacvp.so.1.0.0 -o libacvp.so.1.0.0 $(OBJECTS)
	ln -fs libacvp.so.1.0.0 libacvp.so

acvp_app: app/app_main.c libacvp.a
	$(CC) $(INCDIRS) -pie $(CFLAGS) -o $@ app/app_main.c -L. $(LDFLAGS) -lacvp -lssl -lcrypto -lcurl -ldl

app/app_pkcs11.o: app/app_pkcs11.c
	$(CC) $(INCDIRS) $(PKCS11_INCDIRS) $(CFLAGS) -c $< -o $@

app/pkcs11_server.o: app/pkcs11_server.c
	$(CC) $(INCDIRS) $(PKCS11_INCDIRS) $(CFLAGS) -c $< -o $@

pkcs11_app: app/app_pkcs11.o app/pkcs11_server.o libacvp.a
	$(CC) $(INCDIRS) $(PKCS11_INCDIRS) -pie $(CFLAGS) -o $@ app/app_pkcs11.o app/pkcs11_server.o -L. $(LDFLAGS) -lacvp -lcurl -ldl

clean:
	rm -f *.[ao]
	rm -f src/*.[ao]
	rm -f app/*.[ao]
	rm -f libacvp.so.1.0.0
	rm -f acvp_app
	rm -f testgcm
