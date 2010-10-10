CC = gcc
CFLAGS = -fPIC -DPIC -Wall
CPPFLAGS = -DTCL_USE_STUBS=1 -DHAVE_DLOPEN=1 -DHAVE_DLFCN_H=1
SHFLAGS = -nostartfiles -rdynamic -shared
LIBS = -ldl -ltclstub8.5 

all: tclpkcs11.so

pkcs11.h: pkcs11f.h pkcs11t.h
tclpkcs11.o: tclpkcs11.c pkcs11.h
tclpkcs11.so: tclpkcs11.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(SHFLAGS) -o tclpkcs11.so tclpkcs11.o $(LIBS)

clean:
	rm -f tclpkcs11.so tclpkcs11.o

distclean: clean

.PHONY: all clean distclean
