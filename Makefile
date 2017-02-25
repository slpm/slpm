CFLAGS += -m32
LDFLAGS += -m32

CFLAGS += -ffunction-sections -fdata-sections
LDFLAGS += -Wl,--gc-sections

CPPFLAGS += -Wall -Wextra -pedantic -Werror
CPPFLAGS += -Os -g
CPPFLAGS += -DNDEBUG=1
CFLAGS += -std=c99
LDFLAGS += -static
CC := diet -v -Os $(CC)

.PHONY: all
all: slpm

slpm: slpm.o __fxstat.o libsodium/src/libsodium/.libs/libsodium.a

.PHONY: clean
clean:
	rm -f *.o slpm
	$(MAKE) -C libsodium distclean

libsodium/src/libsodium/.libs/libsodium.a:
	cd libsodium && ./autogen.sh
	cd libsodium && ./configure --disable-dependency-tracking --enable-minimal
	$(MAKE) -C libsodium
	$(MAKE) -C libsodium check
