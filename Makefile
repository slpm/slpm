CFLAGS += -ffunction-sections -fdata-sections
LDFLAGS += -Wl,--gc-sections

CPPFLAGS += -Wall -Wextra -pedantic -Werror
CPPFLAGS += -Os -g
CPPFLAGS += -DNDEBUG=1
CFLAGS += -std=c99
S := libsodium/src/libsodium/
CPPFLAGS += -I$Sinclude
ORIGCC := $(CC)

.PHONY: all
all: slpm

slpm: CC := diet -v -Os $(CC)
slpm: slpm.o __fxstat.o $S.libs/libsodium.a

.PHONY: clean
clean:
	rm -f *.o slpm
	$(MAKE) -C libsodium distclean

$S.libs/libsodium.a: CC := $(ORIGCC)
$S.libs/libsodium.a:
	cd libsodium && ./autogen.sh
	cd libsodium && ./configure --disable-dependency-tracking --enable-minimal
	$(MAKE) -C libsodium
	$(MAKE) -C libsodium check
