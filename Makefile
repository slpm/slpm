# TODO: this needs to be configurable
CPPFLAGS += -m32
LDFLAGS += -m32

CPPFLAGS += -ffunction-sections -fdata-sections
LDFLAGS += -Wl,--gc-sections

CPPFLAGS += -Wall -Wextra -pedantic -Werror
CPPFLAGS += -Os -g
CPPFLAGS += -DNDEBUG=1
CFLAGS += -std=c99
CXXFLAGS += -std=c++11
S := libsodium/src/libsodium/
CPPFLAGS += -I$Sinclude
ORIGCC := $(CC)

CPPFLAGS += -fno-unwind-tables -fno-asynchronous-unwind-tables
CPPFLAGS += -fno-align-functions
CPPFLAGS += -ffast-math
LDFLAGS += -Wl,--relax
LDFLAGS += -Wl,-hash-style=sysv -Wl,-hash-size=1
LDFLAGS += -Wl,--build-id=none

STRIP_SECTIONS := \
	.note* \
	.comment*

.PHONY: all
all: slpm.comp

#slpm: CC := diet -v -Os $(CC)
slpm: slpm.o __fxstat.o $S.libs/libsodium.a

slpm.comp: slpm.stripped
	upx --brute --force -o$@ $<

%.stripped: %
	objcopy --only-keep-debug $< $<.debug
	objcopy $(addprefix -R ,$(STRIP_SECTIONS)) --strip-all $< $@
	! type sstrip >/dev/null 2>&1 || sstrip -z $@
	ls -la $@


.PHONY: clean
clean:
	rm -f *.o slpm
	$(MAKE) -C libsodium distclean

$S.libs/libsodium.a: CC := $(ORIGCC)
$S.libs/libsodium.a:
	cd libsodium && ./autogen.sh
	cd libsodium && ./configure --disable-dependency-tracking --enable-minimal CPPFLAGS=-m32 LDFLAGS=-m32
	$(MAKE) -C libsodium
	$(MAKE) -C libsodium check
