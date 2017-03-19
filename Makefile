# TODO: this needs to be configurable
CPPFLAGS += -m32
LDFLAGS += -m32

CPPFLAGS += -ffunction-sections -fdata-sections
LDFLAGS += -Wl,--gc-sections

CPPFLAGS += -Wall -Wextra -pedantic -Werror
CPPFLAGS += -Os -g
CPPFLAGS += -DNDEBUG=1
CFLAGS += -std=c99
CXXFLAGS += -std=c++1y
S := libsodium/src/libsodium/
CPPFLAGS += -I$Sinclude -I$Sinclude/sodium
ORIGCC := $(CC)

CXXFLAGS += -fno-rtti -fno-exceptions
CPPFLAGS += -fno-unwind-tables -fno-asynchronous-unwind-tables
CPPFLAGS += -fno-align-functions
CPPFLAGS += -ffast-math
LDFLAGS += -Wl,--relax
LDFLAGS += -Wl,-hash-style=sysv -Wl,-hash-size=1
LDFLAGS += -Wl,--build-id=none
LDFLAGS += -static -nostdlib

CPPFLAGS += -D_BSD_SOURCE -DHAVE_MMAP -DHAVE_SYS_MMAN_H
CPPFLAGS := $(filter-out -fstack-protector,$(CPPFLAGS)) -fno-stack-protector

STRIP_SECTIONS := \
	.note* \
	.comment*

.PHONY: all
all: slpm.comp

O := start-Linux.o mylibc-lowlevel.o mylibc.o slpm.o utils.o ssh-agent.o
O += sodium-utils.o
O += $Scrypto_auth/hmacsha256/cp/hmac_hmacsha256.o
O += $Scrypto_hash/sha256/cp/hash_sha256.o
O += $Scrypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.o
O += $Scrypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.o
O += $Scrypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.o
O += $Scrypto_pwhash/scryptsalsa208sha256/scrypt_platform.o
O += $Scrypto_sign/ed25519/ref10/keypair.o
O += $Scrypto_hash/sha512/cp/hash_sha512.o
O += $Scrypto_core/curve25519/ref10/curve25519_ref10.o
O += $Scrypto_pwhash/argon2/argon2-encoding-patched.o

slpm: $O

$Scrypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.o: CPPFLAGS += -Wno-type-limits

$Scrypto_pwhash/argon2/argon2-encoding-patched.c: $Scrypto_pwhash/argon2/argon2-encoding.c
	sed -e 's/static size_t to_base64/size_t to_base64/g' $< > $@

slpm.comp: slpm.stripped
	upx --brute --force -o$@ $<
	touch $@

SSTRIP := elfkickers/sstrip/sstrip

%.stripped: % $(SSTRIP)
	objcopy --only-keep-debug $< $<.debug
	objcopy $(addprefix -R ,$(STRIP_SECTIONS)) --strip-all $< $@
	$(SSTRIP) -z $@
	ls -la $@

$(SSTRIP):
	$(MAKE) -C elfkickers/sstrip

.PHONY: clean
clean:
	rm -f $O slpm *.comp *.stripped *.debug
	rm -f $Scrypto_pwhash/argon2/argon2-encoding-patched.c
	$(MAKE) -C elfkickers clean

.PHONY: check
check: slpm.comp
	./check.sh
