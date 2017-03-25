# TODO: this needs to be configurable
CPPFLAGS += -m32
LDFLAGS += -m32

CPPFLAGS += -ffunction-sections -fdata-sections
LDFLAGS += -Wl,--gc-sections

CPPFLAGS += -DVERSION='"$(shell git describe --long)"'
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

SUMS := SHA256SUMS SHA512SUMS

.PHONY: all
all: $(SUMS)

SHA256SUMS: slpm.comp
	sha256sum -b $^ | tee $@

SHA512SUMS: slpm.comp
	sha512sum -b $^ | tee $@

.PHONY: all-sign
all-sign: $(SUMS:%=%.sign)

%.sign: %
	gpg2 -b --armor $(OUTPUT_OPTION) $<

SRC := \
	start-Linux.o \
	mylibc-lowlevel.o \
	mylibc.o \
	slpm.o \
	utils.o \
	ssh-agent.o \
	sodium-utils.o \
	mpw.o

O := $(addprefix src/,$(SRC))
O += $Scrypto_auth/hmacsha256/cp/hmac_hmacsha256.o
O += $Scrypto_hash/sha256/cp/hash_sha256.o
O += $Scrypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.o
O += $Scrypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.o
O += $Scrypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.o
O += $Scrypto_pwhash/scryptsalsa208sha256/scrypt_platform.o
O += $Scrypto_pwhash/argon2/argon2-encoding-patched.o
O += tweetnacl/tweetnacl.o

src/slpm: $O

$Scrypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.o: CPPFLAGS += -Wno-type-limits

$Scrypto_pwhash/argon2/argon2-encoding-patched.c: $Scrypto_pwhash/argon2/argon2-encoding.c
	sed -e 's/static size_t to_base64/size_t to_base64/g' $< > $@

slpm.comp: slpm.stripped
	upx --ultra-brute --force $(OUTPUT_OPTION) $<
	touch $@

SSTRIP := elfkickers/sstrip/sstrip

%.stripped: src/% $(SSTRIP)
	nm --defined-only --format=posix --size-sort --reverse-sort $< | \
		sed -e 's/[0-9a-f]\+ \([0-9a-f]\+\)$$/\1/g' | c++filt | uniq -c | tee $<.sizes
	objcopy --only-keep-debug $< $<.debug
	objcopy $(addprefix -R ,$(STRIP_SECTIONS)) --strip-all $< $@
	$(SSTRIP) -z $@
	ls -la $@

$(SSTRIP):
	$(MAKE) -C elfkickers/sstrip

.PHONY: clean
clean:
	rm -f $O slpm *.comp *.stripped *.debug *.sizes *SUMS *.sign
	rm -f $Scrypto_pwhash/argon2/argon2-encoding-patched.c
	$(MAKE) -C elfkickers clean

.PHONY: check
check: slpm.comp
	./check.sh
