CPPFLAGS += -Wall -Wextra -pedantic
CPPFLAGS += -Os -g
CPPFLAGS += -DNDEBUG=1 -m32
CFLAGS += -std=c99
LDLIBS += -lsodium
LDFLAGS += -static -m32
CC := diet -v -Os $(CC)

.PHONY: all
all: slpm

slpm: slpm.o __fxstat.o

.PHONY: clean
clean:
	rm -f *.o slpm
