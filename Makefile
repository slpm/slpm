CPPFLAGS += -Wall -Wextra -pedantic
CPPFLAGS += -O2 -g
CPPFLAGS += -DNDEBUG=1
CFLAGS += -std=c11
LDLIBS += -lsodium
LDFLAGS += -static
CC := diet -v -Os $(CC)

.PHONY: all
all: slpm

slpm: slpm.o __fxstat.o

.PHONY: clean
clean:
	rm -f *.o slpm
