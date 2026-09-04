CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11
LDLIBS  = -lcurl -ljansson
PREFIX  = /usr/local

SRCS = src/main.c src/net.c src/relay.c src/state.c src/prov.c src/jsonx.c
HDRS = src/rogue.h

rogue: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

test: rogue
	./tests/selftest.sh

install: rogue
	install -m 0755 rogue $(PREFIX)/bin/rogue
	install -m 0755 scripts/watchdog.sh $(PREFIX)/bin/rogue-watchdog

clean:
	rm -f rogue

.PHONY: test install clean