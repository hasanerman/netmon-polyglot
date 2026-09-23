CC ?= cc
CFLAGS ?= -std=c17 -O2 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS += -Iinclude -D_POSIX_C_SOURCE=200809L
LDLIBS += -ldl -lpthread
SAN = -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1

SRC = src/sniffer.c src/capture_loop.c src/pcap_replay.c src/device.c src/posix_pcap.c
OBJ = $(SRC:src/%.c=build/obj/%.o)

.PHONY: all test asan clean

all: build/libsniffer.a build/sniff build/test_replay build/test_device

build/obj/%.o: src/%.c include/sniffer.h src/sniffer_internal.h
	@mkdir -p build/obj
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

build/libsniffer.a: $(OBJ)
	ar rcs $@ $^

build/sniff: tools/sniff.c build/libsniffer.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LDLIBS)

build/test_%: tests/test_%.c tests/check.h build/libsniffer.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $< build/libsniffer.a -o $@ $(LDLIBS)

test: all
	./build/test_replay
	./build/test_device

asan: clean
	$(MAKE) CFLAGS="$(CFLAGS) $(SAN)" LDLIBS="$(LDLIBS) $(SAN)" test

clean:
	rm -rf build
