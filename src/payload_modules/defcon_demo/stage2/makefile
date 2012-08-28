
CC=gcc
CFLAGS=-Wall -g

all: sc_server shclient

sc_server: sc_server.c linux-x86.bin netbsd-x86.bin
	$(CC) $(CFLAGS) -o sc_server sc_server.c

linux-x86.bin:
	cd payload_src && make

netbsd-x86.bin:
	@echo
	@echo -e '!!! You need to copy netbsd stage2 from something else...ill throw an int3 in the blank !!!'
	@echo
	@sleep 2
	printf '\xcc' > netbsd-x86.bin

clean:
	rm -f core expl shellcode.h payload.o payload sc_server *.bin shclient
	cd payload_src && make clean
