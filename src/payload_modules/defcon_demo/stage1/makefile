
all: /tmp/linux-stage1.bin /tmp/netbsd-stage1.bin

/tmp/linux-stage1.bin: payload-linux26.S makefile mkbin.sh
	$(CC) $(CFLAGS) -c -o payload-linux26.o payload-linux26.S
	./mkbin.sh payload-linux26.o > /tmp/linux-stage1.bin

/tmp/netbsd-stage1.bin: payload-netbsd.S makefile mkbin.sh
	$(CC) $(CFLAGS) -c -o payload-netbsd.o payload-netbsd.S
	./mkbin.sh payload-netbsd.o > /tmp/netbsd-stage1.bin

clean:
	rm -f payload-linux26.o /tmp/linux-stage1.bin payload-linux26 payload-netbsd.o /tmp/netbsd-stage1.bin
