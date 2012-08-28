include ../../../Makefile.inc

SRCS=common.c testp1.c tests1.c
OBJS=$(SRCS:.c=.o)
PKTS=pkt1.xxd pkt2.xxd pkt3.xxd

%.dat: %.xxd
	cat $< | xxd -r > $@

LDFLAGS=$(G_LDFLAGS) -L../../unilib -L../ -lscan -lunilib -lpcap

all: $(OBJS) $(PKTS:.xxd=.dat)
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -o tests1 common.o tests1.o $(LDFLAGS)
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -o testp1 common.o testp1.o $(LDFLAGS)

clean:
	rm -f $(OBJS) tests1 testp1 *.dat
distclean:
install:
uninstall:
