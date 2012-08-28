include ../../Makefile.inc

SRCS=arch.c chtbl.c cidr.c drone.c gtod.c intf.c modules.c output.c panic.c pcaputil.c prng.c qfifo.c rbtree.c route.c settings.c sleep.c socktrans.c standard_dns.c terminate.c tsc.c xdelay.c xipc.c xmalloc.c xpoll.c pktutil.c
HDRS=arch.h chtbl.h cidr.h drone.h intf.h modules.h output.h panic.h pcaputil.h prng.h qfifo.h rbtree.h route.h socktrans.h standard_dns.h terminate.h xdelay.h xipc.h xmalloc.h xpoll.h pktutil.h xipc_private.h

OBJS=$(SRCS:.c=.lo)
LIBNAME=libunilib.la

xmalloc.c: _xmalloc.c
	ln -s _xmalloc.c xmalloc.c

xmalloc.h: _xmalloc.h
	ln -s _xmalloc.h xmalloc.h

prng.c: mt19937ar.c
	ln -s mt19937ar.c prng.c

all: $(LIBNAME) xmalloc.c xmalloc.h prng.c

tsc.lo: tsc.c
	$(LIBTOOL) --mode=compile $(CC) -g -c -o tsc.lo tsc.c -I.. $(CINCS)

$(OBJS): $(HDRS)

$(LIBNAME): $(OBJS)
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -o $(LIBNAME) $(OBJS)

clean:
	$(LIBTOOL) --mode=clean rm -f $(OBJS)
	$(LIBTOOL) --mode=clean rm -f $(LIBNAME)

distclean: clean

install: all
uninstall:
