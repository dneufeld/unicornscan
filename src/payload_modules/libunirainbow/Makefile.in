include ../../../Makefile.inc

SRCS=common.c x86_alpha.c x86_jmpsled.c x86_nops.c x86_xor.c fstwrtr.c
HDRS=libunirainbow.h

OBJS=$(SRCS:.c=.lo)
LIBNAME=libunirainbow.la

all: $(LIBNAME)

$(OBJS): $(HDRS)

$(LIBNAME): $(OBJS)
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -o $(LIBNAME) $(OBJS)

clean:
	$(LIBTOOL) --mode=clean rm -f $(OBJS)
	$(LIBTOOL) --mode=clean rm -f $(LIBNAME)

distclean: clean

install: all
uninstall:
