include ../Makefile.inc

SRCS=patricia.c
OBJS=$(SRCS:.c=.o)

OUTLIB=libuext.a

all: $(OUTLIB)

install:

distclean:

uninstall:

$(OUTLIB): $(OBJS)
	$(AR) $(ARFLAGS) $(OUTLIB) $(OBJS)
	$(RANLIB) $(OUTLIB)

demo: $(OBJS) demo.c
	$(CC) $(CFLAGS) -o demo demo.c $(OBJS)

clean:
	rm -f $(OUTLIB) $(OBJS) demo
