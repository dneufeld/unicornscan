include ../../../Makefile.inc

SRCS=p0f.c
HDRS=fpentry.h mtu.h p0f-config.h tcp.h tos.h 

OBJS=$(SRCS:.c=.lo)

all: $(OBJS)

clean:
	$(LIBTOOL) --mode=clean rm -f $(OBJS)

distclean:

install:
