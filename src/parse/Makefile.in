include ../../Makefile.inc

SRCS=parse.tab.c lex.uu.c putil.c
HDRS=parse.tab.h parse.h putil.h
OBJS=$(SRCS:.c=.lo)

LIBNAME=libparse.la
BOB=parse.tab.c lex.uu.c

all: $(LIBNAME)

$(OBJS): $(HDRS)

prepare: $(BOB)

$(LIBNAME): $(OBJS) $(HDRS)
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -o $(LIBNAME) $(OBJS)

parse.tab.c: parse.y
	$(BISON) -puu parse.y

lex.uu.c: parse.l parse.tab.h
	$(FLEX) -Puu parse.l

install: all
uninstall:

clean:
	$(LIBTOOL) --mode=clean rm -f $(OBJS) $(LIBNAME)

distclean: clean
	rm -f parse.tab.c parse.tab.h lex.uu.c
