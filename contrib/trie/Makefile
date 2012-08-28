CC=gcc-4.1.1
CFLAGS= -Wall -Wshadow -Wcast-align -Wchar-subscripts -Wno-deprecated-declarations -Wformat-nonliteral -Wformat-security -Wimplicit -Wsign-compare -Wunused -Wmissing-format-attribute -Wmissing-noreturn -Wmissing-braces -Wparentheses -Wsequence-point -Wno-format-y2k -Wpointer-arith -fstrict-aliasing
CFLAGS+= -ggdb  -Werror
LDFLAGS=

PROGNAME=test
SRCS=trie.c stats.c
OBJS=$(SRCS:.c=.o)

all: $(PROGNAME)

.c.o: $<
	$(CC) $(CFLAGS) -c $< -o $@

$(PROGNAME): $(OBJS)
	$(CC) $(OBJS) -o $(PROGNAME) $(LDFLAGS)

install:
	@echo "fuck you! shut up! you're wrong!"

distclean: clean

clean:
	rm -f $(PROGNAME) $(OBJS) test.svg gmon.out
