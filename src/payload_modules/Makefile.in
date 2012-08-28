include ../../Makefile.inc

SRCS=ntalk.c rdns.c sip.c upnp.c http.c httpexp.c

OBJS=$(SRCS:.c=.lo)
SHLIBS=$(OBJS:.lo=.la)

CFLAGS += -DMODULE=1 -I./libunirainbow -L./libunirainbow

%.la: %.lo
	$(LIBTOOL) --mode=link $(CC) $(MODCLFLAGS) $(CFLAGS) -o $@ $< -lunirainbow

all: libunirainbowd $(SHLIBS)

clean:
	$(LIBTOOL) --mode=clean rm -f $(SHLIBS)
	$(LIBTOOL) --mode=clean rm -f $(OBJS)
	rm -rf .libs $(OBJS:.lo=.o)
	cd libunirainbow && $(USE_MAKE) clean

libunirainbowd:
	cd libunirainbow && $(USE_MAKE)

distclean: clean

install: all
	mkdir -p $(DESTDIR)/$(MODDIR)
	for g in $(SHLIBS); do \
		$(LIBTOOL) --mode=install $(INSTALL_PROGRAM) -m 755 $$g $(DESTDIR)/$(MODDIR)/; \
		if test -f $(DESTDIR)/$(MODDIR)/$${g%%.la}.so; then \
			$(CHCON) system_u:object_r:shlib_t $(DESTDIR)/$(MODDIR)/$${g%%.la}.so; \
		fi \
	done
	# this is totally retarded
	$(LIBTOOL) --mode=finish $(DESTDIR)/$(MODDIR)

uninstall:
	for g in $(SHLIBS); do \
		$(LIBTOOL) --mode=uninstall rm -f $(DESTDIR)/$(MODDIR)/$${g}; \
	done
