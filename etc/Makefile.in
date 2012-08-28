include ../Makefile.inc

all:
	cat unicorn.conf.in | sed -e 's#@CONFDIR@#$(sysconfdir)/$(TARGETNAME)#g' -e 's#@MODDIR@#$(MODDIR)#g' > unicorn.conf

install: all
	mkdir -p $(DESTDIR)/$(sysconfdir)/$(TARGETNAME)
	$(INSTALL_PROGRAM) modules.conf $(DESTDIR)/$(sysconfdir)/$(TARGETNAME)
	$(INSTALL_PROGRAM) payloads.conf $(DESTDIR)/$(sysconfdir)/$(TARGETNAME)
	$(INSTALL_PROGRAM) unicorn.conf $(DESTDIR)/$(sysconfdir)/$(TARGETNAME)
	$(INSTALL_PROGRAM) oui.txt $(DESTDIR)/$(sysconfdir)/$(TARGETNAME)
	$(INSTALL_PROGRAM) ports.txt $(DESTDIR)/$(sysconfdir)/$(TARGETNAME)
	$(CHCON) -R system_u:object_r:unicornscan_share_t $(DESTDIR)/$(sysconfdir)/$(TARGETNAME)

uninstall:
	rm -f $(DESTDIR)/$(sysconfdir)/$(TARGETNAME)/modules.conf
	rm -f $(DESTDIR)/$(sysconfdir)/$(TARGETNAME)/oui.conf
	rm -f $(DESTDIR)/$(sysconfdir)/$(TARGETNAME)/payloads.conf
	rm -f $(DESTDIR)/$(sysconfdir)/$(TARGETNAME)/port-numbers
	rm -f $(DESTDIR)/$(sysconfdir)/$(TARGETNAME)/unicorn.conf

clean:

distclean: clean
	rm -f unicorn.conf
