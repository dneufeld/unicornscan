include ../Makefile.inc

all: unicornscan.fc.in
	cat unicornscan.fc.in  | sed -e "s,@BINDIR@,$(bindir),g" -e "s,@LIBEXECDIR@,$(libexecdir),g" \
	-e "s,@SYSCONFDIR@,$(sysconfdir),g" -e "s,@LIBDIR@,$(libdir),g" -e "s,@LOCALSTATEDIR@,$(localstatedir),g" \
	> unicornscan.fc

clean:
	rm -f unicornscan.fc

relabel: all
	setfiles unicornscan.fc $(sysconfdir)/unicornscan
	setfiles unicornscan.fc $(bindir)/{unicornscan,unicycle,unibrow,fantaip}
	setfiles unicornscan.fc $(libdir)/unicornscan
	setfiles unicornscan.fc $(libexecdir)/unicornscan
	setfiles unicornscan.fc $(localstatedir)/unicornscan

distclean: clean

install:
uninstall:
