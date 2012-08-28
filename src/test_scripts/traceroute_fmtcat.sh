#!/bin/sh -x

unicornscan -t6-30 www.i2net.com:mTCE2,80 -HIvE -Uc \
	-o'imip: IMM: %r to %hn trace %Tn from %sn port %pn ttl %t seq %S window %w' \
	-o'ip: REP: %r to %hn trace %Tn from %sn port %pn ttl %t seq %S window %w'
