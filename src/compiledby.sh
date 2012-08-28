#!/bin/sh

if [ "x" = "x${CC}" ]
then
	CC=cc
fi

# works for gcc and icc, (even uncloaking liars with the name cc) what more do you want..
CC_VER=`$CC -v 2>&1 | grep '[Vg][ec][rc][s ][iv][oe][nr]' | sed 's/[^0-9\.]//g'`
if [ $CC = "cc" ]
then
	CC=`$CC --version 2>/dev/null | awk '$1 ~ /^cc/{gsub("[()]", "", $2);print $2}' | dd conv=lcase 2>/dev/null`
fi

printf '#define COMPILE_STR "Compiled by %s on %s at %s with %s version %s"\n' "`whoami`" "`uname -snrm`" "`date`" $CC $CC_VER
