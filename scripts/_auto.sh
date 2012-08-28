#!/bin/sh 

rm -f configure aclocal.m4
for g in `ls m4/*.m4`; do cat $g >> aclocal.m4; done && autoconf
rm -rf Makefile Makefile.inc autom4te.cache confdefs.h config.log config.status
