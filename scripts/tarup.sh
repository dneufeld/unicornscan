#!/bin/sh

export PKNAME=`basename $(pwd)`

./scripts/_auto.sh

date > tstamp

corefl=`find . -name "*core*" -print`
if [ "x${corefl}" != "x" ]
then
	echo
	echo "found core file(s)"
	echo "## $corefl ##"
	echo
	exit
fi

objfl=`find . \( -name "*.la" -o -name "*.o" -o -name "*.a" -o -name "*.so" -o -name "*.lo" \) -print`
if [ "x${objfl}" != "x" ]
then
	echo
	echo "found object file(s)"
	echo "## $objfl ##"
	echo
	exit
fi

find . -exec touch {} \; -print

(cd src/parse && bison -d -puu parse.y && flex -sB -Puu parse.l)

sescrsh=`find . -name ".*.swp" -print`
if [ "x${sescrsh}" != "x" ]
then
	echo
	echo review crashed vi session
	echo \#\# $sescrsh \#\#
	echo
	exit
fi

if [ "x${1}" = "xclean" ]
then
	exit
fi

(cd ..
if [ -f ${PKNAME}.tar.gz ]
then
	mv ${PKNAME}.tar.gz ${PKNAME}.tar.gz.old
fi
tar -cvf - ./${PKNAME} | gzip -c9 > ${PKNAME}.tar.gz
)
