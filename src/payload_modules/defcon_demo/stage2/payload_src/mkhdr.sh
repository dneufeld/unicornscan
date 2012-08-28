#!/bin/sh -x

EP=`readelf -a payload | awk -F':' '$1 ~ /Entry point/{print $2}' | sed 's/ //g'`

cat <<EOF > hdr.s

.globl _start

_start:
	xorl	%eax,		%eax
	pushl	%eax
	movl	\$${EP},	%eax
	jmp	*%eax

EOF

as -o hdr.o hdr.s

sc=$(objdump -d hdr.o |awk -F'[:\t]' '$1 ~ /^ +[0-9a-z]+/{print $3}'|tr '\n' ' '| sed -e 's/[0-9a-f][0-9a-f] /\\x&/g' -e 's/ //g')

printf "$sc" > tst

dd if=payload of=stage2 2>/dev/null
dd conv=notrunc if=tst of=stage2 2>/dev/null

cat stage2 > ../linux-x86.bin
