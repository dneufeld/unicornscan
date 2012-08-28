#!/bin/sh

sc=$(objdump -d ${*}|awk -F'[:\t]' '$1 ~ /^ +[0-9a-z]+/{print $3}'|tr '\n' ' '| sed -e 's/[0-9a-f][0-9a-f] /\\x&/g' -e 's/ //g')

cat <<EOF > shellcode.h
#ifndef _SHELLCODE_H
# define _SHELLCODE_H

#define SHELLCODE	"$sc"
#define SHELLCODE_LEN	(sizeof(SHELLCODE) - 1)

#endif
EOF
