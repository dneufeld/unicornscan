#!/bin/sh

sc=$(objdump -d ${*}|awk -F'[:\t]' '$1 ~ /^ +[0-9a-z]+/{print $3}'|tr '\n' ' '| sed -e 's/[0-9a-f][0-9a-f] /\\x&/g' -e 's/ //g')

printf "$sc"
