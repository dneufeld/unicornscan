#!/bin/sh

PROGNAME="./test"
TESTFILE="test.svg"
DICT="dict"

cat $DICT | $PROGNAME > $TESTFILE
