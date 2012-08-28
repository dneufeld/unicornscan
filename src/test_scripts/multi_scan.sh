#!/bin/sh -x
 
unicornscan -mA -Iv -p22,80 ${*} gateway/24 random:mT gateway:mU,q
