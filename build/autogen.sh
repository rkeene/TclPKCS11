#! /bin/bash

cat aclocal/*.m4 > aclocal.m4
autoconf
rm -rf autom4te.cache
