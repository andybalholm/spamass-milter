#!/bin/sh
#
# Run this to update & generate all the automatic things
#

autoheader
aclocal
automake --add-missing
autoconf

./configure $*


