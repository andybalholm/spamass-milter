#!/bin/sh -e
#
# Run this to update & generate all the automatic things
#

aclocal
autoheader
automake --add-missing
autoconf

./configure $*
