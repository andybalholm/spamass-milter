#!/bin/sh -e
# $Id: autogen.sh,v 1.3 2002/07/24 16:19:53 dnelson Exp $
# Run this to update & generate all the automatic things
#

aclocal
autoheader
automake --add-missing
autoconf

./configure $*
