#!/bin/sh -e
# $Id: rhautogen.sh,v 1.1 2002/07/24 16:19:53 dnelson Exp $
# Run this to update & generate all the automatic things
# (RedHat version)

/bin/rm -f acconfig.h missing
aclocal-1.5
autoheader-2.53
automake-1.5 --add-missing
autoconf-2.53

./configure $*
