#!/bin/sh -e
# $Id: autogen.sh,v 1.4 2002/11/15 07:17:18 dnelson Exp $
# Run this to update & generate all the automatic things
#

# hack because some OSes (cough RedHat cough) default to 2.13 even
# though a perfectly good 2.5x is available
AC=
for i in 255 -2.55 2.55 254 -2.54 2.54 253 -2.53 2.53 ; do
 if which autoconf$i ; then 
  AC=$i ; break
 fi
done
aclocal
autoheader$AC
automake --add-missing
autoconf$AC

./configure $*
