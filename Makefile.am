## Process this file with automake to produce Makefile.in
## $Id: Makefile.am,v 1.3 2002/07/23 02:02:12 dnelson Exp $

AUTOMAKE_OPTIONS = no-dependencies

CLEANFILES = *~ .deps/* .libs/* .deps .libs 
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in \
	config.log config.status configure configure.lineno stamp-h.in \
	COPYING INSTALL config.guess config.sub install-sh missing mkinstalldirs
maintainer-clean-local:
	rm -rf autom4te.cache

sbin_PROGRAMS = spamass-milter
spamass_milter_SOURCES = spamass-milter.cpp

