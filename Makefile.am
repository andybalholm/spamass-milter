## Process this file with automake to produce Makefile.in
## $Id: Makefile.am,v 1.4 2002/07/24 16:19:53 dnelson Exp $

AUTOMAKE_OPTIONS = no-dependencies

CLEANFILES = *~ .deps/* .libs/* .deps .libs 
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in \
	config.log config.status configure configure.lineno stamp-h.in \
	COPYING INSTALL config.guess config.sub install-sh missing mkinstalldirs
maintainer-clean-local:
	rm -rf autom4te.cache

sbin_PROGRAMS =	spamass-milter
DEB_CONTRIB =	contrib/spamass-milter
RH_CONTRIB =	contrib/spamass-milter-redhat.rc \
		contrib/spamass-milter.spec \
		contrib/spamass-milter.spec.in
MISC_CONTRIB =	contrib/README.gnus
spamass_milter_SOURCES = spamass-milter.cpp spamass-milter.h 
EXTRA_DIST =	$(DEB_CONTRIB) \
		$(RH_CONTRIB) \
		$(MISC_CONTRIB)
