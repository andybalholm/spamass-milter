## Process this file with automake to produce Makefile.in
## $Id: Makefile.am,v 1.8 2002/11/15 07:18:26 dnelson Exp $

AUTOMAKE_OPTIONS = no-dependencies foreign

CLEANFILES = *~ .deps/* .libs/* .deps .libs 
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in \
	config.log config.status configure configure.lineno stamp-h.in \
	COPYING INSTALL config.guess config.sub install-sh missing mkinstalldirs
maintainer-clean-local:
	rm -rf autom4te.cache $(distdir) $(distdir).tar.gz
distclean-local:
	rm -f configure.lineno

# rebuild ChangeLog during dist, but only if it's a zero-byte file
# (i.e. clean CVS co)
dist-hook: 
	if test ! -s $(distdir)/ChangeLog ; then \
		cvs2cl --no-wrap -S -U contrib/users --stdout > $(distdir)/ChangeLog ; \
	fi

changelog:
	cvs2cl --no-wrap -S -U contrib/users 

man_MANS = 	spamass-milter.1
sbin_PROGRAMS =	spamass-milter
DEB_CONTRIB =	contrib/spamass-milter
RH_CONTRIB =	contrib/spamass-milter-redhat.rc \
		contrib/spamass-milter.spec \
		contrib/spamass-milter.spec.in
MISC_CONTRIB =	contrib/README.gnus
spamass_milter_SOURCES = spamass-milter.cpp spamass-milter.h 
EXTRA_DIST =	$(DEB_CONTRIB) \
		$(RH_CONTRIB) \
		$(MISC_CONTRIB) \
		spamass-milter.1.in
