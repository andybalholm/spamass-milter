## Process this file with automake to produce Makefile.in
## $Id: Makefile.am,v 1.17 2003/08/04 23:03:42 dnelson Exp $

AUTOMAKE_OPTIONS = no-dependencies foreign dist-bzip2

# The number of files autoconf leaves lying around after a clean is amazing.
CLEANFILES = *~ .deps/* .libs/* .deps .libs spamass-milter.man
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in \
	config.log config.status configure configure.lineno stamp-h.in \
	COPYING INSTALL config.guess config.sub install-sh missing mkinstalldirs \
	spamass-milter.man.in $(distdir).tar.gz $(distdir).tar.bz2
maintainer-clean-local:
	rm -rf autom4te* $(distdir)
distclean-local:
	rm -f configure.lineno

# rebuild ChangeLog during dist, but only if it's a zero-byte file
# (i.e. clean CVS co)
dist-hook: 
	if test ! -s $(distdir)/ChangeLog ; then \
		cvs2cl --no-wrap -S -U contrib/users --stdout > $(distdir)/ChangeLog ; \
	fi

.PHONY: upload changelog dist-hook

upload: dist-all
	rsync -a --progress $(distdir).tar.bz2 $(distdir).tar.gz subversions.gnu.org:/upload/spamass-milt/

changelog:
	cvs2cl --no-wrap -S -U contrib/users 

# Can't distribute mdoc2man yet
#.1.man: mdoc2man.awk
#	$(AWK) -f mdoc2man.awk $< > $@

spamass-milter.man.in: spamass-milter.1.in mdoc2man.awk
	$(AWK) -f mdoc2man.awk spamass-milter.1.in > $@

if HAVE_MDOC
man_MANS = 	spamass-milter.1
else
man1_MANS = 	spamass-milter.man
endif
sbin_PROGRAMS =	spamass-milter
DEB_CONTRIB =	contrib/spamass-milter
RH_CONTRIB =	contrib/spamass-milter-redhat.rc \
		contrib/spamass-milter.spec \
		contrib/spamass-milter.spec.in
FBSD_CONTRIB =	contrib/spamass-milter.sh
MISC_CONTRIB =	contrib/README.gnus
spamass_milter_SOURCES = spamass-milter.cpp spamass-milter.h 
spamass_milter_LDADD = @LIBOBJS@
EXTRA_DIST =	$(DEB_CONTRIB) \
		$(RH_CONTRIB) \
		$(FBSD_CONTRIB) \
		$(MISC_CONTRIB) \
		spamass-milter.1.in \
		spamass-milter.man.in \
		subst_poll.h

spamass-milter.cpp: spamass-milter.h
