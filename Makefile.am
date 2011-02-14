## Process this file with automake to produce Makefile.in
## $Id: Makefile.am,v 1.23 2011/02/14 21:46:13 dnelson Exp $

AUTOMAKE_OPTIONS = no-dependencies foreign dist-bzip2

# The number of files autoconf leaves lying around after a clean is amazing.
CLEANFILES = *~ .libs/* .libs spamass-milter.man
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in \
	config.log config.status configure configure.lineno stamp-h.in \
	COPYING INSTALL config.guess config.sub install-sh missing mkinstalldirs \
	${DIST_ARCHIVES} ${DIST_ARCHIVE_SIGS}

maintainer-clean-local:
	-chmod -R +w autom4te* $(distdir)
	rm -rf autom4te* $(distdir)
distclean-local:
	rm -f configure.lineno

# rebuild ChangeLog during dist, but only if it's a zero-byte file
# (i.e. clean CVS co)
dist-hook: 
	if test ! -s $(distdir)/ChangeLog ; then \
		cvs2cl --no-wrap -S -U contrib/users --stdout > $(distdir)/ChangeLog ; \
	fi

.PHONY: sign upload changelog dist-hook

DIST_ARCHIVE_SIGS=${DIST_ARCHIVES:S/$/.sig/}

# Bah. Automake does not have a dist-local hook which would let me
# create the PGP sigs when the distfiles themselves are built.  So
# build them just before upload.
sign: dist-all
	rm -f ${DIST_ARCHIVE_SIGS}
	for file in ${DIST_ARCHIVES} ; \
	do \
		gpg -b -a -u 6B56A1DD -o $$file.sig $$file ; \
	done

upload: dist-all sign
	rsync -a --progress ${DIST_ARCHIVES} dl.sv.nongnu.org:/releases/spamass-milt/

# ftp got disabled at some point?
#upload: dist-all sign
#	ncftpput savannah.gnu.org incoming/savannah/spamass-milt \
#		${DIST_ARCHIVES} ${DIST_ARCHIVE_SIGS}

# The good old way
#upload: dist-all
#	rsync -a --progress $(distdir).tar.bz2 $(distdir).tar.gz subversions.gnu.org:/upload/spamass-milt/

changelog:
	cvs2cl --no-wrap -S -U contrib/users 

.1.man: mdoc2man.awk
	$(AWK) -f mdoc2man.awk $< > $@

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
		mdoc2man.awk \
		spamass-milter.1.in \
		subst_poll.h

spamass-milter.cpp: spamass-milter.h
