## Process this file with automake to produce Makefile.in
## $Id: Makefile.am,v 1.2 2002/01/16 21:41:21 greve Exp $

PACKAGE = @PACKAGE@
VERSION = @VERSION@
SPAMC = @SPAMC@

INCLUDES = 
LIBS = @LIBS@ /usr/lib/libmilter/libmilter.a /usr/lib/libmilter/libsm.a

CLEANFILES=*~ .deps/* .libs/* .deps .libs

if DEBUG
DEBUGFLAGS += -g -Wall
else
DEBUGFLAGS += -O2 -Wall
endif

CXXFLAGS = $(DEBUGFLAGS)
CFLAGS   = $(DEBUGFLAGS)
LDFLAGS += 


bin_PROGRAMS = spamass-milter
spamass_milter_SOURCES = spamass-milter.cpp

