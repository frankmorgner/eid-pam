AM_CFLAGS = $(PAM_CFLAGS) $(LIBCURL_CPPFLAGS)
LIBS = $(LIBCURL) $(PAM_LIBS)
AM_LDFLAGS = -module -avoid-version -shared -no-undefined \
	-export-symbols "$(srcdir)/pam.exports"

noinst_HEADERS = eid.h drop_privs.h

noinst_LTLIBRARIES = libeid.la

libeid_la_SOURCES = eid.c

pam_LTLIBRARIES = eid-pam.la

eid_pam_la_SOURCES = pam.c drop_privs.c pam.exports
eid_pam_la_LIBADD = libeid.la

bin_PROGRAMS = eid-add

eid_add_SOURCES = eid-add.c
eid_add_LDADD = libeid.la
