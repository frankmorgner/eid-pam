AM_CFLAGS = $(PAM_CFLAGS) $(LIBCURL_CPPFLAGS) $(LWS_CFLAGS) $(JSONC_CFLAGS)
LIBS = $(LIBCURL) $(LWS_LIBS) $(JSONC_LIBS) $(PAM_LIBS)
AM_LDFLAGS = -module -avoid-version -shared -no-undefined \
	-export-symbols "$(srcdir)/pam.exports"

noinst_HEADERS = http.h drop_privs.h selbstauskunft.h

noinst_LTLIBRARIES = libeid.la

libeid_la_SOURCES = http.c aa2_ws.c selbstauskunft.c

pam_LTLIBRARIES = eid-pam.la

eid_pam_la_SOURCES = pam.c drop_privs.c pam.exports
eid_pam_la_LIBADD = libeid.la

bin_PROGRAMS = eid-add

eid_add_SOURCES = eid-add.c
eid_add_LDADD = libeid.la

noinst_PROGRAMS = test-login test-passwd

test_login_SOURCES = test.c login.c $(eid_pam_la_SOURCES)
test_login_LDADD = libeid.la
test_login_CFLAGS  = $(AM_CFLAGS)

test_passwd_SOURCES = test.c passwd.c $(eid_pam_la_SOURCES)
test_passwd_LDADD = libeid.la
test_passwd_CFLAGS  = $(AM_CFLAGS)
