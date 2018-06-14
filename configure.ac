AC_PREREQ(2.60)

define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [1])
define([PACKAGE_VERSION_FIX], [0])
define([PRODUCT_BUGREPORT], [https://github.com/frankmorgner/eid-pam/issues])

AC_INIT([eid-pam],[PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX],[PRODUCT_BUGREPORT])
AC_CONFIG_AUX_DIR([.])
AM_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([src/pam.c])

AC_CANONICAL_HOST
AC_PROG_CC
PKG_PROG_PKG_CONFIG

AC_ARG_WITH(
	[pamdir],
	[AS_HELP_STRING([--with-pamdir=PATH],[Specify the directory where PAM modules are stored])],
	[pamdir="${withval}"],
	[
		if test "${prefix}" = "/usr"; then
			pamdir="/lib${libdir##*/lib}/security"
		else
			pamdir="\$(libdir)/security"
		fi
	]
)

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION(0.18.3)

dnl Add the languages which your application supports here.
ALL_LINGUAS="de"

dnl Checks for programs.
AC_PROG_CPP

dnl Add libtool support.
ifdef(
	[LT_INIT],
	[LT_INIT],
	[AC_PROG_LIBTOOL]
)

if test -z "${PAM_LIBS}"; then
	AC_ARG_VAR([PAM_CFLAGS], [C compiler flags for pam])
	AC_ARG_VAR([PAM_LIBS], [linker flags for pam])
	AC_CHECK_LIB(
		[pam],
		[pam_authenticate],
		[PAM_LIBS="-lpam"],
		[AC_MSG_ERROR([Cannot find pam])]
	)
fi
AC_CHECK_HEADERS([security/pam_modules.h security/_pam_macros.h security/pam_modutil.h], [], [],
  [#include <sys/types.h>
   #include <security/pam_appl.h>])

AC_SEARCH_LIBS([pam_modutil_drop_priv], ["pam"], [AC_DEFINE([HAVE_PAM_MODUTIL_DROP_PRIV], [1], [Define to 1 if pam supports pam_modutil_drop_priv])])
AC_CHECK_FUNCS([strnstr])

dnl 7.8.1 is the first version to support curl_easy_*
LIBCURL_CHECK_CONFIG([], [7.39.0], [], [AC_MSG_ERROR([Cannot find curl])])

saved_CFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} ${PAM_CFLAGS} ${LIBCURL_CPPFLAGS}"
LIBS="$LIBS ${PAM_LIBS} ${LIBCURL}"

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([ \
	string.h syslog.h fcntl.h unistd.h security/pam_ext.h \
])
AC_TYPE_SIZE_T
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_VPRINTF

CFLAGS="${saved_CFLAGS}"
LIBS="$saved_LIBS"

AC_SUBST([pamdir])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([eid-pam has been configured with the following options:

Version:                 ${PACKAGE_VERSION}

Binaries:                $(eval eval eval echo "${bindir}")
Libraries:               $(eval eval eval echo "${libdir}")
PAM modules:             ${pamdir}

Host:                    ${host}
Compiler:                ${CC}
Preprocessor flags:      ${CPPFLAGS}
Compiler flags:          ${CFLAGS}
Linker flags:            ${LDFLAGS}
Libraries:               ${LIBS}

PAM_CFLAGS:              ${PAM_CFLAGS}
PAM_LIBS:                ${PAM_LIBS}
LIBCURL_CPPFLAGS:        ${LIBCURL_CPPFLAGS}
LIBCURL:                 ${LIBCURL}
])
