dnl Process this file with `autoreconf -fviW all` to produce a configure script.
AC_INIT([pgpdump],
  dnl Get the version from Git.  The m4_dquote macro is used instead of quotes to ensure that the
  dnl command is only run once.  The command itself outputs m4 quotes to prevent incidental
  dnl expansion (the m4_esyscmd macro does not quote the command output itself, so the command
  dnl output is subject to expansion).
  m4_dquote(m4_esyscmd([printf "[%s]" "$(build-aux/git-version-gen .dist-version)"])),
  [https://github.com/kazu-yamamoto/pgpdump/issues],
  [],
  [https://www.mew.org/~kazu/proj/pgpdump/])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_AUX_DIR([build-aux])
AC_REQUIRE_AUX_FILE([tap-driver.sh])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects no-define])

dnl Checks for programs.
dnl AC_PROG_INSTALL

dnl Checks for libraries.
AC_CHECK_LIB([z], [inflate])
AC_CHECK_LIB([bz2], [BZ2_bzBuffToBuffDecompress])

dnl Checks for header files.
AC_CONFIG_HEADERS([config.h])

AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([unixlib/local.h])
AC_CHECK_HEADERS_ONCE([sys/time.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_STRUCT_TIMEZONE

dnl Checks for library functions.

AC_SYS_LARGEFILE

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
