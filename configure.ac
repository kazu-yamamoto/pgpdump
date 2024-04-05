dnl Process this file with autoconf to produce a configure script.
AC_INIT
AC_CONFIG_SRCDIR([pgpdump.c])

dnl Checks for programs.
dnl AC_PROG_INSTALL

dnl Checks for libraries.
AC_CHECK_LIB(z, inflate)
AC_CHECK_LIB(bz2, BZ2_bzBuffToBuffDecompress)

dnl Checks for header files.
AC_CONFIG_HEADERS([config.h])
m4_warn([obsolete],
[The preprocessor macro `STDC_HEADERS' is obsolete.
  Except in unusual embedded environments, you can safely include all
  ISO C90 headers unconditionally.])dnl
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP

AC_CHECK_HEADERS(unistd.h)
AC_CHECK_HEADERS(sys/time.h)
AC_CHECK_HEADERS(unixlib/local.h)
m4_warn([obsolete],
[Update your code to rely only on HAVE_SYS_TIME_H,
then remove this warning and the obsolete code below it.
All current systems provide time.h; it need not be checked for.
Not all systems provide sys/time.h, but those that do, all allow
you to include it and time.h simultaneously.])dnl
AC_CHECK_HEADERS_ONCE([sys/time.h])
# Obsolete code to be removed.
if test $ac_cv_header_sys_time_h = yes; then
  AC_DEFINE([TIME_WITH_SYS_TIME],[1],[Define to 1 if you can safely include both <sys/time.h>
	     and <time.h>.  This macro is obsolete.])
fi
# End of obsolete code.


dnl Checks for typedefs, structures, and compiler characteristics.
AC_STRUCT_TIMEZONE

dnl Checks for library functions.

AC_SYS_LARGEFILE

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
