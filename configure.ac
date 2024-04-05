dnl Process this file with autoconf to produce a configure script.
AC_INIT
AC_CONFIG_SRCDIR([pgpdump.c])

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
