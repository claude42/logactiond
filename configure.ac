#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([logactiond], 0.1, [logactiond@aw.net])
#AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_SRCDIR([src/logactiond.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SUBDIRS([libconfig])

# Checks for programs.
AC_PROG_CC

#necessary for gnulib
#gl_EARLY
#gl_INIT

# Checks for libraries.
#AC_CHECK_LIB([config], [config_init], , [AC_MSG_ERROR([LIBCONFIG NOT FOUND])])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h stdlib.h string.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([regcomp strdup strerror strndup strrchr])

ACX_PTHREAD

AC_CHECK_FUNCS([inotify_init],
  [AC_DEFINE([HAVE_INOTIFY], [1],
    [Define to 1 if you have usable inotify support.])])

AC_CHECK_LIB([systemd], [sd_journal_open])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
#lib/Makefile
AC_OUTPUT
