#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([logactiond], 0.2, [info@logactiond.org])
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
AC_CHECK_LIB([config], [config_set_include_func])
AM_CONDITIONAL([USE_LIBCONFIG], [test "$ac_cv_lib_config_config_set_include_func" = yes])
AC_CHECK_LIB([resolv], [inet_net_pton])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h stdlib.h string.h syslog.h unistd.h fcntl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([regcomp strdup strerror strndup strrchr ftruncate strcasecmp fcntl])

ACX_PTHREAD

AC_CHECK_FUNCS([inotify_init],
  [AC_DEFINE([HAVE_INOTIFY], [1],
    [Define to 1 if you have usable inotify support.])])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
#lib/Makefile
AC_OUTPUT
