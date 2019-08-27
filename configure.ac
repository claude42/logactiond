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
AM_CONDITIONAL([USE_INSTALLED_LIBCONFIG], [test "$ac_cv_lib_config_config_set_include_func" = yes])
AC_CHECK_LIB([systemd], [sd_journal_open])
AC_CHECK_LIB([resolv], [inet_net_pton])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h stdlib.h string.h syslog.h unistd.h fcntl.h netinet/in.h sys/socket.h pthread_np.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UID_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([regcomp strdup strerror strndup strrchr ftruncate strcasecmp fcntl strtol])

AX_PTHREAD

AC_CHECK_FUNCS([inotify_init],
  [AC_DEFINE([HAVE_INOTIFY], [1],
    [Define to 1 if you have usable inotify support.])])

HOLD_LIBS="$LIBS"
LIBS="-pthread"

AC_MSG_CHECKING([for pthread_setname_np])
AC_LINK_IFELSE(
  [AC_LANG_SOURCE[
    #define _GNU_SOURCE
    #include <pthread.h>
    int main(int argc, char** argv) {
      int ret = pthread_setname_np(pthread_self(), "name");
      return ret;
    }
  ]],
  [AC_DEFINE([HAVE_PTHREAD_SETNAME_NP], [1], [Define if you have pthread_setname_np function.])
  AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])] )

AC_MSG_CHECKING([for pthread_set_name_np])
AC_LINK_IFELSE(
  [AC_LANG_SOURCE[
    #include <pthread.h>
    int main(int argc, char** argv) {
      pthread_set_name_np(pthread_self(), "name");
      return 0;
    }
  ]],
  [AC_DEFINE([HAVE_PTHREAD_SET_NAME_NP], [1], [Define if you have pthread_set_name_np function.])
  AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])] )

LIBS="$HOLD_LIBS"

AC_CHECK_FILE([/run],
  [AC_DEFINE([HAVE_RUN], [1],
    [Define to 1 if you have /run.])])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
#lib/Makefile
AC_OUTPUT
