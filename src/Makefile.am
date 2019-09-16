if !USE_INSTALLED_LIBCONFIG
  logactiond_LDADD = $(top_srcdir)/libconfig/lib/.libs/libconfig.a
  logactiond_checkrules_LDADD = $(top_srcdir)/libconfig/lib/.libs/libconfig.a
  logactiond_cleanup_LDADD = $(top_srcdir)/libconfig/lib/.libs/libconfig.a
endif


sbin_PROGRAMS = logactiond logactiond-cleanup logactiond-queue
bin_PROGRAMS = logactiond-checkrules
logactiond_SOURCES = logactiond.c logactiond.h configfile.c rules.c patterns.c sources.c misc.c inotify.c nodelist.c nodelist.h properties.c commands.c endqueue.c addresses.c polling.c status.c watch.c systemd.c fifo.c
logactiond_CPPFLAGS = -I$(top_srcdir)/libconfig/lib -DCONF_DIR="\"$(sysconfdir)/logactiond\""
logactiond_CFLAGS = $(PTHREAD_CFLAGS)

logactiond_checkrules_SOURCES = logactiond-checkrules.c logactiond.h addresses.c commands.c configfile.c misc.c nodelist.c nodelist.h patterns.c properties.c rules.c sources.c
logactiond_checkrules_CPPFLAGS = -I$(top_srcdir)/libconfig/lib -DCONF_DIR="\"$(sysconfdir)/logactiond\"" -DNOCOMMANDS -DNOWATCH -DNOMONITORING
logactiond_checkrules_CFLAGS = $(PTHREAD_CFLAGS)

logactiond_cleanup_SOURCES = logactiond-cleanup.c logactiond.h addresses.c commands.c configfile.c misc.c nodelist.c nodelist.h patterns.c properties.c rules.c sources.c endqueue.c
logactiond_cleanup_CPPFLAGS = -I$(top_srcdir)/libconfig/lib -DCONF_DIR="\"$(sysconfdir)/logactiond\"" -DNOWATCH -DNOMONITORING -DONLYCLEANUPCOMMANDS
logactiond_cleanup_CFLAGS = $(PTHREAD_CFLAGS)

logactiond_queue_SOURCES = logactiond-queue.c logactiond.h
logactiond_queue_CPPFLAGS = -I$(top_srcdir)/libconfig/lib


#logactiond_LDADD = $(PTHREAD_LIBS)
#logactiond_LDADD = $(top_srcdir)/lib/libgnu.a $(PTHREAD_LIBS)
#logactiond_CPPFLAGS = -I$(top_srcdir)/lib
#logactiond_LDFLAGS = -Lconfig
