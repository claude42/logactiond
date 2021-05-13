if !USE_INSTALLED_LIBCONFIG
  logactiond_LDADD = $(top_srcdir)/libconfig/lib/.libs/libconfig.a
  logactiond_checkrules_LDADD = $(top_srcdir)/libconfig/lib/.libs/libconfig.a
  logactiond_cleanup_LDADD = $(top_srcdir)/libconfig/lib/.libs/libconfig.a
endif


sbin_PROGRAMS = logactiond logactiond-cleanup
bin_PROGRAMS = logactiond-checkrules ladc
logactiond_SOURCES = logactiond.c logactiond.h configfile.c configfile.h rules.c rules.h patterns.c patterns.h sources.c sources.h misc.c misc.h inotify.c inotify.h nodelist.c nodelist.h properties.c properties.h commands.c commands.h metacommands.c metacommands.h endqueue.c endqueue.h addresses.c addresses.h polling.c polling.h status.c status.h watch.c watch.h systemd.c systemd.h fifo.c fifo.h remote.c remote.h messages.c messages.h logging.c logging.h dnsbl.c dnsbl.h crypto.c crypto.h state.c state.h ndebug.h binarytree.c binarytree.h
logactiond_CPPFLAGS = -I$(top_srcdir)/libconfig/lib -DCONF_DIR="\"$(sysconfdir)/logactiond\"" -DSTATE_DIR="\"$(sharedstatedir)/logactiond\"" -DRUN_DIR="\"$(runstatedir)\""
logactiond_CFLAGS = $(PTHREAD_CFLAGS) $(LIBSODIUM_CFLAGS) $(CFLAGS)
logactiond_LDFLAGS = $(LIBSODIUM_LIBS) $(LIBS)

logactiond_checkrules_SOURCES = logactiond-checkrules.c logactiond.h addresses.c addresses.h commands.c commands.h configfile.c configfile.h misc.c misc.h nodelist.c nodelist.h patterns.c patterns.h properties.c properties.h rules.c rules.h sources.c sources.h logging.c logging.h ndebug.h binarytree.c binarytree.h
logactiond_checkrules_CPPFLAGS = -I$(top_srcdir)/libconfig/lib -DCONF_DIR="\"$(sysconfdir)/logactiond\"" -DRUN_DIR="\"$(runstatedir)\"" -DNOCOMMANDS -DNOWATCH -DNOMONITORING -DNOCRYPTO -DCLIENTONLY

logactiond_cleanup_SOURCES = logactiond-cleanup.c logactiond.h addresses.c addresses.h commands.c commands.h configfile.c configfile.h misc.c misc.h nodelist.c nodelist.h patterns.c patterns.h properties.c properties.h rules.c rules.h sources.c sources.h endqueue.c endqueue.h logging.c logging.h ndebug.h binarytree.c binarytree.h
logactiond_cleanup_CPPFLAGS = -I$(top_srcdir)/libconfig/lib -DCONF_DIR="\"$(sysconfdir)/logactiond\"" -DRUN_DIR="\"$(runstatedir)\"" -DNOWATCH -DNOMONITORING -DONLYCLEANUPCOMMANDS -DNOCRYPTO -DCLIENTONLY

ladc_SOURCES = ladc.c logactiond.h messages.c messages.h logging.c logging.h misc.c misc.h nodelist.c nodelist.h crypto.c crypto.h ndebug.h addresses.c addresses.h
ladc_CPPFLAGS = -I$(top_srcdir)/libconfig/lib -DCLIENTONLY -DRUN_DIR="\"$(runstatedir)\""
ladc_CFLAGS = $(LIBSODIUM_CFLAGS) $(CFLAGS)
ladc_LDFLAGS = $(LIBSODIUM_LIBS) $(LIBS)

#testerli_CPPFLAGS = -I$(top_srcdir)/libconfig/lib -DCLIENTONLY -DNOCRYPTO -DNOCOMMANDS -DNOWATCH -DNOMONITORING
#testerli_SOURCES = testerli.c logging.c logging.h addresses.c addresses.h nodelist.c misc.c misc.h ndebug.h


#logactiond_LDADD = $(PTHREAD_LIBS)
#logactiond_LDADD = $(top_srcdir)/lib/libgnu.a $(PTHREAD_LIBS)
#logactiond_CPPFLAGS = -I$(top_srcdir)/lib
#logactiond_LDFLAGS = -Lconfig
