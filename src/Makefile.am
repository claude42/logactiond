sbin_PROGRAMS = logactiond
logactiond_SOURCES = logactiond.c configfile.c rules.c patterns.c sources.c watch.c misc.c inotify.c nodelist.c properties.c commands.c endqueue.c addresses.c
logactiond_LDADD = $(top_srcdir)/libconfig/lib/.libs/libconfig.a
logactiond_CPPFLAGS = -I$(top_srcdir)/libconfig/lib -DCONF_DIR="\"$(sysconfdir)/logactiond\""
logactiond_CFLAGS = $(PTHREAD_CFLAGS)
# because of inet_net_pton
logactiond_LDFLAGS = -lresolv




#logactiond_LDADD = $(PTHREAD_LIBS)
#logactiond_LDADD = $(top_srcdir)/lib/libgnu.a $(PTHREAD_LIBS)
#logactiond_CPPFLAGS = -I$(top_srcdir)/lib
#logactiond_LDFLAGS = -Lconfig
