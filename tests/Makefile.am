AUTOMAKE_OPTIONS = subdir-objects
TESTS = check_misc check_addresses check_commands check_properties check_patterns check_endqueue #check_crypto
check_PROGRAMS = check_misc check_addresses check_commands check_properties check_patterns check_endqueue #check_crypto
MY_CFLAGS = -g -Wall -fprofile-arcs -ftest-coverage

check_misc_SOURCES = check_misc.c $(top_builddir)/src/misc.h 
check_misc_CFLAGS = $(PTHREAD_CFLAGS) $(CFLAGS) $(CHECK_CFLAGS) $(MY_CFLAGS)
check_misc_LDADD = $(top_builddir)/src/logactiond-addresses.o $(top_builddir)/src/logactiond-logging.o $(top_builddir)/src/logactiond-nodelist.o $(top_builddir)/src/logactiond-misc.o $(CHECK_LIBS)

check_addresses_SOURCES = check_addresses.c
check_addresses_CFLAGS = $(PTHREAD_CFLAGS) $(CFLAGS) $(CHECK_CFLAGS) $(MY_CFLAGS)
check_addresses_LDADD = $(top_builddir)/src/logactiond-logging.o $(top_builddir)/src/logactiond-nodelist.o $(top_builddir)/src/logactiond-misc.o $(CHECK_LIBS)

check_commands_SOURCES = check_commands.c
check_commands_CFLAGS = $(PTHREAD_CFLAGS) $(CFLAGS) $(CHECK_CFLAGS) $(MY_CFLAGS)
check_commands_LDADD = $(top_builddir)/src/logactiond-logging.o $(top_builddir)/src/logactiond-nodelist.o $(top_builddir)/src/logactiond-misc.o $(CHECK_LIBS)  $(top_builddir)/src/logactiond-addresses.o $(top_builddir)/src/logactiond-properties.o # $(top_builddir)/src/logactiond-rules.o $(top_builddir)/src/logactiond-patterns.o $(top_builddir)/src/logactiond-endqueue.o $(top_builddir)/src/logactiond-remote.o $(top_builddir)/src/logactiond-sources.o $(top_builddir)/src/logactiond-dnsbl.o $(top_builddir)/src/logactiond-messages.o
#check_commands_LDADD = $(top_builddir)/src/logactiond-addresses.o $(top_builddir)/src/logactiond-properties.o $(top_builddir)/src/logactiond-rules.o $(top_builddir)/src/logactiond-patterns.o $(top_builddir)/src/logactiond-sources.o $(top_builddir)/src/logactiond-endqueue.o $(top_builddir)/src/logactiond-remote.o $(top_builddir)/src/logactiond-logging.o $(top_builddir)/src/logactiond-nodelist.o $(top_builddir)/src/logactiond-misc.o $(CHECK_LIBS)

check_endqueue_SOURCES = check_endqueue.c
check_endqueue_CFLAGS = $(PTHREAD_CFLAGS) $(CFLAGS) $(CHECK_CFLAGS) $(MY_CFLAGS)
check_endqueue_LDADD = $(top_builddir)/src/logactiond-logging.o $(top_builddir)/src/logactiond-nodelist.o $(top_builddir)/src/logactiond-misc.o $(top_builddir)/src/logactiond-addresses.o $(top_builddir)/src/logactiond-properties.o $(CHECK_LIBS)

check_properties_SOURCES = check_properties.c $(top_builddir)/src/properties.h 
check_properties_CFLAGS = $(PTHREAD_CFLAGS) $(CFLAGS) $(CHECK_CFLAGS) $(MY_CFLAGS)
check_properties_LDADD = $(top_builddir)/src/logactiond-logging.o $(top_builddir)/src/logactiond-nodelist.o $(top_builddir)/src/logactiond-misc.o $(CHECK_LIBS)

check_patterns_SOURCES = check_patterns.c
check_patterns_CFLAGS = $(PTHREAD_CFLAGS) $(CFLAGS) $(CHECK_CFLAGS) $(MY_CFLAGS)
check_patterns_LDADD = $(top_builddir)/src/logactiond-properties.o $(top_builddir)/src/logactiond-logging.o $(top_builddir)/src/logactiond-nodelist.o $(top_builddir)/src/logactiond-misc.o $(CHECK_LIBS)

#check_crypto_SOURCES = check_crypto.c
#check_crypto_CFLAGS = $(PTHREAD_CFLAGS) $(LIBSODIUM_CFLAGS) $(CFLAGS) $(CHECK_CFLAGS) $(MY_CFLAGS)
#check_crypto_LDADD = $(top_builddir)/src/logactiond-addresses.o $(top_builddir)/src/logactiond-properties.o $(top_builddir)/src/logactiond-logging.o $(top_builddir)/src/logactiond-nodelist.o $(top_builddir)/src/logactiond-misc.o $(CHECK_LIBS)
#check_crypto_LDFLAGS = $(LIBSODIUM_LIBS) $(LIBS)
