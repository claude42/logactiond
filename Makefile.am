#SUBDIRS = lib src
SUBDIRS = libconfig src

confdir = $(sysconfdir)/logactiond
dist_conf_DATA = conf/logactiond.cfg conf/remote.cfg

actionsdir = $(confdir)/actions
dist_actions_DATA = conf/actions/*.cfg
dist_actions_SCRIPTS = conf/actions/*-initialize conf/actions/*-shutdown conf/actions/*-begin conf/actions/*-end

rulesdir = $(confdir)/rules
dist_rules_DATA = conf/rules/*

sourcesdir = $(confdir)/sources
dist_sources_DATA = conf/sources/*

testdir = $(confdir)/test
dist_test_DATA = conf/test/*

install-data-local:
	    $(MKDIR_P) $(DESTDIR)$(libdir)/logactiond

EXTRA_DIST = contrib/* README.md 


#ACLOCAL_AMFLAGS = -I m4
#EXTRA_DIST = m4/gnulib-cache.m4

# in EXTRA_DIST sollten auch noch weitere Sachen rein.....
