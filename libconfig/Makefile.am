
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = lib 

.PHONY: dist-rpm

dist-rpm: distcheck
	rpmbuild -ta $(distdir).tar.gz

EXTRA_DIST = \
	m4/*.m4 \
	*.sln \
	test.cfg \
	TODO \
	libconfig.spec

dist-hook:
	rm -rf `find $(distdir)/contrib -name .svn`

test:
	cd tests && ./libconfig_tests
