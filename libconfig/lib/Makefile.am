
# Versioning rules ( C:R:A )
#
# Perform EACH step that applies.
#
# 1. Start with version 0:0:0.
# 2. If any of the sources have changed, increment R. This is a new revision
#    of the current interface.
# 3. If the interface has changed, increment C and set R to 0. This is the
#    first revision of a new interface.
# 4. If the interface has changed, and the new interface is a superset of the
#    previous interface (that is, if the previous interface has not been
#    broken by the changes in this new release), increment A. This release is
#    backwards compatible with the previous release.
# 5. If the new interface has removed elements with respect to the
#    previous interface, then backward compatibility is broken; set A to 0.
#    This release has a new, but backwards incompatible interface.
#
# For more info see section 6.3 of the GNU Libtool Manual.

VERINFO = -version-info 11:2:0

## Flex
PARSER_PREFIX = libconfig_yy
AM_LFLAGS = --header-file=scanner.h --prefix=$(PARSER_PREFIX)

## Bison
AM_YFLAGS = -d -p $(PARSER_PREFIX)


libsrc = grammar.y libconfig.c parsectx.h scanctx.c scanctx.h scanner.l \
    strbuf.c strbuf.h strvec.c strvec.h util.c util.h wincompat.c wincompat.h libconfig.h

BUILT_SOURCES = scanner.c scanner.h grammar.c grammar.h

noinst_LTLIBRARIES = libconfig.la

libconfig_la_SOURCES = $(libsrc)

libcppflags = -D_REENTRANT

libconfig_la_CPPFLAGS = -DPARSER_PREFIX=\"$(PARSER_PREFIX)\" $(libcppflags)

libconfig_la_LDFLAGS = $(VERINFO) -no-undefined

EXTRA_DIST = \
	$(BUILT_SOURCES) \
	libconfigcpp.cc libconfig.hh \
	*.vcproj \
	*.vcxproj

