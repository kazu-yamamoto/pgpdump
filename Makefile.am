AM_CFLAGS = -O -Wall
EXTRA_DIST =

bin_PROGRAMS = pgpdump
pgpdump_SOURCES = \
	buffer.c \
	keys.c \
	packet.c \
	pgpdump.c \
	pgpdump.h \
	signature.c \
	subfunc.c \
	tagfuncs.c \
	types.c \
	uatfunc.c
dist_man1_MANS = pgpdump.1

EXTRA_DIST += build-aux/git-version-gen
dist-hook:
	printf %s\\n '$(VERSION)' >'$(distdir)'/.dist-version
