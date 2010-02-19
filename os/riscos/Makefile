# Makefile for RISC OS pgpdump

PGPDUMP=pgpdump-0/20
ZLIB=^.zlib-1/1/4
LIBBZIP2=^.bzip2-1/0/2

CC=cc
LINK=link
MAKE=amu

DEPEND=-depend !Depend
CC_FLAGS=-Wp -throwback -Otime -I$(ZLIB),$(LIBBZIP2),Unix: -JUnix: -D__riscos__ -DHAVE_CONFIG_H
LD_FLAGS=
UNIXLIB=Unix:o.UnixLib

PGPDUMP_OBJS=buffer.o \
	keys.o \
	packet.o \
	pgpdump.o \
	signature.o \
	subfunc.o \
	tagfuncs.o \
	types.o \
	uatfunc.o

.INIT:
	-cdir o

## Rule Patterns ##

.SUFFIXES:	.c .o

.c.o:
	$(CC) $(CC_FLAGS) $(DEPEND) -c -o $@ $<

# Static dependencies:

pgpdump: $(PGPDUMP_OBJS) $(ZLIB).zlib $(LIBBZIP2).libbzip2
	$(LINK) $(LD_FLAGS) -o pgpdump $(PGPDUMP_OBJS) $(ZLIB).zlib $(LIBBZIP2).libbzip2 $(UNIXLIB)
	-squeeze pgpdump

$(ZLIB).zlib:
	dir $(ZLIB)
	amu
	dir ^.$(PGPDUMP)

$(LIBBZIP2).libbzip2:
	dir $(LIBBZIP2)
	amu
	dir ^.$(PGPDUMP)

clean:
	-ifthere pgpdump then wipe pgpdump ~CFR~V
	-ifthere o.* then wipe o.* ~CFR~V

# Dynamic dependencies:
