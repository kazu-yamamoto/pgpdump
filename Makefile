# comment out unless you have zlib.
DEFS = -DHAVE_ZLIB
LIBS = -lz

INCS = pgpdump.h
SRCS = pgpdump.c types.c tagfuncs.c packet.c subfunc.c signature.c keys.c \
       armor.c uncomp.c
OBJS = pgpdump.o types.o tagfuncs.o packet.o subfunc.o signature.o keys.o \
       armor.o uncomp.o
PROG = pgpdump

CFLAGS = -O -Wall
BINDIR = /usr/local/bin
RM = rm -f

.c.o:
	$(CC) -c $(CFLAGS) $(DEFS) $<

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG) $(OBJS) $(LIBS)

clean:
	$(RM) $(OBJS) $(PROG)

install:
	install -c -m 555 $(PROG) $(BINDIR)
