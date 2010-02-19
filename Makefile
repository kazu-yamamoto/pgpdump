INCS = pgpdump.h
SRCS = pgpdump.c types.c tagfuncs.c packet.c subfunc.c signature.c keys.c \
       armor.c uncompress.c
OBJS = pgpdump.o types.o tagfuncs.o packet.o subfunc.o signature.o keys.o \
       armor.o uncompress.o
PROG = pgpdump

#LIBS = -lz
#DEFS = -DHAVE_ZLIB
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
