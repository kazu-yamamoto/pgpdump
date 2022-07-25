/*
 * pgpdump.c
 */

#include "pgpdump.h"
#include <stdarg.h>

int aflag;
int dflag;
int gflag;
int iflag;
int lflag;
int mflag;
int pflag;
int uflag;

private string pgpdump_version = "0.35, Copyright (C) 1998-2022 Kazu Yamamoto";
private string prog;

private string getprog(void);
private void setprog(string);

private void usage(void);
private void version(void);

private string
getprog() {
	return prog;
}

#ifdef HAVE_UNIXLIB_LOCAL_H
#include <unixlib/local.h>
int __riscosify_control = __RISCOSIFY_NO_PROCESS;
#define PATH_SEPC '.'
#else  /* HAVE_UNIXLIB_LOCAL_H */
#define PATH_SEPC '/'
#endif /* HAVE_UNIXLIB_LOCAL_H */

private void
setprog(string p) {
	if ((prog = strrchr(p, PATH_SEPC)) == NULL)
		prog = p;
	else
		prog++;
}

private void
usage(void)
{
	string prog = getprog();
	fprintf(stderr, "%s -h|-v\n", prog);
	fprintf(stderr, "%s [-agilmpu] [PGPfile]\n", prog);
	fprintf(stderr, "\t -h -- displays this help\n");
	fprintf(stderr, "\t -v -- displays version\n");
	fprintf(stderr, "\t -a -- accepts ASCII input only\n");
	fprintf(stderr, "\t -g -- selects alternate dump format\n");
	fprintf(stderr, "\t -i -- dumps integer packets\n");
	fprintf(stderr, "\t -l -- dumps literal packets\n");
	fprintf(stderr, "\t -m -- dumps marker packets\n");
	fprintf(stderr, "\t -p -- dumps private packets\n");
	fprintf(stderr, "\t -u -- displays UTC time\n");
	exit(EXIT_SUCCESS);
}

public void
warning(const string fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", getprog());
	va_start(ap, fmt);
	if (fmt != NULL)
                vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

public void
warn_exit(const string fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", getprog());
	va_start(ap, fmt);
	if (fmt != NULL)
                vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

private void
version(void)
{
	fprintf(stderr, "%s version %s\n", getprog(), pgpdump_version);
	exit(EXIT_SUCCESS);
}

int
main(int argc, string argv[])
{
        int c;
	aflag = 0;
	gflag = 0;
	iflag = 0;
	lflag = 0;
	mflag = 0;
	pflag = 0;
	uflag = 0;

	setprog(argv[0]);

	while ((c = getopt(argc, argv, "hvagilmpu")) != -1)
		switch (c){
		case 'h':
			usage();
			break;
		case 'v':
			version();
			break;
		case 'a':
			aflag++;
			break;
		case 'g':
			gflag++;
			break;
		case 'i':
			iflag++;
			break;
		case 'l':
			lflag++;
			break;
		case 'm':
			mflag++;
			break;
		case 'p':
			pflag++;
			break;
		case 'u':
			uflag++;
			break;
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

        if (argc > 0) {
	        string target = argv[0];
		if (freopen(target, "rb", stdin) == NULL)
			warn_exit("can't open %s.", target);
        }

	parse_packet();
	exit(EXIT_SUCCESS);
}

public void
skip(int len)
{
        int i;
        for (i = 0; i < len; i++)
                Getc();
}

public void
dump(int len)
{
        if (gflag)
                gdump(len);
        else {
                int i;
                for (i = 0; i < len; i++)
                        printf("%02x ", Getc());
        }
}

public void
pdump(int len)
{
        if (gflag)
                gdump(len);
        else {
                int i;
                for (i = 0; i < len; i++)
                        printf("%c", Getc());
        }
}

public void
kdump(int len)
{
        int i;
        printf("0x");
        for (i = 0; i < len; i++)
                printf("%02X", Getc());
}

public void
gdump(int len) /* mixed dump (like GnuPG) */
{
        int i;
        for (i = 0; i < len; i++) {
                int c = Getc();
		if (isprint(c) == NO)
			printf("\\x%02x", c);
		else
			printf("%c", c);
        }
}

/*
 * Copyright (C) 1998 Kazuhiko Yamamoto
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
