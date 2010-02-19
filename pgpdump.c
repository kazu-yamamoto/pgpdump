/*
 * pgpdump.c
 */

#include "pgpdump.h"
#include <stdarg.h>

private char *pgpdump_version = "0.07, Copyright (C) 1998-2001 Kazu Yamamoto";
private char *prog;

private void usage(void);
private void version(void);
	
private void
usage(void)
{
	fprintf(stderr, "%s -h|-v\n", prog);	
	fprintf(stderr, "%s [-i|-l|-m|-p|-u] [PGPfile]\n", prog);
	fprintf(stderr, "\t -h -- displays this help\n");
	fprintf(stderr, "\t -v -- displays version\n");
	fprintf(stderr, "\t -i -- dumps integer packets\n");
	fprintf(stderr, "\t -l -- prints literal packets\n");
	fprintf(stderr, "\t -m -- prints marker packets\n");
	fprintf(stderr, "\t -p -- dumps private packets\n");
	fprintf(stderr, "\t -u -- displays UTC time\n");
	exit(SUCCESS);
}

public void
warning(const char *fmt, ...)
{
	va_list ap;

	if (prog != NULL)
		fprintf(stderr, "%s: ", prog);
	va_start(ap, fmt);
	if (fmt != NULL)
                vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

public void
warn_exit(const char *fmt, ...)
{
	va_list ap;

	if (prog != NULL)
		fprintf(stderr, "%s: ", prog);
	va_start(ap, fmt);
	if (fmt != NULL)
                vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	exit(ERROR);
}

private void
version(void)
{
	fprintf(stderr, "%s version %s\n", prog, pgpdump_version);
	exit(SUCCESS);
}

int
main(int argc, char *argv[])
{
	char *target = NULL;

	iflag = 0;
	lflag = 0;
	mflag = 0;
	pflag = 0;
	uflag = 0;
	
	if ((prog = strrchr(argv[0], '/')) == NULL)
		prog = argv[0];
	else
		prog++;
	while (--argc > 0) {
		if (**(++argv) == '-'){
			switch (argv[0][1]){
			case 'h':
				usage();
				break;
			case 'v':
				version();
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
		} else {
			target=argv[0];
			break;
		}
	}

	if (target != NULL)
		if (freopen(target, "rb", stdin) == NULL)
			warn_exit("can't open %s.", target); 
	
	parse_packet();
	exit(SUCCESS);
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
