/*
 * pgpdump.c
 */

#include "pgpdump.h"

private char *pgpdump_version = "0.06, Copyright (C) 1998-2001 Kazu Yamamoto";
private char *prog;

private void usage(void);
private void version(void);
	
private void
usage(void)
{
	fprintf(stderr, "%s [-h|-m|-l|-i|-p] PGPfile\n", prog);
	fprintf(stderr, "\t -h -- displays this help\n");
	fprintf(stderr, "\t -m -- prints marker\n");
	fprintf(stderr, "\t -l -- prints literal\n");
	fprintf(stderr, "\t -i -- dump integer\n");
	fprintf(stderr, "\t -p -- dump private\n");
	exit(ERROR);
}

public void
error(char *msg)
{
	fprintf(stderr, "%s: %s\n", prog, msg);
	exit(ERROR);
}

private void
version(void)
{
	fprintf(stderr, "%s version %s\n", prog, pgpdump_version);
	exit(ERROR);
}

int
main (int argc, char *argv[])
{
	char *target = NULL;
	FILE *input_stream;

	iflag = 0;
	mflag = 0;
	lflag = 0;
	pflag = 0;
	
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
			default:
				usage();
			}
		} else {
			target=argv[0];
			break;
		}
	}

	if (target == NULL)
		error("no file specified.");
	if ((input_stream = fopen(target, "r")) == NULL)
		error("can't open the file."); 
	Set_input_file(input_stream);
	
	parse_packet();
	exit(SUCCESS);
}

private FILE *input = NULL;
private int MAGIC_COUNT = 0;

public void
Set_input_file(FILE *file)
{
	input = file;
}

public FILE *
Get_input_file(void)
{
	return input;
}

public int
Getc(void)
{
	int c = getc(input);

	MAGIC_COUNT++;
	if (c == EOF) exit(ERROR);
	return c;
}

public int
Getc1(void)
{
	MAGIC_COUNT++;
	return getc(input);
}

public int
Getc_getlen(void)
{
	return MAGIC_COUNT;
}

public void
Getc_resetlen(void)
{
	MAGIC_COUNT = 0;
}

public FILE *
Get_temp_file(char **file_name) {
	int fd;
	char *name = (char *)malloc(BUFSIZ);
	FILE *stream;

	if (name == NULL)
		error("memory exhausted.");

	strcpy(name, "/tmp/pgpdump.XXXXXX");

	if ((fd = mkstemp(name)) == -1)
		error("can't open a temporary file.");

	if ((stream = fdopen(fd, "r+")) == NULL)
		error("can't open a temporary file.");

	*file_name = name;
	return stream;
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
