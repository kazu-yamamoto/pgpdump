/*
 * armor.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "pgpdump.h"

#define YES 1
#define NO  1

#define ON  1
#define OFF 0

#define CR 13
#define LF 10

#define PADDING '='
#define EOP -2

#define OOB -1

private int GetChar(FILE *, int);
private void base64_decode(FILE *, FILE *);
	
private char
base256[] = {
	OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB,
    
	OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB,
      /*                                                -                / */
	OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB, OOB,OOB,OOB, 62, OOB,OOB,OOB, 63,
      /*  0   1   2   3    4   5   6   7    8   9                =        */
	 52, 53, 54, 55,  56, 57, 58, 59,  60, 61,OOB,OOB, OOB,OOB,OOB,OOB,
      /*      A   B   C    D   E   F   G    H   I   J   K    L   M   N   O*/
	OOB,  0,  1,  2,   3,  4,  5,  6,   7,  8,  9, 10,  11, 12, 13, 14,
      /*  P   Q   R   S    T   U   V   W    X   Y   Z                     */
	 15, 16, 17, 18,  19, 20, 21, 22,  23, 24, 25,OOB, OOB,OOB,OOB,OOB,
      /*      a   b   c    d   e   f   g    h   i   j   k    l   m   n   o*/
	OOB, 26, 27, 28,  29, 30, 31, 32,  33, 34, 35, 36,  37, 38, 39, 40,
      /*  p   q   r   s    t   u   v   w    x   y   z                     */
	 41, 42, 43, 44,  45, 46, 47, 48,  49, 50, 51,OOB, OOB,OOB,OOB,OOB, 
};


private int
GetChar(FILE *stream, int cannot_be_eof)
{
	int c, ret;
	static int Ineof = OFF;

	if (Ineof == ON)
		return EOF;
    
	do {
		c = getc(stream);
	} while ( c == CR || c == LF);

	if (c == EOF) {
		if (cannot_be_eof == YES)
			error("base64 decoder saw premature EOF.");
		Ineof = ON;
		return(EOF);
	}

	if (c == PADDING)
		return(EOP);
	
	if ((ret = base256[c]) == OOB)
		error("base64 decoder saw an illegal character.");
	
	return(ret);
}

private void
base64_decode(FILE *infile, FILE *outfile)
{
	int c1, c2, c3, c4;
    
	while ((c1 = GetChar(infile, NO)) != EOF) {
		if (c1 == EOP)
			break;
		if ((c2 = GetChar(infile, YES)) == EOP)
			break;
		putc(((c1 << 2) | ((c2 & 0x30) >> 4)), outfile);

		if ((c3 = GetChar(infile, YES)) == EOP)
			break;
		putc((((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2)), outfile);
		
		if ((c4 = GetChar(infile, YES)) == EOP)
			break;
		putc((((c3 & 0x03) << 6) | c4), outfile);
	}
}

public void
armor_decode(void)
{

	FILE *input = Get_input_file();
	FILE *output;
	char buffer[BUFSIZ], outfile[BUFSIZ];

	strcpy(outfile, "/tmp/pgpdump.XXXXXX");

	if (mktemp(outfile) == NULL)
		error("can't open a temporary file.");
	output = fopen(outfile, "w");
	if (output == NULL)
		error("can't open the file."); 

	do {
		fgets(buffer, BUFSIZ, input);
	} while (buffer[0] != CR && buffer[0] != LF);
	
	base64_decode(input, output);

	fclose(input);
	fclose(output);
	Set_input_file(outfile);
	unlink(outfile);
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
