/*
 * uncompress.c
 * NOT YET IMPLEMENTED
 */

/* 
 * 0 uncompressed
 * 1 ZIP 1951 without zlib header
 *	inflateInit2 (strm, -13)
 *	inflateInit2_(strm, -13, ZLIB_VERSION, sizeof(z_stream))
 * 2 ZLIB 1950 with zlib header
 *	inflateInit  (strm)
 *	inflateInit_ (strm, ZLIB_VERSION, sizeof(z_stream))
 *	inflateInit2_(strm, DEF_WBITS(15?), ZLIB_VERSION, sizeof(z_stream))
 */

#include <stdio.h>
#include <zlib.h>
#include <unistd.h>
#include "pgpdump.h"

public void
Compressed_Data_Packet(int len) 
{
#ifdef HAVE_ZLIB
	int alg = Getc();
	int ilen = BUFSIZ, olen = BUFSIZ * 8;
	int err = 0, inflated = 0;
	char ibuf[ilen], obuf[olen], *outfile;
	FILE *input = Get_input_file(), *output;
	z_stream z;
	
	comp_algs(alg);

	z.zalloc = (alloc_func)0;
	z.zfree = (free_func)0;
	z.opaque = (voidpf)0;

	switch (alg) {
	case 0:
		return;
	case 1:
		err = inflateInit2(&z, -13);
		break;
	case 2:
		err = inflateInit(&z);
		break;
	default:
		error("unknown compress algorithm.");
	}

	if (err != Z_OK)
		error("inflateInit error.");

	output = Get_temp_file(&outfile);
	
	z.avail_in = 0;
	z.next_out = obuf;
	z.avail_out = olen;

	do {
		if (z.avail_in == 0) {
			ilen = fread(ibuf, sizeof(char), ilen, input);
			z.next_in  = ibuf;
			z.avail_in = ilen;
		}

		err = inflate(&z, Z_SYNC_FLUSH);
		if (err == Z_BUF_ERROR) break; /* xxx */
		if (err != Z_OK && err != Z_STREAM_END) {
			unlink(outfile);
			error("inflate error.");
		}

		inflated = olen - z.avail_out;
		if (inflated > 0) {
			fwrite(obuf, sizeof(char), inflated, output);
			z.next_out = obuf;
			z.avail_out = olen;
		}
	} while (err != Z_STREAM_END);

	if (inflateEnd(&z) != Z_OK) {
		unlink(outfile);
		error("inflateEnd error");
	}

	fclose(input);
	fclose(output);
	if ((output = fopen(outfile, "r")) == NULL) {
		unlink(outfile);
		error("can't reopen the stream.");
	}

	Set_input_file(output);
	unlink(outfile);
#else /* HAVE_ZLIB */
	comp_algs(Getc());
	error("Can't uncompress without zlib.");
#endif /* HAVE_ZLIB */
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
