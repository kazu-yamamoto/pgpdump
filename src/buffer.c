/*
 * buffer.c
 */

#include <ctype.h>
#include <strings.h>
#include "pgpdump.h"

typedef char * cast_t;

private int line_not_blank(byte *);
private int read_binary(byte *, unsigned int);
private int read_radix64(byte *, unsigned int);
private int decode_radix64(byte *, unsigned int);

#ifdef HAVE_LIBZ
#include <zlib.h>
private int inflate_gzip(byte *, unsigned int);
private z_stream z;
#endif  /* HAVE_LIBZ */

#ifdef HAVE_LIBBZ2
#include <bzlib.h>
private int inflate_bzip2(byte *, unsigned int);
private bz_stream bz;
#endif  /* HAVE_LIBBZ2 */

#define NUL '\0'
#define CR  '\r'
#define LF  '\n'

#define OOB -1
#define EOP -2
#define ELF -3
#define ECR -4
#define SPC -5

private unsigned int MAGIC_COUNT = 0;
private unsigned int AVAIL_COUNT = 0;
private byte *NEXT_IN = NULL;

private int (*d_func1)(byte *, unsigned int);
private int (*d_func2)(byte *, unsigned int);
private int (*d_func3)(byte *, unsigned int);

private byte tmpbuf[BUFSIZ];
private byte d_buf1[BUFSIZ];
private byte d_buf2[BUFSIZ];
private byte d_buf3[BUFSIZ];

private signed char
base256[] = {
	OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB, OOB,SPC,ELF,OOB, OOB,ECR,OOB,OOB,

	OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB,
      /*                                                -                / */
	SPC,OOB,OOB,OOB, OOB,OOB,OOB,OOB, OOB,OOB,OOB, 62, OOB,OOB,OOB, 63,
      /*  0   1   2   3    4   5   6   7    8   9                =        */
	 52, 53, 54, 55,  56, 57, 58, 59,  60, 61,OOB,OOB, OOB,EOP,OOB,OOB,
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
line_not_blank(byte *s)
{
	while (isspace(*s)) {
		if (*s == CR || *s == LF)
			return NO;
		s++;
	}
	return YES;
}

private int
read_binary(byte *p, unsigned int max)
{
	if (feof(stdin)) {
		exit(EXIT_SUCCESS);
	}

	size_t ret = fread(p, sizeof(byte), max, stdin);

	if (ferror(stdin)) {
		warn_exit("error in read_binary");
	}

	return ret;
}

private int
read_radix64(byte *p, unsigned int max)
{
	static int done = NO, found = NO;
	int c, d, out = 0, lf = 0, cr = 0;
	byte *lim = p + max;

	if (done == YES) return 0;

	if (found == NO) {

	again:
		do {
			if (fgets((cast_t)tmpbuf, BUFSIZ, stdin) == NULL)
				warn_exit("can't find PGP armor boundary.");
		} while (strncmp("-----BEGIN PGP", (cast_t)tmpbuf, 14) != 0);

		if (strncmp("-----BEGIN PGP SIGNED", (cast_t)tmpbuf, 21) == 0)
			goto again;

		do {
			if (fgets((cast_t)tmpbuf, BUFSIZ, stdin) == NULL)
				warn_exit("can't find PGP armor.");
		} while (line_not_blank(tmpbuf) == YES);
		found = YES;
	}

	while (p < lim) {
		c = getchar();
		if (c == EOF) {
			done = YES;
			return out;
		}
		if (c >= 128) {
		  continue;
		}
		d = base256[c];
		switch (d) {
		case OOB:
			warning("illegal radix64 character.");
			goto skiptail;
		case EOP:
			/* radix64 surely matches this */
			goto skiptail;
		case ELF:
			if (++lf >= 2) goto skiptail;
			continue;
		case ECR:
			if (++cr >= 2) goto skiptail;
			continue;
		case SPC:
			continue;
		}
		lf = cr = 0;
		*p++ = d;
		out++;
	}
	return out;
 skiptail:
	while (getchar() != EOF);
	done = YES;
	return out;
}

private int
decode_radix64(byte *p, unsigned int max)
{
	static int done = NO;
	static unsigned int avail = 0;
	static byte *q;
	unsigned int i, size, out = 0;
	byte c1, c2, c3, c4, *r, *lim = p + max;

	if (done == YES) return 0;

	while (p + 3 < lim) {
		if (avail < 4) {
			r = q;
			q = d_buf1;
			for (i = 0; i < avail; i++)
				*q++ = *r++;
			size = (*d_func1)(q, sizeof(d_buf1) - avail);
			q = d_buf1;
			avail += size;
			if (size == 0) {
				done = YES;
				switch (avail) {
				case 0:
					return out;
				case 1:
					warning("illegal radix64 length.");
					return out; /* anyway */
				case 2:
					c1 = *q++;
					c2 = *q++;
					*p++ = (c1 << 2) | ((c2 & 0x30) >> 4);
					return out + 1;
				case 3:
					c1 = *q++;
					c2 = *q++;
					c3 = *q++;
					*p++ = (c1 << 2) | ((c2 & 0x30) >> 4);
					*p++ = ((c2 & 0x0f) << 4) |
						((c3 & 0x3c) >> 2);
					return out + 2;
				}
			}
		}

		if (avail >= 4) {
			c1 = *q++;
			c2 = *q++;
			c3 = *q++;
			c4 = *q++;
			*p++ = (c1 << 2) | ((c2 & 0x30) >> 4);
			*p++ = ((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2);
			*p++ = ((c3 & 0x03) << 6) | c4;
			avail -= 4;
			out += 3;
		}
	}
	return out;
}

#ifdef HAVE_LIBZ
private int
inflate_gzip(byte *p, unsigned int max)
{
	static int done = NO;
	int err, size, inflated = 0, old;

	if (done == YES) return 0;

	z.next_out = p;
	z.avail_out = max;

	while (z.avail_out != 0) {
		if (z.avail_in == 0) {
			size = (*d_func2)(d_buf2, sizeof(d_buf2));
			z.next_in  = d_buf2;
			z.avail_in = size;
		}

		old = z.avail_out;
		err = inflate(&z, Z_SYNC_FLUSH);

		if (err != Z_OK && err != Z_STREAM_END)
			warn_exit("zlib inflate error (%d).", err);

		inflated = max - z.avail_out;

		if (old == z.avail_out && z.avail_in != 0)
			break;

		if (err == Z_STREAM_END) {
			done = YES;
			/* 8 bytes (crc and isize) are left. */
			if (inflateEnd(&z) != Z_OK)
				warn_exit("zlib inflateEnd error.");
			break;
		}
	}

	return inflated;
}
#endif /* HAVE_LIBZ */

#ifdef HAVE_LIBBZ2
private int
inflate_bzip2(byte *p, unsigned int max)
{
	static int done = NO;
	int err, size, inflated = 0, old;

	if (done == YES) return 0;

	bz.next_out = (cast_t)p;
	bz.avail_out = max;

	while (bz.avail_out != 0) {
		if (bz.avail_in == 0) {
			size = (*d_func2)(d_buf2, sizeof(d_buf2));
			if (size == 0)
				warn_exit("bzip2 no data for BZ2_bzDecompress");
			bz.next_in  = (cast_t)d_buf2;
			bz.avail_in = size;
		}

		old = bz.avail_out;
		err = BZ2_bzDecompress(&bz);

		if (err != BZ_OK && err != BZ_STREAM_END)
			warn_exit("bzip2 BZ2_bzDecompress error (%d).", err);

		inflated = max - bz.avail_out;

		if (old == bz.avail_out && bz.avail_in != 0)
			break;

		if (err == BZ_STREAM_END) {
			done = YES;
			/* 8 bytes (crc and isize) are left. */
			if (BZ2_bzDecompressEnd(&bz) != BZ_OK)
				warn_exit("bzip2 BZ2_bzDecompressEnd error.");
			break;
		}
	}

	return inflated;
}
#endif /* HAVE_LIBBZ2 */

public int
Getc1(void)
{
	byte c;

	if (AVAIL_COUNT == 0) {
		AVAIL_COUNT = (*d_func3)(d_buf3, sizeof(d_buf3));
		if (AVAIL_COUNT == 0)
			return EOF;
		NEXT_IN = d_buf3;
	}

	AVAIL_COUNT--;
	MAGIC_COUNT++;
	c = *NEXT_IN;
	NEXT_IN++;
	return c;
}

public int
Getc(void)
{
	int c = Getc1();
	if (c == EOF)
		warn_exit("unexpected end of file.");
	return c;
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

public void
set_armor(void)
{
	d_func1 = read_radix64;
	d_func2 = NULL;
	d_func3 = decode_radix64;
}

public void
set_binary(void)
{
	d_func1 = NULL;
	d_func2 = NULL;
	d_func3 = read_binary;
}

/*
 * Assuming Compressed_Data_Packet ends at the end of file
 */

public void
Compressed_Data_Packet(int len)
{
#if defined(HAVE_LIBZ) || defined(HAVE_LIBBZ2)
	unsigned int alg = Getc();
	int err;
	private int (*func)(byte *, unsigned int);

	comp_algs(alg);

#ifdef HAVE_LIBZ
	z.zalloc = (alloc_func)0;
	z.zfree = (free_func)0;
	z.opaque = (voidpf)0;
#endif /* HAVE_LIBZ */
#ifdef HAVE_LIBBZ2
	bz.bzalloc = (void *)0;
	bz.bzfree = (void *)0;
	bz.opaque = (void *)0;
#endif /* HAVE_LIBBZ2 */

	/*
	 * 0 uncompressed
	 * 1 ZIP without zlib header (RFC 1951)
	 *	inflateInit2 (strm, -13)
	 * 2 ZLIB with zlib header (RFC 1950)
	 *	inflateInit  (strm)
	 * 3 BZIP2 (http://sources.redhat.com/bzip2/)
	 */

	switch (alg) {
	case 0:
		return;
#ifdef HAVE_LIBZ
	case 1:
		err = inflateInit2(&z, -13);
		if (err != Z_OK) warn_exit("zlib inflateInit error.");
		func = inflate_gzip;
		break;
	case 2:
		err = inflateInit(&z);
		if (err != Z_OK) warn_exit("zlib inflateInit error.");
		func = inflate_gzip;
		break;
#endif /* HAVE_LIBZ */
#ifdef HAVE_LIBBZ2
	case 3:
		err = BZ2_bzDecompressInit(&bz, 0, 0);
		if (err != BZ_OK) warn_exit("bzip2 BZ2_bzDecompressInit error.");
		func = inflate_bzip2;
		break;
#endif /* HAVE_LIBBZ2 */
	default:
		warn_exit("unknown compress algorithm.");
	}

#ifdef HAVE_LIBZ
	z.next_in  = d_buf2;
	z.avail_in = AVAIL_COUNT;
	z.next_out = 0;
	z.avail_out = sizeof(d_buf2);
#endif /* HAVE_LIBZ */
#ifdef HAVE_LIBBZ2
	bz.next_in  = (cast_t)d_buf2;
	bz.avail_in = AVAIL_COUNT;
	bz.next_out = 0;
	bz.avail_out = sizeof(d_buf2);
#endif /* HAVE_LIBBZ2 */

	memcpy(d_buf2, NEXT_IN, AVAIL_COUNT);
	AVAIL_COUNT = 0;

	if (d_func1 == NULL) {
		d_func1 = NULL;
		d_func2 = read_binary;
		d_func3 = func;
	} else {
		d_func1 = read_radix64;
		d_func2 = decode_radix64;
		d_func3 = func;
	}
#else /* defined(HAVE_LIBZ) || defined(HAVE_LIBBZ2) */
	comp_algs(Getc());
	warn_exit("can't uncompress without zlib/bzip2.");
#endif /* defined(HAVE_LIBZ) || defined(HAVE_LIBBZ2) */
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
