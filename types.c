/*
 * types.c
 */

#include "pgpdump.h"
#include <time.h>

private void time4_base(char *, time_t *);
private time_t key_creation_time = 0;
private time_t sig_creation_time = 0;

#define PUB_ALGS_NUM 22
private char *
PUB_ALGS[PUB_ALGS_NUM] = {
	"unknown(pub 0)", 
	"RSA Encrypt or Sign(pub 1)",
	"RSA Encrypt-Only(pub 2)",
	"RSA Sign-Only(pub 3)",
	"unknown(pub 4)",
	"unknown(pub 5)", 
	"unknown(pub 6)", 
	"unknown(pub 7)", 
	"unknown(pub 8)", 
	"unknown(pub 9)", 
	"unknown(pub 10)", 
	"unknown(pub 11)", 
	"unknown(pub 12)", 
	"unknown(pub 13)", 
	"unknown(pub 14)", 
	"unknown(pub 15)", 
	"ElGamal Encrypt-Only(pub 16)", 
	"DSA Digital Signature Standard(pub 17)",
	"Reserved for Elliptic Curve(pub 18)", 
	"Reserved for ECDSA(pub 19)", 
	"ElGamal Encrypt or Sign (pub 20)", 
	"X9.42 Diffie-Hellman (pub 21)", 
};

public void
pub_algs(unsigned int type)
{
	printf("\tPub alg - ");
	if (type < PUB_ALGS_NUM)
		printf(PUB_ALGS[type]);
	else
		printf("unknown(pub %d)", type);
	printf("\n");
}

#define SYM_ALGS_NUM 11
private char *
SYM_ALGS[SYM_ALGS_NUM] = {
	"Plaintext or unencrypted data(sym 0)", 
	"IDEA(sym 1)", 
	"Triple-DES(sym 2)",
	"CAST5(sym 3)", 
	"Blowfish(sym 4)", 
	"SAFER-SK128(sym 5)", 
	"DES/SK(sym 6)", 
	"AES with 128-bit key(sym 7)", 
	"AES with 192-bit key(sym 8)", 
	"AES with 256-bit key(sym 9)",
	"Twofish with 256-bit key(sym 10)",
};

public void
sym_algs(unsigned int type)
{
	printf("\tSym alg - ");
	if (type < SYM_ALGS_NUM)
		printf(SYM_ALGS[type]);
	else
		printf("unknown(sym %d)", type);
	printf("\n");
}

private int
IV_LEN[SYM_ALGS_NUM] = {
	0,      /* Plaintext */
	8,	/* IDEA */
	8,	/* Triple-DES */
	8,	/* CAST5 */
	8,	/* Blowfish */
	8,	/* SAFER-SK128 */
	8,	/* Reserved for DES/SK (AES) */
	16,	/* AES-128 */
	16,	/* AES-192 */
	16,	/* AES-256 */
	16,	/* Twofish */
};

public int
iv_len(unsigned int type)
{
	if (type < SYM_ALGS_NUM)
		return IV_LEN[type];
	else
		return 0;
}

#define COMP_ALGS_NUM 3
private char *
COMP_ALGS[] = {
	"Uncompressed(comp 0)",
	"ZIP <RFC1951>(comp 1)", 
	"ZLIB <RFC1950>(comp 2)",
};

public void
comp_algs(unsigned int type)
{
	printf("\tComp alg - ");
	if (type < COMP_ALGS_NUM)
		printf(COMP_ALGS[type]);
	else
		printf("unknown(comp %d)", type);
	printf("\n");
}

#define HASH_ALGS_NUM 8
private char *
HASH_ALGS[] = {
	"unknown(hash 0)",
	"MD5(hash 1)",
	"SHA1(hash 2)",
	"RIPEMD160(hash 3)",
	"double-width SHA(hash 4)",
	"MD2(hash 5)", 
	"TIGER192(hash 6)",
	"HAVAL-5-160(hash 7)",
};

public void
hash_algs(unsigned int type)
{
	printf("\tHash alg - ");
	if (type < HASH_ALGS_NUM)
		printf(HASH_ALGS[type]);
	else
		printf("unknown(hash %d)", type);
	printf("\n");
}

public void
key_id(void)
{
	printf("\tKey ID - ");
	dump(8);
	printf("\n");
}

public void
fingerprint(void)
{
	printf("\tFingerprint - ");
	dump(20);
	printf("\n");
}

private void
time4_base(char *str, time_t *pt)
{
	struct tm* ptm;
	char* pat;
	char* pyr;

	ptm = uflag ? gmtime(pt) : localtime(pt);

	pat = asctime(ptm);
	pat[19] = 0;
	pyr = pat + 20;

	if (uflag)
		printf("\t%s - %s UTC %s", str, pat, pyr); 
	else
		printf("\t%s - %s %s %s", str, pat, tzname[ptm->tm_isdst], pyr); 
}

public void
time4(char *str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();
			
	time4_base(str, &t);
}

public void
sig_creation_time4(char *str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();
	
	sig_creation_time = t;
	
	time4_base(str, &t);
}

public void
sig_expiration_time4(char *str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();
	
	t += sig_creation_time;
	
	time4_base(str, &t);
}

public void
key_creation_time4(char *str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();
	
	key_creation_time = t;
	
	time4_base(str, &t);
}

public void
key_expiration_time4(char *str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();
	
	t += key_creation_time;
	
	time4_base(str, &t);
}

public void
ver(int old, int new, int ver)
{
	printf("\t");
	if (new != NULL_VER && new == ver)
		printf("New");
	else if (old != NULL_VER && old == ver)
		printf("Old");
	else
		printf("Unknown");
	printf(" version(%d)\n", ver);
}

#define EXPBIAS 6

public void
string_to_key(void)
{
	int type = Getc();

	printf("\tString-to-key(s2k %d):\n", type);
	switch (type) {
	case 0x00:
		printf("\t");
		hash_algs(Getc());
		break;
	case 0x01:
		printf("\t");
		hash_algs(Getc());
		printf("\t\tSalt - ");
		dump(8);
		printf("\n");
		break;
	case 0x03:
		printf("\t");
		hash_algs(Getc());
		printf("\t\tSalt - ");
		dump(8);
		printf("\n");
		{
			int count, c = Getc();
			count = (16 + (c & 15)) << ((c >> 4) + EXPBIAS);
			printf("\t\tCount - %d(coded count %d)\n", count, c);
		}
		break;
	default:
		printf("\t\tunknown(s2k %d)\n", type);
	}
}

public void
multi_precision_integer(char *str)
{
	int bits = Getc() * 256 + Getc();
	int bytes = (bits + 7) / 8;
		
	printf("\t%s(%d bits) - ", str, bits);
	if (iflag) {
		dump(bytes);
	} else {
		printf("...");
		skip(bytes);
	}
	printf("\n");
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
