/*
 * types.c
 */

#include "pgpdump.h"

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#if HAVE_STRUCT_TM_TM_ZONE
# define tm_zone(tm) (tm->tm_zone)
#elif HAVE_TZNAME
# define tm_zone(tm) (tzname[tm->tm_isdst])
#elif __MINGW32__
# define tm_zone(tm) (tzname[tm->tm_isdst])
#else
# ifndef tzname  /* For SGI. */
  extern string tzname[]; /* RS6000 and others reject char **tzname. */
# endif
# define tm_zone(tm) (tzname[tm->tm_isdst])
#endif

private void time4_base(string, time_t *);
private time_t key_creation_time = 0;
private time_t sig_creation_time = 0;

/*
 * 2021-11-02, "pub 18" description updated
 * Reference: RFC 6637 (June 2012)
 */
private string
PUB_ALGS[] = {
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
	"DSA Digital Signature Algorithm(pub 17)",
	"ECDH Elliptic Curve Diffie-Hellman Algorithm(pub 18)",
	"ECDSA Elliptic Curve Digital Signature Algorithm(pub 19)",
	"Reserved formerly ElGamal Encrypt or Sign(pub 20)",
	"Reserved for Diffie-Hellman (pub 21)",
	"EdDSA Edwards-curve Digital Signature Algorithm(pub 22)",
	"Reserved - AEDH",
	"Reserved - AEDSA",
};
#define PUB_ALGS_NUM (sizeof(PUB_ALGS) / sizeof(string))

public void
pub_algs(unsigned int type)
{
	printf("\tPub alg - ");
	if (type < PUB_ALGS_NUM)
		printf("%s", PUB_ALGS[type]);
	else
		printf("unknown(pub %d)", type);
	printf("\n");
}

private string
SYM_ALGS[] = {
	"Plaintext or unencrypted data(sym 0)",
	"IDEA(sym 1)",
	"Triple-DES(sym 2)",
	"CAST5(sym 3)",
	"Blowfish(sym 4)",
	"Reserved(sym 5)",
	"Reserved(sym 6)",
	"AES with 128-bit key(sym 7)",
	"AES with 192-bit key(sym 8)",
	"AES with 256-bit key(sym 9)",
	"Twofish with 256-bit key(sym 10)",
	"Camellia with 128-bit key(sym 11)",
	"Camellia with 192-bit key(sym 12)",
	"Camellia with 256-bit key(sym 13)",
};
#define SYM_ALGS_NUM (sizeof(SYM_ALGS) / sizeof(string))

public void
sym_algs(unsigned int type)
{
	printf("\tSym alg - ");
	sym_algs2(type);
	printf("\n");
}

public void
sym_algs2(unsigned int type)
{
	if (type < SYM_ALGS_NUM)
		printf("%s", SYM_ALGS[type]);
	else
		printf("unknown(sym %d)", type);
}

private int
IV_LEN[] = {
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
	16,	/* Camellia-128 */
	16,	/* Camellia-192 */
	16,	/* Camellia-256 */
};

public int
iv_len(unsigned int type)
{
	if (type < SYM_ALGS_NUM)
		return IV_LEN[type];
	else
		return 0;
}

private string
COMP_ALGS[] = {
	"Uncompressed(comp 0)",
	"ZIP <RFC1951>(comp 1)",
	"ZLIB <RFC1950>(comp 2)",
	"BZip2(comp 3)",
};
#define COMP_ALGS_NUM (sizeof(COMP_ALGS) / sizeof(string))

public void
comp_algs(unsigned int type)
{
	printf("\tComp alg - ");
	if (type < COMP_ALGS_NUM)
		printf("%s", COMP_ALGS[type]);
	else
		printf("unknown(comp %d)", type);
	printf("\n");
}

/*
 * Added: 2021-11-28
 * Reference: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-9.6
 * Section "9.6. AEAD Algorithms"
 */
private string
AEAD_ALGS[] = {
	"unknown(aead 0)",
	"EAX(aead 1)",
	"OCB(aead 2)",
};
#define AEAD_ALGS_NUM (sizeof(AEAD_ALGS) / sizeof(string))

public void
aead_algs(unsigned int type)
{
	printf("\tAEAD alg - ");
	if (type < AEAD_ALGS_NUM)
		printf("%s", AEAD_ALGS[type]);
	else
		printf("unknown(aead %d)", type);
	printf("\n");
}

private string
HASH_ALGS[] = {
	"unknown(hash 0)",
	"MD5(hash 1)",
	"SHA1(hash 2)",
	"RIPEMD160(hash 3)",
	"Reserved(hash 4)",
	"Reserved(hash 5)",
	"Reserved(hash 6)",
	"Reserved(hash 7)",
	"SHA256(hash 8)",
	"SHA384(hash 9)",
	"SHA512(hash 10)",
	"SHA224(hash 11)",
	"SHA3-256(hash 12)",
	"Reserved(hash 13)",
	"SHA3-512(hash 14)",
};
#define HASH_ALGS_NUM (sizeof(HASH_ALGS) / sizeof(string))

public void
hash_algs(unsigned int type)
{
	printf("\tHash alg - ");
	if (type < HASH_ALGS_NUM)
		printf("%s", HASH_ALGS[type]);
	else
		printf("unknown(hash %d)", type);
	printf("\n");
}

public void
key_id(void)
{
	printf("\tKey ID - ");
	kdump(8);
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
time4_base(string str, time_t *pt)
{
	struct tm* ptm;
	char* pat;
	char* pyr;

	if (*pt < 0) {  /* 32 bit time_t and after 2038-01-19 */
		printf("\t%s - cannot print date after 2038-01-19\n", str);
		return;
	}

	ptm = uflag ? gmtime(pt) : localtime(pt);

	pat = asctime(ptm);
	pat[19] = 0;
	pyr = pat + 20;

	if (uflag)
		printf("\t%s - %s UTC %s", str, pat, pyr);
	else
		printf("\t%s - %s %s %s", str, pat, tm_zone(ptm), pyr);
}

public void
time4(string str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();

	time4_base(str, &t);
}

public void
sig_creation_time4(string str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();

	sig_creation_time = t;

	time4_base(str, &t);
}

public void
sig_expiration_time4(string str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();

	t += sig_creation_time;

	time4_base(str, &t);
}

public void
key_creation_time4(string str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();

	key_creation_time = t;

	time4_base(str, &t);
}

public void
key_expiration_time4(string str)
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

public int
string_to_key(void)
{
	int has_iv = YES;
	int type = Getc();
	int hash = Getc();

	switch (type) {
	case 0:
		printf("\tSimple string-to-key(s2k %d):\n", type);
		printf("\t");
		hash_algs(hash);
		break;
	case 1:
		printf("\tSalted string-to-key(s2k %d):\n", type);
		printf("\t");
		hash_algs(hash);
		printf("\t\tSalt - ");
		dump(8);
		printf("\n");
		break;
	case 2:
		printf("\tReserved string-to-key(s2k %d)\n", type);
		break;
	case 3:
		printf("\tIterated and salted string-to-key(s2k %d):\n", type);
		printf("\t");
		hash_algs(hash);
		printf("\t\tSalt - ");
		dump(8);
		printf("\n");
		{
			int count, c = Getc();
			count = (16 + (c & 15)) << ((c >> 4) + EXPBIAS);
			printf("\t\tCount - %d(coded count %d)\n", count, c);
		}
		break;
	case 101:
		has_iv = NO;
		{
			char temp[4];
			int j, snlen;
			for (j = 0; j < 4; j++) temp[j] = Getc();
			if (!memcmp(temp, "GNU", 3)) {
				type = 1000 + temp[3];
				switch (type) {
					case 1001:
						printf("\tGnuPG gnu-dummy (s2k %d)\n", type);
						break;
					case 1002:
						snlen = Getc();
						printf("\tGnuPG gnu-divert-to-card (s2k %d)\n\tSerial Number: ", type);
						dump(snlen);
						puts ("");
						break;
					default:
						printf("\tGnuPG unknown extension (s2k %d)\n", type);
						break;
				}
			} else {
				printf("\tPrivate/experimental string-to-key(s2k %d)\n", type);
			}
		}
		break;
	default:
		printf("\tUnknown string-to-key(s2k %d)\n", type);
	}
	return has_iv;
}

public void
multi_precision_integer(string str)
{
        int bytes;
        int bits = Getc() * 256;
        bits += Getc();
        bytes = (bits + 7) / 8;

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
