/*
 * keys.c
 */

#include "pgpdump.h"

private int PUBLIC;
private int VERSION;

private void old_Public_Key_Packet(void);
private void new_Public_Key_Packet(int);
private void IV(unsigned int);
private void plain_Secret_Key(int);
private void encrypted_Secret_Key(int, int);

public void
Public_Subkey_Packet(int len) 
{
	Public_Key_Packet(len);
}

public void
Public_Key_Packet(int len) 
{
	VERSION = Getc();
	printf("\tVer %d - ", VERSION);
	switch (VERSION) {
	case 2:
	case 3:
		printf("old\n");
		old_Public_Key_Packet();
		break;
	case 4:
		printf("new\n");
		new_Public_Key_Packet(len - 1);
		break;
	default:
		warn_exit("unknown version (%d).", VERSION);
		break;
	}
}

private void
old_Public_Key_Packet(void)
{
	int days;
	time4("Public key creation time");
	days = Getc();
	days += Getc() * 256;
	printf("\tValid days - %d[0 is forever]\n", days);
	PUBLIC = Getc();
	pub_algs(PUBLIC); /* PUBLIC should be 1 */
	multi_precision_integer("RSA n");
	multi_precision_integer("RSA e");
}

private void
new_Public_Key_Packet(int len)
{
	key_creation_time4("Public key creation time");
	PUBLIC = Getc();
	pub_algs(PUBLIC);
	switch (PUBLIC) {
	case 1:
	case 2:
	case 3:
		multi_precision_integer("RSA n");
		multi_precision_integer("RSA e");
		break;
	case 16:
	case 20:
		multi_precision_integer("ElGamal p");
		multi_precision_integer("ElGamal g");
		multi_precision_integer("ElGamal y");
		break;
	case 17:
		multi_precision_integer("DSA p");
		multi_precision_integer("DSA q");
		multi_precision_integer("DSA g");
		multi_precision_integer("DSA y");
		break;
	default:
		printf("\tUnknown public key(pub %d)\n", PUBLIC);
		skip(len - 5);
		break;
	}
}

private void
IV(unsigned int len)
{
	printf("\tIV - ");
	dump(len);
	printf("\n");
}

public void
Secret_Subkey_Packet(int len) 
{
	Secret_Key_Packet(len);
}

public void
Secret_Key_Packet(int len)
{
	int s2k, sym;

	Getc_resetlen();
	Public_Key_Packet(len);
	s2k = Getc();
	switch (s2k) {
	case 0:
		plain_Secret_Key(len - Getc_getlen());
		break;
	case 254:
		sym = Getc();
		sym_algs(sym);
		string_to_key();
		IV(iv_len(sym));
		encrypted_Secret_Key(len - Getc_getlen(), YES);
		break;
	case 255:
		sym = Getc();
		sym_algs(sym);
		string_to_key();
		IV(iv_len(sym));
		encrypted_Secret_Key(len - Getc_getlen(), NO);
		break;
	default:
		sym = s2k;
		sym_algs(sym);
		IV(iv_len(sym));
		encrypted_Secret_Key(len - Getc_getlen(), NO);
		break;
	}
}

private void
plain_Secret_Key(int len)
{
	switch (VERSION) {
	case 2:
	case 3:
		/* PUBLIC should be 1. */
		multi_precision_integer("Encrypted RSA d");
		multi_precision_integer("Encrypted RSA p");
		multi_precision_integer("Encrypted RSA q");
		multi_precision_integer("Encrypted RSA u");
		printf("\tChecksum - ");
		dump(2);
		printf("\n");
		break;
	case 4:
		switch (PUBLIC) {
		case 1:
		case 2:
		case 3:
			multi_precision_integer("RSA d");
			multi_precision_integer("RSA p");
			multi_precision_integer("RSA q");
			multi_precision_integer("RSA u");
			break;
		case 16:
		case 20:
			multi_precision_integer("ElGamal x");
			break;
		case 17:
			multi_precision_integer("DSA x");
			break;
		default:
			printf("\tUnknown secret key(pub %d)\n", PUBLIC);
			skip(len - 2);
			break;
		}
		printf("\tChecksum - ");
		dump(2);
		printf("\n");
		break;
	default:
		printf("\tunknown version (%d)\n", VERSION);
		skip(len);
		break;
	}
}

private void
encrypted_Secret_Key(int len, int sha1)
{
	switch (VERSION) {
	case 2:
	case 3:
		/* PUBLIC should be 1.
		   MPI prefix count is not encrypted. */
		multi_precision_integer("Encrypted RSA d");
		multi_precision_integer("Encrypted RSA p");
		multi_precision_integer("Encrypted RSA q");
		multi_precision_integer("Encrypted RSA u");
		printf("\tChecksum - ");
		dump(2);
		printf("\n");
		break;
	case 4:
		switch (PUBLIC) {
		case 1:
		case 2:
		case 3:
			printf("\tEncrypted RSA d\n");
			printf("\tEncrypted RSA p\n");
			printf("\tEncrypted RSA q\n");
			printf("\tEncrypted RSA u\n");
			break;
		case 16:
		case 20:
			printf("\tEncrypted ElGamal x\n");
			break;
		case 17:
			printf("\tEncrypted DSA x\n");
			break;
		default:
			printf("\tUnknown encrypted key(pub %d)\n", PUBLIC);
			break;
		}
		if (sha1 == YES)
			printf("\tEncrypted SHA1 hash\n");
		else
			printf("\tEncrypted checksum\n");
		skip(len);
		break;
	default:
		printf("\tunknown version (%d)\n", VERSION);
		skip(len);
		break;
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
