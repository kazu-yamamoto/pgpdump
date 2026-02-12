/*
 * signature.c
 */

#include "pgpdump.h"

private void hash2(void);
private void signature_multi_precision_integer(int, int);
private void signature_type(int);
private void new_Signature_Packet(int);
private void old_Signature_Packet(int);

private void
hash2(void)
{
	printf("\tHash left 2 bytes - ");
	dump(2);
	printf("\n");
}
/*
 * (2021-11-25) Added code for signatures #18, #19, and #22
 * Reference: https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-04.html
 */
private void
signature_multi_precision_integer(int pub, int len)
{
	switch (pub) {
	case 1:
	case 2:
	case 3:
		multi_precision_integer("RSA m^d mod n");
		printf("\t\t-> PKCS-1\n");
		break;
	case 16:
	case 20:
		multi_precision_integer("ElGamal a = g^k mod p");
		multi_precision_integer("ElGamal b = (h - a*x)/k mod p - 1");
		break;
	case 17:
		multi_precision_integer("DSA r");
		multi_precision_integer("DSA s");
		printf("\t\t-> hash(DSA q bits)\n");
		break;
        case 18:
		multi_precision_integer("ECDH G");
                break;
        case 19:
		multi_precision_integer("ECDSA r");
		multi_precision_integer("ECDSA s");
                break;
        case 22:
		multi_precision_integer("EdDSA R");
		multi_precision_integer("EdDSA s");
                break;
	default:
		printf("\tUnknown signature(pub %d)\n", pub);
		skip(len);
		break;
	}
}

private void
signature_type(int type)
{
	printf("\tSig type - ");
	switch (type) {
	case 0x00:
		printf("Signature of a binary document(0x00).");
		break;
	case 0x01:
		printf("Signature of a canonical text document(0x01).");
		break;
	case 0x02:
		printf("Standalone signature(0x02).");
		break;
	case 0x10:
		printf("Generic certification of a User ID and Public Key packet(0x10).");
		break;
	case 0x11:
		printf("Persona certification of a User ID and Public Key packet.(0x11)");
		break;
	case 0x12:
		printf("Casual certification of a User ID and Public Key packet(0x12).");
		break;
	case 0x13:
		printf("Positive certification of a User ID and Public Key packet(0x13).");
		break;
	case 0x18:
		printf("Subkey Binding Signature(0x18).");
		break;
	case 0x19:
		printf("Primary Key Binding Signature(0x19).");
		break;
	case 0x1f:
		printf("Signature directly on a key(0x1f).");
		break;
	case 0x20:
		printf("Key revocation signature(0x20).");
		break;
	case 0x28:
		printf("Subkey revocation signature(0x28).");
		break;
	case 0x30:
		printf("Certification revocation signature(0x30).");
		break;
	case 0x40:
		printf("Timestamp signature(0x40).");
		break;
	case 0x50:
		printf("Third-Party Confirmation signature(0x50).");
		break;
	default:
		printf("unknown(%02x)", type);
		break;
	}
	printf("\n");
}

public void
One_Pass_Signature_Packet(int len)
{
	ver(NULL_VER, 3, Getc());
	signature_type(Getc());
	hash_algs(Getc());
	pub_algs(Getc());
	key_id();
	printf("\tNext packet - ");
	if (Getc() == 0)
		printf("another one pass signature");
	else
		printf("other than one pass signature");
	printf("\n");
}

public void
Signature_Packet(int len)
{
	int ver;

	ver = Getc();
	printf("\tVer %d - ", ver);
	switch (ver) {
	case 2:
	case 3:
		printf("old\n");
		old_Signature_Packet(len - 1);
		break;
	case 4:
		printf("new\n");
		new_Signature_Packet(len - 1);
		break;
	default:
		printf("unknown\n");
		skip(len - 1);
		break;
	}
}

private void
old_Signature_Packet(int len)
{
	int pub;

	printf("\tHash material(%d bytes):\n", Getc());
	printf("\t");
	signature_type(Getc());
	printf("\t");
	time4("Creation time");
	key_id();
	pub = Getc();
	pub_algs(pub);
	hash_algs(Getc());
	hash2();
	signature_multi_precision_integer(pub, len - 19);
}

private void
new_Signature_Packet(int len)
{
	int pub, hsplen, usplen;

	signature_type(Getc());
	pub = Getc();
	pub_algs(pub);
	hash_algs(Getc());
	hsplen = Getc() * 256;
	hsplen += Getc();
	parse_signature_subpacket("Hashed Sub", hsplen);
	usplen = Getc() * 256;
	usplen += Getc();
	parse_signature_subpacket("Sub", usplen);
	hash2();
	signature_multi_precision_integer(pub, len - 9 - hsplen - usplen);
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
