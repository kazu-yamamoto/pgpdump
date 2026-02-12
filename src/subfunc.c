/*
 * subfunc.c
 */

#include "pgpdump.h"

public void
signature_creation_time(int len)
{
	printf("\t");
	sig_creation_time4("Time");
}

public void
signature_expiration_time(int len)
{
	printf("\t");
	sig_expiration_time4("Time");
}

public void
exportable_certification(int len)
{
	printf("\t\tExportable - ");
	if (Getc() == 0)
		printf("No");
	else
		printf("Yes");
	printf("\n");
}

public void
trust_signature(int len)
{
	printf("\t\tLevel - ");
	dump(1);
	printf("\n");
	printf("\t\tAmount - ");
	dump(1);
	printf("\n");
}

public void
regular_expression(int len)
{
	printf("\t\tRegex - ");
	pdump(len);
	printf("\n");
}

public void
revocable(int len)
{
	printf("\t\tRevocable - ");
	if (Getc() == 0)
		printf("No");
	else
		printf("Yes");
	printf("\n");
}

public void
key_expiration_time(int len)
{
	printf("\t");
	key_expiration_time4("Time");
}

public void
additional_decryption_key(int len)
{
	int c = Getc();
	printf("\t\tClass - ");
	switch (c) {
	case 0x80:
		printf("Strong request");
		break;
	case 0x0:
		printf("Normal");
		break;
	default:
		printf("Unknown class(%02x)", c);
		break;
	}
	printf("\n");
	printf("\t");
	pub_algs(Getc());
	printf("\t");
	fingerprint();
}

public void
preferred_symmetric_algorithms(int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("\t");
		sym_algs(Getc());
	}
}


public void
preferred_aead_algorithms(int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("\t");
		aead_algs(Getc());
	}
}

public void
revocation_key(int len)
{
	int c = Getc();
	printf("\t\tClass - ");
	if (c & 0x80)
		switch (c) {
		case 0x80:
			printf("Normal");
			break;
		case 0xc0:
			printf("Sensitive");
			break;
		default:
			printf("Unknown class(%02x)", c);
			break;
		}
	else
		printf("Unknown class(%02x)", c);

	printf("\n");
	printf("\t");
	pub_algs(Getc());
	printf("\t");
	fingerprint();
}

public void
issuer_key_ID(int len)
{
	printf("\t");
	key_id();
}

public void
notation_data(int len)
{
	int c, nlen, vlen, human = 0;
	printf("\t\tFlag - ");
	c = Getc();
	switch (c) {
	case 0x80:
		printf("Human-readable");
		human = 1;
		break;
	case 0x0:
		printf("Normal");
		break;
	default:
		printf("Unknown flag1(%02x)", c);
		break;
	}
	c = Getc();
	if (c != 0) printf("Unknown flag2(%02x)", c);
	c = Getc();
	if (c != 0) printf("Unknown flag3(%02x)", c);
	c = Getc();
	if (c != 0) printf("Unknown flag4(%02x)", c);
	printf("\n");
	nlen = Getc() * 256;
	nlen += Getc();
	vlen = Getc() * 256;
	vlen += Getc();
	printf("\t\tName - ");
	pdump(nlen);
	printf("\n");
	printf("\t\tValue - ");
	if (human)
		pdump(vlen);
	else
		dump(vlen);
	printf("\n");
}

public void
preferred_hash_algorithms(int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("\t");
		hash_algs(Getc());
	}
}

public void
preferred_compression_algorithms(int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("\t");
		comp_algs(Getc());
	}
}

public void
key_server_preferences(int len)
{
	int c = Getc();
	printf("\t\tFlag - ");
	switch (c) {
	case 0x80:
		printf("No-modify");
		break;
	case 0x0:
		printf("Normal");
		break;
	default:
		printf("Unknown flag(%02x)", c);
		break;
	}
	printf("\n");
	skip(len - 1);
}

public void
preferred_key_server(int len)
{
	printf("\t\tURL - ");
	pdump(len);
	printf("\n");
}

public void
primary_user_id(int len)
{
	printf("\t\tPrimary - ");
	if (Getc() == 0)
		printf("No");
	else
		printf("Yes");
	printf("\n");
}

public void
policy_URL(int len)
{
	printf("\t\tURL - ");
	pdump(len);
	printf("\n");
}

public void
key_flags(int len)
{
	int c = Getc();
	if (c & 0x01)
		printf("\t\tFlag - This key may be used to certify other keys\n");
	if (c & 0x02)
		printf("\t\tFlag - This key may be used to sign data\n");
	if (c & 0x04)
		printf("\t\tFlag - This key may be used to encrypt communications\n");
	if (c & 0x08)
		printf("\t\tFlag - This key may be used to encrypt storage\n");
	if (c & 0x10)
		printf("\t\tFlag - The private component of this key may have been split by a secret-sharing mechanism\n");
	if (c & 0x20)
		printf("\t\tFlag - This key may be used for authentication\n");
	if (c & 0x80)
		printf("\t\tFlag - The private component of this key may be in the possession of more than one person\n");
	skip(len-1);
}

public void
signer_user_id(int len)
{
	printf("\t");
	User_ID_Packet(len);
}

public void
reason_for_revocation(int len)
{
	int c = Getc();
	printf("\t\tReason - ");
	switch (c) {
	case 0:
		printf("No reason specified");
		break;
	case 1:
		printf("Key is superseded");
		break;
	case 2:
		printf("Key material has been compromised");
		break;
	case 3:
		printf("Key is retired and no longer used");
		break;
	case 32:
		printf("User ID information is no longer valid");
		break;
	default:
		printf("Unknown reason(%2d)", c);
		break;
	}
	printf("\n");
	printf("\t\tComment - ");
	pdump(len - 1);
	printf("\n");
}

public void
features(int len)
{
        int c = Getc();
        if (c & 0x01)
                printf("\t\tFlag - Modification detection (packets 18 and 19)\n");
        if ((c & ~0xfe) == 0)
                printf("\t\tFlag - undefined\n");
        skip(len - 1);
}

public void
signature_target(int len)
{
	printf("\t");
        pub_algs(Getc());
	printf("\t");
        hash_algs(Getc());
	printf("\t\tTarget signature digest(%d bytes)\n", len - 2);
        skip(len - 2);
}

public void
embedded_signature(int len)
{
	Signature_Packet(len);
}

public void
issuer_fingerprint(int len)
{
        int v = Getc();
        len = len-1;
	printf("\t v%d -", v);
        if (v == 4) {
          if (len != 20) {
            printf(" had %d bytes, should have had 20\n", len);
            skip(len);
          } else {
            fingerprint();
          }
        } else {
          printf(" unknown version\n");
          skip(len);
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
