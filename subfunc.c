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
placeholder_for_backward_compatibility(int len)
{
	printf("\t\txxx\n");
	skip(len);
	/* xxx */
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
revocation_key(int len)
{
	int c = Getc();
	printf("\t\tClass - ");
	if (c == 0x80)
		printf("Unrestricted");
	else if (c == 0xc0)
		printf("Sensitive");
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
	int nlen, vlen, human = 0;
	printf("\t\tFlag - ");
	if (Getc() & 0x80)      {
		printf("Human-readable\n");
		human = 1;
	}
	skip(3);
	nlen = Getc() * 256 + Getc();
	vlen = Getc() * 256 + Getc();
	printf("\t\tName - ");
	if (human)
		pdump(nlen);
	else
		dump(nlen);
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
	printf("\t\tFlag - ");
	if (Getc() & 0x80)
		printf("No-modify\n");
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
		printf("\t\tFlag - The private component of this key may have been split by "
					"a secret-sharing mechanism\n");
	if (c & 0x80)
		printf("\t\tFlag - The private component of this key may be in the "
					"possession of more than one person\n");
	if ((c & ~0x60) == 0)
		printf("\t\tFlag - \n");
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
	if (c == 0)
		printf("No reason specified");
	else if (c == 0x01)
		printf("Key is superceded");
	else if (c == 0x02)
		printf("Key material has been compromised");
	else if (c == 0x03)
		printf("Key is retired and no longer used");
	else if (c == 0x20)
		printf("User ID information is no longer valid");
	else
		printf("Unknown reason(%02x)", c);
	printf("\n");
	printf("\t\tComment - ");
	pdump(len - 1);
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
