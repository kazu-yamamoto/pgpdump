/*
 * packet.c
 */

#include "pgpdump.h"

private int get_new_len(int);
private int is_partial(int);

#define BINARY_TAG_FLAG 0x80
#define NEW_TAG_FLAG    0x40
#define TAG_MASK        0x3f
#define PARTIAL_MASK    0x1f
#define TAG_COMPRESSED     8

#define OLD_TAG_SHIFT      2
#define OLD_LEN_MASK    0x03

#define TAG_NUM 64
private char *
TAG[TAG_NUM] = {
	"Reserved",
	"Public-Key Encrypted Session Key Packet", 
	"Signature Packet", 
	"Symmetric-Key Encrypted Session Key Packet", 
	"One-Pass Signature Packet", 
	"Secret Key Packet", 
	"Public Key Packet", 
	"Secret Subkey Packet", 
	"Compressed Data Packet", 
	"Symmetrically Encrypted Data Packet", 
	"Marker Packet",
	"Literal Data Packet", 
	"Trust Packet", 
	"User ID Packet", 
	"Public Subkey Packet",
	"Symmetrically Encrypted and MDC Packet",  /* xxx */
	"Modification Detection Code Packet",  /* xxx */
	"unknown", /* xxx PHOTO */
	"Symmetrically Encrypted and MDC Packet", /* xxx GPG */
	"Modification Detection Code Packet",     /* xxx GPG */
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"Private",	
	"Private",
	"Private",
	"Private",	
};

private void
(*tag_func[])() = {
	Reserved,
	Public_Key_Encrypted_Session_Key_Packet,
	Signature_Packet,
	Symmetric_Key_Encrypted_Session_Key_Packet,
	One_Pass_Signature_Packet,
	Secret_Key_Packet,
	Public_Key_Packet,
	Secret_Subkey_Packet,
	Compressed_Data_Packet,
	Symmetrically_Encrypted_Data_Packet,
	Marker_Packet,
	Literal_Data_Packet,
	Trust_Packet,
	User_ID_Packet,
	Public_Subkey_Packet,
	NULL, /* xxx */
	NULL, /* xxx */
	NULL, /* xxx */
	Symmetrically_Encrypted_and_MDC_Packet, /* xxx */
	Modification_Detection_Code_Packet, /* xxx */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	Private_Packet,
	Private_Packet,
	Private_Packet,
	Private_Packet,
};
	
#define SUB_NUM 30
private char *
SUB[SUB_NUM] = {
	"unknown(sub 0)",
	"unknown(sub 1)",
	"signature creation time(sub 2)",
	"signature expiration time(sub 3)",
	"exportable certification(sub 4)",
	"trust signature(sub 5)", 
	"regular expression(sub 6)",
	"revocable(sub 7)",
	"unknown(sub 8)",
	"key expiration time(sub 9)",
	"additional decryption key(sub 10) WARNING: see CA-2000-18!!!",
	"preferred symmetric algorithms(sub 11)", 
	"revocation key(sub 12)", 
	"unknown(sub 13)",
	"unknown(sub 14)",
	"unknown(sub 15)",
	"issuer key ID(sub 16)", 
	"unknown(sub 17)",
	"unknown(sub 18)",
	"unknown(sub 19)",
	"notation data(sub 20)",
	"preferred hash algorithms(sub 21)",
	"preferred compression algorithms(sub 22)",
	"key server preferences(sub 23)",
	"preferred key server(sub 24)",
	"primary user id(sub 25)",
	"policy URL(sub 26)", 
	"key flags(sub 27)",
	"signer's user id(sub 28)",
	"reason for revocation(sub 29)",
};

private void
(*sub_func[])() = {
	NULL,
	NULL,
	signature_creation_time, 
	signature_expiration_time, 
	exportable_certification, 
	trust_signature, 
	regular_expression, 
	revocable, 
	NULL, 
	key_expiration_time,
	additional_decryption_key,
	preferred_symmetric_algorithms, 
	revocation_key, 
	NULL, 
	NULL, 
	NULL, 
	issuer_key_ID, 
	NULL, 
	NULL, 
	NULL, 
	notation_data, 
	preferred_hash_algorithms, 
	preferred_compression_algorithms, 
	key_server_preferences, 
	preferred_key_server, 
	primary_user_id, 
	policy_URL, 
	key_flags,
	signer_user_id, 
	reason_for_revocation, 
};

private int
get_new_len(int c)
{
	int len;

	if (c < 192)
		len = c;
	else if (c < 224)
		len = ((c - 192) << 8) + Getc() + 192;
	else if (c == 255)
		len = (Getc() << 24) | (Getc () << 16)
			| (Getc() << 8) | Getc ();
	else
		len = 1 << (c & PARTIAL_MASK);
	return len;
}

private int
is_partial(int c)
{
	if (c < 224 || c == 255)
		return NO;
	else
		return YES;
}

public void
parse_packet(void)
{
	int c, tag, len = 0;
	int partial = NO;

	c = getchar();
	ungetc(c, stdin);
	
	/* If the PGP packet is in the binary raw form, 7th bit of
	 * the first byte is always 1. If it is set, let's assume
	 * it is the binary raw form. Otherwise, let's assume
	 * it is encoded with radix64.
	 */
	if (c & BINARY_TAG_FLAG)
		set_binary();
	else
		set_armor();
	
	while ((c = Getc1()) != EOF) {
		partial = NO;
		tag = c & TAG_MASK;
		if (c & NEW_TAG_FLAG) {
			printf("New: ");
			c = Getc();
			len = get_new_len(c);
			partial = is_partial(c);
		} else {
			int tlen;

			printf("Old: ");
			tlen = c & OLD_LEN_MASK;
			tag >>= OLD_TAG_SHIFT;

			switch (tlen) {
			case 0:
				len = Getc();
				break;
			case 1:
				len = (Getc() << 8) + Getc();
				break;
			case 2:
				len = (Getc() << 24) | (Getc () << 16) |
					(Getc() << 8) | Getc ();
				break;
			case 3:
				if (tag == TAG_COMPRESSED)
					len = 0;
				else
					len = EOF;
				break;
			}
		}
		if (tag < TAG_NUM)
			printf("%s(tag %d)", TAG[tag], tag);
		else
			printf("unknown(tag %d)", tag);

		if (partial == YES)
			printf("(%d bytes) partial start\n", len);
		else if (tag == TAG_COMPRESSED)
			printf("\n");
		else if (len == EOF)
			printf("(until eof)\n");
		else
			printf("(%d bytes)\n", len);

		if (tag < TAG_NUM && tag_func[tag] != NULL)
			(*tag_func[tag])(len);
		else {
			printf("\tUNKNOWN TAG\n");
			skip(len);
		}
		while (partial == YES) {
			printf("New: ");
			c = Getc();
			len = get_new_len(c);
			partial = is_partial(c);
			if (partial == YES)
				printf("\t(%d bytes) partial continue\n", len);
			else
				printf("\t(%d bytes) partial end\n", len);
			skip(len);
		}
		if (len == EOF) return;
	}
}

public void
parse_subpacket(char *prefix, int tlen)
{
	int len, sub;
	
	while (tlen > 0) {
		len = Getc();
		if (len < 192)
			tlen --;
		else if (len < 223) {
			len = ((len - 192) << 8) + Getc() + 192;
			tlen -= 2;
		} else if (len == 255) {
			len = (Getc() << 24) | (Getc () << 16) |
				(Getc() << 8) | Getc ();
			tlen -= 5;
		}
		tlen -= len;
		sub = Getc(); /* len includes this field byte */
		len --;
		if (sub < SUB_NUM)
			printf("\t%s: %s", prefix, SUB[sub]);
		else
			printf("\t%s: unknown(sub %d)", prefix, sub);
		printf("(%d bytes)\n", len);
		if (sub < SUB_NUM && sub_func[sub] != NULL)
			(*sub_func[sub])(len);
		else {
			printf("\tUNKNOWN SUB PARCKET\n");
			skip(len);
		}
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
