/*
 * packet.c
 */

#include "pgpdump.h"

typedef void (*funcptr)();

private int get_new_len(int);
private int is_partial(int);

#define BINARY_TAG_FLAG 0x80
#define NEW_TAG_FLAG    0x40
#define TAG_MASK        0x3f
#define PARTIAL_MASK    0x1f
#define TAG_COMPRESSED     8

#define OLD_TAG_SHIFT      2
#define OLD_LEN_MASK    0x03

#define CRITICAL_BIT	0x80
#define CRITICAL_MASK	0x7f

private string
TAG[] = {
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
	"unknown",
	"unknown",
	"User Attribute Packet",
	"Symmetrically Encrypted and MDC Packet",
	"Modification Detection Code Packet",
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
#define TAG_NUM (sizeof(TAG) * sizeof(string))

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
	NULL,
	NULL,
	User_Attribute_Packet,
	Symmetrically_Encrypted_and_MDC_Packet,
	Modification_Detection_Code_Packet,
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

private string
SIGSUB[] = {
	"reserved(sub 0)",
	"reserved(sub 1)",
	"signature creation time(sub 2)",
	"signature expiration time(sub 3)",
	"exportable certification(sub 4)",
	"trust signature(sub 5)",
	"regular expression(sub 6)",
	"revocable(sub 7)",
	"reserved(sub 8)",
	"key expiration time(sub 9)",
	"additional decryption key(sub 10) WARNING: see CA-2000-18!!!",
	"preferred symmetric algorithms(sub 11)",
	"revocation key(sub 12)",
	"reserved(sub 13)",
	"reserved(sub 14)",
	"reserved(sub 15)",
	"issuer key ID(sub 16)",
	"reserved(sub 17)",
	"reserved(sub 18)",
	"reserved(sub 19)",
	"notation data(sub 20)",
	"preferred hash algorithms(sub 21)",
	"preferred compression algorithms(sub 22)",
	"key server preferences(sub 23)",
	"preferred key server(sub 24)",
	"primary User ID(sub 25)",
	"policy URL(sub 26)",
	"key flags(sub 27)",
	"signer's User ID(sub 28)",
	"reason for revocation(sub 29)",
        "features(sub 30)",
        "signature target(sub 31)",
	"embedded signature(sub 32)",
	"issuer fingerprint(sub 33)",
        "preferred_aead_algorithms(sub 34)",
};
#define SIGSUB_NUM (sizeof(SIGSUB) / sizeof(string))

private funcptr
sigsub_func[] = {
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
        features,
        signature_target,
	embedded_signature,
	issuer_fingerprint,
	preferred_aead_algorithms,
};

private string
UATSUB[] = {
	"unknown(sub 0)",
	"image attribute(sub 1)",
};
#define UATSUB_NUM (sizeof(UATSUB) / sizeof(string))

private funcptr
uatsub_func[] = {
	NULL,
	image_attribute,
};

private int
get_new_len(int c)
{
	int len;

	if (c < 192)
		len = c;
	else if (c < 224)
		len = ((c - 192) << 8) + Getc() + 192;
	else if (c == 255) {
	        len = (Getc() << 24);
	        len |= (Getc() << 16);
	        len |= (Getc() << 8);
	        len |= Getc();
	} else
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
	int have_packet = NO;

	c = getchar();
	ungetc(c, stdin);

	/* If the PGP packet is in the binary raw form, 7th bit of
	 * the first byte is always 1. If it is set, let's assume
	 * it is the binary raw form. Otherwise, let's assume
	 * it is encoded with radix64.
	 */
	if (c & BINARY_TAG_FLAG) {
		if (aflag)
			warn_exit("binary input is not allowed.");
		set_binary();
	} else
		set_armor();

	while ((c = Getc1()) != EOF) {
		have_packet = YES;
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
				len = (Getc() << 8);
				len += Getc();
				break;
			case 2:
			        len = Getc() << 24;
			        len |= Getc() << 16;
			        len |= Getc() << 8;
			        len |= Getc();
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
		else
			skip(len);
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
	if ( have_packet == NO )
		warn_exit("unexpected end of file.");
}

public void
parse_signature_subpacket(string prefix, int tlen)
{
	int len, subtype, critical;

	while (tlen > 0) {
		len = Getc();
		if (len < 192)
			tlen--;
		else if (len < 255) {
			len = ((len - 192) << 8) + Getc() + 192;
			tlen -= 2;
		} else if (len == 255) {
		        len = Getc() << 24;
		        len |= Getc() << 16;
		        len |= Getc() << 8;
		        len |= Getc();
			tlen -= 5;
		}
		tlen -= len;
		subtype = Getc(); /* len includes this field byte */
		len--;

		/* Handle critical bit of subpacket type */
		critical = NO;
		if (subtype & CRITICAL_BIT) {
			critical = YES;
			subtype &= CRITICAL_MASK;
		}

		if (subtype < SIGSUB_NUM)
			printf("\t%s: %s%s", prefix, SIGSUB[subtype], critical ? "(critical)" : "");
		else
			printf("\t%s: unknown(sub %d%s)", prefix, subtype, critical ? ", critical" : "");
		printf("(%d bytes)\n", len);
		if (subtype < SIGSUB_NUM && sigsub_func[subtype] != NULL)
			(*sigsub_func[subtype])(len);
		else
			skip(len);
	}
}

public void
parse_userattr_subpacket(string prefix, int tlen)
{
	int len, subtype;

	while (tlen > 0) {
		len = Getc();
		if (len < 192)
			tlen--;
		else if (len < 255) {
			len = ((len - 192) << 8) + Getc() + 192;
			tlen -= 2;
		} else if (len == 255) {
		        len = Getc() << 24;
		        len |= Getc() << 16;
		        len |= Getc() << 8;
		        len |= Getc();
			tlen -= 5;
		}
		tlen -= len;
		subtype = Getc();
		len--;  /* len includes this field byte */

		if (subtype < UATSUB_NUM)
			printf("\t%s: %s", prefix, UATSUB[subtype]);
		else
			printf("\t%s: unknown(sub %d)", prefix, subtype);
		printf("(%d bytes)\n", len);
		if (subtype < UATSUB_NUM && uatsub_func[subtype] != NULL)
			(*uatsub_func[subtype])(len);
		else
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
