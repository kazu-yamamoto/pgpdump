/*
 * tagfunc.c
 */

#include "pgpdump.h"

#define SYM_ALG_MODE_NOT_SPECIFIED  1
#define SYM_ALG_MODE_SYM_ENC        2
#define SYM_ALG_MODE_PUB_ENC        3

private int sym_alg_mode = SYM_ALG_MODE_NOT_SPECIFIED;
private void reset_sym_alg_mode();
private void set_sym_alg_mode(int);
private int get_sym_alg_mode();

private void
reset_sym_alg_mode()
{
	sym_alg_mode = SYM_ALG_MODE_NOT_SPECIFIED;
}

private void
set_sym_alg_mode(int mode)
{
	sym_alg_mode = mode;
}

private int
get_sym_alg_mode()
{
	return sym_alg_mode;
}

public void
Reserved(int len)
{
	skip(len);
}

public void
Public_Key_Encrypted_Session_Key_Packet(int len)
{
	int pub;
	ver(2, 3, Getc());
	key_id();
	pub = Getc();
	pub_algs(pub);
	switch (pub) {
	case 1:
	case 2:
	case 3:
		multi_precision_integer("RSA m^e mod n");
		break;
	case 16:
	case 20:
		multi_precision_integer("ElGamal g^k mod p");
		multi_precision_integer("ElGamal m * y^k mod p");
		break;
	case 17:
		multi_precision_integer("DSA ?");
		multi_precision_integer("DSA ?");
		break;
	default:
		printf("\t\tunknown(pub %d)\n", pub);
		skip(len - 10);
	}
	printf("\t\t-> m = sym alg(1 byte) + checksum(2 bytes) + PKCS-1 block type 02\n");
	set_sym_alg_mode(SYM_ALG_MODE_PUB_ENC);
}

public void
Symmetric_Key_Encrypted_Session_Key_Packet(int len)
{
	int left = len, alg;
	ver(NULL_VER, 4, Getc());
	alg = Getc();
	sym_algs(alg);
	left -= 2;
	Getc_resetlen();
	string_to_key();
	left -= Getc_getlen();
	if (left != 0) {
		printf("\tEncrypted session key\n");
		printf("\t\t-> sym alg(1 bytes) + session key\n");
		skip(left);
	}
	set_sym_alg_mode(SYM_ALG_MODE_SYM_ENC);
}

public void
Symmetrically_Encrypted_Data_Packet(int len)
{
	int mode = get_sym_alg_mode();
	switch (mode) {
	case SYM_ALG_MODE_NOT_SPECIFIED:
		printf("\tEncrypted data [sym alg is IDEA, simple string-to-key]\n");
		break;
	case SYM_ALG_MODE_SYM_ENC:
		printf("\tEncrypted data [sym alg is specified in sym-key encrypted session key]\n");
		break;
	case SYM_ALG_MODE_PUB_ENC:
		printf("\tEncrypted data [sym alg is specified in pub-key encrypted session key]\n");
		break;
	}
	skip(len);
	reset_sym_alg_mode();
}

public void
Marker_Packet(int len)
{
	printf("\tString - ");
	if (mflag) {
		pdump(len);
	} else {
		printf("...");
		skip(len);
	}
	printf("\n");
}

public void
Literal_Data_Packet(int len)
{
	int format, flen, blen;

	format = Getc();
	printf("\tPacket data format - ");
	switch (format) {
	case 'b':
		printf("binary");
		break;
	case 't':
		printf("text");
		break;
	case 'u':
		printf("UTF-8 text");
		break;
	case 'l':
		/* RFC 1991 incorrectly define this as '1' */
		printf("local");
		break;
	default:
		printf("unknown");
	}
	printf("\n");
	flen = Getc();
	printf("\tFilename - ");
	pdump(flen);
	printf("\n");
	/* RFC 4880: modification date of a file or time the packet itself was created */
	time4("Creation time");
	blen = len - 6 - flen;
	printf("\tLiteral - ");
	if (lflag) {
		pdump(blen);
	} else {
		printf("...");
		skip(blen);
	}
	printf("\n");
}

public void
Trust_Packet(int len)
{
	printf("\tTrust - ");
	dump(len);
	printf("\n");
}

public void
User_ID_Packet(int len)
{
	printf("\tUser ID - ");
	pdump(len);
	printf("\n");
}

public void
User_Attribute_Packet(int len)
{
	parse_userattr_subpacket("Sub", len);
}

public void
Symmetrically_Encrypted_and_MDC_Packet(int len)
{
	int mode = get_sym_alg_mode();
	printf("\tVer %d\n", Getc());
	switch (mode) {
	case SYM_ALG_MODE_SYM_ENC:
		printf("\tEncrypted data [sym alg is specified in sym-key encrypted session key]\n");
		break;
	case SYM_ALG_MODE_PUB_ENC:
		printf("\tEncrypted data [sym alg is specified in pub-key encrypted session key]\n");
		break;
	}
	printf("\t\t(plain text + MDC SHA1(20 bytes))\n");
	skip(len - 1);
	reset_sym_alg_mode();
}

/* this function is not used because this packet appears only
   in encrypted packets. */
public void
Modification_Detection_Code_Packet(int len)
{
	printf("\tMDC - SHA1(20 bytes)\n");
	skip(len);
}

public void
Private_Packet(int len)
{
	printf("\tPrivate - ");
	if (pflag) {
		dump(len);
	} else {
		printf("...");
		skip(len);
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
