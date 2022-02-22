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
	days = Getc() * 256;
	days += Getc();
	printf("\tValid days - %d[0 is forever]\n", days);
	PUBLIC = Getc();
	pub_algs(PUBLIC); /* PUBLIC should be 1 */
	multi_precision_integer("RSA n");
	multi_precision_integer("RSA e");
}

/* added: 2021-11-11; extended: 2022-02-21 (BrainPool 384,512; RFC5639)
 * Reference: draft-ietf-openpgp-crypto-refresh-04 (10/2021);section 9.2 ECC Curves for OpenPGP
 * https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-04.html
 * Note (2021-11-25): actual ECC curve hex OID padded to 10 to match incoming oid array length
 *                    so that memcmp will work properly (compare two values of the same size)
 */
private unsigned char BrainPool256r1_OID[10]={0x2B,0x24,0x3,0x3,0x2,0x8,0x1,0x1,0x7,0};
private unsigned char BrainPool384r1_OID[10]={0x2B,0x24,0x3,0x3,0x2,0x8,0x1,0x1,0x0b,0};
private unsigned char BrainPool512r1_OID[10]={0x2B,0x24,0x3,0x3,0x2,0x8,0x1,0x1,0x0d,0};
private unsigned char NIST_P256_OID[10]={0x2A,0x86,0x48,0xCE,0x3D,0x3,0x1,0x7,0,0};
private unsigned char NIST_P384_OID[10]={0x2B,0x81,0x04,0x00,0x22,0,0,0,0,0};
private unsigned char NIST_P521_OID[10]={0x2B,0x81,0x04,0x00,0x23,0,0,0,0,0};
private unsigned char Ed25519_OID[10]={0x2B,0x06,0x01,0x04,0x01,0xDA,0x47,0x0F,0x01,0};
private unsigned char Ed448_OID[10]={0x2B,0x65,0x71,0,0,0,0,0,0,0};
private unsigned char Curve25519_OID[10]={0x2B,0x06,0x01,0x04,0x01,0x97,0x55,0x01,0x05,0x01};
private unsigned char X448_OID[10]={0x2B,0x65,0x6F,0,0,0,0,0,0,0};

private unsigned char oid_input_HEX[10]={0,0,0,0,0,0,0,0,0,0};
#define oid_input_HEX_size sizeof(oid_input_HEX)
private size_t oidLEN;
private int FoundECC=NO;
private int jj;

private struct {
  const unsigned char *oidhex;
  const char *name;
  const char *oidstring;
} ELLIP_CURVES[] = {
  {NIST_P256_OID,"NIST P-256","0x2A 86 48 CE 3D 03 01 07"},
  {NIST_P384_OID,"NIST P-384","0x2B 81 04 00 22"},
  {NIST_P521_OID,"NIST P-521","0x2B 81 04 00 23"},
  {Ed25519_OID,"Ed25519","0x2B 06 01 04 01 DA 47 0F 01"},
  {Ed448_OID,"Ed448","0x2B 65 71"},
  {Curve25519_OID,"Curve25519","0x2B 06 01 04 01 97 55 01 05 01"},
  {X448_OID,"X448","0x2B 65 6F"},
  {BrainPool256r1_OID,"brainpoolP256r1","0x2B 24 03 03 02 08 01 01 07"},
  {BrainPool384r1_OID,"BrainPoolP384r1","0x2B 24 03 03 02 08 01 01 07 0b"},
  {BrainPool512r1_OID,"BrainPoolP512r1","0x2B 24 03 03 02 08 01 01 07 0d"}
};
#define ELLIP_CURVES_NUM 10

/* end 2021-11-11 */


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
	case 18:/*ECDH*/
		oidLEN = Getc();
		for(jj=0;jj<oidLEN;jj++){oid_input_HEX[jj]=Getc();}
	        for(jj=0;jj<ELLIP_CURVES_NUM;jj++){
		  if(memcmp(ELLIP_CURVES[jj].oidhex,oid_input_HEX,oid_input_HEX_size) == 0){
	            FoundECC=YES;
	            break;
	          }
	        }
	        if(FoundECC){
	          printf("\tElliptic Curve - ");
	          printf("%s (%s)\n",ELLIP_CURVES[jj].name,ELLIP_CURVES[jj].oidstring);
	        }
	        else{
	          printf("\tunknown(elliptic curve - ");
	          for(jj=0;jj<oidLEN;jj++){
	            printf("%02hhu,%02x ",oid_input_HEX[jj],oid_input_HEX[jj]);
	          }
	          puts(")");
	        }
		multi_precision_integer("ECDH Q");
/* note - what follows is most of what the "draft-ietf-openpgp-crypto-refresh-04"
 * specifies for "13.5 EC DH Algorithm (ECDH)" minus the following:
 * a) 'one-octet public key algorithm ID defined in Section 9.1'
 * b) '20 octets representing the UTF-8 encoding of the string "Anonymous Sender"'
 * c) '20 octets representing a recipient encryption subkey or a primary key fingerprint'
 * The end result is consonant with GnuPG-2.3.3 "list-packets" output in fields/bytes,
 * though gpg-2.3.3 displays "pkey[2]" [32 bits]" where the supposed KDF parameters exist.
 */
		unsigned int KDFparmsSize,KDFbits,KDFhashID,KDFsymAlgoID;
		KDFparmsSize=Getc();/*don't display*/
                KDFbits=(KDFparmsSize + 1)*8;
                Getc();/*bypass supposed KDF constant */
		KDFhashID=Getc();
		KDFsymAlgoID=Getc();
		printf("\tECDH KDF params(%d bits) - ...\n",KDFbits);
                printf("\t\t%s ","KDFhashID: ");
		hash_algs(KDFhashID);
                printf("\t\t%s ","KDFsymAlgoID: ");
		sym_algs(KDFsymAlgoID);
		break;
	case 19:/*ECDSA*/
		oidLEN = Getc();
		for(jj=0;jj<oidLEN;jj++){oid_input_HEX[jj]=Getc();}
	        for(jj=0;jj<ELLIP_CURVES_NUM;jj++){
		  if(memcmp(ELLIP_CURVES[jj].oidhex,oid_input_HEX,oid_input_HEX_size) == 0){
	            FoundECC=YES;
	            break;
	          }
                }
	        if(FoundECC){
	          printf("\tElliptic Curve - ");
	          printf("%s (%s)\n",ELLIP_CURVES[jj].name,ELLIP_CURVES[jj].oidstring);
	        }
	        else{
	          printf("\tunknown(elliptic curve - ");
	          for(jj=0;jj<oidLEN;jj++){
	            printf("%02hhu,%02x ",oid_input_HEX[jj],oid_input_HEX[jj]);
	          }
	          puts(")");
	        }
		multi_precision_integer("ECDSA Q");
		break;
        case 22:/*EdDSA*/
		oidLEN = Getc();
		for(jj=0;jj<oidLEN;jj++){oid_input_HEX[jj]=Getc();}
	        for(jj=0;jj<ELLIP_CURVES_NUM;jj++){
		  if(memcmp(ELLIP_CURVES[jj].oidhex,oid_input_HEX,oid_input_HEX_size) == 0){
	            FoundECC=YES;
	            break;
	          }
                }
	        if(FoundECC){
	          printf("\tElliptic Curve - ");
	          printf("%s (%s)\n",ELLIP_CURVES[jj].name,ELLIP_CURVES[jj].oidstring);
	        }
	        else{
	          printf("\tunknown(elliptic curve - ");
	          for(jj=0;jj<oidLEN;jj++){
	            printf("%02hhu,%02x ",oid_input_HEX[jj],oid_input_HEX[jj]);
	          }
	          puts(")");
	        }
		multi_precision_integer("EdDSA Q");
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
		if (string_to_key() == YES)
			IV(iv_len(sym));
		encrypted_Secret_Key(len - Getc_getlen(), YES);
		break;
	case 255:
		sym = Getc();
		sym_algs(sym);
		if (string_to_key() == YES)
			IV(iv_len(sym));
		encrypted_Secret_Key(len - Getc_getlen(), NO);
		break;
	default:
		sym = s2k;
		sym_algs(sym);
		printf("\tSimple string-to-key for IDEA\n");
		IV(iv_len(sym));
		encrypted_Secret_Key(len - Getc_getlen(), NO);
		break;
	}
}

/*
 * 2021-11-29: added cases 18,19,22 (copied from Public key)
 */

private void
plain_Secret_Key(int len)
{
	switch (VERSION) {
	case 2:
	case 3:
		/* PUBLIC should be 1. */
		/* Tested by specifying a null passphrase. */
		multi_precision_integer("RSA d");
		multi_precision_integer("RSA p");
		multi_precision_integer("RSA q");
		multi_precision_integer("RSA u");
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
	case 18:/*ECDH*/
		oidLEN = Getc();
		for(jj=0;jj<oidLEN;jj++){oid_input_HEX[jj]=Getc();}
	        for(jj=0;jj<ELLIP_CURVES_NUM;jj++){
		  if(memcmp(ELLIP_CURVES[jj].oidhex,oid_input_HEX,oid_input_HEX_size) == 0){
	            FoundECC=YES;
	            break;
	          }
	        }
	        if(FoundECC){
	          printf("\tElliptic Curve - ");
	          printf("%s (%s)\n",ELLIP_CURVES[jj].name,ELLIP_CURVES[jj].oidstring);
	        }
	        else{
	          printf("\tunknown(elliptic curve - ");
	          for(jj=0;jj<oidLEN;jj++){
	            printf("%02hhu,%02x ",oid_input_HEX[jj],oid_input_HEX[jj]);
	          }
	          puts(")");
	        }
		multi_precision_integer("ECDH Q");
/* note - what follows is most of what the "draft-ietf-openpgp-crypto-refresh-04"
 * specifies for "13.5 EC DH Algorithm (ECDH)" minus the following:
 * a) 'one-octet public key algorithm ID defined in Section 9.1'
 * b) '20 octets representing the UTF-8 encoding of the string "Anonymous Sender"'
 * c) '20 octets representing a recipient encryption subkey or a primary key fingerprint'
 * The end result is consonant with GnuPG-2.3.3 "list-packets" output in fields/bytes,
 * though gpg-2.3.3 displays "pkey[2]" [32 bits]" where the supposed KDF parameters exist.
 */
		unsigned int KDFparmsSize,KDFbits,KDFhashID,KDFsymAlgoID;
		KDFparmsSize=Getc();/*don't display*/
                KDFbits=(KDFparmsSize + 1)*8;
                Getc();/*bypass supposed KDF constant */
		KDFhashID=Getc();
		KDFsymAlgoID=Getc();
		printf("\tECDH KDF params(%d bits) - ...\n",KDFbits);
                printf("\t\t%s ","KDFhashID: ");
		hash_algs(KDFhashID);
                printf("\t\t%s ","KDFsymAlgoID: ");
		sym_algs(KDFsymAlgoID);
		break;
	case 19:/*ECDSA*/
		oidLEN = Getc();
		for(jj=0;jj<oidLEN;jj++){oid_input_HEX[jj]=Getc();}
	        for(jj=0;jj<ELLIP_CURVES_NUM;jj++){
		  if(memcmp(ELLIP_CURVES[jj].oidhex,oid_input_HEX,oid_input_HEX_size) == 0){
	            FoundECC=YES;
	            break;
	          }
                }
	        if(FoundECC){
	          printf("\tElliptic Curve - ");
	          printf("%s (%s)\n",ELLIP_CURVES[jj].name,ELLIP_CURVES[jj].oidstring);
	        }
	        else{
	          printf("\tunknown(elliptic curve - ");
	          for(jj=0;jj<oidLEN;jj++){
	            printf("%02hhu,%02x ",oid_input_HEX[jj],oid_input_HEX[jj]);
	          }
	          puts(")");
	        }
		multi_precision_integer("ECDSA Q");
		break;
        case 22:/*EdDSA*/
		oidLEN = Getc();
		for(jj=0;jj<oidLEN;jj++){oid_input_HEX[jj]=Getc();}
	        for(jj=0;jj<ELLIP_CURVES_NUM;jj++){
		  if(memcmp(ELLIP_CURVES[jj].oidhex,oid_input_HEX,oid_input_HEX_size) == 0){
	            FoundECC=YES;
	            break;
	          }
                }
	        if(FoundECC){
	          printf("\tElliptic Curve - ");
	          printf("%s (%s)\n",ELLIP_CURVES[jj].name,ELLIP_CURVES[jj].oidstring);
	        }
	        else{
	          printf("\tunknown(elliptic curve - ");
	          for(jj=0;jj<oidLEN;jj++){
	            printf("%02hhu,%02x ",oid_input_HEX[jj],oid_input_HEX[jj]);
	          }
	          puts(")");
	        }
		multi_precision_integer("EdDSA Q");
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

/*
 * 2021-11-29: Added cases 18,19,20
 */
private void
encrypted_Secret_Key(int len, int sha1)
{
	if (len == 0)
		return;

	switch (VERSION) {
	case 2:
	case 3:
		/* PUBLIC should be 1.
		   Printable since an MPI prefix count is not encrypted. */
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
                case 18:
                        printf("\tEncrypted ECDH x\n");
                        break;
                case 19:
                        printf("\tEncrypted ECDSA x\n");
                        break;
                case 22:
                        printf("\tEncrypted EdDSA x\n");
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
