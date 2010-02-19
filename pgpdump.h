/*
 * pgpdump.h
 */

#define public extern
#define private static

#define SUCCESS 0
#define ERROR 1

#define NULL_VER -1

/*
 * Global
 */

int mflag;
int lflag;
int iflag;

/*
 * pgpdump.c
 */

public void error(char *);
public void Set_input_file(char *);
public FILE *Get_input_file(void);
public int Getc(void);
public int Getc_getlen(void);
public void Getc_resetlen(void);


#define skip(len) {int i; for (i = 0; i < (len); i++) Getc();}
#define pdump(len) {int i; for (i = 0; i < (len); i++) putchar(Getc());}
#define dump(len) {int i; for (i = 0; i < (len); i++) printf("%02x ", Getc());}

/*
 *  packet.c
 */

public void parse_packet(void);
public void parse_subpacket(char *, int);

/*
 * types.c
 */

public void pub_algs(int);
public void sym_algs(int);
public void comp_algs(int);
public void hash_algs(int);
public void key_id(void);
public void time4(char *);
public void ver(int, int, int);
public void string_to_key(void);
public void multi_precision_integer(char *);
	
/*
 * tagfunc.c
 */
public void Reserved(int);
public void Public_Key_Encrypted_Session_Key_Packet(int);
public void Symmetric_Key_Encrypted_Session_Key_Packet(int);
public void Symmetrically_Encrypted_Data_Packet(int);
public void Marker_Packet(int);
public void Literal_Data_Packet(int);
public void Trust_Packet(int);
public void User_ID_Packet(int);

/*
 * keys.c
 */

public void Public_Key_Packet(int);
public void Public_Subkey_Packet(int);
public void Secret_Key_Packet(int);
public void Secret_Subkey_Packet(int);

/*
 * uncompress.c
 */

public void Compressed_Data_Packet(int);

/*
 * signature.c
 */

public void One_Pass_Signature_Packet(int);
public void Signature_Packet(int);

/*
 * subfunc.c
 */

public void signature_creation_time(int);
public void signature_expiration_time(int);
public void exportable_certification(int);
public void trust_signature(int);
public void regular_expression(int);
public void revocable(int);
public void key_expiration_time(int);
public void placeholder_for_backward_compatibility(int);
public void preferred_symmetric_algorithms(int);
public void revocation_key(int);
public void issuer_key_ID(int);
public void notation_data(int);
public void preferred_hash_algorithms(int);
public void preferred_compression_algorithms(int);
public void key_server_preferences(int);
public void preferred_key_server(int);
public void primary_user_id(int);
public void policy_URL(int);
public void key_flags(int);
public void signer_user_id(int);
public void reason_for_revocation(int);

/*
 * armor.c
 */

public void armor_decode(void);

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
