/*
 * pgpdump.h
 */

#ifndef _PGP_DUMP_H_
#define _PGP_DUMP_H_

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#define public extern
#define private static

typedef char * string;
typedef unsigned char byte;

#define YES 1
#define NO  0

#define NULL_VER -1

/*
 * Global
 */

public int aflag;
public int gflag;
public int iflag;
public int lflag;
public int mflag;
public int pflag;
public int uflag;

/*
 * pgpdump.c
 */

public void warning(const string, ...);
public void warn_exit(const string, ...);
public void skip(int);
public void dump(int);
public void pdump(int);
public void kdump(int);
public void gdump(int);

/*
 * buffer.c
 */

public void Compressed_Data_Packet(int);

public void set_armor(void);
public void set_binary(void);

public int Getc(void);
public int Getc1(void);
public int Getc_getlen(void);
public void Getc_resetlen(void);

/*
 *  packet.c
 */

public void parse_packet(void);
public void parse_signature_subpacket(string, int);
public void parse_userattr_subpacket(string, int);

/*
 * types.c
 */

public void pub_algs(unsigned int);
public void sym_algs(unsigned int);
public void sym_algs2(unsigned int);
public int  iv_len(unsigned int);
public void comp_algs(unsigned int);
public void hash_algs(unsigned int);
public void aead_algs(unsigned int);
public void key_id(void);
public void fingerprint(void);
public void time4(string);
public void sig_creation_time4(string);
public void sig_expiration_time4(string);
public void key_creation_time4(string);
public void key_expiration_time4(string);
public void ver(int, int, int);
public int string_to_key(void);
public void multi_precision_integer(string);

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
public void User_Attribute_Packet(int);
public void Symmetrically_Encrypted_and_MDC_Packet(int);
public void Modification_Detection_Code_Packet(int);
public void Private_Packet(int);

/*
 * keys.c
 */

public void Public_Key_Packet(int);
public void Public_Subkey_Packet(int);
public void Secret_Key_Packet(int);
public void Secret_Subkey_Packet(int);

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
public void additional_decryption_key(int);
public void preferred_symmetric_algorithms(int);
public void preferred_aead_algorithms(int);
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
public void features(int);
public void signature_target(int);
public void embedded_signature(int);
public void issuer_fingerprint(int);

/*
 * uatfunc.c
 */

public void image_attribute(int);

#endif /* _PGP_DUMP_H_ */

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
