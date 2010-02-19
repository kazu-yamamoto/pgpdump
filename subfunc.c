/*
 * subfunc.c
 */

#include <stdio.h>
#include "pgpdump.h"

public void
signature_creation_time(int len)
{
	printf("\t");	
	time4("Time");
}

public void
signature_expiration_time(int len)
{
	printf("\t");	
	time4("Time");
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
	printf("\t\tlevel - ");
	dump(1);
	printf("\n");
	printf("\t\tamount - ");		
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
	time4("Time");
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
	printf("\t\txxx\n");
	skip(len);
	/* xxx */
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
	printf("\t\txxx\n");
	skip(len);
	/* xxx */
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
	printf("\t\txxx\n");
	skip(len);
	/* xxx */
}

public void
signer_user_id(int len)
{
	printf("\t\txxx\n");
	skip(len);
	/* xxx */
}	

public void
reason_for_revocation(int len)
{
	printf("\t\txxx\n");
	skip(len);
	/* xxx */
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
