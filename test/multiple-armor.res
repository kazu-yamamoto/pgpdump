New: One-Pass Signature Packet(tag 4)(70 bytes)
	Latest version(6)
	Sig type - Signature of a canonical text document(0x01).
	Hash alg - SHA512(hash 10)
	Pub alg - Ed25519(pub 27)
	Salt - 76 49 5f 50 21 88 90 f7 f5 e2 ee 3c 18 22 51 4f 70 50 0f 55 1d 86 e5 c9 21 e4 04 e3 4a 53 fb ac 
	Fingerprint - cb 18 6c 4f 06 09 a6 97 e4 d5 2d fa 6c 72 2b 0c 1f 1e 27 c1 8a 56 70 8f 65 25 ec 27 ba d9 ac c9 
	Next packet - other than one pass signature
New: Literal Data Packet(tag 11)(74 bytes)
	Packet data format - UTF-8 text
	Filename - 
	Creation time - Thu Jan  1 00:00:00 UTC 1970
	Literal - ...
New: Signature Packet(tag 2)(152 bytes)
	Ver 6 - latest
	Sig type - Signature of a canonical text document(0x01).
	Pub alg - Ed25519(pub 27)
	Hash alg - SHA512(hash 10)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Tue Dec 13 16:08:03 UTC 2022
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v6 -	Fingerprint - cb 18 6c 4f 06 09 a6 97 e4 d5 2d fa 6c 72 2b 0c 1f 1e 27 c1 8a 56 70 8f 65 25 ec 27 ba d9 ac c9 
	Hash left 2 bytes - 69 36 
	Salt - 76 49 5f 50 21 88 90 f7 f5 e2 ee 3c 18 22 51 4f 70 50 0f 55 1d 86 e5 c9 21 e4 04 e3 4a 53 fb ac 
	Ed25519 signature(64 bytes) - ...
New: Symmetric-Key Encrypted Session Key Packet(tag 3)(60 bytes)
	Latest version(6)
	Sym alg - AES with 128-bit key(sym 7)
	AEAD alg - GCM(aead 3)
	Iterated and salted string-to-key(s2k 3):
		Hash alg - SHA256(hash 8)
		Salt - e9 d3 97 85 b2 07 00 08 
		Count - 65011712(coded count 255)
	IV - b4 2e 7c 48 3e f4 88 44 57 cb 37 26 
	Encrypted session key
	Authentication tag - 85 1a bf ff 75 26 df 2d d5 54 41 75 79 a7 79 9f 
New: Symmetrically Encrypted and MDC Packet(tag 18)(105 bytes)
	Ver 2
	Sym alg - AES with 128-bit key(sym 7)
	AEAD alg - GCM(aead 3)
	Chunk size - 4096(coded 6)
	Salt - fc b9 44 90 bc b9 8b bd c9 d1 06 c6 09 02 66 94 0f 72 e8 9e dc 21 b5 59 6b 15 76 b1 01 ed 0f 9f 
	Encrypted data
		(plain text chunks + AEAD tags)
