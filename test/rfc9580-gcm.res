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
