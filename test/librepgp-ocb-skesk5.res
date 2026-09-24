Old: Symmetric-Key Encrypted Session Key Packet(tag 3)(77 bytes)
	LibrePGP version(5)
	Sym alg - AES with 256-bit key(sym 9)
	AEAD alg - OCB(aead 2)
	Iterated and salted string-to-key(s2k 3):
		Hash alg - SHA256(hash 8)
		Salt - f2 1f d7 c4 52 14 20 25 
		Count - 65536(coded count 96)
	IV - 15 86 66 8c bb b2 16 c5 bc e8 29 7a 13 4a d4 
	Encrypted session key
	Authentication tag - a5 b2 7b b8 5f 2e 1d 23 b0 79 e3 11 e9 24 e8 aa 
New: OCB Encrypted Data Packet(tag 20)(76 bytes)
	Ver 1
	Sym alg - AES with 256-bit key(sym 9)
	AEAD alg - OCB(aead 2)
	Chunk size - 4194304(coded 16)
	IV - 0c 07 eb b7 6e 96 3a 83 de 8e cb 90 c0 63 11 
	Encrypted data
		(plain text chunks + AEAD tags + final AEAD tag)
