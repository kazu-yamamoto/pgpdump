New: Symmetric-Key Encrypted Session Key Packet(tag 3)(64 bytes)
	Latest version(6)
	Sym alg - AES with 128-bit key(sym 7)
	AEAD alg - EAX(aead 1)
	Iterated and salted string-to-key(s2k 3):
		Hash alg - SHA256(hash 8)
		Salt - a5 ae 57 9d 1f c5 d8 2b 
		Count - 65011712(coded count 255)
	IV - 69 22 4f 91 99 93 b3 50 6f a3 b5 9a 6a 73 cf f8 
	Encrypted session key
	Authentication tag - f9 2c 45 4e b6 5e be 00 ab 59 86 c6 8e 6e 7c 55 
New: Symmetrically Encrypted and MDC Packet(tag 18)(105 bytes)
	Ver 2
	Sym alg - AES with 128-bit key(sym 7)
	AEAD alg - EAX(aead 1)
	Chunk size - 4096(coded 6)
	Salt - 9f f9 0e 3b 32 19 64 f3 a4 29 13 c8 dc c6 61 93 25 01 52 27 ef b7 ea ea a4 9f 04 c2 e6 74 17 5d 
	Encrypted data
		(plain text chunks + AEAD tags)
