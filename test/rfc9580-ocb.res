New: Symmetric-Key Encrypted Session Key Packet(tag 3)(63 bytes)
	Latest version(6)
	Sym alg - AES with 128-bit key(sym 7)
	AEAD alg - OCB(aead 2)
	Iterated and salted string-to-key(s2k 3):
		Hash alg - SHA256(hash 8)
		Salt - 56 a2 98 d2 f5 e3 64 53 
		Count - 65011712(coded count 255)
	IV - cf cc 5c 11 66 4e db 9d b4 25 90 d7 dc 46 b0 
	Encrypted session key
	Authentication tag - 11 23 f8 87 ae 60 d4 fd 61 4e 08 37 d8 19 d3 6c 
New: Symmetrically Encrypted and MDC Packet(tag 18)(105 bytes)
	Ver 2
	Sym alg - AES with 128-bit key(sym 7)
	AEAD alg - OCB(aead 2)
	Chunk size - 4096(coded 6)
	Salt - 20 a6 61 f7 31 fc 9a 30 32 b5 62 33 26 02 7e 3a 5d 8d b5 74 8e be ff 0b 0c 59 10 d0 9e cd d6 41 
	Encrypted data
		(plain text chunks + AEAD tags)
