Old: Public-Key Encrypted Session Key Packet(tag 1)(117 bytes)
	New version(3)
	Key ID - 0x1BD769B156855400
	Pub alg - ECDH Elliptic Curve Diffie-Hellman Algorithm(pub 18)
	ECDH ephemeral public key(448 bits) - ...
	ECDH wrapped session key(48 bytes) - ...
New: OCB Encrypted Data Packet(tag 20)(82 bytes)
	Ver 1
	Sym alg - AES with 256-bit key(sym 9)
	AEAD alg - OCB(aead 2)
	Chunk size - 4194304(coded 16)
	IV - 6c 0c d6 64 a2 b5 e4 3f dc ec 55 64 bc f6 19 
	Encrypted data
		(plain text chunks + AEAD tags + final AEAD tag)
