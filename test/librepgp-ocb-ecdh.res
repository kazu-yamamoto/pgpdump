Old: Public-Key Encrypted Session Key Packet(tag 1)(94 bytes)
	New version(3)
	Key ID - 0x37725B89E11B1629
	Pub alg - ECDH Elliptic Curve Diffie-Hellman Algorithm(pub 18)
	ECDH ephemeral public key(263 bits) - ...
	ECDH wrapped session key(48 bytes) - ...
New: OCB Encrypted Data Packet(tag 20)(76 bytes)
	Ver 1
	Sym alg - AES with 256-bit key(sym 9)
	AEAD alg - OCB(aead 2)
	Chunk size - 4194304(coded 16)
	IV - 5e 49 43 64 42 36 4e e3 b6 b3 03 25 11 44 aa 
	Encrypted data
		(plain text chunks + AEAD tags + final AEAD tag)
