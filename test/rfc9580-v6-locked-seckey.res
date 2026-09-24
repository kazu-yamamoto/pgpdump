New: Secret Key Packet(tag 5)(130 bytes)
	Ver 6 - latest
	Public key creation time - Wed Nov 30 16:08:03 UTC 2022
	Pub alg - Ed25519(pub 27)
	Ed25519 public key(32 bytes) - ...
	Sym alg - AES with 256-bit key(sym 9)
	AEAD alg - OCB(aead 2)
	Argon2 string-to-key(s2k 4):
		Salt - 5d 6f d7 1c 9e 09 6d 1e b6 91 7b 6e 6e 1e ec ae 
		Passes - 1
		Parallelism - 4
		Memory - 2^21 KiB
	IV - b4 a8 a9 27 4f ab e6 32 f8 75 a7 06 59 20 21 
	Encrypted Ed25519 secret key
	AEAD authentication tag
New: Signature Packet(tag 2)(177 bytes)
	Ver 6 - latest
	Sig type - Signature directly on a key(0x1f).
	Pub alg - Ed25519(pub 27)
	Hash alg - SHA512(hash 10)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Wed Nov 30 16:08:03 UTC 2022
	Hashed Sub: preferred symmetric algorithms(sub 11)(2 bytes)
		Sym alg - AES with 256-bit key(sym 9)
		Sym alg - AES with 128-bit key(sym 7)
	Hashed Sub: preferred hash algorithms(sub 21)(4 bytes)
		Hash alg - SHA512(hash 10)
		Hash alg - SHA3-512(hash 14)
		Hash alg - SHA256(hash 8)
		Hash alg - SHA3-256(hash 12)
	Hashed Sub: preferred compression algorithms(sub 22)(1 bytes)
		Comp alg - Uncompressed(comp 0)
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used to certify other keys
		Flag - This key may be used to sign data
	Hashed Sub: features(sub 30)(1 bytes)
		Flag - Modification detection (packets 18 and 19)
		Flag - Version 2 Symmetrically Encrypted and Integrity Protected Data packet
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v6 -	Fingerprint - cb 18 6c 4f 06 09 a6 97 e4 d5 2d fa 6c 72 2b 0c 1f 1e 27 c1 8a 56 70 8f 65 25 ec 27 ba d9 ac c9 
	Hashed Sub: preferred AEAD ciphersuites(sub 39)(4 bytes)
		Ciphersuite - AES with 256-bit key(sym 9) + OCB(aead 2)
		Ciphersuite - AES with 128-bit key(sym 7) + OCB(aead 2)
	Hash left 2 bytes - ad 28 
	Salt - 10 3e 2d 7d 22 7e c0 e6 d7 ce 44 71 db 36 bf c9 70 83 25 36 90 27 14 98 a7 ef 05 76 c0 7f aa e1 
	Ed25519 signature(64 bytes) - ...
New: Secret Subkey Packet(tag 7)(130 bytes)
	Ver 6 - latest
	Public key creation time - Wed Nov 30 16:08:03 UTC 2022
	Pub alg - X25519(pub 25)
	X25519 public key(32 bytes) - ...
	Sym alg - AES with 256-bit key(sym 9)
	AEAD alg - OCB(aead 2)
	Argon2 string-to-key(s2k 4):
		Salt - 0e 61 84 68 29 da 86 9a be 0e a6 15 45 dc 14 cc 
		Passes - 1
		Parallelism - 4
		Memory - 2^21 KiB
	IV - 2e 13 ca 9f f4 e7 24 fb 1c 2e b1 df 86 02 09 
	Encrypted X25519 secret key
	AEAD authentication tag
New: Signature Packet(tag 2)(155 bytes)
	Ver 6 - latest
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - Ed25519(pub 27)
	Hash alg - SHA512(hash 10)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Wed Nov 30 16:08:03 UTC 2022
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used to encrypt communications
		Flag - This key may be used to encrypt storage
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v6 -	Fingerprint - cb 18 6c 4f 06 09 a6 97 e4 d5 2d fa 6c 72 2b 0c 1f 1e 27 c1 8a 56 70 8f 65 25 ec 27 ba d9 ac c9 
	Hash left 2 bytes - 04 01 
	Salt - a6 e9 18 6d 9d 59 35 fc 8f e5 63 14 cd b5 27 48 6a 5a 51 20 f9 b7 62 a2 35 a7 29 f0 39 01 0a 56 
	Ed25519 signature(64 bytes) - ...
