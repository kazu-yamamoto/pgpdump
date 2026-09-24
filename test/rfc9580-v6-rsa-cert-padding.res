New: Public Key Packet(tag 6)(401 bytes)
	Ver 6 - latest
	Public key creation time - Thu Sep 24 08:21:59 UTC 2026
	Pub alg - RSA Encrypt or Sign(pub 1)
	RSA n(3072 bits) - ...
	RSA e(17 bits) - ...
New: Signature Packet(tag 2)(488 bytes)
	Ver 6 - latest
	Sig type - Signature directly on a key(0x1f).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA512(hash 10)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Thu Sep 24 08:21:59 UTC 2026
	Hashed Sub: preferred symmetric algorithms(sub 11)(2 bytes)
		Sym alg - AES with 256-bit key(sym 9)
		Sym alg - AES with 128-bit key(sym 7)
	Hashed Sub: preferred hash algorithms(sub 21)(2 bytes)
		Hash alg - SHA512(hash 10)
		Hash alg - SHA256(hash 8)
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used to certify other keys
	Hashed Sub: features(sub 30)(1 bytes)
		Flag - Modification detection (packets 18 and 19)
		Flag - Version 2 Symmetrically Encrypted and Integrity Protected Data packet
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v6 -	Fingerprint - e5 21 a9 21 bf dd c7 59 90 91 39 29 40 fb 96 69 6c c3 be 9d 02 6f 68 62 37 b8 4e 11 03 06 cf 90 
	Hash left 2 bytes - 19 34 
	Salt - d6 d5 56 f3 91 51 8c 4f 07 5c ef 19 7a 93 19 79 5f dd 09 d2 75 5f 48 e6 88 a1 08 e4 2f bc 64 3c 
	RSA m^d mod n(3070 bits) - ...
		-> PKCS-1
New: User ID Packet(tag 13)(17 bytes)
	User ID - <rsa@example.com>
New: Signature Packet(tag 2)(488 bytes)
	Ver 6 - latest
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA512(hash 10)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Thu Sep 24 08:21:59 UTC 2026
	Hashed Sub: preferred symmetric algorithms(sub 11)(2 bytes)
		Sym alg - AES with 256-bit key(sym 9)
		Sym alg - AES with 128-bit key(sym 7)
	Hashed Sub: preferred hash algorithms(sub 21)(2 bytes)
		Hash alg - SHA512(hash 10)
		Hash alg - SHA256(hash 8)
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used to certify other keys
	Hashed Sub: features(sub 30)(1 bytes)
		Flag - Modification detection (packets 18 and 19)
		Flag - Version 2 Symmetrically Encrypted and Integrity Protected Data packet
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v6 -	Fingerprint - e5 21 a9 21 bf dd c7 59 90 91 39 29 40 fb 96 69 6c c3 be 9d 02 6f 68 62 37 b8 4e 11 03 06 cf 90 
	Hash left 2 bytes - f4 58 
	Salt - 2f 0c 05 b0 01 65 f8 de 28 ac 9a 26 85 72 69 38 11 fe c6 db 5f 9f 6c 4e b5 5c c1 63 98 3f 34 cd 
	RSA m^d mod n(3071 bits) - ...
		-> PKCS-1
New: User ID Packet(tag 13)(3 bytes)
	User ID - rsa
New: Signature Packet(tag 2)(491 bytes)
	Ver 6 - latest
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA512(hash 10)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Thu Sep 24 08:21:59 UTC 2026
	Hashed Sub: preferred symmetric algorithms(sub 11)(2 bytes)
		Sym alg - AES with 256-bit key(sym 9)
		Sym alg - AES with 128-bit key(sym 7)
	Hashed Sub: preferred hash algorithms(sub 21)(2 bytes)
		Hash alg - SHA512(hash 10)
		Hash alg - SHA256(hash 8)
	Hashed Sub: primary User ID(sub 25)(critical)(1 bytes)
		Primary - Yes
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used to certify other keys
	Hashed Sub: features(sub 30)(1 bytes)
		Flag - Modification detection (packets 18 and 19)
		Flag - Version 2 Symmetrically Encrypted and Integrity Protected Data packet
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v6 -	Fingerprint - e5 21 a9 21 bf dd c7 59 90 91 39 29 40 fb 96 69 6c c3 be 9d 02 6f 68 62 37 b8 4e 11 03 06 cf 90 
	Hash left 2 bytes - 5b f5 
	Salt - 02 9f 6d 6a ea cf bf 6b 9d 67 1d c6 87 fd 12 43 eb b9 89 5a 58 f7 9a f9 e0 07 82 d0 53 4d 06 e1 
	RSA m^d mod n(3071 bits) - ...
		-> PKCS-1
New: Public Subkey Packet(tag 14)(401 bytes)
	Ver 6 - latest
	Public key creation time - Thu Sep 24 08:21:59 UTC 2026
	Pub alg - RSA Encrypt or Sign(pub 1)
	RSA n(3072 bits) - ...
	RSA e(17 bits) - ...
New: Signature Packet(tag 2)(477 bytes)
	Ver 6 - latest
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA512(hash 10)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Thu Sep 24 08:21:59 UTC 2026
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used to encrypt communications
		Flag - This key may be used to encrypt storage
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v6 -	Fingerprint - e5 21 a9 21 bf dd c7 59 90 91 39 29 40 fb 96 69 6c c3 be 9d 02 6f 68 62 37 b8 4e 11 03 06 cf 90 
	Hash left 2 bytes - ee ea 
	Salt - 44 55 3f f7 c7 c9 fc 48 57 9a f7 f0 06 92 d0 20 24 83 9a 17 13 bc 5e 3a ab b6 a4 22 dd d8 c6 3d 
	RSA m^d mod n(3072 bits) - ...
		-> PKCS-1
New: Public Subkey Packet(tag 14)(401 bytes)
	Ver 6 - latest
	Public key creation time - Thu Sep 24 08:21:59 UTC 2026
	Pub alg - RSA Encrypt or Sign(pub 1)
	RSA n(3072 bits) - ...
	RSA e(17 bits) - ...
New: Signature Packet(tag 2)(954 bytes)
	Ver 6 - latest
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA512(hash 10)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Thu Sep 24 08:21:59 UTC 2026
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used for authentication
	Hashed Sub: embedded signature(sub 32)(critical)(474 bytes)
	Ver 6 - latest
	Sig type - Primary Key Binding Signature(0x19).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA512(hash 10)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Thu Sep 24 08:21:59 UTC 2026
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v6 -	Fingerprint - 9d 91 95 ae 38 b1 11 fe 06 87 2c 9a 62 66 bd ff 79 c8 30 b9 73 ac e0 26 3b af 4d 3b ed c6 d0 14 
	Hash left 2 bytes - 11 72 
	Salt - 51 fa 8c 83 79 b0 c5 c2 6b 1b 86 b7 9b df 2a 42 63 95 d8 01 0a 35 68 4c 5c a2 33 58 fc 5a c8 24 
	RSA m^d mod n(3071 bits) - ...
		-> PKCS-1
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v6 -	Fingerprint - e5 21 a9 21 bf dd c7 59 90 91 39 29 40 fb 96 69 6c c3 be 9d 02 6f 68 62 37 b8 4e 11 03 06 cf 90 
	Hash left 2 bytes - 21 82 
	Salt - 9f 5f 5a a1 05 51 9a e5 20 eb ac d6 a0 45 a0 ea 4f cb 94 28 a9 6a 1f 1a 6d 58 87 c6 a9 6c 86 bd 
	RSA m^d mod n(3070 bits) - ...
		-> PKCS-1
New: Public Subkey Packet(tag 14)(401 bytes)
	Ver 6 - latest
	Public key creation time - Thu Sep 24 08:21:59 UTC 2026
	Pub alg - RSA Encrypt or Sign(pub 1)
	RSA n(3072 bits) - ...
	RSA e(17 bits) - ...
New: Signature Packet(tag 2)(954 bytes)
	Ver 6 - latest
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA512(hash 10)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Thu Sep 24 08:21:59 UTC 2026
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used to sign data
	Hashed Sub: embedded signature(sub 32)(critical)(474 bytes)
	Ver 6 - latest
	Sig type - Primary Key Binding Signature(0x19).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA512(hash 10)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Thu Sep 24 08:21:59 UTC 2026
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v6 -	Fingerprint - 2f b2 bd 80 da c9 c5 d9 60 79 04 d9 af fc 88 09 f4 25 d6 d2 3e 63 c7 92 1d f8 d4 db 4e ef 5f 86 
	Hash left 2 bytes - 47 99 
	Salt - a0 55 1b d8 58 41 14 9e 9f d3 68 95 ac b0 f5 82 c5 f7 f0 03 7f 32 b3 0e fb df d1 3d 11 81 72 56 
	RSA m^d mod n(3071 bits) - ...
		-> PKCS-1
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v6 -	Fingerprint - e5 21 a9 21 bf dd c7 59 90 91 39 29 40 fb 96 69 6c c3 be 9d 02 6f 68 62 37 b8 4e 11 03 06 cf 90 
	Hash left 2 bytes - 7d ff 
	Salt - c7 c1 a9 b7 9b 52 f4 0c 49 cb f7 cf 8f 0f 81 18 cd 9f b3 04 ae 85 14 52 64 38 71 c8 1a f5 68 d8 
	RSA m^d mod n(3071 bits) - ...
		-> PKCS-1
New: Padding Packet(tag 21)(16 bytes)
	Padding - ...
