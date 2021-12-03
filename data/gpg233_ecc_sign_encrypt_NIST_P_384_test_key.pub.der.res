Old: Public Key Packet(tag 6)(111 bytes)
	Ver 4 - new
	Public key creation time - Mon Nov 29 09:23:52 UTC 2021
	Pub alg - ECDSA Elliptic Curve Digital Signature Algorithm(pub 19)
	Elliptic Curve - NIST P-384 (0x2B 81 04 00 22)
	ECDSA Q(771 bits) - ...
Old: User ID Packet(tag 13)(46 bytes)
	User ID -  (gpg233_ecc_sign_encrypt_NIST_P_384_test_key)
Old: Signature Packet(tag 2)(179 bytes)
	Ver 4 - new
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - ECDSA Elliptic Curve Digital Signature Algorithm(pub 19)
	Hash alg - SHA384(hash 9)
	Hashed Sub: issuer fingerprint(sub 33)(21 bytes)
	 v4 -	Fingerprint - 11 89 9c 98 38 06 90 de bd 09 1b 38 14 53 30 a9 f3 18 b7 d9 
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Mon Nov 29 09:23:52 UTC 2021
	Hashed Sub: key flags(sub 27)(1 bytes)
		Flag - This key may be used to certify other keys
		Flag - This key may be used to sign data
	Hashed Sub: preferred symmetric algorithms(sub 11)(4 bytes)
		Sym alg - AES with 256-bit key(sym 9)
		Sym alg - AES with 192-bit key(sym 8)
		Sym alg - AES with 128-bit key(sym 7)
		Sym alg - Triple-DES(sym 2)
	Hashed Sub: preferred_aead_algorithms(sub 34)(2 bytes)
		AEAD alg - OCB(aead 2)
		AEAD alg - EAX(aead 1)
	Hashed Sub: preferred hash algorithms(sub 21)(5 bytes)
		Hash alg - SHA512(hash 10)
		Hash alg - SHA384(hash 9)
		Hash alg - SHA256(hash 8)
		Hash alg - SHA224(hash 11)
		Hash alg - SHA1(hash 2)
	Hashed Sub: preferred compression algorithms(sub 22)(2 bytes)
		Comp alg - ZLIB <RFC1950>(comp 2)
		Comp alg - ZIP <RFC1951>(comp 1)
	Hashed Sub: features(sub 30)(1 bytes)
		Flag - Modification detection (packets 18 and 19)
	Hashed Sub: key server preferences(sub 23)(1 bytes)
		Flag - No-modify
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - 0x145330A9F318B7D9
	Hash left 2 bytes - f5 98 
	ECDSA r(384 bits) - ...
	ECDSA s(384 bits) - ...
Old: Public Subkey Packet(tag 14)(115 bytes)
	Ver 4 - new
	Public key creation time - Mon Nov 29 09:23:52 UTC 2021
	Pub alg - ECDH Elliptic Curve Diffie-Hellman Algorithm(pub 18)
	Elliptic Curve - NIST P-384 (0x2B 81 04 00 22)
	ECDH Q(771 bits) - ...
	ECDH KDF params(32 bits) - ...
		KDFhashID:  	Hash alg - SHA384(hash 9)
		KDFsymAlgoID:  	Sym alg - AES with 256-bit key(sym 9)
Old: Signature Packet(tag 2)(152 bytes)
	Ver 4 - new
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - ECDSA Elliptic Curve Digital Signature Algorithm(pub 19)
	Hash alg - SHA384(hash 9)
	Hashed Sub: issuer fingerprint(sub 33)(21 bytes)
	 v4 -	Fingerprint - 11 89 9c 98 38 06 90 de bd 09 1b 38 14 53 30 a9 f3 18 b7 d9 
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Mon Nov 29 09:23:52 UTC 2021
	Hashed Sub: key flags(sub 27)(1 bytes)
		Flag - This key may be used to encrypt communications
		Flag - This key may be used to encrypt storage
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - 0x145330A9F318B7D9
	Hash left 2 bytes - 74 b8 
	ECDSA r(383 bits) - ...
	ECDSA s(383 bits) - ...
