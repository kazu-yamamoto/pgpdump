Old: Public Key Packet(tag 6)(83 bytes)
	Ver 4 - new
	Public key creation time - Mon Nov 29 09:27:41 UTC 2021
	Pub alg - ECDSA Elliptic Curve Digital Signature Algorithm(pub 19)
	Elliptic Curve - brainpoolP256r1 (0x2B 24 03 03 02 08 01 01 07)
	ECDSA Q(515 bits) - ...
Old: User ID Packet(tag 13)(51 bytes)
	User ID -  (gpg233_ecc_sign_encrypt_Brainpool_P-256_test-key)
Old: Signature Packet(tag 2)(147 bytes)
	Ver 4 - new
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - ECDSA Elliptic Curve Digital Signature Algorithm(pub 19)
	Hash alg - SHA256(hash 8)
	Hashed Sub: issuer fingerprint(sub 33)(21 bytes)
	 v4 -	Fingerprint - de 7d e3 95 a3 c2 23 6b ec 46 50 e6 e0 47 66 c3 f7 19 d1 cb 
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Mon Nov 29 09:27:41 UTC 2021
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
		Key ID - 0xE04766C3F719D1CB
	Hash left 2 bytes - 6c 63 
	ECDSA r(255 bits) - ...
	ECDSA s(253 bits) - ...
Old: Public Subkey Packet(tag 14)(87 bytes)
	Ver 4 - new
	Public key creation time - Mon Nov 29 09:27:41 UTC 2021
	Pub alg - ECDH Elliptic Curve Diffie-Hellman Algorithm(pub 18)
	Elliptic Curve - brainpoolP256r1 (0x2B 24 03 03 02 08 01 01 07)
	ECDH Q(515 bits) - ...
	ECDH KDF params(32 bits) - ...
		KDFhashID:  	Hash alg - SHA256(hash 8)
		KDFsymAlgoID:  	Sym alg - AES with 128-bit key(sym 7)
Old: Signature Packet(tag 2)(120 bytes)
	Ver 4 - new
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - ECDSA Elliptic Curve Digital Signature Algorithm(pub 19)
	Hash alg - SHA256(hash 8)
	Hashed Sub: issuer fingerprint(sub 33)(21 bytes)
	 v4 -	Fingerprint - de 7d e3 95 a3 c2 23 6b ec 46 50 e6 e0 47 66 c3 f7 19 d1 cb 
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Mon Nov 29 09:27:41 UTC 2021
	Hashed Sub: key flags(sub 27)(1 bytes)
		Flag - This key may be used to encrypt communications
		Flag - This key may be used to encrypt storage
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - 0xE04766C3F719D1CB
	Hash left 2 bytes - 44 93 
	ECDSA r(256 bits) - ...
	ECDSA s(255 bits) - ...
