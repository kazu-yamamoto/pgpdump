Old: Public Key Packet(tag 6)(397 bytes)
	Ver 4 - new
	Public key creation time - Mon Nov 29 09:15:37 UTC 2021
	Pub alg - RSA Encrypt or Sign(pub 1)
	RSA n(3072 bits) - ...
	RSA e(17 bits) - ...
Old: User ID Packet(tag 13)(32 bytes)
	User ID -  (gpg233_rsa_sign_only_test_key)
Old: Signature Packet(tag 2)(465 bytes)
	Ver 4 - new
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA256(hash 8)
	Hashed Sub: issuer fingerprint(sub 33)(21 bytes)
	 v4 -	Fingerprint - 15 16 1e 0a 76 1e 5b 67 1f d3 23 93 bb db 73 68 49 f1 11 dd 
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Mon Nov 29 09:15:37 UTC 2021
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
		Key ID - 0xBBDB736849F111DD
	Hash left 2 bytes - 2d d0 
	RSA m^d mod n(3072 bits) - ...
		-> PKCS-1
