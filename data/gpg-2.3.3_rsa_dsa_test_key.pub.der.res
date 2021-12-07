Old: Public Key Packet(tag 6)(397 bytes)
	Ver 4 - new
	Public key creation time - Mon Nov 29 09:04:17 UTC 2021
	Pub alg - RSA Encrypt or Sign(pub 1)
	RSA n(3072 bits) - ...
	RSA e(17 bits) - ...
Old: User ID Packet(tag 13)(29 bytes)
	User ID -  (gpg-2.3.3_rsa_dsa_test_key)
Old: Signature Packet(tag 2)(465 bytes)
	Ver 4 - new
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA256(hash 8)
	Hashed Sub: issuer fingerprint(sub 33)(21 bytes)
	 v4 -	Fingerprint - fb 8a 1b 1a e9 5b 82 66 63 8f f7 5b 0b 4b 30 cd 79 26 1d 66 
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Mon Nov 29 09:04:17 UTC 2021
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
		Key ID - 0x0B4B30CD79261D66
	Hash left 2 bytes - ca 51 
	RSA m^d mod n(3071 bits) - ...
		-> PKCS-1
Old: Public Subkey Packet(tag 14)(397 bytes)
	Ver 4 - new
	Public key creation time - Mon Nov 29 09:04:17 UTC 2021
	Pub alg - RSA Encrypt or Sign(pub 1)
	RSA n(3072 bits) - ...
	RSA e(17 bits) - ...
Old: Signature Packet(tag 2)(438 bytes)
	Ver 4 - new
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA256(hash 8)
	Hashed Sub: issuer fingerprint(sub 33)(21 bytes)
	 v4 -	Fingerprint - fb 8a 1b 1a e9 5b 82 66 63 8f f7 5b 0b 4b 30 cd 79 26 1d 66 
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Mon Nov 29 09:04:17 UTC 2021
	Hashed Sub: key flags(sub 27)(1 bytes)
		Flag - This key may be used to encrypt communications
		Flag - This key may be used to encrypt storage
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - 0x0B4B30CD79261D66
	Hash left 2 bytes - 19 3c 
	RSA m^d mod n(3071 bits) - ...
		-> PKCS-1
