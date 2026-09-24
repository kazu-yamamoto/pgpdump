Old: Public Key Packet(tag 6)(273 bytes)
	Ver 5 - librepgp
	Public key creation time - Thu Sep 24 21:25:03 UTC 2026
	Pub alg - RSA Encrypt or Sign(pub 1)
	RSA n(2048 bits) - ...
	RSA e(17 bits) - ...
Old: User ID Packet(tag 13)(23 bytes)
	User ID - rsa v5 <r5@example.com>
Old: Signature Packet(tag 2)(367 bytes)
	Ver 5 - librepgp
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA256(hash 8)
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v5 -	Fingerprint - 1c 14 7b 18 3b 0a 5e 02 93 e1 12 08 90 49 92 9c d4 30 56 fd 7c 56 e4 53 09 9a 89 bc 1c df a4 56 
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Thu Sep 24 21:25:03 UTC 2026
	Hashed Sub: notation data(sub 20)(26 bytes)
		Flag - Human-readable
		Name - manu
		Value - 2,2.5+1.12,0,3
	Hashed Sub: key flags(sub 27)(1 bytes)
		Flag - This key may be used to certify other keys
		Flag - This key may be used to sign data
	Hashed Sub: preferred symmetric algorithms(sub 11)(4 bytes)
		Sym alg - AES with 256-bit key(sym 9)
		Sym alg - AES with 192-bit key(sym 8)
		Sym alg - AES with 128-bit key(sym 7)
		Sym alg - Triple-DES(sym 2)
	Hashed Sub: preferred encryption modes(sub 34)(1 bytes)
		AEAD alg - OCB(aead 2)
	Hashed Sub: preferred hash algorithms(sub 21)(5 bytes)
		Hash alg - SHA512(hash 10)
		Hash alg - SHA384(hash 9)
		Hash alg - SHA256(hash 8)
		Hash alg - SHA224(hash 11)
		Hash alg - SHA1(hash 2)
	Hashed Sub: preferred compression algorithms(sub 22)(3 bytes)
		Comp alg - ZLIB <RFC1950>(comp 2)
		Comp alg - BZip2(comp 3)
		Comp alg - ZIP <RFC1951>(comp 1)
	Hashed Sub: features(sub 30)(1 bytes)
		Flag - Modification detection (packets 18 and 19)
		Flag - OCB Encrypted Data (packet 20) and version 5 Symmetric-Key Encrypted Session Key (packet 3) [LibrePGP]
		Flag - Version 5 keys and fingerprints [LibrePGP]
	Hashed Sub: key server preferences(sub 23)(1 bytes)
		Flag - No-modify
	Hash left 2 bytes - 22 2d 
	RSA m^d mod n(2048 bits) - ...
		-> PKCS-1
