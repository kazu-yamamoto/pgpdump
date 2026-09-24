Old: Secret Key Packet(tag 5)(143 bytes)
	Ver 5 - librepgp
	Public key creation time - Thu Sep 24 21:25:17 UTC 2026
	Pub alg - EdDSA Edwards-curve Digital Signature Algorithm(pub 22)
	Elliptic Curve - Ed25519 (0x2B 06 01 04 01 DA 47 0F 01)
	EdDSA Q(263 bits) - ...
	Sym alg - AES with 128-bit key(sym 7)
	Iterated and salted string-to-key(s2k 3):
		Hash alg - SHA1(hash 2)
		Salt - 47 e6 c8 a6 00 da 50 0c 
		Count - 65011712(coded count 255)
	IV - e8 5a 89 48 49 f7 49 12 e9 a3 63 c2 42 13 3f a8 
	Encrypted EdDSA x
	Encrypted SHA1 hash
Old: User ID Packet(tag 13)(23 bytes)
	User ID - pw v5 <pw5@example.com>
Old: Signature Packet(tag 2)(177 bytes)
	Ver 5 - librepgp
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - EdDSA Edwards-curve Digital Signature Algorithm(pub 22)
	Hash alg - SHA512(hash 10)
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v5 -	Fingerprint - b2 78 1d 25 c0 fd 39 ab d1 bd 48 0e fa eb 24 9d 39 7d d3 11 1e c4 da 09 b9 6d 17 8e 68 fa 9b cd 
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Thu Sep 24 21:25:17 UTC 2026
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
	Hashed Sub: preferred_aead_algorithms(sub 34)(1 bytes)
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
		Flag - Reserved (AEAD Encrypted Data)
		Flag - Reserved (v5 keys)
	Hashed Sub: key server preferences(sub 23)(1 bytes)
		Flag - No-modify
	Hash left 2 bytes - 0c df 
	EdDSA R(254 bits) - ...
	EdDSA s(256 bits) - ...
