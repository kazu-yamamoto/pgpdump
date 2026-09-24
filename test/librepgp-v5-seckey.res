Old: Secret Key Packet(tag 5)(140 bytes)
	Ver 5 - librepgp
	Public key creation time - Thu Sep 24 21:24:52 UTC 2026
	Pub alg - EdDSA Edwards-curve Digital Signature Algorithm(pub 22)
	Elliptic Curve - Ed448 (0x2B 65 71)
	EdDSA Q(455 bits) - ...
	EdDSA x(456 bits) - ...
	Checksum - 1f 50 
Old: User ID Packet(tag 13)(25 bytes)
	User ID - ed448 <ed448@example.com>
Old: Signature Packet(tag 2)(227 bytes)
	Ver 5 - librepgp
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - EdDSA Edwards-curve Digital Signature Algorithm(pub 22)
	Hash alg - SHA512(hash 10)
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v5 -	Fingerprint - 7b 5f 9b bc b4 1d 49 56 25 eb 63 6d 8f 24 8e 4c 3e 79 dd 1c e0 10 54 a5 b9 9f 66 1f d3 98 73 9b 
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Thu Sep 24 21:24:52 UTC 2026
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
	Hash left 2 bytes - 10 23 
	EdDSA R(456 bits) - ...
	EdDSA s(454 bits) - ...
Old: Secret Subkey Packet(tag 7)(142 bytes)
	Ver 5 - librepgp
	Public key creation time - Thu Sep 24 21:25:03 UTC 2026
	Pub alg - ECDH Elliptic Curve Diffie-Hellman Algorithm(pub 18)
	Elliptic Curve - X448 (0x2B 65 6F)
	ECDH Q(446 bits) - ...
	ECDH KDF params(32 bits) - ...
		KDFhashID:  	Hash alg - SHA512(hash 10)
		KDFsymAlgoID:  	Sym alg - AES with 256-bit key(sym 9)
	ECDH x(448 bits) - ...
	Checksum - 1d f7 
Old: Signature Packet(tag 2)(200 bytes)
	Ver 5 - librepgp
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - EdDSA Edwards-curve Digital Signature Algorithm(pub 22)
	Hash alg - SHA512(hash 10)
	Hashed Sub: issuer fingerprint(sub 33)(33 bytes)
	 v5 -	Fingerprint - 7b 5f 9b bc b4 1d 49 56 25 eb 63 6d 8f 24 8e 4c 3e 79 dd 1c e0 10 54 a5 b9 9f 66 1f d3 98 73 9b 
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Thu Sep 24 21:25:03 UTC 2026
	Hashed Sub: notation data(sub 20)(26 bytes)
		Flag - Human-readable
		Name - manu
		Value - 2,2.5+1.12,0,3
	Hashed Sub: key flags(sub 27)(1 bytes)
		Flag - This key may be used to encrypt communications
		Flag - This key may be used to encrypt storage
	Hash left 2 bytes - 5f e8 
	EdDSA R(455 bits) - ...
	EdDSA s(455 bits) - ...
