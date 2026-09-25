New: Signature Packet(tag 2)(52 bytes)
	Ver 4 - new
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA256(hash 8)
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Mon Sep 21 14:13:20 UTC 2026
	Hashed Sub: malformed subpacket(0 bytes)
	Hashed Sub: key flags(sub 27)(0 bytes)
		Malformed(too short)
	Hashed Sub: signature creation time(sub 2)(2 bytes)
		Malformed(too short)
	Hashed Sub: notation data(sub 20)(10 bytes)
		Flag - Human-readable
		Malformed(name 5 bytes, value 255 bytes)
	Hashed Sub: primary User ID(sub 25)(1 bytes)
		Primary - Yes
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - 0x0102030405060708
	Hash left 2 bytes - 12 34 
	RSA m^d mod n(16 bits) - ...
		-> PKCS-1
New: User ID Packet(tag 13)(25 bytes)
	User ID - after <after@example.com>
