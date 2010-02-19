Old: Public Key Packet(tag 6)(418 bytes)
	Ver 4 - new
	Public key creation time - Sun Oct 11 23:27:53 JST 1998
	Pub alg - DSA Digital Signature Algorithm(pub 17)
	DSA p(1024 bits) - ...
	DSA q(160 bits) - ...
	DSA g(1023 bits) - ...
	DSA y(1023 bits) - ...
Old: User ID Packet(tag 13)(35 bytes)
	User ID - Kazuhiko Yamamoto <kazu@iijlab.net>
Old: Signature Packet(tag 2)(87 bytes)
	Ver 4 - new
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - DSA Digital Signature Algorithm(pub 17)
	Hash alg - SHA1(hash 2)
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Sun Oct 11 23:27:53 JST 1998
	Hashed Sub: preferred symmetric algorithms(sub 11)(2 bytes)
		Sym alg - Blowfish(sym 4)
		Sym alg - CAST5(sym 3)
	Hashed Sub: preferred hash algorithms(sub 21)(4 bytes)
		Hash alg - RIPEMD160(hash 3)
		Hash alg - SHA1(hash 2)
		Hash alg - TIGER192(hash 6)
		Hash alg - MD5(hash 1)
	Hashed Sub: preferred compression algorithms(sub 22)(2 bytes)
		Comp alg - ZLIB <RFC1950>(comp 2)
		Comp alg - ZIP <RFC1951>(comp 1)
	Hashed Sub: key server preferences(sub 23)(1 bytes)
		Flag - No-modify
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - 0xFD90DA9732D8EBD2
	Hash left 2 bytes - e2 cb 
	DSA r(158 bits) - ...
	DSA s(158 bits) - ...
		-> hash(160 bits)
Old: Public Subkey Packet(tag 14)(269 bytes)
	Ver 4 - new
	Public key creation time - Sun Oct 11 23:29:23 JST 1998
	Pub alg - ElGamal Encrypt-Only(pub 16)
	ElGamal p(1024 bits) - ...
	ElGamal g(3 bits) - ...
	ElGamal y(1024 bits) - ...
Old: Signature Packet(tag 2)(70 bytes)
	Ver 4 - new
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - DSA Digital Signature Algorithm(pub 17)
	Hash alg - SHA1(hash 2)
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Sun Oct 11 23:29:23 JST 1998
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - 0xFD90DA9732D8EBD2
	Hash left 2 bytes - 42 66 
	DSA r(160 bits) - ...
	DSA s(160 bits) - ...
		-> hash(160 bits)
