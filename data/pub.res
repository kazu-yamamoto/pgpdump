Old: Public Key Packet(tag 6)(418 bytes)
	Ver 4 - new
	Public key creation time - Thu Nov 26 22:49:00 1998
	Pub alg - DSA Digital Signature Standard(pub 17)
	DSA p(1024 bits) - ...
	DSA q(160 bits) - ...
	DSA g(1024 bits) - ...
	DSA y(1021 bits) - ...
Old: User ID Packet(tag 13)(31 bytes)
	User ID - Kazu Yamamoto <kazu@iijlab.net>
Old: Signature Packet(tag 2)(75 bytes)
	Ver 4 - new
	Sig type - Generic certification of a User ID and Public Key packet(0x10).
	Pub alg - DSA Digital Signature Standard(pub 17)
	Hash alg - SHA1(hash 2)
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Thu Nov 26 22:49:00 1998
	Hashed Sub: preferred symmetric algorithms(sub 11)(3 bytes)
		Sym alg - CAST5(sym 3)
		Sym alg - IDEA(sym 1)
		Sym alg - Triple-DES(sym 2)
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - a7 97 78 e2 47 b6 30 37 
	Hash left 2 bytes - 7e 87 
	DSA r(160 bits) - ...
	DSA s(154 bits) - ...
		-> hash(160 bits)
Old: User ID Packet(tag 13)(20 bytes)
	User ID - robby@dd.iij4u.or.jp
Old: Signature Packet(tag 2)(75 bytes)
	Ver 4 - new
	Sig type - Generic certification of a User ID and Public Key packet(0x10).
	Pub alg - DSA Digital Signature Standard(pub 17)
	Hash alg - SHA1(hash 2)
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Fri Nov 27 02:18:58 1998
	Hashed Sub: preferred symmetric algorithms(sub 11)(3 bytes)
		Sym alg - CAST5(sym 3)
		Sym alg - IDEA(sym 1)
		Sym alg - Triple-DES(sym 2)
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - a7 97 78 e2 47 b6 30 37 
	Hash left 2 bytes - ba ef 
	DSA r(160 bits) - ...
	DSA s(160 bits) - ...
		-> hash(160 bits)
Old: Public Subkey Packet(tag 14)(525 bytes)
	Ver 4 - new
	Public key creation time - Thu Nov 26 22:49:00 1998
	Pub alg - ElGamal Encrypt-Only(pub 16)
	ElGamal p(2048 bits) - ...
	ElGamal g(2 bits) - ...
	ElGamal y(2048 bits) - ...
Old: Signature Packet(tag 2)(63 bytes)
	Ver 3 - old
	Hash material(5 bytes):
		Sig type - Subkey Binding Signature(0x18).
		Creation time - Thu Nov 26 22:49:00 1998
	Key ID - a7 97 78 e2 47 b6 30 37 
	Pub alg - DSA Digital Signature Standard(pub 17)
	Hash alg - SHA1(hash 2)
	Hash left 2 bytes - e8 41 
	DSA r(160 bits) - ...
	DSA s(160 bits) - ...
		-> hash(160 bits)
