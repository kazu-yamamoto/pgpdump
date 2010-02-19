Old: One-Pass Signature Packet(tag 4)(13 bytes)
	New version(3)
	Sig type - Signature of a binary document(0x00).
	Hash alg - SHA1(hash 2)
	Pub alg - DSA Digital Signature Standard(pub 17)
	Key ID - fd 90 da 97 32 d8 eb d2 
	Next packet - other than one pass signature
Old: Literal Data Packet(tag 11)(45 bytes)
	Format - binary
	Filename - hoge
	File modified time - Sat Nov 28 01:11:39 JST 1998
	Literal - ...
Old: Signature Packet(tag 2)(70 bytes)
	Ver 4 - new
	Sig type - Signature of a binary document(0x00).
	Pub alg - DSA Digital Signature Standard(pub 17)
	Hash alg - SHA1(hash 2)
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Sat Nov 28 01:11:39 JST 1998
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - fd 90 da 97 32 d8 eb d2 
	Hash left 2 bytes - 0a 7d 
	DSA r(160 bits) - ...
	DSA s(159 bits) - ...
		-> hash(160 bits)
