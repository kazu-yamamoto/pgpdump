Old: One-Pass Signature Packet(tag 4)(13 bytes)
	New version(3)
	Sig type - Signature of a binary document(0x00).
	Hash alg - SHA1(hash 2)
	Pub alg - DSA Digital Signature Algorithm(pub 17)
	Key ID - 0xFD90DA9732D8EBD2
	Next packet - other than one pass signature
Old: Literal Data Packet(tag 11)(45 bytes)
	Packet data format - binary
	Filename - hoge
	Creation time - Fri Nov 27 16:11:39 UTC 1998
	Literal - ...
Old: Signature Packet(tag 2)(70 bytes)
	Ver 4 - new
	Sig type - Signature of a binary document(0x00).
	Pub alg - DSA Digital Signature Algorithm(pub 17)
	Hash alg - SHA1(hash 2)
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Fri Nov 27 16:11:39 UTC 1998
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - 0xFD90DA9732D8EBD2
	Hash left 2 bytes - 0a 7d 
	DSA r(160 bits) - ...
	DSA s(159 bits) - ...
		-> hash(DSA q bits)
