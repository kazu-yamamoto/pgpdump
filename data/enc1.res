Old: Marker Packet(tag 10)(3 bytes)
	String - ...
New: Symmetric-Key Encrypted Session Key Packet(tag 3)(4 bytes)
	New version(4)
	Sym alg - CAST5(sym 3)
	String-to-key(s2k 0):
		Hash alg - MD5(hash 1)
New: Symmetrically Encrypted Data Packet(tag 9)(56 bytes)
	Encrypted data [sym alg is CAST5(sym 3)]
