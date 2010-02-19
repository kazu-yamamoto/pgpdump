Old: Marker Packet(tag 10)(3 bytes)
	String - ...
New: Public-Key Encrypted Session Key Packet(tag 1)(525 bytes)
	New version(3)
	Key ID - f6 70 5a bf 6e d9 54 e8 
	Pub alg - ElGamal Encrypt-Only(pub 16)
	DSA g^k mod p(2037 bits) - ...
	DSA m * y^k mod p(2048 bits) - ...
		-> m = sym alg(1) + checksum(2) + PKCS-1 block type 02
New: Symmetrically Encrypted Data Packet(tag 9)(56 bytes)
	Encrypted data [if pub/sym session key not present, sym alg - IDEA]
