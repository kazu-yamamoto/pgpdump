New: Secret Key Packet(tag 5)(73 bytes)
	Ver 4 - new
	Public key creation time - Wed Jan  1 00:00:00 UTC 2025
	Pub alg - Ed25519(pub 27)
	Ed25519 public key(32 bytes) - ...
	Ed25519 secret key(32 bytes) - ...
	Checksum - 10 e5 
New: User ID Packet(tag 13)(46 bytes)
	User ID - PQC user (Test Key) <pqc-test-key@example.com>
New: Signature Packet(tag 2)(192 bytes)
	Ver 4 - new
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - Ed25519(pub 27)
	Hash alg - SHA256(hash 8)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Wed Jan  1 00:00:00 UTC 2025
	Hashed Sub: preferred symmetric algorithms(sub 11)(2 bytes)
		Sym alg - AES with 256-bit key(sym 9)
		Sym alg - AES with 128-bit key(sym 7)
	Hashed Sub: issuer key ID(sub 16)(critical)(8 bytes)
		Key ID - 0x7102FFED3B9CF12D
	Hashed Sub: notation data(sub 20)(52 bytes)
		Flag - Normal
		Name - salt@notations.openpgpjs.org
		Value - e5 25 5b 2a 98 19 0a 3f 60 98 2e 0d b1 6b a2 57 
	Hashed Sub: preferred hash algorithms(sub 21)(1 bytes)
		Hash alg - SHA256(hash 8)
	Hashed Sub: preferred compression algorithms(sub 22)(1 bytes)
		Comp alg - Uncompressed(comp 0)
	Hashed Sub: primary User ID(sub 25)(1 bytes)
		Primary - Yes
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used to certify other keys
		Flag - This key may be used to sign data
	Hashed Sub: features(sub 30)(1 bytes)
		Flag - Modification detection (packets 18 and 19)
		Flag - Version 2 Symmetrically Encrypted and Integrity Protected Data packet
	Hashed Sub: issuer fingerprint(sub 33)(21 bytes)
	 v4 -	Fingerprint - 34 2e 5d b2 de 34 52 15 cb 2c 94 4f 71 02 ff ed 3b 9c f1 2d 
	Hashed Sub: preferred AEAD ciphersuites(sub 39)(4 bytes)
		Ciphersuite - AES with 256-bit key(sym 9) + OCB(aead 2)
		Ciphersuite - AES with 128-bit key(sym 7) + OCB(aead 2)
	Hash left 2 bytes - 8a ff 
	Ed25519 signature(64 bytes) - ...
New: Secret Subkey Packet(tag 7)(1321 bytes)
	Ver 4 - new
	Public key creation time - Wed Jan  1 00:00:00 UTC 2025
	Pub alg - ML-KEM-768+X25519(pub 35)
	X25519 public key(32 bytes) - ...
	ML-KEM-768 public key(1184 bytes) - ...
	X25519 secret key(32 bytes) - ...
	ML-KEM-768 secret key seed(64 bytes) - ...
	Checksum - 2e e5 
New: Signature Packet(tag 2)(170 bytes)
	Ver 4 - new
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - Ed25519(pub 27)
	Hash alg - SHA256(hash 8)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Wed Jan  1 00:00:00 UTC 2025
	Hashed Sub: issuer key ID(sub 16)(critical)(8 bytes)
		Key ID - 0x7102FFED3B9CF12D
	Hashed Sub: notation data(sub 20)(52 bytes)
		Flag - Normal
		Name - salt@notations.openpgpjs.org
		Value - 81 55 a7 e6 d3 2a c7 33 5f f1 a0 29 97 8d f8 50 
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used to encrypt communications
		Flag - This key may be used to encrypt storage
	Hashed Sub: issuer fingerprint(sub 33)(21 bytes)
	 v4 -	Fingerprint - 34 2e 5d b2 de 34 52 15 cb 2c 94 4f 71 02 ff ed 3b 9c f1 2d 
	Hash left 2 bytes - e7 fd 
	Ed25519 signature(64 bytes) - ...
