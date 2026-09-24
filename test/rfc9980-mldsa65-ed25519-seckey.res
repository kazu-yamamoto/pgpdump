New: Secret Key Packet(tag 5)(2059 bytes)
	Ver 6 - latest
	Public key creation time - Wed Jan  1 00:00:00 UTC 2025
	Pub alg - ML-DSA-65+Ed25519(pub 30)
	Ed25519 public key(32 bytes) - ...
	ML-DSA-65 public key(1952 bytes) - ...
	Ed25519 secret key(32 bytes) - ...
	ML-DSA-65 secret key seed(32 bytes) - ...
New: Signature Packet(tag 2)(3468 bytes)
	Ver 6 - latest
	Sig type - Signature directly on a key(0x1f).
	Pub alg - ML-DSA-65+Ed25519(pub 30)
	Hash alg - SHA3-256(hash 12)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Wed Jan  1 00:00:00 UTC 2025
	Hashed Sub: preferred symmetric algorithms(sub 11)(2 bytes)
		Sym alg - AES with 256-bit key(sym 9)
		Sym alg - AES with 128-bit key(sym 7)
	Hashed Sub: preferred hash algorithms(sub 21)(2 bytes)
		Hash alg - SHA3-256(hash 12)
		Hash alg - SHA256(hash 8)
	Hashed Sub: preferred compression algorithms(sub 22)(1 bytes)
		Comp alg - Uncompressed(comp 0)
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used to certify other keys
		Flag - This key may be used to sign data
	Hashed Sub: features(sub 30)(1 bytes)
		Flag - Modification detection (packets 18 and 19)
		Flag - Version 2 Symmetrically Encrypted and Integrity Protected Data packet
	Hashed Sub: issuer fingerprint(sub 33)(critical)(33 bytes)
	 v6 -	Fingerprint - a3 e2 e1 4b 6a 49 3f f9 30 fb 27 32 1f 12 5e 9a 68 80 33 8b e9 fb 7d a3 ae 06 5e a6 57 93 24 2f 
	Hashed Sub: preferred AEAD ciphersuites(sub 39)(4 bytes)
		Ciphersuite - AES with 256-bit key(sym 9) + OCB(aead 2)
		Ciphersuite - AES with 128-bit key(sym 7) + OCB(aead 2)
	Hash left 2 bytes - af 20 
	Salt - c7 1d 71 be 48 16 e2 73 c0 bd 5d 4c 0d dd c1 75 
	Ed25519 signature(64 bytes) - ...
	ML-DSA-65 signature(3309 bytes) - ...
New: User ID Packet(tag 13)(46 bytes)
	User ID - PQC user (Test Key) <pqc-test-key@example.com>
New: Signature Packet(tag 2)(3448 bytes)
	Ver 6 - latest
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - ML-DSA-65+Ed25519(pub 30)
	Hash alg - SHA3-256(hash 12)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Wed Jan  1 00:00:00 UTC 2025
	Hashed Sub: primary User ID(sub 25)(1 bytes)
		Primary - Yes
	Hashed Sub: issuer fingerprint(sub 33)(critical)(33 bytes)
	 v6 -	Fingerprint - a3 e2 e1 4b 6a 49 3f f9 30 fb 27 32 1f 12 5e 9a 68 80 33 8b e9 fb 7d a3 ae 06 5e a6 57 93 24 2f 
	Hash left 2 bytes - ce f2 
	Salt - 13 6a 34 bb 16 6c d1 ac 8f 01 5e c3 66 77 fc 2b 
	Ed25519 signature(64 bytes) - ...
	ML-DSA-65 signature(3309 bytes) - ...
New: Secret Subkey Packet(tag 7)(1323 bytes)
	Ver 6 - latest
	Public key creation time - Wed Jan  1 00:00:00 UTC 2025
	Pub alg - ML-KEM-768+X25519(pub 35)
	X25519 public key(32 bytes) - ...
	ML-KEM-768 public key(1184 bytes) - ...
	X25519 secret key(32 bytes) - ...
	ML-KEM-768 secret key seed(64 bytes) - ...
New: Signature Packet(tag 2)(3448 bytes)
	Ver 6 - latest
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - ML-DSA-65+Ed25519(pub 30)
	Hash alg - SHA3-256(hash 12)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Wed Jan  1 00:00:00 UTC 2025
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used to encrypt communications
		Flag - This key may be used to encrypt storage
	Hashed Sub: issuer fingerprint(sub 33)(critical)(33 bytes)
	 v6 -	Fingerprint - a3 e2 e1 4b 6a 49 3f f9 30 fb 27 32 1f 12 5e 9a 68 80 33 8b e9 fb 7d a3 ae 06 5e a6 57 93 24 2f 
	Hash left 2 bytes - 19 61 
	Salt - 0e 38 5b fd 0a 18 4a d4 5c 1d 63 1e 63 80 38 81 
	Ed25519 signature(64 bytes) - ...
	ML-DSA-65 signature(3309 bytes) - ...
