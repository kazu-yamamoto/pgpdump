New: Secret Key Packet(tag 5)(107 bytes)
	Ver 6 - latest
	Public key creation time - Wed Jan  1 00:00:00 UTC 2025
	Pub alg - SLH-DSA-SHAKE-128s(pub 32)
	SLH-DSA public key(32 bytes) - ...
	SLH-DSA secret key(64 bytes) - ...
New: Signature Packet(tag 2)(7951 bytes)
	Ver 6 - latest
	Sig type - Signature directly on a key(0x1f).
	Pub alg - SLH-DSA-SHAKE-128s(pub 32)
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
	 v6 -	Fingerprint - ee d4 d1 3f c3 6c 78 e4 82 76 a9 32 33 33 9c 4d d2 30 fd 5f 6f 5c 5b 82 c6 3d 5c 0b 5e 36 1d 92 
	Hashed Sub: preferred AEAD ciphersuites(sub 39)(4 bytes)
		Ciphersuite - AES with 256-bit key(sym 9) + OCB(aead 2)
		Ciphersuite - AES with 128-bit key(sym 7) + OCB(aead 2)
	Hash left 2 bytes - a7 25 
	Salt - 27 b4 24 72 6e a0 a9 32 37 f7 b4 b6 79 94 ec a5 
	SLH-DSA signature(7856 bytes) - ...
New: User ID Packet(tag 13)(46 bytes)
	User ID - PQC user (Test Key) <pqc-test-key@example.com>
New: Signature Packet(tag 2)(7931 bytes)
	Ver 6 - latest
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - SLH-DSA-SHAKE-128s(pub 32)
	Hash alg - SHA3-256(hash 12)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Wed Jan  1 00:00:00 UTC 2025
	Hashed Sub: primary User ID(sub 25)(1 bytes)
		Primary - Yes
	Hashed Sub: issuer fingerprint(sub 33)(critical)(33 bytes)
	 v6 -	Fingerprint - ee d4 d1 3f c3 6c 78 e4 82 76 a9 32 33 33 9c 4d d2 30 fd 5f 6f 5c 5b 82 c6 3d 5c 0b 5e 36 1d 92 
	Hash left 2 bytes - 97 14 
	Salt - 4a cf 3e 5c a3 ce dd 87 b0 c3 79 1d 34 66 6b 10 
	SLH-DSA signature(7856 bytes) - ...
New: Secret Subkey Packet(tag 7)(1323 bytes)
	Ver 6 - latest
	Public key creation time - Wed Jan  1 00:00:00 UTC 2025
	Pub alg - ML-KEM-768+X25519(pub 35)
	X25519 public key(32 bytes) - ...
	ML-KEM-768 public key(1184 bytes) - ...
	X25519 secret key(32 bytes) - ...
	ML-KEM-768 secret key seed(64 bytes) - ...
New: Signature Packet(tag 2)(7931 bytes)
	Ver 6 - latest
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - SLH-DSA-SHAKE-128s(pub 32)
	Hash alg - SHA3-256(hash 12)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Wed Jan  1 00:00:00 UTC 2025
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used to encrypt communications
		Flag - This key may be used to encrypt storage
	Hashed Sub: issuer fingerprint(sub 33)(critical)(33 bytes)
	 v6 -	Fingerprint - ee d4 d1 3f c3 6c 78 e4 82 76 a9 32 33 33 9c 4d d2 30 fd 5f 6f 5c 5b 82 c6 3d 5c 0b 5e 36 1d 92 
	Hash left 2 bytes - 66 fd 
	Salt - 38 16 b4 47 06 6f d3 8c af 6c d9 01 35 ae a9 b5 
	SLH-DSA signature(7856 bytes) - ...
