New: Secret Key Packet(tag 5)(2749 bytes)
	Ver 6 - latest
	Public key creation time - Wed Jan  1 00:00:00 UTC 2025
	Pub alg - ML-DSA-87+Ed448(pub 31)
	Ed448 public key(57 bytes) - ...
	ML-DSA-87 public key(2592 bytes) - ...
	Ed448 secret key(57 bytes) - ...
	ML-DSA-87 secret key seed(32 bytes) - ...
New: Signature Packet(tag 2)(4852 bytes)
	Ver 6 - latest
	Sig type - Signature directly on a key(0x1f).
	Pub alg - ML-DSA-87+Ed448(pub 31)
	Hash alg - SHA3-512(hash 14)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Wed Jan  1 00:00:00 UTC 2025
	Hashed Sub: preferred symmetric algorithms(sub 11)(2 bytes)
		Sym alg - AES with 256-bit key(sym 9)
		Sym alg - AES with 128-bit key(sym 7)
	Hashed Sub: preferred hash algorithms(sub 21)(2 bytes)
		Hash alg - SHA3-512(hash 14)
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
	 v6 -	Fingerprint - 0d 7a 8b e1 41 0c d6 8e ed 48 45 ab 48 7b 4b 4c fa ec d8 eb ad 1a 11 66 a8 42 30 49 92 00 ee 20 
	Hashed Sub: preferred AEAD ciphersuites(sub 39)(4 bytes)
		Ciphersuite - AES with 256-bit key(sym 9) + OCB(aead 2)
		Ciphersuite - AES with 128-bit key(sym 7) + OCB(aead 2)
	Hash left 2 bytes - 9e f1 
	Salt - 89 33 e7 92 67 39 22 1f 94 e6 b3 69 2b d5 9a a9 db 96 e7 88 e2 85 dc ca 31 e4 27 2f 68 25 b7 5e 
	Ed448 signature(114 bytes) - ...
	ML-DSA-87 signature(4627 bytes) - ...
New: User ID Packet(tag 13)(46 bytes)
	User ID - PQC user (Test Key) <pqc-test-key@example.com>
New: Signature Packet(tag 2)(4832 bytes)
	Ver 6 - latest
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - ML-DSA-87+Ed448(pub 31)
	Hash alg - SHA3-512(hash 14)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Wed Jan  1 00:00:00 UTC 2025
	Hashed Sub: primary User ID(sub 25)(1 bytes)
		Primary - Yes
	Hashed Sub: issuer fingerprint(sub 33)(critical)(33 bytes)
	 v6 -	Fingerprint - 0d 7a 8b e1 41 0c d6 8e ed 48 45 ab 48 7b 4b 4c fa ec d8 eb ad 1a 11 66 a8 42 30 49 92 00 ee 20 
	Hash left 2 bytes - 3b f8 
	Salt - 85 9e 0a e1 29 a6 8b ee b2 65 72 3c 94 09 c7 5f e5 97 41 f3 c8 54 4b cb 5b 04 6f 46 35 48 ca 22 
	Ed448 signature(114 bytes) - ...
	ML-DSA-87 signature(4627 bytes) - ...
New: Secret Subkey Packet(tag 7)(1755 bytes)
	Ver 6 - latest
	Public key creation time - Wed Jan  1 00:00:00 UTC 2025
	Pub alg - ML-KEM-1024+X448(pub 36)
	X448 public key(56 bytes) - ...
	ML-KEM-1024 public key(1568 bytes) - ...
	X448 secret key(56 bytes) - ...
	ML-KEM-1024 secret key seed(64 bytes) - ...
New: Signature Packet(tag 2)(4832 bytes)
	Ver 6 - latest
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - ML-DSA-87+Ed448(pub 31)
	Hash alg - SHA3-512(hash 14)
	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
		Time - Wed Jan  1 00:00:00 UTC 2025
	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
		Flag - This key may be used to encrypt communications
		Flag - This key may be used to encrypt storage
	Hashed Sub: issuer fingerprint(sub 33)(critical)(33 bytes)
	 v6 -	Fingerprint - 0d 7a 8b e1 41 0c d6 8e ed 48 45 ab 48 7b 4b 4c fa ec d8 eb ad 1a 11 66 a8 42 30 49 92 00 ee 20 
	Hash left 2 bytes - b0 64 
	Salt - e4 42 74 aa 92 9c 72 60 4e 97 71 37 ee 6f 44 37 1b 5a 2f 2e f4 db bd 51 ab 43 c3 61 a1 96 3c 13 
	Ed448 signature(114 bytes) - ...
	ML-DSA-87 signature(4627 bytes) - ...
