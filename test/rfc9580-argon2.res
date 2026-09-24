New: Symmetric-Key Encrypted Session Key Packet(tag 3)(39 bytes)
	New version(4)
	Sym alg - AES with 128-bit key(sym 7)
	Argon2 string-to-key(s2k 4):
		Salt - 9c 52 f8 3c 27 f9 5e 50 d5 35 44 0e cd ff 31 36 
		Passes - 1
		Parallelism - 4
		Memory - 2^21 KiB
	Encrypted session key
		-> sym alg(1 bytes) + session key
New: Symmetrically Encrypted and MDC Packet(tag 18)(62 bytes)
	Ver 1
	Encrypted data [sym alg is specified in sym-key encrypted session key]
		(plain text + MDC SHA1(20 bytes))
