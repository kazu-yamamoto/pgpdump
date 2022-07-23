# pgpdump: a PGP packet visualizer

- Kazu Yamamoto <kazu@iij.ad.jp>
- August 16, 2010

## Overview

**pgpdump** is a PGP packet visualizer which displays the packet format of OpenPGP ([RFC 4880](https://datatracker.ietf.org/doc/html/rfc4880)) and PGP version 2 ([RFC 1991](https://datatracker.ietf.org/doc/html/rfc1991)).

Here is an example:

	% pgpdump data/sig1
	Old: Marker Packet(tag 10)(3 bytes)
		String - ...
	New: One-Pass Signature Packet(tag 4)(13 bytes)
		New version(3)
		Sig type - Signature of a binary document(0x00).
		Hash alg - SHA1(hash 2)
		Pub alg - DSA Digital Signature Algorithm(pub 17)
		Key ID - 0xA79778E247B63037
		Next packet - other than one pass signature
	New: Signature Packet(tag 2)(63 bytes)
		Ver 3 - old
		Hash material(5 bytes):
			Sig type - Signature of a binary document(0x00).
			Creation time - Fri Nov 27 22:35:02 JST 1998
		Key ID - 0xA79778E247B63037
		Pub alg - DSA Digital Signature Algorithm(pub 17)
		Hash alg - SHA1(hash 2)
		Hash left 2 bytes - 8f 82
		DSA r(160 bits) - ...
		DSA s(157 bits) - ...
			-> hash(DSA q bits)

## Installation

Take the following steps to install **pgpdump**.

	% ./configure
	% make
	% su
	# make install

Binaries are available for Mac OS X via Homebrew:

	% brew install pgpdump

## Usage

To know how to use pgpdump, type `pgpdump -h`.

Some examples are stored in the `data` directory. Also, you can visualize your pubring and secring.

## Home page

The official home page of pgpdump is:

* https://www.mew.org/~kazu/proj/pgpdump/

## Bugs

* pgpdump assumes that a compressed packet continues until the end of the specified file.

## Testing

The test program is written in Haskell. I recommend to install [Haskell Platform](https://www.haskell.org/platform/) if you want to test. After that, please install necessary libraries:

	% cabal install test-framework-hunit


Now you can execute the test program:

	% cd data
	% runghc test.hs
