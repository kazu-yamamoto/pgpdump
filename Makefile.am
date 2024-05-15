AM_CFLAGS = -O -Wall
EXTRA_DIST =

bin_PROGRAMS = pgpdump
pgpdump_SOURCES = \
	buffer.c \
	keys.c \
	packet.c \
	pgpdump.c \
	pgpdump.h \
	signature.c \
	subfunc.c \
	tagfuncs.c \
	types.c \
	uatfunc.c
dist_man1_MANS = pgpdump.1

AM_TESTS_ENVIRONMENT = PGPDUMP='$(builddir)/pgpdump'
TEST_EXTENSIONS = .res
RES_LOG_COMPILER = $(srcdir)/test/test
RES_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
TESTS = \
	test/enc1.res \
	test/enc2.res \
	test/enc3.res \
	test/enc.res \
	test/gpg1.res \
	test/gpg233_dsa_elgamal_test_key.pub.der.res \
	test/gpg233_ecc_sign_encrypt_Brainpool_P-256_test-key.pub.der.res \
	test/gpg233_ecc_sign_encrypt_Curve25519_test_key.pub.der.res \
	test/gpg233_ecc_sign_encrypt_NIST_P_384_test_key.pub.der.res \
	test/gpg233_ecc_sign_only_Brainpool_P-256_test_key.pub.der.res \
	test/gpg233_ecc_sign_only_Curve_25519_test_key.pub.der.res \
	test/gpg233_ecc_sign_only_NIST_P-384_test_key.pub.der.res \
	test/gpg-2.3.3_rsa_dsa_test_key.pub.der.res \
	test/gpg233_rsa_sign_only_test_key.pub.der.res \
	test/gpg2.res \
	test/gpg3.res \
	test/pub1.res \
	test/pub.res \
	test/sig1.res \
	test/sig2.res \
	test/sig3.res \
	test/sig.res
EXTRA_DIST += $(TESTS) $(TESTS:.res=) test/test

EXTRA_DIST += build-aux/git-version-gen
dist-hook:
	printf %s\\n '$(VERSION)' >'$(distdir)'/.dist-version
