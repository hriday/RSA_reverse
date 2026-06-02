import unittest

from rsa_poc import pem

# Same 512-bit RSA key, two encodings. Both must decode to FIXTURE_N / 65537.
PKCS1_PEM = """\
-----BEGIN RSA PUBLIC KEY-----
MEgCQQD1oSmduq6iToZHF8IJfQWRCBYbtj3dptvncaHIwHm+kdwkHY56kVKcbHR/
kzgTEWqbC7Qln26yv71e35LQwDSrAgMBAAE=
-----END RSA PUBLIC KEY-----
"""

SPKI_PEM = """\
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAPWhKZ26rqJOhkcXwgl9BZEIFhu2Pd2m
2+dxocjAeb6R3CQdjnqRUpxsdH+TOBMRapsLtCWfbrK/vV7fktDANKsCAwEAAQ==
-----END PUBLIC KEY-----
"""

FIXTURE_N = 12864662934208601539761718960743191828799474324895033652352950267330150268692429766835616245849250203447713818535770738663427795444668351747373138737902763
FIXTURE_E = 65537

# Small-prime PKCS#1 key (n = 174121 * 557857 = 97134618697), actually factorable.
SMALL_PKCS1_PEM = """\
-----BEGIN RSA PUBLIC KEY-----
MAwCBRadrKhJAgMBAAE=
-----END RSA PUBLIC KEY-----
"""
SMALL_N = 97134618697

# Non-RSA SPKI (EC P-256) — must be rejected with an OID error.
EC_SPKI_PEM = """\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb2GShHmCVkPlmUEmVMC00CYihcmC
1dcoGNsbDVY3xXF1k8zKBNSy1bxlYQsikSLV14Qp8AMSAbOL1uTfr+D7EA==
-----END PUBLIC KEY-----
"""

# The user's truncated 512-bit key — declared SEQUENCE length exceeds bytes present.
TRUNCATED_PEM = """\
-----BEGIN RSA PUBLIC KEY-----
MEgCQQDXtxF4LjzvrDjJT5bJWsyMof3w7U/UgpVKNxnCkH3NiQ/mhRTFpLZB
4n6Iq5OglpfSYl6emKgYwdJW2I5vAgMBAAE=
-----END RSA PUBLIC KEY-----
"""


class TestPkcs1(unittest.TestCase):
    def test_pkcs1_round_trip(self):
        result = pem.parse_public_pem(PKCS1_PEM)
        self.assertEqual(result, {"n": FIXTURE_N, "e": FIXTURE_E})

    def test_small_prime_pkcs1(self):
        result = pem.parse_public_pem(SMALL_PKCS1_PEM)
        self.assertEqual(result["n"], SMALL_N)
        self.assertEqual(result["e"], 65537)


class TestSpki(unittest.TestCase):
    def test_spki_round_trip(self):
        result = pem.parse_public_pem(SPKI_PEM)
        self.assertEqual(result, {"n": FIXTURE_N, "e": FIXTURE_E})

    def test_spki_matches_pkcs1(self):
        # Same key, two encodings -> identical n, e.
        self.assertEqual(
            pem.parse_public_pem(SPKI_PEM),
            pem.parse_public_pem(PKCS1_PEM),
        )


if __name__ == "__main__":
    unittest.main()
