import json
import tempfile
import unittest
from pathlib import Path

from rsa_poc import keyfile, pem

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


class TestErrors(unittest.TestCase):
    def test_truncated_key_raises(self):
        with self.assertRaises(ValueError) as cm:
            pem.parse_public_pem(TRUNCATED_PEM)
        self.assertIn("declared length exceeds", str(cm.exception))

    def test_non_rsa_oid_raises(self):
        with self.assertRaises(ValueError) as cm:
            pem.parse_public_pem(EC_SPKI_PEM)
        self.assertIn("not an RSA key", str(cm.exception))

    def test_no_markers_raises(self):
        with self.assertRaises(ValueError) as cm:
            pem.parse_public_pem("just some text, no PEM here")
        self.assertIn("not a valid PEM", str(cm.exception))

    def test_bad_base64_raises(self):
        bad = "-----BEGIN RSA PUBLIC KEY-----\n!!!!not base64!!!!\n-----END RSA PUBLIC KEY-----\n"
        with self.assertRaises(ValueError) as cm:
            pem.parse_public_pem(bad)
        self.assertIn("base64", str(cm.exception))


class TestLoadPublicDispatch(unittest.TestCase):
    def _write(self, name, text):
        d = tempfile.mkdtemp()
        p = Path(d) / name
        p.write_text(text, encoding="utf-8")
        return p

    def test_load_public_reads_pem(self):
        p = self._write("pub.pem", PKCS1_PEM)
        self.assertEqual(keyfile.load_public(p), {"n": FIXTURE_N, "e": FIXTURE_E})

    def test_load_public_reads_spki_pem(self):
        p = self._write("pub.pem", SPKI_PEM)
        self.assertEqual(keyfile.load_public(p), {"n": FIXTURE_N, "e": FIXTURE_E})

    def test_load_public_still_reads_json(self):
        p = self._write("pub.json", json.dumps({"n": 97134618697, "e": 65537}))
        self.assertEqual(keyfile.load_public(p), {"n": 97134618697, "e": 65537})

    def test_load_public_pem_error_is_prefixed(self):
        p = self._write("bad.pem", TRUNCATED_PEM)
        with self.assertRaises(ValueError) as cm:
            keyfile.load_public(p)
        self.assertIn(str(p), str(cm.exception))


if __name__ == "__main__":
    unittest.main()
