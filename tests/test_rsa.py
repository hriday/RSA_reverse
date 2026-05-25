import random
import unittest

from rsa_poc.primes import is_prime
from rsa_poc.rsa import decrypt, derive_private_key, encrypt, keygen


class TestKeygen(unittest.TestCase):
    def test_keygen_produces_consistent_keys(self):
        pub, priv = keygen(digits=6)
        self.assertEqual(pub["n"], priv["n"])
        self.assertEqual(pub["e"], priv["e"])
        self.assertTrue(is_prime(priv["p"]))
        self.assertTrue(is_prime(priv["q"]))
        self.assertNotEqual(priv["p"], priv["q"])
        self.assertEqual(priv["p"] * priv["q"], priv["n"])
        # d * e ≡ 1 (mod φ(n))
        phi = (priv["p"] - 1) * (priv["q"] - 1)
        self.assertEqual((priv["d"] * priv["e"]) % phi, 1)

    def test_keygen_respects_digit_count(self):
        _, priv = keygen(digits=4)
        self.assertEqual(len(str(priv["p"])), 4)
        self.assertEqual(len(str(priv["q"])), 4)


class TestIntegerRoundTrip(unittest.TestCase):
    def test_decrypt_of_encrypt_recovers_int(self):
        pub, priv = keygen(digits=6)
        rng = random.Random(20260525)
        for _ in range(10):
            m = rng.randrange(0, pub["n"])
            c = encrypt(pub, m)
            self.assertEqual(decrypt(priv, c), m)

    def test_encrypt_rejects_message_not_less_than_n(self):
        pub, _ = keygen(digits=6)
        with self.assertRaises(ValueError):
            encrypt(pub, pub["n"])
        with self.assertRaises(ValueError):
            encrypt(pub, pub["n"] + 1)


class TestDerivePrivateKey(unittest.TestCase):
    def test_derive_matches_keygen(self):
        _, priv = keygen(digits=6)
        rebuilt = derive_private_key(priv["p"], priv["q"], priv["e"])
        self.assertEqual(rebuilt["n"], priv["n"])
        self.assertEqual(rebuilt["e"], priv["e"])
        self.assertEqual(rebuilt["d"], priv["d"])


if __name__ == "__main__":
    unittest.main()
