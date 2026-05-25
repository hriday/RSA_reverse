import unittest

from rsa_poc.factor import pollard_rho
from rsa_poc.rsa import keygen


class TestPollardRhoHandPicked(unittest.TestCase):
    def _assert_factors(self, p, q):
        a, b = pollard_rho(p * q)
        self.assertEqual({a, b}, {p, q})
        self.assertLessEqual(a, b)

    def test_close_primes(self):
        self._assert_factors(100003, 100019)

    def test_far_apart_primes(self):
        self._assert_factors(100003, 999983)

    def test_small_primes(self):
        self._assert_factors(101, 103)

    def test_three_digit_primes(self):
        self._assert_factors(541, 977)


class TestPollardRhoProperty(unittest.TestCase):
    def test_recovers_keypair_factors(self):
        for _ in range(10):
            _, priv = keygen(digits=6)
            a, b = pollard_rho(priv["n"])
            self.assertEqual({a, b}, {priv["p"], priv["q"]})


class TestPollardRhoRejections(unittest.TestCase):
    def test_rejects_n_too_small(self):
        for n in (-5, 0, 1, 2, 3):
            with self.subTest(n=n), self.assertRaises(ValueError):
                pollard_rho(n)

    def test_rejects_prime(self):
        with self.assertRaises(ValueError):
            pollard_rho(100003)

    def test_rejects_prime_square(self):
        with self.assertRaises(ValueError):
            pollard_rho(101 * 101)

    def test_rejects_product_of_three_primes(self):
        with self.assertRaises(ValueError):
            pollard_rho(101 * 103 * 107)


if __name__ == "__main__":
    unittest.main()
