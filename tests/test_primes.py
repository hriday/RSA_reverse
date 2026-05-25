import unittest

from rsa_poc.primes import is_prime


def _trial_division(n):
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


class TestIsPrime(unittest.TestCase):
    def test_agrees_with_trial_division_small(self):
        for n in range(0, 10_001):
            with self.subTest(n=n):
                self.assertEqual(is_prime(n), _trial_division(n))

    def test_known_primes_near_six_digit_boundary(self):
        for p in [100003, 100019, 999983, 999979]:
            with self.subTest(p=p):
                self.assertTrue(is_prime(p))

    def test_carmichael_numbers_are_composite(self):
        for n in [561, 1105, 1729, 2465, 2821, 6601]:
            with self.subTest(n=n):
                self.assertFalse(is_prime(n))

    def test_negatives_and_small_edge_cases(self):
        self.assertFalse(is_prime(-7))
        self.assertFalse(is_prime(0))
        self.assertFalse(is_prime(1))
        self.assertTrue(is_prime(2))
        self.assertTrue(is_prime(3))


from rsa_poc.primes import random_prime


class TestRandomPrime(unittest.TestCase):
    def test_returns_prime_with_exact_digit_count(self):
        for digits in (3, 4, 5, 6):
            for _ in range(5):
                p = random_prime(digits)
                with self.subTest(digits=digits, p=p):
                    self.assertEqual(len(str(p)), digits)
                    self.assertTrue(is_prime(p))

    def test_rejects_digits_below_two(self):
        with self.assertRaises(ValueError):
            random_prime(1)
        with self.assertRaises(ValueError):
            random_prime(0)
        with self.assertRaises(ValueError):
            random_prime(-3)


if __name__ == "__main__":
    unittest.main()
