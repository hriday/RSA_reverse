"""Pollard's rho factoring of semiprimes."""

from __future__ import annotations

import random
from math import gcd

from rsa_poc.primes import is_prime


def _rho_attempt(n: int, rng: random.Random) -> int | None:
    x = rng.randrange(2, n - 1)
    y = x
    c = rng.randrange(1, n - 1)
    d = 1
    while d == 1:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = gcd(abs(x - y), n)
    if d == n:
        return None
    return d


def pollard_rho(n: int, rng: random.Random | None = None) -> tuple[int, int]:
    if n < 4:
        raise ValueError(f"n={n} too small to factor as a semiprime")
    if is_prime(n):
        raise ValueError(f"n={n} is prime; nothing to factor")
    if rng is None:
        rng = random.Random()
    factor = None
    for _ in range(64):
        factor = _rho_attempt(n, rng)
        if factor is not None:
            break
    if factor is None:
        raise ValueError(f"pollard_rho failed to find a factor of n={n}")
    other = n // factor
    if not is_prime(factor) or not is_prime(other):
        raise ValueError(
            f"n={n} is not a product of two primes (got {factor} * {other})"
        )
    if factor == other:
        raise ValueError(f"n={n} is a prime square ({factor}^2)")
    p, q = sorted((factor, other))
    return p, q
