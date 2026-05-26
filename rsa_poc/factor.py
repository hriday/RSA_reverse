"""Pollard's rho factoring of semiprimes."""

from __future__ import annotations

import random
from math import gcd

from rsa_poc.primes import is_prime


# Batch size for accumulating |x - y| products before each gcd call. gcd dominates
# per-iteration cost for the n sizes in this PoC, so batching is the speedup.
_BRENT_BATCH = 128


def _brent_attempt(n: int, rng: random.Random) -> int | None:
    # Brent's variant of Pollard's rho:
    #   - hare y advances in power-of-2 epochs (1, 2, 4, ..., 2^k steps)
    #   - tortoise x is snapshotted at the start of each epoch
    #   - per epoch, accumulate |x - y| products mod n for `_BRENT_BATCH` steps,
    #     then one gcd call extracts a factor if any pair shared a divisor with n
    #   - on the rare "overshoot" where the batched gcd equals n, replay the
    #     epoch one step at a time to find which step actually hit the factor
    y = rng.randrange(2, n - 1)
    c = rng.randrange(1, n - 1)
    r = 1
    g = 1
    x = y
    ys = y
    while g == 1:
        x = y
        for _ in range(r):
            y = (y * y + c) % n
        k = 0
        while k < r and g == 1:
            ys = y
            limit = min(_BRENT_BATCH, r - k)
            q = 1
            for _ in range(limit):
                y = (y * y + c) % n
                q = (q * abs(x - y)) % n
            g = gcd(q, n)
            k += limit
        r *= 2
    if g == n:
        while True:
            ys = (ys * ys + c) % n
            g = gcd(abs(x - ys), n)
            if g > 1:
                break
        if g == n:
            return None
    return g


def pollard_rho(n: int, rng: random.Random | None = None) -> tuple[int, int]:
    if n < 4:
        raise ValueError(f"n={n} too small to factor as a semiprime")
    if is_prime(n):
        raise ValueError(f"n={n} is prime; nothing to factor")
    if rng is None:
        rng = random.Random()
    factor = None
    for _ in range(64):
        factor = _brent_attempt(n, rng)
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
