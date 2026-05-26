"""Pollard's rho factoring of semiprimes.

Two cycle-detection variants are supported via the `algorithm` parameter of
`pollard_rho`:

- "floyd"  -- classic tortoise-and-hare: tortoise steps once per iteration,
              hare steps twice, one gcd per iteration. Simple to understand.
- "brent"  -- (default) hare advances in power-of-2 epochs, gcds are batched
              over 128 step-pairs. ~2-3x faster at the n sizes in this PoC
              because gcd dominates per-iteration cost.

Both variants share the same outer scaffolding (precheck for primes, restart
on degenerate `gcd == n`, post-check that both factors are prime and distinct).
"""

from __future__ import annotations

import random
from math import gcd

from rsa_poc.primes import is_prime

ALGORITHMS = ("brent", "floyd")
DEFAULT_ALGORITHM = "brent"

# Batch size for accumulating |x - y| products before each gcd call. gcd dominates
# per-iteration cost for the n sizes in this PoC, so batching is the speedup.
_BRENT_BATCH = 128


def _floyd_attempt(n: int, rng: random.Random) -> int | None:
    # Classic Pollard's rho with Floyd's cycle detection:
    # tortoise x steps once, hare y steps twice, one gcd per step.
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


def pollard_rho(
    n: int,
    rng: random.Random | None = None,
    algorithm: str = DEFAULT_ALGORITHM,
) -> tuple[int, int]:
    if algorithm not in ALGORITHMS:
        raise ValueError(
            f"unknown algorithm {algorithm!r}; choose one of {ALGORITHMS}"
        )
    if n < 4:
        raise ValueError(f"n={n} too small to factor as a semiprime")
    if is_prime(n):
        raise ValueError(f"n={n} is prime; nothing to factor")
    if rng is None:
        rng = random.Random()
    attempt = _brent_attempt if algorithm == "brent" else _floyd_attempt
    factor = None
    for _ in range(64):
        factor = attempt(n, rng)
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
