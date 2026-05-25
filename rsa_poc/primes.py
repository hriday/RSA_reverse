"""Primality testing and random prime sampling."""

from __future__ import annotations

import secrets

# Deterministic Miller-Rabin witnesses sufficient for n < 3,317,044,064,679,887,385,961,981.
# Reference: https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Testing_against_small_sets_of_bases
_DETERMINISTIC_WITNESSES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in _DETERMINISTIC_WITNESSES:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for a in _DETERMINISTIC_WITNESSES:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(digits: int) -> int:
    if digits < 2:
        raise ValueError(f"digits must be >= 2, got {digits}")
    lo = 10 ** (digits - 1)
    hi = 10 ** digits  # exclusive
    span = hi - lo
    while True:
        candidate = lo + secrets.randbelow(span)
        if candidate % 2 == 0:
            candidate += 1
            if candidate >= hi:
                continue
        if is_prime(candidate):
            return candidate
