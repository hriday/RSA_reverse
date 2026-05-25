"""RSA keygen, encrypt/decrypt, and text/block encoding for the PoC."""

from __future__ import annotations

from math import gcd

from rsa_poc.primes import random_prime

DEFAULT_E = 65537
_KEYGEN_MAX_RETRIES = 20


def derive_private_key(p: int, q: int, e: int = DEFAULT_E) -> dict:
    if p == q:
        raise ValueError("p and q must be distinct primes")
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError(f"e={e} is not coprime to phi(n)")
    d = pow(e, -1, phi)
    return {"n": n, "e": e, "d": d, "p": p, "q": q}


def keygen(digits: int, e: int = DEFAULT_E) -> tuple[dict, dict]:
    for _ in range(_KEYGEN_MAX_RETRIES):
        p = random_prime(digits)
        q = random_prime(digits)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) != 1:
            continue
        priv = derive_private_key(p, q, e)
        pub = {"n": priv["n"], "e": priv["e"]}
        return pub, priv
    raise ValueError(
        f"could not find primes with gcd(e={e}, phi(n))==1 after "
        f"{_KEYGEN_MAX_RETRIES} attempts; choose a different e"
    )


def encrypt(pub: dict, m: int) -> int:
    if m < 0 or m >= pub["n"]:
        raise ValueError(f"message {m} out of range [0, n={pub['n']})")
    return pow(m, pub["e"], pub["n"])


def decrypt(priv: dict, c: int) -> int:
    return pow(c, priv["d"], priv["n"])
