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


def _block_size(n: int) -> int:
    size = (n.bit_length() - 1) // 8
    if size < 1:
        raise ValueError(f"n={n} is too small to encode even one byte per block")
    return size


def text_to_blocks(text: str, n: int) -> list[int]:
    data = text.encode("utf-8")
    if not data:
        return []
    size = _block_size(n)
    blocks = []
    for i in range(0, len(data), size):
        chunk = data[i : i + size]
        blocks.append(int.from_bytes(chunk, "big"))
    return blocks


def blocks_to_text(blocks: list[int], n: int, total_len: int) -> str:
    if total_len == 0:
        return ""
    size = _block_size(n)
    if not blocks:
        raise ValueError("blocks empty but total_len > 0")
    out = bytearray()
    for i, m in enumerate(blocks):
        is_last = i == len(blocks) - 1
        if is_last:
            remaining = total_len - size * (len(blocks) - 1)
            if remaining < 1 or remaining > size:
                raise ValueError(
                    f"total_len={total_len} inconsistent with {len(blocks)} blocks of size {size}"
                )
            out.extend(m.to_bytes(remaining, "big"))
        else:
            out.extend(m.to_bytes(size, "big"))
    return out.decode("utf-8")
