# RSA Small-Prime PoC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI that generates a small-prime RSA keypair, encrypts a message, and then recovers the plaintext from only the public key + ciphertext by factoring `n` with Pollard's rho — proving why small primes are unsafe.

**Architecture:** A `rsa_poc/` package with focused stdlib-only modules (`primes`, `rsa`, `factor`, `keyfile`, `cli`) plus `tests/` using `unittest`. Each module has one responsibility and is testable in isolation. The CLI is a thin argparse layer over the library.

**Tech Stack:** Python 3.8+ standard library only — `argparse`, `json`, `math`, `secrets`, `random`, `time`, `sys`, `pathlib`, `unittest`. No third-party dependencies.

---

## File structure

```
RSA_reverse/
├── rsa_poc/
│   ├── __init__.py
│   ├── __main__.py
│   ├── primes.py
│   ├── rsa.py
│   ├── factor.py
│   ├── keyfile.py
│   └── cli.py
├── tests/
│   ├── __init__.py
│   ├── test_primes.py
│   ├── test_rsa.py
│   └── test_factor.py
└── docs/
    └── superpowers/
        ├── specs/
        │   └── 2026-05-25-rsa-small-prime-poc-design.md
        └── plans/
            └── 2026-05-25-rsa-small-prime-poc.md   ← this file
```

Per-file responsibility:

| File | Responsibility |
|---|---|
| `rsa_poc/primes.py` | Primality testing (Miller–Rabin), random prime sampling by digit count |
| `rsa_poc/rsa.py` | Keygen, encrypt/decrypt, derive private key from p+q, text↔block encoding |
| `rsa_poc/factor.py` | Pollard's rho factoring of semiprimes |
| `rsa_poc/keyfile.py` | JSON load/save for public/private keys + ciphertext file format |
| `rsa_poc/cli.py` | argparse dispatcher for `generate` / `encrypt` / `factor` / `break` |
| `rsa_poc/__main__.py` | Entry point: `python -m rsa_poc` |
| `tests/test_*.py` | `unittest` test modules — one per library module |

Dependency direction: `cli → {rsa, factor, primes, keyfile}`, `rsa → primes`, `factor` and `keyfile` stand alone.

---

## Task 0: Repo skeleton

**Files:**
- Create: `rsa_poc/__init__.py`
- Create: `tests/__init__.py`
- Create: `.gitignore`

- [ ] **Step 1: Initialize git repo**

Run from `/Users/hriday/code/RSA_reverse/`:
```bash
git init
git add docs/
git commit -m "docs: add design spec and implementation plan"
```

- [ ] **Step 2: Create package skeleton**

Create `rsa_poc/__init__.py` with this content:

```python
"""RSA small-prime proof-of-concept.

Demonstrates why RSA must not use small primes by factoring the public modulus
and recovering plaintext from ciphertext.
"""
```

Create `tests/__init__.py` as an empty file (zero bytes).

- [ ] **Step 3: Create .gitignore**

Create `.gitignore` with:

```
__pycache__/
*.py[cod]
*.egg-info/
.pytest_cache/
.venv/
venv/
keys/
*.swp
.DS_Store
```

- [ ] **Step 4: Commit**

```bash
git add rsa_poc/__init__.py tests/__init__.py .gitignore
git commit -m "chore: scaffold rsa_poc package and tests"
```

---

## Task 1: `primes.is_prime` (Miller–Rabin)

**Files:**
- Create: `rsa_poc/primes.py`
- Test: `tests/test_primes.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_primes.py`:

```python
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


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run from repo root:
```bash
python -m unittest tests.test_primes -v
```

Expected: `ModuleNotFoundError: No module named 'rsa_poc.primes'`.

- [ ] **Step 3: Implement `is_prime`**

Create `rsa_poc/primes.py`:

```python
"""Primality testing and random prime sampling."""

from __future__ import annotations

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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m unittest tests.test_primes -v
```

Expected: all 4 test methods PASS.

- [ ] **Step 5: Commit**

```bash
git add rsa_poc/primes.py tests/test_primes.py
git commit -m "feat(primes): add deterministic Miller-Rabin is_prime"
```

---

## Task 2: `primes.random_prime`

**Files:**
- Modify: `rsa_poc/primes.py` (append `random_prime`)
- Modify: `tests/test_primes.py` (append `TestRandomPrime` class)

- [ ] **Step 1: Write failing tests**

Append to `tests/test_primes.py` (above `if __name__ == "__main__":`):

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m unittest tests.test_primes -v
```

Expected: `TestRandomPrime` tests fail with `ImportError: cannot import name 'random_prime'`.

- [ ] **Step 3: Implement `random_prime`**

Append to `rsa_poc/primes.py`:

```python
import secrets


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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m unittest tests.test_primes -v
```

Expected: all tests in `tests/test_primes.py` PASS.

- [ ] **Step 5: Commit**

```bash
git add rsa_poc/primes.py tests/test_primes.py
git commit -m "feat(primes): add random_prime(digits) sampler"
```

---

## Task 3: `rsa.keygen` and integer encrypt/decrypt

**Files:**
- Create: `rsa_poc/rsa.py`
- Create: `tests/test_rsa.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_rsa.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m unittest tests.test_rsa -v
```

Expected: `ModuleNotFoundError: No module named 'rsa_poc.rsa'`.

- [ ] **Step 3: Implement keygen + integer crypto + derive_private_key**

Create `rsa_poc/rsa.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m unittest tests.test_rsa -v
```

Expected: all 5 test methods PASS.

- [ ] **Step 5: Commit**

```bash
git add rsa_poc/rsa.py tests/test_rsa.py
git commit -m "feat(rsa): add keygen, derive_private_key, encrypt, decrypt"
```

---

## Task 4: `rsa.text_to_blocks` / `blocks_to_text` (text encoding)

**Files:**
- Modify: `rsa_poc/rsa.py` (append encoding helpers)
- Modify: `tests/test_rsa.py` (append `TestTextRoundTrip` class)

- [ ] **Step 1: Write failing tests**

Append to `tests/test_rsa.py` (above `if __name__ == "__main__":`):

```python
from rsa_poc.rsa import blocks_to_text, text_to_blocks


class TestTextRoundTrip(unittest.TestCase):
    def _round_trip(self, text):
        pub, priv = keygen(digits=6)
        blocks = text_to_blocks(text, pub["n"])
        encrypted = [encrypt(pub, m) for m in blocks]
        decrypted = [decrypt(priv, c) for c in encrypted]
        total_len = len(text.encode("utf-8"))
        recovered = blocks_to_text(decrypted, pub["n"], total_len)
        self.assertEqual(recovered, text)

    def test_ascii_message(self):
        self._round_trip("attack at dawn")

    def test_utf8_message(self):
        self._round_trip("café — déjà vu — naïve")

    def test_empty_message(self):
        self._round_trip("")

    def test_single_byte_message(self):
        self._round_trip("a")

    def test_message_with_leading_null_byte_in_block(self):
        # Forces a block whose top byte is 0x00 — exercises the length-trim path.
        self._round_trip("\x00hello\x00world")

    def test_text_to_blocks_each_block_less_than_n(self):
        pub, _ = keygen(digits=6)
        blocks = text_to_blocks("the quick brown fox jumps over the lazy dog", pub["n"])
        for m in blocks:
            self.assertLess(m, pub["n"])
            self.assertGreaterEqual(m, 0)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m unittest tests.test_rsa -v
```

Expected: new tests fail with `ImportError: cannot import name 'text_to_blocks'`.

- [ ] **Step 3: Implement text encoding**

Append to `rsa_poc/rsa.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m unittest tests.test_rsa -v
```

Expected: all tests in `tests/test_rsa.py` PASS.

- [ ] **Step 5: Commit**

```bash
git add rsa_poc/rsa.py tests/test_rsa.py
git commit -m "feat(rsa): add text_to_blocks and blocks_to_text"
```

---

## Task 5: `factor.pollard_rho`

**Files:**
- Create: `rsa_poc/factor.py`
- Create: `tests/test_factor.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_factor.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m unittest tests.test_factor -v
```

Expected: `ModuleNotFoundError: No module named 'rsa_poc.factor'`.

- [ ] **Step 3: Implement Pollard's rho**

Create `rsa_poc/factor.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m unittest tests.test_factor -v
```

Expected: all 8 test methods PASS. May take a few seconds on the property test.

- [ ] **Step 5: Commit**

```bash
git add rsa_poc/factor.py tests/test_factor.py
git commit -m "feat(factor): add pollard_rho for semiprimes"
```

---

## Task 6: `keyfile` JSON I/O

**Files:**
- Create: `rsa_poc/keyfile.py`

Note: `keyfile` is thin I/O glue. Its correctness is exercised by the integration test in Task 8 and (indirectly) by manual CLI smoke. No dedicated unit-test module per the spec's testing strategy.

- [ ] **Step 1: Implement `keyfile.py`**

Create `rsa_poc/keyfile.py`:

```python
"""JSON I/O for public keys, private keys, and ciphertext files."""

from __future__ import annotations

import json
from pathlib import Path

_PUB_FIELDS = ("n", "e")
_PRIV_FIELDS = ("n", "e", "d", "p", "q")


def save_public(path: str | Path, pub: dict) -> None:
    _write_json(path, {k: pub[k] for k in _PUB_FIELDS})


def save_private(path: str | Path, priv: dict) -> None:
    _write_json(path, {k: priv[k] for k in _PRIV_FIELDS})


def load_public(path: str | Path) -> dict:
    return _read_required(path, _PUB_FIELDS)


def load_private(path: str | Path) -> dict:
    return _read_required(path, _PRIV_FIELDS)


def save_ciphertext(path: str | Path, blocks: list[int], total_len: int) -> None:
    p = Path(path)
    lines = [str(total_len)] + [str(b) for b in blocks]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_ciphertext(path: str | Path) -> tuple[list[int], int]:
    p = Path(path)
    raw = p.read_text(encoding="utf-8").splitlines()
    if not raw:
        raise ValueError(f"{p}: ciphertext file is empty")
    try:
        total_len = int(raw[0])
    except ValueError as exc:
        raise ValueError(f"{p}: first line must be plaintext byte length") from exc
    blocks = []
    for i, line in enumerate(raw[1:], start=2):
        line = line.strip()
        if not line:
            continue
        try:
            blocks.append(int(line))
        except ValueError as exc:
            raise ValueError(f"{p}:{i}: not an integer: {line!r}") from exc
    return blocks, total_len


def _write_json(path: str | Path, data: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _read_required(path: str | Path, fields: tuple[str, ...]) -> dict:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{p}: invalid JSON: {exc.msg}") from exc
    missing = [f for f in fields if f not in data]
    if missing:
        raise ValueError(f"{p}: missing required field(s): {', '.join(missing)}")
    return {f: int(data[f]) for f in fields}
```

- [ ] **Step 2: Smoke-test the I/O round-trip from a Python REPL**

Run from repo root:
```bash
python -c "
from rsa_poc import keyfile
keyfile.save_public('/tmp/pub.json', {'n': 123, 'e': 65537})
print(keyfile.load_public('/tmp/pub.json'))
keyfile.save_ciphertext('/tmp/c.txt', [1, 2, 3], 14)
print(keyfile.load_ciphertext('/tmp/c.txt'))
"
```

Expected output:
```
{'n': 123, 'e': 65537}
([1, 2, 3], 14)
```

- [ ] **Step 3: Commit**

```bash
git add rsa_poc/keyfile.py
git commit -m "feat(keyfile): add JSON I/O for keys and ciphertext"
```

---

## Task 7: `cli` — argparse + subcommand handlers

**Files:**
- Create: `rsa_poc/cli.py`
- Create: `rsa_poc/__main__.py`

- [ ] **Step 1: Create the CLI module**

Create `rsa_poc/cli.py`:

```python
"""Command-line interface: generate / encrypt / factor / break."""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

from rsa_poc import factor as factor_mod
from rsa_poc import keyfile, rsa


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rsa_poc")
    sub = parser.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="generate a small-prime RSA keypair")
    g.add_argument("--out-dir", required=True, type=Path)
    g.add_argument("--digits", type=int, default=6)
    g.add_argument("--e", dest="e", type=int, default=rsa.DEFAULT_E)
    g.set_defaults(func=_cmd_generate)

    e = sub.add_parser("encrypt", help="encrypt a message with a public key")
    e.add_argument("--key", required=True, type=Path)
    e.add_argument("--out", required=True, type=Path)
    msg = e.add_mutually_exclusive_group(required=True)
    msg.add_argument("--message", type=str)
    msg.add_argument("--message-file", type=Path)
    e.set_defaults(func=_cmd_encrypt)

    f = sub.add_parser("factor", help="factor n from a public key (prints p, q)")
    f.add_argument("--key", required=True, type=Path)
    f.add_argument("--verbose", action="store_true")
    f.add_argument("--seed", type=int)
    f.set_defaults(func=_cmd_factor)

    b = sub.add_parser("break", help="factor n and decrypt ciphertext")
    b.add_argument("--key", required=True, type=Path)
    b.add_argument("--ciphertext-file", required=True, type=Path)
    b.add_argument("--out", type=Path)
    b.add_argument("--verbose", action="store_true")
    b.add_argument("--seed", type=int)
    b.set_defaults(func=_cmd_break)

    return parser


def _cmd_generate(args) -> int:
    if args.digits < 2:
        raise ValueError(f"--digits must be >= 2, got {args.digits}")
    if args.digits > 6:
        sys.stderr.write(
            f"warning: --digits={args.digits} is beyond the PoC's tuned range; "
            "factoring may be slow.\n"
        )
    pub, priv = rsa.keygen(digits=args.digits, e=args.e)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    keyfile.save_public(args.out_dir / "pub.json", pub)
    keyfile.save_private(args.out_dir / "priv.json", priv)
    print(f"wrote {args.out_dir / 'pub.json'}")
    print(f"wrote {args.out_dir / 'priv.json'}")
    print(f"n = {pub['n']}  e = {pub['e']}  ({args.digits}-digit primes)")
    return 0


def _cmd_encrypt(args) -> int:
    pub = keyfile.load_public(args.key)
    if args.message is not None:
        text = args.message
    else:
        text = args.message_file.read_text(encoding="utf-8")
    blocks_plain = rsa.text_to_blocks(text, pub["n"])
    blocks_cipher = [rsa.encrypt(pub, m) for m in blocks_plain]
    total_len = len(text.encode("utf-8"))
    keyfile.save_ciphertext(args.out, blocks_cipher, total_len)
    print(f"wrote {args.out}  ({len(blocks_cipher)} block(s), {total_len} byte plaintext)")
    return 0


def _cmd_factor(args) -> int:
    pub = keyfile.load_public(args.key)
    rng = random.Random(args.seed) if args.seed is not None else None
    t0 = time.perf_counter()
    p, q = factor_mod.pollard_rho(pub["n"], rng=rng)
    elapsed = time.perf_counter() - t0
    print(f"n = {pub['n']}")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"factored in {elapsed:.4f}s")
    if args.verbose:
        sys.stderr.write(f"# n bit length: {pub['n'].bit_length()}\n")
    return 0


def _cmd_break(args) -> int:
    pub = keyfile.load_public(args.key)
    blocks, total_len = keyfile.load_ciphertext(args.ciphertext_file)
    rng = random.Random(args.seed) if args.seed is not None else None

    t0 = time.perf_counter()
    p, q = factor_mod.pollard_rho(pub["n"], rng=rng)
    t_factor = time.perf_counter() - t0

    t0 = time.perf_counter()
    priv = rsa.derive_private_key(p, q, pub["e"])
    t_derive = time.perf_counter() - t0

    t0 = time.perf_counter()
    plain_blocks = [rsa.decrypt(priv, c) for c in blocks]
    plaintext = rsa.blocks_to_text(plain_blocks, pub["n"], total_len)
    t_decrypt = time.perf_counter() - t0

    if args.out is not None:
        args.out.write_text(plaintext, encoding="utf-8")
        sys.stderr.write(f"wrote {args.out}\n")
    else:
        sys.stdout.write(plaintext)
        if not plaintext.endswith("\n"):
            sys.stdout.write("\n")

    sys.stderr.write(
        f"# timing: factor={t_factor:.4f}s  derive_d={t_derive:.6f}s  "
        f"decrypt={t_decrypt:.6f}s\n"
    )
    if args.verbose:
        sys.stderr.write(f"# recovered p={p}  q={q}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Create the module entry point**

Create `rsa_poc/__main__.py`:

```python
from rsa_poc.cli import main

raise SystemExit(main())
```

- [ ] **Step 3: Smoke-test the full pipeline manually**

Run from repo root:
```bash
rm -rf /tmp/rsa_poc_smoke && mkdir -p /tmp/rsa_poc_smoke
python -m rsa_poc generate --digits 6 --out-dir /tmp/rsa_poc_smoke/
python -m rsa_poc encrypt --key /tmp/rsa_poc_smoke/pub.json --message "attack at dawn" --out /tmp/rsa_poc_smoke/ciphertext.txt
python -m rsa_poc factor --key /tmp/rsa_poc_smoke/pub.json
python -m rsa_poc break --key /tmp/rsa_poc_smoke/pub.json --ciphertext-file /tmp/rsa_poc_smoke/ciphertext.txt
```

Expected: the final `break` command prints `attack at dawn`. Each step's `n` matches across `generate`, `factor`, `break`. `factor` and `break` complete in well under a second.

- [ ] **Step 4: Commit**

```bash
git add rsa_poc/cli.py rsa_poc/__main__.py
git commit -m "feat(cli): add generate/encrypt/factor/break subcommands"
```

---

## Task 8: Final verification — full test suite + end-to-end demo

**Files:** none (verification only)

- [ ] **Step 1: Run the full test suite**

```bash
python -m unittest discover tests -v
```

Expected: all tests in `test_primes`, `test_rsa`, `test_factor` PASS. No errors, no skips.

- [ ] **Step 2: Run an end-to-end demo with a non-ASCII message**

```bash
rm -rf /tmp/rsa_poc_demo && mkdir -p /tmp/rsa_poc_demo
python -m rsa_poc generate --digits 6 --out-dir /tmp/rsa_poc_demo/
python -m rsa_poc encrypt --key /tmp/rsa_poc_demo/pub.json --message "café — déjà vu" --out /tmp/rsa_poc_demo/ciphertext.txt
python -m rsa_poc break --key /tmp/rsa_poc_demo/pub.json --ciphertext-file /tmp/rsa_poc_demo/ciphertext.txt
```

Expected: `break` prints exactly `café — déjà vu`.

- [ ] **Step 3: Run the digit-range sweep manually**

For digits in 3, 4, 5, 6 — confirm the demo completes:
```bash
for d in 3 4 5 6; do
  rm -rf /tmp/rsa_poc_d${d} && mkdir -p /tmp/rsa_poc_d${d}
  python -m rsa_poc generate --digits ${d} --out-dir /tmp/rsa_poc_d${d}/
  python -m rsa_poc encrypt --key /tmp/rsa_poc_d${d}/pub.json --message "hi" --out /tmp/rsa_poc_d${d}/ct.txt
  python -m rsa_poc break --key /tmp/rsa_poc_d${d}/pub.json --ciphertext-file /tmp/rsa_poc_d${d}/ct.txt
done
```

Expected: each iteration prints `hi`.

- [ ] **Step 4: Confirm warning fires for `--digits > 6`**

```bash
python -m rsa_poc generate --digits 7 --out-dir /tmp/rsa_poc_big/ 2>&1 | head -5
```

Expected: stderr contains the warning `--digits=7 is beyond the PoC's tuned range`. The command should still succeed (may take several seconds).

- [ ] **Step 5: Commit any trailing changes (if needed) and tag**

If everything passes cleanly and nothing has changed since Task 7, skip the commit step. Otherwise:
```bash
git status
git add -A
git commit -m "chore: final cleanups after end-to-end verification"
```

The PoC is complete when the test suite is green and the end-to-end demo in Step 2 reproduces the message.
