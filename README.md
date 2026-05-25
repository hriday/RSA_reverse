# RSA Small-Prime PoC

A teaching proof-of-concept that demonstrates why RSA must not use small primes. Generates an RSA keypair from 3–6 digit primes, encrypts a message, then recovers the plaintext from only the public key and ciphertext by factoring `n` with Pollard's rho.

> **Not for production use.** This implements textbook RSA with no padding (no OAEP, no PKCS), small primes, and no side-channel resistance. The whole point is that an attacker can break it on a laptop in milliseconds.

## Requirements

- Python 3.8+
- Standard library only — no `pip install` step.

## Quick start

### Defender side

```bash
# 1. Generate a keypair with 6-digit primes
python -m rsa_poc generate --digits 6 --out-dir keys/

# 2. Encrypt a message with the public key
python -m rsa_poc encrypt --key keys/pub.json --message "attack at dawn" --out ciphertext.txt
```

### Attacker side (only sees `pub.json` + `ciphertext.txt`)

```bash
# Just factor n
python -m rsa_poc factor --key keys/pub.json
# n = 97134618697
# p = 174121
# q = 557857
# factored in 0.0001s

# Full break — recover the plaintext
python -m rsa_poc break --key keys/pub.json --ciphertext-file ciphertext.txt
# attack at dawn
# # timing: factor=0.0004s  derive_d=0.000003s  decrypt=0.000024s
```

## CLI

| Subcommand | Required | Optional |
|---|---|---|
| `generate` | `--out-dir` | `--digits N` (default 6, range 3–6; >6 warns), `--e E` (default 65537) |
| `encrypt` | `--key`, `--out`, one of `--message`/`--message-file` | |
| `factor` | `--key` | `--verbose`, `--seed S` |
| `break` | `--key`, `--ciphertext-file` | `--out`, `--verbose`, `--seed S` |

## How it works

1. **Keygen.** Two random `d`-digit primes `p`, `q` via Miller–Rabin. `n = p*q`, `φ = (p-1)(q-1)`, `d = e⁻¹ mod φ` (with `e = 65537`).
2. **Encrypt.** Plaintext UTF-8 bytes are split into blocks of `(n.bit_length() - 1) // 8` bytes so each block integer `m < n`. Ciphertext blocks are `c = mᵉ mod n`.
3. **Factor.** Pollard's rho with `f(x) = x² + c mod n` and Floyd's cycle detection. Restart with a fresh `c` if `gcd(|x-y|, n) == n`. For 6-digit primes, finishes in well under a second.
4. **Break.** Factor `n` → recover `p, q` → compute `d` → decrypt each ciphertext block → reassemble bytes → decode UTF-8.

## Project structure

```
rsa_poc/
├── primes.py     # Miller-Rabin is_prime, random_prime(digits)
├── rsa.py        # keygen, encrypt, decrypt, derive_private_key, text<->blocks
├── factor.py     # pollard_rho (semiprimes only)
├── keyfile.py    # JSON I/O for pub.json, priv.json, ciphertext.txt
├── cli.py        # argparse: generate / encrypt / factor / break
└── __main__.py   # python -m rsa_poc

tests/            # unittest — test_primes, test_rsa, test_factor (26 tests)

docs/superpowers/
├── specs/        # design spec
└── plans/        # implementation plan
```

## File formats

`pub.json`
```json
{"n": 97134618697, "e": 65537}
```

`priv.json`
```json
{"n": 97134618697, "e": 65537, "d": 12345678901, "p": 174121, "q": 557857}
```

`ciphertext.txt` — first line is the plaintext byte length, subsequent lines are ciphertext blocks:
```
14
4823910
192847
80213
6512
```

## Running the tests

```bash
python -m unittest discover tests -v
```

26 tests across `primes`, `rsa`, and `factor`. End-to-end CLI coverage is by manual smoke test (see [the implementation plan](docs/superpowers/plans/2026-05-25-rsa-small-prime-poc.md) Task 8).

## Design and implementation docs

- [Design spec](docs/superpowers/specs/2026-05-25-rsa-small-prime-poc-design.md)
- [Implementation plan](docs/superpowers/plans/2026-05-25-rsa-small-prime-poc.md)
