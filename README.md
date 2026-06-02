# RSA Small-Prime PoC

A teaching proof-of-concept that demonstrates why RSA must not use small primes. Generates an RSA keypair from small primes (3 to 32 digits, tuned for fast demos up to 14), encrypts a message, then recovers the plaintext from only the public key and ciphertext by factoring `n` with Pollard's rho. Both classic Floyd cycle detection and Brent's faster batched-gcd variant are selectable on the CLI.

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

### Attacker side (only sees `pub.json` + optional `ciphertext.txt`)

```bash
# Just factor n
python -m rsa_poc factor --key keys/pub.json
# n = 97134618697
# p = 174121
# q = 557857
# factored in 0.0001s using brent
```

`--key` also accepts PEM public keys, not just `pub.json`:

```bash
# Both -----BEGIN RSA PUBLIC KEY----- (PKCS#1) and
# -----BEGIN PUBLIC KEY----- (SPKI) are recognized automatically.
python -m rsa_poc factor --key somekey.pem
```

> The PEM is only parsed for `n` and `e`. Large moduli (e.g. a real 512-bit key)
> load fine but Pollard's rho will never finish on them — this tool only cracks
> the small-prime keys the PoC is built around.

```bash
# Recover the full private key from the public key alone (no ciphertext needed)
python -m rsa_poc break --key keys/pub.json
# n = 97134618697
# e = 65537
# d = 12345678901
# p = 174121
# q = 557857
# # timing: factor=0.0004s (brent)  derive_d=0.000003s

# Or save the recovered key to a file
python -m rsa_poc break --key keys/pub.json --out recovered-priv.json

# Full break — also decrypt a ciphertext
python -m rsa_poc break --key keys/pub.json --ciphertext-file ciphertext.txt
# attack at dawn
# # timing: factor=0.0004s (brent)  derive_d=0.000003s  decrypt=0.000024s
```

## CLI

| Subcommand | Required | Optional |
|---|---|---|
| `generate` | `--out-dir` | `--digits N` (default 6, range 2–32; >14 prints a warning about factoring cost), `--e E` (default 65537) |
| `encrypt` | `--key`, `--out`, one of `--message`/`--message-file` | |
| `factor` | `--key` | `--algorithm {brent,floyd}` (default `brent`), `--verbose`, `--seed S` |
| `break` | `--key` | `--ciphertext-file` (also decrypt it), `--algorithm {brent,floyd}` (default `brent`), `--out` (plaintext if `--ciphertext-file` set, else recovered `priv.json`), `--verbose`, `--seed S` |

## How it works

1. **Keygen.** Two random `d`-digit primes `p`, `q` via Miller–Rabin. `n = p*q`, `φ = (p-1)(q-1)`, `d = e⁻¹ mod φ` (with `e = 65537`).
2. **Encrypt.** Plaintext UTF-8 bytes are split into blocks of `(n.bit_length() - 1) // 8` bytes so each block integer `m < n`. Ciphertext blocks are `c = mᵉ mod n`.
3. **Factor.** Pollard's rho with `f(x) = x² + c mod n`. Two cycle-detection variants are selectable via `--algorithm`:
   - **`brent`** (default): hare advances in power-of-2 epochs; one batched gcd covers up to 128 step-pairs. ~2-3× faster than Floyd at our `n` sizes because gcd dominates per-iteration cost.
   - **`floyd`**: classic tortoise-and-hare; tortoise once, hare twice, one gcd per step. Simpler to read; useful for understanding the core idea.

   Both restart with a fresh `c` if `gcd(|x-y|, n) == n`. Cost scales as ~√p: microseconds at 6 digits, ~0.2 s at 12, seconds at 14, minutes at 16, infeasible beyond ~20.
4. **Break.** Factor `n` → recover `p, q` → compute `d` → decrypt each ciphertext block → reassemble bytes → decode UTF-8.

## Project structure

```
rsa_poc/
├── primes.py     # Miller-Rabin is_prime, random_prime(digits)
├── rsa.py        # keygen, encrypt, decrypt, derive_private_key, text<->blocks
├── factor.py     # pollard_rho (semiprimes only)
├── keyfile.py    # JSON I/O for pub.json, priv.json, ciphertext.txt
├── pem.py        # parse RSA public keys from PEM (PKCS#1 + SPKI), stdlib only
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

PEM public keys (input only) — both headers are accepted wherever `--key` is used:

```
-----BEGIN RSA PUBLIC KEY-----   (PKCS#1 RSAPublicKey)
-----BEGIN PUBLIC KEY-----       (SPKI SubjectPublicKeyInfo, RSA only)
```

## Running the tests

```bash
python -m unittest discover tests -v
```

26 tests across `primes`, `rsa`, and `factor`. End-to-end CLI coverage is by manual smoke test (see [the implementation plan](docs/superpowers/plans/2026-05-25-rsa-small-prime-poc.md) Task 8).

## Design and implementation docs

- [Design spec](docs/superpowers/specs/2026-05-25-rsa-small-prime-poc-design.md)
- [Implementation plan](docs/superpowers/plans/2026-05-25-rsa-small-prime-poc.md)
