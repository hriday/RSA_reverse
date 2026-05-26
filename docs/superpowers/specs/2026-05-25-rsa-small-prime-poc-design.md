# RSA Small-Prime PoC — Design

**Status:** Approved
**Date:** 2026-05-25

## Goal

A Python proof-of-concept demonstrating why RSA must not use small primes. The PoC generates a keypair from primes up to 6 digits, encrypts a message, then recovers the plaintext from only the public key and ciphertext by factoring `n` with Pollard's rho. The end-to-end attack-on-toy-key demo is what makes the lesson land.

## Non-goals

- Production-grade RSA (no padding, no OAEP, no secure key storage).
- Factoring primes beyond ~7 digits in reasonable time. A `>6` digit option is exposed with a warning, but performance is not tuned.
- Side-channel resistance, constant-time arithmetic, timing-attack resistance.
- Network protocols, PEM/DER interop, or compatibility with `openssl`/`cryptography`.
- A full GUI or notebook walkthrough.

## Constraints

- **Standard library only.** No `pip install` step. Allowed modules: `argparse`, `json`, `math`, `secrets`, `random`, `time`, `sys`, `pathlib`, `unittest`.
- **Python 3.8+.** Required for `pow(e, -1, m)` modular inverse.
- **Prime size range:** 3 to 14 digits is the tuned range where `factor`/`break` finish in seconds. `--digits` accepts up to 32 with a stderr warning beyond 14 explaining the cost curve. Values >32 are rejected.

## Architecture

```
rsa_poc/
├── __init__.py
├── __main__.py        # enables `python -m rsa_poc`
├── primes.py          # is_prime, random_prime
├── rsa.py             # keygen, encrypt, decrypt, derive_private_key, text<->blocks
├── factor.py          # pollard_rho
├── keyfile.py         # JSON I/O for pub.json, priv.json, ciphertext.txt
└── cli.py             # argparse dispatcher: generate / encrypt / factor / break

tests/
├── test_primes.py
├── test_rsa.py
└── test_factor.py
```

Dependencies flow one way: `cli → {rsa, factor, primes, keyfile}`, `rsa → primes`, `factor` stands alone, `keyfile` stands alone.

## Module contracts

### `primes.py`
- `is_prime(n: int) -> bool` — Miller–Rabin with deterministic witnesses sufficient for `n < 2^64`.
- `random_prime(digits: int) -> int` — uniform-random prime with exactly `digits` decimal digits, sampled via `secrets.randbelow`. Raises `ValueError` for `digits < 2`.

### `rsa.py`
- `keygen(digits: int, e: int = 65537) -> tuple[PublicKey, PrivateKey]`
  - `PublicKey = {"n": int, "e": int}`
  - `PrivateKey = {"n": int, "e": int, "d": int, "p": int, "q": int}`
  - Retries up to 20 times if `gcd(e, φ(n)) != 1`; raises `ValueError` if it cannot find a coprime pair (signals a bad `e`).
- `encrypt(pub, m: int) -> int` — computes `pow(m, e, n)`. Raises `ValueError` if `m >= n`.
- `decrypt(priv, c: int) -> int` — computes `pow(c, d, n)`.
- `derive_private_key(p: int, q: int, e: int) -> PrivateKey` — used by `break` after factoring.
- `text_to_blocks(text: str, n: int) -> list[int]` — UTF-8 encodes, then splits into blocks of `block_size = (n.bit_length() - 1) // 8` bytes so every block integer is `< n`. The final block is left as-is (its byte length is stored implicitly by being the last block; see Encoding below).
- `blocks_to_text(blocks: list[int], n: int, total_len: int) -> str` — inverse of `text_to_blocks`. Reads `total_len` bytes total across blocks, then decodes UTF-8.

### `factor.py`
- `pollard_rho(n: int) -> tuple[int, int]` — returns `(p, q)` with `p <= q` and `p * q == n`. Uses `f(x) = (x² + c) mod n` with random `c` and Brent's cycle-detection variant (hare advances in power-of-2 epochs, batched gcd over 128-step chunks; ~2-3× faster than Floyd's at our prime sizes). Restarts with fresh `c` on `gcd == n`. Raises `ValueError` if `n < 4`, if `is_prime(n)` (precheck), if the returned factor is itself composite (`n` had three or more prime factors), or if `p == q` (`n` was a prime square).

### `keyfile.py`
- `save_public(path, pub)` / `load_public(path) -> PublicKey`
- `save_private(path, priv)` / `load_private(path) -> PrivateKey`
- `save_ciphertext(path, blocks: list[int], total_len: int)` — writes `total_len` on the first line, then one int per line.
- `load_ciphertext(path) -> tuple[list[int], int]` — returns `(blocks, total_len)`.

### `cli.py`
- `main(argv: list[str] | None = None) -> int` — argparse with four subparsers.
- Each subcommand is one small function that calls into the library and writes files / prints.

## CLI surface

| Subcommand | Required flags | Optional flags |
|---|---|---|
| `generate` | `--out-dir DIR` | `--digits N` (default 6, range 3–6; values >6 print a stderr warning and proceed), `--e E` (default 65537) |
| `encrypt` | `--key FILE`, `--out FILE`, exactly one of `--message STR` / `--message-file FILE` | |
| `factor` | `--key FILE` | `--verbose` (prints iteration count and restart count), `--seed S` (seeds `random` so Pollard's rho's choice of `c` and starting `x` is reproducible — useful for demo recordings) |
| `break` | `--key FILE`, `--ciphertext-file FILE` | `--out FILE` (write recovered plaintext to file; default is stdout), `--verbose`, `--seed S` (same as `factor`) |

Sample invocations:
```
python -m rsa_poc generate --digits 6 --out-dir ./keys/
python -m rsa_poc encrypt --key keys/pub.json --message "attack at dawn" --out ciphertext.txt
python -m rsa_poc factor --key keys/pub.json
python -m rsa_poc break --key keys/pub.json --ciphertext-file ciphertext.txt
```

## File formats

**`pub.json`**
```json
{"n": 123456789013, "e": 65537}
```

**`priv.json`**
```json
{"n": 123456789013, "e": 65537, "d": 98765432101, "p": 100003, "q": 1234567891}
```

**`ciphertext.txt`** — first line is the original plaintext byte length (used to trim the last block during decoding); subsequent lines are ciphertext block integers, one per line:
```
14
4823910
192847
80213
```

## Data flow

### `generate`
1. Sample distinct primes `p`, `q` of `--digits` digits via `random_prime`.
2. Compute `n = p * q`, `φ = (p-1)*(q-1)`.
3. If `gcd(e, φ) != 1`, restart from step 1 (bounded retry: 20 attempts).
4. Compute `d = pow(e, -1, φ)`.
5. Write `pub.json` and `priv.json` in `--out-dir`.

### `encrypt`
1. Load `pub.json`.
2. Encode message as UTF-8 bytes; record `total_len`.
3. Split bytes into blocks of `block_size = (n.bit_length() - 1) // 8` bytes; interpret each as big-endian int. Final block may be short.
4. For each block `m`, compute `c = pow(m, e, n)`.
5. Write ciphertext file with `total_len` header line.

### `factor`
1. Load `pub.json`.
2. Run `pollard_rho(n)`; time it.
3. Print `p`, `q`, and elapsed seconds.

### `break`
1. Load `pub.json` and ciphertext file (blocks + `total_len`).
2. Run `pollard_rho(n)` → `p, q`. Time this phase.
3. Compute `φ = (p-1)*(q-1)`, `d = pow(e, -1, φ)`. Time this phase.
4. Decrypt each block: `m = pow(c, d, n)`. Time this phase.
5. Reassemble bytes (using `block_size` and `total_len` to trim the final block) and decode UTF-8.
6. Print plaintext (or write to `--out`) and a timing breakdown to stderr.

## Error handling

Fail fast with one-line `ValueError` or `SystemExit` messages. No custom exception hierarchy.

- `primes.random_prime(digits)`: `ValueError` if `digits < 2`.
- `rsa.keygen`: `ValueError` if no coprime `φ` found in 20 retries (suggests bad `--e`).
- `rsa.encrypt`: `ValueError` if any block `>= n` (defensive — should be impossible if `text_to_blocks` is correct).
- `factor.pollard_rho`: `ValueError` if `n < 4`, `is_prime(n)`, the returned factor is itself composite, or `p == q`.
- `keyfile.load_*`: prepend filename to `json.JSONDecodeError` / `KeyError` messages.
- `cli`: argparse handles mutual exclusion and required flags. `--digits > 6` prints a stderr warning but proceeds. Errors from the library are caught at the `main` level and turned into a one-line `sys.stderr.write` + exit code 1.

## Testing strategy

All tests use `unittest` from the standard library. Run with `python -m unittest discover tests`.

### `test_primes.py`
- `is_prime` matches a brute trial-division oracle for `n ∈ [2, 10_000]`.
- `is_prime` returns `False` for several known Carmichael numbers (561, 1105, 1729) and `True` for known primes near the 6-digit boundary.
- `random_prime(d)` returns a value with exactly `d` digits that passes `is_prime`, for `d ∈ {3, 4, 5, 6}`.

### `test_rsa.py`
- Integer round-trip: for a fixed keypair, `decrypt(encrypt(m)) == m` for random `m < n` (10 iterations).
- Text round-trip: `blocks_to_text(decrypt_all(encrypt_all(text)), n, total_len) == text` for ASCII, mixed UTF-8 (e.g., emoji), and an empty string.
- `derive_private_key(p, q, e)` produces the same `d` as `keygen` when given matching primes.

### `test_factor.py`
- `pollard_rho(p*q)` returns `{p, q}` (set equality) for hand-picked prime pairs: close (100003, 100019), far (100003, 999983), small (101, 103).
- Property test: for 10 random keypairs (3–6 digit primes), assert `pollard_rho(n)` recovers `{p, q}`.
- `pollard_rho` raises on: a prime input, a prime square, a product of three distinct primes.

No CLI end-to-end / subprocess tests in this PoC — the CLI layer is a thin argparse wrapper over the library, and adding subprocess harnessing would inflate scope without catching realistic bugs.

## Encoding details (for unambiguous implementation)

- `block_size = (n.bit_length() - 1) // 8`. For 6-digit primes, `n ≈ 10^11–10^12`, `bit_length ≈ 37–40`, so `block_size = 4` bytes. Every block's integer is then `< 2^32 < n`.
- Bytes are split into chunks of `block_size`, each converted to int via `int.from_bytes(chunk, "big")`. The last chunk may be shorter; its length is recoverable from `total_len % block_size` (with `block_size` itself if the remainder is 0).
- On decode, each block is converted via `int.to_bytes(length, "big")`. For non-final blocks `length = block_size`. For the final block, `length = total_len - (len(blocks) - 1) * block_size`.
- This avoids leading-zero ambiguity, which would otherwise corrupt bytes whose top byte happens to be `0x00`.

## Out of scope (recorded for clarity)

- Supporting user-supplied `p`, `q` on the CLI. `generate` always samples primes itself.
- Trial-division or Fermat's-method alternative factorers. Pollard's rho only.
- Multi-message batched encryption beyond one input file at a time.
