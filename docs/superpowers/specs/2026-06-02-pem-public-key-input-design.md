# PEM Public-Key Input — Design

**Date:** 2026-06-02
**Status:** Approved

## Problem

The PoC's `factor`, `break`, and `encrypt` commands load public keys only from
`pub.json` (`{"n": ..., "e": ...}`). Real-world RSA public keys are distributed
as PEM text:

```
-----BEGIN RSA PUBLIC KEY-----
...base64...
-----END RSA PUBLIC KEY-----
```

Today such a key cannot be loaded at all. We want `--key` to accept PEM files in
addition to `pub.json`, so the existing attack commands work on keys in this
format.

## Goal

Add PEM public-key **input** parsing, standard-library only, with no CLI changes
beyond accepting `.pem` content wherever `--key` is used.

### Non-goals (YAGNI)

- PEM **export** from `generate` (still writes `pub.json`).
- Private-key PEM, encrypted PEM, or binary DER files.
- Making large keys factorable. A 512-bit modulus (155 decimal digits) loads
  fine but Pollard's rho — which scales as ~√p — will never finish on it. This
  is documented, not fixed.

## Constraints

- **Standard library only.** No `cryptography`, no `pip install`. The parser is
  a hand-written ASN.1/DER reader. This preserves the repo's core property.
- Output shape unchanged: `{"n": int, "e": int}`, so downstream code is
  untouched.

## Approach

Auto-detect format by content in `keyfile.load_public()`:

- Stripped text begins with `-----BEGIN` → parse as PEM.
- Otherwise → existing JSON path.

`-----BEGIN` vs `{` is unambiguous, so no `--key-format` flag is needed.

## Components

### New module: `rsa_poc/pem.py`

Single public function:

```python
def parse_public_pem(text: str) -> dict:  # -> {"n": int, "e": int}
```

Supports two PEM types:

| PEM header | Structure |
|---|---|
| `-----BEGIN RSA PUBLIC KEY-----` | PKCS#1 `RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }` |
| `-----BEGIN PUBLIC KEY-----` | SPKI `SubjectPublicKeyInfo`: `SEQUENCE { AlgorithmIdentifier, BIT STRING }`, where the BIT STRING wraps the PKCS#1 `RSAPublicKey`. The `AlgorithmIdentifier` OID must be RSA: `1.2.840.113549.1.1.1`. |

Internals (private helpers in the module):

- `_pem_to_der(text)` — find the `BEGIN/END` markers, base64-decode the body,
  return `(der_bytes, label)` where `label` is `"RSA PUBLIC KEY"` or
  `"PUBLIC KEY"`.
- A minimal DER reader that yields `(tag, value_bytes, rest)` for one TLV,
  decoding short- and long-form lengths. It raises on a declared length that
  exceeds the available bytes — this is exactly what catches the truncated
  example key.
- `_read_integer`, `_read_sequence`, `_read_bitstring`, `_read_oid` built on the
  reader.

### Modified: `rsa_poc/keyfile.py`

`load_public(path)`:

1. Read the file text (existing `FileNotFoundError` → `ValueError` handling).
2. If `text.lstrip().startswith("-----BEGIN")`: return
   `pem.parse_public_pem(text)`.
3. Else: existing JSON parse + required-field validation.

No other functions change. `encrypt`, `factor`, `break` get PEM support for
free because they all go through `load_public`.

## Error handling

All failures raise `ValueError` with a clear, prefixed message (matching the
existing `"{path}: ..."` style), surfaced by `cli.main`'s existing
`except ValueError`. Cases:

- No `BEGIN/END` markers, or mismatched label → `"...: not a valid PEM public key"`.
- Base64 decode failure → `"...: invalid base64 in PEM body"`.
- DER length overruns / unexpected tags → `"...: malformed DER: <detail>"`.
- SPKI with non-RSA OID → `"...: not an RSA key (unexpected algorithm OID)"`.

The truncated 512-bit example key falls into the DER-overrun case and produces a
clear malformed-DER error rather than a crash or silent wrong answer.

## Testing

New `tests/test_pem.py` (unittest, matching the existing suite):

- **PKCS#1 round-trip** — a known fixture PEM decodes to its expected `n`, `e`.
- **SPKI round-trip** — same key in `-----BEGIN PUBLIC KEY-----` form decodes to
  the same `n`, `e`.
- **Fixtures are generated independently** (via `openssl`) and hardcoded as
  string constants, so the test does not validate the parser against our own
  encoder (non-circular).
- **Malformed input** — the truncated example key, a non-PEM string, a bad-OID
  SPKI key, and a length-overrun DER each raise `ValueError`.
- **JSON still works** — `keyfile.load_public` on a `pub.json` returns the right
  dict (guards the auto-detect dispatch).

End-to-end: a manual smoke test that `python -m rsa_poc factor --key <small>.pem`
recovers `p, q` for a small-prime key, added to the README/plan smoke list.

## Docs

README: note that `--key` accepts a `.pem` file (both `RSA PUBLIC KEY` and
`PUBLIC KEY` headers) as well as `pub.json`, with a one-line caveat that large
moduli load but are not factorable by this tool.
