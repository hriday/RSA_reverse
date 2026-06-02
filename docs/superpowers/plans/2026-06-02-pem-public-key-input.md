# PEM Public-Key Input Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `--key` accept `-----BEGIN RSA PUBLIC KEY-----` (PKCS#1) and `-----BEGIN PUBLIC KEY-----` (SPKI) PEM files anywhere `pub.json` works today.

**Architecture:** A new standard-library-only module `rsa_poc/pem.py` hand-parses ASN.1/DER and returns `{"n": int, "e": int}`. `keyfile.load_public()` auto-detects PEM vs JSON by content and dispatches, so `factor`/`break`/`encrypt` get PEM support with no CLI changes.

**Tech Stack:** Python 3.8+ standard library only (`base64`, `binascii`). No third-party deps. `unittest` for tests.

---

## File Structure

- **Create `rsa_poc/pem.py`** — `parse_public_pem(text) -> {"n","e"}`, plus private DER/PEM helpers. Sole responsibility: turn PEM text into `n, e`.
- **Modify `rsa_poc/keyfile.py`** — `load_public()` auto-detects PEM; refactor JSON parse into a text-based helper to avoid a double file read.
- **Create `tests/test_pem.py`** — parser unit tests with independent (openssl-generated) fixtures + error cases + JSON-dispatch guard.
- **Modify `README.md`** — document `.pem` input and the large-key caveat.

## Test Fixtures (independently generated via openssl — non-circular)

These are real constants used by the tests. The 512-bit PKCS#1 and SPKI fixtures
are the *same key*, so both must decode to the same `n`/`e`.

```python
# Same 512-bit RSA key, two encodings. Both must decode to FIXTURE_N / 65537.
PKCS1_PEM = """\
-----BEGIN RSA PUBLIC KEY-----
MEgCQQD1oSmduq6iToZHF8IJfQWRCBYbtj3dptvncaHIwHm+kdwkHY56kVKcbHR/
kzgTEWqbC7Qln26yv71e35LQwDSrAgMBAAE=
-----END RSA PUBLIC KEY-----
"""

SPKI_PEM = """\
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAPWhKZ26rqJOhkcXwgl9BZEIFhu2Pd2m
2+dxocjAeb6R3CQdjnqRUpxsdH+TOBMRapsLtCWfbrK/vV7fktDANKsCAwEAAQ==
-----END PUBLIC KEY-----
"""

FIXTURE_N = 12864662934208601539761718960743191828799474324895033652352950267330150268692429766835616245849250203447713818535770738663427795444668351747373138737902763
FIXTURE_E = 65537

# Small-prime PKCS#1 key (n = 174121 * 557857 = 97134618697), actually factorable.
SMALL_PKCS1_PEM = """\
-----BEGIN RSA PUBLIC KEY-----
MAwCBRadrKhJAgMBAAE=
-----END RSA PUBLIC KEY-----
"""
SMALL_N = 97134618697

# Non-RSA SPKI (EC P-256) — must be rejected with an OID error.
EC_SPKI_PEM = """\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb2GShHmCVkPlmUEmVMC00CYihcmC
1dcoGNsbDVY3xXF1k8zKBNSy1bxlYQsikSLV14Qp8AMSAbOL1uTfr+D7EA==
-----END PUBLIC KEY-----
"""

# The user's truncated 512-bit key — declared SEQUENCE length exceeds bytes present.
TRUNCATED_PEM = """\
-----BEGIN RSA PUBLIC KEY-----
MEgCQQDXtxF4LjzvrDjJT5bJWsyMof3w7U/UgpVKNxnCkH3NiQ/mhRTFpLZB
4n6Iq5OglpfSYl6emKgYwdJW2I5vAgMBAAE=
-----END RSA PUBLIC KEY-----
"""
```

---

### Task 1: PKCS#1 parsing in `pem.py`

**Files:**
- Create: `rsa_poc/pem.py`
- Test: `tests/test_pem.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_pem.py`. Include the full **Test Fixtures** block above at the
top of the file (after imports), then:

```python
import unittest

from rsa_poc import pem

# <-- paste the Test Fixtures constants here -->


class TestPkcs1(unittest.TestCase):
    def test_pkcs1_round_trip(self):
        result = pem.parse_public_pem(PKCS1_PEM)
        self.assertEqual(result, {"n": FIXTURE_N, "e": FIXTURE_E})

    def test_small_prime_pkcs1(self):
        result = pem.parse_public_pem(SMALL_PKCS1_PEM)
        self.assertEqual(result["n"], SMALL_N)
        self.assertEqual(result["e"], 65537)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_pem -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rsa_poc.pem'`.

- [ ] **Step 3: Write minimal implementation**

Create `rsa_poc/pem.py`:

```python
"""Parse RSA public keys from PEM text (PKCS#1 and SPKI). Standard library only."""

from __future__ import annotations

import base64
import binascii

_PKCS1_LABEL = "RSA PUBLIC KEY"
_SPKI_LABEL = "PUBLIC KEY"


def parse_public_pem(text: str) -> dict:
    """Return {"n": int, "e": int} from a PEM RSA public key.

    Accepts PKCS#1 ('RSA PUBLIC KEY') and SPKI ('PUBLIC KEY') PEM.
    Raises ValueError on malformed or non-RSA input.
    """
    der, label = _pem_to_der(text)
    if label == _PKCS1_LABEL:
        return _parse_pkcs1(der)
    if label == _SPKI_LABEL:
        return _parse_spki(der)
    raise ValueError(f"unsupported PEM label: {label!r}")


def _pem_to_der(text: str) -> tuple[bytes, str]:
    lines = text.strip().splitlines()
    begin = end = None
    label = ""
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("-----BEGIN ") and s.endswith("-----"):
            begin = i
            label = s[len("-----BEGIN "):-len("-----")].strip()
        elif s.startswith("-----END ") and s.endswith("-----"):
            end = i
            break
    if begin is None or end is None or end <= begin:
        raise ValueError("not a valid PEM public key (missing BEGIN/END markers)")
    body = "".join(l.strip() for l in lines[begin + 1:end])
    try:
        der = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64 in PEM body") from exc
    return der, label


def _read_tlv(der: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER tag-length-value at offset. Return (tag, value, next_offset)."""
    if offset >= len(der):
        raise ValueError("malformed DER: unexpected end of data")
    tag = der[offset]
    offset += 1
    if offset >= len(der):
        raise ValueError("malformed DER: truncated length")
    first = der[offset]
    offset += 1
    if first & 0x80:
        num = first & 0x7F
        if num == 0:
            raise ValueError("malformed DER: indefinite length not supported")
        if offset + num > len(der):
            raise ValueError("malformed DER: truncated long-form length")
        length = int.from_bytes(der[offset:offset + num], "big")
        offset += num
    else:
        length = first
    if offset + length > len(der):
        raise ValueError("malformed DER: declared length exceeds available bytes")
    return tag, der[offset:offset + length], offset + length


def _parse_pkcs1(der: bytes) -> dict:
    tag, body, _ = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("malformed DER: expected SEQUENCE for RSAPublicKey")
    tag_n, n_bytes, off = _read_tlv(body, 0)
    if tag_n != 0x02:
        raise ValueError("malformed DER: expected INTEGER modulus")
    tag_e, e_bytes, _ = _read_tlv(body, off)
    if tag_e != 0x02:
        raise ValueError("malformed DER: expected INTEGER exponent")
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    if n <= 0 or e <= 0:
        raise ValueError("malformed DER: non-positive n or e")
    return {"n": n, "e": e}
```

(SPKI support is added in Task 2; the `_parse_spki` call exists but the function
is defined next task. The PKCS#1 tests in this task do not reach it.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_pem -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add rsa_poc/pem.py tests/test_pem.py
git commit -m "feat(pem): parse PKCS#1 RSA public keys from PEM"
```

---

### Task 2: SPKI parsing + RSA OID check

**Files:**
- Modify: `rsa_poc/pem.py`
- Test: `tests/test_pem.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_pem.py`:

```python
class TestSpki(unittest.TestCase):
    def test_spki_round_trip(self):
        result = pem.parse_public_pem(SPKI_PEM)
        self.assertEqual(result, {"n": FIXTURE_N, "e": FIXTURE_E})

    def test_spki_matches_pkcs1(self):
        # Same key, two encodings -> identical n, e.
        self.assertEqual(
            pem.parse_public_pem(SPKI_PEM),
            pem.parse_public_pem(PKCS1_PEM),
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_pem.TestSpki -v`
Expected: FAIL — `NameError: name '_parse_spki' is not defined` (raised when called).

- [ ] **Step 3: Write minimal implementation**

Add to `rsa_poc/pem.py` (define `_RSA_OID` near the labels, and add `_parse_spki`):

```python
# RSA encryption algorithm OID 1.2.840.113549.1.1.1, DER-encoded value bytes.
_RSA_OID = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
```

```python
def _parse_spki(der: bytes) -> dict:
    tag, body, _ = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("malformed DER: expected SEQUENCE for SubjectPublicKeyInfo")
    tag_alg, alg, off = _read_tlv(body, 0)
    if tag_alg != 0x30:
        raise ValueError("malformed DER: expected AlgorithmIdentifier SEQUENCE")
    tag_oid, oid, _ = _read_tlv(alg, 0)
    if tag_oid != 0x06:
        raise ValueError("malformed DER: expected algorithm OID")
    if oid != _RSA_OID:
        raise ValueError("not an RSA key (unexpected algorithm OID)")
    tag_bs, bits, _ = _read_tlv(body, off)
    if tag_bs != 0x03:
        raise ValueError("malformed DER: expected BIT STRING")
    if not bits or bits[0] != 0x00:
        raise ValueError("malformed DER: unexpected BIT STRING padding")
    return _parse_pkcs1(bits[1:])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_pem -v`
Expected: PASS (4 tests total).

- [ ] **Step 5: Commit**

```bash
git add rsa_poc/pem.py tests/test_pem.py
git commit -m "feat(pem): parse SPKI RSA public keys, enforce RSA OID"
```

---

### Task 3: Error handling for malformed / non-RSA input

**Files:**
- Test: `tests/test_pem.py` (implementation already in place from Tasks 1-2)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_pem.py`:

```python
class TestErrors(unittest.TestCase):
    def test_truncated_key_raises(self):
        with self.assertRaises(ValueError) as cm:
            pem.parse_public_pem(TRUNCATED_PEM)
        self.assertIn("declared length exceeds", str(cm.exception))

    def test_non_rsa_oid_raises(self):
        with self.assertRaises(ValueError) as cm:
            pem.parse_public_pem(EC_SPKI_PEM)
        self.assertIn("not an RSA key", str(cm.exception))

    def test_no_markers_raises(self):
        with self.assertRaises(ValueError) as cm:
            pem.parse_public_pem("just some text, no PEM here")
        self.assertIn("not a valid PEM", str(cm.exception))

    def test_bad_base64_raises(self):
        bad = "-----BEGIN RSA PUBLIC KEY-----\n!!!!not base64!!!!\n-----END RSA PUBLIC KEY-----\n"
        with self.assertRaises(ValueError) as cm:
            pem.parse_public_pem(bad)
        self.assertIn("base64", str(cm.exception))
```

- [ ] **Step 2: Run test to verify it fails, then passes**

The implementation from Tasks 1-2 already covers these paths. Run:

Run: `python -m unittest tests.test_pem -v`
Expected: PASS (8 tests total). If any error message assertion fails, adjust the
message text in `pem.py` to match — do not weaken the assertions.

- [ ] **Step 3: Commit**

```bash
git add tests/test_pem.py
git commit -m "test(pem): cover truncated, non-RSA, and malformed PEM input"
```

---

### Task 4: Auto-detect PEM vs JSON in `keyfile.load_public`

**Files:**
- Modify: `rsa_poc/keyfile.py`
- Test: `tests/test_pem.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_pem.py` (add `import json`, `import tempfile`, `from pathlib import Path`, `from rsa_poc import keyfile` to the imports at the top):

```python
class TestLoadPublicDispatch(unittest.TestCase):
    def _write(self, name, text):
        d = tempfile.mkdtemp()
        p = Path(d) / name
        p.write_text(text, encoding="utf-8")
        return p

    def test_load_public_reads_pem(self):
        p = self._write("pub.pem", PKCS1_PEM)
        self.assertEqual(keyfile.load_public(p), {"n": FIXTURE_N, "e": FIXTURE_E})

    def test_load_public_reads_spki_pem(self):
        p = self._write("pub.pem", SPKI_PEM)
        self.assertEqual(keyfile.load_public(p), {"n": FIXTURE_N, "e": FIXTURE_E})

    def test_load_public_still_reads_json(self):
        p = self._write("pub.json", json.dumps({"n": 97134618697, "e": 65537}))
        self.assertEqual(keyfile.load_public(p), {"n": 97134618697, "e": 65537})

    def test_load_public_pem_error_is_prefixed(self):
        p = self._write("bad.pem", TRUNCATED_PEM)
        with self.assertRaises(ValueError) as cm:
            keyfile.load_public(p)
        self.assertIn(str(p), str(cm.exception))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_pem.TestLoadPublicDispatch -v`
Expected: FAIL — PEM file routed into JSON parser → `invalid JSON`.

- [ ] **Step 3: Write minimal implementation**

In `rsa_poc/keyfile.py`, add the import near the top (after `from pathlib import Path`):

```python
from rsa_poc import pem
```

Replace `load_public` (currently `return _read_required(path, _PUB_FIELDS)`) with:

```python
def load_public(path: str | Path) -> dict:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"{p}: file not found") from exc
    if text.lstrip().startswith("-----BEGIN"):
        try:
            return pem.parse_public_pem(text)
        except ValueError as exc:
            raise ValueError(f"{p}: {exc}") from exc
    return _required_from_text(p, text, _PUB_FIELDS)
```

Refactor `_read_required` to share the JSON logic via a text-based helper. Replace
the existing `_read_required` body with a read-then-delegate, and add
`_required_from_text`:

```python
def _read_required(path: str | Path, fields: tuple[str, ...]) -> dict:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"{p}: file not found") from exc
    return _required_from_text(p, text, fields)


def _required_from_text(p: Path, text: str, fields: tuple[str, ...]) -> dict:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{p}: invalid JSON: {exc.msg}") from exc
    missing = [f for f in fields if f not in data]
    if missing:
        raise ValueError(f"{p}: missing required field(s): {', '.join(missing)}")
    return {f: int(data[f]) for f in fields}
```

`load_private` continues to call `_read_required` unchanged.

- [ ] **Step 4: Run the full test suite**

Run: `python -m unittest discover tests -v`
Expected: PASS — all existing tests plus the new `test_pem` tests (no regressions
in `test_primes`, `test_rsa`, `test_factor`).

- [ ] **Step 5: Commit**

```bash
git add rsa_poc/keyfile.py tests/test_pem.py
git commit -m "feat(keyfile): auto-detect PEM public keys in load_public"
```

---

### Task 5: End-to-end smoke test + README docs

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Manual end-to-end smoke test (factor a PEM key)**

Write the small-prime PEM to a file and factor it:

```bash
cat > /tmp/small_pub.pem <<'EOF'
-----BEGIN RSA PUBLIC KEY-----
MAwCBRadrKhJAgMBAAE=
-----END RSA PUBLIC KEY-----
EOF
python -m rsa_poc factor --key /tmp/small_pub.pem
```

Expected output (order of p/q may differ):
```
n = 97134618697
p = 174121
q = 557857
factored in 0.000Xs using brent
```

Then verify a full key recovery:

```bash
python -m rsa_poc break --key /tmp/small_pub.pem
```
Expected: prints `n`, `e`, `d`, `p`, `q` with `n = 97134618697`.

- [ ] **Step 2: Confirm large-key behavior is a clean load (not a crash)**

```bash
cat > /tmp/big_pub.pem <<'EOF'
-----BEGIN RSA PUBLIC KEY-----
MEgCQQD1oSmduq6iToZHF8IJfQWRCBYbtj3dptvncaHIwHm+kdwkHY56kVKcbHR/
kzgTEWqbC7Qln26yv71e35LQwDSrAgMBAAE=
-----END RSA PUBLIC KEY-----
EOF
python -m rsa_poc factor --key /tmp/big_pub.pem --verbose
```
Expected: the key loads (no parse error) and `factor` begins running Pollard's rho;
it will not finish on a 512-bit modulus. Press Ctrl-C. This confirms the parser
works and the limitation is the factoring math, not the input path. (Do not leave
it running.)

- [ ] **Step 3: Update README**

In `README.md`, in the **Attacker side** section, after the existing `factor`
example, add:

````markdown
`--key` also accepts PEM public keys, not just `pub.json`:

```bash
# Both -----BEGIN RSA PUBLIC KEY----- (PKCS#1) and
# -----BEGIN PUBLIC KEY----- (SPKI) are recognized automatically.
python -m rsa_poc factor --key somekey.pem
```

> The PEM is only parsed for `n` and `e`. Large moduli (e.g. a real 512-bit key)
> load fine but Pollard's rho will never finish on them — this tool only cracks
> the small-prime keys the PoC is built around.
````

In the **File formats** section, after the `ciphertext.txt` block, add:

````markdown
PEM public keys (input only) — both headers are accepted wherever `--key` is used:

```
-----BEGIN RSA PUBLIC KEY-----   (PKCS#1 RSAPublicKey)
-----BEGIN PUBLIC KEY-----       (SPKI SubjectPublicKeyInfo, RSA only)
```
````

In the **Project structure** tree, add a line under `keyfile.py`:

```
├── pem.py        # parse RSA public keys from PEM (PKCS#1 + SPKI), stdlib only
```

- [ ] **Step 4: Run the full suite once more**

Run: `python -m unittest discover tests -v`
Expected: PASS (all tests green).

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: document PEM public-key input for --key"
```

---

## Self-Review Notes

- **Spec coverage:** `pem.py` module + `parse_public_pem` (Tasks 1-2); PKCS#1 and
  SPKI with OID check (Tasks 1-2); auto-detect in `load_public` (Task 4); error
  handling for truncated/non-RSA/no-markers/bad-base64 (Task 3); non-circular
  openssl fixtures (fixtures block); JSON-still-works guard (Task 4); README docs
  incl. large-key caveat (Task 5). All spec sections mapped.
- **Out of scope (per spec):** PEM export, private/encrypted PEM, binary DER —
  none added.
- **Type consistency:** `parse_public_pem`, `_pem_to_der`, `_read_tlv`,
  `_parse_pkcs1`, `_parse_spki`, `_required_from_text` names are used identically
  across all tasks. Return shape is `{"n": int, "e": int}` throughout.
