"""Parse RSA public keys from PEM text (PKCS#1 and SPKI). Standard library only."""

from __future__ import annotations

import base64
import binascii

_PKCS1_LABEL = "RSA PUBLIC KEY"
_SPKI_LABEL = "PUBLIC KEY"

# RSA encryption algorithm OID 1.2.840.113549.1.1.1, DER-encoded value bytes.
_RSA_OID = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])


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
