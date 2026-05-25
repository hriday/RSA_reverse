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
