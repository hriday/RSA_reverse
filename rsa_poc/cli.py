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
    if args.digits > 32:
        raise ValueError(f"--digits must be <= 32, got {args.digits}")
    if args.digits > 14:
        sys.stderr.write(
            f"warning: --digits={args.digits} is beyond the PoC's tuned range (<=14). "
            "key generation is fast, but `factor`/`break` use Pollard's rho (Brent's "
            "variant) which scales as ~sqrt(p) -- expect seconds at 14-15 digits, "
            "minutes at 16, hours at 18, and effectively forever at 24+.\n"
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
        try:
            text = args.message_file.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise ValueError(f"{args.message_file}: file not found") from exc
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
        args.out.parent.mkdir(parents=True, exist_ok=True)
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
