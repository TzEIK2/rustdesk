#!/usr/bin/env python3
"""Generate a valid RustDesk rendezvous server key.

RustDesk clients accept -k / RENDEZVOUS_KEY values that are base64-encoded
32-byte ED25519 public keys (44 chars including the trailing "=" padding).

Usage:
    python3 gen_rd_key.py          # 生成一把新 key
    python3 gen_rd_key.py --count 3  # 一次生成多把
    python3 gen_rd_key.py --verify "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw="  # 校验已有 key
"""

import argparse
import base64
import secrets
import sys


def gen_key() -> str:
    raw = secrets.token_bytes(32)
    key = base64.b64encode(raw).decode("ascii")
    assert len(key) == 44, f"unexpected length {len(key)}"
    assert base64.b64decode(key) == raw
    return key


def verify(key: str) -> bool:
    try:
        raw = base64.b64decode(key, validate=True)
    except Exception as e:
        print(f"FAIL  base64 decode error: {e}", file=sys.stderr)
        return False
    if len(raw) != 32:
        print(f"FAIL  decoded to {len(raw)} bytes, expected 32", file=sys.stderr)
        return False
    if len(key) != 44:
        print(f"WARN  {len(key)} chars (expected 44), missing padding?", file=sys.stderr)
    print("OK    valid 32-byte base64 key")
    return True


def main():
    parser = argparse.ArgumentParser(description="Generate/verify RustDesk -k key")
    parser.add_argument("--count", type=int, default=1, help="number of keys to generate")
    parser.add_argument("--verify", type=str, metavar="KEY", help="verify an existing key")
    args = parser.parse_args()

    if args.verify:
        ok = verify(args.verify)
        sys.exit(0 if ok else 1)

    for i in range(args.count):
        key = gen_key()
        print(key)


if __name__ == "__main__":
    main()
