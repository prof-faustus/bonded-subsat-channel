"""Block serialisation and merkle-root computation.

A block on the wire is a header (80 bytes) followed by a var_int
transaction count and the serialised transactions. This module also
implements the standard merkle-root computation: pairwise
double-SHA256 with duplication of the last element when the count is
odd, repeated until a single 32-byte root remains.
"""

from __future__ import annotations

import hashlib
from typing import Sequence

from bitcoinx import Tx

from .headers import HEADER_SIZE, build_raw_header, header_hash
from .p2p import double_sha256, encode_varint, read_varint
import io


def merkle_root(txids: Sequence[bytes]) -> bytes:
    if not txids:
        return b"\x00" * 32
    level: list[bytes] = list(txids)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            nxt.append(double_sha256(level[i] + level[i + 1]))
        level = nxt
    return level[0]


def serialise_block(header: bytes, txs: Sequence[Tx]) -> bytes:
    if len(header) != HEADER_SIZE:
        raise ValueError(f"header must be 80 bytes (got {len(header)})")
    out = bytearray(header)
    out += encode_varint(len(txs))
    for tx in txs:
        out += tx.to_bytes()
    return bytes(out)


def parse_block(raw: bytes) -> tuple[bytes, list[Tx]]:
    if len(raw) < HEADER_SIZE:
        raise ValueError("block too short")
    header = raw[:HEADER_SIZE]
    buf = io.BytesIO(raw[HEADER_SIZE:])
    n = read_varint(buf)
    txs: list[Tx] = []
    for _ in range(n):
        # Read until Tx.read consumes; use a small wrapper since bitcoinx
        # exposes Tx.read on a stream.
        from bitcoinx.tx import Tx as _Tx
        txs.append(_Tx.read(buf.read))
    return header, txs


__all__ = ["merkle_root", "serialise_block", "parse_block"]
