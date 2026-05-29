"""Header store and proof-of-work header-chain validation.

Headers are 80-byte fixed structures:

    version    (4 bytes, little-endian int32)
    prev_hash  (32 bytes)
    merkle_root(32 bytes)
    timestamp  (4 bytes, little-endian uint32)
    bits       (4 bytes, little-endian uint32)
    nonce      (4 bytes, little-endian uint32)

The block hash is the double-SHA256 of the 80-byte header (Satoshi
notation: little-endian internal byte order).

The header store keeps a longest-chain index by cumulative work and a
hash-to-header map. Reorganisations are handled by re-ranking on insert.
The store is regtest-friendly: ``bits`` is taken as-given (no DAA),
and validation requires that ``hash <= target_from_bits(bits)``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

from ..errors import ChannelError


HEADER_SIZE = 80


class HeaderError(ChannelError):
    pass


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def header_hash(header80: bytes) -> bytes:
    """Return the 32-byte block hash (internal byte order)."""
    if len(header80) != HEADER_SIZE:
        raise HeaderError(f"header must be 80 bytes (got {len(header80)})")
    return double_sha256(header80)


def bits_to_target(bits: int) -> int:
    """Decode compact-target ("nBits") to integer target."""
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def hash_to_int(h: bytes) -> int:
    return int.from_bytes(h[::-1], "big")  # display byte order for comparison


@dataclass(frozen=True)
class Header:
    """Parsed block header with cached hash."""

    raw: bytes
    height: int
    cumulative_work: int

    @property
    def hash(self) -> bytes:
        return header_hash(self.raw)

    @property
    def version(self) -> int:
        return int.from_bytes(self.raw[0:4], "little", signed=True)

    @property
    def prev_hash(self) -> bytes:
        return self.raw[4:36]

    @property
    def merkle_root(self) -> bytes:
        return self.raw[36:68]

    @property
    def timestamp(self) -> int:
        return int.from_bytes(self.raw[68:72], "little")

    @property
    def bits(self) -> int:
        return int.from_bytes(self.raw[72:76], "little")

    @property
    def nonce(self) -> int:
        return int.from_bytes(self.raw[76:80], "little")


def build_raw_header(version: int, prev_hash: bytes, merkle_root: bytes,
                     timestamp: int, bits: int, nonce: int) -> bytes:
    """Serialise an 80-byte raw header from fields."""
    if len(prev_hash) != 32:
        raise HeaderError(f"prev_hash must be 32 bytes (got {len(prev_hash)})")
    if len(merkle_root) != 32:
        raise HeaderError(f"merkle_root must be 32 bytes (got {len(merkle_root)})")
    return (
        version.to_bytes(4, "little", signed=True) +
        prev_hash +
        merkle_root +
        (timestamp & 0xFFFFFFFF).to_bytes(4, "little") +
        (bits & 0xFFFFFFFF).to_bytes(4, "little") +
        (nonce & 0xFFFFFFFF).to_bytes(4, "little")
    )


# ---------------------------------------------------------------------------
# Header store
# ---------------------------------------------------------------------------


@dataclass
class HeaderStore:
    """In-memory header chain with longest-chain selection by cumulative work.

    Initialised with a single genesis header at height 0 with cumulative
    work equal to its per-header work.
    """

    by_hash: dict[bytes, Header] = field(default_factory=dict)
    tip_hash: bytes = b""

    @classmethod
    def with_genesis(cls, raw_genesis_header: bytes) -> "HeaderStore":
        store = cls()
        genesis_h = header_hash(raw_genesis_header)
        bits = int.from_bytes(raw_genesis_header[72:76], "little")
        work = _work_for_bits(bits)
        store.by_hash[genesis_h] = Header(
            raw=raw_genesis_header, height=0, cumulative_work=work,
        )
        store.tip_hash = genesis_h
        return store

    def height(self) -> int:
        return self.by_hash[self.tip_hash].height

    def tip(self) -> Header:
        return self.by_hash[self.tip_hash]

    def lookup(self, h: bytes) -> Optional[Header]:
        return self.by_hash.get(h)

    def connect(self, raw_header: bytes) -> Header:
        """Validate and connect ``raw_header`` to the store.

        Returns the connected :class:`Header`. Raises :class:`HeaderError`
        on PoW failure, missing parent, or duplicate.
        """
        if len(raw_header) != HEADER_SIZE:
            raise HeaderError("connect: header must be 80 bytes")
        h = header_hash(raw_header)
        if h in self.by_hash:
            return self.by_hash[h]  # idempotent
        prev = raw_header[4:36]
        parent = self.by_hash.get(prev)
        if parent is None:
            raise HeaderError(f"connect: parent {prev[::-1].hex()} not found")
        bits = int.from_bytes(raw_header[72:76], "little")
        target = bits_to_target(bits)
        if target <= 0:
            raise HeaderError(f"connect: target <= 0 from bits {bits:#x}")
        if hash_to_int(h) > target:
            raise HeaderError(
                f"connect: PoW failed (hash {h[::-1].hex()} > target {target:#x})"
            )
        work = _work_for_bits(bits)
        new_header = Header(
            raw=raw_header,
            height=parent.height + 1,
            cumulative_work=parent.cumulative_work + work,
        )
        self.by_hash[h] = new_header
        tip = self.by_hash[self.tip_hash]
        if new_header.cumulative_work > tip.cumulative_work:
            self.tip_hash = h
        return new_header

    def chain_from_tip(self, n: Optional[int] = None) -> list[Header]:
        """Walk back from tip; default returns the whole chain."""
        out: list[Header] = []
        h: Optional[Header] = self.tip()
        while h is not None:
            out.append(h)
            if h.height == 0 or (n is not None and len(out) >= n):
                break
            h = self.by_hash.get(h.prev_hash)
        return out

    def header_at_height(self, height: int) -> Optional[Header]:
        """Return the header on the longest chain at ``height``, or None."""
        if height < 0 or height > self.height():
            return None
        # Walk back from tip.
        h: Optional[Header] = self.tip()
        while h is not None:
            if h.height == height:
                return h
            h = self.by_hash.get(h.prev_hash)
        return None


# ---------------------------------------------------------------------------
# Per-header work (number of expected hashes ≈ 2^256 / (target+1))
# ---------------------------------------------------------------------------


def _work_for_bits(bits: int) -> int:
    target = bits_to_target(bits)
    if target <= 0:
        return 0
    return (1 << 256) // (target + 1)


__all__ = [
    "HEADER_SIZE",
    "HeaderError",
    "Header",
    "HeaderStore",
    "header_hash",
    "build_raw_header",
    "bits_to_target",
    "hash_to_int",
]
