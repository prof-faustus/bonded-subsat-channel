"""BSV peer-to-peer wire protocol — message framing and core message types.

Frame layout:

    magic    (4 bytes, little-endian)
    command  (12 bytes, NUL-padded ASCII)
    length   (4 bytes, little-endian uint32: payload length)
    checksum (4 bytes: first 4 bytes of double-SHA256 of payload)
    payload  (length bytes)

Supported commands (the minimum sufficient to drive an embedded regtest
node and satisfy the spec):

    version, verack, ping, pong,
    addr, getaddr,
    inv, getdata, notfound,
    tx, block, headers, getheaders, mempool.

The implementation is **wire-protocol native**: no HTTP, no REST, no
mAPI, no ARC. The framing and serialisation are exactly the original
Bitcoin/BSV protocol bytes.
"""

from __future__ import annotations

import hashlib
import io
import struct
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..errors import ChannelError


PROTOCOL_VERSION = 70016
SERVICES_NONE = 0
USER_AGENT = b"/channel-ref:0.1/"
MAX_MESSAGE_SIZE = 32 * 1024 * 1024  # generous; regtest only locally
HEADER_SIZE = 24


class P2PError(ChannelError):
    """Wire-protocol decode/encode failures."""


# ---------------------------------------------------------------------------
# Hash helpers (double-SHA256 = "Hash" in Satoshi notation)
# ---------------------------------------------------------------------------


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# ---------------------------------------------------------------------------
# varint, var_str, var_bytes
# ---------------------------------------------------------------------------


def encode_varint(n: int) -> bytes:
    if n < 0:
        raise P2PError(f"varint must be non-negative (got {n})")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xFD" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xFE" + n.to_bytes(4, "little")
    return b"\xFF" + n.to_bytes(8, "little")


def read_varint(buf: io.BytesIO) -> int:
    b = buf.read(1)
    if not b:
        raise P2PError("EOF reading varint prefix")
    v = b[0]
    if v < 0xFD:
        return v
    if v == 0xFD:
        data = buf.read(2)
        if len(data) != 2:
            raise P2PError("short varint(2)")
        return int.from_bytes(data, "little")
    if v == 0xFE:
        data = buf.read(4)
        if len(data) != 4:
            raise P2PError("short varint(4)")
        return int.from_bytes(data, "little")
    data = buf.read(8)
    if len(data) != 8:
        raise P2PError("short varint(8)")
    return int.from_bytes(data, "little")


def encode_var_bytes(b: bytes) -> bytes:
    return encode_varint(len(b)) + b


def read_var_bytes(buf: io.BytesIO, cap: int = MAX_MESSAGE_SIZE) -> bytes:
    n = read_varint(buf)
    if n > cap:
        raise P2PError(f"var_bytes length {n} exceeds cap {cap}")
    data = buf.read(n)
    if len(data) != n:
        raise P2PError(f"short var_bytes (wanted {n}, got {len(data)})")
    return data


# ---------------------------------------------------------------------------
# Message frame
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Frame:
    """A framed P2P message: magic, command, payload."""

    magic: bytes
    command: str
    payload: bytes

    def serialise(self) -> bytes:
        cmd_bytes = self.command.encode("ascii")
        if len(cmd_bytes) > 12:
            raise P2PError(f"command {self.command!r} > 12 bytes")
        cmd_padded = cmd_bytes + b"\x00" * (12 - len(cmd_bytes))
        length = len(self.payload).to_bytes(4, "little")
        checksum = double_sha256(self.payload)[:4]
        return self.magic + cmd_padded + length + checksum + self.payload


def parse_frame(data: bytes, expect_magic: Optional[bytes] = None) -> tuple[Frame, int]:
    """Parse one frame from ``data``; return (frame, bytes_consumed).

    Raises :class:`P2PError` on framing errors. If ``data`` is incomplete,
    raises :class:`P2PError` with the prefix ``'incomplete frame'``.
    """
    if len(data) < HEADER_SIZE:
        raise P2PError("incomplete frame: header")
    magic = data[:4]
    if expect_magic is not None and magic != expect_magic:
        raise P2PError(f"magic mismatch: got {magic.hex()}, expected {expect_magic.hex()}")
    command = data[4:16].rstrip(b"\x00").decode("ascii", errors="replace")
    length = int.from_bytes(data[16:20], "little")
    if length > MAX_MESSAGE_SIZE:
        raise P2PError(f"message length {length} > MAX_MESSAGE_SIZE")
    expected_checksum = data[20:24]
    end = HEADER_SIZE + length
    if len(data) < end:
        raise P2PError("incomplete frame: payload")
    payload = data[HEADER_SIZE:end]
    actual_checksum = double_sha256(payload)[:4]
    if actual_checksum != expected_checksum:
        raise P2PError("frame checksum mismatch")
    return Frame(magic=magic, command=command, payload=payload), end


# ---------------------------------------------------------------------------
# net_addr (used inside version / addr)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NetAddr:
    services: int = SERVICES_NONE
    ip: bytes = b"\x00" * 16  # IPv6 (IPv4 via ::ffff:0:0 prefix in real net)
    port: int = 0

    def serialise(self, include_time: bool = False, timestamp: int | None = None) -> bytes:
        out = b""
        if include_time:
            ts = timestamp if timestamp is not None else int(time.time())
            out += ts.to_bytes(4, "little")
        out += self.services.to_bytes(8, "little")
        out += (self.ip + b"\x00" * 16)[:16]
        out += self.port.to_bytes(2, "big")
        return out

    @classmethod
    def parse(cls, buf: io.BytesIO, include_time: bool = False) -> "NetAddr":
        if include_time:
            ts_bytes = buf.read(4)
            if len(ts_bytes) != 4:
                raise P2PError("short NetAddr.timestamp")
        services = int.from_bytes(buf.read(8), "little")
        ip = buf.read(16)
        if len(ip) != 16:
            raise P2PError("short NetAddr.ip")
        port = int.from_bytes(buf.read(2), "big")
        return cls(services=services, ip=ip, port=port)


# ---------------------------------------------------------------------------
# Concrete messages
# ---------------------------------------------------------------------------


@dataclass
class VersionMessage:
    version: int = PROTOCOL_VERSION
    services: int = SERVICES_NONE
    timestamp: int = field(default_factory=lambda: int(time.time()))
    addr_recv: NetAddr = field(default_factory=NetAddr)
    addr_from: NetAddr = field(default_factory=NetAddr)
    nonce: int = 0
    user_agent: bytes = USER_AGENT
    start_height: int = 0
    relay: bool = True

    def serialise(self) -> bytes:
        out = b""
        out += self.version.to_bytes(4, "little", signed=True)
        out += self.services.to_bytes(8, "little")
        out += self.timestamp.to_bytes(8, "little", signed=True)
        out += self.addr_recv.serialise()
        out += self.addr_from.serialise()
        out += self.nonce.to_bytes(8, "little")
        out += encode_var_bytes(self.user_agent)
        out += self.start_height.to_bytes(4, "little", signed=True)
        out += b"\x01" if self.relay else b"\x00"
        return out

    @classmethod
    def parse(cls, payload: bytes) -> "VersionMessage":
        buf = io.BytesIO(payload)
        version = int.from_bytes(buf.read(4), "little", signed=True)
        services = int.from_bytes(buf.read(8), "little")
        timestamp = int.from_bytes(buf.read(8), "little", signed=True)
        addr_recv = NetAddr.parse(buf)
        addr_from = NetAddr.parse(buf)
        nonce = int.from_bytes(buf.read(8), "little")
        user_agent = read_var_bytes(buf)
        start_height = int.from_bytes(buf.read(4), "little", signed=True)
        relay_byte = buf.read(1)
        relay = bool(relay_byte and relay_byte[0])
        return cls(version=version, services=services, timestamp=timestamp,
                   addr_recv=addr_recv, addr_from=addr_from, nonce=nonce,
                   user_agent=user_agent, start_height=start_height,
                   relay=relay)


@dataclass(frozen=True)
class InvVector:
    """``(type, hash)`` inventory entry. Type 1 = tx, 2 = block."""

    inv_type: int
    hash: bytes  # 32 bytes (internal byte order)

    def serialise(self) -> bytes:
        if len(self.hash) != 32:
            raise P2PError(f"InvVector.hash must be 32 bytes (got {len(self.hash)})")
        return self.inv_type.to_bytes(4, "little") + self.hash

    @classmethod
    def parse(cls, buf: io.BytesIO) -> "InvVector":
        t = int.from_bytes(buf.read(4), "little")
        h = buf.read(32)
        if len(h) != 32:
            raise P2PError("short InvVector.hash")
        return cls(inv_type=t, hash=h)


INV_TX = 1
INV_BLOCK = 2


def encode_inv(vectors: Iterable[InvVector]) -> bytes:
    items = list(vectors)
    out = encode_varint(len(items))
    for v in items:
        out += v.serialise()
    return out


def parse_inv(payload: bytes) -> list[InvVector]:
    buf = io.BytesIO(payload)
    n = read_varint(buf)
    return [InvVector.parse(buf) for _ in range(n)]


@dataclass(frozen=True)
class GetHeadersMessage:
    """Request headers between block_locator and hash_stop (32-byte zero = end)."""

    version: int
    block_locator: tuple[bytes, ...]
    hash_stop: bytes = b"\x00" * 32

    def serialise(self) -> bytes:
        out = self.version.to_bytes(4, "little")
        out += encode_varint(len(self.block_locator))
        for h in self.block_locator:
            if len(h) != 32:
                raise P2PError("locator hash must be 32 bytes")
            out += h
        if len(self.hash_stop) != 32:
            raise P2PError("hash_stop must be 32 bytes")
        out += self.hash_stop
        return out

    @classmethod
    def parse(cls, payload: bytes) -> "GetHeadersMessage":
        buf = io.BytesIO(payload)
        version = int.from_bytes(buf.read(4), "little")
        n = read_varint(buf)
        locator = tuple(buf.read(32) for _ in range(n))
        for h in locator:
            if len(h) != 32:
                raise P2PError("short locator hash")
        hash_stop = buf.read(32)
        if len(hash_stop) != 32:
            raise P2PError("short hash_stop")
        return cls(version=version, block_locator=locator, hash_stop=hash_stop)


@dataclass(frozen=True)
class HeadersMessage:
    """Reply to getheaders: a list of 80-byte block headers (each with a trailing 0 tx count)."""

    raw_headers: tuple[bytes, ...]

    def serialise(self) -> bytes:
        out = encode_varint(len(self.raw_headers))
        for h in self.raw_headers:
            if len(h) != 80:
                raise P2PError(f"header must be 80 bytes (got {len(h)})")
            out += h + b"\x00"  # zero tx count
        return out

    @classmethod
    def parse(cls, payload: bytes) -> "HeadersMessage":
        buf = io.BytesIO(payload)
        n = read_varint(buf)
        headers: list[bytes] = []
        for _ in range(n):
            h = buf.read(80)
            if len(h) != 80:
                raise P2PError("short header")
            _tx_count = read_varint(buf)  # always 0 in headers messages
            headers.append(h)
        return cls(raw_headers=tuple(headers))


@dataclass(frozen=True)
class PingMessage:
    nonce: int = 0

    def serialise(self) -> bytes:
        return self.nonce.to_bytes(8, "little")

    @classmethod
    def parse(cls, payload: bytes) -> "PingMessage":
        if len(payload) < 8:
            raise P2PError("short ping payload")
        return cls(nonce=int.from_bytes(payload[:8], "little"))


__all__ = [
    "PROTOCOL_VERSION",
    "MAX_MESSAGE_SIZE",
    "P2PError",
    "Frame",
    "parse_frame",
    "double_sha256",
    "encode_varint",
    "read_varint",
    "encode_var_bytes",
    "read_var_bytes",
    "NetAddr",
    "VersionMessage",
    "InvVector",
    "INV_TX",
    "INV_BLOCK",
    "encode_inv",
    "parse_inv",
    "GetHeadersMessage",
    "HeadersMessage",
    "PingMessage",
]
