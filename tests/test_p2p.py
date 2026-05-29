"""G3 — P2P wire-protocol error-path tests.

A consumer-ready node must reject malformed peer messages cleanly rather
than propagate the error into state. Each test below feeds a malformed
byte stream into ``parse_frame`` (or the per-message parser) and asserts
the parser raises :class:`channel.node.p2p.P2PError` — never silently
accepts, never crashes a higher layer.
"""

from __future__ import annotations

import io
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from channel.node.p2p import (  # noqa: E402
    Frame, GetHeadersMessage, HeadersMessage, InvVector, NetAddr,
    P2PError, PingMessage, VersionMessage,
    double_sha256, encode_inv, encode_varint, parse_frame, parse_inv,
    read_var_bytes, read_varint,
)


MAGIC = b"\xDA\xB5\xBF\xFA"  # BSV regtest


# ---------------------------------------------------------------------------
# Framing errors
# ---------------------------------------------------------------------------


def test_p2p_bad_magic_is_rejected() -> None:
    """A frame with wrong magic must raise P2PError."""
    good = Frame(MAGIC, "ping", b"\x00" * 8).serialise()
    bad = bytearray(good)
    bad[0:4] = b"\xFF\xFF\xFF\xFF"  # corrupt the magic
    with pytest.raises(P2PError) as exc:
        parse_frame(bytes(bad), expect_magic=MAGIC)
    assert "magic" in str(exc.value).lower()


def test_p2p_bad_checksum_is_rejected() -> None:
    """A frame whose checksum doesn't match the payload must raise."""
    good = Frame(MAGIC, "ping", b"\x01" * 8).serialise()
    bad = bytearray(good)
    bad[20] ^= 0xFF  # flip a byte in the checksum
    with pytest.raises(P2PError) as exc:
        parse_frame(bytes(bad), expect_magic=MAGIC)
    assert "checksum" in str(exc.value).lower()


def test_p2p_oversized_length_field_is_rejected() -> None:
    """A length-prefix larger than MAX_MESSAGE_SIZE must raise.

    The 32-bit length field can encode up to ~4 GB; the parser caps at
    ``MAX_MESSAGE_SIZE`` (~32 MB) and must reject anything bigger.
    """
    payload = b"\x00" * 8
    bad = bytearray()
    bad += MAGIC
    bad += b"ping".ljust(12, b"\x00")
    bad += (0xFFFFFFFF).to_bytes(4, "little")  # 4 GB-1, well over the cap
    bad += double_sha256(payload)[:4]
    bad += payload
    with pytest.raises(P2PError) as exc:
        parse_frame(bytes(bad), expect_magic=MAGIC)
    msg = str(exc.value).lower()
    assert "max" in msg or "length" in msg


def test_p2p_truncated_header_is_rejected() -> None:
    """A buffer shorter than 24 bytes (header size) must raise."""
    with pytest.raises(P2PError) as exc:
        parse_frame(b"\xDA\xB5\xBF\xFA" + b"ping".ljust(8, b"\x00"),
                    expect_magic=MAGIC)
    assert "incomplete" in str(exc.value).lower()


def test_p2p_truncated_payload_is_rejected() -> None:
    """A frame whose payload doesn't match the declared length must raise."""
    payload = b"\x01" * 16
    raw = Frame(MAGIC, "ping", payload).serialise()
    truncated = raw[:-4]  # drop last 4 payload bytes
    with pytest.raises(P2PError) as exc:
        parse_frame(truncated, expect_magic=MAGIC)
    assert "incomplete" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# varint / var_bytes errors
# ---------------------------------------------------------------------------


def test_p2p_varint_eof_at_prefix() -> None:
    with pytest.raises(P2PError):
        read_varint(io.BytesIO(b""))


def test_p2p_varint_short_8_byte_form() -> None:
    """An 0xFF prefix promises 8 bytes; provide only 3."""
    with pytest.raises(P2PError):
        read_varint(io.BytesIO(b"\xFF\x01\x02\x03"))


def test_p2p_var_bytes_cap_enforced() -> None:
    """A var_bytes claiming more than cap must raise."""
    # Construct a buffer with a varint of 1_000_000 then nothing.
    buf = io.BytesIO(b"\xFE" + (1_000_000).to_bytes(4, "little"))
    with pytest.raises(P2PError):
        read_var_bytes(buf, cap=100)


# ---------------------------------------------------------------------------
# Per-message parsers
# ---------------------------------------------------------------------------


def test_p2p_getheaders_short_locator_hash_rejected() -> None:
    """A getheaders payload claiming N hashes but missing bytes must raise."""
    # version (4) + varint(1) + only 5 bytes of a 32-byte hash + hash_stop(32)
    payload = (
        (70016).to_bytes(4, "little")
        + b"\x01"
        + b"\xAA" * 5  # truncated locator hash
        + b"\x00" * 32
    )
    with pytest.raises(P2PError):
        GetHeadersMessage.parse(payload)


def test_p2p_headers_short_header_rejected() -> None:
    """A headers payload claiming N headers but missing bytes must raise."""
    payload = b"\x01" + b"\xAA" * 40  # 1 header but only 40 of 80 bytes
    with pytest.raises(P2PError):
        HeadersMessage.parse(payload)


def test_p2p_inv_invalid_hash_length_rejected() -> None:
    """A truncated inv vector must raise during parse."""
    payload = b"\x01" + b"\x01\x00\x00\x00" + b"\xBB" * 10  # only 10 of 32
    with pytest.raises(P2PError):
        parse_inv(payload)


def test_p2p_inv_vector_serialise_validates_hash_length() -> None:
    with pytest.raises(P2PError):
        InvVector(1, b"\x00" * 10).serialise()


def test_p2p_ping_payload_too_short_rejected() -> None:
    with pytest.raises(P2PError):
        PingMessage.parse(b"\x00" * 4)


# ---------------------------------------------------------------------------
# Stateful: a bad frame does not corrupt subsequent parses
# ---------------------------------------------------------------------------


def test_p2p_bad_frame_does_not_corrupt_subsequent_parse() -> None:
    """After a P2PError on one frame, a fresh well-formed frame still parses."""
    good = Frame(MAGIC, "ping", b"\x00" * 8).serialise()
    bad = bytearray(good)
    bad[20] ^= 0xFF  # bad checksum on the first frame
    # Reject the bad one.
    with pytest.raises(P2PError):
        parse_frame(bytes(bad), expect_magic=MAGIC)
    # The parser holds no state; a fresh good frame parses cleanly.
    f, consumed = parse_frame(good, expect_magic=MAGIC)
    assert f.command == "ping"
    assert consumed == len(good)
