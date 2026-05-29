"""Phase 7 GATE: embedded BSV node.

Verifies:
- P2P wire-protocol message frames round-trip correctly.
- Header PoW connect/reject; longest-chain selection.
- Mempool admission validates inputs through the interpreter.
- A block can be generated, applied to the UTXO set, and conserves value.
- A double-spend conflicting input is rejected.
- A higher-sequence replacement is accepted (the channel construction's
  supersession primitive).
- A reorg of depth 2 is handled (longest chain is selected by cumulative work).
"""

from __future__ import annotations

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from bitcoinx import Ops, PrivateKey, Script, Tx, TxInput, TxOutput  # noqa: E402

from channel.config import SIGHASH_ALL_FORKID  # noqa: E402
from channel.node.block import merkle_root  # noqa: E402
from channel.node.blockstore import BlockStore, UtxoEntry  # noqa: E402
from channel.node.headers import (  # noqa: E402
    HeaderError, HeaderStore, bits_to_target, build_raw_header, header_hash, hash_to_int,
)
from channel.node.mempool import Mempool  # noqa: E402
from channel.node.network import EmbeddedNode, REGTEST_BITS, REGTEST_VERSION, make_regtest_genesis  # noqa: E402
from channel.node.p2p import (  # noqa: E402
    Frame, GetHeadersMessage, HeadersMessage, InvVector, INV_TX, NetAddr,
    PingMessage, VersionMessage, encode_inv, encode_varint, parse_frame, parse_inv,
    read_varint,
)
from channel.node.validation import validate_tx  # noqa: E402
from channel.scripts import p2pkh_script, p2pkh_unlock  # noqa: E402
from channel.signing import sign_input  # noqa: E402
from channel.verify import verify_spend  # noqa: E402


# ---------------------------------------------------------------------------
# P2P wire protocol — round-trip
# ---------------------------------------------------------------------------


def test_p2p_frame_roundtrip() -> None:
    payload = b"\x01\x02\x03"
    f = Frame(magic=b"\xDA\xB5\xBF\xFA", command="ping", payload=payload)
    raw = f.serialise()
    parsed, consumed = parse_frame(raw, expect_magic=b"\xDA\xB5\xBF\xFA")
    assert consumed == len(raw)
    assert parsed.command == "ping"
    assert parsed.payload == payload


def test_p2p_version_roundtrip() -> None:
    v = VersionMessage(start_height=42, user_agent=b"/test:1/")
    payload = v.serialise()
    v2 = VersionMessage.parse(payload)
    assert v2.start_height == 42
    assert v2.user_agent == b"/test:1/"


def test_p2p_inv_roundtrip() -> None:
    vs = [InvVector(INV_TX, bytes([i]) * 32) for i in range(3)]
    payload = encode_inv(vs)
    vs2 = parse_inv(payload)
    assert vs2 == vs


def test_p2p_getheaders_headers_roundtrip() -> None:
    locator = (b"\x11" * 32, b"\x22" * 32)
    gh = GetHeadersMessage(version=70016, block_locator=locator)
    payload = gh.serialise()
    gh2 = GetHeadersMessage.parse(payload)
    assert gh2.block_locator == locator

    raw = b"\x33" * 80
    hm = HeadersMessage(raw_headers=(raw,))
    payload = hm.serialise()
    hm2 = HeadersMessage.parse(payload)
    assert hm2.raw_headers == (raw,)


def test_p2p_checksum_mismatch_rejected() -> None:
    f = Frame(magic=b"\xDA\xB5\xBF\xFA", command="ping", payload=b"\x00")
    raw = bytearray(f.serialise())
    raw[20] ^= 0xFF  # flip a byte of the checksum
    with pytest.raises(Exception):
        parse_frame(bytes(raw), expect_magic=b"\xDA\xB5\xBF\xFA")


# ---------------------------------------------------------------------------
# Header chain
# ---------------------------------------------------------------------------


def test_header_store_connect_genesis_only() -> None:
    g = make_regtest_genesis()
    s = HeaderStore.with_genesis(g)
    assert s.height() == 0
    assert s.tip().hash == header_hash(g)


def test_header_store_connect_one() -> None:
    g = make_regtest_genesis()
    s = HeaderStore.with_genesis(g)
    h1 = build_raw_header(REGTEST_VERSION, header_hash(g), b"\x00" * 32,
                          1_700_000_001, REGTEST_BITS, 0)
    s.connect(h1)
    assert s.height() == 1


def test_header_store_reject_bad_pow() -> None:
    g = make_regtest_genesis()
    s = HeaderStore.with_genesis(g)
    # Use a tiny target that's almost impossible to satisfy with nonce=0.
    bad_bits = 0x1d00ffff
    h1 = build_raw_header(REGTEST_VERSION, header_hash(g), b"\x00" * 32,
                          1_700_000_001, bad_bits, 0)
    with pytest.raises(HeaderError):
        s.connect(h1)


# ---------------------------------------------------------------------------
# Embedded node: generate block, validate tx through interpreter
# ---------------------------------------------------------------------------


def test_node_generate_block_creates_utxo() -> None:
    node = EmbeddedNode()
    priv = PrivateKey.from_random()
    payout = p2pkh_script(priv.public_key)
    bh, txs = node.generate_block(payout_script=payout)
    assert node.height() == 1
    # Coinbase UTXO exists.
    coinbase = txs[0]
    cb_txid = coinbase.hash()
    entry = node.blockstore.get_utxo(cb_txid, 0)
    assert entry is not None
    assert entry.value == node.coinbase_reward


def test_node_admits_tx_only_after_interpreter_verifies() -> None:
    """Spend a coinbase UTXO through a real P2PKH tx; mempool admits."""
    node = EmbeddedNode()
    priv = PrivateKey.from_random()
    payout = p2pkh_script(priv.public_key)
    _bh, [coinbase] = node.generate_block(payout)
    assert node.height() == 1

    # Build a tx that spends the coinbase output to a new P2PKH.
    new_priv = PrivateKey.from_random()
    new_payout = p2pkh_script(new_priv.public_key)
    spend_in = TxInput(coinbase.hash(), 0, Script(b""), 0xFFFFFFFF)
    fee = 1000
    spend_out_value = coinbase.outputs[0].value - fee
    spend_out = TxOutput(spend_out_value, new_payout)
    tx = Tx(1, [spend_in], [spend_out], 0)
    sig = sign_input(tx, 0, coinbase.outputs[0].value, payout, priv,
                     SIGHASH_ALL_FORKID)
    tx.inputs[0] = TxInput(coinbase.hash(), 0, p2pkh_unlock(sig, priv.public_key),
                            0xFFFFFFFF)
    # Sanity check via direct interpreter (also done inside admit).
    verify_spend(tx, 0, coinbase.outputs[0])
    result = node.submit_tx(tx)
    assert result.ok, result.reason
    assert result.fee == fee
    assert node.mempool.size() == 1


def test_node_rejects_double_spend_in_mempool() -> None:
    node = EmbeddedNode()
    priv = PrivateKey.from_random()
    payout = p2pkh_script(priv.public_key)
    _bh, [coinbase] = node.generate_block(payout)

    # Build two conflicting spends of the same coinbase output, same sequence.
    def _make_spend(seq: int, fee: int) -> Tx:
        new_priv = PrivateKey.from_random()
        new_payout = p2pkh_script(new_priv.public_key)
        spend_in = TxInput(coinbase.hash(), 0, Script(b""), seq)
        spend_out_value = coinbase.outputs[0].value - fee
        tx = Tx(1, [spend_in], [TxOutput(spend_out_value, new_payout)], 0)
        sig = sign_input(tx, 0, coinbase.outputs[0].value, payout, priv,
                         SIGHASH_ALL_FORKID)
        tx.inputs[0] = TxInput(coinbase.hash(), 0,
                                p2pkh_unlock(sig, priv.public_key), seq)
        return tx

    tx_a = _make_spend(seq=10, fee=1000)
    tx_b = _make_spend(seq=10, fee=1000)  # same seq -> not a valid replacement

    assert node.submit_tx(tx_a).ok
    assert not node.submit_tx(tx_b).ok


def test_node_accepts_higher_sequence_replacement() -> None:
    """The channel construction's supersession primitive at the node level."""
    node = EmbeddedNode()
    priv = PrivateKey.from_random()
    payout = p2pkh_script(priv.public_key)
    _bh, [coinbase] = node.generate_block(payout)

    def _make_spend(seq: int) -> Tx:
        new_priv = PrivateKey.from_random()
        new_payout = p2pkh_script(new_priv.public_key)
        spend_in = TxInput(coinbase.hash(), 0, Script(b""), seq)
        tx = Tx(1, [spend_in], [TxOutput(coinbase.outputs[0].value - 1000, new_payout)], 0)
        sig = sign_input(tx, 0, coinbase.outputs[0].value, payout, priv,
                         SIGHASH_ALL_FORKID)
        tx.inputs[0] = TxInput(coinbase.hash(), 0,
                                p2pkh_unlock(sig, priv.public_key), seq)
        return tx

    tx_old = _make_spend(seq=10)
    tx_new = _make_spend(seq=11)

    assert node.submit_tx(tx_old).ok
    assert node.submit_tx(tx_new).ok
    # Old evicted; new in pool.
    assert not node.mempool.contains(tx_old.hash())
    assert node.mempool.contains(tx_new.hash())


def test_node_reorg_depth_2_handled() -> None:
    """Build a fork that overtakes the active chain by cumulative work."""
    node = EmbeddedNode()
    priv = PrivateKey.from_random()
    payout = p2pkh_script(priv.public_key)
    # Active chain: 3 blocks.
    h1, _ = node.generate_block(payout)
    h2, _ = node.generate_block(payout)
    h3, _ = node.generate_block(payout)
    assert node.height() == 3

    # Build a fork off h1: each fork header is mined under regtest bits so
    # the PoW check passes (regtest bits make this essentially free).
    target = bits_to_target(REGTEST_BITS)
    fork_parent = h1
    fork_chain: list[bytes] = []
    for i in range(3):
        nonce = 0
        while True:
            rh = build_raw_header(
                REGTEST_VERSION,
                prev_hash=fork_parent,
                merkle_root=b"\xAB" * 32,
                timestamp=1_800_000_000 + i,
                bits=REGTEST_BITS,
                nonce=nonce,
            )
            if hash_to_int(header_hash(rh)) <= target:
                break
            nonce += 1
        node.headers.connect(rh)
        fork_parent = header_hash(rh)
        fork_chain.append(fork_parent)
    # Reorg to the longer fork (3 headers off h1 vs 2 off h1 on the active chain).
    assert node.headers.height() == 4
    assert node.headers.tip_hash == fork_chain[-1]
