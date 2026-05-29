"""Embedded BSV node — regtest run mode.

The default mode is a **self-contained local regtest**: the node carries
its own header chain, UTXO store, and mempool, and can generate blocks
locally so the whole stack runs on one machine with zero external
infrastructure. Block generation uses regtest's permissive ``bits`` value
so PoW is satisfied trivially.

A separate ``connect`` mode (not enabled by default and not required for
any test) accepts a list of peer addresses to dial over the real wire
protocol (see :mod:`channel.node.p2p`); it is off by default.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence

from bitcoinx import Ops, Script, Tx, TxInput, TxOutput

from .block import merkle_root, serialise_block
from .blockstore import BlockStore, UtxoEntry
from .headers import HeaderError, HeaderStore, bits_to_target, build_raw_header, header_hash, hash_to_int
from .mempool import Mempool
from .p2p import double_sha256
from .validation import ValidationResult, validate_tx


_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Regtest parameters
# ---------------------------------------------------------------------------
#
# We use a bespoke regtest genesis (rather than the BSV mainnet/regtest
# genesis) so the embedded node has a complete on-disk-or-in-memory
# self-contained chain. The bits value (0x207fffff) gives a target of
# 2**224, which trivially admits any header.

REGTEST_BITS = 0x207FFFFF
REGTEST_VERSION = 1
REGTEST_GENESIS_PREV = b"\x00" * 32


def make_regtest_genesis(timestamp: int | None = None) -> bytes:
    """Build a deterministic regtest genesis header."""
    ts = timestamp if timestamp is not None else 1_700_000_000
    return build_raw_header(
        version=REGTEST_VERSION,
        prev_hash=REGTEST_GENESIS_PREV,
        merkle_root=b"\x00" * 32,
        timestamp=ts,
        bits=REGTEST_BITS,
        nonce=0,
    )


# ---------------------------------------------------------------------------
# Coinbase tx for generated blocks
# ---------------------------------------------------------------------------


def make_coinbase(payout_value: int, payout_script: Script,
                  height: int, extra: bytes = b"") -> Tx:
    """Build a coinbase tx paying ``payout_value`` to ``payout_script``.

    The scriptSig encodes the block height per BIP34 (minimal-push).
    """
    # Encode height as a script number.
    if height == 0:
        h_bytes: bytes = b""
    else:
        h_buf = bytearray()
        n = height
        while n:
            h_buf.append(n & 0xFF)
            n >>= 8
        if h_buf[-1] & 0x80:
            h_buf.append(0)
        h_bytes = bytes(h_buf)
    script_sig = Script() << h_bytes
    if extra:
        script_sig = script_sig << extra
    cb_in = TxInput(
        prev_hash=b"\x00" * 32,
        prev_idx=0xFFFFFFFF,
        script_sig=script_sig,
        sequence=0xFFFFFFFF,
    )
    cb_out = TxOutput(payout_value, payout_script)
    return Tx(1, [cb_in], [cb_out], 0)


# ---------------------------------------------------------------------------
# EmbeddedNode
# ---------------------------------------------------------------------------


@dataclass
class EmbeddedNode:
    """The whole node: headers, blockstore, mempool, observers.

    Run mode is regtest by default. The node does not attempt to dial
    network peers; all transactions enter via :meth:`submit_tx` and all
    blocks via :meth:`generate_block` (in regtest) or
    :meth:`accept_block` (when fed externally).
    """

    network_magic: bytes = b"\xDA\xB5\xBF\xFA"  # BSV regtest magic
    blockstore: BlockStore = field(default_factory=BlockStore)
    headers: HeaderStore = field(init=False)
    mempool: Mempool = field(init=False)
    genesis: bytes = field(init=False)
    coinbase_reward: int = 50_00_000_000  # 50 BSV in satoshis (regtest)

    def __post_init__(self) -> None:
        self.genesis = make_regtest_genesis()
        self.headers = HeaderStore.with_genesis(self.genesis)
        self.blockstore.store_block(header_hash(self.genesis), 0, self.genesis)
        self.mempool = Mempool(store=self.blockstore)

    # ----- public interface ----------------------------------------------

    def height(self) -> int:
        return self.headers.height()

    def tip_hash(self) -> bytes:
        return self.headers.tip_hash

    def submit_tx(self, tx: Tx) -> ValidationResult:
        """Admit a tx to the mempool (validated through the interpreter)."""
        return self.mempool.admit(tx)

    def generate_block(self, payout_script: Script,
                       include_mempool: bool = True,
                       extra_coinbase: bytes = b"") -> tuple[bytes, list[Tx]]:
        """Mine a single regtest block and apply it to the UTXO set.

        Returns ``(block_hash, [coinbase, ...included_mempool_txs])``.
        """
        tip = self.headers.tip()
        height = tip.height + 1
        coinbase_fee_total = 0
        included: list[Tx] = []
        if include_mempool:
            included = list(self.mempool.all_txs())
            for tx in included:
                # Recompute fee from the store's view.
                res = validate_tx(tx, self.blockstore)
                if res.ok:
                    coinbase_fee_total += res.fee
        coinbase = make_coinbase(
            payout_value=self.coinbase_reward + coinbase_fee_total,
            payout_script=payout_script,
            height=height,
            extra=extra_coinbase,
        )
        txs = [coinbase, *included]
        txids = [tx.hash() for tx in txs]
        m_root = merkle_root(txids)
        bits = REGTEST_BITS
        target = bits_to_target(bits)
        # Mine: find a nonce such that hash <= target. With the regtest
        # bits, nonce=0 is virtually always sufficient; we loop just in
        # case.
        nonce = 0
        timestamp = int(time.time())
        while True:
            raw_header = build_raw_header(
                version=REGTEST_VERSION,
                prev_hash=tip.hash,
                merkle_root=m_root,
                timestamp=timestamp,
                bits=bits,
                nonce=nonce,
            )
            h = header_hash(raw_header)
            if hash_to_int(h) <= target:
                break
            nonce += 1
            if nonce > 1_000_000:
                raise RuntimeError("regtest mine: nonce exhausted (shouldn't happen)")
        # Connect header.
        self.headers.connect(raw_header)
        # Apply to blockstore.
        self.blockstore.store_block(h, height, serialise_block(raw_header, txs))
        self.blockstore.connect_block_utxos(height, txs)
        # Evict mined transactions from mempool.
        for tx in included:
            self.mempool.evict(tx.hash())
        _log.info("regtest mined block height=%d txs=%d", height, len(txs))
        return h, txs

    def accept_block(self, raw_header: bytes, txs: list[Tx]) -> None:
        """Accept an externally-supplied (e.g. peer-relayed) block."""
        self.headers.connect(raw_header)
        height = self.headers.lookup(header_hash(raw_header)).height  # type: ignore[union-attr]
        h = header_hash(raw_header)
        self.blockstore.store_block(h, height, serialise_block(raw_header, txs))
        self.blockstore.connect_block_utxos(height, txs)
        for tx in txs:
            self.mempool.evict(tx.hash())


__all__ = [
    "EmbeddedNode",
    "make_regtest_genesis",
    "make_coinbase",
    "REGTEST_BITS",
    "REGTEST_VERSION",
]
