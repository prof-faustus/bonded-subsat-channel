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

from .block import merkle_root, parse_block, serialise_block
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

    Reorg handling. Each connected block records, in :attr:`undo_log`,
    the UTXOs it consumed (so they can be re-added on disconnect). When
    :meth:`accept_block` connects a header that shifts the longest chain
    onto a fork, the node first disconnects blocks back to the common
    ancestor (replaying the undo log in reverse) and then connects each
    block of the new chain in order. The UTXO set after the reorg is
    therefore exactly what a fresh ingest of the heavier chain would
    produce, which is the invariant the spec calls for.
    """

    network_magic: bytes = b"\xDA\xB5\xBF\xFA"  # BSV regtest magic
    blockstore: BlockStore = field(default_factory=BlockStore)
    headers: HeaderStore = field(init=False)
    mempool: Mempool = field(init=False)
    genesis: bytes = field(init=False)
    coinbase_reward: int = 50_00_000_000  # 50 BSV in satoshis (regtest)
    # block_hash -> list of (txid, vout, value, script, height) entries
    # for outputs spent when this block was connected.
    undo_log: dict[bytes, list[tuple[bytes, int, int, bytes, int]]] = field(default_factory=dict)
    # block_hash -> list of (txid, vout) entries created by the block,
    # so a disconnect can remove them precisely (covers coinbase too).
    created_log: dict[bytes, list[tuple[bytes, int]]] = field(default_factory=dict)

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
        # Apply to blockstore (records undo data).
        self.blockstore.store_block(h, height, serialise_block(raw_header, txs))
        self._connect_block_with_undo(h, height, txs)
        # Evict mined transactions from mempool.
        for tx in included:
            self.mempool.evict(tx.hash())
        _log.info("regtest mined block height=%d txs=%d", height, len(txs))
        return h, txs

    def accept_block(self, raw_header: bytes, txs: list[Tx]) -> None:
        """Accept an externally-supplied block; reorg the UTXO set if needed."""
        prev_tip = self.headers.tip_hash
        self.headers.connect(raw_header)
        h = header_hash(raw_header)
        new_tip = self.headers.tip_hash
        height = self.headers.lookup(h).height  # type: ignore[union-attr]
        self.blockstore.store_block(h, height, serialise_block(raw_header, txs))
        if new_tip == h and prev_tip != self.headers.lookup(h).prev_hash:  # type: ignore[union-attr]
            # The new block extended a fork that has overtaken the active
            # chain. Reorganise the UTXO set onto the new chain.
            self._reorg_utxos(from_tip=prev_tip, to_tip=new_tip)
        elif new_tip == h:
            # Direct extension of the active chain.
            self._connect_block_with_undo(h, height, txs)
            for tx in txs:
                self.mempool.evict(tx.hash())
        # Otherwise the new block is on a stale fork; headers store it
        # but we don't touch the UTXO set.

    # ------------------------------------------------------------------ #
    # Reorg machinery
    # ------------------------------------------------------------------ #

    def _connect_block_with_undo(self, block_hash: bytes, height: int,
                                  txs: list[Tx]) -> None:
        """Apply a block to the UTXO set; record undo data."""
        undo: list[tuple[bytes, int, int, bytes, int]] = []
        created: list[tuple[bytes, int]] = []
        for tx in txs:
            txid = tx.hash()
            if not tx.is_coinbase():
                for tin in tx.inputs:
                    entry = self.blockstore.get_utxo(bytes(tin.prev_hash), int(tin.prev_idx))
                    if entry is not None:
                        undo.append((entry.txid, entry.vout, entry.value,
                                     entry.script_pubkey, entry.height))
            for i in range(len(tx.outputs)):
                created.append((txid, i))
        self.blockstore.connect_block_utxos(height, txs)
        self.undo_log[block_hash] = undo
        self.created_log[block_hash] = created

    def _disconnect_block(self, block_hash: bytes) -> None:
        """Reverse a block's effect on the UTXO set using the undo log."""
        # Remove outputs the block created.
        for txid, vout in self.created_log.get(block_hash, []):
            existing = self.blockstore.get_utxo(txid, vout)
            if existing is not None:
                # spend_utxo removes the entry.
                self.blockstore.spend_utxo(txid, vout)
        # Re-add inputs the block had consumed.
        for txid, vout, value, script, h in self.undo_log.get(block_hash, []):
            self.blockstore.add_utxo(UtxoEntry(
                txid=txid, vout=vout, value=value,
                script_pubkey=script, height=h,
            ))
        # Forget the undo data; the block is no longer connected.
        self.undo_log.pop(block_hash, None)
        self.created_log.pop(block_hash, None)

    def _reorg_utxos(self, from_tip: bytes, to_tip: bytes) -> None:
        """Disconnect blocks back to common ancestor; connect the new chain."""
        # Walk back from each tip until the chains meet.
        def path_to(h: bytes) -> list[bytes]:
            out: list[bytes] = []
            cur = self.headers.lookup(h)
            while cur is not None and cur.height > 0:
                out.append(cur.hash)
                cur = self.headers.lookup(cur.prev_hash)
            out.append(self.headers.lookup(self.genesis_hash()).hash)  # type: ignore[union-attr]
            return out

        old_path = path_to(from_tip)
        new_path = path_to(to_tip)
        old_set = set(old_path)
        # Find the first shared ancestor on the new path.
        ancestor: Optional[bytes] = None
        for h in new_path:
            if h in old_set:
                ancestor = h
                break
        if ancestor is None:
            raise RuntimeError("reorg: no common ancestor (corrupt header chain)")
        # Disconnect from old_tip back to (but not including) ancestor.
        for h in old_path:
            if h == ancestor:
                break
            self._disconnect_block(h)
        # Connect from ancestor (exclusive) up to new_tip in order.
        new_chain_to_connect = []
        for h in new_path:
            if h == ancestor:
                break
            new_chain_to_connect.append(h)
        new_chain_to_connect.reverse()
        for h in new_chain_to_connect:
            raw_block = self.blockstore.get_block(h)
            if raw_block is None:
                raise RuntimeError(
                    f"reorg: block {h[::-1].hex()} not in blockstore"
                )
            _hdr, txs = parse_block(raw_block)
            height_h = self.headers.lookup(h).height  # type: ignore[union-attr]
            self._connect_block_with_undo(h, height_h, txs)
            for tx in txs:
                self.mempool.evict(tx.hash())
        _log.info("reorg: disconnected %d blocks, connected %d blocks",
                   len(old_path) - new_path.index(ancestor),
                   len(new_chain_to_connect))

    def genesis_hash(self) -> bytes:
        return header_hash(self.genesis)


__all__ = [
    "EmbeddedNode",
    "make_regtest_genesis",
    "make_coinbase",
    "REGTEST_BITS",
    "REGTEST_VERSION",
]
