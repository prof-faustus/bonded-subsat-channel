"""Block and UTXO storage with a pluggable backend.

Defaults to a SQLite-backed store (Python's stdlib ``sqlite3``). The schema
is intentionally simple: one table of headers (by hash), one table of raw
serialised blocks (by hash), and one table of unspent outputs keyed by
``(txid, vout)``. UTXO entries carry the satoshi value and the
locking-script bytes so they can be passed straight to the interpreter.

The store is in-memory by default (URI ``:memory:``); pass a file path to
persist. Atomic writes are achieved by SQLite's transaction discipline.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional

from bitcoinx import Script, Tx, TxOutput

from ..errors import ChannelError


class BlockStoreError(ChannelError):
    pass


@dataclass(frozen=True)
class UtxoEntry:
    """A single unspent output: where it came from and what it locks."""

    txid: bytes
    vout: int
    value: int
    script_pubkey: bytes
    height: int  # height of the block containing the tx (-1 for mempool)

    def as_txoutput(self) -> TxOutput:
        return TxOutput(self.value, Script(self.script_pubkey))


SCHEMA = """
CREATE TABLE IF NOT EXISTS headers (
    hash BLOB PRIMARY KEY,
    height INTEGER NOT NULL,
    raw BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS blocks (
    hash BLOB PRIMARY KEY,
    height INTEGER NOT NULL,
    raw BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS utxos (
    txid BLOB NOT NULL,
    vout INTEGER NOT NULL,
    value INTEGER NOT NULL,
    script_pubkey BLOB NOT NULL,
    height INTEGER NOT NULL,
    PRIMARY KEY (txid, vout)
);
CREATE INDEX IF NOT EXISTS utxos_script ON utxos(script_pubkey);
"""


class BlockStore:
    """SQLite-backed block/UTXO store."""

    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        # ``check_same_thread=False`` allows the daemon's request threads
        # to invoke node operations without spawning a per-thread
        # connection; we serialise writes via :attr:`_lock`.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        import threading as _threading
        self._lock = _threading.RLock()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # ----- blocks -----------------------------------------------------------

    def store_block(self, block_hash: bytes, height: int, raw_block: bytes) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT OR REPLACE INTO blocks(hash, height, raw) VALUES (?, ?, ?)",
                (block_hash, height, raw_block),
            )

    def get_block(self, block_hash: bytes) -> Optional[bytes]:
        with self._lock:
            cur = self._conn.execute("SELECT raw FROM blocks WHERE hash = ?", (block_hash,))
            row = cur.fetchone()
            return bytes(row[0]) if row else None

    def block_height(self, block_hash: bytes) -> Optional[int]:
        with self._lock:
            cur = self._conn.execute("SELECT height FROM blocks WHERE hash = ?", (block_hash,))
            row = cur.fetchone()
            return int(row[0]) if row else None

    # ----- UTXO set ---------------------------------------------------------

    def add_utxo(self, entry: UtxoEntry) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT OR REPLACE INTO utxos(txid, vout, value, script_pubkey, height) "
                "VALUES (?, ?, ?, ?, ?)",
                (entry.txid, entry.vout, entry.value, entry.script_pubkey, entry.height),
            )

    def spend_utxo(self, txid: bytes, vout: int) -> Optional[UtxoEntry]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT value, script_pubkey, height FROM utxos WHERE txid = ? AND vout = ?",
                (txid, vout),
            )
            row = cur.fetchone()
            if not row:
                return None
            entry = UtxoEntry(
                txid=txid, vout=vout, value=int(row[0]),
                script_pubkey=bytes(row[1]), height=int(row[2]),
            )
            self._conn.execute("DELETE FROM utxos WHERE txid = ? AND vout = ?", (txid, vout))
            self._conn.commit()
            return entry

    def get_utxo(self, txid: bytes, vout: int) -> Optional[UtxoEntry]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT value, script_pubkey, height FROM utxos WHERE txid = ? AND vout = ?",
                (txid, vout),
            )
            row = cur.fetchone()
            if not row:
                return None
            return UtxoEntry(
                txid=txid, vout=vout, value=int(row[0]),
                script_pubkey=bytes(row[1]), height=int(row[2]),
            )

    def utxos_for_script(self, script_pubkey: bytes) -> list[UtxoEntry]:
        """Return all UTXOs locked by ``script_pubkey`` (for wallet scans)."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT txid, vout, value, height FROM utxos WHERE script_pubkey = ?",
                (script_pubkey,),
            )
            out: list[UtxoEntry] = []
            for row in cur.fetchall():
                out.append(UtxoEntry(
                    txid=bytes(row[0]), vout=int(row[1]), value=int(row[2]),
                    script_pubkey=script_pubkey, height=int(row[3]),
                ))
            return out

    def utxo_count(self) -> int:
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM utxos")
            return int(cur.fetchone()[0])

    # ----- connect / disconnect block -----------------------------------------

    def connect_block_utxos(self, height: int, txs: list[Tx]) -> None:
        """Apply a block's tx outputs to the UTXO set and remove its inputs.

        Spending the inputs is conditional on the input not being from a
        coinbase or a prior tx in the same block; here we treat the block
        as a single atomic group: spend inputs first, then add outputs.
        """
        with self.transaction() as c:
            for tx in txs:
                txid = tx.hash()
                if not tx.is_coinbase():
                    for tin in tx.inputs:
                        c.execute(
                            "DELETE FROM utxos WHERE txid = ? AND vout = ?",
                            (bytes(tin.prev_hash), int(tin.prev_idx)),
                        )
                for i, tout in enumerate(tx.outputs):
                    c.execute(
                        "INSERT OR REPLACE INTO utxos(txid, vout, value, script_pubkey, height) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (txid, i, int(tout.value), bytes(tout.script_pubkey), height),
                    )

    def disconnect_block_utxos(self, height: int, txs: list[Tx],
                                spent_inputs: dict[tuple[bytes, int], UtxoEntry]) -> None:
        """Reverse a block: re-add spent inputs, remove its outputs.

        ``spent_inputs`` records the UTXO entries consumed by the block's
        non-coinbase inputs (needed because the spend deleted them).
        """
        with self.transaction() as c:
            for tx in txs:
                txid = tx.hash()
                for i in range(len(tx.outputs)):
                    c.execute(
                        "DELETE FROM utxos WHERE txid = ? AND vout = ?",
                        (txid, i),
                    )
            for (ptxid, pvout), entry in spent_inputs.items():
                c.execute(
                    "INSERT OR REPLACE INTO utxos(txid, vout, value, script_pubkey, height) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (ptxid, pvout, entry.value, entry.script_pubkey, entry.height),
                )


__all__ = ["BlockStore", "UtxoEntry", "BlockStoreError"]
