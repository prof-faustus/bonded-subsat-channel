"""Durable system store: wallet seed, channel states, bonds, tower registry.

This module owns the *system-wide* persistence: wallet seed (encrypted),
per-channel state history (every version), bond records, and watchtower
registry. The embedded node owns its own block/UTXO storage; see
:mod:`channel.node.blockstore`.

Backed by SQLite (Python stdlib) with WAL journal mode for atomic writes.
A crash mid-update never corrupts state because each ``commit()`` is
either fully applied or fully discarded.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from ..errors import ChannelError


class StoreError(ChannelError):
    pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS wallet (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    encrypted_seed BLOB
);
CREATE TABLE IF NOT EXISTS channel_states (
    channel_id BLOB NOT NULL,
    version INTEGER NOT NULL,
    state_json TEXT NOT NULL,
    PRIMARY KEY (channel_id, version)
);
CREATE TABLE IF NOT EXISTS channel_meta (
    channel_id BLOB PRIMARY KEY,
    cfg_json TEXT NOT NULL,
    keys_hex TEXT NOT NULL,
    funding_tx_hex TEXT NOT NULL,
    funding_confirmed INTEGER NOT NULL DEFAULT 0,
    parent_value INTEGER NOT NULL
);
"""


class SystemStore:
    """SQLite-backed system store."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        # ``check_same_thread=False`` lets multiple threads share the
        # connection; we serialise access via :attr:`_lock`. Without it,
        # SQLite rejects cross-thread use even when only one thread
        # writes at a time.
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
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

    # ----- wallet seed ------------------------------------------------------

    def put_wallet_seed(self, encrypted_seed: bytes) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT OR REPLACE INTO wallet(id, encrypted_seed) VALUES (1, ?)",
                (encrypted_seed,),
            )

    def get_wallet_seed(self) -> Optional[bytes]:
        cur = self._conn.execute("SELECT encrypted_seed FROM wallet WHERE id = 1")
        row = cur.fetchone()
        return bytes(row[0]) if row else None

    # ----- channel meta + states -------------------------------------------

    def put_channel_meta(self, channel_id: bytes, cfg_json: str, keys_hex: str,
                          funding_tx_hex: str, funding_confirmed: bool,
                          parent_value: int) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT OR REPLACE INTO channel_meta"
                " (channel_id, cfg_json, keys_hex, funding_tx_hex, "
                "funding_confirmed, parent_value)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (channel_id, cfg_json, keys_hex, funding_tx_hex,
                 int(funding_confirmed), parent_value),
            )

    def get_channel_meta(self, channel_id: bytes) -> Optional[dict[str, object]]:
        cur = self._conn.execute(
            "SELECT cfg_json, keys_hex, funding_tx_hex, funding_confirmed, parent_value "
            "FROM channel_meta WHERE channel_id = ?",
            (channel_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "cfg_json": row[0],
            "keys_hex": row[1],
            "funding_tx_hex": row[2],
            "funding_confirmed": bool(row[3]),
            "parent_value": int(row[4]),
        }

    def put_channel_state(self, channel_id: bytes, version: int,
                          state_json: str) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT OR REPLACE INTO channel_states(channel_id, version, state_json) "
                "VALUES (?, ?, ?)",
                (channel_id, version, state_json),
            )

    def get_latest_channel_state(self, channel_id: bytes) -> Optional[tuple[int, str]]:
        cur = self._conn.execute(
            "SELECT version, state_json FROM channel_states "
            "WHERE channel_id = ? ORDER BY version DESC LIMIT 1",
            (channel_id,),
        )
        row = cur.fetchone()
        return (int(row[0]), str(row[1])) if row else None

    def list_channels(self) -> list[bytes]:
        cur = self._conn.execute("SELECT channel_id FROM channel_meta")
        return [bytes(r[0]) for r in cur.fetchall()]


__all__ = ["SystemStore", "StoreError"]
