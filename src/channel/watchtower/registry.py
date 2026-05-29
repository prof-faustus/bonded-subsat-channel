"""Watchtower registry: durable per-channel watch records.

Each record carries:
- the funding txid (the channel's identifier);
- the current-state transaction (a fully-signed Tx ready to broadcast);
- a forfeiture transaction (ready to broadcast against each offender's bond).

The tower holds **no key** that lets it move funds to itself; the records
are pre-signed by the channel's parties. This is the custody-free property
of §17.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from bitcoinx import Tx

from ..errors import ChannelError


class RegistryError(ChannelError):
    pass


@dataclass
class WatchRecord:
    """One channel's watch record.

    Attributes
    ----------
    channel_id
        Stable identifier; we use the funding txid.
    current_state_tx_hex
        Serialised current state tx. The version is implicit in its
        input sequences; the tower rebroadcasts this when a stale state
        is observed for this channel.
    forfeit_tx_hex_by_owner
        Map from offender bond owner index -> a pre-signed forfeit tx
        (one per possible offender).
    horizon
        Settlement horizon (block height) before which a contested
        broadcast must be overtaken.
    """

    channel_id: bytes
    current_state_tx_hex: str
    forfeit_tx_hex_by_owner: dict[int, str] = field(default_factory=dict)
    horizon: int = 0

    def current_state_tx(self) -> Tx:
        return Tx.from_hex(self.current_state_tx_hex)

    def forfeit_tx_for(self, owner: int) -> Tx:
        if owner not in self.forfeit_tx_hex_by_owner:
            raise RegistryError(f"no forfeit tx for owner {owner}")
        return Tx.from_hex(self.forfeit_tx_hex_by_owner[owner])


@dataclass
class Registry:
    """In-memory registry with optional file-backed persistence."""

    records: dict[bytes, WatchRecord] = field(default_factory=dict)
    path: Optional[Path] = None

    @classmethod
    def open(cls, path: str | Path | None = None) -> "Registry":
        r = cls(path=Path(path) if path else None)
        if r.path and r.path.exists():
            r._load()
        return r

    def register(self, record: WatchRecord) -> None:
        self.records[record.channel_id] = record
        self._save()

    def get(self, channel_id: bytes) -> Optional[WatchRecord]:
        return self.records.get(channel_id)

    def update(self, record: WatchRecord) -> None:
        self.records[record.channel_id] = record
        self._save()

    def all(self) -> Iterable[WatchRecord]:
        return list(self.records.values())

    def __len__(self) -> int:
        return len(self.records)

    # ----- persistence ------------------------------------------------------

    def _save(self) -> None:
        if not self.path:
            return
        data = {
            "records": [
                {
                    "channel_id": r.channel_id.hex(),
                    "current_state_tx_hex": r.current_state_tx_hex,
                    "forfeit_tx_hex_by_owner": {str(k): v for k, v in r.forfeit_tx_hex_by_owner.items()},
                    "horizon": r.horizon,
                }
                for r in self.records.values()
            ]
        }
        self.path.write_text(json.dumps(data, indent=2))

    def _load(self) -> None:
        if not self.path:
            return
        data = json.loads(self.path.read_text())
        for raw in data.get("records", []):
            rec = WatchRecord(
                channel_id=bytes.fromhex(raw["channel_id"]),
                current_state_tx_hex=raw["current_state_tx_hex"],
                forfeit_tx_hex_by_owner={int(k): v for k, v in raw["forfeit_tx_hex_by_owner"].items()},
                horizon=int(raw["horizon"]),
            )
            self.records[rec.channel_id] = rec


__all__ = ["WatchRecord", "Registry", "RegistryError"]
