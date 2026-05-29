"""Per-channel locking and the multi-channel manager.

A ``ChannelManager`` holds a set of :class:`Channel` instances keyed by
funding txid; each channel has its own :class:`threading.RLock`. Updates
to a channel are serialised by its lock; independent channels proceed in
parallel. This is sufficient for the concurrency guarantees stated in
§18: many channels in parallel; per-channel state updates serialised;
a close uses the latest committed state, and any in-flight transfer
either commits before the close or is rejected.
"""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

from ..errors import ChannelError, StateError
from ..lifecycle import Channel
from ..store.recover import persist_channel
from ..store.store import SystemStore


_log = logging.getLogger(__name__)


class ManagerError(ChannelError):
    pass


@dataclass
class ChannelManager:
    """A registry of channels with per-channel locking and durable persistence."""

    store: SystemStore
    channels: dict[bytes, Channel] = field(default_factory=dict)
    _locks: dict[bytes, threading.RLock] = field(default_factory=dict)
    _registry_lock: threading.Lock = field(default_factory=threading.Lock)
    closed_channels: set[bytes] = field(default_factory=set)

    def add(self, ch: Channel) -> bytes:
        channel_id = ch.funding_txid()
        with self._registry_lock:
            if channel_id in self.channels:
                raise ManagerError(f"channel {channel_id[::-1].hex()} already registered")
            self.channels[channel_id] = ch
            self._locks[channel_id] = threading.RLock()
        persist_channel(self.store, ch)
        return channel_id

    def get(self, channel_id: bytes) -> Channel:
        ch = self.channels.get(channel_id)
        if ch is None:
            raise ManagerError(f"channel {channel_id[::-1].hex()} not found")
        return ch

    @contextmanager
    def locked(self, channel_id: bytes) -> Iterator[Channel]:
        lock = self._locks.get(channel_id)
        if lock is None:
            raise ManagerError(f"channel {channel_id[::-1].hex()} not registered")
        lock.acquire()
        try:
            yield self.channels[channel_id]
        finally:
            lock.release()

    def apply_transfer(self, channel_id: bytes, sender: int, recipient: int,
                       delta: int) -> int:
        """Atomically apply a single transfer; returns new version."""
        if channel_id in self.closed_channels:
            raise StateError(f"channel {channel_id[::-1].hex()} already closed")
        with self.locked(channel_id) as ch:
            ch.apply_transfer(sender, recipient, delta)
            persist_channel(self.store, ch)
            return ch.state.version

    def cooperative_close(self, channel_id: bytes) -> tuple:
        """Cooperative close; channel is sealed against further transfers."""
        with self.locked(channel_id) as ch:
            if channel_id in self.closed_channels:
                raise StateError("channel already closed")
            tx, utxos = ch.cooperative_close()
            self.closed_channels.add(channel_id)
            persist_channel(self.store, ch)
            return tx, utxos


__all__ = ["ChannelManager", "ManagerError"]
