"""Redundant watchtower cluster — liveness hardening.

Part I's security argument relies on **at least one honest party
monitoring the chain and rebroadcasting within Δ**. The single
watchtower of :mod:`channel.watchtower.tower` discharges this for
clients that go offline, but the assumption then re-applies to the
tower itself.

This module hardens the liveness assumption from "one specific party
is online" to "**at least one of k independent watchers is online**".
Each watcher in a cluster:

- is registered independently with its own destination pubkey,
- holds an independent pre-signed forfeit transaction crediting **its
  own** pubkey the tower fee,
- observes the same mempool and races to broadcast on a stale-state
  event,
- collects nothing if it does not act (no broadcast → no fee).

The race is resolved by the consensus single-spend rule: exactly one
of the k broadcasts confirms, and the winner is paid. The remaining
k−1 attempts are evicted from the mempool. Because every variant is a
valid forfeit transaction (each pre-signed with SIGHASH_ALL by the
honest counterparties against its specific fee output), the
construction admits exactly one winning watcher, deterministically
under whichever broadcast reaches the miner first.

Property gained: the probability of a successful defence is

    1 − P(all k watchers offline simultaneously),

which decays geometrically in k. Concretely, if each watcher has
independent uptime ``u``, cluster uptime is ``1 − (1 − u)^k``.

Each watcher is custody-free (it never signs anything; its pubkey is
only the destination of pre-signed payments), and the per-watcher fee
``f`` per intervention is fixed at registration.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

from bitcoinx import PublicKey, Tx

from ..errors import ChannelError
from ..lifecycle import Channel
from ..node.network import EmbeddedNode
from .registry import Registry, WatchRecord
from .tower import Tower


_log = logging.getLogger(__name__)


class ClusterError(ChannelError):
    pass


@dataclass(frozen=True)
class WatcherSpec:
    """A single watcher's identity: destination pubkey + per-intervention fee."""

    pubkey: PublicKey
    fee_per_intervention: int


@dataclass
class WatchCluster:
    """A k-of-k-independent watcher cluster bound to one :class:`EmbeddedNode`.

    "k-of-k-independent" means: any single one of the k watchers acting
    is sufficient to defend the channel. There is no quorum; the
    single-spend rule of the underlying ledger naturally serialises
    the race.
    """

    node: EmbeddedNode
    watchers: list[Tower] = field(default_factory=list)

    @classmethod
    def of_size(cls, node: EmbeddedNode, specs: Sequence[WatcherSpec],
                ) -> "WatchCluster":
        """Build a cluster with one tower per spec. Each tower has its own registry."""
        if not specs:
            raise ClusterError("cluster must have at least one watcher")
        watchers = [
            Tower(node=node, registry=Registry(), tower_pubkey=spec.pubkey)
            for spec in specs
        ]
        return cls(node=node, watchers=watchers)

    def size(self) -> int:
        return len(self.watchers)

    def register_channel(self, ch: Channel, specs: Sequence[WatcherSpec],
                          offenders: Iterable[int] = (0,)) -> None:
        """Register the channel with every watcher.

        Each watcher receives a pre-signed forfeit tx that pays **its
        own** pubkey ``fee_per_intervention`` satoshis. The current
        state transaction is the same across watchers (it is
        symmetric).
        """
        if len(specs) != len(self.watchers):
            raise ClusterError(
                f"specs length {len(specs)} != cluster size {len(self.watchers)}"
            )
        # Use the latest co-signed state.
        current_tx, _ = ch.sign_state_tx(ch.state)

        for spec, watcher in zip(specs, self.watchers):
            forfeit_hex_by_owner: dict[int, str] = {}
            for offender in offenders:
                forfeit_tx, _ = ch.forfeit_bond_tx(
                    offender=offender,
                    tower_pubkey=spec.pubkey,
                    tower_fee=spec.fee_per_intervention,
                )
                forfeit_hex_by_owner[offender] = forfeit_tx.to_hex()
            watcher.register(WatchRecord(
                channel_id=ch.funding_txid(),
                current_state_tx_hex=current_tx.to_hex(),
                forfeit_tx_hex_by_owner=forfeit_hex_by_owner,
                horizon=ch.cfg.L0,
            ))

    def total_interventions(self) -> int:
        return sum(w.interventions for w in self.watchers)

    def total_forfeits(self) -> int:
        return sum(w.forfeits for w in self.watchers)

    def disable(self, indices: Iterable[int]) -> None:
        """Detach the named watchers' mempool observers (simulate offline)."""
        for i in indices:
            if not 0 <= i < len(self.watchers):
                raise ClusterError(f"watcher index {i} out of range")
            w = self.watchers[i]
            try:
                self.node.mempool.observers.remove(w._observe)
            except ValueError:
                pass

    def enable(self, indices: Iterable[int]) -> None:
        """Re-attach the named watchers' mempool observers (back online)."""
        for i in indices:
            w = self.watchers[i]
            if w._observe not in self.node.mempool.observers:
                self.node.mempool.observers.append(w._observe)


__all__ = ["WatchCluster", "WatcherSpec", "ClusterError"]
