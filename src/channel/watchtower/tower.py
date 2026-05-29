"""The watchtower service: monitor and respond.

When a stale state for a watched channel appears in the embedded node's
mempool (lower input sequence than the current state the tower holds),
the tower broadcasts the current state to overtake it under the
original replacement rule. After the current state confirms, the tower
broadcasts the pre-signed forfeiture against the offender's bond.

The tower has no key custody: every transaction it broadcasts was
pre-signed at registration time. Failure of the tower delays settlement
but cannot move funds to the tower.

Incentive (D14). The tower has an associated public key
:attr:`tower_pubkey`. At watch-record registration time, the channel's
counterparties pre-sign forfeiture transactions that include a fixed
``tower_fee`` satoshi P2PKH output paying ``tower_pubkey``. The
``SIGHASH_ALL | FORKID`` commitment on those signatures binds them to
the exact output structure. The tower can therefore broadcast a
forfeit **only if it carries the tower-fee output verbatim**. Acting
correctly: broadcasts the pre-signed tx → receives the fee. Inaction:
no broadcast → no fee. Collusion / tampering: any modification
invalidates the multisig and the tx is rejected by the interpreter.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from bitcoinx import PublicKey, Tx

from ..errors import ChannelError
from ..node.mempool import Mempool
from ..node.network import EmbeddedNode
from ..node.validation import ValidationResult
from .registry import Registry, WatchRecord


_log = logging.getLogger(__name__)


class TowerError(ChannelError):
    pass


@dataclass
class Tower:
    """A watchtower bound to an :class:`EmbeddedNode` and a :class:`Registry`.

    Carries the tower's own destination public key for incentive
    payments. The tower never signs any spend itself — it only
    broadcasts transactions the channel parties pre-signed — so
    custody-freedom is preserved; the public key is solely the address
    at which the pre-signed payments land.
    """

    node: EmbeddedNode
    registry: Registry
    tower_pubkey: Optional[PublicKey] = None
    interventions: int = 0
    forfeits: int = 0
    on_intervention: Optional[Callable[[bytes, Tx], None]] = None

    def __post_init__(self) -> None:
        self.node.mempool.add_observer(self._observe)

    # ----- registration -----------------------------------------------------

    def register(self, record: WatchRecord) -> None:
        self.registry.register(record)

    # ----- observer / response ---------------------------------------------

    def _observe(self, event: str, tx: Tx) -> None:
        """Called by the mempool on every admit/replace/evict."""
        if event not in ("admit", "replace"):
            return
        # Inspect each input's outpoint to see if this tx spends a
        # watched channel's funding output.
        for tin in tx.inputs:
            outpoint = (bytes(tin.prev_hash), int(tin.prev_idx))
            # The funding output of the channel is at vout=0 of the
            # funding txid; the channel_id is the funding txid.
            if outpoint[1] != 0:
                continue
            record = self.registry.get(outpoint[0])
            if record is None:
                continue
            # Does this tx represent an outdated state? Compare the
            # input's sequence against the current-state tx's.
            current = record.current_state_tx()
            if int(tin.sequence) >= int(current.inputs[0].sequence):
                # This is the current state (or newer); no action needed.
                continue
            # Stale state observed: rebroadcast the current state.
            _log.warning("watchtower: stale state for channel %s detected; "
                         "rebroadcasting current state",
                         outpoint[0][::-1].hex())
            res = self.node.submit_tx(current)
            if res.ok:
                self.interventions += 1
                if self.on_intervention:
                    self.on_intervention(outpoint[0], current)

    def forfeit_offender_bond(self, channel_id: bytes, offender: int) -> ValidationResult:
        """Broadcast the pre-signed forfeit tx for ``offender`` against ``channel_id``."""
        record = self.registry.get(channel_id)
        if record is None:
            raise TowerError(f"no record for channel {channel_id[::-1].hex()}")
        tx = record.forfeit_tx_for(offender)
        res = self.node.submit_tx(tx)
        if res.ok:
            self.forfeits += 1
        return res


__all__ = ["Tower", "TowerError"]
