"""Phase 9 GATE: watchtower.

Spec scenario: an honest party goes offline; a corrupted counterparty
broadcasts a superseded state; the tower detects it and broadcasts the
current state (overtaking by sequence number) and then takes the
offender's bond via the forfeiture branch. All spends verify through
the interpreter.
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from bitcoinx import PrivateKey, Tx  # noqa: E402

from channel.config import ChannelConfig  # noqa: E402
from channel.keymgmt import KeyBook  # noqa: E402
from channel.lifecycle import Channel  # noqa: E402
from channel.node.network import EmbeddedNode  # noqa: E402
from channel.watchtower.incentive import IncentiveLedger  # noqa: E402
from channel.watchtower.monitor import Monitor  # noqa: E402
from channel.watchtower.registry import Registry, WatchRecord  # noqa: E402
from channel.watchtower.tower import Tower  # noqa: E402
from channel.verify import verify_spend  # noqa: E402


def _fresh_channel(n: int = 3, k: int = 1000, S: int = 1, bond: int = 1) -> Channel:
    cfg = ChannelConfig.uniform_bond(n=n, k=k, S=S, bond=bond)
    book = KeyBook.from_ints(list(range(60_000, 60_000 + n)))
    ch = Channel.open(cfg, book)
    ch.mark_confirmed()
    return ch


def _seed_funding_into_node(node: EmbeddedNode, ch: Channel) -> None:
    """Insert the channel's funding outputs directly into the node's UTXO set."""
    txid = ch.funding_txid()
    for i, out in enumerate(ch.funding_tx.outputs):
        from channel.node.blockstore import UtxoEntry
        node.blockstore.add_utxo(UtxoEntry(
            txid=txid, vout=i, value=out.value,
            script_pubkey=bytes(out.script_pubkey), height=1,
        ))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_persistence_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "reg.json")
        r1 = Registry.open(path)
        rec = WatchRecord(
            channel_id=b"\xAA" * 32,
            current_state_tx_hex="0100000000",  # not a real tx; persistence-only
            forfeit_tx_hex_by_owner={},
            horizon=500,
        )
        r1.register(rec)
        # Reload.
        r2 = Registry.open(path)
        assert r2.get(b"\xAA" * 32) is not None
        assert r2.get(b"\xAA" * 32).horizon == 500  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Tower defends: stale state -> current state rebroadcast
# ---------------------------------------------------------------------------


def test_tower_overtakes_stale_state_broadcast() -> None:
    node = EmbeddedNode()
    ch = _fresh_channel()
    _seed_funding_into_node(node, ch)

    # Advance the channel state.
    ch.apply_transfer(0, 1, 300)
    ch.apply_transfer(0, 2, 300)
    current_tx, _ = ch.sign_state_tx(ch.state)

    # Build a superseded state (version 0 forced, allocation kept as
    # initial).
    stale_tx, _ = ch.superseded_state_tx_for(0, (1000, 0, 0))

    # Pre-sign a forfeit tx for offender index 0.
    forfeit_tx, _ = ch.forfeit_bond_tx(offender=0)

    # Tower setup.
    reg = Registry()
    tower = Tower(node=node, registry=reg)
    rec = WatchRecord(
        channel_id=ch.funding_txid(),
        current_state_tx_hex=current_tx.to_hex(),
        forfeit_tx_hex_by_owner={0: forfeit_tx.to_hex()},
        horizon=ch.cfg.L0,
    )
    tower.register(rec)

    # Offender broadcasts stale state into the mempool.
    res = node.submit_tx(stale_tx)
    assert res.ok, res.reason

    # Tower should have observed and rebroadcast the current state,
    # replacing the stale one under the original replacement rule.
    assert tower.interventions == 1
    assert node.mempool.contains(current_tx.hash())
    assert not node.mempool.contains(stale_tx.hash())

    # Tower then takes the offender's bond.
    forfeit_result = tower.forfeit_offender_bond(ch.funding_txid(), offender=0)
    assert forfeit_result.ok, forfeit_result.reason
    assert tower.forfeits == 1


def test_tower_no_action_on_current_state_broadcast() -> None:
    """A fresh current-state broadcast does NOT trigger an intervention."""
    node = EmbeddedNode()
    ch = _fresh_channel()
    _seed_funding_into_node(node, ch)
    ch.apply_transfer(0, 1, 100)
    current_tx, _ = ch.sign_state_tx(ch.state)
    forfeit_tx, _ = ch.forfeit_bond_tx(offender=0)

    reg = Registry()
    tower = Tower(node=node, registry=reg)
    tower.register(WatchRecord(
        channel_id=ch.funding_txid(),
        current_state_tx_hex=current_tx.to_hex(),
        forfeit_tx_hex_by_owner={0: forfeit_tx.to_hex()},
        horizon=ch.cfg.L0,
    ))

    assert node.submit_tx(current_tx).ok
    assert tower.interventions == 0


# ---------------------------------------------------------------------------
# Incentive
# ---------------------------------------------------------------------------


def test_incentive_caps_fee_at_bond() -> None:
    ledger = IncentiveLedger(fee_per_intervention=5)
    assert ledger.record(bond_value=10) == 5
    assert ledger.record(bond_value=2) == 2  # capped
    assert ledger.total() == 7


# ---------------------------------------------------------------------------
# G1 — Monitor periodic-tick loop
# ---------------------------------------------------------------------------


def test_monitor_loop_emits_ticks() -> None:
    """Monitor start/run/stop lifecycle increments an observable tick counter.

    Uses a short interval (50 ms) so the test exercises at least two
    ticks within a deterministic window without sleeping the suite.
    """
    import time as _time

    node = EmbeddedNode()
    reg = Registry()
    tower = Tower(node=node, registry=reg)
    mon = Monitor(tower=tower, interval_s=0.05)

    assert not mon.is_running()
    mon.start()
    try:
        assert mon.is_running()
        # Wait until at least two ticks land, but cap the wait so a stuck
        # monitor fails fast rather than blocking the suite.
        deadline = _time.monotonic() + 1.5
        while mon.ticks < 2 and _time.monotonic() < deadline:
            _time.sleep(0.02)
        assert mon.ticks >= 2, f"monitor only ticked {mon.ticks} times in 1.5s"
    finally:
        mon.stop()
    assert not mon.is_running()


def test_monitor_idempotent_start_and_stop() -> None:
    """Double start/stop must be safe and not leak threads."""
    node = EmbeddedNode()
    tower = Tower(node=node, registry=Registry())
    mon = Monitor(tower=tower, interval_s=0.05)
    mon.start()
    mon.start()  # second start is a no-op while the thread is alive
    assert mon.is_running()
    mon.stop()
    mon.stop()  # safe to stop again
    assert not mon.is_running()
