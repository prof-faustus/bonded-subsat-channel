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


# ---------------------------------------------------------------------------
# D14 — Script-enforced tower payment
# ---------------------------------------------------------------------------


def test_tower_fee_paid_in_pre_signed_forfeit_verifies_through_VM() -> None:
    """The pre-signed forfeit pays the tower its fee; spend verifies."""
    node = EmbeddedNode()
    ch = _fresh_channel(n=3, k=1000, S=1, bond=2)  # bond=2 so fee+share>0
    _seed_funding_into_node(node, ch)
    ch.apply_transfer(0, 1, 300)

    tower_priv = PrivateKey((77_777).to_bytes(32, "big"))
    tower_fee = 1  # 1 satoshi to the tower

    # Counterparties pre-sign the forfeit transaction that pays the tower.
    forfeit_tx, forfeit_utxos = ch.forfeit_bond_tx(
        offender=0,
        tower_pubkey=tower_priv.public_key,
        tower_fee=tower_fee,
    )
    # The spend verifies through the interpreter — the counterparty
    # signatures match the output set including the tower-fee output.
    from channel.verify import verify_spend
    assert verify_spend(forfeit_tx, 0, forfeit_utxos[0])

    # The first output is the tower-fee output, paying the tower's pubkey.
    from channel.scripts import p2pkh_script
    expected_script = bytes(p2pkh_script(tower_priv.public_key))
    assert forfeit_tx.outputs[0].value == tower_fee
    assert bytes(forfeit_tx.outputs[0].script_pubkey) == expected_script


def test_tower_cannot_redirect_fee_to_itself_under_sighash_all() -> None:
    """G8/D14 — tampering with the tower output invalidates the multisig.

    Constructs a pre-signed forfeit paying the tower its fee, then a
    tampered variant that redirects the tower-fee output to a different
    pubkey. The tampered variant must be **rejected by the interpreter**,
    not by any Python guard. This is what makes the incentive
    script-enforced: the tower has no way to profitably modify the
    transaction; its only profitable action is broadcasting the
    pre-signed forfeit verbatim.
    """
    node = EmbeddedNode()
    ch = _fresh_channel(n=3, k=1000, S=1, bond=2)
    _seed_funding_into_node(node, ch)

    tower_priv = PrivateKey((77_778).to_bytes(32, "big"))
    attacker_priv = PrivateKey((88_888).to_bytes(32, "big"))
    tower_fee = 1

    forfeit_tx, forfeit_utxos = ch.forfeit_bond_tx(
        offender=0,
        tower_pubkey=tower_priv.public_key,
        tower_fee=tower_fee,
    )
    # Original verifies.
    from channel.verify import verify_spend, spend_verifies
    assert verify_spend(forfeit_tx, 0, forfeit_utxos[0])

    # Tamper: keep the same multisig script_sig (so the counterparties'
    # signatures are unchanged) but swap the tower-fee output to pay an
    # attacker-controlled pubkey. SIGHASH_ALL must catch this.
    from bitcoinx import Tx, TxOutput
    from channel.scripts import p2pkh_script
    tampered = Tx(
        forfeit_tx.version,
        list(forfeit_tx.inputs),
        # First output (tower fee) redirected to the attacker.
        [TxOutput(tower_fee, p2pkh_script(attacker_priv.public_key))]
        + list(forfeit_tx.outputs[1:]),
        forfeit_tx.locktime,
    )
    assert not spend_verifies(tampered, 0, forfeit_utxos[0])


def test_tower_cannot_omit_fee_output_under_sighash_all() -> None:
    """A tampered forfeit that omits the tower-fee output is VM-rejected."""
    node = EmbeddedNode()
    ch = _fresh_channel(n=3, k=1000, S=1, bond=2)
    _seed_funding_into_node(node, ch)

    tower_priv = PrivateKey((77_779).to_bytes(32, "big"))
    tower_fee = 1

    forfeit_tx, forfeit_utxos = ch.forfeit_bond_tx(
        offender=0,
        tower_pubkey=tower_priv.public_key,
        tower_fee=tower_fee,
    )

    from bitcoinx import Tx
    tampered = Tx(
        forfeit_tx.version,
        list(forfeit_tx.inputs),
        list(forfeit_tx.outputs[1:]),  # drop the tower-fee output
        forfeit_tx.locktime,
    )
    from channel.verify import spend_verifies
    assert not spend_verifies(tampered, 0, forfeit_utxos[0])


def test_tower_no_fee_path_still_supported() -> None:
    """Backwards compatibility: forfeit_bond_tx without a tower works as before."""
    node = EmbeddedNode()
    ch = _fresh_channel(n=3, k=1000, S=1, bond=1)
    _seed_funding_into_node(node, ch)
    forfeit_tx, forfeit_utxos = ch.forfeit_bond_tx(offender=0)
    from channel.verify import verify_spend
    assert verify_spend(forfeit_tx, 0, forfeit_utxos[0])


def test_tower_incentive_only_collected_on_intervention() -> None:
    """End-to-end: tower's fee lands as a UTXO only after the forfeit is mined.

    Scenario:
    1. Tower is registered with a pre-signed forfeit that pays it.
    2. The offender broadcasts a stale state.
    3. The tower overtakes the stale state and submits the forfeit.
    4. The block is mined. The tower's pubkey now has a UTXO equal to
       the fee.
    5. Counter-scenario: a separate tower that registers but never
       intervenes accumulates no UTXOs.
    """
    from channel.scripts import p2pkh_script
    node = EmbeddedNode()
    ch = _fresh_channel(n=3, k=1000, S=1, bond=2)
    _seed_funding_into_node(node, ch)
    ch.apply_transfer(0, 1, 400)
    current_tx, _ = ch.sign_state_tx(ch.state)

    tower_priv = PrivateKey((77_780).to_bytes(32, "big"))
    tower_pk = tower_priv.public_key
    tower_fee_sat = 1
    forfeit_tx, _ = ch.forfeit_bond_tx(
        offender=0, tower_pubkey=tower_pk, tower_fee=tower_fee_sat,
    )

    reg = Registry()
    tower = Tower(node=node, registry=reg, tower_pubkey=tower_pk)
    tower.register(WatchRecord(
        channel_id=ch.funding_txid(),
        current_state_tx_hex=current_tx.to_hex(),
        forfeit_tx_hex_by_owner={0: forfeit_tx.to_hex()},
        horizon=ch.cfg.L0,
    ))

    # Offender's stale broadcast.
    stale_tx, _ = ch.superseded_state_tx_for(0, (1000, 0, 0))
    assert node.submit_tx(stale_tx).ok
    assert tower.interventions == 1

    # The tower then submits the pre-signed forfeit.
    assert tower.forfeit_offender_bond(ch.funding_txid(), 0).ok

    # Mine the mempool — the tower's payout becomes a UTXO.
    miner_priv = PrivateKey.from_random()
    node.generate_block(p2pkh_script(miner_priv.public_key))

    tower_script_bytes = bytes(p2pkh_script(tower_pk))
    tower_utxos = node.blockstore.utxos_for_script(tower_script_bytes)
    assert len(tower_utxos) == 1
    assert tower_utxos[0].value == tower_fee_sat


def test_tower_no_intervention_no_fee() -> None:
    """A passive tower (registered, never intervenes) holds zero UTXOs."""
    from channel.scripts import p2pkh_script
    node = EmbeddedNode()
    tower_priv = PrivateKey((77_790).to_bytes(32, "big"))
    tower = Tower(node=node, registry=Registry(),
                   tower_pubkey=tower_priv.public_key)
    # Mine some unrelated blocks; the tower never sees a stale state.
    other_priv = PrivateKey.from_random()
    node.generate_block(p2pkh_script(other_priv.public_key))
    node.generate_block(p2pkh_script(other_priv.public_key))
    assert tower.interventions == 0
    tower_script_bytes = bytes(p2pkh_script(tower_priv.public_key))
    assert node.blockstore.utxos_for_script(tower_script_bytes) == []
