"""L — Liveness hardening: k-of-k-independent watchtower cluster.

Verifies the cluster's central property: as long as **any one** of the
k watchers is online, a stale broadcast is defended. The single-spend
rule serialises the race; exactly one watcher's forfeit confirms and
collects the fee.
"""

from __future__ import annotations

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from bitcoinx import PrivateKey  # noqa: E402

from channel.config import ChannelConfig  # noqa: E402
from channel.keymgmt import KeyBook  # noqa: E402
from channel.lifecycle import Channel  # noqa: E402
from channel.node.blockstore import UtxoEntry  # noqa: E402
from channel.node.network import EmbeddedNode  # noqa: E402
from channel.scripts import p2pkh_script  # noqa: E402
from channel.watchtower.cluster import (  # noqa: E402
    ClusterError, WatchCluster, WatcherSpec,
)


def _fresh_channel(n: int = 3, k: int = 1000, S: int = 1, bond: int = 2) -> Channel:
    cfg = ChannelConfig.uniform_bond(n=n, k=k, S=S, bond=bond)
    book = KeyBook.from_ints(list(range(80_000, 80_000 + n)))
    ch = Channel.open(cfg, book)
    ch.mark_confirmed()
    return ch


def _seed_funding(node: EmbeddedNode, ch: Channel) -> None:
    txid = ch.funding_txid()
    for i, out in enumerate(ch.funding_tx.outputs):
        node.blockstore.add_utxo(UtxoEntry(
            txid=txid, vout=i, value=out.value,
            script_pubkey=bytes(out.script_pubkey), height=1,
        ))


def _specs(n: int, seed_base: int = 90_000) -> list[WatcherSpec]:
    return [
        WatcherSpec(
            pubkey=PrivateKey((seed_base + i).to_bytes(32, "big")).public_key,
            fee_per_intervention=1,
        )
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_cluster_requires_at_least_one_watcher() -> None:
    node = EmbeddedNode()
    with pytest.raises(ClusterError):
        WatchCluster.of_size(node, [])


def test_cluster_size_matches_specs() -> None:
    node = EmbeddedNode()
    cluster = WatchCluster.of_size(node, _specs(5))
    assert cluster.size() == 5


# ---------------------------------------------------------------------------
# Defence under partial-offline conditions
# ---------------------------------------------------------------------------


def test_cluster_defends_when_only_one_watcher_online() -> None:
    """k=5 watchers, 4 disabled, the 5th defends."""
    node = EmbeddedNode()
    ch = _fresh_channel()
    _seed_funding(node, ch)
    ch.apply_transfer(0, 1, 300)

    specs = _specs(5)
    cluster = WatchCluster.of_size(node, specs)
    cluster.register_channel(ch, specs)

    # Disable 4 watchers; only watcher index 4 remains online.
    cluster.disable([0, 1, 2, 3])

    # Offender broadcasts a stale state.
    stale_tx, _ = ch.superseded_state_tx_for(0, (1000, 0, 0))
    assert node.submit_tx(stale_tx).ok

    # Exactly one watcher (the only enabled one) intervenes.
    assert cluster.total_interventions() == 1
    assert cluster.watchers[4].interventions == 1
    for i in range(4):
        assert cluster.watchers[i].interventions == 0


def test_cluster_defence_survives_independent_watcher_failures() -> None:
    """Even with random disable patterns, defence holds whenever ≥ 1 watcher is online."""
    node = EmbeddedNode()
    ch = _fresh_channel()
    _seed_funding(node, ch)
    ch.apply_transfer(0, 1, 200)

    specs = _specs(3)
    cluster = WatchCluster.of_size(node, specs)
    cluster.register_channel(ch, specs)
    # Disable two watchers (1 of 3 remains).
    cluster.disable([0, 2])

    stale_tx, _ = ch.superseded_state_tx_for(0, (1000, 0, 0))
    assert node.submit_tx(stale_tx).ok
    assert cluster.total_interventions() == 1


def test_cluster_zero_defence_when_all_watchers_offline() -> None:
    """Honest evaluation: if **every** watcher is offline, no defence happens.

    This is the residual liveness assumption; the cluster reduces, but
    does not eliminate, dependence on at-least-one-honest-watcher being
    online.
    """
    node = EmbeddedNode()
    ch = _fresh_channel()
    _seed_funding(node, ch)
    ch.apply_transfer(0, 1, 200)

    specs = _specs(3)
    cluster = WatchCluster.of_size(node, specs)
    cluster.register_channel(ch, specs)
    cluster.disable([0, 1, 2])

    stale_tx, _ = ch.superseded_state_tx_for(0, (1000, 0, 0))
    assert node.submit_tx(stale_tx).ok
    assert cluster.total_interventions() == 0


def test_cluster_only_one_forfeit_confirms_via_single_spend() -> None:
    """With all watchers online, multiple intervene but only one forfeit confirms.

    The single-spend rule guarantees exactly one forfeit transaction
    against the offender's bond can confirm. Each watcher's forfeit
    pays its own pubkey, so the winner's pubkey ends up with the fee
    UTXO after mining, and no other watcher does.
    """
    node = EmbeddedNode()
    ch = _fresh_channel()
    _seed_funding(node, ch)
    ch.apply_transfer(0, 1, 300)

    specs = _specs(3)
    cluster = WatchCluster.of_size(node, specs)
    cluster.register_channel(ch, specs)

    # Stale broadcast.
    stale_tx, _ = ch.superseded_state_tx_for(0, (1000, 0, 0))
    assert node.submit_tx(stale_tx).ok
    # All 3 watchers attempt the same current-state rebroadcast
    # (idempotent in the mempool); each records an intervention.
    assert cluster.total_interventions() == 3

    # Each watcher then submits its own forfeit variant; only the
    # first to land in the mempool wins (the rest conflict on the
    # offender's bond input).
    for watcher in cluster.watchers:
        watcher.forfeit_offender_bond(ch.funding_txid(), 0)

    miner = PrivateKey.from_random()
    node.generate_block(p2pkh_script(miner.public_key))

    # Exactly one watcher's pubkey holds a fee UTXO.
    n_paid = 0
    for spec in specs:
        utxos = node.blockstore.utxos_for_script(bytes(p2pkh_script(spec.pubkey)))
        if utxos:
            assert len(utxos) == 1
            assert utxos[0].value == spec.fee_per_intervention
            n_paid += 1
    assert n_paid == 1, f"expected exactly 1 watcher paid; got {n_paid}"


def test_cluster_re_enable_restores_observer() -> None:
    """disable() / enable() round trip restores the observer.

    The cluster registers at the current channel state (>= version 1
    so the stale broadcast at version 0 is strictly behind). Then the
    observer for watcher 0 is detached and re-attached; the test
    verifies the re-enabled watcher reacts to a subsequent stale
    broadcast.
    """
    node = EmbeddedNode()
    ch = _fresh_channel()
    _seed_funding(node, ch)
    ch.apply_transfer(0, 1, 200)  # state at version 1 before registering

    specs = _specs(2)
    cluster = WatchCluster.of_size(node, specs)
    cluster.register_channel(ch, specs)

    cluster.disable([0])
    cluster.enable([0])

    stale_tx, _ = ch.superseded_state_tx_for(0, (1000, 0, 0))
    assert node.submit_tx(stale_tx).ok
    # Both watchers online and reacting; each submits the current state
    # (the mempool admits the first and dedupes the second as already
    # present, but both count an intervention attempt).
    assert cluster.total_interventions() == 2
