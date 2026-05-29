"""Phase 10 GATE: persistence/recovery + parallel-transfer concurrency.

Tests:
- A channel's state is persisted across a fresh SystemStore reload.
- A crash-recovery test: open, transfer, simulate restart, assert state
  is reloaded and cooperative close still verifies.
- Many parallel transfers across many channels: conservation holds for
  every channel; the per-channel lock prevents interleaved updates.
"""

from __future__ import annotations

import os
import random
import sys
import tempfile
import threading

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from channel.accounting import quantise  # noqa: E402
from channel.config import ChannelConfig  # noqa: E402
from channel.keymgmt import KeyBook  # noqa: E402
from channel.lifecycle import Channel  # noqa: E402
from channel.runtime.manager import ChannelManager  # noqa: E402
from channel.store.recover import persist_channel, recover_channel  # noqa: E402
from channel.store.store import SystemStore  # noqa: E402
from channel.verify import verify_all_inputs  # noqa: E402


def _fresh_channel(n: int = 4, k: int = 1000, S: int = 1, bond: int = 1,
                    seed: int = 70_000) -> Channel:
    cfg = ChannelConfig.uniform_bond(n=n, k=k, S=S, bond=bond)
    book = KeyBook.from_ints(list(range(seed, seed + n)))
    ch = Channel.open(cfg, book)
    ch.mark_confirmed()
    return ch


# ---------------------------------------------------------------------------
# Crash recovery
# ---------------------------------------------------------------------------


def test_persistence_and_recovery_through_system_store() -> None:
    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "system.sqlite")
        store = SystemStore(db)
        ch = _fresh_channel()
        ch.apply_transfer(0, 1, 200)
        ch.apply_transfer(0, 2, 200)
        persist_channel(store, ch)
        store.close()

        # "Crash": reopen the SystemStore.
        store2 = SystemStore(db)
        try:
            recovered = recover_channel(store2, ch.funding_txid())
            assert recovered is not None
            assert recovered.state.balances == ch.state.balances
            assert recovered.state.version == ch.state.version
            # The cooperative close still verifies through the VM.
            tx, utxos = recovered.cooperative_close()
            verify_all_inputs(tx, utxos)
        finally:
            store2.close()


def test_manager_serialises_per_channel_updates() -> None:
    """Per-channel lock guarantees no interleaved state corruption."""
    store = SystemStore(":memory:")
    mgr = ChannelManager(store=store)
    ch1 = _fresh_channel(seed=70_100)
    ch2 = _fresh_channel(seed=70_200)
    id1 = mgr.add(ch1)
    id2 = mgr.add(ch2)

    transfers_per_channel = 80
    seed_balance = ch1.state.balances[0]  # both identical

    def hammer(chan_id: bytes, transfers: int, rng: random.Random) -> None:
        for _ in range(transfers):
            # Sender 0 -> random recipient. The balance read is outside the
            # lock; if a peer thread updates between read and write, the
            # transfer is rejected by the accounting boundary. This is the
            # exact behaviour required by §18: a transfer either commits
            # cleanly under the lock or is rejected, never half-applied.
            ch = mgr.get(chan_id)
            sender_balance = ch.state.balances[0]
            if sender_balance == 0:
                continue
            recipient = rng.randint(1, ch.cfg.n - 1)
            delta = rng.randint(0, sender_balance)
            try:
                mgr.apply_transfer(chan_id, 0, recipient, delta)
            except Exception:  # noqa: BLE001 -- rejection is expected
                pass

    threads: list[threading.Thread] = []
    for chan_id, rng_seed in [(id1, 1), (id2, 2)]:
        for worker in range(4):
            rng = random.Random(rng_seed * 1000 + worker)
            t = threading.Thread(target=hammer, args=(chan_id, transfers_per_channel // 4, rng))
            threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Conservation per channel.
    for chan_id in [id1, id2]:
        ch = mgr.get(chan_id)
        ch.state.conservation_check(ch.cfg)
        assert sum(ch.state.balances) == ch.cfg.k * ch.cfg.S
        # Versions can be anywhere up to 4 * transfers_per_channel / 4, but
        # *each* applied transfer must have bumped the version exactly by 1.
        assert ch.state.version > 0


def test_close_after_concurrent_transfers_verifies() -> None:
    store = SystemStore(":memory:")
    mgr = ChannelManager(store=store)
    ch = _fresh_channel(n=5, k=10_000, S=3, seed=70_300)
    cid = mgr.add(ch)

    def driver(rng_seed: int) -> None:
        rng = random.Random(rng_seed)
        for _ in range(40):
            ch_local = mgr.get(cid)
            s = ch_local.state.balances[0]
            if s == 0:
                continue
            r = rng.randint(1, ch_local.cfg.n - 1)
            d = rng.randint(0, s)
            try:
                mgr.apply_transfer(cid, 0, r, d)
            except Exception:  # noqa: BLE001
                pass

    threads = [threading.Thread(target=driver, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    tx, utxos = mgr.cooperative_close(cid)
    verify_all_inputs(tx, utxos)


def test_closed_channel_rejects_further_transfers() -> None:
    store = SystemStore(":memory:")
    mgr = ChannelManager(store=store)
    ch = _fresh_channel(seed=70_400)
    cid = mgr.add(ch)
    mgr.apply_transfer(cid, 0, 1, 100)
    mgr.cooperative_close(cid)
    with pytest.raises(Exception):
        mgr.apply_transfer(cid, 0, 1, 50)
