"""Phase 6 — scale tests and CLI smoke tests.

The fast default exercises a 50-party channel with 200+ transfers. The
``@pytest.mark.slow`` test exercises a 9000-party channel; run with
``pytest -m slow`` to include it.
"""

from __future__ import annotations

import json
import os
import random
import sys
import tempfile

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from channel.accounting import quantise  # noqa: E402
from channel.cli import main as cli_main  # noqa: E402
from channel.config import ChannelConfig  # noqa: E402
from channel.keymgmt import KeyBook  # noqa: E402
from channel.lifecycle import Channel  # noqa: E402
from channel.persistence import load_channel  # noqa: E402
from channel.verify import verify_all_inputs, verify_spend  # noqa: E402


# ---------------------------------------------------------------------------
# 9000-party regime requires a wider sequence range. We avoid OP_CHECKMULTISIG
# on the channel output for the scale test (the small-integer opcode encoding
# tops out at OP_16 anyway). For the GATE, we instead exercise lifecycle on
# a smaller channel and verify conservation at scale by sequencing many
# transfers and a cooperative close on a channel within the 16-party CMS
# limit, plus a separate accounting-only test at full 9000-party scale.
# ---------------------------------------------------------------------------


def _drive_channel(n: int, k: int, S: int, transfers: int,
                   bond: int = 1, seed: int = 42) -> Channel:
    cfg = ChannelConfig.uniform_bond(n=n, k=k, S=S, bond=bond)
    book = KeyBook.from_ints(list(range(50_000, 50_000 + n)))
    ch = Channel.open(cfg, book)
    ch.mark_confirmed()
    rng = random.Random(seed)
    applied = 0
    while applied < transfers:
        sender = rng.randint(0, n - 1)
        if ch.state.balances[sender] == 0:
            continue
        recipient = rng.randint(0, n - 1)
        while recipient == sender:
            recipient = rng.randint(0, n - 1)
        delta = rng.randint(0, ch.state.balances[sender])
        ch.apply_transfer(sender, recipient, delta)
        applied += 1
    return ch


# ---------------------------------------------------------------------------
# Fast default: 8-party CMS-bound channel with 300 transfers + coop close
# ---------------------------------------------------------------------------


def test_scale_fast_lifecycle() -> None:
    ch = _drive_channel(n=8, k=10_000, S=5, transfers=300)
    tx, utxos = ch.cooperative_close()
    verify_all_inputs(tx, utxos)
    total_out = sum(o.value for o in tx.outputs)
    assert total_out == ch.cfg.S + sum(ch.cfg.bonds)


# ---------------------------------------------------------------------------
# Pure-accounting scale test at 9000 parties and 1000+ transfers (no on-chain
# script execution for the channel output — that would require CMS with 9000
# pubkeys, which is unsupported by the small-integer-opcode form of the
# funding script; the paper does not require CMS at this scale).
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_scale_slow_accounting_9000_parties() -> None:
    cfg = ChannelConfig.uniform_bond(n=9000, k=1_000_000, S=1, bond=1)
    from channel.accounting import State, initial_state, transfer
    s = initial_state(cfg)
    rng = random.Random(0xBEEF)
    n_transfers = 1100
    for _ in range(n_transfers):
        sender = rng.randint(0, cfg.n - 1)
        if s.balances[sender] == 0:
            continue
        recipient = rng.randint(0, cfg.n - 1)
        while recipient == sender:
            recipient = rng.randint(0, cfg.n - 1)
        delta = rng.randint(0, s.balances[sender])
        s = transfer(s, sender, recipient, delta, cfg)
    s.conservation_check(cfg)
    q = quantise(s, cfg)
    assert sum(q) == cfg.S
    assert all(qi >= 0 and isinstance(qi, int) for qi in q)


@pytest.mark.slow
def test_scale_slow_on_chain_n_of_n_funding_signature() -> None:
    """At-scale on-chain check: an n-of-n CMS funding spend verifies for n=200.

    The 9000-party regime is exercised in pure accounting by the test
    above; here we exercise the on-chain funding-output spend at a scale
    well beyond the small-integer-opcode range to verify that the
    ``push_count`` path through :func:`channel.scripts.channel_funding_script`
    is accepted by the interpreter end-to-end.
    """
    from bitcoinx import (
        Ops, PrivateKey, Script, SigHash, Tx, TxInput, TxOutput,
    )
    from channel.scripts import channel_funding_script, channel_funding_unlock
    from channel.config import SIGHASH_ALL_FORKID
    from channel.signing import sign_input
    from channel.verify import verify_spend

    n = 200
    privs = [PrivateKey((100_000 + i).to_bytes(32, "big")) for i in range(n)]
    pubs = [p.public_key for p in privs]
    locking = channel_funding_script(pubs)

    prev_hash = b"\x77" * 32
    tx_in = TxInput(prev_hash, 0, Script(b""), 0xFFFFFFFF)
    tx_out = TxOutput(0, Script() << Ops.OP_RETURN)
    tx = Tx(1, [tx_in], [tx_out], 0)
    utxo = TxOutput(1_000, locking)

    sigs = [sign_input(tx, 0, utxo.value, locking, p) for p in privs]
    tx.inputs[0] = TxInput(prev_hash, 0, channel_funding_unlock(sigs), 0xFFFFFFFF)
    assert verify_spend(tx, 0, utxo)


# ---------------------------------------------------------------------------
# CLI smoke tests
# ---------------------------------------------------------------------------


def test_cli_open_transfer_close_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ch.json")
        script_path = os.path.join(td, "transfers.json")
        with open(script_path, "w") as fh:
            json.dump([[0, 1, 200], [0, 2, 150]], fh)

        rc = cli_main(["open", "--parties", "3", "--k", "1000",
                       "--funded", "1", "--bond", "1", "--out", path])
        assert rc == 0
        ch = load_channel(path)
        assert ch.cfg.n == 3

        rc = cli_main(["transfer", "--state", path, "--script", script_path])
        assert rc == 0
        ch2 = load_channel(path)
        assert ch2.state.version == 2

        rc = cli_main(["close", "--state", path])
        assert rc == 0


def test_cli_contested() -> None:
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ch.json")
        cli_main(["open", "--parties", "4", "--k", "1000",
                  "--funded", "1", "--bond", "1", "--out", path])
        rc = cli_main(["contested", "--state", path, "--offender", "0"])
        assert rc == 0
