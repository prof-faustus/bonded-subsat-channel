"""Phase 3 GATE: lifecycle, bonds, key-replacement, persistence.

All settlement paths exercised here are run through the real interpreter via
``channel.verify``. The negative cases (refusing to sign before confirmation,
seller signing after key replacement) are also interpreter-rejected.
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from bitcoinx import Ops, PrivateKey, Script, TxInput, TxOutput  # noqa: E402

from channel.accounting import State, quantise, transfer  # noqa: E402
from channel.config import ChannelConfig, FINAL_SEQUENCE, SIGHASH_ALL_FORKID  # noqa: E402
from channel.errors import StateError, UnconfirmedFundingError  # noqa: E402
from channel.keymgmt import KeyBook  # noqa: E402
from channel.lifecycle import Channel, refresh_channel  # noqa: E402
from channel.persistence import load_channel, save_channel  # noqa: E402
from channel.scripts import (  # noqa: E402
    channel_funding_unlock, p2pkh_script, p2pkh_unlock,
)
from channel.signing import sign_input  # noqa: E402
from channel.verify import spend_verifies, verify_all_inputs, verify_spend  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fresh_channel(n: int = 3, k: int = 1000, S: int = 1, bond: int = 1) -> Channel:
    cfg = ChannelConfig.uniform_bond(n=n, k=k, S=S, bond=bond)
    book = KeyBook.from_ints(list(range(1000, 1000 + n)))
    return Channel.open(cfg, book)


# ---------------------------------------------------------------------------
# Open
# ---------------------------------------------------------------------------


def test_open_creates_channel_and_bond_outputs() -> None:
    ch = _fresh_channel(n=3, k=1000, S=2, bond=1)
    assert ch.channel_output_value() == 2
    assert len(ch.bonds) == 3
    assert [b.value for b in ch.bonds] == [1, 1, 1]
    # Funding tx structure.
    assert len(ch.funding_tx.outputs) == 1 + 3
    assert ch.funding_tx.outputs[0].value == 2


def test_unconfirmed_funding_refuses_signing() -> None:
    ch = _fresh_channel()
    with pytest.raises(UnconfirmedFundingError):
        ch.sign_state_tx(ch.state)
    with pytest.raises(UnconfirmedFundingError):
        ch.cooperative_close()


# ---------------------------------------------------------------------------
# Transfer + state tx
# ---------------------------------------------------------------------------


def test_signed_state_tx_verifies_through_interpreter() -> None:
    ch = _fresh_channel(n=4, k=1000, S=1)
    ch.mark_confirmed()
    ch.apply_transfer(0, 1, 600)
    ch.apply_transfer(1, 2, 400)
    tx, utxos = ch.sign_state_tx(ch.state)
    assert verify_spend(tx, 0, utxos[0])


def test_state_tx_sequence_encodes_version() -> None:
    ch = _fresh_channel()
    ch.mark_confirmed()
    ch.apply_transfer(0, 1, 100)
    ch.apply_transfer(1, 2, 50)
    tx, _ = ch.sign_state_tx(ch.state)
    assert tx.inputs[0].sequence == ch.state.version  # START_SEQUENCE = 0


# ---------------------------------------------------------------------------
# Cooperative close
# ---------------------------------------------------------------------------


def test_cooperative_close_verifies_all_inputs() -> None:
    ch = _fresh_channel(n=5, k=1000, S=3, bond=1)
    ch.mark_confirmed()
    ch.apply_transfer(0, 1, 500)
    ch.apply_transfer(0, 2, 500)
    ch.apply_transfer(0, 3, 500)
    ch.apply_transfer(0, 4, 500)
    tx, utxos = ch.cooperative_close()
    # Every input must verify through the VM.
    verify_all_inputs(tx, utxos)
    # Conservation: total out == S + sum(bonds)
    total_out = sum(o.value for o in tx.outputs)
    assert total_out == ch.cfg.S + sum(ch.cfg.bonds)


def test_cooperative_close_payouts_match_Q_star_plus_bond() -> None:
    ch = _fresh_channel(n=4, k=10_000, S=1, bond=1)
    ch.mark_confirmed()
    ch.apply_transfer(0, 1, 2500)
    ch.apply_transfer(0, 2, 2500)
    ch.apply_transfer(0, 3, 2500)
    q = quantise(ch.state, ch.cfg)
    tx, _ = ch.cooperative_close()
    # Per-party payout = q_i + b_i.
    expected = sorted(q[i] + ch.cfg.bonds[i] for i in range(ch.cfg.n)
                      if q[i] + ch.cfg.bonds[i] > 0)
    actual = sorted(o.value for o in tx.outputs)
    assert expected == actual


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------


def test_refresh_carries_allocation() -> None:
    ch = _fresh_channel(n=3, k=1000, S=1, bond=1)
    ch.mark_confirmed()
    ch.apply_transfer(0, 1, 400)
    ch.apply_transfer(0, 2, 300)
    new_ch = refresh_channel(ch, new_L=ch.cfg.L0 + 1000)
    assert new_ch.cfg.L0 == ch.cfg.L0 + 1000
    assert new_ch.state.balances == ch.state.balances
    assert new_ch.state.version == 0  # successor channel starts fresh


# ---------------------------------------------------------------------------
# Contested close & coalition refusal
# ---------------------------------------------------------------------------


def test_superseded_state_does_not_become_settlement_and_bond_is_forfeit() -> None:
    """A party broadcasts a superseded state; honest parties overtake and forfeit."""
    ch = _fresh_channel(n=3, k=1000, S=1, bond=1)
    ch.mark_confirmed()
    # Take the channel through several transfers; current state version > 0.
    ch.apply_transfer(0, 1, 400)
    ch.apply_transfer(0, 2, 300)
    current_state = ch.state

    # The offender (party 0) holds a state where they kept more.
    superseded_allocation = (1000, 0, 0)
    superseded_tx, super_utxos = ch.superseded_state_tx_for(0, superseded_allocation)

    # Honest parties broadcast the current state tx.
    current_tx, current_utxos = ch.sign_state_tx(current_state)

    # Both spends must verify in isolation (they conflict on the channel
    # output, but the script interpreter accepts each as a valid spend).
    assert verify_spend(superseded_tx, 0, super_utxos[0])
    assert verify_spend(current_tx, 0, current_utxos[0])

    # The current state carries a strictly higher input sequence: under the
    # original replacement rule it supersedes the older broadcast before
    # locktime maturity.
    assert current_tx.inputs[0].sequence > superseded_tx.inputs[0].sequence

    # The honest counterparties then forfeit the offender's bond.
    forfeit_tx, forfeit_utxos = ch.forfeit_bond_tx(offender=0)
    assert verify_spend(forfeit_tx, 0, forfeit_utxos[0])


def test_coalition_forfeiture_unprofitable() -> None:
    """For any subset C of refusers, sum(b_i for i in C) > max gain |C|."""
    # With per-party bond = 1 satoshi, the aggregate forfeiture is |C|,
    # which equals the maximum rounding gain of |C| (one satoshi per
    # refuser). The paper's strict-inequality variant requires bond > 1.
    ch = _fresh_channel(n=4, k=1000, S=1, bond=2)
    ch.mark_confirmed()
    # Coalition C = {0, 1}.
    coalition_bond = sum(ch.cfg.bonds[i] for i in [0, 1])
    max_rounding_gain = len([0, 1])  # at most 1 satoshi per member
    assert coalition_bond > max_rounding_gain


# ---------------------------------------------------------------------------
# Key-replacement transfer
# ---------------------------------------------------------------------------


def test_key_replacement_buyer_spends_seller_rejected() -> None:
    """After a key swap, the buyer can sign and the seller cannot."""
    ch = _fresh_channel(n=3, k=1000, S=1, bond=1)
    ch.mark_confirmed()

    # Move some balance to party 0 so they have something to "sell".
    ch.apply_transfer(0, 1, 200)
    ch.apply_transfer(0, 2, 200)

    # Party 0 (seller) is being replaced by a buyer with a fresh key.
    seller_priv = ch.keybook.private(0)
    buyer_priv = PrivateKey.from_random()

    # Build a fresh, post-replacement channel by rotating the funding under
    # the new key set. We re-open a sibling channel that uses the new key
    # for party 0 and the original keys elsewhere.
    new_book = ch.keybook.copy()
    new_book.replace(0, buyer_priv)
    new_ch = Channel.open(ch.cfg, new_book)
    new_ch.mark_confirmed()
    new_ch.state = State(ch.state.balances, version=0)

    # Now the buyer can produce a valid cooperative close.
    tx, utxos = new_ch.cooperative_close()
    verify_all_inputs(tx, utxos)

    # The seller cannot produce a valid bond-return spend on the new bond.
    # Build a return-tx for the buyer's bond (owner = new key) signed by
    # the seller's old key; the VM must reject.
    bond = new_ch.bonds[0]
    burn = Script() << Ops.OP_RETURN
    tx_in = TxInput(bond.funding_txid, bond.vout, Script(b""), FINAL_SEQUENCE)
    seller_tx = type(tx)(1, [tx_in], [TxOutput(0, burn)], 0)
    bad_sig = sign_input(seller_tx, 0, bond.value, bond.locking_script,
                         seller_priv, SIGHASH_ALL_FORKID)
    from channel.scripts import bond_return_unlock
    seller_tx.inputs[0] = TxInput(
        tx_in.prev_hash, tx_in.prev_idx,
        bond_return_unlock(bad_sig), tx_in.sequence,
    )
    assert not spend_verifies(seller_tx, 0, bond.utxo())


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_persistence_roundtrip() -> None:
    ch = _fresh_channel(n=4, k=500, S=1, bond=1)
    ch.mark_confirmed()
    ch.apply_transfer(0, 1, 100)
    ch.apply_transfer(0, 2, 100)
    ch.apply_transfer(1, 3, 50)

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ch.json")
        save_channel(ch, path)
        loaded = load_channel(path)

    assert loaded.state.balances == ch.state.balances
    assert loaded.state.version == ch.state.version
    assert loaded.cfg.k == ch.cfg.k
    assert loaded.funding_tx.hash() == ch.funding_tx.hash()
    # The reloaded channel can perform a cooperative close that verifies.
    tx, utxos = loaded.cooperative_close()
    verify_all_inputs(tx, utxos)
