"""Phase 5 — negative tests.

Every malformed spend in this file must be **rejected by the interpreter**
(except for the fractional/negative satoshi tests, which are rejected by
the accounting boundary before any tx is constructed).
"""

from __future__ import annotations

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from bitcoinx import Ops, PrivateKey, Script, Tx, TxInput, TxOutput, hash160  # noqa: E402

from channel.accounting import ensure_whole_satoshi  # noqa: E402
from channel.config import FINAL_SEQUENCE, SIGHASH_ALL_FORKID  # noqa: E402
from channel.errors import FractionalSatoshiError  # noqa: E402
from channel.routing import build_path, build_claim_tx, build_return_tx  # noqa: E402
from channel.scripts import (  # noqa: E402
    bond_forfeit_unlock, bond_return_unlock, bond_script,
    channel_funding_script, channel_funding_unlock,
    hop_claim_unlock, hop_return_unlock, hop_script, p2pkh_script,
)
from channel.signing import sign_input  # noqa: E402
from channel.verify import spend_verifies, verify_spend  # noqa: E402


def _keys(start: int, n: int) -> list[PrivateKey]:
    return [PrivateKey((start + i).to_bytes(32, "big")) for i in range(n)]


def _build_spend(utxo_script, utxo_value=1000, locktime=0,
                 sequence=FINAL_SEQUENCE):
    prev_hash = b"\xEE" * 32
    tx_in = TxInput(prev_hash, 0, Script(b""), sequence)
    tx_out = TxOutput(0, Script() << Ops.OP_RETURN)
    tx = Tx(1, [tx_in], [tx_out], locktime)
    utxo = TxOutput(utxo_value, utxo_script)
    return tx, utxo


def _set_sig(tx: Tx, script_sig: Script) -> None:
    old = tx.inputs[0]
    tx.inputs[0] = TxInput(old.prev_hash, old.prev_idx, script_sig, old.sequence)


# ---------------------------------------------------------------------------
# §10 case 1: funding close with only n-1 of n signatures
# ---------------------------------------------------------------------------


def test_funding_close_missing_one_of_n_signatures_rejected_by_VM() -> None:
    privs = _keys(40000, 4)
    pubs = [p.public_key for p in privs]
    locking = channel_funding_script(pubs)
    tx, utxo = _build_spend(locking, utxo_value=10_000)

    sigs = [sign_input(tx, 0, utxo.value, locking, p) for p in privs[:3]]
    # 4th signature replaced by a zero placeholder.
    _set_sig(tx, channel_funding_unlock(sigs + [b"\x00"]))
    assert not spend_verifies(tx, 0, utxo)


# ---------------------------------------------------------------------------
# §10 case 2: bond forfeiture with only m-1 of m counterparty signatures
# ---------------------------------------------------------------------------


def test_bond_forfeit_missing_one_counterparty_rejected_by_VM() -> None:
    owner, cp1, cp2, cp3 = _keys(40100, 4)
    locking = bond_script(owner.public_key,
                          [cp1.public_key, cp2.public_key, cp3.public_key])
    tx, utxo = _build_spend(locking, utxo_value=1)

    sig1 = sign_input(tx, 0, utxo.value, locking, cp1)
    sig2 = sign_input(tx, 0, utxo.value, locking, cp2)
    # Third sig missing -> replaced by zero placeholder.
    _set_sig(tx, Script() << Ops.OP_0 << sig1 << sig2 << b"\x00" << Ops.OP_0)
    assert not spend_verifies(tx, 0, utxo)


# ---------------------------------------------------------------------------
# §10 case 3: hop claim with a wrong preimage
# ---------------------------------------------------------------------------


def test_hop_claim_wrong_preimage_rejected_by_VM() -> None:
    payer, payee = _keys(40200, 2)
    real = b"\x12" * 32
    locking = hop_script(hash160(real), payee.public_key, payer.public_key)
    tx, utxo = _build_spend(locking, utxo_value=500)

    sig = sign_input(tx, 0, utxo.value, locking, payee)
    wrong = b"\x99" * 32
    _set_sig(tx, hop_claim_unlock(sig, wrong))
    assert not spend_verifies(tx, 0, utxo)


# ---------------------------------------------------------------------------
# §10 case 4: hop return signed by a key other than the payer
# ---------------------------------------------------------------------------


def test_hop_return_signed_by_non_payer_rejected_by_VM() -> None:
    payer, payee = _keys(40300, 2)
    locking = hop_script(hash160(b"\x05" * 32), payee.public_key, payer.public_key)
    tx, utxo = _build_spend(locking, utxo_value=500)

    bad_sig = sign_input(tx, 0, utxo.value, locking, payee)  # payee, not payer
    _set_sig(tx, hop_return_unlock(bad_sig))
    assert not spend_verifies(tx, 0, utxo)


# ---------------------------------------------------------------------------
# §10 case 5: a superseded lower-sequence state alongside the current state
# ---------------------------------------------------------------------------


def test_superseded_state_does_not_supersede_current_under_replacement_rule() -> None:
    """The current (higher-sequence) state overtakes the superseded one.

    Both spends are individually valid through the VM; the replacement rule
    is *not* enforced by script (it is a consensus property of node mempool
    handling). What the test asserts is: the relative ordering of the
    sequence numbers is correct (so a node applying the original rule
    will prefer the newer state).
    """
    from channel.lifecycle import Channel
    from channel.keymgmt import KeyBook
    from channel.config import ChannelConfig
    cfg = ChannelConfig.uniform_bond(n=3, k=1000, S=1)
    book = KeyBook.from_ints([40400, 40401, 40402])
    ch = Channel.open(cfg, book)
    ch.mark_confirmed()
    ch.apply_transfer(0, 1, 200)
    ch.apply_transfer(0, 2, 200)
    current = ch.state

    superseded_tx, _ = ch.superseded_state_tx_for(0, (1000, 0, 0))
    current_tx, _ = ch.sign_state_tx(current)
    # Both individually accepted by VM (the script is the same n-of-n).
    # The replacement rule says: current_tx's sequence > superseded_tx's,
    # so it replaces it before locktime maturity.
    assert current_tx.inputs[0].sequence > superseded_tx.inputs[0].sequence


# ---------------------------------------------------------------------------
# §10 case 6: fractional or negative satoshi value rejected at the boundary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [0.5, 1.25, -1, -100, 2.0, "1"])
def test_fractional_or_negative_satoshi_rejected_by_accounting(bad: object) -> None:
    with pytest.raises(FractionalSatoshiError):
        ensure_whole_satoshi(bad)
