"""Phase 1 GATE tests.

Every locking script built by ``channel.scripts`` is exercised here with at
least one positive and one negative case. **Both** are driven through the
real interpreter via ``channel.verify.verify_spend`` / ``spend_verifies``;
negative cases must be rejected by the VM, not by a Python guard.
"""

from __future__ import annotations

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from bitcoinx import (  # noqa: E402
    Ops, PrivateKey, Script, Tx, TxInput, TxOutput, hash160,
)

from channel.config import FINAL_SEQUENCE, SIGHASH_ALL_FORKID  # noqa: E402
from channel.scripts import (  # noqa: E402
    bond_forfeit_unlock,
    bond_return_unlock,
    bond_script,
    channel_funding_script,
    channel_funding_unlock,
    hop_claim_unlock,
    hop_return_unlock,
    hop_script,
    op_n,
    p2pkh_script,
    p2pkh_unlock,
)
from channel.signing import sign_input  # noqa: E402
from channel.verify import spend_verifies, verify_spend  # noqa: E402

from conftest import burn_output, deterministic_keys, simple_spend_tx  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers local to this file
# ---------------------------------------------------------------------------


def _build_unsigned_tx(
    utxo_script: Script,
    utxo_value: int = 1000,
    sequence: int = FINAL_SEQUENCE,
    locktime: int = 0,
) -> tuple[Tx, TxOutput]:
    """Fresh tx spending a single hypothetical UTXO + an OP_RETURN output."""
    prev_hash = b"\x11" * 32
    tx = simple_spend_tx(prev_hash, 0, utxo_value - 1, Script() << Ops.OP_RETURN,
                         sequence=sequence, locktime=locktime)
    utxo = TxOutput(utxo_value, utxo_script)
    return tx, utxo


def _set_script_sig(tx: Tx, idx: int, script_sig: Script) -> None:
    """Attach a script_sig to an input (Tx is mutable in-place via .inputs[i])."""
    old = tx.inputs[idx]
    tx.inputs[idx] = TxInput(old.prev_hash, old.prev_idx, script_sig, old.sequence)


# ---------------------------------------------------------------------------
# op_n helper (the central encoding trap)
# ---------------------------------------------------------------------------


def test_op_n_emits_opcode_not_pushdata() -> None:
    """op_n(3) must serialise as OP_3 (0x53), not as a data push of 3."""
    assert bytes(Script() << op_n(0)) == b"\x00"   # OP_0
    assert bytes(Script() << op_n(1)) == b"\x51"   # OP_1
    assert bytes(Script() << op_n(3)) == b"\x53"   # OP_3
    assert bytes(Script() << op_n(16)) == b"\x60"  # OP_16


# ---------------------------------------------------------------------------
# §4.1 — n-of-n channel-funding output
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n", [2, 3, 5, 7])
def test_channel_funding_positive(n: int) -> None:
    privs = deterministic_keys(n, start=100)
    pubs = [p.public_key for p in privs]
    locking = channel_funding_script(pubs)

    tx, utxo = _build_unsigned_tx(locking, utxo_value=10_000)
    sigs = [sign_input(tx, 0, utxo.value, locking, p) for p in privs]
    _set_script_sig(tx, 0, channel_funding_unlock(sigs))

    assert verify_spend(tx, 0, utxo)


def test_channel_funding_missing_one_signature() -> None:
    privs = deterministic_keys(3, start=200)
    pubs = [p.public_key for p in privs]
    locking = channel_funding_script(pubs)

    tx, utxo = _build_unsigned_tx(locking, utxo_value=10_000)
    # Sign with only the first two parties (n-1 of n) and present a zero
    # placeholder for the missing third signature so the script reaches
    # CHECKMULTISIG with the wrong content. The VM must reject.
    sig1 = sign_input(tx, 0, utxo.value, locking, privs[0])
    sig2 = sign_input(tx, 0, utxo.value, locking, privs[1])
    _set_script_sig(
        tx, 0,
        Script() << Ops.OP_0 << sig1 << sig2 << b"\x00",  # bogus 3rd sig
    )
    assert not spend_verifies(tx, 0, utxo)


def test_channel_funding_wrong_signer() -> None:
    privs = deterministic_keys(3, start=300)
    pubs = [p.public_key for p in privs]
    locking = channel_funding_script(pubs)
    impostor = deterministic_keys(1, start=999)[0]

    tx, utxo = _build_unsigned_tx(locking, utxo_value=10_000)
    sig1 = sign_input(tx, 0, utxo.value, locking, privs[0])
    sig2 = sign_input(tx, 0, utxo.value, locking, privs[1])
    sig3_bad = sign_input(tx, 0, utxo.value, locking, impostor)
    _set_script_sig(tx, 0, channel_funding_unlock([sig1, sig2, sig3_bad]))
    assert not spend_verifies(tx, 0, utxo)


# ---------------------------------------------------------------------------
# §4.2 — Hashlocked hop
# ---------------------------------------------------------------------------


def _setup_hop(seed: int = 400) -> tuple:
    payer, payee = deterministic_keys(2, start=seed)
    preimage = (b"\x42" * 32)
    image = hash160(preimage)
    locking = hop_script(image, payee.public_key, payer.public_key)
    return payer, payee, preimage, image, locking


def test_hop_claim_branch_positive() -> None:
    payer, payee, preimage, _image, locking = _setup_hop()
    tx, utxo = _build_unsigned_tx(locking, utxo_value=5_000)
    sig = sign_input(tx, 0, utxo.value, locking, payee)
    _set_script_sig(tx, 0, hop_claim_unlock(sig, preimage))
    assert verify_spend(tx, 0, utxo)


def test_hop_claim_with_wrong_preimage() -> None:
    payer, payee, _preimage, _image, locking = _setup_hop(seed=410)
    tx, utxo = _build_unsigned_tx(locking, utxo_value=5_000)
    sig = sign_input(tx, 0, utxo.value, locking, payee)
    bad_preimage = b"\xAA" * 32
    _set_script_sig(tx, 0, hop_claim_unlock(sig, bad_preimage))
    assert not spend_verifies(tx, 0, utxo)


def test_hop_return_branch_positive() -> None:
    payer, payee, _preimage, _image, locking = _setup_hop(seed=420)
    tx, utxo = _build_unsigned_tx(locking, utxo_value=5_000)
    sig = sign_input(tx, 0, utxo.value, locking, payer)
    _set_script_sig(tx, 0, hop_return_unlock(sig))
    assert verify_spend(tx, 0, utxo)


def test_hop_return_signed_by_wrong_key() -> None:
    """The ELSE branch demands the payer's key; the payee cannot return."""
    payer, payee, _preimage, _image, locking = _setup_hop(seed=430)
    tx, utxo = _build_unsigned_tx(locking, utxo_value=5_000)
    sig_wrong = sign_input(tx, 0, utxo.value, locking, payee)  # payee, not payer
    _set_script_sig(tx, 0, hop_return_unlock(sig_wrong))
    assert not spend_verifies(tx, 0, utxo)


# ---------------------------------------------------------------------------
# §4.3 — P2PKH payout
# ---------------------------------------------------------------------------


def test_p2pkh_positive() -> None:
    priv = deterministic_keys(1, start=500)[0]
    locking = p2pkh_script(priv.public_key)
    tx, utxo = _build_unsigned_tx(locking, utxo_value=1_000)
    sig = sign_input(tx, 0, utxo.value, locking, priv)
    _set_script_sig(tx, 0, p2pkh_unlock(sig, priv.public_key))
    assert verify_spend(tx, 0, utxo)


def test_p2pkh_wrong_signer() -> None:
    owner, impostor = deterministic_keys(2, start=510)
    locking = p2pkh_script(owner.public_key)
    tx, utxo = _build_unsigned_tx(locking, utxo_value=1_000)
    sig = sign_input(tx, 0, utxo.value, locking, impostor)
    _set_script_sig(tx, 0, p2pkh_unlock(sig, owner.public_key))
    assert not spend_verifies(tx, 0, utxo)


# ---------------------------------------------------------------------------
# §4.4 — Bond output
# ---------------------------------------------------------------------------


def test_bond_return_branch_positive() -> None:
    owner, cp1, cp2 = deterministic_keys(3, start=600)
    locking = bond_script(owner.public_key, [cp1.public_key, cp2.public_key])
    tx, utxo = _build_unsigned_tx(locking, utxo_value=1)
    sig = sign_input(tx, 0, utxo.value, locking, owner)
    _set_script_sig(tx, 0, bond_return_unlock(sig))
    assert verify_spend(tx, 0, utxo)


def test_bond_return_signed_by_counterparty_fails() -> None:
    owner, cp1, cp2 = deterministic_keys(3, start=610)
    locking = bond_script(owner.public_key, [cp1.public_key, cp2.public_key])
    tx, utxo = _build_unsigned_tx(locking, utxo_value=1)
    bad = sign_input(tx, 0, utxo.value, locking, cp1)
    _set_script_sig(tx, 0, bond_return_unlock(bad))
    assert not spend_verifies(tx, 0, utxo)


def test_bond_forfeit_branch_positive() -> None:
    owner, cp1, cp2 = deterministic_keys(3, start=620)
    locking = bond_script(owner.public_key, [cp1.public_key, cp2.public_key])
    tx, utxo = _build_unsigned_tx(locking, utxo_value=1)
    sig1 = sign_input(tx, 0, utxo.value, locking, cp1)
    sig2 = sign_input(tx, 0, utxo.value, locking, cp2)
    _set_script_sig(tx, 0, bond_forfeit_unlock([sig1, sig2]))
    assert verify_spend(tx, 0, utxo)


def test_bond_forfeit_missing_one_counterparty() -> None:
    owner, cp1, cp2 = deterministic_keys(3, start=630)
    locking = bond_script(owner.public_key, [cp1.public_key, cp2.public_key])
    tx, utxo = _build_unsigned_tx(locking, utxo_value=1)
    sig1 = sign_input(tx, 0, utxo.value, locking, cp1)
    _set_script_sig(
        tx, 0,
        Script() << Ops.OP_0 << sig1 << b"\x00" << Ops.OP_0,
    )
    assert not spend_verifies(tx, 0, utxo)
