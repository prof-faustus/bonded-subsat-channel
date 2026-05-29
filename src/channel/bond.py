"""Bond outputs: construction, return, and forfeiture.

A bond is a one-satoshi-or-more output locked under :func:`scripts.bond_script`
with two branches: a *return* branch (the owner co-signing a cooperative
close) and a *forfeiture* branch (every counterparty signing). The bond is
created at funding alongside the channel output, and is spent at close
along with the channel output.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from bitcoinx import Ops, PrivateKey, PublicKey, Script, Tx, TxInput, TxOutput

from .accounting import ensure_whole_satoshi
from .config import FINAL_SEQUENCE, SIGHASH_ALL_FORKID
from .errors import ScriptBuildError
from .scripts import bond_forfeit_unlock, bond_return_unlock, bond_script
from .signing import sign_input


@dataclass(frozen=True)
class BondOutput:
    """Description of a single bond output.

    Attributes
    ----------
    owner_index
        Index of the bond's owner in the channel's participant list.
    value
        Satoshi value locked in the bond (``>= 1``).
    funding_txid
        Hash of the funding transaction that created this bond.
    vout
        Output index of the bond inside the funding transaction.
    locking_script
        The bond locking script.
    """

    owner_index: int
    value: int
    funding_txid: bytes
    vout: int
    locking_script: Script

    def utxo(self) -> TxOutput:
        return TxOutput(self.value, self.locking_script)


def make_bond_script_for(owner: PublicKey, counterparties: Sequence[PublicKey]) -> Script:
    """Build the bond locking script for ``owner`` against ``counterparties``."""
    if not counterparties:
        raise ScriptBuildError("bond requires at least one counterparty")
    return bond_script(owner, list(counterparties))


def sign_bond_return(
    tx: Tx, input_index: int, bond: BondOutput, owner_priv: PrivateKey,
) -> Script:
    """Sign and return the ``script_sig`` for the bond's IF (return) branch."""
    ensure_whole_satoshi(bond.value)
    sig = sign_input(tx, input_index, bond.value, bond.locking_script,
                     owner_priv, SIGHASH_ALL_FORKID)
    return bond_return_unlock(sig)


def sign_bond_forfeit(
    tx: Tx, input_index: int, bond: BondOutput,
    counterparty_privs: Sequence[PrivateKey],
) -> Script:
    """Sign and return the ``script_sig`` for the bond's ELSE branch.

    ``counterparty_privs`` must contain the counterparty private keys in the
    same order they appear in the locking script.
    """
    if not counterparty_privs:
        raise ScriptBuildError("bond_forfeit needs >=1 counterparty signatures")
    sigs = [
        sign_input(tx, input_index, bond.value, bond.locking_script,
                   p, SIGHASH_ALL_FORKID)
        for p in counterparty_privs
    ]
    return bond_forfeit_unlock(sigs)


__all__ = [
    "BondOutput",
    "make_bond_script_for",
    "sign_bond_return",
    "sign_bond_forfeit",
]
