"""SIGHASH-aware signing helpers.

Every signature in this protocol is produced over a sighash committing to
``SIGHASH_ALL | SIGHASH_FORKID``: every input and output is bound. Bitcoin
DER signatures are appended with a single byte equal to the sighash type;
``bitcoinx``'s interpreter expects this convention.

The interpreter rejects DER signatures whose ``s`` value is not low. We
therefore call :meth:`PrivateKey.sign` which by default produces low-S DER
signatures.
"""

from __future__ import annotations

from bitcoinx import PrivateKey, Script, SigHash, Tx

from .config import SIGHASH_ALL_FORKID


def sign_input(
    tx: Tx,
    input_index: int,
    utxo_value: int,
    script_code: Script,
    priv: PrivateKey,
    sighash: SigHash = SIGHASH_ALL_FORKID,
) -> bytes:
    """Sign ``input_index`` of ``tx`` and return ``DER || sighash_byte``.

    Parameters
    ----------
    tx
        The transaction being signed. Inputs at indices other than
        ``input_index`` are committed to per the sighash flags.
    input_index
        The index of the input being signed.
    utxo_value
        Satoshi value of the UTXO this input is spending. Required by the
        FORKID sighash digest (BIP143-style commitment).
    script_code
        The locking script of the UTXO being spent (the script-code subject
        to the signature commitment). For our scripts this is the full
        locking script.
    priv
        The signing key.
    sighash
        The sighash flag; defaults to ``ALL | FORKID``.
    """
    digest = tx.signature_hash(input_index, utxo_value, script_code, sighash)
    der = priv.sign(digest, hasher=None)
    return der + bytes([int(sighash)])


__all__ = ["sign_input"]
