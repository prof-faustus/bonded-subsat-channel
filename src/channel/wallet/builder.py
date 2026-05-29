"""Transaction construction: coin selection, change, fee, sign+sign for P2PKH.

The fee model is straightforward: a flat per-byte rate (configurable; the
default in :mod:`channel.fees`). The builder selects UTXOs greedily by
largest-first until the required amount plus fee is met, then adds a
change output to the wallet if the remainder exceeds a dust threshold.

Only P2PKH inputs are signed here. Other input types are produced and
signed by their respective owners (channel close, bond return, hop
claim/return); the wallet's role is funding and ordinary payments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence, TYPE_CHECKING

from bitcoinx import PrivateKey, PublicKey, Script, Tx, TxInput, TxOutput

if TYPE_CHECKING:
    # Only imported during type-checking to avoid the wallet/lifecycle
    # import cycle at runtime.
    from ..config import ChannelConfig
    from ..keymgmt import KeyBook

from ..accounting import ensure_whole_satoshi
from ..config import FINAL_SEQUENCE, SIGHASH_ALL_FORKID
from ..errors import ChannelError
from ..scripts import p2pkh_script, p2pkh_unlock
from ..signing import sign_input
from ..node.blockstore import UtxoEntry


DEFAULT_FEE_PER_BYTE = 1  # sat/byte; consumer-tuneable via channel.fees
DEFAULT_DUST_THRESHOLD = 1  # 1 satoshi (the construction's whole-satoshi premise)


class WalletBuildError(ChannelError):
    pass


@dataclass(frozen=True)
class FundingOutput:
    """An (script_pubkey, value) pair to be paid by the builder."""

    script_pubkey: Script
    value: int


def select_utxos(utxos: Sequence[UtxoEntry], target_value: int) -> list[UtxoEntry]:
    """Greedy largest-first selection covering at least ``target_value``."""
    if target_value < 0:
        raise WalletBuildError(f"target_value must be >= 0 (got {target_value})")
    sorted_u = sorted(utxos, key=lambda u: -u.value)
    selected: list[UtxoEntry] = []
    acc = 0
    for u in sorted_u:
        selected.append(u)
        acc += u.value
        if acc >= target_value:
            return selected
    raise WalletBuildError(f"insufficient funds: have {acc}, need {target_value}")


def build_and_sign_payment(
    funder_utxos_with_keys: list[tuple[UtxoEntry, PrivateKey]],
    outputs: Sequence[FundingOutput],
    change_pubkey: PublicKey,
    fee_per_byte: int = DEFAULT_FEE_PER_BYTE,
    dust_threshold: int = DEFAULT_DUST_THRESHOLD,
) -> Tx:
    """Construct, sign, and return a payment tx.

    ``funder_utxos_with_keys`` is the pre-selected list of (utxo, key)
    pairs whose signatures will be supplied. ``change_pubkey`` receives
    the change (a single P2PKH output), if the change exceeds
    ``dust_threshold``.
    """
    if not funder_utxos_with_keys:
        raise WalletBuildError("no funding inputs supplied")
    for u, _k in funder_utxos_with_keys:
        ensure_whole_satoshi(u.value)
    for o in outputs:
        ensure_whole_satoshi(o.value)

    # Outputs (caller's + placeholder change for size estimation).
    out_list: list[TxOutput] = [TxOutput(o.value, o.script_pubkey) for o in outputs]
    change_script = p2pkh_script(change_pubkey)
    # Provisional: add a change output for size estimation; we'll set the
    # value after computing the fee.
    out_list.append(TxOutput(0, change_script))

    inputs: list[TxInput] = []
    for u, _k in funder_utxos_with_keys:
        inputs.append(TxInput(u.txid, u.vout, Script(b""), FINAL_SEQUENCE))

    tx = Tx(1, inputs, out_list, 0)
    # Size estimation: assume each P2PKH script_sig is ~108 bytes signed.
    estimated_sigsize = 108 * len(inputs)
    rough_size = tx.size() + estimated_sigsize
    fee = rough_size * fee_per_byte

    total_in = sum(u.value for u, _k in funder_utxos_with_keys)
    total_out_specified = sum(o.value for o in outputs)
    change_value = total_in - total_out_specified - fee
    if change_value < 0:
        raise WalletBuildError(
            f"funds {total_in} < specified {total_out_specified} + fee {fee}"
        )
    if change_value < dust_threshold:
        # Drop the change output; the un-output value becomes additional fee.
        out_list = [TxOutput(o.value, o.script_pubkey) for o in outputs]
    else:
        out_list[-1] = TxOutput(change_value, change_script)
    tx = Tx(1, inputs, out_list, 0)

    # Sign each input. Each input is a P2PKH spend of the funder's UTXO.
    for i, (u, priv) in enumerate(funder_utxos_with_keys):
        utxo_script = Script(u.script_pubkey)
        sig = sign_input(tx, i, u.value, utxo_script, priv, SIGHASH_ALL_FORKID)
        tx.inputs[i] = TxInput(u.txid, u.vout,
                                p2pkh_unlock(sig, priv.public_key),
                                FINAL_SEQUENCE)
    return tx


# ---------------------------------------------------------------------------
# D11 — wallet-funded channel funding transaction
# ---------------------------------------------------------------------------


def build_channel_funding_tx(
    funder_utxos_with_keys: list[tuple[UtxoEntry, PrivateKey]],
    cfg: "ChannelConfig",  # forward-stringly typed to avoid a circular import
    keybook: "KeyBook",
    change_pubkey: PublicKey,
    fee_per_byte: int = DEFAULT_FEE_PER_BYTE,
) -> Tx:
    """Build, sign, and return the channel-funding transaction.

    Inputs are P2PKH spends of the supplied wallet UTXOs. Outputs are
    the canonical channel-funding output vector (the n-of-n channel
    output of value ``S`` followed by the n bond outputs), plus a P2PKH
    change output to ``change_pubkey`` whenever the change exceeds the
    dust threshold.

    The returned transaction is what the wallet submits to the embedded
    node's mempool. After it confirms (mined into a block),
    :meth:`channel.lifecycle.Channel.from_funding_tx` wraps it so the
    channel layer's state / close / forfeit transactions reference the
    real funding txid.

    This closes scoping decision D11: the funding tx now spends real
    wallet UTXOs and is admitted through the same mempool-validation
    path as any other transaction (every input verified through the
    Bitcoin Script interpreter via :func:`channel.verify.verify_spend`).
    """
    # Local import: avoids the import cycle the channel layer would
    # introduce if wallet/ imported lifecycle/ at module-load time.
    from ..lifecycle import build_channel_outputs

    if not funder_utxos_with_keys:
        raise WalletBuildError("no funding inputs supplied")
    for u, _k in funder_utxos_with_keys:
        ensure_whole_satoshi(u.value)

    channel_outputs = build_channel_outputs(cfg, keybook)
    channel_value = sum(o.value for o in channel_outputs)
    change_script = p2pkh_script(change_pubkey)

    inputs = [
        TxInput(u.txid, u.vout, Script(b""), FINAL_SEQUENCE)
        for u, _k in funder_utxos_with_keys
    ]
    # Provisional out_list with a zero-valued change for size estimation.
    out_list = list(channel_outputs) + [TxOutput(0, change_script)]
    tx = Tx(1, inputs, out_list, 0)
    rough_size = tx.size() + 108 * len(inputs)  # P2PKH script_sig ~108 B
    fee = rough_size * fee_per_byte

    total_in = sum(u.value for u, _k in funder_utxos_with_keys)
    change = total_in - channel_value - fee
    if change < 0:
        raise WalletBuildError(
            f"funds {total_in} < channel funding {channel_value} + fee {fee}"
        )
    if change < DEFAULT_DUST_THRESHOLD:
        # No change output (the un-output value becomes fee).
        out_list = list(channel_outputs)
    else:
        out_list[-1] = TxOutput(change, change_script)
    tx = Tx(1, inputs, out_list, 0)

    # Sign each P2PKH input.
    for i, (u, priv) in enumerate(funder_utxos_with_keys):
        utxo_script = Script(u.script_pubkey)
        sig = sign_input(tx, i, u.value, utxo_script, priv, SIGHASH_ALL_FORKID)
        tx.inputs[i] = TxInput(
            u.txid, u.vout,
            p2pkh_unlock(sig, priv.public_key),
            FINAL_SEQUENCE,
        )
    return tx


__all__ = [
    "WalletBuildError",
    "FundingOutput",
    "select_utxos",
    "build_and_sign_payment",
    "build_channel_funding_tx",
    "DEFAULT_FEE_PER_BYTE",
    "DEFAULT_DUST_THRESHOLD",
]
