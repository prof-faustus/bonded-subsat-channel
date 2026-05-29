"""High-level wallet send: pay an address, broadcast via the embedded node."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Sequence

from bitcoinx import PrivateKey, PublicKey, Script, Tx

from ..errors import ChannelError
from ..node.network import EmbeddedNode
from ..node.validation import ValidationResult
from ..scripts import p2pkh_script
from .builder import (
    DEFAULT_DUST_THRESHOLD,
    DEFAULT_FEE_PER_BYTE,
    FundingOutput,
    WalletBuildError,
    build_and_sign_payment,
    select_utxos,
)
from .utxo import WalletUtxoView


_log = logging.getLogger(__name__)


class SendError(ChannelError):
    pass


@dataclass
class SendResult:
    tx: Tx
    fee: int
    accepted: bool
    reason: str = ""


def pay_p2pkh(
    view: WalletUtxoView,
    target_pubkey: PublicKey,
    amount: int,
    change_pubkey: PublicKey,
    node: EmbeddedNode,
    fee_per_byte: int = DEFAULT_FEE_PER_BYTE,
) -> SendResult:
    """Build, sign, broadcast a P2PKH payment of ``amount`` satoshis.

    Returns a :class:`SendResult`. Inputs are selected greedily from the
    wallet's confirmed UTXOs.
    """
    utxos = view.refresh()
    if not utxos:
        raise SendError("no UTXOs available to spend")
    # Roughly target amount + a generous fee headroom; the builder
    # computes the actual fee.
    selected = select_utxos(utxos, amount + 1_000)
    keyed: list[tuple] = []
    for u in selected:
        entry = view.scripts.keys_for(u.script_pubkey)
        if entry is None:
            raise SendError(f"no key for UTXO script {u.script_pubkey.hex()[:16]}...")
        _, _, priv = entry
        keyed.append((u, priv))

    target_script = p2pkh_script(target_pubkey)
    out = FundingOutput(target_script, amount)
    tx = build_and_sign_payment(keyed, [out], change_pubkey, fee_per_byte)
    fee = sum(u.value for u, _ in keyed) - sum(o.value for o in tx.outputs)
    result = node.submit_tx(tx)
    return SendResult(tx=tx, fee=fee, accepted=result.ok, reason=result.reason)


__all__ = ["SendError", "SendResult", "pay_p2pkh"]
